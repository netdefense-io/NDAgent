<?php

/**
 * Copyright (C) 2026 NetDefense
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 */

namespace OPNsense\NetDefense;

use OPNsense\Auth\Group;
use OPNsense\Auth\User;

/**
 * Low-level handling of NetDefense-owned OPNsense accounts, straight
 * through the same Auth models the provisioners create them with: the
 * password every such account carries, and their removal.
 *
 * Why removal exists at all: the OPNsense Usermanager API refuses to delete
 * the account whose credentials authenticate the request
 * ("Not allowed to remove logged in user netdefense-agent", HTTP 500).
 * The agent authenticates as `netdefense-agent`, so its own API user can
 * never be removed over the API — the decommission sequence has to do it
 * locally, as root, outside any API session. That is what
 * ApiCredsProvisioner::deprovision() and
 * ReadOnlyUserProvisioner::deprovision() do, and this class is the half
 * they share.
 *
 * Why the password exists: the Auth\User model rejects a row without one,
 * and OPNsense's own migration runner validates the whole user set. A
 * passwordless row therefore aborts that runner as soon as any <user> in
 * config.xml lacks a uuid attribute. Nobody logs in with these accounts,
 * so the password is a random hash whose plaintext is discarded, produced
 * the way OPNsense's add_user.php produces it.
 *
 * Caller contract, identical to the provisioners': the caller owns
 * Config::getInstance()->lock(), save(), unlock() and the Backend
 * triggers. These methods only mutate the in-memory Config tree.
 *
 * Everything here is idempotent. An absent user or group is success, not
 * an error: the decommission sequence is re-runnable by design, and the
 * uninstall helper calls it a second time as a belt-and-braces pass.
 */
class LocalAccounts
{
    /** fillPassword() found no password and wrote a scrambled one. */
    public const PASSWORD_SET = 'set';

    /** fillPassword() found a password and left it alone. */
    public const PASSWORD_KEPT = 'kept';

    /** No hash could be generated; the row is exactly as it was found. */
    public const PASSWORD_FAILED = 'failed';

    /**
     * Random plaintext for a scrambled password: 50 random bytes, as
     * OPNsense generates them, except that two byte values are re-rolled
     * until none is left. NUL, because PHP 8.2.18+ refuses it in a
     * password. LF, because under password-policy compliance the model
     * pipes the plaintext into `openssl passwd -6 -stdin`, which hashes
     * every line on its own: a plaintext holding a LF comes back as several
     * hashes (or a leading "<NULL>" line), not as one crypt string.
     *
     * @param callable|null $randomBytes byte source, random_bytes() by default
     */
    public static function randomPassword(?callable $randomBytes = null): string
    {
        $randomBytes = $randomBytes ?? 'random_bytes';
        $password = $randomBytes(50);
        for ($i = 0, $n = strlen($password); $i < $n; $i++) {
            while ($password[$i] === "\0" || $password[$i] === "\n") {
                $password[$i] = $randomBytes(1);
            }
        }
        return $password;
    }

    /**
     * Give a user row a scrambled password unless it already has one.
     *
     * Emptiness is decided with isEmpty(), never with a (string) cast: on
     * OPNsense 26.x the password field (UpdateOnlyTextField) casts to ''
     * whatever it holds, so a string test would re-hash and overwrite a
     * password an operator set through the GUI on every run. Assigning ''
     * to that field is a no-op, which is why the hash is checked too.
     *
     * A failure to generate the hash, or a result that is not one crypt
     * string, never throws and never half-writes: on PASSWORD_FAILED the row
     * is untouched. The hash and the plaintext are never returned or logged.
     *
     * @param User $userMdl the model $userNode belongs to; its hashing rules
     *                      (bcrypt, or SHA-512 crypt under password-policy
     *                      compliance) apply
     * @param mixed $userNode a row of $userMdl->user
     * @return string PASSWORD_SET, PASSWORD_KEPT or PASSWORD_FAILED
     */
    public static function fillPassword(User $userMdl, $userNode): string
    {
        if (!$userNode->password->isEmpty()) {
            return self::PASSWORD_KEPT;
        }

        try {
            $hash = $userMdl->generatePasswordHash(self::randomPassword());
        } catch (\Throwable $e) {
            return self::PASSWORD_FAILED;
        }
        if (!is_string($hash) || preg_match('/^\$[0-9a-z]+\$\S+$/D', $hash) !== 1) {
            return self::PASSWORD_FAILED;
        }

        $userNode->password = $hash;
        if ($userNode->password->isEmpty()) {
            return self::PASSWORD_FAILED;
        }
        if (isset($userNode->pwd_changed_at)) {
            $userNode->pwd_changed_at = microtime(true);
        }
        return self::PASSWORD_SET;
    }

    /**
     * Fill in the password of every existing row named $name that has none.
     * Never creates a row, never touches any other field, never replaces a
     * password that is set.
     *
     * The User model is built here, after whatever ran before this call was
     * serialized: serializeToConfig() on this legacy-mapper model rewrites
     * the whole /system/user set from the instance it is called on, so two
     * instances alive at once silently revert each other's changes.
     *
     * @return array{found:bool,changed:bool,failed:bool}
     */
    public static function fillExistingPassword(string $name): array
    {
        $userMdl = new User();
        $found = false;
        $changed = false;
        $failed = false;

        foreach ($userMdl->user->iterateItems() as $user) {
            if ((string)$user->name !== $name) {
                continue;
            }
            $found = true;
            $outcome = self::fillPassword($userMdl, $user);
            $changed = $changed || $outcome === self::PASSWORD_SET;
            $failed = $failed || $outcome === self::PASSWORD_FAILED;
        }

        if ($changed) {
            $userMdl->serializeToConfig(false, true);
        }

        return ['found' => $found, 'changed' => $changed, 'failed' => $failed];
    }

    /**
     * Delete one OPNsense user by name, with its API keys, and drop its
     * uid from every group that still lists it.
     *
     * The API keys live inside the user node and go with it, but they are
     * also cleared explicitly, so that any path which ends up keeping the
     * user node still cannot leave a live key on it. A stranded
     * admin-privileged API credential is the whole defect this code
     * exists to prevent.
     *
     * Group membership is matched on the NUMERIC uid, not the config-tree
     * UUID — OPNsense's ACL resolves <member> against <uid>, and
     * ReadOnlyUserProvisioner::provision() writes it that way.
     *
     * @return bool true when something was removed
     */
    public static function removeUser(string $name): bool
    {
        $userMdl = new User();

        // Collect first, mutate after: deleting while iterating the same
        // ArrayField is not safe, and a duplicated name (possible after a
        // hand-edited config.xml) must not stop the sweep at the first hit.
        $uuids = [];
        $uids = [];
        foreach ($userMdl->user->iterateItems() as $uuid => $user) {
            if ((string)$user->name !== $name) {
                continue;
            }
            $uuids[] = (string)$uuid;
            $uid = (string)$user->uid;
            if ($uid !== '') {
                $uids[] = $uid;
            }
            foreach ($user->apikeys->all() as $keyData) {
                if (is_array($keyData) && isset($keyData['key'])) {
                    $user->apikeys->del($keyData['key']);
                } elseif (is_string($keyData)) {
                    $user->apikeys->del($keyData);
                }
            }
        }

        if (empty($uuids)) {
            return false;
        }

        foreach ($uuids as $uuid) {
            $userMdl->user->del($uuid);
        }
        $userMdl->serializeToConfig(false, true);

        self::dropGroupMemberships($uids);

        return true;
    }

    /**
     * Delete one OPNsense group by name.
     *
     * @return bool true when something was removed
     */
    public static function removeGroup(string $name): bool
    {
        $groupMdl = new Group();

        $uuids = [];
        foreach ($groupMdl->group->iterateItems() as $uuid => $group) {
            if ((string)$group->name === $name) {
                $uuids[] = (string)$uuid;
            }
        }

        if (empty($uuids)) {
            return false;
        }

        foreach ($uuids as $uuid) {
            $groupMdl->group->del($uuid);
        }
        $groupMdl->serializeToConfig(false, true);

        return true;
    }

    /**
     * Remove the given uids from every group's member list, so no group
     * is left pointing at a uid that no longer resolves to a user.
     *
     * @param string[] $uids numeric uids of the users just removed
     */
    private static function dropGroupMemberships(array $uids): void
    {
        if (empty($uids)) {
            return;
        }

        $groupMdl = new Group();
        $dirty = false;

        foreach ($groupMdl->group->iterateItems() as $group) {
            $members = array_filter(explode(',', (string)$group->member));
            $kept = array_values(array_diff($members, $uids));
            if (count($kept) !== count($members)) {
                $group->member = implode(',', $kept);
                $dirty = true;
            }
        }

        if ($dirty) {
            $groupMdl->serializeToConfig(false, true);
        }
    }
}
