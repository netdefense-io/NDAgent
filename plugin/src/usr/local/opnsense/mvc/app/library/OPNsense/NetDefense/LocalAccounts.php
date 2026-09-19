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
 * Low-level removal of NetDefense-owned OPNsense accounts, straight
 * through the same Auth models the provisioners create them with.
 *
 * Why this exists at all: the OPNsense Usermanager API refuses to delete
 * the account whose credentials authenticate the request
 * ("Not allowed to remove logged in user netdefense-agent", HTTP 500).
 * The agent authenticates as `netdefense-agent`, so its own API user can
 * never be removed over the API — the decommission sequence has to do it
 * locally, as root, outside any API session. That is what
 * ApiCredsProvisioner::deprovision() and
 * ReadOnlyUserProvisioner::deprovision() do, and this class is the half
 * they share.
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
