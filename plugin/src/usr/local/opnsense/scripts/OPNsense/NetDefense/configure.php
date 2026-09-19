#!/usr/local/bin/php
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

/**
 * Unattended-install CLI helper for the NetDefense agent plugin.
 *
 * Invoked by the post-pkg-install path of /repo.netdefense.io/install.sh
 * when the operator passes --auto-setup=<token>. Persists token + deviceId
 * + (optionally) provisions the OPNsense API user/key + (optionally)
 * enables the agent — all in a single Config save — then triggers the
 * template reload and service restart so the agent comes up "armed".
 *
 * Also carries the two reverse operations used by the agent's
 * self-decommission sequence:
 *   --reset-identity       clears the stored identity so a later reinstall
 *                          on the same box registers as a genuinely new
 *                          device rather than inheriting a deviceId bound
 *                          to a deleted row;
 *   --deprovision-accounts removes the netdefense-agent and
 *                          netdefense-readonly OPNsense accounts locally,
 *                          which the API cannot do for the agent's own
 *                          user (see the function docblock below).
 *
 * Usage:
 *   configure.php --token=<uuid> [--device-id=<uuid>] [--setup-api]
 *                 [--enable] [--server=<url>] [--json]
 *   configure.php --reset-identity [--json]
 *   configure.php --deprovision-accounts [--json]
 *
 * Exit codes:
 *   0   success (or idempotent no-op)
 *   21  token/deviceId persisted but API setup failed (recoverable;
 *       finish API setup in the web UI)
 *   22  failed before any persistence (Config lock contention, model
 *       validation error)
 *   30  bad CLI args
 *
 * The Volt template at service/templates/OPNsense/NetDefense/ndagent.conf
 * does the actual /usr/local/etc/ndagent.conf rendering — this script just
 * mutates the underlying Settings model and triggers a template reload.
 */

require_once 'config.inc';
require_once 'auth.inc';
require_once 'script/load_phalcon.php';

use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\NetDefense\ApiCredsProvisioner;
use OPNsense\NetDefense\ReadOnlyUserProvisioner;
use OPNsense\NetDefense\Settings;

const EXIT_OK = 0;
const EXIT_API_FAILED = 21;
const EXIT_NO_PERSIST = 22;
const EXIT_BAD_ARGS = 30;

const UUID_RE = '/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/';

/**
 * Print a result block (--json) or human-readable lines and exit.
 *
 * The API key and secret are never included in the payload — they live
 * only in /conf/config.xml and ndagent.conf. Stdout from this script
 * lands in install.sh logs, CI consoles, and operator screenshots; the
 * key must not appear on any of those surfaces.
 */
function emit(array $payload, int $code, bool $json): void
{
    if ($json) {
        fwrite(STDOUT, json_encode($payload, JSON_UNESCAPED_SLASHES) . "\n");
    } else {
        fwrite(STDOUT, "result: " . ($payload['result'] ?? 'unknown') . "\n");
        foreach ($payload as $k => $v) {
            if ($k === 'result') {
                continue;
            }
            if (is_bool($v)) {
                $v = $v ? 'true' : 'false';
            }
            fwrite(STDOUT, "$k: $v\n");
        }
    }
    exit($code);
}

$opts = getopt('', [
    'token:',
    'device-id:',
    'setup-api',
    'enable',
    'server:',
    'reset-identity',
    'deprovision-accounts',
    'json',
]);

$json = isset($opts['json']);

/**
 * Clear the stored NetDefense identity from config.xml.
 *
 * Called by the agent's self-decommission sequence (see
 * internal/tasks/decommission.go) after the device row has been
 * permanently deleted and every managed object has been reconciled away.
 * Clearing deviceId here is what lets a later `install.sh --auto-setup`
 * on the same box mint a fresh device: with a deviceId still stored, the
 * guard below would keep the old one and the new installation would
 * inherit an identity whose row, key and counters no longer exist.
 *
 * The API key/secret go too — the netdefense-agent OPNsense user backing
 * them was deleted moments earlier, so leaving them would only leave dead
 * credentials in config.xml.
 *
 * Model validation is deliberately NOT run here: token and deviceId are
 * Required=Y with a UUID mask, so an empty value fails validation by
 * design. That constraint exists to stop a half-configured device being
 * saved from the GUI; it must not stop a decommissioned device being
 * emptied. The plugin package is uninstalled seconds later anyway.
 *
 * Idempotent: already-empty fields report cleared:false and still exit 0.
 */
function resetIdentity(bool $json): void
{
    $gotLock = false;
    $cleared = [];
    try {
        Config::getInstance()->lock();
        $gotLock = true;

        $mdl = new Settings();
        $fields = ['deviceId', 'token', 'apiKey', 'apiSecret', 'bootstrapToken'];
        foreach ($fields as $field) {
            if ((string)$mdl->$field !== '') {
                $mdl->$field = '';
                $cleared[] = $field;
            }
        }
        if ((string)$mdl->enabled !== '0') {
            $mdl->enabled = '0';
            $cleared[] = 'enabled';
        }
        if ((string)$mdl->apiConfigured !== '0') {
            $mdl->apiConfigured = '0';
            $cleared[] = 'apiConfigured';
        }

        $mdl->serializeToConfig(false, true);
        Config::getInstance()->save();
        Config::getInstance()->unlock();
        $gotLock = false;
    } catch (\Exception $e) {
        if ($gotLock) {
            Config::getInstance()->unlock();
        }
        emit(
            ['result' => 'failed', 'message' => $e->getMessage()],
            EXIT_NO_PERSIST,
            $json
        );
    }

    // Re-render ndagent.conf outside the Config lock so the file on disk
    // matches the now-empty model.
    (new Backend())->configdRun('template reload OPNsense/NetDefense');

    emit(
        [
            'result' => 'ok',
            'cleared' => !empty($cleared),
            'cleared_fields' => implode(',', $cleared),
            'reloaded' => true,
        ],
        EXIT_OK,
        $json
    );
}

/**
 * Remove the two NetDefense-owned OPNsense accounts, locally.
 *
 * Called by the agent's self-decommission sequence (see
 * internal/tasks/decommission.go) right after the API-based identity
 * removals, and once more by /usr/local/sbin/ndagent-decommission.sh just
 * before `pkg delete` — the package and this script are still present at
 * that point, and a second run is a no-op when the first one worked.
 *
 * Why it cannot be done over the OPNsense API: the agent authenticates as
 * netdefense-agent, and Usermanager refuses to delete the account behind
 * the request it is serving —
 * `{"errorMessage":"Not allowed to remove logged in user netdefense-agent"}`,
 * HTTP 500. That refusal is deterministic, so the API path can never
 * remove the agent's own user, and before this existed every
 * decommissioned box kept a `page-all` user with a live API key in
 * config.xml. This script runs as root, outside any API session, and goes
 * straight through the Auth models — the symmetric inverse of the
 * provisioning ApiCredsProvisioner does at install time.
 *
 * netdefense-readonly is removed here too, so the call is a complete
 * belt-and-braces pass: a device with no working API, or one whose API
 * removal failed, still ends up with neither account.
 *
 * Idempotent: nothing to remove reports removed:false and still exits 0.
 * No model validation, for the same reason --reset-identity skips it.
 */
function deprovisionAccounts(bool $json): void
{
    $gotLock = false;
    try {
        Config::getInstance()->lock();
        $gotLock = true;

        $agent = ApiCredsProvisioner::deprovision();
        $readonly = ReadOnlyUserProvisioner::deprovision();

        if ($agent['removed'] || $readonly['removed']) {
            Config::getInstance()->save();
        }

        Config::getInstance()->unlock();
        $gotLock = false;
    } catch (\Exception $e) {
        if ($gotLock) {
            Config::getInstance()->unlock();
        }
        emit(
            ['result' => 'failed', 'message' => $e->getMessage()],
            EXIT_NO_PERSIST,
            $json
        );
    }

    // Outside the Config lock. `auth sync user` reconciles the local shell
    // accounts against config.xml and deletes any whose config entry is
    // gone — these two carry no shell so normally have no local account at
    // all, but a device where one was added by hand must not keep it.
    $backend = new Backend();
    foreach (
        [
            ApiCredsProvisioner::NETDEFENSE_USERNAME,
            ReadOnlyUserProvisioner::READONLY_USERNAME,
        ] as $username
    ) {
        $backend->configdpRun('auth sync user', [$username]);
    }

    // Re-render ndagent.conf: the API credentials it carried have just
    // been cleared from the model.
    $backend->configdRun('template reload OPNsense/NetDefense');

    emit(
        [
            'result' => 'ok',
            'agent_removed' => $agent['removed'],
            'readonly_removed' => $readonly['removed'],
            'removed' => $agent['removed'] || $readonly['removed'],
            'reloaded' => true,
        ],
        EXIT_OK,
        $json
    );
}

if (isset($opts['reset-identity'])) {
    resetIdentity($json);
}

if (isset($opts['deprovision-accounts'])) {
    deprovisionAccounts($json);
}

if (!isset($opts['token'])) {
    emit(['result' => 'failed', 'message' => '--token=<uuid> is required'], EXIT_BAD_ARGS, $json);
}

$token = strtolower(trim($opts['token']));
if (!preg_match(UUID_RE, $token)) {
    emit(['result' => 'failed', 'message' => 'invalid --token format (expected UUID)'], EXIT_BAD_ARGS, $json);
}

$deviceId = null;
if (isset($opts['device-id'])) {
    $deviceId = strtolower(trim($opts['device-id']));
    if (!preg_match(UUID_RE, $deviceId)) {
        emit(['result' => 'failed', 'message' => 'invalid --device-id format (expected UUID)'], EXIT_BAD_ARGS, $json);
    }
}

$doSetupApi = isset($opts['setup-api']);
$doEnable = isset($opts['enable']);
$serverOverride = isset($opts['server']) ? trim($opts['server']) : null;

$result = [
    'result' => 'ok',
    'token_set' => false,
    'token_changed' => false,
    'device_id' => null,
    'enabled' => false,
    'api_setup' => 'not_requested',
];

$gotLock = false;
try {
    Config::getInstance()->lock();
    $gotLock = true;

    $mdl = new Settings();

    $existingToken = (string)$mdl->token;
    $existingDeviceId = (string)$mdl->deviceId;

    // Token: write + flag changed if different from prior.
    if ($existingToken !== $token) {
        $mdl->token = $token;
        $result['token_set'] = true;
        if ($existingToken !== '' && $existingToken !== $token) {
            $result['token_changed'] = true;
        }
    } else {
        $result['token_set'] = false;
    }

    // deviceId: only fill when caller supplied one OR none stored yet.
    // Never overwrite an existing deviceId silently — it's bound to the
    // device's signing keypair on the NetDefense side.
    if ($deviceId !== null) {
        if ($existingDeviceId !== '' && $existingDeviceId !== $deviceId) {
            // Operator passed a different deviceId than what's already
            // stored; keep the stored one but SAY SO. Rebinding is a
            // separate ndcli flow, and a box that silently ignored the
            // deviceId it was just handed looks installed-and-working
            // while registering as the wrong device — which is exactly
            // how this was first hit in the lab.
            //
            // A decommissioned box does not land here: the agent clears
            // the stored deviceId via --reset-identity before the
            // package is removed.
            $result['device_id'] = $existingDeviceId;
            $result['device_id_kept'] = true;
            $result['warning'] = 'a different deviceId is already stored; keeping it. '
                . 'Requested ' . $deviceId . ', kept ' . $existingDeviceId . '. '
                . 'To bind this box to a new device, re-install on a clean box or use the ndcli rebind flow.';
            if (!$json) {
                fwrite(STDERR, 'WARNING: ' . $result['warning'] . "\n");
            }
        } else {
            $mdl->deviceId = $deviceId;
            $result['device_id'] = $deviceId;
        }
    } else {
        $result['device_id'] = $existingDeviceId !== '' ? $existingDeviceId : null;
    }

    if ($serverOverride !== null) {
        $mdl->serverAddress = $serverOverride;
    }

    if ($doEnable) {
        $mdl->enabled = '1';
        $result['enabled'] = true;
    } else {
        $result['enabled'] = ((string)$mdl->enabled === '1');
    }

    // Validate the model now so we fail before mutating User/api keys.
    $validationMessages = $mdl->performValidation();
    $errors = [];
    foreach ($validationMessages as $msg) {
        $errors[] = $msg->getField() . ': ' . $msg->getMessage();
    }
    if (!empty($errors)) {
        Config::getInstance()->unlock();
        $gotLock = false;
        emit(
            ['result' => 'failed', 'message' => 'model validation failed', 'errors' => $errors],
            EXIT_NO_PERSIST,
            $json
        );
    }

    $mdl->serializeToConfig(false, true);

    // Stage 1 done: token/deviceId/enabled in the in-memory Config.
    // Stage 2: API provisioning. Failure here is recoverable — the token
    // is the more important half. We save what we have and report exit 21.

    $apiSetupResult = null;
    if ($doSetupApi) {
        $apiSetupResult = ApiCredsProvisioner::provision(false);
        $result['api_setup'] = $apiSetupResult['result'];
        // Note: the actual key/secret are deliberately not propagated
        // here — they're already in config.xml and the rendered
        // ndagent.conf. The operator never needs to see them.

        // Provision the shared read-only WebAdmin user in the same
        // transaction so it exists from day one. It has no API key and
        // no password — only the curated read-only ACL — so a failure
        // here is non-fatal to the agent (token/API are the load-bearing
        // halves). Report it but don't change the exit path.
        $readonlyResult = ReadOnlyUserProvisioner::provision();
        $result['readonly_setup'] = $readonlyResult['result'];
    }

    Config::getInstance()->save();
    Config::getInstance()->unlock();
    $gotLock = false;
} catch (\Exception $e) {
    if ($gotLock) {
        Config::getInstance()->unlock();
    }
    emit(
        ['result' => 'failed', 'message' => $e->getMessage()],
        EXIT_NO_PERSIST,
        $json
    );
}

// Backend triggers (outside the Config lock).
$backend = new Backend();

if ($doSetupApi && isset($apiSetupResult) && $apiSetupResult['result'] === 'ok') {
    $backend->configdpRun('auth sync user', [ApiCredsProvisioner::NETDEFENSE_USERNAME]);
}

if ($doSetupApi && isset($readonlyResult) && $readonlyResult['result'] === 'ok') {
    $backend->configdpRun('auth sync user', [ReadOnlyUserProvisioner::READONLY_USERNAME]);
}

$backend->configdRun('template reload OPNsense/NetDefense');

if ($doEnable) {
    $backend->configdRun('netdefense restart');
}

if ($doSetupApi && isset($apiSetupResult) && $apiSetupResult['result'] === 'failed') {
    // Token saved, API failed. Recoverable.
    $result['result'] = 'partial';
    $result['message'] = 'token saved, API setup failed: ' . ($apiSetupResult['message'] ?? 'unknown');
    emit($result, EXIT_API_FAILED, $json);
}

emit($result, EXIT_OK, $json);
