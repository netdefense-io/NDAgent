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
 * Usage:
 *   configure.php --token=<uuid> [--device-id=<uuid>] [--setup-api]
 *                 [--enable] [--server=<url>] [--json]
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
use OPNsense\NetDefense\Settings;

const EXIT_OK = 0;
const EXIT_API_FAILED = 21;
const EXIT_NO_PERSIST = 22;
const EXIT_BAD_ARGS = 30;

const UUID_RE = '/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/';

/**
 * Print a result block (--json) or human-readable lines and exit.
 */
function emit(array $payload, int $code, bool $json): void
{
    if ($json) {
        fwrite(STDOUT, json_encode($payload, JSON_UNESCAPED_SLASHES) . "\n");
    } else {
        fwrite(STDOUT, "result: " . ($payload['result'] ?? 'unknown') . "\n");
        foreach ($payload as $k => $v) {
            if ($k === 'result' || $k === 'api_secret') {
                continue; // never print the secret to a tty
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
    'json',
]);

$json = isset($opts['json']);

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
            // stored; warn but do not overwrite. Rebinding is a separate
            // ndcli flow.
            $result['device_id'] = $existingDeviceId;
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
        if ($apiSetupResult['result'] === 'ok' && isset($apiSetupResult['api_key'])) {
            $result['api_key'] = $apiSetupResult['api_key'];
        } elseif ($apiSetupResult['result'] === 'skipped') {
            // OK: existing user+key; reuse them. apiKey is already in config XML.
        }
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
