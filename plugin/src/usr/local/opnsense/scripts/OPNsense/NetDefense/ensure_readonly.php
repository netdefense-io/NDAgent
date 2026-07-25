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
 * Token-free entry point: idempotently reconcile the netdefense-readonly
 * OPNsense user + group to the desired state (READONLY_PRIVS), and
 * grandfather any Settings field whose default changed after a device's
 * config.xml was last saved — on every package install or upgrade.
 *
 * This script is invoked directly from the +MANIFEST post-install hook
 * after configd restarts, so it runs on every `pkg install` AND every
 * `pkg upgrade` — not just on fresh installs. That makes READONLY_PRIVS
 * the single source of truth for the read-only ACL: edit the constant,
 * ship a new package, and the updated priv set is reconciled on every
 * device at next upgrade without any manual intervention.
 *
 * Does NOT require --token. Does NOT touch the agent token, device_uuid,
 * API key/secret, or any other Settings field beyond the two narrow
 * default-migrations below. Only calls ReadOnlyUserProvisioner::provision()
 * and fires the necessary backend triggers.
 *
 * Config-default migrations performed here. Both follow the same shape:
 * only touch config.xml when the plugin is already configured (token
 * present) AND the specific field's XML node is absent — i.e. this
 * device's saved config predates the field. A genuinely fresh,
 * never-configured device is left untouched here and picks up
 * Settings.xml's current <Default> the first time it IS configured (GUI
 * Apply or the unattended configure.php helper), so neither migration ever
 * fires for a real fresh install.
 *
 *   - webadminReadonlyUser: persists the read-only WebAdmin username
 *     default so the Volt template renders webadmin_readonly_user= in
 *     ndagent.conf on an upgrade from a version that predates the field.
 *   - rejectDangerousSnippets: persists an explicit "0" (off) so a device
 *     that was already relying on the old permissive default doesn't
 *     silently start rejecting dangerous SYNC_API snippet content it was
 *     already applying, now that Settings.xml's <Default> for this field
 *     is "1" (secure-by-default). This is the grandfathering mechanism for
 *     the reject_dangerous_snippets default flip — see CLAUDE.md's
 *     "Device-local dangerous-snippet gate" section for the full story
 *     (the Go-side default, this reconcile, and the rejection message
 *     format all need to stay in sync).
 *
 * Usage:
 *   ensure_readonly.php [--json]
 *
 * Exit codes:
 *   0   ok or skipped (no change needed)
 *   1   failed
 */

require_once 'config.inc';
require_once 'auth.inc';
require_once 'script/load_phalcon.php';

use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\NetDefense\ReadOnlyUserProvisioner;
use OPNsense\NetDefense\Settings;

$json = in_array('--json', $argv ?? [], true);

function emit_ro(array $result, int $code, bool $asJson): void
{
    if ($asJson) {
        echo json_encode($result, JSON_UNESCAPED_SLASHES) . "\n";
    } else {
        echo $result['message'] . "\n";
    }
    exit($code);
}

$gotLock = false;
$roResult = null;
$settingsChanged = false;

try {
    Config::getInstance()->lock();
    $gotLock = true;

    // Reconcile user + group + priv set to desired state.
    $roResult = ReadOnlyUserProvisioner::provision();

    // Persist per-field defaults to config.xml when the plugin is
    // configured (token present) but a given field's XML node is absent.
    // We write the node directly rather than calling serializeToConfig()
    // to avoid rewriting every Settings field (which would overwrite an
    // unconfigured install's required-but-empty fields).
    $cfg = Config::getInstance()->object();
    $isConfigured = isset($cfg->OPNsense->netdefense->settings)
        && (string)$cfg->OPNsense->netdefense->settings->token !== '';

    if (
        $isConfigured
        && !isset($cfg->OPNsense->netdefense->settings->webadminReadonlyUser)
    ) {
        $cfg->OPNsense->netdefense->settings->webadminReadonlyUser =
            ReadOnlyUserProvisioner::READONLY_USERNAME;
        $settingsChanged = true;
    }

    // Grandfather the previous permissive reject_dangerous_snippets
    // default (see the header docblock) for any device already configured
    // before this field existed in its saved config.xml.
    if (
        $isConfigured
        && !isset($cfg->OPNsense->netdefense->settings->rejectDangerousSnippets)
    ) {
        $cfg->OPNsense->netdefense->settings->rejectDangerousSnippets = '0';
        $settingsChanged = true;
    }

    if ($roResult['result'] === 'ok' || $settingsChanged) {
        Config::getInstance()->save();
    }

    Config::getInstance()->unlock();
    $gotLock = false;
} catch (\Exception $e) {
    if ($gotLock) {
        Config::getInstance()->unlock();
    }
    emit_ro(
        ['result' => 'failed', 'message' => 'Exception: ' . $e->getMessage()],
        1,
        $json
    );
}

// Backend triggers (outside the Config lock).
$backend = new Backend();

if ($roResult['result'] === 'ok') {
    $backend->configdpRun('auth sync user', [ReadOnlyUserProvisioner::READONLY_USERNAME]);
}

// Always reload the template so ndagent.conf reflects any state change —
// the read-only user was just created/repaired, or one of the
// webadminReadonlyUser / rejectDangerousSnippets defaults was just
// written to config.xml.
$backend->configdRun('template reload OPNsense/NetDefense');

$messages = [
    'ok'      => 'Read-only WebAdmin user provisioned.',
    'skipped' => 'Read-only WebAdmin user already up to date.',
    'failed'  => $roResult['message'] ?? 'Provisioning failed.',
];
$msg = isset($messages[$roResult['result']])
    ? $messages[$roResult['result']]
    : $roResult['message'] ?? 'Unknown result.';

emit_ro(
    ['result' => $roResult['result'], 'message' => $msg],
    $roResult['result'] === 'failed' ? 1 : 0,
    $json
);
