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
 * OPNsense user + group to the desired state (READONLY_PRIVS), give the
 * netdefense-agent and netdefense-readonly users a scrambled password when
 * they have none, and grandfather any Settings field whose default changed
 * after a device's config.xml was last saved — on every package install or
 * upgrade.
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
 * default-migrations below. Only calls ApiCredsProvisioner::ensurePassword()
 * and ReadOnlyUserProvisioner::provision() and fires the necessary backend
 * triggers.
 *
 * Passwords: earlier releases created both accounts with an empty one, which
 * makes OPNsense's own migration runner abort once any <user> lacks a uuid
 * attribute. An account with no password gets a random hash; one that already
 * has a password is never replaced. The agent account is never created or
 * deleted here. See LocalAccounts.
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
 *     the reject_dangerous_snippets default flip (the Go-side default,
 *     this reconcile, and the rejection message format all need to stay
 *     in sync).
 *
 * Usage:
 *   ensure_readonly.php [--json]
 *
 * Exit codes:
 *   0   ok or skipped (no change needed), or a password could not be hashed
 *       — that is logged and reported as a warning but is never fatal, since
 *       the +MANIFEST hook runs this script without `|| true` and a
 *       password problem must not fail the pkg transaction
 *   1   failed
 */

require_once 'config.inc';
require_once 'auth.inc';
require_once 'script/load_phalcon.php';

use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\NetDefense\ApiCredsProvisioner;
use OPNsense\NetDefense\LocalAccounts;
use OPNsense\NetDefense\ReadOnlyUserProvisioner;
use OPNsense\NetDefense\Settings;

$json = in_array('--json', $argv ?? [], true);

function emit_ro(array $result, int $code, bool $asJson, array $notes = []): void
{
    if ($asJson) {
        echo json_encode($result, JSON_UNESCAPED_SLASHES) . "\n";
    } else {
        echo $result['message'] . "\n";
        foreach ($notes as $note) {
            echo $note . "\n";
        }
    }
    exit($code);
}

/**
 * Mirror a line to syslog: a bare `pkg upgrade` or the Firmware GUI do not
 * keep the post-install stdout anywhere persistent, and the account
 * passwords are otherwise changed silently.
 *
 * Opened once and never closed: on OPNsense 26.7 (syslog-ng 4.12) a closelog()
 * followed by another openlog() in the same process loses every line after
 * the first.
 */
function log_ro(int $priority, string $message): void
{
    static $opened = false;
    if (!$opened) {
        openlog('ndagent-ensure-readonly', LOG_PID, LOG_DAEMON);
        $opened = true;
    }
    syslog($priority, $message);
}

$gotLock = false;
$roResult = null;
$agentPassword = ['result' => 'skipped', 'changed' => false, 'message' => ''];
$settingsChanged = false;

try {
    Config::getInstance()->lock();
    $gotLock = true;

    // Fill in an empty password on the agent's own account. Runs before the
    // read-only provisioner so each one builds its User model after the
    // previous one was serialized: the whole user set is rewritten from
    // whichever instance serializes last.
    $agentPassword = ApiCredsProvisioner::ensurePassword();

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

    // Carry any existing rejectDangerousSnippets value across to its
    // positively-phrased replacement, allowAllSnippetContent, inverting it.
    //
    // This runs BEFORE the grandfathering block below and is the reason a
    // rename cannot change behaviour: a device that was explicitly permissive
    // (reject=0, typically because the grandfathering below wrote it on an
    // earlier upgrade) becomes allowAll=1 and stays permissive. A device that
    // was explicitly secure (reject=1) becomes allowAll=0 and stays secure.
    //
    // Without this, the new field would simply be absent on every existing
    // device, the model default (0 = secure) would apply, and the fleets
    // deliberately grandfathered as permissive would tighten silently on
    // package upgrade -- breaking in-use snippets with no warning.
    //
    // The old node is left in place rather than removed: it is inert once the
    // template stops reading it, and leaving it makes a downgrade to an
    // earlier plugin build behave correctly instead of reverting to defaults.
    if (
        isset($cfg->OPNsense->netdefense->settings->rejectDangerousSnippets)
        && !isset($cfg->OPNsense->netdefense->settings->allowAllSnippetContent)
    ) {
        $wasRejecting = (string)$cfg->OPNsense->netdefense->settings->rejectDangerousSnippets === '1';
        $cfg->OPNsense->netdefense->settings->allowAllSnippetContent = $wasRejecting ? '0' : '1';
        $settingsChanged = true;
    }

    // Grandfather the previous permissive default (see the header docblock)
    // for any device already configured before either field existed in its
    // saved config.xml. Expressed in the new field: allow all = permissive.
    if (
        $isConfigured
        && !isset($cfg->OPNsense->netdefense->settings->allowAllSnippetContent)
    ) {
        $cfg->OPNsense->netdefense->settings->allowAllSnippetContent = '1';
        $settingsChanged = true;
    }

    if ($roResult['result'] === 'ok' || $agentPassword['changed'] || $settingsChanged) {
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

if ($agentPassword['changed']) {
    $backend->configdpRun('auth sync user', [ApiCredsProvisioner::NETDEFENSE_USERNAME]);
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

$notes = [];
$warnings = [];
if ($agentPassword['result'] === 'ok') {
    $notes[] = $agentPassword['message'];
} elseif ($agentPassword['result'] === 'failed') {
    $warnings[] = $agentPassword['message'];
}
$roPassword = $roResult['password'] ?? LocalAccounts::PASSWORD_KEPT;
if ($roPassword === LocalAccounts::PASSWORD_SET) {
    $notes[] = 'Scrambled password set on the ' . ReadOnlyUserProvisioner::READONLY_USERNAME . ' user';
} elseif ($roPassword === LocalAccounts::PASSWORD_FAILED) {
    $warnings[] = 'Failed to generate a password hash for the ' . ReadOnlyUserProvisioner::READONLY_USERNAME . ' user';
}
foreach ($notes as $note) {
    log_ro(LOG_NOTICE, $note);
}
foreach ($warnings as $warning) {
    log_ro(LOG_WARNING, $warning);
    $notes[] = 'WARNING: ' . $warning . '. Retry with: configctl netdefense ensure-readonly';
}

$payload = [
    'result' => $roResult['result'],
    'message' => $msg,
    'agent_password' => $agentPassword['result'],
];
if (!empty($warnings)) {
    $payload['warnings'] = $warnings;
}

// A provisioner that failed only because it could not hash a password is a
// warning, not a failure: see the exit codes above.
$roFailed = $roResult['result'] === 'failed' && $roPassword !== LocalAccounts::PASSWORD_FAILED;

emit_ro($payload, $roFailed ? 1 : 0, $json, $notes);
