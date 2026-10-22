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
 * Take the firmware pin off a device when the agent cannot.
 *
 * A device in a firmware track is held at one release by OPNsense's own firmware
 * flavour setting (system.firmware.flavour = <series>/MINT/<dir>/latest), which
 * the agent keeps a record of. If the agent goes away while the setting stays,
 * the device is frozen: nothing it updates from offers more than the pin. Two
 * things take the agent away for good, and both call this:
 *
 *  - removing the package (the +MANIFEST pre-deinstall hook, unless pkg is
 *    upgrading it: PKG_UPGRADE is set then);
 *  - decommissioning the device (the agent's own sequence, and the uninstall
 *    helper, which runs after the agent's API user is gone and so cannot use
 *    the REST API).
 *
 * It goes through the same model OPNsense's own /api/core/firmware/set does and
 * then runs the same two configd actions (firmware flush, firmware reload), so
 * the repository files are rewritten from the setting.
 *
 * Behaviour:
 *  - Compare-and-swap. The setting is restored only while it still equals a value
 *    the agent's record says it wrote; the comparison is made again under the
 *    config lock. A flavour somebody else set stays as it is.
 *  - Idempotent and quiet when there is nothing to do: no record, a record that
 *    holds no pin, a setting already back at the original value.
 *  - It never touches the agent's record: a package that is only being upgraded
 *    (a split upgrade pkg runs as a delete and an install) is healed by the new
 *    agent re-pinning at its installed release, which needs the record.
 *
 * Usage:
 *   release_firmware_flavour.php [--state-file=PATH] [--json]
 *
 * Exit codes:
 *   0   done or nothing to do (released, not_ours, already_restored,
 *       nothing_pinned, no_state)
 *   22  failed before anything was saved (config lock, model validation)
 *   23  the agent's record exists and cannot be understood; nothing was touched
 *   30  bad CLI args
 */

require_once 'config.inc';
require_once 'auth.inc';
require_once 'script/load_phalcon.php';

use OPNsense\Core\Backend;
use OPNsense\Core\Firmware;
use OPNsense\NetDefense\ConfigTransaction;
use OPNsense\NetDefense\FirmwareFlavourRelease;

const EXIT_OK = 0;
const EXIT_NO_PERSIST = 22;
const EXIT_STATE_UNREADABLE = 23;
const EXIT_BAD_ARGS = 30;

const DEFAULT_STATE_FILE = '/var/db/ndagent/firmware-track.json';

/**
 * Print a result block (--json) or human-readable lines and exit.
 */
function emit(array $payload, int $code, bool $json): void
{
    if ($json) {
        fwrite(STDOUT, json_encode($payload, JSON_UNESCAPED_SLASHES) . "\n");
    } else {
        fwrite(STDOUT, 'result: ' . ($payload['result'] ?? 'unknown') . "\n");
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

$opts = getopt('', ['state-file::', 'json']);
$json = isset($opts['json']);
$stateFile = DEFAULT_STATE_FILE;
if (array_key_exists('state-file', $opts)) {
    $given = $opts['state-file'];
    if (!is_string($given) || $given === '' || $given[0] !== '/') {
        emit(['result' => 'failed', 'message' => '--state-file takes one absolute path'], EXIT_BAD_ARGS, $json);
    }
    $stateFile = $given;
}

try {
    $state = FirmwareFlavourRelease::readState($stateFile);
} catch (\Throwable $e) {
    emit(['result' => 'failed', 'message' => $e->getMessage()], EXIT_STATE_UNREADABLE, $json);
}

try {
    $current = (string)(new Firmware())->flavour;
    $decision = FirmwareFlavourRelease::decide($state, $current);
    if ($decision['result'] !== FirmwareFlavourRelease::RESULT_RELEASED) {
        emit(['result' => $decision['result'], 'released' => false, 'flavour' => $current], EXIT_OK, $json);
    }

    // A bounded wait for the lock: a pkg hook must not hang on a stuck one.
    // Whoever runs this must not wrap it in timeout(1) or kill it either.
    ConfigTransaction::begin();

    // Compare again under the lock: a GUI save between the read and the lock
    // must not be overwritten.
    $mdl = new Firmware();
    $current = (string)$mdl->flavour;
    $decision = FirmwareFlavourRelease::decide($state, $current);
    if ($decision['result'] !== FirmwareFlavourRelease::RESULT_RELEASED) {
        ConfigTransaction::end();
        emit(['result' => $decision['result'], 'released' => false, 'flavour' => $current], EXIT_OK, $json);
    }

    $restoreTo = (string)$decision['restore_to'];
    $mdl->flavour = $restoreTo;

    $errors = [];
    foreach ($mdl->performValidation() as $msg) {
        $errors[] = $msg->getField() . ': ' . $msg->getMessage();
    }
    if (!empty($errors)) {
        ConfigTransaction::end();
        emit(['result' => 'failed', 'message' => 'model validation failed', 'errors' => $errors], EXIT_NO_PERSIST, $json);
    }

    $mdl->serializeToConfig(false, true);
    ConfigTransaction::commit(sprintf(
        'NetDefense: firmware pin released, flavour restored to %s',
        $restoreTo === '' ? 'the default' : $restoreTo
    ));
} catch (\Throwable $e) {
    ConfigTransaction::end();
    emit(['result' => 'failed', 'message' => $e->getMessage()], EXIT_NO_PERSIST, $json);
}

// The same two actions /api/core/firmware/set runs after it saves: forget the
// cached check result and write the repository files from the setting. Outside
// the config lock.
$backend = new Backend();
$backend->configdRun('firmware flush');
$backend->configdRun('firmware reload');

emit(
    ['result' => FirmwareFlavourRelease::RESULT_RELEASED, 'released' => true, 'from' => $current, 'to' => $restoreTo],
    EXIT_OK,
    $json
);
