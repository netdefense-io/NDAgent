#!/usr/local/bin/php
<?php

/**
 * Copyright (C) 2026 NetDefense
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Clear the bootstrapToken (re-bind token) field in the NetDefense
 * Settings model.
 *
 * Invoked by the agent itself, immediately after a successful
 * registration whose ndagent.conf still carried `bootstrap_token=`.
 * The token is single-use and the broker has already cleared its
 * server-side hash at consumption time; this helper just removes the
 * matching local field so the operator does not have to.
 *
 * Behaviour:
 *  - Idempotent. If bootstrapToken is already empty, the script reports
 *    "already_empty" and exits 0 without touching Config or reloading
 *    the template.
 *  - When the field is non-empty, clears it, persists Config, and runs
 *    `configctl template reload OPNsense/NetDefense` so the next
 *    rendering of /usr/local/etc/ndagent.conf drops the
 *    `bootstrap_token=` line.
 *
 * Usage:
 *   clear_rebind_token.php [--json]
 *
 * Exit codes:
 *   0   success (cleared OR already empty — both report exit 0)
 *   22  failed before any persistence (Config lock contention,
 *       model validation error)
 *
 * The Volt template at service/templates/OPNsense/NetDefense/ndagent.conf
 * does the actual ndagent.conf rendering — this script only mutates the
 * underlying Settings model and triggers a template reload.
 */

require_once 'config.inc';
require_once 'auth.inc';
require_once 'script/load_phalcon.php';

use OPNsense\Core\Backend;
use OPNsense\NetDefense\ConfigTransaction;
use OPNsense\NetDefense\Settings;

const EXIT_OK = 0;
const EXIT_NO_PERSIST = 22;

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

$opts = getopt('', ['json']);
$json = isset($opts['json']);

try {
    $mdl = new Settings();
    $existing = (string)$mdl->bootstrapToken;

    if ($existing === '') {
        emit(
            ['result' => 'already_empty', 'cleared' => false, 'reloaded' => false],
            EXIT_OK,
            $json
        );
    }

    ConfigTransaction::begin();

    $mdl = new Settings();
    if ((string)$mdl->bootstrapToken === '') {
        // Lost the race with a concurrent writer; nothing to do.
        ConfigTransaction::end();
        emit(
            ['result' => 'already_empty', 'cleared' => false, 'reloaded' => false],
            EXIT_OK,
            $json
        );
    }

    $mdl->bootstrapToken = '';

    $validationMessages = $mdl->performValidation();
    $errors = [];
    foreach ($validationMessages as $msg) {
        $errors[] = $msg->getField() . ': ' . $msg->getMessage();
    }
    if (!empty($errors)) {
        ConfigTransaction::end();
        emit(
            ['result' => 'failed', 'message' => 'model validation failed', 'errors' => $errors],
            EXIT_NO_PERSIST,
            $json
        );
    }

    $mdl->serializeToConfig(false, true);
    ConfigTransaction::commit('NetDefense: consumed rebind token cleared');
} catch (\Exception $e) {
    ConfigTransaction::end();
    emit(
        ['result' => 'failed', 'message' => $e->getMessage()],
        EXIT_NO_PERSIST,
        $json
    );
}

// Trigger the template reload outside the Config lock so the rendered
// ndagent.conf reflects the now-empty field. The agent is the caller
// and will pick the change up on its next config read.
$backend = new Backend();
$backend->configdRun('template reload OPNsense/NetDefense');

emit(
    ['result' => 'ok', 'cleared' => true, 'reloaded' => true],
    EXIT_OK,
    $json
);
