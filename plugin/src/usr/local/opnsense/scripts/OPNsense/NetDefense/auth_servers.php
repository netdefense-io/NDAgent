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
 * AUTH_SERVER / AUTH_ORDER sync/decommission helper.
 *
 * Invocation: `auth_servers.php --json`, request JSON on stdin, response
 * JSON on stdout, exit 0 on "handled" (per-element outcomes carry any
 * failure — see AuthServerHelper::sync()/decommission()). Any other exit
 * code fails the whole AUTH family on the Go side.
 *
 * Recommended invocation flags (Go side): `php -d display_errors=0
 * -d log_errors=0 -d zend.exception_ignore_args=1 auth_servers.php
 * --json`. Those three flags stop a PHP warning/notice or an uncaught
 * exception's argument dump from ever reaching stdout/stderr with a
 * field value embedded in it — the helper never echoes values; a stray
 * warning is the one class of leak these flags close that this script's
 * own try/catch below cannot.
 *
 * The request is read from stdin only, deliberately departing from the
 * "PHP helpers take argv" baseline this repo's other CLI helpers use —
 * a secret (`ldap_bindpw`) must never appear in `ps` output or a shell
 * history. `--json` is accepted for contract compatibility; unlike this
 * repo's other CLI helpers, output here is always JSON regardless of
 * whether the flag is present (the wire contract has no human-readable
 * mode).
 *
 * Not tied to task/WebSocket cancellation — the Go side starts
 * this with `exec.Command`, not the task context, and sends SIGTERM only
 * after its own ceiling. Before the Config lock is acquired, default
 * signal disposition applies (a kill here is harmless — nothing has been
 * mutated yet). Once `AuthServerHelper` acquires the lock it ignores
 * SIGTERM/SIGINT until it unlocks — a kill mid-`save()` truncates
 * config.xml.
 */

// Belt-and-suspenders so the helper never echoes a field value: the Go
// side is documented to invoke this script with
// `-d display_errors=0 -d log_errors=0 -d zend.exception_ignore_args=1`
// (see this file's own header comment), but that protection lived ONLY
// in the caller's invocation — running this script by hand (as every
// lab-verification pass has done) silently lost it.
// Setting the same three here makes the protection self-enforcing
// regardless of how the script is invoked. `ini_set()` this early can
// still be overridden by php.ini's own `display_errors`/`log_errors` for
// anything logged before this line runs, but nothing has read stdin or
// touched Config yet, so there is no field value to leak before this
// point.
ini_set('display_errors', '0');
ini_set('log_errors', '0');
ini_set('zend.exception_ignore_args', '1');

require_once 'config.inc';
require_once 'auth.inc';
require_once 'script/load_phalcon.php';

use OPNsense\NetDefense\AuthServerHelper;

const MAX_REQUEST_BYTES = 1048576; // 1 MB — symmetry with the 1 MB stdout cap NDAgent enforces on this script's stdout

/**
 * Codes this script's own catch block may report. Anything else (a raw
 * PHP exception message, which could in principle carry a value from a
 * bug elsewhere) is mapped to a generic fault code rather than echoed —
 * this: "the helper never echoes values" applies to failure
 * paths too, not only success ones.
 */
const KNOWN_FAULT_CODES = [
    'AUTH_LOCK_TIMEOUT', 'AUTH_LAYOUT_UNSUPPORTED', 'WRITE_ALLOWLIST_VIOLATION',
    'AUTH_REQUEST_INVALID', 'CONSUMER_SCAN_FAILED',
];

/**
 * "Handled" (per-element outcomes, `servers`/`facilities`/`exclusion`
 * present) exits 0. A protocol-level fault — the request never got that
 * far, so there is no per-element shape to report at all — exits
 * non-zero: any other exit fails the whole AUTH family. The JSON body is
 * still written to stdout for diagnostics; Go must key off the exit
 * code, never off the presence/absence of a `servers` key, to decide
 * "handled" vs. "the AUTH family failed".
 */
function emit(array $response, int $exitCode = 0): void
{
    $encoded = json_encode($response, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    if ($encoded === false) {
        // A hand-made server's name (echoed read-only in a warning/local_servers
        // entry) could in principle carry invalid UTF-8 that survives the
        // substitute flag's own edge cases — never fall through to writing
        // a bare newline with exit 0, which would read as "handled, no
        // outcomes" rather than a fault.
        fwrite(STDOUT, json_encode(['contract' => 1, 'error' => ['code' => 'AUTH_HELPER_FAULT']]) . "\n");
        exit(2);
    }
    fwrite(STDOUT, $encoded . "\n");
    exit($exitCode);
}

$raw = stream_get_contents(STDIN, MAX_REQUEST_BYTES + 1);
if ($raw === false || strlen($raw) > MAX_REQUEST_BYTES) {
    emit(['contract' => 1, 'error' => ['code' => 'AUTH_REQUEST_INVALID']], 2);
}

$request = json_decode((string)$raw, true);
if (
    !is_array($request) || !isset($request['mode']) || !is_string($request['mode'])
    || ($request['contract'] ?? null) !== 1
) {
    emit(['contract' => 1, 'error' => ['code' => 'AUTH_REQUEST_INVALID']], 2);
}

try {
    $helper = new AuthServerHelper();
    switch ($request['mode']) {
        case 'sync':
            $response = $helper->sync($request);
            break;
        case 'decommission':
            $response = $helper->decommission($request);
            break;
        default:
            emit(['contract' => 1, 'error' => ['code' => 'AUTH_REQUEST_INVALID']], 2);
    }
} catch (\Throwable $e) {
    $code = $e->getMessage();
    $safeCode = in_array($code, KNOWN_FAULT_CODES, true) ? $code : 'AUTH_HELPER_FAULT';
    emit(['contract' => 1, 'error' => ['code' => $safeCode]], 2);
}

emit($response);
