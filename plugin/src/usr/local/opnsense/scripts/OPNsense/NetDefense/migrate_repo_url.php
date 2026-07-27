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
 * Self-migrating post-install step: rewrite the pkg(8) repository URL in
 * /usr/local/etc/pkg/repos/NetDefense.conf from the pre-dual-ABI flat form
 * (.../opnsense) to the ABI-nested form (.../opnsense/${ABI}, pkg(8)
 * substitutes ${ABI} per device at every `pkg update`).
 *
 * Background: build/publish-repo.sh now publishes each channel's package
 * repository under an ABI-nested subtree
 * (.../opnsense/FreeBSD:14:amd64/, .../opnsense/FreeBSD:15:amd64/) and,
 * for freebsd14 publishes only, also mirrors the same content to the flat
 * .../opnsense/ root as a bootstrap safety net for any device that never
 * runs this migration. See build/README.md's "Dual-ABI package
 * repository" section for the full design.
 *
 * Wired into +MANIFEST's post-install hook next to ensure_readonly.php,
 * so it runs on every `pkg install`/`pkg upgrade` — the PLUGIN_INSTALL
 * task path, a bare `pkg upgrade` over SSH, and the OPNsense Firmware GUI
 * plugin-update flow all go through this hook. Idempotent by
 * construction: the rewrite regex matches ONLY the exact pre-migration
 * flat URL for a known channel; an already-nested URL or an
 * unrecognized/hand-edited config is left untouched (never rewritten
 * twice, never clobbered).
 *
 * Deliberately does NOT touch config.xml / the Settings model.
 * NetDefense.conf is a plain pkg(8) repo config file that lives entirely
 * outside OPNsense's MVC config tree, so — unlike ensure_readonly.php and
 * configure.php — this script skips the config.inc/auth.inc/Phalcon
 * bootstrap on purpose: fewer dependencies means fewer ways for this
 * best-effort step to fail mid pkg-transaction.
 *
 * Safety: the original file is backed up (same
 * "<file>.backup.<timestamp>" convention as install.sh's configure_repo())
 * before any write, and the rewrite itself is a write-to-temp + atomic
 * rename so a crash mid-write can never leave NetDefense.conf partially
 * written. A pkg transaction is already mid-flight against the OLD url
 * when this hook runs (pkg has already resolved/fetched using it for
 * this very install/upgrade), so the write only needs to be safe for the
 * *next* `pkg update` — it never needs to interrupt the current one.
 *
 * Usage:
 *   migrate_repo_url.php [--json]
 *
 * Exit codes. The +MANIFEST invocation wraps this call in `|| true` on
 * top of the internal best-effort handling below — a non-zero exit here
 * must never fail (or even cosmetically flag as failed) the pkg
 * transaction that is installing/upgrading this very package:
 *   0   migrated, already-migrated, unrecognized/untouched, or the repo
 *       conf file is simply absent (e.g. a sideloaded/local install)
 *   1   read/backup/write failure — logged, but still non-fatal to the
 *       caller thanks to the `|| true` wrapper
 */

const REPO_CONF_FILE = '/usr/local/etc/pkg/repos/NetDefense.conf';

$json = in_array('--json', $argv ?? [], true);

/**
 * Emit the result (stdout, for +MANIFEST's post-install log capture —
 * PLUGIN_INSTALL routes this into /var/log/ndagent-plugin-install.log)
 * and mirror it to syslog (for every other invocation path — a bare
 * `pkg upgrade` over SSH or the Firmware GUI don't capture post-install
 * stdout anywhere persistent) so "did device X migrate?" is always
 * answerable from device logs regardless of how the upgrade was
 * triggered.
 */
function emit_migrate(array $result, int $code, bool $asJson): void
{
    if ($asJson) {
        echo json_encode($result, JSON_UNESCAPED_SLASHES) . "\n";
    } else {
        echo $result['message'] . "\n";
    }

    openlog('ndagent-migrate-repo-url', LOG_PID, LOG_DAEMON);
    syslog($result['result'] === 'failed' ? LOG_WARNING : LOG_NOTICE, $result['message']);
    closelog();

    exit($code);
}

if (!is_readable(REPO_CONF_FILE)) {
    emit_migrate(
        [
            'result' => 'absent',
            'message' => 'migrate_repo_url: ' . REPO_CONF_FILE . ' not present -- nothing to migrate '
                . '(sideloaded/local install, or repo registered under a different name?)',
        ],
        0,
        $json
    );
}

$content = file_get_contents(REPO_CONF_FILE);
if ($content === false) {
    emit_migrate(
        ['result' => 'failed', 'message' => 'migrate_repo_url: failed to read ' . REPO_CONF_FILE],
        1,
        $json
    );
}

// Already-nested form: url: "https://repo.netdefense.io/<env>/opnsense/${ABI}"
// with the literal, unexpanded pkg ${ABI} variable. Checked first so an
// already-migrated device is a clean no-op without ever touching the
// flat-form regex below.
$nestedPattern = '/^[ \t]*url:\s*"https:\/\/repo\.netdefense\.io\/(prod|qa|dev)\/opnsense\/\$\{ABI\}"\s*,?\s*$/m';
if (preg_match($nestedPattern, $content, $m)) {
    emit_migrate(
        [
            'result' => 'skipped',
            'message' => "migrate_repo_url: already on the ABI-nested URL (channel={$m[1]}) -- no-op",
        ],
        0,
        $json
    );
}

// Exact pre-migration flat-root form only -- anchored end-to-end (leading
// whitespace, then literally "url:", then the flat URL, then only a
// closing quote/comma/trailing whitespace) so this can never match an
// already-nested URL (which has a third path segment) or a hand-edited /
// unrelated url: line. Anything that doesn't match this exact shape
// falls through to the "unrecognized" branch below untouched.
$flatPattern = '/^(?<indent>[ \t]*url:\s*")https:\/\/repo\.netdefense\.io\/(?<env>prod|qa|dev)\/opnsense(?<tail>"\s*,?\s*)$/m';
if (!preg_match($flatPattern, $content, $m)) {
    emit_migrate(
        [
            'result' => 'unrecognized',
            'message' => 'migrate_repo_url: url: line does not match the known flat NetDefense URL form -- '
                . 'left untouched (hand-edited or unusual repo config?)',
        ],
        0,
        $json
    );
}

$env = $m['env'];

// Build the replacement by plain string concatenation -- never through
// PCRE's `$1`/`${1}` backreference syntax in the replacement string, and
// never through a PHP double-quoted string. Either would try to
// interpret `${ABI}`: PCRE as a (nonexistent, digit-only) capture group
// reference, PHP as interpolation of a variable named $ABI. It must land
// in the file as the five literal characters `$`, `{`, `A`, `B`, `I`,
// `}` so pkg(8) substitutes it per-device at every future `pkg update`.
// This is the exact same trap install.sh's REPO_URL construction hit on
// the shell side (see its "\${ABI}" escape and comment) -- concatenation
// with a single-quoted PHP literal sidesteps both interpreters at once
// rather than trying to escape through either one.
$abiLiteral = '${ABI}';
$newLine = $m['indent'] . 'https://repo.netdefense.io/' . $env . '/opnsense/' . $abiLiteral . $m['tail'];

$newContent = preg_replace_callback($flatPattern, static function () use ($newLine) {
    return $newLine;
}, $content, 1);

if ($newContent === null || $newContent === $content) {
    emit_migrate(
        ['result' => 'failed', 'message' => 'migrate_repo_url: rewrite produced no change (unexpected) -- left untouched'],
        1,
        $json
    );
}

// Backup before writing, same convention as install.sh's configure_repo().
$backupFile = REPO_CONF_FILE . '.backup.' . date('Ymd_His');
if (!@copy(REPO_CONF_FILE, $backupFile)) {
    emit_migrate(
        [
            'result' => 'failed',
            'message' => "migrate_repo_url: failed to back up to {$backupFile} before rewrite -- left untouched",
        ],
        1,
        $json
    );
}

// Atomic write: temp file in the same directory (same filesystem, so
// rename() is atomic), then rename over the original. A failure at any
// point up to and including the rename leaves the original
// NetDefense.conf exactly as it was -- never partially written.
$tmpFile = REPO_CONF_FILE . '.tmp.' . getmypid();
if (
    @file_put_contents($tmpFile, $newContent) === false
    || !@rename($tmpFile, REPO_CONF_FILE)
) {
    @unlink($tmpFile);
    emit_migrate(
        [
            'result' => 'failed',
            'message' => "migrate_repo_url: failed to write {$tmpFile} -> " . REPO_CONF_FILE
                . " -- original preserved, backup at {$backupFile}",
        ],
        1,
        $json
    );
}

emit_migrate(
    [
        'result' => 'migrated',
        'message' => "migrate_repo_url: rewrote NetDefense.conf url (channel={$env}) to the ABI-nested form; "
            . "backup at {$backupFile}",
    ],
    0,
    $json
);
