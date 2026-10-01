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

/**
 * Which OPNsense privileges make a local account administrator-equivalent.
 *
 * The classification is data: `opnsense_admin_equivalence.json`, reviewed in
 * NDDataModels and copied here byte for byte, next to the agent's own copy
 * (`internal/opnapi/opnsense_admin_equivalence.json`). `AdminEquivalenceTest.php`
 * pins its SHA-256, holds the two copies identical and runs every shared vector.
 *
 * A privilege entry is one element of a priv list, or a whole priv CSV as
 * OPNsense stores it, so it can pack several IDs. It is split on ',', each token
 * is trimmed and lowercased, empty tokens are skipped, and the entry is
 * administrator-equivalent as soon as one token is: a key of the catalog's
 * `admin_equivalent` map, a key of neither map (an ID nobody reviewed, a
 * lookalike spelling), or one the structural floor that predates the catalog
 * catches (page-all, anything ending in -all, anything naming both "system" and
 * "admin", all-pages). Normalization is ASCII only, on purpose: every catalog key
 * is ASCII, so a token with any other byte in it, NUL included, is unknown and
 * therefore elevated.
 *
 * Pure: nothing here touches OPNsense, so it runs wherever the repo is checked
 * out.
 */
final class AdminEquivalence
{
    public const CATALOG_FILE = 'opnsense_admin_equivalence.json';

    /** ASCII whitespace. PHP's default trim() set also holds NUL, which must stay a byte of the token. */
    private const TRIM = " \t\n\x0B\f\r";

    /** @var array<string,mixed>|null */
    private static $catalog = null;

    /**
     * @return array{sha256:string,admin_equivalent:array<string,string>,non_admin:array<string,string>,ro_backstop_allowlist:array<string,string>,protected_groups:array<string>,protected_users:array<string>,assumes_min_opnsense:string}
     * @throws \RuntimeException when the catalog is missing or is not whole
     */
    public static function catalog(): array
    {
        if (self::$catalog !== null) {
            return self::$catalog;
        }
        $raw = @file_get_contents(__DIR__ . '/' . self::CATALOG_FILE);
        if ($raw === false) {
            throw new \RuntimeException(self::CATALOG_FILE . ' is missing');
        }
        $doc = json_decode($raw, true);
        if (
            !is_array($doc)
            || ($doc['schema'] ?? null) !== 1
            || ($doc['kind'] ?? null) !== 'opnsense-admin-equivalence'
            || ($doc['meta']['unknown_id_policy'] ?? null) !== 'admin_equivalent'
            || !is_string($doc['meta']['assumes_min_opnsense'] ?? null)
        ) {
            throw new \RuntimeException(self::CATALOG_FILE . ' is not a version 1 admin-equivalence catalog');
        }
        foreach (['admin_equivalent', 'non_admin', 'ro_backstop_allowlist', 'protected_groups', 'protected_users'] as $section) {
            if (!is_array($doc[$section] ?? null) || ($section !== 'ro_backstop_allowlist' && $doc[$section] === [])) {
                throw new \RuntimeException(self::CATALOG_FILE . ' has no usable ' . $section);
            }
        }
        self::$catalog = [
            'sha256' => hash('sha256', $raw),
            'admin_equivalent' => $doc['admin_equivalent'],
            'non_admin' => $doc['non_admin'],
            'ro_backstop_allowlist' => $doc['ro_backstop_allowlist'],
            'protected_groups' => $doc['protected_groups'],
            'protected_users' => $doc['protected_users'],
            'assumes_min_opnsense' => $doc['meta']['assumes_min_opnsense'],
        ];
        return self::$catalog;
    }

    /** The normalized, non-empty tokens of one privilege entry. */
    public static function privTokens(string $entry): array
    {
        $tokens = [];
        foreach (explode(',', $entry) as $raw) {
            $token = strtr(trim($raw, self::TRIM), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz');
            if ($token !== '') {
                $tokens[] = $token;
            }
        }
        return $tokens;
    }

    /** True for a normalized token that is admin-equivalent, unknown, or caught by the structural floor. */
    public static function privTokenIsElevated(string $token): bool
    {
        $catalog = self::catalog();
        if (isset($catalog['admin_equivalent'][$token]) || !isset($catalog['non_admin'][$token])) {
            return true;
        }
        return $token === 'page-all'
            || $token === 'all-pages'
            || substr($token, -4) === '-all'
            || (strpos($token, 'system') !== false && strpos($token, 'admin') !== false);
    }

    /** True if any token of a privilege entry is elevated. */
    public static function privEntryIsElevated(string $entry): bool
    {
        foreach (self::privTokens($entry) as $token) {
            if (self::privTokenIsElevated($token)) {
                return true;
            }
        }
        return false;
    }
}
