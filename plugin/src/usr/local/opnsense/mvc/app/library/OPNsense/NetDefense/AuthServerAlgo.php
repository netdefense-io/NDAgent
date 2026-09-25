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
 * Pure, side-effect-free algorithms for the AUTH_SERVER / AUTH_ORDER PHP
 * helper (`scripts/OPNsense/NetDefense/auth_servers.php` +
 * `AuthServerHelper.php`).
 *
 * Every method here takes plain PHP scalars/arrays and returns plain PHP
 * scalars/arrays or throws \RuntimeException — nothing touches
 * OPNsense\Core\Config, the Auth models, or any other live OPNsense
 * runtime state. That split is deliberate: it is what lets
 * `plugin/tests/AuthServerAlgoTest.php` exercise every rule in this file
 * on any PHP 7.4+/8.x install with the repo checked out, the same way
 * `ReadOnlyUserProvisionerPrivDriftTest.php` exercises the read-only priv
 * reconciliation algorithm without a live config.xml.
 *
 * `AuthServerHelper` is the Config-dependent orchestration layer that
 * calls into these methods.
 */
class AuthServerAlgo
{
    // -----------------------------------------------------------------
    // Shared constants (mirrors NDDataModels/Schema.py's AUTH_* constants.
    // Kept in sync manually; there is no shared library between the
    // Python service and this Go-adjacent PHP helper).
    // -----------------------------------------------------------------

    /** The lowest OPNsense release AUTH mutations may run against. */
    const FLOOR_RELEASE = [26, 1, 6];

    const LOCAL_DATABASE = 'Local Database';
    const LOCAL_API = 'Local API';

    /**
     * OPNsense's own built-in connectors. Sourced from the two
     * constants above (single source of truth) rather than a second,
     * independently-typed literal pair — compared case-insensitively at
     * every call site (see `validateServerName()`).
     */
    const RESERVED_SERVER_NAMES = [self::LOCAL_DATABASE, self::LOCAL_API];

    /** Protected local group names, compared case-insensitively. */
    const PROTECTED_GROUP_NAMES = ['admins', 'netdefense-readonly'];

    /** The static half of the reserved-name exclusion set. */
    const RESERVED_STATIC_USER_NAMES = ['root', 'netdefense-agent', 'netdefense-readonly'];

    /** Unicode code points (mirrors NDDataModels' Python len()), not bytes. */
    const EXTENDED_QUERY_MAX_LEN = 1536;

    /**
     * The COMPOSED effective query (user query + every reserved-name
     * negation) — a value distinct from the AUTHORING cap on the raw,
     * user-typed field (`EXTENDED_QUERY_MAX_LEN`). Set at 16384
     * characters, independent of the 1536-character authoring cap — a
     * mid-size org's composed value can legitimately need well over
     * 1536 codepoints once every reserved name is negated in. Do not
     * conflate the two constants; changing one must never silently move
     * the other.
     */
    const COMPOSED_EXCLUSION_MAX_LEN = 16384;

    /** Recursion ceiling for the RFC 4515 parser — clean error, not a crash. */
    const EXTENDED_QUERY_MAX_DEPTH = 32;

    /**
     * `order` is 1-8 strings. NDDataModels enforces this at build
     * time (authoritative); this is device-side defense in depth,
     * checked by `AuthServerHelper::planFacilities()`
     * (`AUTH_ORDER_TOO_LONG`) before any resolution/Local-Database-rule/gate check runs.
     */
    const AUTH_ORDER_MAX_ENTRIES = 8;

    /** Content keys are config.xml keys verbatim. `nd_*` keys are authoring-only and never written. */
    public const AUTH_SERVER_WRITABLE_KEYS = [
        'host', 'ldap_port', 'ldap_urltype', 'ldap_protver', 'ldap_scope',
        'ldap_basedn', 'ldap_authcn', 'ldap_extended_query', 'ldap_attr_user',
        'ldap_binddn', 'ldap_bindpw', 'caseInSensitiveUsernames',
        'ldap_read_properties', 'ldap_sync_memberof_constraint',
        'ldap_sync_memberof', 'ldap_attr_memberof', 'ldap_sync_memberof_groups',
        'ldap_sync_default_groups', 'ldap_sync_create_local_users',
    ];

    public const BOOLEAN_KEYS = [
        'caseInSensitiveUsernames', 'ldap_read_properties',
        'ldap_sync_memberof_constraint', 'ldap_sync_memberof',
        'ldap_sync_create_local_users',
    ];

    /** Authoring-only keys beyond AUTH_SERVER_WRITABLE_KEYS a valid payload may carry (never written). */
    public const AUTH_SERVER_ND_KEYS = ['nd_allow_cleartext_ldap'];

    /**
     * Name shape — 1-128 chars, no leading/trailing space, this
     * charset. `\z`, not `$` — see `isValidOidOrDescr()`'s doc comment for
     * why a bare `$` would let a name ending in "\n" slip through.
     */
    public const SERVER_NAME_MAX_LEN = 128;
    public const SERVER_NAME_RE = '/^[A-Za-z0-9_+.\- ]+\z/';

    /** The three allowed values; "TCP - Standard" needs the cleartext acknowledgement. */
    public const LDAP_URLTYPES = ['StartTLS', 'SSL - Encrypted', 'TCP - Standard'];

    /** caseInSensitiveUsernames is only safe with an attribute that itself matches case-insensitively. */
    public const CASE_INSENSITIVE_OK_ATTRS = ['samaccountname', 'uid', 'cn', 'mail', 'userprincipalname'];

    public const HOST_MAX_LEN = 253;
    public const BASEDN_MAX_LEN = 1024;
    public const AUTHCN_MAX_LEN = 2048;

    /** Up to 16 GROUP names per Limit/default-group CSV field. */
    public const GROUP_CSV_MAX_ENTRIES = 16;

    /**
     * Verified read-only on the lab (`LDAP.php::setProperties()`):
     * `!empty($config['ldap_attr_memberof'])` means OPNsense's own
     * runtime already falls back to this exact value when the key is
     * absent or empty — its class property default is the literal
     * string below. This helper writes the default EXPLICITLY
     * (`buildEffectiveFields()`) rather than relying on that fallback,
     * so config.xml never depends on OPNsense's internal default for a
     * value NetDefense wrote, and the GUI (which also always posts a
     * literal value, see `system_authservers.php:262`) and this helper
     * always agree on what is actually live.
     */
    public const LDAP_ATTR_MEMBEROF_DEFAULT = 'memberOf';

    // -----------------------------------------------------------------
    // Stable per-rule sub-codes for AuthServerHelper's tentative-upsert
    // catch block. One generic AUTH_SERVER_INVALID told a consumer
    // nothing about which of a dozen possible rules failed; every code
    // below still names only the rule, never the value, just at finer
    // grain. The allow-list (AUTH_SERVER_INVALID_CODES) mirrors
    // auth_servers.php's own KNOWN_FAULT_CODES pattern: a RuntimeException
    // whose message does NOT match one of these is never trusted as a
    // code as-is (see AuthServerHelper's catch block), so a stray/future
    // exception can never surface an arbitrary message as if it were a
    // stable code.
    // -----------------------------------------------------------------

    public const CODE_INVALID_NAME = 'AUTH_SERVER_INVALID_NAME';
    public const CODE_INVALID_UNKNOWN_FIELD = 'AUTH_SERVER_INVALID_UNKNOWN_FIELD';
    public const CODE_INVALID_FIELD_TYPE = 'AUTH_SERVER_INVALID_FIELD_TYPE';
    public const CODE_INVALID_CONTROL_CHARS = 'AUTH_SERVER_INVALID_CONTROL_CHARS';
    public const CODE_INVALID_HOST = 'AUTH_SERVER_INVALID_HOST';
    public const CODE_INVALID_BASEDN = 'AUTH_SERVER_INVALID_BASEDN';
    public const CODE_INVALID_AUTHCN = 'AUTH_SERVER_INVALID_AUTHCN';
    public const CODE_INVALID_ATTR_USER = 'AUTH_SERVER_INVALID_ATTR_USER';
    public const CODE_INVALID_ATTR_MEMBEROF = 'AUTH_SERVER_INVALID_ATTR_MEMBEROF';
    public const CODE_INVALID_URLTYPE = 'AUTH_SERVER_INVALID_URLTYPE';
    public const CODE_INVALID_PROTOCOL = 'AUTH_SERVER_INVALID_PROTOCOL';
    public const CODE_INVALID_EXTENDED_QUERY = 'AUTH_SERVER_INVALID_EXTENDED_QUERY';
    public const CODE_INVALID_BIND_PAIR = 'AUTH_SERVER_INVALID_BIND_PAIR';
    public const CODE_INVALID_GROUPS = 'AUTH_SERVER_INVALID_GROUPS';
    public const CODE_INVALID_CASE_INSENSITIVE = 'AUTH_SERVER_INVALID_CASE_INSENSITIVE';

    /** The complete, authoritative set of `validateServerName()`/`validateServerFieldsShape()`/`validateServerFieldsRequired()` sub-codes. */
    public const AUTH_SERVER_INVALID_CODES = [
        self::CODE_INVALID_NAME, self::CODE_INVALID_UNKNOWN_FIELD, self::CODE_INVALID_FIELD_TYPE,
        self::CODE_INVALID_CONTROL_CHARS, self::CODE_INVALID_HOST, self::CODE_INVALID_BASEDN,
        self::CODE_INVALID_AUTHCN, self::CODE_INVALID_ATTR_USER, self::CODE_INVALID_ATTR_MEMBEROF,
        self::CODE_INVALID_URLTYPE, self::CODE_INVALID_PROTOCOL, self::CODE_INVALID_EXTENDED_QUERY,
        self::CODE_INVALID_BIND_PAIR, self::CODE_INVALID_GROUPS, self::CODE_INVALID_CASE_INSENSITIVE,
    ];

    // -----------------------------------------------------------------
    // Codepoint-array helper
    // -----------------------------------------------------------------

    /**
     * Split a string into an array of single-UTF-8-codepoint strings,
     * index-compatible with Python's codepoint-indexed string semantics
     * (the source the RFC 4515 parser below is ported from).
     *
     * @throws \RuntimeException on malformed UTF-8.
     */
    public static function mbChars(string $s): array
    {
        $chars = preg_split('//u', $s, -1, PREG_SPLIT_NO_EMPTY);
        if ($chars === false) {
            throw new \RuntimeException('value is not valid UTF-8');
        }
        return $chars;
    }

    // -----------------------------------------------------------------
    // RFC 4515 filter parser for ldap_extended_query, and the
    // reserved-name exclusion it composes into.
    //
    // A direct, index-for-index port of NDDataModels' Python parser
    // (NDDataModels/Schema.py, `_ldap_parse_*` / `parse_ldap_extended_
    // query`) so both sides accept and reject exactly the same inputs —
    // pinned by the shared fixture table `tests/fixtures/auth/
    // ldap_extended_query_parser.json` (copied verbatim from NDDataModels
    // PR #43 @ 05131cc; see plugin/tests/fixtures/auth/SOURCE.md).
    //
    // Deliberately a "small parser": accepts `simple`, `present`,
    // `substring`, `and`, `or`, `not` and `extensible` filter items;
    // does not implement full RFC 4512 attribute-description syntax
    // beyond a single `;`-suffixed option.
    // -----------------------------------------------------------------

    private static function isAsciiAlpha(string $c): bool
    {
        return strlen($c) === 1 && (($c >= 'A' && $c <= 'Z') || ($c >= 'a' && $c <= 'z'));
    }

    private static function isAsciiAlnumHyphen(string $c): bool
    {
        return strlen($c) === 1 && (
            ($c >= 'A' && $c <= 'Z') || ($c >= 'a' && $c <= 'z') ||
            ($c >= '0' && $c <= '9') || $c === '-'
        );
    }

    private static function isAsciiDigit(string $c): bool
    {
        return strlen($c) === 1 && $c >= '0' && $c <= '9';
    }

    private static function isHexDigit(string $c): bool
    {
        return strlen($c) === 1 && (
            ($c >= '0' && $c <= '9') || ($c >= 'a' && $c <= 'f') || ($c >= 'A' && $c <= 'F')
        );
    }

    /**
     * RFC 4512 `oid = descr / numericoid` — used for matching-rule names
     * too. `\z` (not `$`) anchors the end: PCRE's `$` also matches
     * immediately before a trailing "\n", so without this a matching rule
     * like "caseExactMatch\n:=x" would parse here but fail Python's
     * `fullmatch` in NDDataModels — a shared-fixture parity break (this
     * repo's copy of the RFC 4515 parser is meant to accept/reject byte-
     * for-byte the same inputs, see the fixture table this file's header
     * references).
     */
    private static function isValidOidOrDescr(string $s): bool
    {
        if ($s === '') {
            return false;
        }
        if (preg_match('/^[A-Za-z][A-Za-z0-9-]*\z/', $s) === 1) {
            return true;
        }
        return preg_match('/^[0-9]+(\.[0-9]+)+\z/', $s) === 1;
    }

    /**
     * attr = descr *(";" option) / numericoid — `_LDAP_ATTR_RE` /
     * `_LDAP_OID_RE` in the Python source.
     *
     * @return array{0:string,1:int} [attr, next index]
     */
    private static function consumeAttr(array $chars, int $i): array
    {
        $n = count($chars);
        $start = $i;

        if ($i < $n && self::isAsciiAlpha($chars[$i])) {
            $j = $i + 1;
            while ($j < $n && self::isAsciiAlnumHyphen($chars[$j])) {
                $j++;
            }
            while ($j < $n && $chars[$j] === ';') {
                $k = $j + 1;
                $m = $k;
                while ($m < $n && self::isAsciiAlnumHyphen($chars[$m])) {
                    $m++;
                }
                if ($m === $k) {
                    break; // an empty option suffix does not belong to the attr
                }
                $j = $m;
            }
            return [implode('', array_slice($chars, $start, $j - $start)), $j];
        }

        // numericoid = number 1*( "." number )
        $j = $i;
        $firstDigits = 0;
        while ($j < $n && self::isAsciiDigit($chars[$j])) {
            $j++;
            $firstDigits++;
        }
        if ($firstDigits > 0) {
            $k = $j;
            $dotGroups = 0;
            while ($k < $n && $chars[$k] === '.') {
                $digitsHere = 0;
                $m = $k + 1;
                while ($m < $n && self::isAsciiDigit($chars[$m])) {
                    $m++;
                    $digitsHere++;
                }
                if ($digitsHere === 0) {
                    break;
                }
                $k = $m;
                $dotGroups++;
            }
            if ($dotGroups > 0) {
                return [implode('', array_slice($chars, $start, $k - $start)), $k];
            }
        }

        throw new \RuntimeException('expected an attribute description in the filter');
    }

    /**
     * assertionvalue run up to the next structural '(' or ')', validating
     * "\XX" escapes and rejecting Unicode category Cc (control characters,
     * NUL included) — `_ldap_consume_value` in the Python source.
     *
     * @return array{0:string,1:int} [value, next index]
     */
    private static function consumeValue(array $chars, int $i): array
    {
        $n = count($chars);
        $start = $i;
        while ($i < $n) {
            $c = $chars[$i];
            if ($c === '\\') {
                if ($i + 2 >= $n || !self::isHexDigit($chars[$i + 1]) || !self::isHexDigit($chars[$i + 2])) {
                    throw new \RuntimeException("invalid '\\XX' escape in filter value");
                }
                $i += 3;
                continue;
            }
            if ($c === '(' || $c === ')') {
                break;
            }
            if (preg_match('/^\p{Cc}$/u', $c) === 1) {
                throw new \RuntimeException('filter value must not contain control characters');
            }
            $i++;
        }
        return [implode('', array_slice($chars, $start, $i - $start)), $i];
    }

    /** extensible = [attr] [":dn"] [":" matchingrule] ":=" assertionvalue */
    private static function parseExtensible(array $chars, int $i, ?string $attr): int
    {
        $n = count($chars);

        // ":dn" is the fixed dnattrs marker (RFC 4515), case-insensitive,
        // only when NOT the start of a longer matching-rule name (e.g.
        // "dnFoo") — every valid continuation starts with ':', so the
        // marker must be followed immediately by another ':'.
        $slice3 = implode('', array_slice($chars, $i, 3));
        if (strtolower($slice3) === ':dn' && $i + 3 < $n && $chars[$i + 3] === ':') {
            $i += 3;
        }

        $matchingRule = null;
        if (implode('', array_slice($chars, $i, 2)) !== ':=') {
            if ($i < $n && $chars[$i] === ':') {
                $j = $i + 1;
                $k = $j;
                while ($k < $n && $chars[$k] !== ':' && $chars[$k] !== '=' && $chars[$k] !== '(') {
                    $k++;
                }
                $matchingRule = implode('', array_slice($chars, $j, $k - $j));
                if ($matchingRule === '' || !self::isValidOidOrDescr($matchingRule)) {
                    throw new \RuntimeException('invalid matching rule in extensible filter');
                }
                $i = $k;
            }
        }

        if (implode('', array_slice($chars, $i, 2)) !== ':=') {
            throw new \RuntimeException("expected ':=' in extensible filter");
        }
        $i += 2;

        if ($attr === null && $matchingRule === null) {
            throw new \RuntimeException('extensible filter needs an attribute or a matching rule');
        }

        [, $i] = self::consumeValue($chars, $i);
        return $i;
    }

    private static function parseItem(array $chars, int $i): int
    {
        $n = count($chars);
        if ($i < $n && $chars[$i] === ':') {
            return self::parseExtensible($chars, $i, null);
        }

        [$attr, $i] = self::consumeAttr($chars, $i);

        if ($i < $n && $chars[$i] === ':') {
            return self::parseExtensible($chars, $i, $attr);
        }

        $two = implode('', array_slice($chars, $i, 2));
        if (in_array($two, ['>=', '<=', '~='], true)) {
            $op = $two;
            $i += 2;
        } elseif ($i < $n && $chars[$i] === '=') {
            $op = '=';
            $i += 1;
        } else {
            throw new \RuntimeException('expected a filter operator after the attribute');
        }

        [$value, $i] = self::consumeValue($chars, $i);

        // Only "=" carries substring semantics; a raw, unescaped '*' in a
        // >=/<=/~= value is meaningless and rejected rather than silently
        // accepted as a literal asterisk.
        if ($op !== '=' && strpos($value, '*') !== false) {
            throw new \RuntimeException("'{$op}' filter values must not contain an unescaped '*'");
        }

        return $i;
    }

    /** FILTER = '(' FILTERCOMP ')'. Returns the index just past ')'. */
    private static function parseFilter(array $chars, int $i, int $depth): int
    {
        if ($depth > self::EXTENDED_QUERY_MAX_DEPTH) {
            throw new \RuntimeException(
                "'ldap_extended_query' nests too deeply (max " . self::EXTENDED_QUERY_MAX_DEPTH . ')'
            );
        }
        $n = count($chars);
        if ($i >= $n || $chars[$i] !== '(') {
            throw new \RuntimeException("expected '(' to start a filter");
        }
        $i = self::parseFilterComp($chars, $i + 1, $depth + 1);
        if ($i >= $n || $chars[$i] !== ')') {
            throw new \RuntimeException('unbalanced parentheses in filter');
        }
        return $i + 1;
    }

    private static function parseFilterComp(array $chars, int $i, int $depth): int
    {
        $n = count($chars);
        if ($i >= $n) {
            throw new \RuntimeException('empty filter expression');
        }
        $c = $chars[$i];
        if ($c === '&' || $c === '|') {
            $i += 1;
            if ($i >= $n || $chars[$i] !== '(') {
                throw new \RuntimeException("'&'/'|' must be followed by at least one filter");
            }
            while ($i < $n && $chars[$i] === '(') {
                $i = self::parseFilter($chars, $i, $depth);
            }
            return $i;
        }
        if ($c === '!') {
            return self::parseFilter($chars, $i + 1, $depth);
        }
        return self::parseItem($chars, $i);
    }

    /**
     * Validate `ldap_extended_query` as exactly one RFC 4515 filter item
     * in *stored* form (without the outer parentheses OPNsense wraps it
     * in when composing the effective query).
     *
     * @param int $maxLen the length gate to enforce — defaults to the
     *   AUTHORING cap (the raw user-typed field). The COMPOSED
     *   effective query (user query + reserved-name negations) is a
     *   different value with its own, independently-set cap
     *   (`COMPOSED_EXCLUSION_MAX_LEN`, 16384 — see that constant's doc
     *   comment) — pass it when validating that one (see
     *   `verifyExclusionShape()`); this parser never conflates the two.
     * @throws \RuntimeException on anything else, including trailing
     *   characters after a complete filter item and unbalanced parens.
     */
    public static function parseLdapExtendedQuery(string $value, int $maxLen = self::EXTENDED_QUERY_MAX_LEN): void
    {
        if ($value === '') {
            throw new \RuntimeException("'ldap_extended_query' must not be empty");
        }
        $chars = self::mbChars($value);
        if (count($chars) > $maxLen) {
            throw new \RuntimeException(
                "'ldap_extended_query' exceeds {$maxLen} characters"
            );
        }
        $end = self::parseFilterComp($chars, 0, 0);
        if ($end !== count($chars)) {
            throw new \RuntimeException("'ldap_extended_query' must parse as exactly one filter item");
        }
    }

    /**
     * Decompose a top-level `&(...)(...)...` filter into its immediate
     * child filter-item strings (parens stripped), by paren-depth
     * scanning. Escaped parens ("\28"/"\29") are always 3-char hex escapes
     * inside an assertionvalue — RFC 4515 never allows a literal unescaped
     * paren in a value — so a raw depth count is structurally correct
     * (consumeValue() above enforces the same rule while accepting the
     * string in the first place).
     *
     * Used only by `verifyExclusionShape()` below to confirm a
     * helper-composed string decomposes exactly the way it was built,
     * never on arbitrary untrusted input.
     *
     * @throws \RuntimeException if `$s` is not exactly one top-level AND
     *   filter of one or more balanced parenthesised children.
     */
    public static function topLevelAndChildren(string $s): array
    {
        $chars = self::mbChars($s);
        $n = count($chars);
        if ($n < 1 || $chars[0] !== '&') {
            throw new \RuntimeException('not an AND filter');
        }
        $i = 1;
        $children = [];
        while ($i < $n && $chars[$i] === '(') {
            $depth = 0;
            $start = $i + 1;
            do {
                if (!isset($chars[$i])) {
                    throw new \RuntimeException('unbalanced parentheses');
                }
                if ($chars[$i] === '(') {
                    $depth++;
                } elseif ($chars[$i] === ')') {
                    $depth--;
                }
                $i++;
            } while ($depth > 0);
            $children[] = implode('', array_slice($chars, $start, ($i - 1) - $start));
        }
        if ($i !== $n) {
            throw new \RuntimeException('trailing content after AND filter');
        }
        if (empty($children)) {
            throw new \RuntimeException('AND filter has no children');
        }
        return $children;
    }

    // -----------------------------------------------------------------
    // Per-element re-validation (defense in depth; a fixed-literal
    // RuntimeException per failure, naming only the rule, never the
    // value). Pure and Config-independent so it is exercised directly by
    // AuthServerAlgoTest.php rather than only by lab evidence.
    // -----------------------------------------------------------------

    public static function hasControlChars(string $value): bool
    {
        return preg_match('/[\x00-\x1F]/', $value) === 1;
    }

    /** JSON `true`/non-empty-truthy for a field the caller has already type-checked. */
    private static function truthyField($value): bool
    {
        if (is_bool($value)) {
            return $value;
        }
        return !($value === null || $value === '' || $value === '0' || $value === 0);
    }

    /**
     * @throws \RuntimeException with `CODE_INVALID_NAME` — a stable
     *   sub-code, never a value. Every distinct name
     *   violation collapses to this one code deliberately: sub-codes
     *   group by RULE CATEGORY
     *   ("_NAME", "_HOST", ...), not by the exact reason within one.
     */
    public static function validateServerName(string $name): void
    {
        if ($name === '' || mb_strlen($name, 'UTF-8') > self::SERVER_NAME_MAX_LEN) {
            throw new \RuntimeException(self::CODE_INVALID_NAME);
        }
        if (rtrim($name) !== $name || ltrim($name) !== $name) {
            throw new \RuntimeException(self::CODE_INVALID_NAME);
        }
        if (preg_match(self::SERVER_NAME_RE, $name) !== 1) {
            throw new \RuntimeException(self::CODE_INVALID_NAME);
        }
        $reservedLower = array_map('strtolower', self::RESERVED_SERVER_NAMES);
        if (in_array(strtolower($name), $reservedLower, true)) {
            throw new \RuntimeException(self::CODE_INVALID_NAME);
        }
    }

    /**
     * Re-validates every field's shape: strict key/value types, the
     * name-adjacent shape rules, the urltype allow-list, the cleartext
     * acknowledgement, the extended-query parser, the bind-pair
     * invariant (both or neither, never a silent anonymous fallback),
     * memberOf sync needing Limit groups and ldap_read_properties, the
     * create_local_users prerequisite, the caseInSensitiveUsernames
     * allow-list, protected group names in the CSV fields, and no
     * control characters in any resolved string value.
     *
     * NDManager's build-time validators are authoritative for full
     * shape; this is device-side defense in depth against a helper
     * called directly, an old control-plane build, or a bug in the
     * build path.
     *
     * @throws \RuntimeException on the first violation found, its
     *   message one of the `CODE_INVALID_*` sub-codes (never a value).
     *   Grouped by rule CATEGORY ("_NAME, _HOST, _BIND_PAIR,
     *   _EXTENDED_QUERY, _GROUPS…") rather than one code per exact
     *   sub-reason.
     */
    public static function validateServerFieldsShape(array $fields): void
    {
        foreach ($fields as $key => $_) {
            if (!in_array($key, self::AUTH_SERVER_WRITABLE_KEYS, true) && !in_array($key, self::AUTH_SERVER_ND_KEYS, true)) {
                throw new \RuntimeException(self::CODE_INVALID_UNKNOWN_FIELD);
            }
        }

        foreach (self::BOOLEAN_KEYS as $key) {
            if (array_key_exists($key, $fields) && !is_bool($fields[$key])) {
                throw new \RuntimeException(self::CODE_INVALID_FIELD_TYPE);
            }
        }
        if (array_key_exists('nd_allow_cleartext_ldap', $fields) && !is_bool($fields['nd_allow_cleartext_ldap'])) {
            throw new \RuntimeException(self::CODE_INVALID_FIELD_TYPE);
        }
        foreach (self::AUTH_SERVER_WRITABLE_KEYS as $key) {
            if (in_array($key, self::BOOLEAN_KEYS, true) || $key === 'ldap_port') {
                continue;
            }
            if (array_key_exists($key, $fields) && !is_string($fields[$key])) {
                throw new \RuntimeException(self::CODE_INVALID_FIELD_TYPE);
            }
        }
        if (array_key_exists('ldap_port', $fields)) {
            $port = $fields['ldap_port'];
            $portOk = (is_int($port) && $port >= 1 && $port <= 65535)
                || (is_string($port) && ctype_digit($port) && (int)$port >= 1 && (int)$port <= 65535);
            if (!$portOk) {
                throw new \RuntimeException(self::CODE_INVALID_FIELD_TYPE);
            }
        }

        foreach (['host', 'ldap_basedn', 'ldap_authcn', 'ldap_attr_user', 'ldap_extended_query', 'ldap_protver', 'ldap_scope', 'ldap_binddn'] as $strField) {
            if (isset($fields[$strField]) && is_string($fields[$strField]) && self::hasControlChars($fields[$strField])) {
                throw new \RuntimeException(self::CODE_INVALID_CONTROL_CHARS);
            }
        }
        if (isset($fields['host']) && is_string($fields['host'])) {
            if ($fields['host'] === '' || mb_strlen($fields['host'], 'UTF-8') > self::HOST_MAX_LEN
                // \z, not $ — see isValidOidOrDescr()'s doc comment.
                || preg_match('/^[A-Za-z0-9.:-]+\z/', $fields['host']) !== 1) {
                throw new \RuntimeException(self::CODE_INVALID_HOST);
            }
        }
        if (isset($fields['ldap_basedn']) && is_string($fields['ldap_basedn'])
            && mb_strlen($fields['ldap_basedn'], 'UTF-8') > self::BASEDN_MAX_LEN) {
            throw new \RuntimeException(self::CODE_INVALID_BASEDN);
        }
        if (isset($fields['ldap_authcn']) && is_string($fields['ldap_authcn'])
            && mb_strlen($fields['ldap_authcn'], 'UTF-8') > self::AUTHCN_MAX_LEN) {
            throw new \RuntimeException(self::CODE_INVALID_AUTHCN);
        }
        if (isset($fields['ldap_attr_user']) && is_string($fields['ldap_attr_user'])
            // \z, not $ — see isValidOidOrDescr()'s doc comment.
            && preg_match('/^[A-Za-z][A-Za-z0-9-]*\z/', $fields['ldap_attr_user']) !== 1) {
            throw new \RuntimeException(self::CODE_INVALID_ATTR_USER);
        }
        // Same shape as ldap_attr_user (NDDataModels mirrors this too); a
        // present-but-empty value is left to buildEffectiveFields()'s own
        // LDAP_ATTR_MEMBEROF_DEFAULT fallback, not rejected here.
        if (isset($fields['ldap_attr_memberof']) && is_string($fields['ldap_attr_memberof'])
            && $fields['ldap_attr_memberof'] !== ''
            && preg_match('/^[A-Za-z][A-Za-z0-9-]*\z/', $fields['ldap_attr_memberof']) !== 1) {
            throw new \RuntimeException(self::CODE_INVALID_ATTR_MEMBEROF);
        }

        $urltype = $fields['ldap_urltype'] ?? null;
        if ($urltype !== null && !in_array($urltype, self::LDAP_URLTYPES, true)) {
            throw new \RuntimeException(self::CODE_INVALID_URLTYPE);
        }
        if ($urltype === 'TCP - Standard' && ($fields['nd_allow_cleartext_ldap'] ?? false) !== true) {
            throw new \RuntimeException(self::CODE_INVALID_URLTYPE);
        }

        if (isset($fields['ldap_protver']) && $fields['ldap_protver'] !== '' && $fields['ldap_protver'] !== '3') {
            throw new \RuntimeException(self::CODE_INVALID_PROTOCOL);
        }
        if (isset($fields['ldap_scope']) && $fields['ldap_scope'] !== '' && !in_array($fields['ldap_scope'], ['one', 'subtree'], true)) {
            throw new \RuntimeException(self::CODE_INVALID_PROTOCOL);
        }

        if (isset($fields['ldap_extended_query']) && $fields['ldap_extended_query'] !== '') {
            try {
                self::parseLdapExtendedQuery((string)$fields['ldap_extended_query']);
            } catch (\RuntimeException $e) {
                // parseLdapExtendedQuery() keeps its own detailed, RFC-4515-
                // specific messages for its direct callers/tests (it is a
                // general-purpose parser, not AUTH_SERVER-specific) — this
                // call site normalizes whatever it throws into the stable
                // sub-code a consumer of THIS function's result can key on.
                throw new \RuntimeException(self::CODE_INVALID_EXTENDED_QUERY);
            }
        }

        $binddn = $fields['ldap_binddn'] ?? null;
        $bindpw = $fields['ldap_bindpw'] ?? null;
        $binddnSet = $binddn !== null && $binddn !== '';
        $bindpwSet = $bindpw !== null && $bindpw !== '';
        if ($binddnSet !== $bindpwSet) {
            throw new \RuntimeException(self::CODE_INVALID_BIND_PAIR);
        }

        foreach (['ldap_sync_memberof_groups', 'ldap_sync_default_groups'] as $csvField) {
            if (empty($fields[$csvField])) {
                continue;
            }
            $groups = explode(',', (string)$fields[$csvField]);
            // "A CSV of up to 16 GROUP names" — device-side defense
            // in depth (NDManager's build-time validator is authoritative).
            if (count($groups) > self::GROUP_CSV_MAX_ENTRIES) {
                throw new \RuntimeException(self::CODE_INVALID_GROUPS);
            }
            // Mirrors NDDataModels' `_validate_auth_group_csv`: no empty
            // entry, no leading/trailing whitespace, no control
            // characters, no protected name, and no case-insensitive
            // duplicate — every rule that decides what actually gets
            // written to config.xml, not just the entry count.
            $seenLower = [];
            foreach ($groups as $group) {
                if ($group === '') {
                    throw new \RuntimeException(self::CODE_INVALID_GROUPS);
                }
                if (trim($group) !== $group) {
                    throw new \RuntimeException(self::CODE_INVALID_GROUPS);
                }
                if (self::hasControlChars($group)) {
                    throw new \RuntimeException(self::CODE_INVALID_GROUPS);
                }
                $lower = strtolower($group);
                if (in_array($lower, self::PROTECTED_GROUP_NAMES, true)) {
                    throw new \RuntimeException(self::CODE_INVALID_GROUPS);
                }
                if (isset($seenLower[$lower])) {
                    throw new \RuntimeException(self::CODE_INVALID_GROUPS);
                }
                $seenLower[$lower] = true;
            }
        }

        $memberofSync = self::truthyField($fields['ldap_sync_memberof'] ?? null);
        $memberofGroups = trim((string)($fields['ldap_sync_memberof_groups'] ?? ''));
        if ($memberofSync) {
            if ($memberofGroups === '') {
                throw new \RuntimeException(self::CODE_INVALID_GROUPS);
            }
            if (!self::truthyField($fields['ldap_read_properties'] ?? null)) {
                throw new \RuntimeException(self::CODE_INVALID_GROUPS);
            }
        }

        $createLocalUsers = self::truthyField($fields['ldap_sync_create_local_users'] ?? null);
        $defaultGroups = trim((string)($fields['ldap_sync_default_groups'] ?? ''));
        if ($createLocalUsers && !$memberofSync && $defaultGroups === '') {
            throw new \RuntimeException(self::CODE_INVALID_GROUPS);
        }

        if (self::truthyField($fields['caseInSensitiveUsernames'] ?? null)) {
            $attrUser = strtolower((string)($fields['ldap_attr_user'] ?? ''));
            if (!in_array($attrUser, self::CASE_INSENSITIVE_OK_ATTRS, true)) {
                throw new \RuntimeException(self::CODE_INVALID_CASE_INSENSITIVE);
            }
        }
    }

    /**
     * "Required": `host`, `ldap_port`, `ldap_urltype`,
     * `ldap_protver`, `ldap_scope`, `ldap_basedn`, `ldap_authcn` and
     * `ldap_attr_user` — device-side defense in depth (NDManager's
     * build-time validator is authoritative; a valid AUTH_SERVER
     * payload always carries the full canonical field set, never a
     * partial patch, so an absent required key here means a
     * malformed/buggy request, not a legitimate partial update).
     * `validateServerFieldsShape()` only checks the FORMAT of a field
     * that is present — this is the separate presence check, mirroring
     * NDDataModels' `validate_auth_server_snippet_content` (which
     * requires every one of these keys, not just basedn/authcn).
     * Deliberately a SEPARATE function from `validateServerFieldsShape()`
     * rather than folded into it: that function is exercised directly,
     * one rule at a time, against intentionally-partial field maps in
     * `AuthServerAlgoTest.php`, and enforcing required-ness there would
     * force every one of those fixtures to carry the full field set
     * regardless of which single rule each is testing.
     *
     * @throws \RuntimeException with the same sub-code
     *   `validateServerFieldsShape()` uses for that field's format.
     */
    public static function validateServerFieldsRequired(array $fields): void
    {
        if (!isset($fields['ldap_basedn']) || !is_string($fields['ldap_basedn']) || $fields['ldap_basedn'] === '') {
            throw new \RuntimeException(self::CODE_INVALID_BASEDN);
        }
        if (!isset($fields['ldap_authcn']) || !is_string($fields['ldap_authcn']) || $fields['ldap_authcn'] === '') {
            throw new \RuntimeException(self::CODE_INVALID_AUTHCN);
        }
        if (!isset($fields['host']) || !is_string($fields['host']) || $fields['host'] === '') {
            throw new \RuntimeException(self::CODE_INVALID_HOST);
        }
        if (!isset($fields['ldap_port']) || $fields['ldap_port'] === '') {
            throw new \RuntimeException(self::CODE_INVALID_FIELD_TYPE);
        }
        if (!isset($fields['ldap_urltype']) || $fields['ldap_urltype'] === '') {
            throw new \RuntimeException(self::CODE_INVALID_URLTYPE);
        }
        if (!isset($fields['ldap_protver']) || $fields['ldap_protver'] === '') {
            throw new \RuntimeException(self::CODE_INVALID_PROTOCOL);
        }
        if (!isset($fields['ldap_scope']) || $fields['ldap_scope'] === '') {
            throw new \RuntimeException(self::CODE_INVALID_PROTOCOL);
        }
        if (!isset($fields['ldap_attr_user']) || !is_string($fields['ldap_attr_user']) || $fields['ldap_attr_user'] === '') {
            throw new \RuntimeException(self::CODE_INVALID_ATTR_USER);
        }
    }

    /**
     * Device-side defense in depth (NDManager's build-time validator is
     * authoritative): the first case-insensitive duplicate value in
     * `$values`, or null. Shared between two call sites —
     * `AuthServerHelper::planSync()` (duplicate server NAMES within one
     * request's `servers` list) and `planFacilities()` (duplicate AUTH_
     * ORDER entries within one `order` list) — the rule ("no two of
     * these may name the same thing, case-insensitively") is identical;
     * only what a caller does with a hit (a whole-request fault vs. a
     * single facility refusal) differs.
     *
     * @param array<mixed> $values non-string entries are ignored — a
     *   non-string order entry is already caught by the existing
     *   AUTH_ORDER_UNRESOLVED per-entry loop, and a server with no name
     *   at all is already caught as NAME_COLLISION_UNMANAGED.
     */
    public static function findCaseInsensitiveDuplicate(array $values): ?string
    {
        $seen = [];
        foreach ($values as $v) {
            if (!is_string($v) || $v === '') {
                continue;
            }
            $lower = strtolower($v);
            if (isset($seen[$lower])) {
                return $v;
            }
            $seen[$lower] = true;
        }
        return null;
    }

    /**
     * Order-entry syntax — device-side defense in depth (NDManager's
     * build-time AUTH_ORDER validator is authoritative): no comma
     * (`explode(',')` on write would otherwise silently split one
     * "entry" into two tokens) and no control characters.
     *
     * @throws \RuntimeException naming only the rule, never the entry.
     */
    public static function validateOrderEntrySyntax(string $entry): void
    {
        if ($entry === '') {
            throw new \RuntimeException('AUTH_ORDER_ENTRY_INVALID');
        }
        if (strpos($entry, ',') !== false) {
            throw new \RuntimeException('AUTH_ORDER_ENTRY_INVALID');
        }
        if (self::hasControlChars($entry)) {
            throw new \RuntimeException('AUTH_ORDER_ENTRY_INVALID');
        }
    }

    // -----------------------------------------------------------------
    // The Local Database rule: webadmin.order[0] must be "Local Database"
    //
    // Ported verbatim from NDDataModels' `local_database_rule()` and
    // pinned against the same fixture table
    // (tests/fixtures/auth/local_database_rule.json — see
    // plugin/tests/fixtures/auth/SOURCE.md).
    // -----------------------------------------------------------------

    /** @throws \RuntimeException naming only the rule, never the order. */
    public static function localDatabaseRule(array $order): void
    {
        if (empty($order)) {
            throw new \RuntimeException("'order' must be a non-empty list");
        }
        // Strict identity: a JSON boolean/number/null decoded by PHP's
        // json_decode must not loose-compare equal to "Local Database".
        if (!(is_string($order[0]) && $order[0] === self::LOCAL_DATABASE)) {
            throw new \RuntimeException(
                'the first entry of the "webadmin" order must be "Local Database"'
            );
        }
    }

    // -----------------------------------------------------------------
    // Order tokenization — exactly as OPNsense tokenizes it.
    // -----------------------------------------------------------------

    /** `explode(',')`, no trimming, no case folding. */
    public static function tokenizeOrderList(string $csv): array
    {
        return explode(',', $csv);
    }

    public static function joinOrderList(array $names): string
    {
        return implode(',', $names);
    }

    // -----------------------------------------------------------------
    // Resolution set / order-consistency check
    // -----------------------------------------------------------------

    /**
     * Every name in `$order` that does not byte-exactly match a
     * name in `$resolutionSet`. Returns unresolved names in `$order`'s
     * original order, duplicates included (so the caller can report each
     * miss once per occurrence if desired — callers dedupe if they only
     * want the message to list distinct names).
     */
    public static function resolveOrder(array $order, array $resolutionSet): array
    {
        $set = array_flip($resolutionSet);
        $unresolved = [];
        foreach ($order as $name) {
            if (!isset($set[$name])) {
                $unresolved[] = $name;
            }
        }
        return $unresolved;
    }

    // -----------------------------------------------------------------
    // The dangling-token create check
    // -----------------------------------------------------------------

    /**
     * A new server's exact name is a dangling token if it already appears
     * in a live curated consumer list read *before* any write. The create
     * is allowed only when every consumer that names it is a facility
     * whose policy write is decided "written" in this same save.
     *
     * @param string $newName the server name about to be created.
     * @param array<string,array<string>> $preWriteConsumerLists consumer
     *   key (a facility name, or a non-facility curated-path label such
     *   as "openvpn:<uuid>") => list of names it references, read from
     *   live state before any write this save.
     * @param array<string,string> $facilityDecisions facility name =>
     *   "written"|"unchanged"|"refused" decided this save. Only facility
     *   keys can ever appear here — a non-facility consumer key is looked
     *   up and never found, so it can never satisfy the exemption, which
     *   is intentional: NetDefense cannot "decide" an OpenVPN/IPsec/
     *   Captive Portal list this save.
     *
     *   Both "written" AND "unchanged" satisfy the exemption: a
     *   facility whose policy already, explicitly, holds this token
     *   (re-asserted byte-for-byte this same save) is exactly as
     *   intentional a reference as one this save just wrote — refusing
     *   the create there would deadlock a forced re-sync after the admin
     *   hand-deleted the managed server while the policy still names it,
     *   since the create is refused
     *   (CREATE_ACTIVATES_LOGIN_PATH) and the facility is then refused as
     *   SERVER_NOT_APPLIED, forever.
     *
     * @return array<string> the blocking consumer keys (empty = not blocked).
     */
    public static function danglingTokenBlocksCreate(
        string $newName,
        array $preWriteConsumerLists,
        array $facilityDecisions
    ): array {
        $blocking = [];
        foreach ($preWriteConsumerLists as $consumerKey => $names) {
            $decision = $facilityDecisions[$consumerKey] ?? null;
            if (in_array($newName, $names, true) && !in_array($decision, ['written', 'unchanged'], true)) {
                $blocking[] = $consumerKey;
            }
        }
        return $blocking;
    }

    // -----------------------------------------------------------------
    // Helper group check — GROUP_NAME_AMBIGUOUS
    // -----------------------------------------------------------------

    /**
     * True when `$candidateName` (a Limit/default group name on a
     * managed server) collides, case-insensitively, with a live
     * group NetDefense does not manage as an external GROUP in this
     * payload. A name with no live group yet is never ambiguous — OPNsense
     * ignores an unknown group name until users/groups creates it later in
     * the same SYNC.
     *
     * @param array<string> $liveGroupNames every live OPNsense group name.
     * @param array<string> $payloadExternalGroupNamesLower the lowercased
     *   names of every external GROUP in this device's payload.
     */
    public static function groupNameAmbiguous(
        string $candidateName,
        array $liveGroupNames,
        array $payloadExternalGroupNamesLower
    ): bool {
        $candidateLower = strtolower($candidateName);
        foreach ($liveGroupNames as $liveName) {
            if (strtolower($liveName) === $candidateLower) {
                return !in_array($candidateLower, $payloadExternalGroupNamesLower, true);
            }
        }
        return false;
    }

    // -----------------------------------------------------------------
    // Reserved-name exclusion — composed into every managed server's
    // ldap_extended_query so a directory account sharing a reserved
    // name can never log in
    // -----------------------------------------------------------------

    /** RFC 4515 value escaping — mirrors OPNsense's own `ldap_escape()`. */
    public static function ldapEscape(string $value): string
    {
        return strtr($value, [
            '\\' => '\5c',
            '*' => '\2a',
            '(' => '\28',
            ')' => '\29',
            "\x00" => '\00',
        ]);
    }

    /**
     * Build the effective `ldap_extended_query`:
     * `&(<uq | objectClass=*>)(!(<attr>=<n>))…` — the user's own query (or
     * a default presence filter when none is set) ANDed with one negated
     * equality clause per reserved name, names escaped.
     *
     * @param array<string> $reservedNames already resolved, in a stable
     *   (sorted) order — callers must sort for deterministic output so
     *   `verifyExclusionShape()` and any "unchanged" comparison agree run
     *   to run.
     */
    public static function composeExclusionQuery(?string $userQuery, string $attrUser, array $reservedNames): string
    {
        $uqPart = ($userQuery !== null && $userQuery !== '') ? $userQuery : 'objectClass=*';
        $parts = ['(' . $uqPart . ')'];
        foreach ($reservedNames as $name) {
            $parts[] = '(!(' . $attrUser . '=' . self::ldapEscape($name) . '))';
        }
        return '&' . implode('', $parts);
    }

    /**
     * Before any write, confirm a composed exclusion query (a) still
     * parses as exactly one valid RFC 4515 filter item, and (b) decomposes
     * into exactly the shape `composeExclusionQuery()` built: the user
     * query (or default) first, then one `!(<attr>=<escaped name>)` per
     * reserved name, in the same order.
     *
     * @throws \RuntimeException on any mismatch, naming only the shape
     *   check, never a value.
     */
    public static function verifyExclusionShape(
        string $composed,
        ?string $userQuery,
        string $attrUser,
        array $reservedNames
    ): void {
        self::parseLdapExtendedQuery($composed, self::COMPOSED_EXCLUSION_MAX_LEN);

        $children = self::topLevelAndChildren($composed);
        $expectedUq = ($userQuery !== null && $userQuery !== '') ? $userQuery : 'objectClass=*';
        $expected = [$expectedUq];
        foreach ($reservedNames as $name) {
            $expected[] = '!(' . $attrUser . '=' . self::ldapEscape($name) . ')';
        }

        if ($children !== $expected) {
            throw new \RuntimeException('composed exclusion query did not parse back to the expected shape');
        }
    }

    /**
     * Which of `$candidateNames` a (possibly foreign) effective query
     * already excludes, per the exact shape `composeExclusionQuery()`
     * builds. A query that fails to parse as a top-level AND covers
     * nothing (fail-closed — an unparseable live value is never treated
     * as covering a name it might not).
     *
     * @return array<string> the subset of `$candidateNames` covered.
     */
    public static function coveredReservedNames(?string $effectiveQuery, string $attrUser, array $candidateNames): array
    {
        if ($effectiveQuery === null || $effectiveQuery === '') {
            return [];
        }
        try {
            $children = self::topLevelAndChildren($effectiveQuery);
        } catch (\RuntimeException $e) {
            return [];
        }
        $covered = [];
        foreach ($candidateNames as $name) {
            $needle = '!(' . $attrUser . '=' . self::ldapEscape($name) . ')';
            if (in_array($needle, $children, true)) {
                $covered[] = $name;
            }
        }
        return $covered;
    }

    /**
     * Deliberate deviation from the reject_dangerous gate: true iff `$newQuery` is `$liveQuery`
     * with only reserved-name exclusion terms ADDED — the user-query part
     * (child 0) is byte-identical, and every negated term `$liveQuery`
     * already has is still present in `$newQuery`. False (never a write)
     * when `$liveQuery` does not parse as the helper's own AND shape, so
     * an already-foreign/hand-edited value is never treated as a base to
     * narrow from.
     */
    public static function isNarrowingOnly(string $liveQuery, string $newQuery): bool
    {
        try {
            $liveChildren = self::topLevelAndChildren($liveQuery);
            $newChildren = self::topLevelAndChildren($newQuery);
        } catch (\RuntimeException $e) {
            return false;
        }
        if (empty($liveChildren) || empty($newChildren) || $liveChildren[0] !== $newChildren[0]) {
            return false;
        }
        $liveNegations = array_slice($liveChildren, 1);
        $newNegations = array_slice($newChildren, 1);
        foreach ($liveNegations as $neg) {
            if (!in_array($neg, $newNegations, true)) {
                return false;
            }
        }
        return count($newNegations) >= count($liveNegations);
    }

    /** Inverse of `ldapEscape()` — "\XX" hex-pair escapes decoded back to raw bytes. */
    public static function ldapUnescape(string $value): string
    {
        return (string)preg_replace_callback('/\\\\([0-9A-Fa-f]{2})/', static function (array $m): string {
            return chr((int)hexdec($m[1]));
        }, $value);
    }

    /**
     * "Terms are only ever added": the reserved names a
     * LIVE effective query already excludes, read directly off its
     * `(!(<attr>=<escaped name>))` children — regardless of what
     * `$attrUser` currently is, since the live terms were composed
     * against whatever attribute was live AT THE TIME. Used only to UNION
     * into a freshly-composed query so a name dropping out of THIS save's
     * `reserved_names_desired` can never look like the composed query got
     * narrower than the live one — which would otherwise turn a benign
     * save into a refused "widening" under `reject_dangerous`, even though
     * nothing was actually removed from what the device already excludes.
     *
     * Never used to decide coverage (`coveredReservedNames()` does that).
     * A live value that fails to parse as this helper's own AND shape
     * yields no names — fail-closed: nothing is "recovered" from a
     * foreign/hand-edited value, matching `coveredReservedNames()`'s own
     * fail-closed rule.
     *
     * @return array<string> unescaped names, in the order they appear.
     */
    public static function extractExcludedNames(?string $liveQuery): array
    {
        if ($liveQuery === null || $liveQuery === '') {
            return [];
        }
        try {
            $children = self::topLevelAndChildren($liveQuery);
        } catch (\RuntimeException $e) {
            return [];
        }
        $names = [];
        foreach (array_slice($children, 1) as $child) {
            if (preg_match('/^!\([^=]+=(.*)\)$/', $child, $m) === 1) {
                $names[] = self::ldapUnescape($m[1]);
            }
        }
        return $names;
    }

    // -----------------------------------------------------------------
    // OPNsense release floor comparator
    // -----------------------------------------------------------------

    /**
     * Parse `/usr/local/opnsense/version/core`'s `product_version` into a
     * [major, minor, patch] tuple. Accepts "X.Y", "X.Y.Z" and "X.Y.Z_N"
     * (the revision suffix is parsed but not part of the comparison — any
     * revision of a given patch level satisfies the floor once the patch
     * itself does). A missing patch component (the bare series form a
     * .0 release reports) defaults to patch 0.
     */
    public static function parseReleaseTuple(?string $release): ?array
    {
        if ($release === null || $release === '') {
            return null;
        }
        if (preg_match('/^([0-9]+)\.([0-9]+)(?:\.([0-9]+)(?:_[0-9]+)?)?$/', $release, $m) !== 1) {
            return null;
        }
        $major = (int)$m[1];
        $minor = (int)$m[2];
        $patch = isset($m[3]) && $m[3] !== '' ? (int)$m[3] : 0;
        return [$major, $minor, $patch];
    }

    /** True iff `$release` is `self::FLOOR_RELEASE` or later. Missing/unparseable is false. */
    public static function isReleaseSupported(?string $release): bool
    {
        $tuple = self::parseReleaseTuple($release);
        if ($tuple === null) {
            return false;
        }
        return $tuple >= self::FLOOR_RELEASE; // PHP array comparison is lexicographic here
    }

    // -----------------------------------------------------------------
    // Boolean "unchanged" normalization
    // -----------------------------------------------------------------

    /**
     * An absent element and a present-but-empty element both mean
     * "false" for a config.xml boolean, regardless of which XML shape the
     * OPNsense GUI happened to leave behind (a cast-to-bool field omits
     * the element when unchecked; a bare-assignment `additionalFields`
     * field like `caseInSensitiveUsernames` instead leaves `<x/>`).
     * `$raw` is whatever `config_read_array()`/SimpleXML gives back:
     * null (absent), '' (present-but-empty), or a non-empty string.
     */
    public static function normalizeBoolLeaf($raw): bool
    {
        if ($raw === null || $raw === '' || $raw === false) {
            return false;
        }
        return !in_array($raw, ['0', 0], true);
    }

    public static function boolLeafEqual($a, $b): bool
    {
        return self::normalizeBoolLeaf($a) === self::normalizeBoolLeaf($b);
    }

    // -----------------------------------------------------------------
    // Ownership markers
    // -----------------------------------------------------------------

    public static function formatFacilityOwnerMarker(string $deviceUuid, string $writtenValue): string
    {
        return $deviceUuid . ':' . hash('sha256', $writtenValue);
    }

    /** @return array{0:string,1:string}|null [uuid, sha256hex], or null if malformed. */
    public static function parseFacilityOwnerMarker(string $marker): ?array
    {
        $pos = strrpos($marker, ':');
        if ($pos === false || $pos === 0 || $pos === strlen($marker) - 1) {
            return null;
        }
        return [substr($marker, 0, $pos), substr($marker, $pos + 1)];
    }

    // -----------------------------------------------------------------
    // Write allow-list diff — the backstop that catches any mutation
    // outside the paths this class is allowed to touch
    //
    // A flat-map structural diff: every leaf text node in a document is
    // reduced to `path => value`, siblings with the same tag indexed
    // positionally so repeated elements (system/authserver[]) don't
    // collide. Comparing the two flat maps' key sets and values gives the
    // exact set of changed/added/removed leaf paths, independent of which
    // OPNsense config wrapper element the document happens to use — no
    // OPNsense dependency, so this is unit-testable with plain XML
    // strings.
    //
    // Round-2 fix (item 2): leaf TEXT alone is not the whole document.
    // Two axes were previously invisible to this differ, both closeable
    // without any OPNsense dependency:
    //   - XML ATTRIBUTES. `DOMNode::childNodes` never yields attribute
    //     nodes, so a value that moved from an element's text into (or
    //     out of) an attribute on that SAME element, or an attribute that
    //     simply changed while the element's own text stayed put, was
    //     invisible — outside the allow-list, that is exactly the kind of
    //     mutation the write allow-list diff exists to catch.
    //   - ELEMENT PRESENCE. Pure leaf-text diffing gets this right almost
    //     by construction (an absent leaf is `null`, a present-but-empty
    //     one is `''`, and `null !== ''`), but it depends on that
    //     coincidence rather than saying so — every visited node (leaf or
    //     container) now also gets an explicit presence marker, so a node
    //     appearing or disappearing is caught on its own terms rather
    //     than as a side effect of how its leaf/attribute values happen
    //     to compare.
    // -----------------------------------------------------------------

    /**
     * A NUL-prefixed suffix — guaranteed to never collide with a real XML
     * tag name (NUL cannot appear in one) — marking a node's own
     * existence, independent of any leaf text or attribute value it
     * carries.
     */
    private const PRESENCE_SUFFIX = "\x00#present";

    private static function flattenXmlNode(\DOMNode $node, string $path, array &$out): void
    {
        $out[$path . self::PRESENCE_SUFFIX] = '1';

        if ($node instanceof \DOMElement && $node->hasAttributes()) {
            foreach ($node->attributes as $attr) {
                /** @var \DOMAttr $attr */
                $out["{$path}/@{$attr->nodeName}"] = $attr->nodeValue;
            }
        }

        $childElements = [];
        $hasElementChild = false;
        foreach ($node->childNodes as $child) {
            if ($child->nodeType === XML_ELEMENT_NODE) {
                $hasElementChild = true;
                $childElements[] = $child;
            }
        }

        if (!$hasElementChild) {
            $out[$path] = $node->textContent;
            return;
        }

        // Index only tags that actually repeat, so a document with no
        // repeated siblings at a given level produces plain "a/b/c"
        // paths — an allow-list prefix like "system/authserver" then
        // matches every entry without the caller having to spell out
        // "[0]"/"[1]"/... for tags that happen to occur only once today
        // but may repeat tomorrow (system/authserver is exactly that
        // case: zero, one or many entries).
        $counts = [];
        foreach ($childElements as $child) {
            $counts[$child->nodeName] = ($counts[$child->nodeName] ?? 0) + 1;
        }

        $seen = [];
        foreach ($childElements as $child) {
            /** @var \DOMElement $child */
            $tag = $child->nodeName;
            if ($counts[$tag] > 1) {
                $idx = $seen[$tag] ?? 0;
                $seen[$tag] = $idx + 1;
                $segment = "{$tag}[{$idx}]";
            } else {
                $segment = $tag;
            }
            self::flattenXmlNode($child, $path === '' ? $segment : "{$path}/{$segment}", $out);
        }
    }

    /** @return array<string,string> path => leaf text content. */
    public static function flattenXml(string $xml): array
    {
        $doc = new \DOMDocument();
        $doc->preserveWhiteSpace = false;
        $prevUseErrors = libxml_use_internal_errors(true);
        $ok = $doc->loadXML($xml);
        libxml_clear_errors();
        libxml_use_internal_errors($prevUseErrors);
        if (!$ok || $doc->documentElement === null) {
            throw new \RuntimeException('invalid XML document');
        }
        $out = [];
        self::flattenXmlNode($doc->documentElement, '', $out);
        return $out;
    }

    /**
     * Diff two XML documents at the leaf-path level and return every
     * changed/added/removed path that does NOT start with one of
     * `$allowedPrefixes`. Empty return means the diff is entirely inside
     * the allow-list (`WRITE_ALLOWLIST_VIOLATION` fires when this is
     * non-empty).
     *
     * @param array<string> $allowedPrefixes e.g. ["system/authserver",
     *   "system/webgui/authmode", "system/webgui/netdefense_authmode_owner"].
     */
    public static function xmlAllowListDiff(string $beforeXml, string $afterXml, array $allowedPrefixes): array
    {
        $before = self::flattenXml($beforeXml);
        $after = self::flattenXml($afterXml);

        $paths = array_unique(array_merge(array_keys($before), array_keys($after)));
        $violations = [];
        foreach ($paths as $path) {
            $b = $before[$path] ?? null;
            $a = $after[$path] ?? null;
            if ($b === $a) {
                continue;
            }
            if (!self::pathAllowed($path, $allowedPrefixes)) {
                $violations[] = $path;
            }
        }
        sort($violations);
        return $violations;
    }

    private static function pathAllowed(string $path, array $allowedPrefixes): bool
    {
        // A presence marker or a trailing "/@attr" attribute segment on a
        // leaf that is ITSELF exactly one of the allowed paths (not just
        // nested under it) needs the marker/segment stripped before the
        // exact-match branch below can recognise it — a nested path
        // already matches via the prefix+'/' / prefix+'[' branches
        // whether or not it's stripped, so this only widens the exact
        // case, never narrows the nested one.
        $normalized = $path;
        if (substr($normalized, -strlen(self::PRESENCE_SUFFIX)) === self::PRESENCE_SUFFIX) {
            $normalized = substr($normalized, 0, -strlen(self::PRESENCE_SUFFIX));
        } elseif (($atPos = strrpos($normalized, '/@')) !== false) {
            $normalized = substr($normalized, 0, $atPos);
        }

        foreach ($allowedPrefixes as $prefix) {
            if (
                $normalized === $prefix
                || strpos($normalized, $prefix . '/') === 0
                || strpos($normalized, $prefix . '[') === 0
            ) {
                return true;
            }
        }
        return false;
    }

    // -----------------------------------------------------------------
    // Pure planning primitives — the `AuthServerHelper::
    // planSync()` seam. Every method below takes plain scalars/arrays
    // only (no \SimpleXMLElement, no Config), the same discipline the
    // rest of this file already follows, so `AuthServerHelper::planSync()`
    // — the Config-independent core of the sync algorithm — can call them
    // and remain directly unit-testable
    // (`plugin/tests/AuthServerHelperPlanSyncTest.php`) without a live
    // config.xml or Phalcon.
    // -----------------------------------------------------------------

    /**
     * Classification. A live server is
     * managed iff it's LDAP-typed and its owner marker names this device;
     * everything else (a foreign owner, no owner at all, or a non-ldap
     * type) is local — this helper never touches it.
     *
     * @param array<array{name:string,type:string,owner:?string}> $liveServers
     * @return array{0:array<string,true>,1:array<string,true>,2:array<string>}
     *   [managedNamesSet, localNamesSet, allNames]
     */
    public static function classifyServers(array $liveServers, string $deviceUuid): array
    {
        $managed = [];
        $local = [];
        $all = [];
        foreach ($liveServers as $srv) {
            $name = (string)($srv['name'] ?? '');
            $all[] = $name;
            $type = (string)($srv['type'] ?? '');
            $owner = $srv['owner'] ?? null;
            if ($type === 'ldap' && $deviceUuid !== '' && $owner === $deviceUuid) {
                $managed[$name] = true;
            } else {
                $local[$name] = true;
            }
        }
        return [$managed, $local, $all];
    }

    /**
     * Every writable key, always populated (never partial) — a modeled
     * key absent from the request means absent (booleans false, the CSV
     * fields empty, the bind pair cleared), never "leave the live value
     * alone". Unmodeled keys are untouched by the caller's write step
     * regardless. `$secret` is read directly off the
     * request's own `fields['ldap_bindpw']` by the caller (never
     * threaded through any other property/argument), falling back to
     * whatever `$fields['ldap_bindpw']` itself carries when null.
     */
    public static function buildEffectiveFields(array $fields, string $composedQuery, ?string $secret): array
    {
        $out = [];
        foreach (self::AUTH_SERVER_WRITABLE_KEYS as $key) {
            if ($key === 'ldap_extended_query') {
                $out[$key] = $composedQuery;
                continue;
            }
            if ($key === 'ldap_bindpw') {
                $out[$key] = $secret ?? (string)($fields[$key] ?? '');
                continue;
            }
            if (in_array($key, self::BOOLEAN_KEYS, true)) {
                $out[$key] = array_key_exists($key, $fields) ? (bool)$fields[$key] : false;
                continue;
            }
            if ($key === 'ldap_attr_memberof') {
                // Absent/empty already falls back to this exact
                // value at OPNsense's own runtime (LDAP.php::
                // setProperties()'s `!empty()` guard — verified read-only
                // on e2e-b) — write it explicitly so config.xml never
                // depends on that fallback and the GUI (which also
                // always posts a literal value) and this helper agree on
                // what is actually live. See LDAP_ATTR_MEMBEROF_DEFAULT's
                // doc comment.
                $val = array_key_exists($key, $fields) ? (string)$fields[$key] : '';
                $out[$key] = $val !== '' ? $val : self::LDAP_ATTR_MEMBEROF_DEFAULT;
                continue;
            }
            $out[$key] = array_key_exists($key, $fields) ? (string)$fields[$key] : '';
        }
        return $out;
    }

    /**
     * Field-level diff between a server's current live
     * values and the effective values a save would write. `$liveFields`
     * is already normalized the way a snapshot reader produces it: a
     * `bool` for every `BOOLEAN_KEYS` entry, `string|null` (null = absent)
     * for everything else.
     *
     * @param array<string,string|null|bool> $liveFields
     * @param array<string,string|bool> $effectiveFields
     * @return array<string> changed field names, or [] for unchanged.
     */
    public static function diffFields(array $liveFields, array $effectiveFields): array
    {
        $changed = [];
        foreach ($effectiveFields as $key => $value) {
            $current = $liveFields[$key] ?? null;
            if (in_array($key, self::BOOLEAN_KEYS, true)) {
                if (self::normalizeBoolLeaf($current) !== self::normalizeBoolLeaf($value ? '1' : null)) {
                    $changed[] = $key;
                }
                continue;
            }
            $desired = (string)$value;
            if ($current === null ? $desired !== '' : $current !== $desired) {
                $changed[] = $key;
            }
        }
        return $changed;
    }

    /**
     * The reserved-name set, always: the static names, every live
     * `scope=system` user, and the request's own list (which is where
     * GROUP-member names arrive — expanding "every member of every
     * member-managed GROUP" is NDManager/NDAgent's job upstream;
     * this helper's contract is simply to never drop a name the request
     * supplies). An empty/missing request list must never mean "no
     * exclusion at all".
     *
     * @param array<string> $requested
     * @param array<string> $scopeSystemUsernames
     * @return array<string> sorted, deduplicated.
     */
    public static function buildReservedNames(array $requested, array $scopeSystemUsernames): array
    {
        $names = self::RESERVED_STATIC_USER_NAMES;
        foreach ($requested as $n) {
            $names[] = (string)$n;
        }
        foreach ($scopeSystemUsernames as $n) {
            $names[] = (string)$n;
        }
        $names = array_values(array_unique(array_filter($names, static fn($n) => $n !== '')));
        // SORT_STRING, not the default SORT_REGULAR — PHP's default sort()
        // compares two numeric-looking strings ("1e3" vs "1000") as
        // NUMBERS, so a purely-cosmetic reordering of otherwise-identical
        // reserved names could rewrite an unchanged exclusion.
        sort($names, SORT_STRING);
        return $names;
    }

    /**
     * Helper group check over one server's fields — GROUP_NAME_AMBIGUOUS.
     * `$liveGroupNamesExcludingManaged` must already exclude every
     * NetDefense-managed (`[nd-template:*]`-tagged) group, the same way
     * the original Config-reading loop did.
     *
     * @return string|null the colliding group name, or null.
     */
    public static function checkGroupAmbiguityInFields(array $fields, array $liveGroupNamesExcludingManaged): ?string
    {
        foreach (['ldap_sync_memberof_groups', 'ldap_sync_default_groups'] as $csvField) {
            if (empty($fields[$csvField])) {
                continue;
            }
            foreach (explode(',', (string)$fields[$csvField]) as $candidate) {
                if ($candidate === '') {
                    continue;
                }
                if (self::groupNameAmbiguous($candidate, $liveGroupNamesExcludingManaged, [])) {
                    return $candidate;
                }
            }
        }
        return null;
    }

    /**
     * Local-server risk labels (never blocking; the admin's own
     * server gets none of NetDefense's guardrails). `$fields` is a plain
     * read-only snapshot of the hand-made server's config.xml fields.
     */
    public static function localServerRisks(array $fields): array
    {
        $risks = ['no_reserved_exclusion']; // always true — NetDefense never composes into a hand-made server (docs)
        if (($fields['ldap_urltype'] ?? '') === 'TCP - Standard') {
            $risks[] = 'cleartext';
        }
        $memberofSync = self::normalizeBoolLeaf($fields['ldap_sync_memberof'] ?? null);
        $groups = (string)($fields['ldap_sync_memberof_groups'] ?? '');
        if ($memberofSync && $groups === '') {
            $risks[] = 'unscoped_sync';
        }
        foreach (['ldap_sync_memberof_groups', 'ldap_sync_default_groups'] as $csvField) {
            $csv = (string)($fields[$csvField] ?? '');
            if ($csv === '') {
                continue;
            }
            foreach (explode(',', $csv) as $g) {
                if (in_array(strtolower($g), self::PROTECTED_GROUP_NAMES, true)) {
                    $risks[] = 'protected_group';
                    break 2;
                }
            }
        }
        return array_values(array_unique($risks));
    }

    /**
     * stale_names: a reserved name is stale if ANY server still live
     * after the sweep (applied, refused/blocked-but-retained, or simply
     * not touched this save) fails to exclude it, computed from the
     * FINAL (post-decision) `ldap_extended_query`/`ldap_attr_user` per
     * server — never from a per-server flag that could only ever be set
     * for a server that reached "applied" (that under-reported: a server
     * rejected by the gate, blocked as invalid, or retained by the sweep
     * with an old, incomplete exclusion never contributed a gap).
     *
     * @param array<string> $reservedNamesDesired
     * @param array<string,array<string,mixed>> $liveManagedFields name =>
     *   its final field map (whatever will actually be live on the device
     *   after this save — the caller decides that per outcome).
     * @param array<string> $deletedNames excluded: a server that no
     *   longer exists cannot shadow anyone.
     */
    public static function computeStaleReservedNames(array $reservedNamesDesired, array $liveManagedFields, array $deletedNames): array
    {
        if (empty($reservedNamesDesired)) {
            return [];
        }
        $liveManaged = array_diff_key($liveManagedFields, array_flip($deletedNames));
        if (empty($liveManaged)) {
            return []; // nothing offers directory login -> nothing can be shadowed through one
        }
        $stale = [];
        foreach ($reservedNamesDesired as $reservedName) {
            foreach ($liveManaged as $fields) {
                $query = $fields['ldap_extended_query'] ?? null;
                $attrUser = (string)($fields['ldap_attr_user'] ?? '');
                $covered = self::coveredReservedNames($query, $attrUser, [$reservedName]);
                if (empty($covered)) {
                    $stale[] = $reservedName;
                    break;
                }
            }
        }
        return array_values(array_unique($stale));
    }

    /**
     * Mirrors NDManager's/`internal/opnapi/dangerous_fields.go`'s
     * canonical blanket-access rule: a comma-split, lowercased/trimmed
     * token is dangerous if it equals `page-all`, ends with `-all`, or
     * contains both `system` and `admin` substrings. Kept in sync
     * manually — there is no shared library between the Go agent and
     * this PHP helper.
     */
    public static function privGrantsBlanketAccess(string $privCsv): bool
    {
        if ($privCsv === '') {
            return false;
        }
        foreach (explode(',', $privCsv) as $token) {
            $token = strtolower(trim($token));
            if (
                $token === 'page-all'
                || (strlen($token) > 4 && substr($token, -4) === '-all')
                || (strpos($token, 'system') !== false && strpos($token, 'admin') !== false)
            ) {
                return true;
            }
        }
        return false;
    }

    /**
     * PRIVILEGED_LOCAL_USERS_SHADOWABLE — every local user who
     * would gain blanket privilege either directly (their own `priv`) or
     * through membership in a group that grants it. An ACL gotcha:
     * OPNsense group `<member>` stores the user's NUMERIC uid, not a
     * config-tree UUID — a user with no direct priv at all is exactly as
     * shadowable through a privileged group, since NetDefense's own
     * reserved-set reasoning ("every member of every member-managed
     * GROUP") applies just as much to users NetDefense doesn't manage.
     *
     * @param array<array{name:string,uid?:string,priv:string}> $users
     * @param array<array{priv:string,member_uids:array<string>}> $groups
     * @param array<string> $excludeNames names ALREADY covered by the
     *   reserved-name exclusion (the static names, every scope=system
     *   user, at minimum — ideally the full `reservedNamesDesired`), so
     *   the warning reports only OTHER privileged users. Without this, the
     *   count is never lower than 2 in practice (`root` and
     *   `netdefense-agent` are both always privileged AND always
     *   statically excluded already, so they can never actually be
     *   "shadowed" by a directory account), which trained the warning to
     *   read as permanently noisy.
     */
    public static function countShadowablePrivilegedUsers(array $users, array $groups, array $excludeNames = []): int
    {
        $excluded = array_fill_keys($excludeNames, true);
        $privileged = [];
        $uidToName = [];
        foreach ($users as $u) {
            $name = (string)($u['name'] ?? '');
            if ($name === '' || isset($excluded[$name])) {
                continue;
            }
            if (isset($u['uid'])) {
                $uidToName[(string)$u['uid']] = $name;
            }
            if (self::privGrantsBlanketAccess((string)($u['priv'] ?? ''))) {
                $privileged[$name] = true;
            }
        }
        foreach ($groups as $g) {
            if (!self::privGrantsBlanketAccess((string)($g['priv'] ?? ''))) {
                continue;
            }
            foreach ((array)($g['member_uids'] ?? []) as $uid) {
                if (isset($uidToName[(string)$uid])) {
                    $privileged[$uidToName[(string)$uid]] = true;
                }
            }
        }
        return count($privileged);
    }

    /**
     * Decommission — whether a facility's owner marker authorizes a
     * reset. `'reset'` when the marker names this device and its stored
     * hash matches the live value byte-for-byte; `'left_changed_since_
     * written'` when it names this device but the admin changed the
     * value since NetDefense wrote it (ORDER_CHANGED_SINCE_WRITTEN);
     * `'not_ours'` for no marker at all, an unparseable one, or one
     * naming a different device (an HA peer's replicated entry) —
     * left untouched either way.
     *
     * @return 'reset'|'left_changed_since_written'|'not_ours'
     */
    public static function facilityDecommissionOutcome(?string $marker, string $deviceUuid, string $liveValue): string
    {
        if ($marker === null || $marker === '') {
            return 'not_ours';
        }
        $parsed = self::parseFacilityOwnerMarker($marker);
        if ($parsed === null || $parsed[0] !== $deviceUuid) {
            return 'not_ours';
        }
        return hash('sha256', $liveValue) === $parsed[1] ? 'reset' : 'left_changed_since_written';
    }
}
