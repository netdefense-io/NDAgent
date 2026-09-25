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

use OPNsense\Core\Config;

/**
 * AUTH_SERVER / AUTH_ORDER PHP helper — Config-dependent orchestration.
 *
 * Implements both the `sync` and `decommission` modes: server
 * create/update/delete consistency, writing a facility's login order,
 * refusing dangling-token creates, composing the reserved-name
 * exclusion, ownership markers, decommission, and the OPNsense release
 * floor.
 *
 * **The `planSync()` seam.** `sync()` splits into three phases: (1) read
 * a plain-array snapshot of live state off `Config` (`readLiveSnapshot()`
 * and friends — Config-dependent, but produce nothing except arrays/
 * strings/bools); (2) `planSync()` — every decision the sync algorithm
 * makes (classification, gates, the reserved-name exclusion, facility
 * resolution, the dangling-token create check, the sweep, stale_names),
 * taking and returning ONLY plain scalars/
 * arrays, no `\SimpleXMLElement`, no `Config`; (3) `applyServerPlan()` /
 * `applyFacilityPlan()` / `applySweep()` — mechanically turn the plan's
 * decisions into XML writes. `planSync()` is exercised directly by
 * `plugin/tests/AuthServerHelperPlanSyncTest.php`, loadable and runnable
 * the same way `AuthServerAlgoTest.php` exercises `AuthServerAlgo` — no
 * Phalcon, no config.xml, no live OPNsense instance. Everything that
 * genuinely needs a live document (reading it, and the generic
 * CONSUMER_TEXT_MATCH warning scan on delete, which needs to walk the
 * whole document) stays outside `planSync()` and is exercised by lab
 * evidence, the same split `ReadOnlyUserProvisioner` (Config-dependent)
 * and its priv-drift test (algorithm-only) already use in this repo.
 *
 * Every OPNsense object this class may create/touch carries the
 * `221f3268-` device UUID convention on its owner marker (not the UUID
 * prefix itself — auth servers have no MVC model and no add/set/del REST
 * surface at all — but the *marker* is exactly the device_uuid NDAgent
 * already uses everywhere else).
 */
class AuthServerHelper
{
    /** Bounded wait (seconds) for the OPNsense config lock before AUTH_LOCK_TIMEOUT; applies to both sync and decommission. */
    public const LOCK_TIMEOUT_SECONDS = 30;

    /** The ONLY paths this helper may ever change — enforced by the write allow-list diff below. */
    public const WRITE_ALLOWLIST_PREFIXES = [
        'system/authserver',
        'system/webgui/authmode',
        'system/webgui/netdefense_authmode_owner',
    ];

    /** v1 defines only "webadmin"; a future release may add more login-order facilities. */
    public const FACILITY_NAMES = ['webadmin'];

    public const DECOMMISSION_LOG = '/var/log/ndagent-decommission.log';
    public const RELEASE_FILE = '/usr/local/opnsense/version/core';

    private array $decommissionLogLines = [];

    // -----------------------------------------------------------------
    // Entry points
    // -----------------------------------------------------------------

    /** @throws \RuntimeException on a protocol-level failure (lock timeout, layout tripwire, allow-list violation, a failed curated-consumer scan). */
    public function sync(array $request): array
    {
        $deviceUuid = (string)($request['device_uuid'] ?? '');
        if ($deviceUuid === '') {
            // An empty device_uuid would otherwise create servers/facility
            // markers no future run ever recognises as managed (they'd
            // classify as "local" forever — classifyServers() only
            // matches a non-empty uuid), a permanent, silent collision
            // trap. Refuse the whole request rather than limp along.
            throw new \RuntimeException('AUTH_REQUEST_INVALID');
        }

        $this->checkLayout();
        $this->acquireLockBounded(self::LOCK_TIMEOUT_SECONDS);
        $gotLock = true;
        try {
            $cfg = Config::getInstance()->object();
            $this->ensureWebguiNode($cfg);
            $beforeXml = $cfg->asXML();

            $release = $this->readRelease();
            $floorOk = AuthServerAlgo::isReleaseSupported($release);

            $live = $this->readLiveSnapshot($cfg, $deviceUuid);
            $plan = $this->planSync($request, $live, $floorOk);

            $this->applyServerPlan($cfg, $deviceUuid, $plan['server_apply']);
            $this->applyFacilityPlan($cfg, $deviceUuid, $plan['facility_apply']);
            $serverResults = $this->applySweep($cfg, $deviceUuid, $plan['servers'], $plan['sweep']);

            $afterXml = $cfg->asXML();
            $violations = AuthServerAlgo::xmlAllowListDiff($beforeXml, $afterXml, self::WRITE_ALLOWLIST_PREFIXES);
            if (!empty($violations)) {
                throw new \RuntimeException('WRITE_ALLOWLIST_VIOLATION');
            }

            $configWritten = ($beforeXml !== $afterXml);
            if ($configWritten) {
                Config::getInstance()->save();
            }

            Config::getInstance()->unlock();
            $gotLock = false;

            return [
                'contract' => 1,
                'release' => $release,
                'servers' => $serverResults,
                // json_encode()s an empty PHP array as "[]", not "{}" — the
                // wire contract's "facilities" is always a JSON object
                // (keyed by facility name), so an empty result must be
                // forced to object shape explicitly.
                'facilities' => $this->asJsonObject($this->renderFacilitiesForResponse($plan['facilities'])),
                'exclusion' => $plan['exclusion'],
                'warnings' => $plan['warnings'],
                'config_written' => $configWritten,
            ];
        } finally {
            if ($gotLock) {
                Config::getInstance()->unlock();
            }
        }
    }

    /**
     * Decommission. One save. Ignores the gate and the floor. Never
     * edits orders NetDefense did not write. Every managed server
     * is deleted regardless of consumer references (logged, not blocking).
     */
    public function decommission(array $request): array
    {
        $deviceUuid = (string)($request['device_uuid'] ?? '');
        if ($deviceUuid === '') {
            throw new \RuntimeException('AUTH_REQUEST_INVALID');
        }

        $this->checkLayout();
        $this->acquireLockBounded(self::LOCK_TIMEOUT_SECONDS);
        $gotLock = true;
        try {
            $cfg = Config::getInstance()->object();
            $this->ensureWebguiNode($cfg);
            $beforeXml = $cfg->asXML();

            [$managedByName] = $this->classifyLiveServers($cfg, $deviceUuid);
            // Consumer references never block deletion — a curated-scan
            // FAILURE must not become the exception to that rule. Without
            // this catch, a structural surprise in one plugin's XML shape
            // (CONSUMER_SCAN_FAILED, normally a sync()-time family
            // failure) aborted the WHOLE decommission before any server
            // was deleted, and the retry loop's 3 attempts hit the
            // identical failure every time — a permanently undeletable
            // device. Logging references is best-effort only; deletion
            // itself never depends on it.
            try {
                $curatedConsumers = $this->readCuratedConsumerListsSafe($cfg) + $this->readLiveFacilityTokens($cfg);
            } catch (\RuntimeException $e) {
                $this->logDecommission('CONSUMER_SCAN_FAILED (references not logged; deletion proceeds anyway)');
                $curatedConsumers = [];
            }

            $deletedNames = [];
            foreach ($managedByName as $name => $node) {
                foreach ($this->curatedReferences($curatedConsumers, $name) as $xpath) {
                    $this->logDecommission("server \"{$name}\" referenced by {$xpath} at delete time (deleted anyway)");
                }
                $this->removeNode($node);
                $deletedNames[] = $name;
                $this->logDecommission("deleted managed server \"{$name}\"");
            }

            $facilityReport = [];
            foreach (self::FACILITY_NAMES as $fname) {
                $liveValueEl = $this->facilityValueElement($cfg, $fname);
                // An absent authmode key IS "Local Database" — use the
                // same default readLiveFacilityTokens() does, so a marker
                // NetDefense wrote for the literal string "Local Database"
                // still hash-matches after the element itself was later
                // unset (e.g. by hand), rather than mismatching against an
                // empty-string stand-in that was never the real semantics.
                $liveValue = $liveValueEl !== null ? (string)$liveValueEl : AuthServerAlgo::LOCAL_DATABASE;
                $markerEl = $this->facilityOwnerMarkerElement($cfg, $fname);
                $marker = $markerEl !== null ? (string)$markerEl : '';

                $outcome = AuthServerAlgo::facilityDecommissionOutcome($marker === '' ? null : $marker, $deviceUuid, $liveValue);

                if ($outcome === 'reset') {
                    if ($liveValueEl !== null) {
                        $this->removeNode($liveValueEl);
                    }
                    $this->removeNode($markerEl);
                    $this->logDecommission("facility \"{$fname}\" reset to the OPNsense default (hash matched)");
                    $facilityReport[$fname] = 'reset';
                    continue;
                }

                // Left as-is: no marker at all (untouched by design), a
                // foreign/HA-peer marker (also left untouched), or ours
                // but hash-mismatched (the admin changed the value since
                // NetDefense wrote it). Decommission logs
                // ORDER_REFERENCES_DELETED_SERVER whenever the
                // surviving order names a server this pass deleted, no
                // matter which of those three reasons left it in place —
                // including the marker-less case, which an early
                // `continue` on an empty marker used to skip entirely.
                if ($liveValue !== '') {
                    foreach (AuthServerAlgo::tokenizeOrderList($liveValue) as $entry) {
                        if (in_array($entry, $deletedNames, true)) {
                            $this->logDecommission(
                                "facility \"{$fname}\" still names deleted server \"{$entry}\": ORDER_REFERENCES_DELETED_SERVER"
                            );
                        }
                    }
                }

                if ($outcome === 'left_changed_since_written') {
                    // Ours, but changed since we wrote it — leave the
                    // VALUE, but the marker is still our bookkeeping to
                    // remove — decommission's post-condition is that no
                    // marker naming this uuid survives.
                    $this->logDecommission("facility \"{$fname}\" left as-is: ORDER_CHANGED_SINCE_WRITTEN");
                    $facilityReport[$fname] = 'left_changed_since_written';
                    $this->removeNode($markerEl);
                }
            }

            if ($this->localDatabaseShadowed($cfg)) {
                $this->logDecommission('LOCAL_DATABASE_SHADOWED: a live server is literally named "Local Database"; proceeding anyway');
            }

            $afterXml = $cfg->asXML();
            $violations = AuthServerAlgo::xmlAllowListDiff($beforeXml, $afterXml, self::WRITE_ALLOWLIST_PREFIXES);
            if (!empty($violations)) {
                throw new \RuntimeException('WRITE_ALLOWLIST_VIOLATION');
            }

            $configWritten = ($beforeXml !== $afterXml);
            if ($configWritten) {
                Config::getInstance()->save();
            }

            Config::getInstance()->unlock();
            $gotLock = false;

            // Decommission post-condition: a RAW scan of the WHOLE config document
            // for any <netdefense_owner> or <netdefense_authmode_owner>
            // node naming this device — independent of
            // classifyLiveServers()'/facilityOwnerMarkerElement()'s own
            // assumptions about WHERE those nodes live. This is the
            // authoritative post-condition, not classifyLiveServers()'s
            // owner check (which only looks under system/authserver and
            // only for type=ldap): a marker surviving anywhere else in the
            // tree — a bug in the delete logic above, a duplicate/orphaned
            // node, or a future facility whose marker lives elsewhere —
            // must still fail this check.
            $rawHits = $this->rawScanForDeviceMarkers(Config::getInstance()->object(), $deviceUuid);
            foreach ($rawHits as $hitPath) {
                $this->logDecommission("post-condition scan: a marker naming this device still exists at {$hitPath}");
            }

            $postConditionClean = empty($rawHits);

            return [
                'contract' => 1,
                'deleted_servers' => $deletedNames,
                'facilities' => $this->asJsonObject($facilityReport),
                'post_condition_clean' => $postConditionClean,
                'config_written' => $configWritten,
            ];
        } finally {
            if ($gotLock) {
                Config::getInstance()->unlock();
            }
            // Always flush whatever got logged, success or failure — a
            // failed attempt (e.g. WRITE_ALLOWLIST_VIOLATION, or a lock
            // timeout after some prior work) used to leave no trace at
            // all in the decommission log, which is the one thing this
            // log exists for on a failure.
            $this->flushDecommissionLog();
        }
    }

    // -----------------------------------------------------------------
    // Config-independent planning — the planSync() seam. No
    // \SimpleXMLElement, no Config, anywhere in this method or anything
    // it calls. See `plugin/tests/AuthServerHelperPlanSyncTest.php`.
    // -----------------------------------------------------------------

    /**
     * @param array $request the wire request (mode already consumed by
     *   the caller): `device_uuid`, `reject_dangerous`, `servers`,
     *   `facilities`, `reserved_names_desired`.
     * @param array $live see `readLiveSnapshot()`'s doc comment for the
     *   exact shape this must match.
     * @param bool $floorOk pre-computed by the caller from `readRelease()`
     *   + `AuthServerAlgo::isReleaseSupported()` — reading the release
     *   file is filesystem-dependent; the comparison itself is not, and
     *   is already covered by `AuthServerAlgoTest.php`'s floor table.
     *
     * @return array{
     *   servers: array, server_apply: array, facilities: array,
     *   facility_apply: array, sweep: array, deleted_names: array<string>,
     *   exclusion: array, warnings: array
     * }
     */
    public function planSync(array $request, array $live, bool $floorOk): array
    {
        $deviceUuid = (string)($request['device_uuid'] ?? '');
        // Fail CLOSED on an absent/malformed key — a mutation gate must
        // never default to "allow" just because the field didn't arrive.
        $rejectDangerous = (bool)($request['reject_dangerous'] ?? true);
        $servers = $request['servers'] ?? [];
        $facilities = $request['facilities'] ?? [];

        // Device-side defense in depth (NDManager's build-time
        // AUTH_SERVER_NAME_CONFLICT is authoritative): two servers in
        // the SAME request naming the same server, case-insensitively,
        // is a malformed request this helper cannot safely process —
        // deciding "first wins" or "last wins" would silently discard
        // one server's fields. Refuse the whole request, the same way
        // an absent device_uuid does, before anything else reads these
        // names.
        $rawServerNames = array_map(static fn($s) => (string)($s['name'] ?? ''), $servers);
        if (AuthServerAlgo::findCaseInsensitiveDuplicate($rawServerNames) !== null) {
            throw new \RuntimeException('AUTH_REQUEST_INVALID');
        }

        $requestedReservedNames = array_values(array_unique((array)($request['reserved_names_desired'] ?? [])));

        $managedFields = [];
        foreach ($live['managed_servers'] ?? [] as $name => $entry) {
            $managedFields[$name] = $entry['fields'];
        }
        $localNames = $live['local_names'] ?? [];
        $liveGroupNames = $live['live_group_names'] ?? [];
        $reservedNamesDesired = AuthServerAlgo::buildReservedNames($requestedReservedNames, $live['scope_system_usernames'] ?? []);

        // Pre-write curated consumer snapshot — read BEFORE any mutation,
        // used by the dangling-token create check and by the sweep's
        // consumer pre-flight baseline for non-facility paths.
        $preWriteFacilityTokens = $live['facility_tokens'] ?? [];
        $preWriteCuratedConsumers = $live['curated_consumers'] ?? [];

        $serverResults = [];
        $serverApply = [];       // name => ['op'=>'create'|'update','fields'=>effectiveFields]
        // name => field map that will be live after this save, for every
        // name still managed post-upsert. Seeded with every ORIGINAL
        // managed server's live fields — a server this save's request
        // never mentions at all stays exactly as it is (the per-server
        // loop below only OVERWRITES an entry for a name it actually
        // touches; an untouched managed server keeps its pristine live
        // entry here, which is what stale_names and the sweep both need).
        $plannedFields = $managedFields;
        $desiredNames = [];       // every requested name, whatever its outcome — the sweep's "desired" set
        $appliedServerNames = []; // name => true, for names ending create/update/unchanged this save

        // --- Step 3: tentative upserts -----------------------------------
        foreach ($servers as $srv) {
            $name = (string)($srv['name'] ?? '');
            $fields = (array)($srv['fields'] ?? []);
            $result = ['name' => $name, 'changed_fields' => [], 'consumers' => [], 'warnings' => []];

            if ($name !== '') {
                $desiredNames[$name] = true;
            }

            if ($name === '' || isset($localNames[$name])) {
                $result['action'] = 'blocked';
                $result['code'] = 'NAME_COLLISION_UNMANAGED';
                $serverResults[] = $result;
                continue;
            }

            $isUpdate = isset($managedFields[$name]);
            $liveFieldsForName = $managedFields[$name] ?? null;

            try {
                AuthServerAlgo::validateServerName($name);
                AuthServerAlgo::validateServerFieldsShape($fields);
                AuthServerAlgo::validateServerFieldsRequired($fields);
                $groupBlock = AuthServerAlgo::checkGroupAmbiguityInFields($fields, $liveGroupNames);
                if ($groupBlock !== null) {
                    $result['action'] = 'blocked';
                    $result['code'] = 'GROUP_NAME_AMBIGUOUS';
                    if ($isUpdate) {
                        $plannedFields[$name] = $liveFieldsForName;
                    }
                    $serverResults[] = $result;
                    continue;
                }

                // "Terms are only ever added" applies ONLY to the
                // "under the gate" narrowing path, not to an ordinary,
                // fully-gate-permitted update. Union the live query's own
                // already-excluded names with this save's desired set,
                // but ONLY while reject_dangerous is actually on: a
                // reserved name dropping out of
                // `reservedNamesDesired` must never make the composed
                // query look NARROWER than what's already live under the
                // gate — that would turn an otherwise-benign save into a
                // refused "widening", even though nothing was actually
                // removed from what the device excludes today.
                //
                // With the gate OFF this union must NOT apply: the
                // stale-exclusion deferral's timing rule is that a
                // removed USER "stays excluded until the next pass" —
                // i.e. it is expected to actually leave the exclusion
                // once it's genuinely gone (make-before-break), not be
                // retained forever. Unioning unconditionally (the
                // pre-fix behaviour) meant a name could never leave a
                // managed server's exclusion by any path, gate on or
                // off, growing it without bound toward
                // AUTH_EXCLUSION_TOO_LONG.
                $liveQuery = $isUpdate ? ($liveFieldsForName['ldap_extended_query'] ?? null) : null;
                $serverReservedNames = ($isUpdate && $rejectDangerous)
                    ? array_values(array_unique(array_merge(
                        $reservedNamesDesired,
                        AuthServerAlgo::extractExcludedNames($liveQuery)
                    )))
                    : $reservedNamesDesired;
                sort($serverReservedNames, SORT_STRING);

                $composedQuery = AuthServerAlgo::composeExclusionQuery(
                    $fields['ldap_extended_query'] ?? null,
                    (string)($fields['ldap_attr_user'] ?? ''),
                    $serverReservedNames
                );
                if (mb_strlen($composedQuery, 'UTF-8') > AuthServerAlgo::COMPOSED_EXCLUSION_MAX_LEN) {
                    $result['action'] = 'rejected';
                    $result['code'] = 'AUTH_EXCLUSION_TOO_LONG';
                    if ($isUpdate) {
                        $plannedFields[$name] = $liveFieldsForName;
                    }
                    $serverResults[] = $result;
                    continue;
                }
                AuthServerAlgo::verifyExclusionShape(
                    $composedQuery,
                    $fields['ldap_extended_query'] ?? null,
                    (string)($fields['ldap_attr_user'] ?? ''),
                    $serverReservedNames
                );
            } catch (\RuntimeException $e) {
                $result['action'] = 'blocked';
                // A stable per-rule sub-code instead of one generic
                // AUTH_SERVER_INVALID (e.g. AUTH_SERVER_INVALID_
                // NAME/_HOST/_BIND_PAIR/_EXTENDED_QUERY/_GROUPS…) — see
                // AuthServerAlgo::AUTH_SERVER_INVALID_CODES. The allow-
                // list check means an unexpected exception (a bug
                // elsewhere, not one of these validators) can never
                // surface its own message as if it were a stable code —
                // it falls back to the generic code instead.
                $msg = $e->getMessage();
                $result['code'] = in_array($msg, AuthServerAlgo::AUTH_SERVER_INVALID_CODES, true)
                    ? $msg
                    : 'AUTH_SERVER_INVALID';
                if ($isUpdate) {
                    $plannedFields[$name] = $liveFieldsForName;
                }
                $serverResults[] = $result;
                continue;
            }

            // In the pure planner, `ldap_bindpw` is allowed to travel
            // as a plain array/scalar value rather than living only in
            // an object property, given that `zend.exception_
            // ignore_args` is enforced both via `-d` and by the helper's
            // own `ini_set()` call. `planSync()` is Config-independent
            // and pure precisely so it is unit-testable without a live
            // config.xml — every input, the secret included, has to
            // travel as a plain value for that to hold. The leak this
            // guards against (an uncaught exception's argument dump
            // reaching a log or stdout) is closed by the enforced
            // `exception_ignore_args` setting, not by property isolation.
            $effectiveFields = AuthServerAlgo::buildEffectiveFields($fields, $composedQuery, $fields['ldap_bindpw'] ?? null);

            if ($isUpdate) {
                $changed = AuthServerAlgo::diffFields($liveFieldsForName, $effectiveFields);

                if (empty($changed)) {
                    // A no-op is never rejected, whatever the gate/floor
                    // say — deciding the outcome BEFORE applying either
                    // gate is what makes "unchanged" actually mean it.
                    $result['action'] = 'unchanged';
                    $result['code'] = 'OK';
                    $plannedFields[$name] = $effectiveFields;
                    $appliedServerNames[$name] = true;
                } else {
                    // Deliberate deviation from the reject_dangerous gate: a change that touches
                    // ONLY ldap_extended_query, and only by adding
                    // reserved-name exclusions on top of the untouched
                    // live user-query, is never gated by
                    // reject_dangerous (it can only ever narrow access).
                    // The floor still applies either way.
                    $liveQueryText = (string)($liveFieldsForName['ldap_extended_query'] ?? '');
                    $onlyNarrowing = ($changed === ['ldap_extended_query'])
                        && AuthServerAlgo::isNarrowingOnly($liveQueryText, $composedQuery);

                    if (!$onlyNarrowing && $rejectDangerous) {
                        $result['action'] = 'rejected';
                        $result['code'] = 'AUTH_REJECTED_DANGEROUS';
                        $plannedFields[$name] = $liveFieldsForName;
                        $serverResults[] = $result;
                        continue;
                    }
                    if (!$floorOk) {
                        $result['action'] = 'rejected';
                        $result['code'] = 'AUTH_VERSION_UNSUPPORTED';
                        $plannedFields[$name] = $liveFieldsForName;
                        $serverResults[] = $result;
                        continue;
                    }

                    $result['action'] = 'updated';
                    $result['code'] = 'OK';
                    $result['changed_fields'] = $changed;
                    $serverApply[$name] = ['op' => 'update', 'fields' => $effectiveFields];
                    $plannedFields[$name] = $effectiveFields;
                    $appliedServerNames[$name] = true;
                }
            } else {
                // A create is always a real mutation — fully gated.
                if ($rejectDangerous) {
                    $result['action'] = 'rejected';
                    $result['code'] = 'AUTH_REJECTED_DANGEROUS';
                    $serverResults[] = $result;
                    continue;
                }
                if (!$floorOk) {
                    $result['action'] = 'rejected';
                    $result['code'] = 'AUTH_VERSION_UNSUPPORTED';
                    $serverResults[] = $result;
                    continue;
                }

                $result['action'] = 'created';
                $result['code'] = 'OK';
                $result['changed_fields'] = array_keys($effectiveFields);
                $serverApply[$name] = ['op' => 'create', 'fields' => $effectiveFields];
                $plannedFields[$name] = $effectiveFields;
                $appliedServerNames[$name] = true;
            }

            $serverResults[] = $result;
        }

        // --- Facilities + dangling-token re-resolution loop -----------
        $requestedServerNames = array_map(static fn($s) => (string)($s['name'] ?? ''), $servers);
        // Every ORIGINAL managed name (whether or not this save's request
        // touches it — planFacilities' stricter case 2 exists precisely
        // for the ones it doesn't) plus this save's accepted creates. Not
        // `array_keys($plannedFields)`: that map is seeded from
        // `$managedFields` too, but a NEW create only reaches it via the
        // per-server loop above, so the two happen to coincide today —
        // spelled out explicitly here so a future change to how
        // `$plannedFields` is seeded can't silently change this set too.
        $managedNamesSet = array_fill_keys(array_keys($managedFields), true) + $appliedServerNames;
        $facilityResults = [];
        do {
            $roundChanged = false;
            $facilityResults = $this->planFacilities(
                $facilities,
                $preWriteFacilityTokens,
                $managedNamesSet,
                $appliedServerNames,
                $requestedServerNames,
                $localNames,
                $rejectDangerous,
                $floorOk,
                (bool)($live['local_database_shadowed'] ?? false),
                $live['local_servers'] ?? []
            );
            foreach ($serverResults as &$r) {
                if ($r['action'] !== 'created' || !isset($appliedServerNames[$r['name']])) {
                    continue;
                }
                $facilityDecisions = [];
                foreach ($facilityResults as $fname => $fr) {
                    $facilityDecisions[$fname] = $fr['action'];
                }
                $blocking = AuthServerAlgo::danglingTokenBlocksCreate(
                    $r['name'],
                    $preWriteFacilityTokens + $preWriteCuratedConsumers,
                    $facilityDecisions
                );
                if (!empty($blocking)) {
                    // Undo the create.
                    unset($serverApply[$r['name']]);
                    unset($plannedFields[$r['name']]);
                    unset($managedNamesSet[$r['name']]);
                    unset($appliedServerNames[$r['name']]);
                    $r['action'] = 'rejected';
                    $r['code'] = 'CREATE_ACTIVATES_LOGIN_PATH';
                    // Also in `consumers` (not just `warnings`'s free
                    // text), same field CONSUMER_REFERENCED already uses
                    // for its blocking consumer keys, so a caller can key
                    // on structure rather than parsing the warning text.
                    $r['consumers'] = $blocking;
                    $r['warnings'][] = 'blocked by: ' . implode(', ', $blocking);
                    $roundChanged = true;
                }
            }
            unset($r);
        } while ($roundChanged);

        // --- Facility apply instructions ----------------------------------
        $facilityApply = [];
        foreach ($facilityResults as $fname => $fr) {
            if ($fr['action'] === 'written') {
                $facilityApply[$fname] = ['op' => 'write', 'order' => $fr['after']];
                continue;
            }
            if ($fr['action'] !== 'unchanged') {
                continue;
            }
            // Refresh the marker when the policy already equals the live
            // value but the marker is missing or stale — metadata
            // bookkeeping only, never a
            // login-path mutation. Gated on reject_dangerous/the floor
            // anyway: a missing marker on a value that merely happens to
            // COINCIDE with this save's policy is not evidence NetDefense
            // ever actually wrote it — the marker exists specifically so
            // decommission can tell "the live value is still what
            // NetDefense last wrote" — an admin-authored value that
            // happens to match is not that). Claiming it ungated would
            // make an admin-authored order get reset to the OPNsense
            // default at decommission, which the marker's whole purpose
            // is to prevent. A marker naming a DIFFERENT device (an HA peer's
            // replicated entry) is left untouched regardless.
            if ($rejectDangerous || !$floorOk) {
                continue;
            }
            $liveMarker = $live['facility_markers'][$fname] ?? null;
            $expectedMarker = AuthServerAlgo::formatFacilityOwnerMarker($deviceUuid, AuthServerAlgo::joinOrderList($fr['after']));
            if ($liveMarker === $expectedMarker) {
                continue;
            }
            if ($liveMarker !== null && $liveMarker !== '') {
                $parsedLive = AuthServerAlgo::parseFacilityOwnerMarker($liveMarker);
                if ($parsedLive === null || $parsedLive[0] !== $deviceUuid) {
                    continue; // not ours to touch
                }
            }
            $facilityApply[$fname] = ['op' => 'refresh_marker', 'marker' => $expectedMarker];
        }

        // --- Step 6: sweep -------------------------------------------------
        $plannedFacilityTokens = $preWriteFacilityTokens;
        foreach ($facilityResults as $fname => $fr) {
            $plannedFacilityTokens[$fname] = $fr['after'];
        }
        $plannedConsumers = $plannedFacilityTokens + $preWriteCuratedConsumers;

        $sweep = [];
        $deletedNames = [];
        foreach ($managedFields as $name => $ignored) {
            if (isset($desiredNames[$name])) {
                continue; // requested this save, whatever the per-element outcome — never orphan-deleted for a mere refusal
            }
            $hits = $this->curatedReferences($plannedConsumers, $name);
            if (!empty($hits)) {
                $sweep[$name] = ['action' => 'retained', 'code' => 'CONSUMER_REFERENCED', 'consumers' => $hits];
                continue;
            }
            $sweep[$name] = ['action' => 'deleted', 'code' => 'OK', 'consumers' => []];
            $deletedNames[] = $name;
        }

        // --- Exclusion coverage / stale_names -----------------------------
        $staleNames = AuthServerAlgo::computeStaleReservedNames($reservedNamesDesired, $plannedFields, $deletedNames);
        $exclusion = ['stale_names' => $staleNames, 'code' => empty($staleNames) ? 'OK' : 'AUTH_EXCLUSION_STALE'];

        $warnings = [];
        $shadowableCount = (int)($live['shadowable_privileged_count'] ?? 0);
        if ($shadowableCount > 0) {
            $warnings[] = ['code' => 'PRIVILEGED_LOCAL_USERS_SHADOWABLE', 'count' => $shadowableCount];
        }

        return [
            'servers' => $serverResults,
            'server_apply' => $serverApply,
            'facilities' => $facilityResults,
            'facility_apply' => $facilityApply,
            'sweep' => $sweep,
            'deleted_names' => $deletedNames,
            'exclusion' => $exclusion,
            'warnings' => $warnings,
        ];
    }

    /**
     * Plan every requested facility's outcome. Pure: no \SimpleXMLElement,
     * no Config — every input is a plain array/scalar the caller read
     * off (or decided from) the live snapshot.
     *
     * @param array<string,array<string>> $liveFacilityTokens
     * @param array<string,true> $managedNamesSet every name still managed
     *   at THIS point in the re-resolution loop (original managed names, plus this
     *   save's accepted-so-far creates, minus any the loop has undone).
     * @param array<string,true> $appliedServerNames
     * @param array<string,array{fields:array}> $localServerFields for
     *   `local_servers` risk reporting only.
     * @return array<string,array{action:string,code:string,before:array<string>,after:array<string>,unresolved:array<string>,local_servers:array,available:array<string>}>
     */
    private function planFacilities(
        array $facilities,
        array $liveFacilityTokens,
        array $managedNamesSet,
        array $appliedServerNames,
        array $requestedServerNames,
        array $localNames,
        bool $rejectDangerous,
        bool $floorOk,
        bool $localDatabaseShadowed,
        array $localServerFields
    ): array {
        $out = [];

        foreach ($facilities as $fname => $facilityDef) {
            if (!in_array($fname, self::FACILITY_NAMES, true)) {
                continue; // the Go side's facility allow-list is authoritative; defensive skip here
            }
            $order = (array)($facilityDef['order'] ?? []);
            $before = $liveFacilityTokens[$fname] ?? [AuthServerAlgo::LOCAL_DATABASE];

            // The refusal message must list the server names that DO
            // exist (checkRuleInterfaces style) — this IS the
            // resolution set, sorted for a stable, deterministic
            // response. Computed once, up front, so every refusal branch
            // below (including AUTH_ORDER_TOO_LONG) can report it.
            $resolutionSet = array_merge([AuthServerAlgo::LOCAL_DATABASE], array_keys($localNames), array_keys($appliedServerNames));
            $available = array_values(array_unique($resolutionSet));
            sort($available, SORT_STRING);

            // Device-side defense in depth (NDDataModels
            // enforces 1-8 at build time). Checked before resolution so an
            // over-long list gets one clear code instead of a confusing
            // per-entry AUTH_ORDER_UNRESOLVED past index 8.
            if (count($order) > AuthServerAlgo::AUTH_ORDER_MAX_ENTRIES) {
                $out[$fname] = [
                    'action' => 'refused', 'code' => 'AUTH_ORDER_TOO_LONG', 'before' => $before,
                    'after' => $before, 'unresolved' => [], 'local_servers' => [], 'available' => $available,
                ];
                continue;
            }

            // Device-side re-validation: entry syntax (no comma or
            // control chars — a comma would silently split one entry
            // into two via explode(',') on write) and case-insensitive duplicate
            // entries, both device-side defense in depth (NDManager's
            // build-time AUTH_ORDER validator is authoritative). Checked
            // before resolution, same reasoning as AUTH_ORDER_TOO_LONG
            // above: a malformed/duplicated entry gets one clear code
            // rather than a confusing AUTH_ORDER_UNRESOLVED.
            $syntaxViolation = false;
            foreach ($order as $entry) {
                if (!is_string($entry)) {
                    continue; // caught by the existing AUTH_ORDER_UNRESOLVED per-entry loop below
                }
                try {
                    AuthServerAlgo::validateOrderEntrySyntax($entry);
                } catch (\RuntimeException $e) {
                    $syntaxViolation = true;
                    break;
                }
            }
            if ($syntaxViolation) {
                $out[$fname] = [
                    'action' => 'refused', 'code' => 'AUTH_ORDER_ENTRY_INVALID', 'before' => $before,
                    'after' => $before, 'unresolved' => [], 'local_servers' => [], 'available' => $available,
                ];
                continue;
            }
            if (AuthServerAlgo::findCaseInsensitiveDuplicate($order) !== null) {
                $out[$fname] = [
                    'action' => 'refused', 'code' => 'AUTH_ORDER_DUPLICATE_ENTRY', 'before' => $before,
                    'after' => $before, 'unresolved' => [], 'local_servers' => [], 'available' => $available,
                ];
                continue;
            }

            $unresolved = [];
            $code = 'OK';
            foreach ($order as $entry) {
                // First-wins: report the EARLIEST problem, not the last —
                // with the pre-fix "last one wins" behaviour, an order
                // mixing a removed server and a later typo reported only
                // the typo's code, silently dropping the (arguably more
                // actionable) removed-server reason. `unresolved` still
                // collects every offending entry either way (the caller
                // needs every offending entry reported together); only
                // which single `code` accompanies them changes.
                if (!is_string($entry)) {
                    $unresolved[] = (string)$entry;
                    $code = $code === 'OK' ? 'AUTH_ORDER_UNRESOLVED' : $code;
                    continue;
                }
                $requested = in_array($entry, $requestedServerNames, true);
                // Case 1 (requested but not applied) is checked BEFORE
                // case 2 (managed but not requested) — a payload server
                // that IS still requested but was refused/blocked this
                // save is "not applied", never "removed": it is not being
                // taken out of the desired set (this rule has two stricter
                // cases). Checking case 2 first mislabels exactly that
                // situation as a removal.
                if ($requested && !isset($appliedServerNames[$entry])) {
                    $unresolved[] = $entry;
                    $code = $code === 'OK' ? 'AUTH_ORDER_SERVER_NOT_APPLIED' : $code;
                    continue;
                }
                if (!$requested && isset($managedNamesSet[$entry])) {
                    // stricter case 2: a managed server not in the payload at all (being removed).
                    $unresolved[] = $entry;
                    $code = $code === 'OK' ? 'AUTH_ORDER_NAMES_REMOVED_SERVER' : $code;
                    continue;
                }
                if (!in_array($entry, $resolutionSet, true)) {
                    $unresolved[] = $entry;
                    $code = $code === 'OK' ? 'AUTH_ORDER_UNRESOLVED' : $code;
                }
            }

            if (!empty($unresolved)) {
                $out[$fname] = [
                    'action' => 'refused', 'code' => $code, 'before' => $before, 'after' => $before,
                    'unresolved' => array_values(array_unique($unresolved)), 'local_servers' => [],
                    'available' => $available,
                ];
                continue;
            }

            $localServersInOrder = [];
            foreach ($order as $entry) {
                if (isset($localNames[$entry])) {
                    $localServersInOrder[] = [
                        'name' => $entry,
                        'risks' => AuthServerAlgo::localServerRisks($localServerFields[$entry]['fields'] ?? []),
                    ];
                }
            }

            // A no-op is decided BEFORE any gate: the Local Database
            // rule, the shadow check, reject_dangerous and the floor
            // only ever matter for an actual write, exactly like the
            // per-server upsert loop above (the gate applies to
            // create/update/facility WRITES, not a plan that changes
            // nothing).
            if ($order === $before) {
                $out[$fname] = [
                    'action' => 'unchanged', 'code' => 'OK', 'before' => $before, 'after' => $before,
                    'unresolved' => [], 'local_servers' => $localServersInOrder, 'available' => $available,
                ];
                continue;
            }

            try {
                AuthServerAlgo::localDatabaseRule($order);
            } catch (\RuntimeException $e) {
                $out[$fname] = [
                    'action' => 'refused', 'code' => 'LOCAL_DATABASE_RULE_VIOLATION', 'before' => $before,
                    'after' => $before, 'unresolved' => [], 'local_servers' => [], 'available' => $available,
                ];
                continue;
            }

            // The Local Database rule considers only what THIS write would create; the
            // shadow check considers every live server — a managed server
            // can never legitimately be named "Local Database"
            // (validateServerName's own reserved-name check refuses it),
            // so "including ones this save just created" can only ever
            // resolve via a pre-existing hand-made collision, which is
            // exactly what `local_database_shadowed` already captures.
            if ($localDatabaseShadowed) {
                $out[$fname] = [
                    'action' => 'refused', 'code' => 'LOCAL_DATABASE_SHADOWED', 'before' => $before,
                    'after' => $before, 'unresolved' => [], 'local_servers' => [], 'available' => $available,
                ];
                continue;
            }

            if ($rejectDangerous) {
                $out[$fname] = [
                    'action' => 'refused', 'code' => 'AUTH_REJECTED_DANGEROUS', 'before' => $before,
                    'after' => $before, 'unresolved' => [], 'local_servers' => [], 'available' => $available,
                ];
                continue;
            }
            if (!$floorOk) {
                $out[$fname] = [
                    'action' => 'refused', 'code' => 'AUTH_VERSION_UNSUPPORTED', 'before' => $before,
                    'after' => $before, 'unresolved' => [], 'local_servers' => [], 'available' => $available,
                ];
                continue;
            }

            $out[$fname] = [
                'action' => 'written', 'code' => 'OK', 'before' => $before, 'after' => array_values($order),
                'unresolved' => [], 'local_servers' => $localServersInOrder, 'available' => $available,
            ];
        }

        return $out;
    }

    // -----------------------------------------------------------------
    // Applying a plan (Config-dependent; mechanical — every DECISION was
    // already made by planSync()/planFacilities()).
    // -----------------------------------------------------------------

    /** @param array<string,array{op:string,fields:array}> $serverApply */
    private function applyServerPlan(\SimpleXMLElement $cfg, string $deviceUuid, array $serverApply): void
    {
        if (empty($serverApply)) {
            return;
        }
        [$managedByName] = $this->classifyLiveServers($cfg, $deviceUuid);
        foreach ($serverApply as $name => $spec) {
            if ($spec['op'] === 'create') {
                // addChild($tag, $value) does NOT escape $value the way
                // property assignment does — a bare "&" in $value is
                // silently dropped rather than escaped (confirmed on
                // e2e-b). Property assignment on a not-yet-existing child
                // auto-creates it (same pattern ensure_readonly.php
                // already relies on) AND escapes correctly, so every
                // field goes through assignment, never
                // addChild($tag, $value).
                $node = $cfg->system->addChild('authserver');
                $node->refid = uniqid();
                $node->type = 'ldap';
                $node->name = $name;
                $node->netdefense_owner = $deviceUuid;
                $this->writeServerFields($node, $spec['fields']);
            } elseif ($spec['op'] === 'update' && isset($managedByName[$name])) {
                $this->writeServerFields($managedByName[$name], $spec['fields']);
            }
        }
    }

    /**
     * `$spec['op']==='write'` carries `order` (the plan already decided
     * the exact list to write); `refresh_marker` carries `marker` (the
     * exact string to write, already formatted by planSync() from
     * `deviceUuid` — no decision left to make here, only a write).
     *
     * @param array<string,array{op:string,order?:array,marker?:string}> $facilityApply
     */
    private function applyFacilityPlan(\SimpleXMLElement $cfg, string $deviceUuid, array $facilityApply): void
    {
        foreach ($facilityApply as $fname => $spec) {
            if ($fname !== 'webadmin') {
                continue; // only webadmin has a marker/value location today
            }
            if ($spec['op'] === 'write') {
                $value = AuthServerAlgo::joinOrderList($spec['order']);
                $cfg->system->webgui->authmode = $value; // property assignment escapes; see writeServerFields()'s comment
                $cfg->system->webgui->netdefense_authmode_owner = AuthServerAlgo::formatFacilityOwnerMarker($deviceUuid, $value);
            } elseif ($spec['op'] === 'refresh_marker') {
                $cfg->system->webgui->netdefense_authmode_owner = $spec['marker'];
            }
        }
    }

    /**
     * @param array<array{name:string,action:string}> $serverResults the
     *   per-request-server outcomes from planSync(); this method appends
     *   the sweep's own outcomes (retained/deleted) and returns the
     *   combined list, matching sync()'s wire response shape.
     * @param array<string,array{action:string,code:string,consumers:array}> $sweep
     */
    private function applySweep(\SimpleXMLElement $cfg, string $deviceUuid, array $serverResults, array $sweep): array
    {
        if (empty($sweep)) {
            return $serverResults;
        }
        [$managedByName] = $this->classifyLiveServers($cfg, $deviceUuid);
        foreach ($sweep as $name => $decision) {
            if ($decision['action'] === 'retained') {
                $serverResults[] = [
                    'name' => $name, 'action' => 'retained', 'code' => $decision['code'],
                    'changed_fields' => [], 'consumers' => $decision['consumers'], 'warnings' => [],
                ];
                continue;
            }
            // The generic, advisory-only text scan needs the live
            // document, so it happens here (apply time), before removal —
            // it never affects the decision, only the reported warnings.
            $textWarnings = isset($managedByName[$name]) ? $this->genericTextScan($cfg, $name) : [];
            if (isset($managedByName[$name])) {
                $this->removeNode($managedByName[$name]);
            }
            $serverResults[] = [
                'name' => $name, 'action' => 'deleted', 'code' => 'OK',
                'changed_fields' => [], 'consumers' => [], 'warnings' => $textWarnings,
            ];
        }
        return $serverResults;
    }

    // -----------------------------------------------------------------
    // Reading a live snapshot (Config-dependent; produces plain
    // arrays/scalars only — nothing here is used except as planSync()
    // input).
    // -----------------------------------------------------------------

    /**
     * @return array{
     *   managed_servers: array<string,array{fields:array}>,
     *   local_names: array<string,true>,
     *   local_servers: array<string,array{fields:array}>,
     *   live_group_names: array<string>,
     *   scope_system_usernames: array<string>,
     *   facility_tokens: array<string,array<string>>,
     *   facility_markers: array<string,?string>,
     *   curated_consumers: array<string,array<string>>,
     *   local_database_shadowed: bool,
     *   shadowable_privileged_count: int
     * }
     */
    private function readLiveSnapshot(\SimpleXMLElement $cfg, string $deviceUuid): array
    {
        [$managedByName, $localNamesSet] = $this->classifyLiveServers($cfg, $deviceUuid);

        $managedServers = [];
        foreach ($managedByName as $name => $node) {
            $managedServers[$name] = ['fields' => $this->readServerFields($node)];
        }

        $localServers = [];
        if (isset($cfg->system->authserver)) {
            foreach ($cfg->system->authserver as $node) {
                $name = (string)$node->name;
                if (isset($localNamesSet[$name])) {
                    $localServers[$name] = ['fields' => $this->readServerFields($node)];
                }
            }
        }

        $liveGroupNames = [];
        $userRecords = [];
        $groupRecords = [];
        $scopeSystemUsernames = [];
        if (isset($cfg->system->user)) {
            foreach ($cfg->system->user as $u) {
                $uname = (string)$u->name;
                $priv = isset($u->priv) ? (string)$u->priv : '';
                $uid = isset($u->uid) ? (string)$u->uid : null;
                $userRecords[] = ['name' => $uname, 'uid' => $uid, 'priv' => $priv];
                if (isset($u->scope) && (string)$u->scope === 'system') {
                    $scopeSystemUsernames[] = $uname;
                }
            }
        }
        if (isset($cfg->system->group)) {
            foreach ($cfg->system->group as $g) {
                $descr = isset($g->description) ? (string)$g->description : '';
                $isNdManaged = strpos($descr, '[nd-template:') !== false;
                if (!$isNdManaged) {
                    // A NetDefense-managed external GROUP is never
                    // ambiguous with itself — matches internal/opnapi's
                    // `[nd-template:*]` tag (users_types.go). Without this,
                    // every server with Limit/default groups blocks itself
                    // permanently from the sync AFTER the one that creates
                    // its own external GROUP.
                    $liveGroupNames[] = (string)$g->name;
                }
                $memberUids = [];
                if (isset($g->member)) {
                    foreach ($g->member as $m) {
                        $memberUids[] = (string)$m;
                    }
                }
                $groupRecords[] = ['priv' => isset($g->priv) ? (string)$g->priv : '', 'member_uids' => $memberUids];
            }
        }

        $facilityTokens = $this->readLiveFacilityTokens($cfg);
        $facilityMarkers = [];
        foreach (self::FACILITY_NAMES as $fname) {
            $markerEl = $this->facilityOwnerMarkerElement($cfg, $fname);
            $facilityMarkers[$fname] = $markerEl !== null ? (string)$markerEl : null;
        }

        $curatedConsumers = $this->readCuratedConsumerListsSafe($cfg);

        $allServerNames = array_merge(array_keys($managedByName), array_keys($localNamesSet));

        return [
            'managed_servers' => $managedServers,
            'local_names' => $localNamesSet,
            'local_servers' => $localServers,
            'live_group_names' => $liveGroupNames,
            'scope_system_usernames' => $scopeSystemUsernames,
            'facility_tokens' => $facilityTokens,
            'facility_markers' => $facilityMarkers,
            'curated_consumers' => $curatedConsumers,
            'local_database_shadowed' => in_array(AuthServerAlgo::LOCAL_DATABASE, $allServerNames, true),
            // Excludes names ALREADY covered by the reserved-name
            // exclusion's static half (root/netdefense-agent/
            // netdefense-readonly plus every live scope=system user) so
            // the warning doesn't permanently read >= 2 for names that
            // can never actually be shadowed.
            // This is a partial exclusion — it does not know the
            // request's reserved_names_desired (managed USERs/GROUP
            // members), which readLiveSnapshot() has no access to; those
            // are covered only when they also happen to be scope=system.
            'shadowable_privileged_count' => AuthServerAlgo::countShadowablePrivilegedUsers(
                $userRecords,
                $groupRecords,
                array_merge(AuthServerAlgo::RESERVED_STATIC_USER_NAMES, $scopeSystemUsernames)
            ),
        ];
    }

    /**
     * Every writable key, always populated (never partial) — a bool for
     * every `BOOLEAN_KEYS` entry (via `normalizeBoolLeaf()`), and
     * `string|null` (null = element absent) otherwise. This is the exact
     * shape `AuthServerAlgo::diffFields()` expects for `$liveFields`.
     */
    private function readServerFields(\SimpleXMLElement $node): array
    {
        $out = [];
        foreach (AuthServerAlgo::AUTH_SERVER_WRITABLE_KEYS as $key) {
            if (in_array($key, AuthServerAlgo::BOOLEAN_KEYS, true)) {
                $out[$key] = AuthServerAlgo::normalizeBoolLeaf(isset($node->{$key}) ? (string)$node->{$key} : null);
                continue;
            }
            $out[$key] = isset($node->{$key}) ? (string)$node->{$key} : null;
        }
        return $out;
    }

    // -----------------------------------------------------------------
    // Process safety — bounded lock acquisition and signal handling during save()
    // -----------------------------------------------------------------

    /**
     * Bounded lock acquisition: `Config::lock()`'s internal
     * `flock(LOCK_EX)` is BLOCKING with no timeout of its own, so a
     * one-shot CLI helper needs its own ceiling. pcntl is available on
     * every OPNsense 26.x install (confirmed on the lab, PHP 8.5) — an
     * alarm signal interrupts the blocked flock() syscall and this throws
     * a clean `AUTH_LOCK_TIMEOUT` instead of hanging until Go's 5-minute
     * SIGTERM ceiling (which the helper then ignores anyway — see
     * `ignoreTerminationSignals()` below).
     *
     * Deliberately does NOT call `Config::forceReload()` before `lock()`.
     * Testing confirmed `forceReload()` unconditionally closes the file
     * handle a just-acquired flock() lives on, silently dropping it —
     * the exact race this design exists to prevent. `lock(true)`'s own
     * internal `load()` already re-reads the file on the SAME handle as
     * part of acquiring the lock (Config.php:781-789), which is all a
     * one-shot process (starting with a fresh, unlocked handle) needs.
     *
     * Without pcntl, this helper has no way to bound the lock wait NOR to
     * ignore SIGTERM/SIGINT after acquiring it — the kill-during-save()
     * protection this file exists for. pcntl is confirmed present on
     * every OPNsense 26.x install (the lab, PHP 8.5), so the fallback
     * below is not expected to ever run there; failing closed (rather
     * than silently locking unprotected) matches this file's
     * layout-tripwire philosophy for a runtime that doesn't match what
     * was verified.
     *
     * @throws \RuntimeException 'AUTH_LAYOUT_UNSUPPORTED' if pcntl is unavailable.
     */
    private function acquireLockBounded(int $timeoutSeconds): void
    {
        if (!function_exists('pcntl_signal') || !function_exists('pcntl_alarm')) {
            throw new \RuntimeException('AUTH_LAYOUT_UNSUPPORTED');
        }

        pcntl_async_signals(true);
        pcntl_signal(SIGALRM, function () {
            throw new \RuntimeException('AUTH_LOCK_TIMEOUT');
        });
        pcntl_alarm($timeoutSeconds);
        try {
            Config::getInstance()->lock();
        } finally {
            pcntl_alarm(0);
            pcntl_signal(SIGALRM, SIG_DFL);
        }

        $this->ignoreTerminationSignals();
    }

    /**
     * Once the lock is held, the helper runs to completion and ignores
     * SIGTERM/SIGINT until it unlocks — a kill mid-`save()` truncates
     * config.xml, confirmed by an authorized destructive test on the lab.
     * Go deliberately never sets `WaitDelay` on this helper's process —
     * `WaitDelay` escalates to an unconditional SIGKILL once it elapses,
     * regardless of `Cancel`, and a SIGKILL mid-`save()` is exactly the
     * truncation this design exists to prevent. Go's own post-SIGTERM
     * wait is bounded separately, without `WaitDelay`. This
     * signal-ignoring is therefore the ONLY thing standing between an
     * ordinary SIGTERM and a mid-write kill — there is no further Go-side
     * SIGKILL backstop to fall back on.
     */
    private function ignoreTerminationSignals(): void
    {
        if (function_exists('pcntl_signal')) {
            pcntl_async_signals(true);
            pcntl_signal(SIGTERM, SIG_IGN);
            pcntl_signal(SIGINT, SIG_IGN);
        }
    }

    // -----------------------------------------------------------------
    // Layout tripwire — refuse to run against an OPNsense layout this
    // class was not verified against
    // -----------------------------------------------------------------

    public const LEGACY_AUTHSERVERS_PAGE = '/usr/local/www/system_authservers.php';
    public const MVC_MODELS_GLOB = '/usr/local/opnsense/mvc/app/models/OPNsense/*/*Server*.xml';

    private function checkLayout(): void
    {
        if (!function_exists('config_read_array') && !class_exists(Config::class)) {
            throw new \RuntimeException('AUTH_LAYOUT_UNSUPPORTED');
        }
        if (!file_exists(self::LEGACY_AUTHSERVERS_PAGE)) {
            // The premise that "the legacy system_authservers.php
            // writes system/authserver[]" no longer holds on this box.
            throw new \RuntimeException('AUTH_LAYOUT_UNSUPPORTED');
        }
        // A future OPNsense release that migrates auth servers to an MVC
        // model (there is none today) would give this helper a
        // `system/authserver` node whose shape this class doesn't
        // recognise. A model under an "Auth" namespace naming "Server" is
        // the cheap structural signature for that: refuse rather than
        // silently mutate config against a model it never read. The write
        // allow-list diff remains the backstop for any
        // shape this glob doesn't happen to catch.
        foreach ((array)(@glob(self::MVC_MODELS_GLOB) ?: []) as $path) {
            if (stripos($path, '/Auth/') !== false) {
                throw new \RuntimeException('AUTH_LAYOUT_UNSUPPORTED');
            }
        }
    }

    // -----------------------------------------------------------------
    // OPNsense release floor
    // -----------------------------------------------------------------

    private function readRelease(): ?string
    {
        if (!is_readable(self::RELEASE_FILE)) {
            return null;
        }
        $raw = @file_get_contents(self::RELEASE_FILE);
        if ($raw === false) {
            return null;
        }
        $data = json_decode($raw, true);
        if (!is_array($data) || !isset($data['product_version']) || !is_string($data['product_version'])) {
            return null;
        }
        return $data['product_version'];
    }

    // -----------------------------------------------------------------
    // Classification — which live servers this device manages
    // -----------------------------------------------------------------

    /**
     * @return array{0:array<string,\SimpleXMLElement>,1:array<string,true>,2:array<string>}
     *   [managedByName (live node handles), localNamesSet, allLiveNames]
     */
    private function classifyLiveServers(\SimpleXMLElement $cfg, string $deviceUuid): array
    {
        $records = [];
        // Per-name list of nodes that INDIVIDUALLY qualify as managed
        // (their OWN type=ldap and their OWN <netdefense_owner> names this
        // device) — never a name->node map with implicit last-node-wins
        // semantics. A hand-made server sharing a managed server's name
        // (NAME_COLLISION_UNMANAGED territory — should never happen
        // via OPNsense's own GUI, but a hand-edited config.xml or a
        // restored backup can produce one) must not make this helper
        // mutate/delete the WRONG physical node; resolving ownership per
        // node, off each node's own marker, means the unowned duplicate
        // can never be selected no matter how many of them share the
        // name, while the ONE genuinely-owned node is still found and
        // still actable-on (a name collision must not turn into a
        // permanently orphaned managed server that decommission's
        // post-condition can never clear).
        $ownedNodesByName = [];
        if (isset($cfg->system->authserver)) {
            foreach ($cfg->system->authserver as $node) {
                $name = (string)$node->name;
                $type = (string)$node->type;
                $owner = isset($node->netdefense_owner) ? (string)$node->netdefense_owner : null;
                $records[] = ['name' => $name, 'type' => $type, 'owner' => $owner];
                if ($type === 'ldap' && $deviceUuid !== '' && $owner === $deviceUuid) {
                    $ownedNodesByName[$name][] = $node;
                }
            }
        }
        [$managedSet, $localSet, $all] = AuthServerAlgo::classifyServers($records, $deviceUuid);
        $managedByName = [];
        foreach (array_keys($managedSet) as $name) {
            $owned = $ownedNodesByName[$name] ?? [];
            // Exactly one node individually claims this name as managed:
            // unambiguous, whatever ELSE (an unowned hand-made duplicate)
            // also happens to share the name. More than one — two nodes
            // BOTH individually claiming ownership under the same name,
            // which this helper's own create path should never produce
            // — is a genuine collision: touch neither.
            if (count($owned) === 1) {
                $managedByName[$name] = $owned[0];
            }
        }
        return [$managedByName, $localSet, $all];
    }

    // -----------------------------------------------------------------
    // Server field write (boolean normalization; bind pair written or
    // cleared together)
    // -----------------------------------------------------------------

    private function writeServerFields(\SimpleXMLElement $node, array $effectiveFields): void
    {
        foreach (AuthServerAlgo::AUTH_SERVER_WRITABLE_KEYS as $key) {
            if (!array_key_exists($key, $effectiveFields)) {
                continue;
            }
            $value = $effectiveFields[$key];
            if ($key === 'ldap_binddn' || $key === 'ldap_bindpw') {
                continue; // handled as a pair below
            }
            if (in_array($key, AuthServerAlgo::BOOLEAN_KEYS, true)) {
                if ($value) {
                    $node->{$key} = '1';
                } elseif (isset($node->{$key})) {
                    unset($node->{$key});
                }
                continue;
            }
            // SimpleXMLElement property assignment (unlike addChild() below)
            // already XML-entity-escapes its value on the way in — do not
            // pre-escape here, or "&" becomes "&amp;amp;" (confirmed on
            // e2e-b: a live double-escape bug caught by exercising this
            // helper against a real ldap_extended_query containing "&").
            $node->{$key} = (string)$value;
        }

        // Both non-empty, not merely both present — an empty-string
        // ldap_bindpw is `isset()`-true but is not a real password, and
        // validateServerFieldsShape()'s bind-pair invariant is itself
        // "both non-empty, or neither" (never binddn-with-blank-password).
        if (!empty($effectiveFields['ldap_binddn']) && (($effectiveFields['ldap_bindpw'] ?? '') !== '')) {
            $node->ldap_binddn = (string)$effectiveFields['ldap_binddn'];
            $node->ldap_bindpw = (string)$effectiveFields['ldap_bindpw'];
        } else {
            if (isset($node->ldap_binddn)) {
                unset($node->ldap_binddn);
            }
            if (isset($node->ldap_bindpw)) {
                unset($node->ldap_bindpw);
            }
        }
    }

    private function removeNode(\SimpleXMLElement $node): void
    {
        $dom = dom_import_simplexml($node);
        $dom->parentNode->removeChild($dom);
    }

    // -----------------------------------------------------------------
    // Facilities — live reads
    // -----------------------------------------------------------------

    /**
     * `system/webgui` is a core OPNsense config.xml section that exists
     * on every bootstrapped install (it holds the WebGUI's own
     * protocol/port/etc.) — this is a layout tripwire,
     * not a repair. Silently CREATING an absent node here (the previous
     * behaviour) would write outside the tracked before/after snapshot
     * window: `sync()`/`decommission()` take `$beforeXml` right after
     * this call, so an addition made here is baked into "before" and
     * invisible to `xmlAllowListDiff()` — the write allow-list would
     * never see it. Fail closed instead, matching `checkLayout()`'s own
     * philosophy for every other structural surprise.
     *
     * @throws \RuntimeException 'AUTH_LAYOUT_UNSUPPORTED' if either node is missing.
     */
    private function ensureWebguiNode(\SimpleXMLElement $cfg): void
    {
        if (!isset($cfg->system) || !isset($cfg->system->webgui)) {
            throw new \RuntimeException('AUTH_LAYOUT_UNSUPPORTED');
        }
    }

    /** @return array<string,array<string>> facility name => current live tokens. */
    private function readLiveFacilityTokens(\SimpleXMLElement $cfg): array
    {
        $authmode = isset($cfg->system->webgui->authmode)
            ? (string)$cfg->system->webgui->authmode
            : AuthServerAlgo::LOCAL_DATABASE; // absent key => ['Local Database']
        return ['webadmin' => AuthServerAlgo::tokenizeOrderList($authmode)];
    }

    private function facilityValueElement(\SimpleXMLElement $cfg, string $facility): ?\SimpleXMLElement
    {
        if ($facility !== 'webadmin') {
            return null;
        }
        return isset($cfg->system->webgui->authmode) ? $cfg->system->webgui->authmode : null;
    }

    private function facilityOwnerMarkerElement(\SimpleXMLElement $cfg, string $facility): ?\SimpleXMLElement
    {
        if ($facility !== 'webadmin') {
            return null;
        }
        return isset($cfg->system->webgui->netdefense_authmode_owner) ? $cfg->system->webgui->netdefense_authmode_owner : null;
    }

    private function localDatabaseShadowed(\SimpleXMLElement $cfg): bool
    {
        if (!isset($cfg->system->authserver)) {
            return false;
        }
        foreach ($cfg->system->authserver as $node) {
            if ((string)$node->name === AuthServerAlgo::LOCAL_DATABASE) {
                return true;
            }
        }
        return false;
    }

    private function renderFacilitiesForResponse(array $facilityResults): array
    {
        $out = [];
        foreach ($facilityResults as $fname => $fr) {
            $out[$fname] = [
                'action' => $fr['action'],
                'before' => $fr['before'],
                'after' => $fr['after'],
                'code' => $fr['code'],
                'unresolved' => $fr['unresolved'],
                'local_servers' => $fr['local_servers'],
                // Lists the server names that DO exist — an additive
                // wire field (existing consumers ignore an unknown key;
                // no existing field's shape changes).
                'available' => $fr['available'] ?? [],
            ];
        }
        return $out;
    }

    // -----------------------------------------------------------------
    // Consumer pre-flight (curated paths + generic warning scan)
    // -----------------------------------------------------------------

    /**
     * @return array<string,array<string>> consumer key (an XPath-ish
     *   label, e.g. "OPNsense/OpenVPN/Instances/Instance[0]/authmode")
     *   => list of names it references.
     *   Facility keys are NOT included here (the caller merges
     *   `readLiveFacilityTokens()`/the planned-facility-tokens map
     *   separately, keyed by facility NAME, since those need pre- vs.
     *   post-write variants and the facility's own remedy text names the
     *   FACILITY, not an XPath).
     */
    private function readCuratedConsumerLists(\SimpleXMLElement $cfg): array
    {
        $out = [];

        if (isset($cfg->OPNsense->OpenVPN->Instances->Instance)) {
            $i = 0;
            foreach ($cfg->OPNsense->OpenVPN->Instances->Instance as $instance) {
                $authmode = isset($instance->authmode) ? (string)$instance->authmode : '';
                if ($authmode !== '') {
                    $out["OPNsense/OpenVPN/Instances/Instance[{$i}]/authmode"] = explode(',', $authmode);
                }
                $i++;
            }
        }

        if (isset($cfg->OPNsense->IPsec->general->user_source)) {
            $val = (string)$cfg->OPNsense->IPsec->general->user_source;
            if ($val !== '') {
                $out['OPNsense/IPsec/general/user_source'] = explode(',', $val);
            }
        }

        // eap-radius.servers is filtered to type=radius at the MVC model
        // layer — a v1 (LDAP-only) managed AUTH_SERVER can
        // never populate it, so it is read for completeness but is a
        // structural no-op for this feature's v1 scope.
        if (isset($cfg->OPNsense->IPsec->charon->plugins->{'eap-radius'}->servers)) {
            $val = (string)$cfg->OPNsense->IPsec->charon->plugins->{'eap-radius'}->servers;
            if ($val !== '') {
                $out['OPNsense/IPsec/charon/plugins/eap-radius/servers'] = explode(',', $val);
            }
        }

        if (isset($cfg->OPNsense->captiveportal->zones->zone)) {
            $i = 0;
            foreach ($cfg->OPNsense->captiveportal->zones->zone as $zone) {
                $val = isset($zone->authservers) ? (string)$zone->authservers : '';
                if ($val !== '') {
                    $out["OPNsense/captiveportal/zones/zone[{$i}]/authservers"] = explode(',', $val);
                }
                $i++;
            }
        }

        // Proxy (os-squid): mount is lowercase "//OPNsense/proxy", and the
        // AuthenticationServerField lives at forward/authentication/method
        // (Multiple=Y, comma-joined) — confirmed against the real
        // Proxy.xml model (fetched, not installed, on e2e-b; the plugin
        // isn't present on either e2e lab image, hence "read defensively,
        // never assume the path exists" below).
        if (isset($cfg->OPNsense->proxy->forward->authentication->method)) {
            $val = (string)$cfg->OPNsense->proxy->forward->authentication->method;
            if ($val !== '') {
                $out['OPNsense/proxy/forward/authentication/method'] = explode(',', $val);
            }
        }

        return $out;
    }

    /**
     * A failure of the curated scan fails the family with
     * CONSUMER_SCAN_FAILED. Wraps every curated-consumer read so a
     * structural surprise in any plugin's XML shape maps to one specific,
     * documented code rather than an opaque generic fault.
     */
    private function readCuratedConsumerListsSafe(\SimpleXMLElement $cfg): array
    {
        try {
            return $this->readCuratedConsumerLists($cfg);
        } catch (\Throwable $e) {
            throw new \RuntimeException('CONSUMER_SCAN_FAILED');
        }
    }

    /** @return array<string> XPath-ish labels of every curated consumer that references `$name`. */
    private function curatedReferences(array $consumerLists, string $name): array
    {
        $hits = [];
        foreach ($consumerLists as $key => $names) {
            if (in_array($name, $names, true)) {
                $hits[] = $key;
            }
        }
        return $hits;
    }

    /**
     * Warning-only text scan (CONSUMER_TEXT_MATCH). Walks every leaf text
     * value in the document (skipping the authserver subtree itself —
     * that is not an "other" reference) and reports any that contain
     * `$name` as a comma/whitespace-delimited token. Never blocks.
     */
    private function genericTextScan(\SimpleXMLElement $cfg, string $name): array
    {
        $pattern = '/(^|[,\s])' . preg_quote($name, '/') . '($|[,\s])/';
        $hits = [];
        $this->walkTextNodes($cfg, '', function (string $path, string $value) use ($pattern, &$hits, $name) {
            if ($path === 'system/authserver' || strpos($path, 'system/authserver/') === 0 || strpos($path, 'system/authserver[') === 0) {
                return;
            }
            if ($value !== '' && preg_match($pattern, $value) === 1) {
                $hits[] = "CONSUMER_TEXT_MATCH: {$path}";
            }
        });
        return array_slice($hits, 0, 20); // bounded — this is advisory noise, not an exhaustive audit
    }

    private function walkTextNodes(\SimpleXMLElement $node, string $path, callable $cb): void
    {
        $hasChildren = false;
        foreach ($node->children() as $tag => $child) {
            $hasChildren = true;
            $this->walkTextNodes($child, $path === '' ? $tag : "{$path}/{$tag}", $cb);
        }
        if (!$hasChildren) {
            $cb($path, (string)$node);
        }
    }

    /**
     * Decommission post-condition: a raw walk of the WHOLE config document for
     * any `<netdefense_owner>` or `<netdefense_authmode_owner>` node
     * naming this device — servers and facilities both — independent of
     * classifyLiveServers()'/facilityOwnerMarkerElement()'s own
     * assumptions about WHERE those nodes live.
     *
     * @return array<string> the paths of any surviving marker.
     */
    private function rawScanForDeviceMarkers(\SimpleXMLElement $cfg, string $deviceUuid): array
    {
        $hits = [];
        $this->walkTextNodes($cfg, '', function (string $path, string $value) use (&$hits, $deviceUuid) {
            $slash = strrpos($path, '/');
            $tag = $slash !== false ? substr($path, $slash + 1) : $path;
            if ($tag === 'netdefense_owner' && $value === $deviceUuid) {
                $hits[] = $path;
                return;
            }
            if ($tag === 'netdefense_authmode_owner') {
                $parsed = AuthServerAlgo::parseFacilityOwnerMarker($value);
                if ($parsed !== null && $parsed[0] === $deviceUuid) {
                    $hits[] = $path;
                }
            }
        });
        return $hits;
    }

    // -----------------------------------------------------------------
    // Decommission logging
    // -----------------------------------------------------------------

    /** @param array<string,mixed> $assoc */
    private function asJsonObject(array $assoc)
    {
        return empty($assoc) ? new \stdClass() : $assoc;
    }

    private function logDecommission(string $line): void
    {
        $this->decommissionLogLines[] = '[' . date('c') . "] auth: {$line}";
    }

    private function flushDecommissionLog(): void
    {
        if (empty($this->decommissionLogLines)) {
            return;
        }
        @file_put_contents(self::DECOMMISSION_LOG, implode("\n", $this->decommissionLogLines) . "\n", FILE_APPEND | LOCK_EX);
        // Idempotent: now called unconditionally from decommission()'s
        // `finally` block, so a second call (there is none today, but a
        // future caller might add one) must not re-append the same lines.
        $this->decommissionLogLines = [];
    }
}
