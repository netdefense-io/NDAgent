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

use OPNsense\Auth\Group;
use OPNsense\Auth\User;

/**
 * Provisions the shared read-only OPNsense user used for read-only
 * "Open WebAdmin" sessions.
 *
 * The MSSP feature lets a read-only NetDefense user open the OPNsense GUI
 * tunneled through PathFinder. NDAgent forges a PHP session whose Username
 * is this read-only user, so the GUI ACL — not a password — constrains what
 * the operator can see. OPNsense has no global "read-only mode" toggle, so
 * the restriction is a curated page-by-page priv allowlist on a dedicated
 * group, hardened with the global `user-config-readonly` deny-config-write
 * priv as defense-in-depth.
 *
 * The user has NO API key and NO password: it is never used for REST or a
 * real login, only as the forged-session identity. See
 * internal/tasks/connect.go (read_only flag) and
 * internal/pathfinder/session.go (CreateSession).
 *
 * Mirrors ApiCredsProvisioner's idempotency contract: the caller owns the
 * Config lock + save + Backend triggers (`configdpRun 'auth sync user'` and
 * `configdRun 'template reload OPNsense/NetDefense'`). This method only
 * mutates the in-memory Config tree via the User/Group models.
 */
class ReadOnlyUserProvisioner
{
    /** Username/groupname for the shared read-only webadmin identity. */
    const READONLY_USERNAME = 'netdefense-readonly';
    const READONLY_GROUPNAME = 'netdefense-readonly';

    /**
     * Curated read-only ACL allowlist — SINGLE SOURCE OF TRUTH.
     *
     * provision() performs full desired-state reconciliation against this
     * list on every call (not just create-if-missing): a priv added here is
     * added to the group; a priv removed here is removed from the group. The
     * ensure_readonly.php script calls provision() from the +MANIFEST
     * post-install hook, so editing this constant and shipping a new package
     * propagates the change to every managed device at next upgrade —
     * no migration, no manual repair required.
     *
     * Validated against the lab OPNsense priv catalog
     * (`(new OPNsense\Core\ACL())->getPrivList()` on 10.255.10.2). Contains
     * ONLY dashboard / status / read-only diagnostics view pages. It
     * deliberately excludes every `page-firewall-*`, `page-system-*` config
     * page, `page-services-*`, `page-interfaces-*-edit`, and the destructive
     * diagnostics (factory defaults, halt, reboot, backup/restore).
     *
     * `user-config-readonly` ("System: Deny config write") is the global
     * backstop: even if a listed page exposes a POST, OPNsense rejects the
     * write. It is the single most important entry here.
     */
    const READONLY_PRIVS = [
        // Global deny-config-write backstop (defense-in-depth).
        'user-config-readonly',

        // Dashboard / lobby (read-only landing).
        'page-system-login-logout',     // Lobby: Dashboard
        'page-system-status',           // System: Status (read-only report)

        // Status pages (read-only by design).
        'page-status-carp',
        'page-status-dhcpleases',
        'page-status-dhcpv6leases',
        'page-status-dnsoverview',
        'page-status-habackup',
        'page-status-interfaces',
        'page-status-ipsec',
        'page-status-ipsec-leases',
        'page-status-ipsec-sad',
        'page-status-ipsec-spd',
        'page-status-ntp',
        'page-status-openvpn',
        'page-status-services',
        'page-status-trafficgraph',     // Reporting: Traffic
        'page-status-systemlogs-ipsecvpn',
        'page-status-systemlogs-ntpd',
        'page-status-systemlogs-openvpn',
        'page-status-systemlogs-portalauth',
        'page-status-systemlogs-ppp',
        'page-status-systemlogs-routing',
        'page-status-systemlogs-wireless',
        'page-diagnostics-wirelessstatus', // Status: Wireless

        // Diagnostics — read-only views / troubleshooting only.
        'page-diagnostics-arptable',
        'page-diagnostics-ndptable',
        'page-diagnostics-authentication',
        'page-diagnostics-configurationhistory',
        'page-diagnostics-dns_diagnostics',
        'page-diagnostics-health',
        'page-diagnostics-limiter-info',
        'page-diagnostics-netstat',
        'page-diagnostics-networkinsight',
        'page-diagnostics-packetcapture',
        'page-diagnostics-pf-info',
        'page-diagnostics-ping',
        'page-diagnostics-routingtables',
        'page-diagnostics-showstates',
        'page-diagnostics-system-activity',
        'page-diagnostics-system-pftop',
        'page-diagnostics-tables',
        'page-diagnostics-testport',
        'page-diagnostics-traceroute',

        // Log viewers (read-only).
        'page-diagnostics-logs-firewall-dynamic',
        'page-diagnostics-logs-firewall-general',
        'page-diagnostics-logs-firewall-plain',
        'page-diagnostics-logs-firewall-summary',
        'page-diagnostics-logs-gateways',
        'page-diagnostics-logs-system',
    ];

    /**
     * Report current state of the read-only user + group.
     *
     * @return array{configured:bool,user_exists:bool,group_exists:bool,is_member:bool,message:string}
     */
    public static function status(): array
    {
        $status = [
            'configured' => false,
            'user_exists' => false,
            'group_exists' => false,
            'is_member' => false,
            'message' => '',
        ];

        $userUid = null;
        $userMdl = new User();
        foreach ($userMdl->user->iterateItems() as $user) {
            if ((string)$user->name === self::READONLY_USERNAME) {
                $status['user_exists'] = true;
                $userUid = (string)$user->uid;
                break;
            }
        }

        $groupMdl = new Group();
        foreach ($groupMdl->group->iterateItems() as $group) {
            if ((string)$group->name === self::READONLY_GROUPNAME) {
                $status['group_exists'] = true;
                // Membership is the user's numeric uid, not the config-tree
                // UUID — OPNsense's ACL matches <member> against <uid>.
                if ($userUid !== null && $userUid !== '') {
                    $members = explode(',', (string)$group->member);
                    $status['is_member'] = in_array($userUid, $members, true);
                }
                break;
            }
        }

        $status['configured'] =
            $status['user_exists'] && $status['group_exists'] && $status['is_member'];
        $status['message'] = $status['configured']
            ? 'Read-only webadmin user is provisioned.'
            : 'Read-only webadmin user not provisioned.';

        return $status;
    }

    /**
     * Provision the netdefense-readonly group + user idempotently.
     *
     * Caller is responsible for Config::getInstance()->lock()/unlock(),
     * save(), and Backend triggers. This method only mutates the in-memory
     * Config tree via the User/Group models.
     *
     * Idempotency: if the group exists with the curated priv set, the user
     * exists with the right shape, and the user is already a member, returns
     * ['result'=>'skipped',...] without churn. Otherwise it creates/repairs
     * whichever pieces are missing (group, user, membership, priv set) and
     * returns ['result'=>'ok',...].
     *
     * @return array{result:string,message:string}
     */
    public static function provision(): array
    {
        $changed = false;

        // --- User: ensure it exists with the correct shape. ---
        $userMdl = new User();
        $userUid = null;
        foreach ($userMdl->user->iterateItems() as $user) {
            if ((string)$user->name === self::READONLY_USERNAME) {
                $userUid = (string)$user->uid;
                break;
            }
        }

        if ($userUid === null) {
            $user = $userMdl->user->Add();
            if ($user === null) {
                return ['result' => 'failed', 'message' => 'Failed to create read-only user'];
            }
            $user->name = self::READONLY_USERNAME;
            $user->disabled = '0';
            $user->scope = 'user';
            $user->descr = 'NetDefense read-only WebAdmin user (auto-generated)';
            // No password, no API key, no per-user priv. The group carries
            // the curated ACL; the forged PHP session carries the identity.
            $changed = true;
        }

        if ($changed) {
            $userMdl->serializeToConfig(false, true);
            // Re-resolve the NUMERIC uid OPNsense auto-assigned to the
            // freshly added user (UidField::applyDefault picks the next
            // free uid during serialization). The group <member> MUST be
            // this numeric uid — OPNsense's native ACL
            // (ACL::loadUserGroupRights) matches <member> against the
            // user's <uid>, NOT the config-tree UUID. Native groups store
            // e.g. <member>0</member> (root's uid). Writing the UUID here
            // silently resolves the user into NO group (MemberField's
            // option list is keyed by uid), so every page — even the
            // allowlisted ones — is denied.
            foreach ($userMdl->user->iterateItems() as $user) {
                if ((string)$user->name === self::READONLY_USERNAME) {
                    $userUid = (string)$user->uid;
                    break;
                }
            }
        }

        if ($userUid === null || $userUid === '') {
            return ['result' => 'failed', 'message' => 'Read-only user uid unresolved after create'];
        }

        // --- Group: ensure it exists, carries the curated privs, and the
        //     user is a member. ---
        $desiredPrivs = implode(',', self::READONLY_PRIVS);

        $groupMdl = new Group();
        $group = null;
        foreach ($groupMdl->group->iterateItems() as $g) {
            if ((string)$g->name === self::READONLY_GROUPNAME) {
                $group = $g;
                break;
            }
        }

        $groupDirty = false;
        if ($group === null) {
            $group = $groupMdl->group->Add();
            if ($group === null) {
                return ['result' => 'failed', 'message' => 'Failed to create read-only group'];
            }
            $group->name = self::READONLY_GROUPNAME;
            $group->scope = 'user';
            $group->description = 'NetDefense read-only WebAdmin access (auto-generated)';
            $groupDirty = true;
        }

        // Reconcile the priv set (sorted comparison so order/whitespace
        // differences don't trigger spurious rewrites).
        $current = array_filter(explode(',', (string)$group->priv));
        $desired = self::READONLY_PRIVS;
        sort($current);
        $desiredSorted = $desired;
        sort($desiredSorted);
        if ($current !== $desiredSorted) {
            $group->priv = $desiredPrivs;
            $groupDirty = true;
        }

        // Reconcile membership: add the read-only user's NUMERIC uid if
        // absent (see the uid-vs-UUID note above — the ACL matches
        // <member> against <uid>).
        $members = array_filter(explode(',', (string)$group->member));
        if (!in_array($userUid, $members, true)) {
            $members[] = $userUid;
            $group->member = implode(',', $members);
            $groupDirty = true;
        }

        if ($groupDirty) {
            $groupMdl->serializeToConfig(false, true);
            $changed = true;
        }

        if (!$changed) {
            return [
                'result' => 'skipped',
                'message' => 'Read-only webadmin user already provisioned; no change.',
            ];
        }

        return [
            'result' => 'ok',
            'message' => 'Read-only webadmin user provisioned successfully',
        ];
    }
}
