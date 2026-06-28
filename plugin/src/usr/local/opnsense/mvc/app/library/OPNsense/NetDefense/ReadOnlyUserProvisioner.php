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
     * Read-only ACL allowlist — SINGLE SOURCE OF TRUTH.
     *
     * Policy: grant access to EVERY OPNsense WebUI page so a read-only
     * (MSSP) operator can *view* the entire firewall — firewall rules,
     * NAT, interfaces, services, VPN, certs, system config — and rely on
     * `user-config-readonly` ("System: Deny config write") to reject all
     * persistent config writes. This is an inverted allowlist: it lists
     * (almost) the whole priv catalog and SUBTRACTS only what the backstop
     * cannot guard.
     *
     * Why this works (validated on lab OPNsense 26.1.9): every config write
     * funnels through one of two guarded chokepoints, both of which check
     * `user-config-readonly` for non-root users:
     *   - legacy `write_config()` (config.inc) — all `.php` page saves;
     *   - MVC `ApiMutableModelControllerBase::save()` — every model-backed
     *     API add/set/del/toggle (firewall rules, NAT, services, ...).
     * So edit pages render (GET) but Save/Apply is denied. Granting the
     * `*-edit` privs is therefore safe and is what makes "list all firewall
     * rules" (and open a rule to inspect it) work.
     *
     * EXCLUDED — these BYPASS the backstop (they are not config writes) or
     * are pure destructive box-level actions, so they are deliberately NOT
     * granted:
     *   - page-all                          (would grant everything blanket)
     *   - page-diagnostics-rebootsystem     (reboot — not a config write)
     *   - page-diagnostics-haltsystem       (halt — not a config write)
     *   - page-system-firmware-manualupdate (firmware upgrade/reinstall/reboot;
     *                                        FirmwareController has NO backstop check)
     *   - page-diagnostics-factorydefaults  (factory reset — destructive)
     *   - page-snapshots                    (ZFS boot-env rollback/destroy)
     *   - page-diagnostics-backup-restore   (one-click download of the FULL
     *                                        config.xml incl. all secrets — bulk
     *                                        exfil; the GET is not gated by the backstop)
     *   - page-xmlrpclibrary                (HA config-sync XMLRPC write endpoint)
     *   - page-wizard-system                (initial-setup wizard; not a view page)
     *
     * RESIDUAL (accepted): OPNsense bundles a few RUNTIME actions into the
     * same page priv as the read view, and these bypass the backstop because
     * they change no persistent config: service start/stop/reconfigure
     * (page-status-services) and firewall state kill/flush
     * (page-diagnostics-showstates). A read-only operator can therefore
     * restart a service or drop states — runtime-only and recoverable. These
     * cannot be separated from the view without losing the view.
     *
     * Maintenance: OPNsense ACL is allow-only (the sole "deny" is the
     * `user-config-readonly` flag), so a new page priv added by a future
     * OPNsense release must be added here for RO users to reach it. Re-run
     * the catalog dump (`(new OPNsense\\Core\\ACL())->getPrivList()`),
     * diff against this list, and add any new non-destructive page.
     *
     * provision() performs full desired-state reconciliation against this
     * list on every call (not just create-if-missing). ensure_readonly.php
     * calls provision() from the +MANIFEST post-install hook, so editing
     * this constant and shipping a new package propagates the change to
     * every managed device at next upgrade — no migration, no manual repair.
     */
    const READONLY_PRIVS = [
        // --- Backstop ---
        'user-config-readonly',  // System: Deny config write

        // --- Firewall ---
        'page-filter-api',  // Firewall: Rules [new]
        'page-filter-snat-api',  // Firewall: NAT: Source NAT
        'page-firewall-alias-edit',  // Firewall: Alias: Edit
        'page-firewall-aliases',  // Firewall: Aliases
        'page-firewall-categories',  // Firewall: Categories
        'page-firewall-nat-1-1-edit',  // Firewall: NAT: 1:1
        'page-firewall-nat-npt',  // Firewall: NAT: NPTv6
        'page-firewall-nat-outbound',  // Firewall: NAT: Outbound
        'page-firewall-nat-outbound-edit',  // Firewall: NAT: Outbound: Edit
        'page-firewall-nat-portforward-edit',  // Firewall: NAT: Destination NAT
        'page-firewall-rules',  // Firewall: Rules
        'page-firewall-rules-edit',  // Firewall: Rules: Edit
        'page-firewall-schedules',  // Firewall: Schedules
        'page-firewall-schedules-edit',  // Firewall: Schedules: Edit
        'page-firewall-scrub',  // Firewall: Normalization
        'page-firewall-trafficshaper',  // Firewall: Shaper
        'page-firewall-virtualipaddress-edit',  // Interfaces: Virtual IPs: Settings

        // --- Interfaces ---
        'page-hostdiscovery',  // Interfaces: Neighbors: Automatic discovery
        'page-interfaces',  // Interfaces: WAN
        'page-interfaces-assignnetworkports',  // Interfaces: Assign network ports
        'page-interfaces-bridge-edit',  // Interfaces: Bridge
        'page-interfaces-gif-edit',  // Interfaces: GIF
        'page-interfaces-gre-edit',  // Interfaces: GRE
        'page-interfaces-groups-edit',  // Firewall: Groups
        'page-interfaces-lagg-edit',  // Interfaces: LAGG: Edit
        'page-interfaces-loopback',  // Interfaces: Loopback
        'page-interfaces-neighbor',  // Interfaces: Neighbors
        'page-interfaces-ppps',  // Interfaces: PPPs
        'page-interfaces-ppps-edit',  // Interfaces: PPPs: Edit
        'page-interfaces-vlan-edit',  // Interfaces: VLAN
        'page-interfaces-vxlan',  // Interfaces: VXLAN
        'page-interfaces-wireless',  // Interfaces: Wireless
        'page-interfaces-wireless-edit',  // Interfaces: Wireless edit

        // --- Services ---
        'page-dhcp-kea-ctrl-agent',  // Services: DHCP: Kea Ctrl Agent
        'page-dhcp-kea-ddns',  // Services: DHCP: Kea DDNS Agent
        'page-dhcp-kea-v4',  // Services: DHCP: Kea(v4)
        'page-dhcp-kea-v6',  // Services: DHCP: Kea(v6)
        'page-services-captiveportal',  // Services: Captive Portal
        'page-services-dhcprelay',  // Services: DHCRelay
        'page-services-dhcpserver',  // Services: ISC DHCPv4
        'page-services-dhcpserver-editstaticmapping',  // Services: ISC DHCPv4: Edit
        'page-services-dhcpserverv6-editstaticmapping',  // Services: ISC DHCPv6: Edit
        'page-services-dhcpv6server',  // Services: ISC DHCPv6
        'page-services-dnsforwarder',  // Services: Dnsmasq DNS/DHCP: Settings
        'page-services-dnsresolver',  // Services: Unbound DNS: General
        'page-services-dnsresolver-acls',  // Services: Unbound DNS: Access Lists
        'page-services-dnsresolver-advanced',  // Services: Unbound DNS: Advanced
        'page-services-dnsresolver-overrides',  // Services: Unbound DNS: Edit Host and Domain Override
        'page-services-ids',  // Services: Intrusion Detection
        'page-services-monit',  // WebCfg - Services: Monit System Monitoring page
        'page-services-netdefense',  // Services: NetDefense
        'page-services-ntp-gps',  // Services: NTP GPS
        'page-services-ntp-pps',  // Services: NTP PPS
        'page-services-ntpd',  // Services: NTP
        'page-services-opendns',  // Services: DNS Filter
        'page-services-qemuguestagent',  // Services: QEMU Guest Agent
        'page-services-router-advertisements',  // Services: Router Advertisements: Settings
        'page-services-unbound',  // Services: Unbound

        // --- VPN ---
        'page-openvpn-client-export',  // VPN: OpenVPN: Client Export Utility
        'page-openvpn-csc',  // VPN: OpenVPN: Client Specific Override
        'page-openvpn-instances',  // VPN: OpenVPN: Instances
        'page-tailscale-config',  // Tailscale
        'page-vpn-ipsec-connections',  // VPN: IPsec: Connections
        'page-vpn-ipsec-editkeys',  // VPN: IPsec: Edit Pre-Shared Keys
        'page-vpn-ipsec-keypairs',  // VPN: IPsec: Key Pairs
        'page-wireguard-config',  // VPN: WireGuard: Configuration
        'page-wireguard-diagnostics',  // VPN: WireGuard: Status
        'page-wireguard-logs',  // VPN: WireGuard: Log

        // --- Status / Reporting ---
        'page-status-carp',  // Interfaces: Virtual IPs: Status
        'page-status-dhcpleases',  // Services: ISC DHCPv4: Leases
        'page-status-dhcpv6leases',  // Status: ISC DHCPv6: Leases
        'page-status-dnsoverview',  // Status: DNS Overview
        'page-status-habackup',  // Status: HA backup
        'page-status-interfaces',  // Status: Interfaces
        'page-status-ipsec',  // Status: IPsec
        'page-status-ipsec-leases',  // Status: IPsec: Leasespage
        'page-status-ipsec-sad',  // Status: IPsec: SAD
        'page-status-ipsec-spd',  // Status: IPsec: SPD
        'page-status-ntp',  // Status: NTP
        'page-status-openvpn',  // Status: OpenVPN
        'page-status-services',  // Status: Services
        'page-status-systemlogs-ipsecvpn',  // Status: System logs: IPsec VPN
        'page-status-systemlogs-ntpd',  // Status: System logs: NTP
        'page-status-systemlogs-openvpn',  // Status: System logs: OpenVPN
        'page-status-systemlogs-portalauth',  // Status: System logs: Captive portal
        'page-status-systemlogs-ppp',  // Status: System logs: PPP
        'page-status-systemlogs-routing',  // Status: System logs: Routing
        'page-status-systemlogs-wireless',  // Status: System logs: Wireless
        'page-status-trafficgraph',  // Reporting: Traffic

        // --- Diagnostics & Logs ---
        'page-diagnostics-arptable',  // Diagnostics: ARP Table
        'page-diagnostics-authentication',  // Diagnostics: Authentication
        'page-diagnostics-configurationhistory',  // Diagnostics: Configuration History
        'page-diagnostics-crash-reporter',  // System: Crash Reporter
        'page-diagnostics-dns_diagnostics',  // Interfaces: Diagnostics: DNS Lookup
        'page-diagnostics-health',  // Diagnostics: System Health
        'page-diagnostics-limiter-info',  // Diagnostics: Shaper status
        'page-diagnostics-logs-dhcp',  // Services: ISC DHCPv4: Log File
        'page-diagnostics-logs-dnsmasq',  // Services: Dnsmasq DNS/DHCP: Log File
        'page-diagnostics-logs-firewall-dynamic',  // Diagnostics: Logs: Firewall: Live View
        'page-diagnostics-logs-firewall-general',  // Diagnostics: Log: Firewall: General
        'page-diagnostics-logs-firewall-plain',  // Diagnostics: Logs: Firewall: Plain View
        'page-diagnostics-logs-firewall-summary',  // Diagnostics: Logs: Firewall: Summary View
        'page-diagnostics-logs-gateways',  // Diagnostics: Logs: Gateways
        'page-diagnostics-logs-hostdiscovery',  // Interfaces: Neighbors: Discovery Log
        'page-diagnostics-logs-kea',  // Services: DHCP: Kea Log File
        'page-diagnostics-logs-resolver',  // Services: Unbound DNS: Log File
        'page-diagnostics-logs-settings-targets',  // System: Settings: Logging
        'page-diagnostics-logs-system',  // Diagnostics: Logs: System
        'page-diagnostics-ndptable',  // Diagnostics: NDP Table
        'page-diagnostics-netflow',  // Diagnostics: Netflow configuration
        'page-diagnostics-netstat',  // Diagnostics: Netstat
        'page-diagnostics-networkinsight',  // Diagnostics: Network Insight
        'page-diagnostics-packetcapture',  // Diagnostics: Packet Capture
        'page-diagnostics-pf-info',  // Diagnostics: Firewall statistics
        'page-diagnostics-ping',  // Diagnostics: Ping
        'page-diagnostics-routingtables',  // Diagnostics: Routing tables
        'page-diagnostics-showstates',  // Diagnostics: Show States
        'page-diagnostics-system-activity',  // Diagnostics: System Activity
        'page-diagnostics-system-pftop',  // Diagnostics: Firewall sessions
        'page-diagnostics-tables',  // Diagnostics: PF Table IP addresses
        'page-diagnostics-testport',  // Diagnostics: Test Port
        'page-diagnostics-traceroute',  // Diagnostics: Traceroute
        'page-diagnostics-wirelessstatus',  // Status: Wireless

        // --- System (read views; writes blocked by backstop) ---
        'page-system-advanced-admin',  // System: Advanced: Admin Access Page
        'page-system-advanced-firewall',  // System: Advanced: Firewall and NAT
        'page-system-advanced-misc',  // System: Advanced: Miscellaneous
        'page-system-advanced-network',  // Interfaces: Settings
        'page-system-advanced-sysctl',  // System: Advanced: Tunables
        'page-system-authservers',  // System: Authentication Servers
        'page-system-camanager',  // System: CA Manager
        'page-system-certmanager',  // System: Certificate Manager
        'page-system-crlmanager',  // System: CRL Manager
        'page-system-cron',  // System: Settings: Cron
        'page-system-gatewaygroups',  // System: Gateway Groups
        'page-system-gateways',  // System: Gateways
        'page-system-gateways-editgatewaygroups',  // System: Gateways: Edit Gateway Groups
        'page-system-generalsetup',  // System: General Setup
        'page-system-groupmanager',  // System: Access: Groups
        'page-system-hasync',  // System: High Availability
        'page-system-license',  // Lobby: License
        'page-system-login-logout',  // Lobby: Dashboard
        'page-system-staticroutes',  // System: Static Routes
        'page-system-status',  // System: Status
        'page-system-usermanager',  // System: Access: Users
        'page-system-usermanager-addprivs',  // System: Access: Privileges
        'page-system-usermanager-passwordmg',  // Lobby: Password
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
