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
use OPNsense\Core\ACL;

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
 * The user has NO API key and a scrambled password nobody knows: it is
 * never used for REST or a real login, only as the forged-session identity.
 * The password exists because OPNsense rejects a user without one (see
 * LocalAccounts). See internal/tasks/connect.go (read_only flag) and
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
     * Why this works: config writes funnel through two chokepoints, both of
     * which check `user-config-readonly` for non-root users:
     *   - legacy `write_config()` (config.inc) — all `.php` page saves;
     *   - MVC `ApiMutableModelControllerBase::save()` — every model-backed
     *     API add/set/del/toggle (firewall rules, NAT, services, ...).
     * So edit pages render (GET) but Save/Apply is denied. Granting the
     * `*-edit` privs is therefore safe and is what makes "list all firewall
     * rules" (and open a rule to inspect it) work. This is an argument from
     * the two chokepoints, not an audit of every page: a handler that saves
     * the config or acts on the system without going through them is not
     * covered.
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
     *   - page-services-netdefense          (this plugin's OWN full-admin priv;
     *                                        its api/netdefense/* wildcard covers
     *                                        settings/get — cleartext apiKey/apiSecret
     *                                        in the model — plus settings/setupApiCreds,
     *                                        settings/regenerateApiCreds, and
     *                                        service/(start|stop|restart|reconfigure).
     *                                        None of those routes are config-write
     *                                        calls the ApiMutableModelControllerBase
     *                                        backstop can see, so the backstop does not
     *                                        protect them. Use the narrow
     *                                        page-services-netdefense-status priv below
     *                                        instead — explicit non-wildcard patterns
     *                                        covering only the status/log routes an RO
     *                                        operator needs.)
     *   - page-system-trust-settings        (its reconfigure action runs
     *                                        `system trust configure` and
     *                                        `cron restart`: a runtime action,
     *                                        not a config write, so the
     *                                        backstop does not stop it)
     *   - page-diagnostics-logs-dhcrelay    (26.7.4 only: upstream folds its
     *                                        patterns back into
     *                                        page-services-dhcprelay, which is
     *                                        granted)
     *   - page-diagnostics-crash-reporter   (crash_reporter.php prints the PHP
     *                                        error log, dmesg and /var/crash as
     *                                        they are: free text no rule can
     *                                        clean, and the PHP log holds the
     *                                        call arguments of a stack trace,
     *                                        because php.ini logs errors and
     *                                        leaves zend.exception_ignore_args
     *                                        off)
     *   - page-diagnostics-packetcapture    (views and downloads the traffic an
     *                                        administrator captured, whatever
     *                                        credentials it carried; a
     *                                        read-only session cannot start a
     *                                        capture, so it would only ever read
     *                                        those)
     *
     * INCLUDED (narrow substitute): page-services-netdefense-status grants only
     * the status/log routes of this plugin (API status check, agent version /
     * WS-connection status, ndagent service run state, ndagent log viewer)
     * via explicit non-wildcard patterns in ACL.xml — no settings, no
     * credentials, no service control (start/stop/restart/reconfigure). This
     * also includes the plugin's own settings page route
     * (ui/netdefense/settings*) — without it the page itself 403s before an
     * RO session ever reaches the JS that fires the status calls above, so
     * the page-level route is required for the status view to be reachable
     * at all. It also includes api/netdefense/service/status* — the plain
     * run-state read (ApiMutableServiceControllerBase::statusAction(),
     * "Service running/stopped") the settings page polls on load; the
     * pattern is a literal prefix match so it cannot collide with the
     * mutating service/(start|stop|restart|reconfigure) routes (verified via
     * the ACL::urlMatch() port in the priv-drift test). Safe to grant:
     * SettingsController::indexAction() only renders the form shell, and the
     * getAction() strip + setupApiCreds/regenerate guards below still gate
     * the underlying data/mutation regardless of which page privs the caller
     * holds. See ACL.xml for the exact pattern list.
     *
     * RESIDUAL: OPNsense bundles RUNTIME actions into the same page priv as
     * the read view, and these bypass the backstop because they are not
     * config writes or do not ask for it: service start/stop/reconfigure
     * (page-status-services), firewall state kill/flush
     * (page-diagnostics-showstates), interface and firewall apply, log clear,
     * legacy page POSTs, and more. The ACL cannot separate them from the
     * view, so the agent's webadmin proxy refuses them (readOnlyRefusal in
     * internal/pathfinder/readonly_routes.go), the read-only account's own
     * dashboard and menu-favorite saves included, which OPNsense permits on
     * purpose. Accepted: the Rescan link of the wireless status page, and the
     * two residuals about stored secrets under SECRETS below.
     *
     * SECRETS: the ACL grants the views that load stored secrets (certificate
     * and CA keys, WireGuard and IPsec keys, OpenVPN static keys, user password
     * hashes and OTP seeds, ...) together with the rest of the page, and
     * user-config-readonly limits writes, not reads. The webadmin proxy
     * therefore refuses the routes that hand out key material and blanks the
     * named secret fields out of the responses of the others (scrubRules in
     * internal/pathfinder/readonly_scrub.go). No privilege is dropped from this
     * list for them: the read-only operator sees the pages and what they list,
     * not the secrets. Two pages are dropped because what they print is free
     * text that no rule can clean (see EXCLUDED above): the crash reporter and
     * the packet capture.
     *
     * RESIDUAL (secrets), accepted by the operator:
     *   - A grid's search is forwarded. The grid matches the search phrase
     *     against the stored fields of a row, secret included, before the proxy
     *     blanks anything, so a patient read-only user can infer a hidden
     *     stored value (a password hash, a private key, a pre-shared key) by
     *     guessing through the list search. The response itself never carries
     *     the secret.
     *   - Logs and free-text settings (an alias URL, a cron command, a custom
     *     option and the like) stay readable and are not cleaned: they hold
     *     what a component wrote into them, or what an operator typed. The
     *     crash reporter stays excluded.
     *
     * EXCLUDED (AUTH_SERVER / AUTH_ORDER, unconditional): three more
     * pages the earlier inverted-allowlist reasoning above does not cover,
     * because each grants an RO session something beyond a config-write-
     * blocked view once directory authentication servers can exist
     * (`ldap_bindpw` is plaintext in config.xml):
     *   - page-system-authservers          (the auth-servers EDIT page
     *                                        renders `ldap_bindpw` directly
     *                                        into the HTML response body,
     *                                        `value="<?=$pconfig['ldap_bindpw'];?>"`
     *                                        — `type="password"` only masks
     *                                        the browser's rendering, not
     *                                        the wire response; confirmed
     *                                        against the live page source
     *                                        on the lab)
     *   - page-diagnostics-configurationhistory (the History diff/download
     *                                        API returns full config.xml
     *                                        content/diffs, unredacted —
     *                                        any revision spanning an
     *                                        AUTH_SERVER change exposes
     *                                        `ldap_bindpw` the same way)
     *   - page-diagnostics-authentication  (the Authentication TESTER does
     *                                        NOT leak the bind password —
     *                                        confirmed by tracing
     *                                        LDAP.php's `_authenticate()`,
     *                                        which populates
     *                                        `lastAuthProperties` from the
     *                                        TESTED user's own attributes,
     *                                        never the bind credential —
     *                                        excluded instead for a
     *                                        narrower reason: it hands a
     *                                        nominally read-only session an
     *                                        active credential-testing /
     *                                        username-enumeration
     *                                        capability against any
     *                                        configured server)
     * All three are removed unconditionally, not gated on whether any
     * AUTH_SERVER exists yet — the read-only group is provisioned once, at
     * install time, long before an org may attach its first AUTH_SERVER
     * snippet.
     *
     * Maintenance: OPNsense ACL is allow-only (the sole "deny" is the
     * `user-config-readonly` flag), so a new page priv added by a future
     * OPNsense release must be added here for RO users to reach it, or to
     * READONLY_EXCLUDED_PRIVS when it must stay out. A test against the
     * catalogs of the supported releases fails on an id that is in neither.
     *
     * This list is a superset. An id the running OPNsense does not know (a
     * plugin that is not installed, a page another release renamed or
     * removed) is never written to the group: OPNsense's model validation
     * rejects it ("Option [..] not in list") and the ACL ignores it anyway.
     * provision() performs full desired-state reconciliation against
     * effectivePrivs(), this list narrowed to the running catalog, on every
     * call (not just create-if-missing). ensure_readonly.php calls it from
     * the +MANIFEST post-install hook, at boot and after a core update, so
     * editing this constant and shipping a new package propagates the change
     * to every managed device at next upgrade — no migration, no manual repair.
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
        'page-services-netdefense-status',  // Services: NetDefense (status only)
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
        // page-diagnostics-authentication and page-diagnostics-
        // configurationhistory are deliberately absent — see the
        // AUTH_SERVER/AUTH_ORDER doc-comment note above the const —
        // and so are page-diagnostics-crash-reporter and
        // page-diagnostics-packetcapture (free text that cannot be cleaned).
        'page-diagnostics-arptable',  // Diagnostics: ARP Table
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
        'page-diagnostics-pf-info',  // Diagnostics: Firewall statistics
        'page-diagnostics-ping',  // Diagnostics: Ping
        'page-diagnostics-routingtables',  // Diagnostics: Routing tables
        'page-diagnostics-showstates',  // Diagnostics: Show States
        'page-diagnostics-system-activity',  // Diagnostics: System Activity
        'page-diagnostics-system-pftop',  // Diagnostics: Firewall sessions
        'page-diagnostics-system-statistics',  // System: Diagnostics: Statistics
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
        // page-system-authservers is deliberately absent — see the
        // AUTH_SERVER/AUTH_ORDER doc-comment note above the const.
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
     * Privileges an OPNsense release ships that are deliberately NOT granted
     * (the reasons are in the READONLY_PRIVS doc comment). A privilege a
     * release carries is in READONLY_PRIVS or here, so a page nobody has
     * decided about is a test failure, not a silent gap.
     */
    const READONLY_EXCLUDED_PRIVS = [
        'page-all',
        'page-diagnostics-rebootsystem',
        'page-diagnostics-haltsystem',
        'page-system-firmware-manualupdate',
        'page-diagnostics-factorydefaults',
        'page-snapshots',
        'page-diagnostics-backup-restore',
        'page-xmlrpclibrary',
        'page-wizard-system',
        'page-services-netdefense',
        'page-system-authservers',
        'page-diagnostics-configurationhistory',
        'page-diagnostics-authentication',
        'page-system-trust-settings',
        'page-diagnostics-logs-dhcrelay',
        'page-diagnostics-crash-reporter',
        'page-diagnostics-packetcapture',
    ];

    /** Denies config writes; it is a deny, so it is granted whatever the catalog says. */
    const READONLY_BACKSTOP_PRIV = 'user-config-readonly';

    /** Core alone carries well over this many privileges on every supported release. */
    const CATALOG_MIN_ENTRIES = 100;

    /** Every release's catalog has these; one without them is not the real catalog. */
    const CATALOG_ANCHORS = ['page-all', self::READONLY_BACKSTOP_PRIV];

    /**
     * The privilege ids the running OPNsense knows (core and installed
     * plugins), or null when they cannot be read reliably.
     *
     * ACL::getPrivList() answers from a cache that is rebuilt hourly and
     * flushed only by rc.configure_plugins and rc.configure_firmware. The pkg
     * post-install hook runs ensure_readonly.php BEFORE rc.configure_plugins:
     * read as it stands, the cache can lack this plugin's own ACL.xml. The
     * cache is dropped first, and a second instance rebuilds it, because an
     * instance keeps the tags it loaded.
     *
     * Never throws: the caller runs from pkg and boot hooks that must not fail.
     *
     * @return string[]|null
     */
    public static function knownPrivs(): ?array
    {
        try {
            (new ACL())->invalidateCache();
            $list = (new ACL())->getPrivList();
        } catch (\Throwable $e) {
            return null;
        }
        if (!is_array($list) || count($list) < self::CATALOG_MIN_ENTRIES) {
            return null;
        }
        foreach (self::CATALOG_ANCHORS as $anchor) {
            if (!array_key_exists($anchor, $list)) {
                return null;
            }
        }
        return array_keys($list);
    }

    /**
     * The privileges the group is to hold: READONLY_PRIVS, in its order, with
     * every id the catalog does not know left out. OPNsense's model
     * validation rejects such an id ("Option [..] not in list") and the ACL
     * ignores it, so leaving it out changes no access.
     *
     * Without a catalog ($known null) nothing can be vouched for: the group
     * keeps the READONLY_PRIVS ids it already holds and gains none, and
     * anything else in it is dropped. The write backstop is always kept.
     *
     * @param string[]|null $known knownPrivs()
     * @param string[] $current the ids the group holds now
     * @return string[]
     */
    public static function effectivePrivs(?array $known, array $current = []): array
    {
        $grantable = array_flip($known ?? $current);
        return array_values(array_filter(self::READONLY_PRIVS, function ($priv) use ($grantable) {
            return $priv === self::READONLY_BACKSTOP_PRIV || isset($grantable[$priv]);
        }));
    }

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
     * Idempotency: if the group exists with the curated priv set (the
     * effectivePrivs() of the running catalog), the user exists with a
     * password, and the user is already a member, returns
     * ['result'=>'skipped',...] without churn. Otherwise it creates/repairs
     * whichever pieces are missing (group, user, user password, membership,
     * priv set) and returns ['result'=>'ok',...]. An existing password is
     * never replaced; an empty one (from a release that created the user
     * without) gets a scrambled hash, on every row of that name (a
     * hand-edited or merged config.xml can hold it twice).
     *
     * 'password' is 'set', 'kept' or 'failed' (LocalAccounts::PASSWORD_*);
     * 'failed' wins when any row could not be hashed. A failure to hash never
     * aborts the group reconcile of an existing user; only a user that cannot
     * be created without a password returns result 'failed' for it, before
     * anything is written.
     *
     * 'privs' (absent on 'failed') says what the group was left with:
     * 'granted' is the count, 'left_out' the READONLY_PRIVS ids not granted
     * and 'catalog_trusted' whether the running catalog could be read. When it
     * could not, the group gains nothing (effectivePrivs()).
     *
     * @return array{result:string,message:string,password:string,privs?:array{granted:int,left_out:string[],catalog_trusted:bool}}
     */
    public static function provision(): array
    {
        $changed = false;
        $password = LocalAccounts::PASSWORD_KEPT;

        // --- User: ensure it exists with the correct shape. ---
        $userMdl = new User();
        $userUid = null;
        $anyFailed = false;
        foreach ($userMdl->user->iterateItems() as $user) {
            if ((string)$user->name !== self::READONLY_USERNAME) {
                continue;
            }
            // The group <member> takes the uid of the first row; every row
            // still needs its password, or OPNsense's validation rejects it.
            if ($userUid === null) {
                $userUid = (string)$user->uid;
            }
            $outcome = LocalAccounts::fillPassword($userMdl, $user);
            $changed = $changed || $outcome === LocalAccounts::PASSWORD_SET;
            $anyFailed = $anyFailed || $outcome === LocalAccounts::PASSWORD_FAILED;
        }
        if ($anyFailed) {
            $password = LocalAccounts::PASSWORD_FAILED;
        } elseif ($changed) {
            $password = LocalAccounts::PASSWORD_SET;
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
            // No API key, no per-user priv. The group carries the curated
            // ACL; the forged PHP session carries the identity. The password
            // is scrambled: OPNsense refuses a user without one.
            if (LocalAccounts::fillPassword($userMdl, $user) === LocalAccounts::PASSWORD_FAILED) {
                return [
                    'result' => 'failed',
                    'message' => 'Failed to generate a password hash for the ' . self::READONLY_USERNAME . ' user',
                    'password' => LocalAccounts::PASSWORD_FAILED,
                ];
            }
            $password = LocalAccounts::PASSWORD_SET;
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

        // Reconcile the priv set against what this OPNsense can hold (sorted
        // comparison so order/whitespace differences don't trigger spurious
        // rewrites).
        $current = array_filter(explode(',', (string)$group->priv));
        $catalog = self::knownPrivs();
        $desired = self::effectivePrivs($catalog, $current);
        sort($current);
        $desiredSorted = $desired;
        sort($desiredSorted);
        if ($current !== $desiredSorted) {
            $group->priv = implode(',', $desired);
            $groupDirty = true;
        }
        $privs = [
            'granted' => count($desired),
            'left_out' => array_values(array_diff(self::READONLY_PRIVS, $desired)),
            'catalog_trusted' => $catalog !== null,
        ];

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
                'password' => $password,
                'privs' => $privs,
            ];
        }

        return [
            'result' => 'ok',
            'message' => 'Read-only webadmin user provisioned successfully',
            'password' => $password,
            'privs' => $privs,
        ];
    }

    /**
     * The exact inverse of provision(): remove the netdefense-readonly
     * group and user.
     *
     * The decommission sequence normally removes this identity over the
     * OPNsense API (that call does work — the agent is not authenticating
     * as this user). This local path exists so the same
     * `configure.php --deprovision-accounts` call that removes the agent's
     * own API user also cleans up the read-only identity when the API pass
     * never ran or failed: no OPNsense credentials on the device, an API
     * that was unreachable, or a rerun of the sequence.
     *
     * Group first, then user: the group carries the membership, and
     * removing it first means no window where a group points at a uid
     * that no longer resolves.
     *
     * Caller owns the Config lock + save + Backend triggers, exactly as
     * for provision(). Idempotent: already absent reports 'skipped'.
     *
     * @return array{result:string,removed:bool,message:string}
     */
    public static function deprovision(): array
    {
        $groupRemoved = LocalAccounts::removeGroup(self::READONLY_GROUPNAME);
        $userRemoved = LocalAccounts::removeUser(self::READONLY_USERNAME);
        $removed = $groupRemoved || $userRemoved;

        return [
            'result' => $removed ? 'ok' : 'skipped',
            'removed' => $removed,
            'message' => $removed
                ? 'Read-only webadmin user and group removed.'
                : 'No read-only webadmin user or group present; no change.',
        ];
    }
}
