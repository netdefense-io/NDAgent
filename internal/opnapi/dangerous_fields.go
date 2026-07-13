package opnapi

import "strings"

// Dangerous-field detection for the device-local SYNC_API opt-in gate
// (config: reject_dangerous_snippets, default false/permissive).
//
// This mirrors NDManager's producer-side dangerous-field validators (the
// primary control there is an org:su gate). The device-side gate is
// defense-in-depth only: detection here never blocks anything by itself —
// callers in internal/tasks consult ws.RejectDangerousSnippets() and only
// reject an element when the operator has explicitly opted in.
//
// Field set (kept in sync with the producer's definition so the two don't
// drift):
//   - USER/GROUP: priv containing page-all/all-pages/system-admin;
//     scope=="system"; non-empty shell outside the nologin allowlist;
//     non-empty authorizedkeys.
//   - ZABBIX_USERPARAMETER: non-empty command.
//   - ZABBIX_SETTINGS: enable_remote_commands==true; sudo_root==true.
//     server_list is deliberately NOT constrained (legitimate MSSP
//     off-LAN Zabbix servers).

// dangerousUserPrivs are the OPNsense priv tokens that grant broad/admin
// access. page-all is the real OPNsense priv (see the read-only ACL
// gotchas in CLAUDE.md); all-pages and system-admin are additional
// aliases mirrored from the producer-side validator's dangerous-priv set.
var dangerousUserPrivs = map[string]bool{
	"page-all":     true,
	"all-pages":    true,
	"system-admin": true,
}

// nologinShells are shell values that do NOT count as dangerous — an empty
// shell and the standard nologin binaries are the expected values for
// service/monitoring accounts that can't log in interactively.
var nologinShells = map[string]bool{
	"":                  true,
	"/usr/sbin/nologin": true,
	"/sbin/nologin":     true,
	"/usr/bin/false":    true,
}

// DangerousUserFields returns the names of dangerous fields present on a
// USER snippet payload, or nil if none. An empty return means the payload
// is safe to apply regardless of the gate.
func DangerousUserFields(u APIUserPayload) []string {
	var found []string
	if hasDangerousPriv(u.Priv) {
		found = append(found, "priv")
	}
	if u.Scope == "system" {
		found = append(found, "scope")
	}
	if !nologinShells[u.Shell] {
		found = append(found, "shell")
	}
	if u.AuthorizedKeys != "" {
		found = append(found, "authorizedkeys")
	}
	return found
}

// DangerousGroupFields returns the names of dangerous fields present on a
// GROUP snippet payload, or nil if none.
func DangerousGroupFields(g APIGroupPayload) []string {
	if hasDangerousPriv(g.Priv) {
		return []string{"priv"}
	}
	return nil
}

// DangerousZabbixUserParameterFields returns the names of dangerous fields
// present on a ZABBIX_USERPARAMETER snippet payload, or nil if none. A
// UserParameter's `command` is an arbitrary shell command the Zabbix
// server can trigger on demand — that's the entire risk surface.
func DangerousZabbixUserParameterFields(up APIZabbixUserParameterPayload) []string {
	if up.Command != "" {
		return []string{"command"}
	}
	return nil
}

// DangerousZabbixSettingsFields returns the names of dangerous fields
// present on a ZABBIX_SETTINGS snippet payload, or nil if none.
// server_list is intentionally not checked — legitimate MSSP deployments
// point Zabbix at an off-LAN monitoring server.
func DangerousZabbixSettingsFields(p APIZabbixSettingsPayload) []string {
	var found []string
	if p.EnableRemoteCommands {
		found = append(found, "enable_remote_commands")
	}
	if p.SudoRoot {
		found = append(found, "sudo_root")
	}
	return found
}

// hasDangerousPriv checks a priv list for a blanket-access grant. Each
// element is split on "," (and trimmed) before the lookup: OPNsense's
// PrivField is comma-joined on the wire (StringsToCSV in users.go), so a
// caller-supplied element like "page-firewall-rules,page-all" resolves to
// the individual priv "page-all" once applied — an exact per-element lookup
// alone would miss it.
func hasDangerousPriv(privs []string) bool {
	for _, p := range privs {
		for _, tok := range strings.Split(p, ",") {
			if dangerousUserPrivs[strings.TrimSpace(tok)] {
				return true
			}
		}
	}
	return false
}
