package opnapi

import "strings"

// Dangerous-field detection for the device-local SYNC_API gate (config:
// reject_dangerous_snippets, default true/secure — see config.Config's doc
// comment on that field for the grandfathering story on upgrade).
//
// This mirrors NDManager's producer-side dangerous-field validators (the
// primary control there is an org:su gate). The device-side gate is
// defense-in-depth only: detection here never blocks anything by itself —
// callers in internal/tasks consult ws.RejectDangerousSnippets() and only
// reject an element when the gate is on.
//
// Field set (kept in sync with the producer's definition so the two don't
// drift):
//   - USER/GROUP: priv granting blanket access — exact "page-all", any
//     token ending in "-all" (category-wide grant), any token containing
//     both "system" and "admin", or the agent-only "all-pages" alias (see
//     privGrantsBlanketAccess and agentOnlyDangerousPrivs); scope=="system";
//     non-empty shell outside the nologin allowlist; non-empty
//     authorizedkeys.
//   - ZABBIX_USERPARAMETER: non-empty command.
//   - ZABBIX_SETTINGS: enable_remote_commands==true; sudo_root==true.
//     server_list is deliberately NOT constrained (legitimate MSSP
//     off-LAN Zabbix servers).

// agentOnlyDangerousPrivs are additional priv tokens flagged dangerous on
// the agent side only, beyond the canonical pattern in privGrantsBlanketAccess.
// all-pages does not match any of that pattern's rules (it's not exactly
// "page-all", does not end in "-all", and doesn't contain both "system"
// and "admin") but was part of this gate's original literal set, so it's
// kept as a union addition — this keeps the agent at least as strict as
// the canonical NDManager-side check, never less.
var agentOnlyDangerousPrivs = map[string]bool{
	"all-pages": true,
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
			t := strings.ToLower(strings.TrimSpace(tok))
			if t == "" {
				continue
			}
			if privGrantsBlanketAccess(t) || agentOnlyDangerousPrivs[t] {
				return true
			}
		}
	}
	return false
}

// privGrantsBlanketAccess reports whether a single (already lowercased and
// trimmed) OPNsense ACL privilege token grants blanket page/system access.
//
// This is a faithful port of NDManager's canonical, producer-side check —
// NDDataModels/NDDataModels/Schema.py's _priv_grants_blanket_access — kept
// in sync manually since there's no shared library between the Python
// service and this Go agent. Do not let the two drift: the agent's gate is
// defense-in-depth, but it should catch at least everything the primary,
// server-side control catches.
//
// "page-all" is OPNsense's literal "full system administrator" ACL ID: it
// grants every "page-*" privilege at once, i.e. root-equivalent access on
// the web GUI. Any token ending in "-all" (a category-wide grant) and any
// token mentioning both "system" and "admin" are also flagged, as a
// conservative catch-all — a false positive here only costs an extra
// clearance check; a false negative is a privilege escalation.
func privGrantsBlanketAccess(tok string) bool {
	if tok == "page-all" {
		return true
	}
	if strings.HasSuffix(tok, "-all") {
		return true
	}
	if strings.Contains(tok, "system") && strings.Contains(tok, "admin") {
		return true
	}
	return false
}
