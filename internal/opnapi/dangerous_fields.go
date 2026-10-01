package opnapi

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
//   - USER/GROUP: priv naming an administrator-equivalent privilege, as the
//     shared catalog classifies it (PrivPolicy.IsAdminEquivalentPriv: a
//     catalog admin-equivalent ID, an ID the catalog does not know, or the
//     structural floor page-all / *-all / system+admin / all-pages);
//     scope=="system"; non-empty shell outside the nologin allowlist;
//     non-empty authorizedkeys.
//   - USER: groups naming a protected group (admins, netdefense-readonly),
//     which is administrator access or the read-only identity's ACL. A group
//     that is administrator-equivalent only on this device is the caller's to
//     check against the live rows.
//   - ZABBIX_USERPARAMETER: non-empty command.
//   - ZABBIX_SETTINGS: enable_remote_commands==true; sudo_root==true.
//     server_list is deliberately NOT constrained (legitimate MSSP
//     off-LAN Zabbix servers).

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
func DangerousUserFields(u APIUserPayload, policy PrivPolicy) []string {
	var found []string
	if policy.HasAdminEquivalentPriv(u.Priv) {
		found = append(found, "priv")
	}
	for _, entry := range u.Groups {
		if GroupEntryNamesProtectedGroup(entry) {
			found = append(found, "groups")
			break
		}
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
func DangerousGroupFields(g APIGroupPayload, policy PrivPolicy) []string {
	if policy.HasAdminEquivalentPriv(g.Priv) {
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
