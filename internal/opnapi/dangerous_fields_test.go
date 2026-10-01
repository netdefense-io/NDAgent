package opnapi

import (
	"reflect"
	"sort"
	"testing"
)

func sortedStrings(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

func TestDangerousUserFields(t *testing.T) {
	tests := []struct {
		name string
		user APIUserPayload
		want []string
	}{
		{
			name: "fully safe monitoring account",
			user: APIUserPayload{
				Name:  "svc-monitor",
				Scope: "user",
				Shell: "/usr/sbin/nologin",
			},
			want: nil,
		},
		{
			name: "empty shell is safe",
			user: APIUserPayload{Name: "svc", Scope: "user", Shell: ""},
			want: nil,
		},
		{
			name: "sbin nologin is safe",
			user: APIUserPayload{Name: "svc", Scope: "user", Shell: "/sbin/nologin"},
			want: nil,
		},
		{
			name: "usr bin false is safe",
			user: APIUserPayload{Name: "svc", Scope: "user", Shell: "/usr/bin/false"},
			want: nil,
		},
		{
			name: "page-all priv is dangerous",
			user: APIUserPayload{Name: "u", Priv: []string{"page-firewall-rules", "page-all"}},
			want: []string{"priv"},
		},
		{
			name: "all-pages priv is dangerous",
			user: APIUserPayload{Name: "u", Priv: []string{"all-pages"}},
			want: []string{"priv"},
		},
		{
			name: "system-admin priv is dangerous",
			user: APIUserPayload{Name: "u", Priv: []string{"system-admin"}},
			want: []string{"priv"},
		},
		{
			name: "reviewed ordinary privs are safe",
			user: APIUserPayload{Name: "u", Priv: []string{"page-status-services", "page-diagnostics-arptable"}},
			want: nil,
		},
		{
			name: "comma-joined priv element containing page-all is dangerous",
			user: APIUserPayload{Name: "u", Priv: []string{"page-all,other"}},
			want: []string{"priv"},
		},
		{
			name: "comma-joined priv element with whitespace around the dangerous token is dangerous",
			user: APIUserPayload{Name: "u", Priv: []string{"other, page-all "}},
			want: []string{"priv"},
		},
		{
			name: "comma-joined priv element with no dangerous token is safe",
			user: APIUserPayload{Name: "u", Priv: []string{"page-status-services,page-diagnostics-arptable"}},
			want: nil,
		},
		{
			// Divergence case: matches the canonical NDManager-side
			// pattern (_priv_grants_blanket_access) via the "-all" suffix
			// rule, which the agent's old exact-match set missed.
			name: "network-all priv is dangerous (canonical -all suffix rule)",
			user: APIUserPayload{Name: "u", Priv: []string{"network-all"}},
			want: []string{"priv"},
		},
		{
			name: "page-firewall-all priv is dangerous (canonical -all suffix rule)",
			user: APIUserPayload{Name: "u", Priv: []string{"page-firewall-all"}},
			want: []string{"priv"},
		},
		{
			// Divergence case: matches via the canonical "contains both
			// system and admin" rule, not an exact match.
			name: "admin-system-full priv is dangerous (canonical system+admin rule)",
			user: APIUserPayload{Name: "u", Priv: []string{"admin-system-full"}},
			want: []string{"priv"},
		},
		{
			name: "system-super-admin priv is dangerous (canonical system+admin rule)",
			user: APIUserPayload{Name: "u", Priv: []string{"system-super-admin"}},
			want: []string{"priv"},
		},
		{
			// Negative: a reviewed ID that contains "system" but not "admin"
			// matches none of the three structural rules and is ordinary in
			// the catalog.
			name: "page-diagnostics-system-activity priv is safe (system without admin)",
			user: APIUserPayload{Name: "u", Priv: []string{"page-diagnostics-system-activity"}},
			want: nil,
		},
		{
			// The structural rules alone missed this: it has no -all suffix
			// and no "admin", yet it lets its holder edit users, groups and
			// privileges, and so promote themselves.
			name: "page-system-usermanager priv is dangerous (catalog, not the structural rules)",
			user: APIUserPayload{Name: "u", Priv: []string{"page-system-usermanager"}},
			want: []string{"priv"},
		},
		{
			name: "page-system-groupmanager priv is dangerous (26.1 split of the user manager)",
			user: APIUserPayload{Name: "u", Priv: []string{"page-system-groupmanager"}},
			want: []string{"priv"},
		},
		{
			name: "page-system-usermanager-addprivs priv is dangerous (26.1 split of the user manager)",
			user: APIUserPayload{Name: "u", Priv: []string{"page-system-usermanager-addprivs"}},
			want: []string{"priv"},
		},
		{
			name: "page-diagnostics-backup-restore priv is dangerous (whole config export)",
			user: APIUserPayload{Name: "u", Priv: []string{"page-diagnostics-backup-restore"}},
			want: []string{"priv"},
		},
		{
			name: "an ID the catalog does not know is dangerous (unknown means elevated)",
			user: APIUserPayload{Name: "u", Priv: []string{"page-nobody-reviewed-this"}},
			want: []string{"priv"},
		},
		{
			name: "page-system-usermanager-passwordmg priv is safe (self-service password page)",
			user: APIUserPayload{Name: "u", Priv: []string{"page-system-usermanager-passwordmg"}},
			want: nil,
		},
		{
			name: "priv matching is case-insensitive",
			user: APIUserPayload{Name: "u", Priv: []string{"PAGE-ALL"}},
			want: []string{"priv"},
		},
		{
			name: "priv matching trims whitespace before the system+admin rule",
			user: APIUserPayload{Name: "u", Priv: []string{"  system-admin  "}},
			want: []string{"priv"},
		},
		{
			name: "system scope is dangerous",
			user: APIUserPayload{Name: "u", Scope: "system"},
			want: []string{"scope"},
		},
		{
			name: "interactive shell is dangerous",
			user: APIUserPayload{Name: "u", Shell: "/bin/sh"},
			want: []string{"shell"},
		},
		{
			name: "authorizedkeys is dangerous",
			user: APIUserPayload{Name: "u", AuthorizedKeys: "ssh-ed25519 AAAA..."},
			want: []string{"authorizedkeys"},
		},
		{
			name: "membership in admins is dangerous",
			user: APIUserPayload{Name: "u", Groups: []string{"admins"}},
			want: []string{"groups"},
		},
		{
			name: "membership in admins is dangerous whatever the case or padding",
			user: APIUserPayload{Name: "u", Groups: []string{"ops", " ADMINS "}},
			want: []string{"groups"},
		},
		{
			name: "membership in admins packed in one entry is dangerous",
			user: APIUserPayload{Name: "u", Groups: []string{"ops,admins"}},
			want: []string{"groups"},
		},
		{
			name: "membership in the read-only group is dangerous",
			user: APIUserPayload{Name: "u", Groups: []string{"netdefense-readonly"}},
			want: []string{"groups"},
		},
		{
			name: "membership in ordinary groups is safe",
			user: APIUserPayload{Name: "u", Groups: []string{"monitors", "operators,helpdesk", "adminsx"}},
			want: nil,
		},
		{
			name: "groups is reported once however many entries name a protected group",
			user: APIUserPayload{Name: "u", Groups: []string{"admins", "Admins", "netdefense-readonly"}},
			want: []string{"groups"},
		},
		{
			name: "multiple dangerous fields all reported",
			user: APIUserPayload{
				Name:           "u",
				Priv:           []string{"page-all"},
				Groups:         []string{"admins"},
				Scope:          "system",
				Shell:          "/bin/csh",
				AuthorizedKeys: "ssh-ed25519 AAAA...",
			},
			want: []string{"authorizedkeys", "groups", "priv", "scope", "shell"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sortedStrings(DangerousUserFields(tt.user, PrivPolicy{}))
			want := sortedStrings(tt.want)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("DangerousUserFields() = %v, want %v", got, want)
			}
		})
	}
}

func TestDangerousGroupFields(t *testing.T) {
	tests := []struct {
		name  string
		group APIGroupPayload
		want  []string
	}{
		{
			name:  "safe group",
			group: APIGroupPayload{Name: "monitoring", Priv: []string{"page-status-services"}},
			want:  nil,
		},
		{
			name:  "no priv at all is safe",
			group: APIGroupPayload{Name: "empty"},
			want:  nil,
		},
		{
			name:  "page-all is dangerous",
			group: APIGroupPayload{Name: "admins-clone", Priv: []string{"page-all"}},
			want:  []string{"priv"},
		},
		{
			name:  "all-pages is dangerous",
			group: APIGroupPayload{Name: "g", Priv: []string{"all-pages"}},
			want:  []string{"priv"},
		},
		{
			name:  "system-admin is dangerous",
			group: APIGroupPayload{Name: "g", Priv: []string{"system-admin"}},
			want:  []string{"priv"},
		},
		{
			name:  "comma-joined priv element containing page-all is dangerous",
			group: APIGroupPayload{Name: "g", Priv: []string{"page-all,other"}},
			want:  []string{"priv"},
		},
		{
			name:  "network-all is dangerous (canonical -all suffix rule)",
			group: APIGroupPayload{Name: "g", Priv: []string{"network-all"}},
			want:  []string{"priv"},
		},
		{
			name:  "admin-system-full is dangerous (canonical system+admin rule)",
			group: APIGroupPayload{Name: "g", Priv: []string{"admin-system-full"}},
			want:  []string{"priv"},
		},
		{
			name:  "page-diagnostics-system-activity is safe (system without admin)",
			group: APIGroupPayload{Name: "g", Priv: []string{"page-diagnostics-system-activity"}},
			want:  nil,
		},
		{
			name:  "page-system-usermanager is dangerous (catalog)",
			group: APIGroupPayload{Name: "g", Priv: []string{"page-system-usermanager"}},
			want:  []string{"priv"},
		},
		{
			name:  "an ID the catalog does not know is dangerous",
			group: APIGroupPayload{Name: "g", Priv: []string{"page-nobody-reviewed-this"}},
			want:  []string{"priv"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DangerousGroupFields(tt.group, PrivPolicy{})
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DangerousGroupFields() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestDangerousFieldsFollowThePrivPolicy holds the local gate to the same
// policy the clearance gate uses: an ID that is ordinary as reviewed becomes
// dangerous when the policy elevates the floor-dependent ones.
func TestDangerousFieldsFollowThePrivPolicy(t *testing.T) {
	elevated := PrivPolicy{FloorDependentElevated: true}
	user := APIUserPayload{Name: "u", Priv: []string{"page-filter-api"}}
	group := APIGroupPayload{Name: "g", Priv: []string{"page-filter-api"}}

	if got := DangerousUserFields(user, PrivPolicy{}); got != nil {
		t.Errorf("default policy: user fields = %v, want none", got)
	}
	if got := DangerousUserFields(user, elevated); !reflect.DeepEqual(got, []string{"priv"}) {
		t.Errorf("elevating policy: user fields = %v, want [priv]", got)
	}
	if got := DangerousGroupFields(group, PrivPolicy{}); got != nil {
		t.Errorf("default policy: group fields = %v, want none", got)
	}
	if got := DangerousGroupFields(group, elevated); !reflect.DeepEqual(got, []string{"priv"}) {
		t.Errorf("elevating policy: group fields = %v, want [priv]", got)
	}
}

func TestDangerousZabbixUserParameterFields(t *testing.T) {
	tests := []struct {
		name string
		up   APIZabbixUserParameterPayload
		want []string
	}{
		{
			name: "no command is safe",
			up:   APIZabbixUserParameterPayload{Key: "nd-cpu-load"},
			want: nil,
		},
		{
			name: "non-empty command is dangerous",
			up:   APIZabbixUserParameterPayload{Key: "nd-uptime", Command: "uptime"},
			want: []string{"command"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DangerousZabbixUserParameterFields(tt.up)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DangerousZabbixUserParameterFields() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDangerousZabbixSettingsFields(t *testing.T) {
	tests := []struct {
		name string
		p    APIZabbixSettingsPayload
		want []string
	}{
		{
			name: "defaults are safe",
			p:    APIZabbixSettingsPayload{Hostname: "fw1", ServerList: []string{"10.0.0.5"}},
			want: nil,
		},
		{
			name: "off-LAN server_list is safe (not constrained)",
			p:    APIZabbixSettingsPayload{Hostname: "fw1", ServerList: []string{"monitor.mssp.example.com"}},
			want: nil,
		},
		{
			name: "enable_remote_commands is dangerous",
			p:    APIZabbixSettingsPayload{Hostname: "fw1", EnableRemoteCommands: true},
			want: []string{"enable_remote_commands"},
		},
		{
			name: "sudo_root is dangerous",
			p:    APIZabbixSettingsPayload{Hostname: "fw1", SudoRoot: true},
			want: []string{"sudo_root"},
		},
		{
			name: "both dangerous fields reported",
			p:    APIZabbixSettingsPayload{Hostname: "fw1", EnableRemoteCommands: true, SudoRoot: true},
			want: []string{"enable_remote_commands", "sudo_root"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DangerousZabbixSettingsFields(tt.p)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DangerousZabbixSettingsFields() = %v, want %v", got, tt.want)
			}
		})
	}
}
