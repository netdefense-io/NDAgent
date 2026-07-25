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
			name: "unrelated priv is safe",
			user: APIUserPayload{Name: "u", Priv: []string{"page-status-services", "page-diagnostics-arp"}},
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
			user: APIUserPayload{Name: "u", Priv: []string{"page-status-services,page-diagnostics-arp"}},
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
			// Negative: contains "system" but not "admin" — must NOT match
			// the system+admin rule, and matches neither of the other two
			// canonical rules either.
			name: "page-system-information priv is safe (system without admin)",
			user: APIUserPayload{Name: "u", Priv: []string{"page-system-information"}},
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
			name: "multiple dangerous fields all reported",
			user: APIUserPayload{
				Name:           "u",
				Priv:           []string{"page-all"},
				Scope:          "system",
				Shell:          "/bin/csh",
				AuthorizedKeys: "ssh-ed25519 AAAA...",
			},
			want: []string{"authorizedkeys", "priv", "scope", "shell"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sortedStrings(DangerousUserFields(tt.user))
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
			name:  "page-system-information is safe (system without admin)",
			group: APIGroupPayload{Name: "g", Priv: []string{"page-system-information"}},
			want:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DangerousGroupFields(tt.group)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DangerousGroupFields() = %v, want %v", got, tt.want)
			}
		})
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
