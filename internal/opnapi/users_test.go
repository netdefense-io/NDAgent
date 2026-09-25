package opnapi

import "testing"

// TestIsProtectedUser guards the SYNC_API protected-identity set. A revert of
// any of these entries would let SYNC_API create/modify/orphan-delete the
// agent's own OPNsense credentials or the forged-session read-only identity.
func TestIsProtectedUser(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"root", true},
		{"netdefense-agent", true},
		{"netdefense-readonly", true},
		{"admins", false}, // group name, not a username
		{"someotheruser", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsProtectedUser(tt.name); got != tt.want {
				t.Errorf("IsProtectedUser(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

// TestIsProtectedGroup guards the SYNC_API protected group-name set.
// netdefense-readonly must be protected as a group (its priv set is the
// read-only ACL allowlist) in addition to being protected as a user.
func TestIsProtectedGroup(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"admins", true},
		{"netdefense-readonly", true},
		{"root", false}, // username, not a group name
		{"someothergroup", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsProtectedGroup(tt.name); got != tt.want {
				t.Errorf("IsProtectedGroup(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

// TestIsProtectedGroup_CaseInsensitive is the revert guard: OPNsense's
// own memberOf sync lowercases
// every incoming group name and matches it against every local group by
// lowercased name, so a differently-cased snippet name ("Admins", "ADMINS")
// must resolve to the same protected group an exact-case check would miss.
func TestIsProtectedGroup_CaseInsensitive(t *testing.T) {
	tests := []string{"admins", "Admins", "ADMINS", "aDmIns", "netdefense-readonly", "Netdefense-ReadOnly", "NETDEFENSE-READONLY"}
	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			if !IsProtectedGroup(name) {
				t.Errorf("IsProtectedGroup(%q) = false, want true (case-insensitive match)", name)
			}
		})
	}

	if IsProtectedGroup("Someothergroup") {
		t.Error("IsProtectedGroup(\"Someothergroup\") = true, want false (not a protected name in any case)")
	}
}
