package opnapi

import (
	"encoding/json"
	"reflect"
	"strconv"
	"testing"
)

type protectedNamesVectors struct {
	FixtureSHA256   string   `json:"fixture_sha256"`
	ProtectedGroups []string `json:"protected_groups"`
	ProtectedUsers  []string `json:"protected_users"`
	BuiltinAdminGID int      `json:"builtin_admin_gid"`
	GroupNames      []struct {
		Name      string `json:"name"`
		Protected bool   `json:"protected"`
	} `json:"group_names"`
	GroupEntries []struct {
		Entry     string `json:"entry"`
		Protected bool   `json:"names_a_protected_group"`
	} `json:"group_entries"`
	UserNames []struct {
		Name      string `json:"name"`
		Protected bool   `json:"protected"`
	} `json:"user_names"`
}

func TestProtectedNamesVectors(t *testing.T) {
	raw := readTestdata(t, "testdata/protected-names/vectors.json")
	if got := sha256Hex(raw); got != pinnedProtectedVectorsSHA256 {
		t.Fatalf("protected-names vectors sha256 = %s, want %s", got, pinnedProtectedVectorsSHA256)
	}
	var v protectedNamesVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if v.FixtureSHA256 != pinnedAdminEquivalenceSHA256 {
		t.Fatalf("the vectors were generated from catalog %s, this package embeds %s", v.FixtureSHA256, pinnedAdminEquivalenceSHA256)
	}
	if len(v.GroupNames) != 20 || len(v.GroupEntries) != 12 || len(v.UserNames) != 13 {
		t.Fatalf("vector counts = %d/%d/%d group names/group entries/user names, want 20/12/13", len(v.GroupNames), len(v.GroupEntries), len(v.UserNames))
	}

	if !reflect.DeepEqual(v.ProtectedGroups, adminCatalog.protectedGroups) || !reflect.DeepEqual(v.ProtectedUsers, adminCatalog.protectedUsers) {
		t.Errorf("the vectors list protected groups %v and users %v, the catalog %v and %v",
			v.ProtectedGroups, v.ProtectedUsers, adminCatalog.protectedGroups, adminCatalog.protectedUsers)
	}
	if strconv.Itoa(v.BuiltinAdminGID) != BuiltinAdminGID {
		t.Errorf("builtin_admin_gid = %d, BuiltinAdminGID = %q", v.BuiltinAdminGID, BuiltinAdminGID)
	}

	for _, c := range v.GroupNames {
		if got := IsProtectedGroupName(c.Name); got != c.Protected {
			t.Errorf("IsProtectedGroupName(%q) = %v, want %v", c.Name, got, c.Protected)
		}
	}
	for _, c := range v.GroupEntries {
		if got := GroupEntryNamesProtectedGroup(c.Entry); got != c.Protected {
			t.Errorf("GroupEntryNamesProtectedGroup(%q) = %v, want %v", c.Entry, got, c.Protected)
		}
	}
	for _, c := range v.UserNames {
		if got := IsProtectedUser(c.Name); got != c.Protected {
			t.Errorf("IsProtectedUser(%q) = %v, want %v", c.Name, got, c.Protected)
		}
	}
}

// TestProtectedNameMapsComeFromTheCatalog holds the maps SYNC consults at parse
// time and in the orphan sweep to the catalog, so the two cannot drift.
func TestProtectedNameMapsComeFromTheCatalog(t *testing.T) {
	wantUsers := map[string]bool{"root": true, "netdefense-agent": true, "netdefense-readonly": true}
	wantGroups := map[string]bool{"admins": true, "netdefense-readonly": true}
	if !reflect.DeepEqual(ProtectedUsernames, wantUsers) {
		t.Errorf("ProtectedUsernames = %v, want %v", ProtectedUsernames, wantUsers)
	}
	if !reflect.DeepEqual(ProtectedGroupNames, wantGroups) {
		t.Errorf("ProtectedGroupNames = %v, want %v", ProtectedGroupNames, wantGroups)
	}
}

// TestIsProtectedGroupDoesNotTrim pins the difference between the two group
// rules: SYNC's parse-time and sweep check lowercases but never trims, while the
// clearance rule trims as well.
func TestIsProtectedGroupDoesNotTrim(t *testing.T) {
	for _, name := range []string{" admins", "admins ", "\tAdmins\n"} {
		if IsProtectedGroup(name) {
			t.Errorf("IsProtectedGroup(%q) = true, want false: SYNC's parse-time check has never trimmed", name)
		}
		if !IsProtectedGroupName(name) {
			t.Errorf("IsProtectedGroupName(%q) = false, want true", name)
		}
	}
}

func TestProtectedGroupCanonicalName(t *testing.T) {
	if got, ok := ProtectedGroupCanonicalName("  ADMINS "); !ok || got != "admins" {
		t.Errorf("ProtectedGroupCanonicalName(\"  ADMINS \") = %q, %v, want \"admins\", true", got, ok)
	}
	if got, ok := ProtectedGroupCanonicalName("operators"); ok || got != "" {
		t.Errorf("ProtectedGroupCanonicalName(\"operators\") = %q, %v, want \"\", false", got, ok)
	}
}

func TestSplitGroupEntry(t *testing.T) {
	got := SplitGroupEntry(" ops , ,Admins,,  netdefense-readonly ")
	want := []string{"ops", "Admins", "netdefense-readonly"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("SplitGroupEntry = %q, want %q", got, want)
	}
	if len(SplitGroupEntry(" , ")) != 0 {
		t.Error("an entry of separators and spaces names no group")
	}
}
