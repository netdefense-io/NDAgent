package opnapi

import (
	"fmt"
	"reflect"
	"sort"
	"testing"
)

type row = map[string]interface{}

// liveRows is a device shaped like the real model's search rows: the built-in
// admins group with a uid that no user owns any more, the read-only identity,
// two hand-made groups that only this device knows about, and accounts that are
// elevated by each of the ways the index reads.
func liveRows() (users, groups []row) {
	users = []row{
		{"uid": "0", "name": "root", "scope": "system", "priv": "", "group_memberships": "1999", "is_admin": "1"},
		{"uid": "2001", "name": "netdefense-agent", "scope": "user", "priv": "page-all", "group_memberships": "", "is_admin": "1"},
		{"uid": "2002", "name": "netdefense-readonly", "scope": "user", "priv": "", "group_memberships": "2101", "is_admin": "0"},
		{"uid": "2003", "name": "alice-admin", "scope": "user", "priv": "", "group_memberships": "1999", "is_admin": "1"},
		{"uid": "2004", "name": "bob-usermgr", "scope": "user", "priv": "", "group_memberships": "2111", "is_admin": "0"},
		{"uid": "2005", "name": "carol", "scope": "user", "priv": "page-status-services", "group_memberships": "2120", "is_admin": "0"},
		{"uid": "2006", "name": "dave-direct", "scope": "user", "priv": "page-diagnostics-backup-restore", "group_memberships": "", "is_admin": "0"},
		{"uid": "2007", "name": "erin-isadmin", "scope": "user", "priv": "", "group_memberships": "", "is_admin": "1"},
		{"uid": "2008", "name": "frank-plain", "scope": "user", "priv": "", "group_memberships": "", "is_admin": "0"},
		{"uid": "2009", "name": "gina-groupcsv", "scope": "user", "priv": "", "group_memberships": "", "is_admin": "0"},
		{"uid": "2010", "name": "hank-gidonly", "scope": "user", "priv": "", "group_memberships": "2111", "is_admin": "0"},
	}
	groups = []row{
		{"gid": "1999", "name": "admins", "scope": "system", "priv": "page-all", "member": "0,2003,2099"},
		{"gid": "2101", "name": "netdefense-readonly", "scope": "user", "priv": "page-system-login-logout,user-config-readonly", "member": "2002"},
		{"gid": "2110", "name": "ops-all", "scope": "user", "priv": "page-all", "member": "2009"},
		{"gid": "2111", "name": "usermgr", "scope": "user", "priv": "page-firewall-rules,page-system-usermanager", "member": "2004"},
		{"gid": "2120", "name": "monitors", "scope": "user", "priv": "page-status-services", "member": "2005"},
		{"gid": "2130", "name": "mystery", "scope": "user", "priv": "page-not-reviewed", "member": ""},
	}
	return users, groups
}

func TestAccessIndex_Users(t *testing.T) {
	users, groups := liveRows()
	ix := BuildAccessIndex(users, groups, PrivPolicy{}, nil)

	tests := []struct {
		name string
		want []string // reasons, nil means not elevated
	}{
		{"root", []string{ReasonUID0, ReasonProtectedUser, ReasonSystemScope, ReasonIsAdmin, "member-of:admins"}},
		{"netdefense-agent", []string{ReasonProtectedUser, "priv:page-all", ReasonIsAdmin}},
		{"netdefense-readonly", []string{ReasonProtectedUser, "member-of:netdefense-readonly"}},
		{"alice-admin", []string{ReasonIsAdmin, "member-of:admins"}},
		{"bob-usermgr", []string{"member-of:usermgr"}},
		{"carol", nil},
		{"dave-direct", []string{"priv:page-diagnostics-backup-restore"}},
		{"erin-isadmin", []string{ReasonIsAdmin}},
		{"frank-plain", nil},
		{"gina-groupcsv", []string{"member-of:ops-all"}},
		{"hank-gidonly", []string{"member-of:usermgr"}},
		{"nobody-by-that-name", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			live, got := ix.ElevatedUser(tt.name)
			if tt.want == nil {
				if got != nil || live != "" {
					t.Errorf("ElevatedUser(%q) = %q, %v, want not elevated", tt.name, live, got)
				}
				return
			}
			if live != tt.name {
				t.Errorf("live name = %q, want %q", live, tt.name)
			}
			sort.Strings(got)
			want := append([]string(nil), tt.want...)
			sort.Strings(want)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("reasons = %v, want %v", got, want)
			}
		})
	}
}

func TestAccessIndex_Groups(t *testing.T) {
	users, groups := liveRows()
	ix := BuildAccessIndex(users, groups, PrivPolicy{}, nil)

	tests := []struct {
		name string
		want []string
	}{
		{"admins", []string{ReasonProtectedGroup, ReasonBuiltinAdminsGID, "priv:page-all"}},
		{"netdefense-readonly", []string{ReasonProtectedGroup}},
		{"ops-all", []string{"priv:page-all"}},
		{"usermgr", []string{"priv:page-system-usermanager"}},
		{"monitors", nil},
		{"mystery", []string{ReasonPrivUnrecognized}},
		{"not-on-this-device", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, got := ix.ElevatedGroup(tt.name)
			if tt.want == nil {
				if got != nil {
					t.Errorf("ElevatedGroup(%q) = %v, want not elevated", tt.name, got)
				}
				return
			}
			sort.Strings(got)
			want := append([]string(nil), tt.want...)
			sort.Strings(want)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("reasons = %v, want %v", got, want)
			}
		})
	}
}

// TestAccessIndex_UserRowsAndGroupRowsAreUnited holds the two directions of
// membership apart: one account is elevated only because a group row lists its
// uid, another only because its own row lists the gid.
func TestAccessIndex_UserRowsAndGroupRowsAreUnited(t *testing.T) {
	users := []row{
		{"uid": "3001", "name": "by-group-row", "group_memberships": ""},
		{"uid": "3002", "name": "by-user-row", "group_memberships": "3100"},
		{"uid": "3003", "name": "by-neither", "group_memberships": "3200"},
	}
	groups := []row{
		{"gid": "3100", "name": "elevated", "priv": "page-all", "member": ""},
		{"gid": "3200", "name": "benign", "priv": "page-firewall-rules", "member": ""},
	}
	ix := BuildAccessIndex(users, append(groups[:1:1], row{"gid": "3101", "name": "elevated2", "priv": "page-all", "member": "3001"}, groups[1]), PrivPolicy{}, nil)

	if _, r := ix.ElevatedUser("by-group-row"); !HasMembershipReason(r) {
		t.Errorf("an account listed in an elevated group's member CSV must be elevated, got %v", r)
	}
	if _, r := ix.ElevatedUser("by-user-row"); !HasMembershipReason(r) {
		t.Errorf("an account whose own row lists an elevated gid must be elevated, got %v", r)
	}
	if _, r := ix.ElevatedUser("by-neither"); r != nil {
		t.Errorf("membership in a benign group must not elevate, got %v", r)
	}
}

func TestAccessIndex_NamesAreTrimmedAndLowercased(t *testing.T) {
	users, groups := liveRows()
	ix := BuildAccessIndex(users, groups, PrivPolicy{}, nil)

	for _, name := range []string{"admins", "Admins", " ADMINS ", "\tadmins\n"} {
		if live, r := ix.ElevatedGroup(name); live != "admins" || r == nil {
			t.Errorf("ElevatedGroup(%q) = %q, %v, want the live admins group", name, live, r)
		}
	}
	if live, r := ix.ElevatedUser("  ALICE-Admin "); live != "alice-admin" || r == nil {
		t.Errorf("ElevatedUser with a different spelling = %q, %v, want alice-admin", live, r)
	}
}

func TestAccessIndex_DanglingUIDNamesNobody(t *testing.T) {
	users, groups := liveRows()
	ix := BuildAccessIndex(users, groups, PrivPolicy{}, nil)

	// uid 2099 sits in admins.member with no user row. Nothing is indexed under
	// it, and the account that later takes that uid is not known to this snapshot.
	for _, name := range []string{"2099", ""} {
		if _, r := ix.ElevatedUser(name); r != nil {
			t.Errorf("ElevatedUser(%q) = %v, want nothing", name, r)
		}
	}
}

func TestAccessIndex_DuplicateNamesUnite(t *testing.T) {
	users := []row{
		{"uid": "4001", "name": "twin", "priv": ""},
		{"uid": "4002", "name": "TWIN", "priv": "page-system-usermanager"},
	}
	ix := BuildAccessIndex(users, nil, PrivPolicy{}, nil)
	if _, r := ix.ElevatedUser("twin"); r == nil {
		t.Error("two rows of one name, one of them elevated: the name is elevated")
	}
}

func TestAccessIndex_ToleratesMissingAndNumericFields(t *testing.T) {
	users := []row{
		{}, // no fields at all
		{"name": "no-uid", "group_memberships": "1999"},
		{"uid": float64(0), "name": "numeric-root"},
		{"uid": "2100", "name": "bool-admin", "is_admin": true},
		{"uid": "2101", "name": "num-admin", "is_admin": float64(1)},
		{"uid": "2102", "name": "false-admin", "is_admin": "0"},
	}
	groups := []row{
		{},
		{"gid": float64(1999), "name": "admins", "priv": "page-all", "member": ""},
	}
	ix := BuildAccessIndex(users, groups, PrivPolicy{}, nil)

	for _, name := range []string{"no-uid", "numeric-root", "bool-admin", "num-admin"} {
		if _, r := ix.ElevatedUser(name); r == nil {
			t.Errorf("%s must be elevated", name)
		}
	}
	if _, r := ix.ElevatedUser("false-admin"); r != nil {
		t.Errorf("is_admin \"0\" must not elevate, got %v", r)
	}
	if empty := BuildAccessIndex(nil, nil, PrivPolicy{}, nil); func() bool { _, r := empty.ElevatedGroup("admins"); return r != nil }() {
		t.Error("an index built from nothing knows nothing")
	}
}

func TestAccessIndex_FloorDependentPrivFollowsThePolicy(t *testing.T) {
	groups := []row{{"gid": "5001", "name": "dns-editors", "priv": "page-services-unbound", "member": "5101"}}
	users := []row{{"uid": "5101", "name": "dns-user"}}

	if _, r := BuildAccessIndex(users, groups, PrivPolicy{}, nil).ElevatedGroup("dns-editors"); r != nil {
		t.Errorf("default policy: %v, want not elevated", r)
	}
	ix := BuildAccessIndex(users, groups, PrivPolicy{FloorDependentElevated: true}, nil)
	if _, r := ix.ElevatedGroup("dns-editors"); r == nil {
		t.Error("elevating policy: the group must be elevated")
	}
	if _, r := ix.ElevatedUser("dns-user"); !HasMembershipReason(r) {
		t.Errorf("elevating policy: its member must be elevated through it, got %v", r)
	}
}

func TestAccessIndex_PlannedGroup(t *testing.T) {
	_, groups := liveRows()
	ix := BuildAccessIndex(nil, groups, PrivPolicy{}, nil)

	if _, r := ix.ElevatedGroup("new-ops"); r != nil {
		t.Fatalf("control: a group nobody has planned is unknown, got %v", r)
	}
	ix.AddPlannedGroup("New-Ops", nil)
	live, r := ix.ElevatedGroup("new-ops")
	if live != "New-Ops" || !reflect.DeepEqual(r, []string{ReasonPlanned}) {
		t.Errorf("planned group = %q, %v, want New-Ops and [planned]", live, r)
	}
	ix.AddPlannedGroup("  ", nil)
	ix.AddPlannedGroup("admins", nil)
	if _, r := ix.ElevatedGroup("admins"); len(r) < 2 {
		t.Errorf("planning an already elevated group keeps its reasons, got %v", r)
	}
}

// TestAccessIndex_PlannedGroupMakesItsMembersPlanned: a group about to be
// administrator-equivalent makes every account that will be in it so: the members
// the desired element declares, whether or not they exist yet, and the ones the
// group has now, read from the group's member list and from the accounts' own
// group lists alike.
func TestAccessIndex_PlannedGroupMakesItsMembersPlanned(t *testing.T) {
	users := []row{
		{"uid": "7001", "name": "by-group-row", "group_memberships": ""},
		{"uid": "7002", "name": "by-user-row", "group_memberships": "7100"},
		{"uid": "7003", "name": "outsider", "group_memberships": "7200"},
	}
	groups := []row{
		{"gid": "7100", "name": "monitors", "priv": "page-status-services", "member": "7001"},
		{"gid": "7200", "name": "other", "priv": "page-status-services", "member": ""},
	}
	ix := BuildAccessIndex(users, groups, PrivPolicy{}, nil)

	for _, name := range []string{"by-group-row", "by-user-row", "outsider", "declared-new"} {
		if _, r := ix.ElevatedUser(name); r != nil {
			t.Fatalf("control: %s is ordinary before anything is planned, got %v", name, r)
		}
	}

	ix.AddPlannedGroup(" Monitors ", []string{"Declared-New", "  by-group-row", ""})

	for _, name := range []string{"by-group-row", "by-user-row", "declared-new", "DECLARED-NEW"} {
		_, r := ix.ElevatedUser(name)
		group, only := PlannedMembership(r)
		if !only || group != "Monitors" {
			t.Errorf("%s: reasons %v, want planned through Monitors", name, r)
		}
		if HasMembershipReason(r) {
			t.Errorf("%s: a planned membership is not a live one, got %v", name, r)
		}
	}
	if _, r := ix.ElevatedUser("outsider"); r != nil {
		t.Errorf("a member of another group is untouched, got %v", r)
	}
	if live, _ := ix.ElevatedUser("declared-new"); live != "Declared-New" {
		t.Errorf("a declared member that does not exist is shown as declared, got %q", live)
	}
	if live, _ := ix.ElevatedUser("by-group-row"); live != "by-group-row" {
		t.Errorf("a member that exists keeps its own name, got %q", live)
	}
}

func TestPlannedMembership(t *testing.T) {
	tests := []struct {
		name      string
		reasons   []string
		wantGroup string
		wantOnly  bool
	}{
		{"nothing", nil, "", false},
		{"planned", []string{ReasonPlannedMemberOfPrefix + "ops"}, "ops", true},
		{"planned through two groups", []string{ReasonPlannedMemberOfPrefix + "ops", ReasonPlannedMemberOfPrefix + "dev"}, "ops", true},
		{"planned and already live", []string{ReasonPlannedMemberOfPrefix + "ops", "member-of:admins"}, "", false},
		{"planned and administrator by flag", []string{ReasonIsAdmin, ReasonPlannedMemberOfPrefix + "ops"}, "", false},
		{"live only", []string{"member-of:admins"}, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			group, only := PlannedMembership(tt.reasons)
			if group != tt.wantGroup || only != tt.wantOnly {
				t.Errorf("PlannedMembership(%v) = %q, %v, want %q, %v", tt.reasons, group, only, tt.wantGroup, tt.wantOnly)
			}
		})
	}
}

func TestAccountNameKey(t *testing.T) {
	for raw, want := range map[string]string{
		"svc-a":      "svc-a",
		" SVC-A\t":   "svc-a",
		"Svc-A":      "svc-a",
		"":           "",
		"   ":        "",
		"É":          "É", // ASCII only, like every other comparison here
		"name\u00a0": "name\u00a0",
	} {
		if got := AccountNameKey(raw); got != want {
			t.Errorf("AccountNameKey(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestHasMembershipReason(t *testing.T) {
	if !HasMembershipReason([]string{ReasonIsAdmin, "member-of:x"}) {
		t.Error("member-of:x is a membership reason")
	}
	if HasMembershipReason([]string{ReasonIsAdmin, "priv:page-all"}) || HasMembershipReason(nil) {
		t.Error("no membership reason expected")
	}
}

// TestAccessIndex_UnreadableSecurityFieldsFailClosed: OPNsense sends the fields
// the index classifies by as strings. A field that arrives as anything else (a
// list, a map, a bool where text belongs) cannot be classified, and a row that
// cannot be classified is elevated, not ordinary: reading it as empty would blind
// the gate to the very row it could not read, with no error.
func TestAccessIndex_UnreadableSecurityFieldsFailClosed(t *testing.T) {
	list := []interface{}{"page-all"}
	object := map[string]interface{}{"page-all": map[string]interface{}{"selected": 1}}

	users := []row{
		{"uid": "6001", "name": "list-priv", "priv": list},
		{"uid": "6002", "name": "object-priv", "priv": object},
		{"uid": "6003", "name": "bool-priv", "priv": true},
		{"uid": "6004", "name": "list-groups", "group_memberships": []interface{}{"1999"}},
		{"uid": "6005", "name": "object-admin", "is_admin": object},
		{"uid": "6006", "name": "list-scope", "scope": list},
		{"uid": []interface{}{"0"}, "name": "list-uid"},
		{"uid": "6008", "name": "null-fields", "priv": nil, "group_memberships": nil, "is_admin": nil, "scope": nil},
		{"uid": "6009", "name": "absent-fields"},
		{"uid": "6010", "name": "empty-fields", "priv": "", "group_memberships": "", "is_admin": "", "scope": ""},
		{"uid": "6011", "name": "empty-containers", "priv": []interface{}{}, "group_memberships": map[string]interface{}{}, "is_admin": []interface{}{}, "scope": []interface{}{}},
	}
	groups := []row{
		{"gid": "6101", "name": "list-priv-group", "priv": list, "member": ""},
		{"gid": "6102", "name": "list-member-group", "priv": "page-status-services", "member": []interface{}{"6008"}},
		{"gid": true, "name": "bool-gid-group", "priv": "page-status-services"},
		{"gid": "6104", "name": "null-fields-group", "priv": nil, "member": nil},
		{"gid": "6105", "name": "ordinary-group", "priv": "page-status-services", "member": "6009"},
	}
	ix := BuildAccessIndex(users, groups, PrivPolicy{}, nil)

	for name, reason := range map[string]string{
		"list-priv":    "unreadable:priv",
		"object-priv":  "unreadable:priv",
		"bool-priv":    "unreadable:priv",
		"list-groups":  "unreadable:group_memberships",
		"object-admin": "unreadable:is_admin",
		"list-scope":   "unreadable:scope",
		"list-uid":     "unreadable:uid",
	} {
		_, got := ix.ElevatedUser(name)
		if !containsString(got, reason) {
			t.Errorf("user %s: reasons = %v, want %s", name, got, reason)
		}
	}
	for name, reason := range map[string]string{
		"list-priv-group":   "unreadable:priv",
		"list-member-group": "unreadable:member",
		"bool-gid-group":    "unreadable:gid",
	} {
		_, got := ix.ElevatedGroup(name)
		if !containsString(got, reason) {
			t.Errorf("group %s: reasons = %v, want %s", name, got, reason)
		}
	}

	// A null, an absent key, an empty string and an empty list or object are all
	// "nothing set": an empty container holds no privilege and no membership.
	for _, name := range []string{"null-fields", "absent-fields", "empty-fields", "empty-containers"} {
		if _, r := ix.ElevatedUser(name); r != nil {
			t.Errorf("user %s: reasons = %v, want none", name, r)
		}
	}
	for _, name := range []string{"null-fields-group", "ordinary-group"} {
		if _, r := ix.ElevatedGroup(name); r != nil {
			t.Errorf("group %s: reasons = %v, want none", name, r)
		}
	}
}

// liveCatalog is what the device in liveRows defines: every privilege its rows
// hold, except the ones a test leaves out.
func liveCatalog(t testing.TB, without ...string) *DevicePrivs {
	t.Helper()
	omit := map[string]bool{}
	for _, id := range without {
		omit[id] = true
	}
	var ids []string
	for _, id := range []string{
		"page-all", "user-config-readonly", "page-system-login-logout", "page-firewall-rules", "page-system-usermanager",
		"page-status-services", "page-diagnostics-backup-restore", "page-not-reviewed",
	} {
		if !omit[id] {
			ids = append(ids, id)
		}
	}
	return plausibleCatalog(t, ids...)
}

func reasonsOf(reasons []string) []string {
	sort.Strings(reasons)
	return reasons
}

// An ID that the device does not define grants nothing there, so a live row that
// holds only such IDs is not elevated; an ID it defines that the agent's catalog
// does not know stays elevated, and with no catalog to ask every unknown ID does.
func TestAccessIndex_LiveRowsAgainstTheDevicesOwnCatalog(t *testing.T) {
	t.Run("a privilege the device defines and the agent does not know stays elevated", func(t *testing.T) {
		users, groups := liveRows()
		ix := BuildAccessIndex(users, groups, PrivPolicy{}, liveCatalog(t))
		_, reasons := ix.ElevatedGroup("mystery")
		if !reflect.DeepEqual(reasons, []string{ReasonPrivUnrecognized}) {
			t.Errorf("mystery: %v, want %v", reasons, []string{ReasonPrivUnrecognized})
		}
		if cause, _ := ix.OpaqueCause(reasons); cause != CauseUnrecognizedPriv {
			t.Errorf("cause = %q, want %q", cause, CauseUnrecognizedPriv)
		}
	})

	t.Run("a privilege the device does not define is inert", func(t *testing.T) {
		users, groups := liveRows()
		ix := BuildAccessIndex(users, groups, PrivPolicy{}, liveCatalog(t, "page-not-reviewed"))
		if _, reasons := ix.ElevatedGroup("mystery"); reasons != nil {
			t.Errorf("mystery: %v, want not elevated", reasons)
		}
	})

	t.Run("without the catalog it is elevated, as before", func(t *testing.T) {
		users, groups := liveRows()
		ix := BuildAccessIndex(users, groups, PrivPolicy{}, nil)
		if _, reasons := ix.ElevatedGroup("mystery"); !reflect.DeepEqual(reasons, []string{ReasonPrivUnrecognized}) {
			t.Errorf("mystery: %v", reasons)
		}
	})

	t.Run("an administrator-equivalent privilege a release no longer defines is inert", func(t *testing.T) {
		// page-system-usermanager is elevated in the catalog; the device does not define it
		users, groups := liveRows()
		ix := BuildAccessIndex(users, groups, PrivPolicy{}, liveCatalog(t, "page-system-usermanager"))
		if _, reasons := ix.ElevatedGroup("usermgr"); reasons != nil {
			t.Errorf("usermgr: %v, want not elevated", reasons)
		}
		for _, name := range []string{"bob-usermgr", "hank-gidonly"} {
			if _, reasons := ix.ElevatedUser(name); reasons != nil {
				t.Errorf("%s: %v, want not elevated: its group grants nothing", name, reasons)
			}
		}
	})

	t.Run("an undefined privilege next to a defined one does not show", func(t *testing.T) {
		users, groups := liveRows()
		groups = append(groups, row{"gid": "2200", "name": "mixed", "priv": "page-gone,page-all,page-also-gone", "member": ""})
		ix := BuildAccessIndex(users, groups, PrivPolicy{}, liveCatalog(t))
		if _, reasons := ix.ElevatedGroup("mixed"); !reflect.DeepEqual(reasonsOf(reasons), []string{"priv:page-all"}) {
			t.Errorf("mixed: %v, want only priv:page-all (an undefined ID is not an unrecognized one)", reasons)
		}
	})

	t.Run("OPNsense looks a privilege up by exact spelling", func(t *testing.T) {
		users, groups := liveRows()
		for i, priv := range []string{" page-all", "PAGE-ALL", "Page-All ", "page-all ,page-status-services", "\tpage-all"} {
			groups = append(groups, row{"gid": fmt.Sprint(2300 + i), "name": fmt.Sprintf("spelled-%d", i), "priv": priv, "member": ""})
		}
		ix := BuildAccessIndex(users, groups, PrivPolicy{}, liveCatalog(t))
		for i := 0; i < 5; i++ {
			name := fmt.Sprintf("spelled-%d", i)
			if _, reasons := ix.ElevatedGroup(name); reasons != nil {
				t.Errorf("%s: %v, want not elevated: the device does not define that spelling", name, reasons)
			}
		}
		// the same spellings in snippet content stay elevated: the catalog normalizes them
		if !(PrivPolicy{}).IsAdminEquivalentPriv(" PAGE-ALL ") {
			t.Error("a padded, upper-case page-all in a snippet must stay administrator-equivalent")
		}
	})

	t.Run("a privilege on an account's own row", func(t *testing.T) {
		users, groups := liveRows()
		withIt := BuildAccessIndex(users, groups, PrivPolicy{}, liveCatalog(t))
		if _, reasons := withIt.ElevatedUser("dave-direct"); !reflect.DeepEqual(reasons, []string{"priv:page-diagnostics-backup-restore"}) {
			t.Errorf("dave-direct: %v", reasons)
		}
		without := BuildAccessIndex(users, groups, PrivPolicy{}, liveCatalog(t, "page-diagnostics-backup-restore"))
		if _, reasons := without.ElevatedUser("dave-direct"); reasons != nil {
			t.Errorf("dave-direct without the privilege defined: %v, want not elevated", reasons)
		}
	})

	t.Run("the other reasons do not depend on the catalog", func(t *testing.T) {
		users, groups := liveRows()
		ix := BuildAccessIndex(users, groups, PrivPolicy{}, liveCatalog(t, "page-all", "page-system-usermanager", "page-not-reviewed"))
		if _, reasons := ix.ElevatedUser("erin-isadmin"); !reflect.DeepEqual(reasons, []string{ReasonIsAdmin}) {
			t.Errorf("erin-isadmin: %v", reasons)
		}
		if _, reasons := ix.ElevatedGroup("admins"); !containsString(reasons, ReasonProtectedGroup) || !containsString(reasons, ReasonBuiltinAdminsGID) {
			t.Errorf("admins: %v, want the protected-name and builtin-gid reasons", reasons)
		}
		if _, reasons := ix.ElevatedUser("root"); !containsString(reasons, ReasonUID0) || !containsString(reasons, ReasonProtectedUser) {
			t.Errorf("root: %v", reasons)
		}
	})

	t.Run("a floor-dependent privilege follows the policy only where the device defines it", func(t *testing.T) {
		users, groups := liveRows()
		groups = append(groups, row{"gid": "2400", "name": "dns-editors", "priv": "page-services-dnsresolver", "member": ""})
		elevated := PrivPolicy{FloorDependentElevated: true}
		if _, reasons := BuildAccessIndex(users, groups, elevated, plausibleCatalog(t, "page-services-dnsresolver")).ElevatedGroup("dns-editors"); !reflect.DeepEqual(reasons, []string{"priv:page-services-dnsresolver"}) {
			t.Errorf("defined: %v", reasons)
		}
		if _, reasons := BuildAccessIndex(users, groups, elevated, plausibleCatalog(t)).ElevatedGroup("dns-editors"); reasons != nil {
			t.Errorf("undefined: %v, want not elevated", reasons)
		}
		if _, reasons := BuildAccessIndex(users, groups, PrivPolicy{}, plausibleCatalog(t, "page-services-dnsresolver")).ElevatedGroup("dns-editors"); reasons != nil {
			t.Errorf("defined but the policy leaves it ordinary: %v", reasons)
		}
	})
}
