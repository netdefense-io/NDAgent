package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// These tests hold the Superuser clearance gate to its contract, against a fake
// OPNsense whose live rows are set up by each test. The contract, from the
// control plane's side: a snippet carries content_clearance "org:su" in the
// signed SYNC payload when a Superuser authored it as delivered, and the key is
// absent otherwise. From the device's side: an element without it may not give
// an account administrator rights or take one over, whatever
// reject_dangerous_snippets says, and a refusal is one blocked item plus the same
// text in the task's errors, with the element left alone and never deleted.

const adminEquivalentCode = "ADMIN_EQUIVALENT_REQUIRES_SUPERUSER"

func runGate(t *testing.T, f *fakeAccounts, users []opnapi.APIUserPayload, groups []opnapi.APIGroupPayload, rejectDangerous bool) SyncAPIResult {
	t.Helper()
	return executeSyncUsersGroups(context.Background(), f.client, users, groups, rejectDangerous, authDeferralInfo{})
}

func refusedItems(result SyncAPIResult) []SyncAPIItemResult {
	var out []SyncAPIItemResult
	for _, r := range result.Results {
		if r.Action == "rejected" {
			out = append(out, r)
		}
	}
	return out
}

func TestAdminEquivalenceGate_UserElements(t *testing.T) {
	tests := []struct {
		name string
		user opnapi.APIUserPayload
		// refuse is what an element without clearance must draw; clause is a
		// fragment of the message that names why.
		refuse bool
		clause string
	}{
		{"membership in admins", opnapi.APIUserPayload{Name: "svc", Password: "pw-1", Groups: []string{"admins"}}, true, `group "admins"`},
		{"membership in admins, other case", opnapi.APIUserPayload{Name: "svc", Password: "pw-1", Groups: []string{"Admins"}}, true, `group "admins"`},
		{"membership in admins, padded", opnapi.APIUserPayload{Name: "svc", Password: "pw-1", Groups: []string{" ADMINS "}}, true, `group "admins"`},
		{"membership in admins, packed in one entry", opnapi.APIUserPayload{Name: "svc", Password: "pw-1", Groups: []string{"monitors,admins"}}, true, `group "admins"`},
		{"membership in the read-only group", opnapi.APIUserPayload{Name: "svc", Password: "pw-1", Groups: []string{"netdefense-readonly"}}, true, `group "netdefense-readonly"`},
		{"membership in a hand-made page-all group", opnapi.APIUserPayload{Name: "svc", Password: "pw-1", Groups: []string{"nd-hm-all"}}, true, `group "nd-hm-all"`},
		{"membership in a hand-made user-manager group", opnapi.APIUserPayload{Name: "svc", Password: "pw-1", Groups: []string{"nd-hm-usermgr"}}, true, `group "nd-hm-usermgr"`},
		{"membership in an ordinary group", opnapi.APIUserPayload{Name: "svc", Password: "pw-1", Groups: []string{"monitors"}}, false, ""},
		{"direct user-manager privilege", opnapi.APIUserPayload{Name: "svc", Password: "pw-1", Priv: []string{"page-system-usermanager"}}, true, `privilege "page-system-usermanager"`},
		{"direct 26.1 privilege-editing privilege", opnapi.APIUserPayload{Name: "svc", Password: "pw-1", Priv: []string{"page-system-usermanager-addprivs"}}, true, `privilege "page-system-usermanager-addprivs"`},
		{"direct privilege nobody reviewed", opnapi.APIUserPayload{Name: "svc", Password: "pw-1", Priv: []string{"page-never-reviewed"}}, true, "1 privilege ID(s) the catalog does not know"},
		{"direct ordinary privilege", opnapi.APIUserPayload{Name: "svc", Password: "pw-1", Priv: []string{"page-status-services"}}, false, ""},
		{"takeover of an administrator by password", opnapi.APIUserPayload{Name: "alice-admin", Password: "pw-new"}, true, `user "alice-admin"`},
		{"takeover of an administrator by disabled flag", opnapi.APIUserPayload{Name: "alice-admin", Disabled: true}, true, `user "alice-admin"`},
		{"takeover of an administrator with nothing set", opnapi.APIUserPayload{Name: "alice-admin"}, true, `user "alice-admin"`},
		{"takeover of an administrator, other case", opnapi.APIUserPayload{Name: "ALICE-ADMIN", Password: "pw-new"}, true, `user "alice-admin"`},
		{"takeover of an account elevated through a group's member list", opnapi.APIUserPayload{Name: "gina-groupcsv", Password: "pw-new"}, true, `user "gina-groupcsv"`},
		{"takeover of an account elevated through its own group list", opnapi.APIUserPayload{Name: "hank-gidonly", Password: "pw-new"}, true, `user "hank-gidonly"`},
		{"takeover of an account elevated by is_admin alone", opnapi.APIUserPayload{Name: "erin-isadmin", Password: "pw-new"}, true, `user "erin-isadmin"`},
		{"takeover of an account elevated by a direct privilege", opnapi.APIUserPayload{Name: "dave-direct", Password: "pw-new"}, true, `user "dave-direct"`},
		{"takeover of root", opnapi.APIUserPayload{Name: "root", Password: "pw-new"}, true, `user "root"`},
		{"update of an ordinary existing account", opnapi.APIUserPayload{Name: "nd-hm-plain", Password: "pw-new"}, false, ""},
		{"update of a member of an ordinary group", opnapi.APIUserPayload{Name: "carol", Password: "pw-new"}, false, ""},
		{"a new ordinary account", opnapi.APIUserPayload{Name: "newbie", Password: "pw-1"}, false, ""},
	}

	for _, tt := range tests {
		for _, cleared := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/cleared=%v", tt.name, cleared), func(t *testing.T) {
				users, groups := liveAccounts()
				f := newFakeAccounts(t, users, groups)
				user := tt.user
				user.SuperuserCleared = cleared
				user.SnippetName = "the-snippet"
				user.SnippetIndex = 2

				result := runGate(t, f, []opnapi.APIUserPayload{user}, nil, false)

				if tt.refuse && !cleared {
					items := refusedItems(result)
					if len(items) != 1 || items[0].Type != "user" || items[0].Name != tt.user.Name {
						t.Fatalf("refused items = %+v, want exactly one for user %q", items, tt.user.Name)
					}
					if items[0].Code != adminEquivalentCode || items[0].Status != "blocked" {
						t.Errorf("item = %+v, want code %s and status blocked", items[0], adminEquivalentCode)
					}
					if !strings.Contains(items[0].Error, tt.clause) {
						t.Errorf("message %q does not name %q", items[0].Error, tt.clause)
					}
					if result.Success {
						t.Error("a refusal must fail the task")
					}
					assertErrorHasMatchingResultItem(t, "refused user", result.Errors, result.Results)
					if f.wroteAnythingFor("user", tt.user.Name) {
						t.Errorf("a refused element must not reach OPNsense, writes = %v", f.writes)
					}
					return
				}

				if items := refusedItems(result); len(items) != 0 {
					t.Fatalf("unexpected refusal: %+v", items)
				}
				if !result.Success {
					t.Fatalf("unexpected failure: %v", result.Errors)
				}
				if !f.wroteAnythingFor("user", tt.user.Name) {
					t.Errorf("the element must be applied, writes = %v", f.writes)
				}
			})
		}
	}
}

func TestAdminEquivalenceGate_GroupElements(t *testing.T) {
	tests := []struct {
		name   string
		group  opnapi.APIGroupPayload
		refuse bool
		clause string
	}{
		{"a new group with the user manager privilege", opnapi.APIGroupPayload{Name: "new-g", Priv: []string{"page-system-usermanager"}}, true, `privilege "page-system-usermanager"`},
		{"a new group with the 26.1 group-editing privilege", opnapi.APIGroupPayload{Name: "new-g", Priv: []string{"page-system-groupmanager"}}, true, `privilege "page-system-groupmanager"`},
		{"a new group with page-all", opnapi.APIGroupPayload{Name: "new-g", Priv: []string{"page-all"}}, true, `privilege "page-all"`},
		{"a new group with a privilege nobody reviewed", opnapi.APIGroupPayload{Name: "new-g", Priv: []string{"page-never-reviewed"}}, true, "1 privilege ID(s) the catalog does not know"},
		{"a new ordinary group", opnapi.APIGroupPayload{Name: "new-g", Priv: []string{"page-status-services"}}, false, ""},
		{"a new group with no privileges", opnapi.APIGroupPayload{Name: "new-g"}, false, ""},
		{"an existing hand-made administrator group, with its privileges emptied", opnapi.APIGroupPayload{Name: "nd-hm-usermgr", Members: []string{"carol"}}, true, `group "nd-hm-usermgr"`},
		{"an existing hand-made page-all group, with ordinary privileges", opnapi.APIGroupPayload{Name: "nd-hm-all", Priv: []string{"page-status-services"}}, true, `group "nd-hm-all"`},
		{"an existing ordinary group", opnapi.APIGroupPayload{Name: "monitors", Priv: []string{"page-status-services"}, Members: []string{"carol"}}, false, ""},
		{"the admins group under a padded name", opnapi.APIGroupPayload{Name: " Admins "}, true, `group "admins"`},
		{"an external (directory) group with ordinary privileges", opnapi.APIGroupPayload{Name: "dir-eng", ExternalMembers: true, Priv: []string{"page-status-services"}}, false, ""},
		{"an external (directory) group with the user manager privilege", opnapi.APIGroupPayload{Name: "dir-admins", ExternalMembers: true, Priv: []string{"page-system-usermanager"}}, true, `privilege "page-system-usermanager"`},
	}

	for _, tt := range tests {
		for _, cleared := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/cleared=%v", tt.name, cleared), func(t *testing.T) {
				users, groups := liveAccounts()
				f := newFakeAccounts(t, users, groups)
				group := tt.group
				group.SuperuserCleared = cleared
				group.SnippetName = "the-group-snippet"
				group.SnippetIndex = 5

				result := runGate(t, f, nil, []opnapi.APIGroupPayload{group}, false)

				if tt.refuse && !cleared {
					items := refusedItems(result)
					if len(items) != 1 || items[0].Type != "group" || items[0].Name != tt.group.Name {
						t.Fatalf("refused items = %+v, want exactly one for group %q", items, tt.group.Name)
					}
					if items[0].Code != adminEquivalentCode || items[0].Status != "blocked" {
						t.Errorf("item = %+v, want code %s and status blocked", items[0], adminEquivalentCode)
					}
					if !strings.Contains(items[0].Error, tt.clause) {
						t.Errorf("message %q does not name %q", items[0].Error, tt.clause)
					}
					assertErrorHasMatchingResultItem(t, "refused group", result.Errors, result.Results)
					if f.wroteAnythingFor("group", tt.group.Name) {
						t.Errorf("a refused element must not reach OPNsense, writes = %v", f.writes)
					}
					return
				}

				if items := refusedItems(result); len(items) != 0 {
					t.Fatalf("unexpected refusal: %+v", items)
				}
				if !result.Success {
					t.Fatalf("unexpected failure: %v", result.Errors)
				}
				if !f.wroteAnythingFor("group", tt.group.Name) {
					t.Errorf("the element must be applied, writes = %v", f.writes)
				}
			})
		}
	}
}

// TestAdminEquivalenceGate_PinsTheMessage asserts the documented text literally
// and that nothing submitted but a catalog ID can appear in it.
func TestAdminEquivalenceGate_PinsTheMessage(t *testing.T) {
	users, groups := liveAccounts()
	f := newFakeAccounts(t, users, groups)

	user := opnapi.APIUserPayload{
		Name:         "svc",
		Password:     "hunter2-never-echoed",
		Groups:       []string{"admins"},
		Priv:         []string{"page-author-typed-this"},
		SnippetName:  "svc-snippet",
		SnippetIndex: 4,
	}
	result := runGate(t, f, []opnapi.APIUserPayload{user}, nil, false)

	want := `rejected (Superuser clearance required): user snippet "svc-snippet" (index 4) for user "svc" ` +
		`would add membership in administrator-equivalent group "admins" and would grant 1 privilege ID(s) the catalog does not know, which count as administrator-equivalent. ` +
		`It carries no Superuser clearance, so a Superuser must save the snippet (and any variable it uses) again; reject_dangerous_snippets=false does not lift this`
	if len(result.Errors) != 1 || result.Errors[0] != want {
		t.Fatalf("errors = %q\nwant    %q", result.Errors, want)
	}
	for _, leaked := range []string{"hunter2-never-echoed", "page-author-typed-this"} {
		if strings.Contains(result.Errors[0], leaked) {
			t.Errorf("the message echoes %q", leaked)
		}
	}

	// The same refusal of an element that has no provenance falls back to the
	// index-only label, like every other per-snippet message.
	user.SnippetName = ""
	result = runGate(t, f, []opnapi.APIUserPayload{user}, nil, false)
	if !strings.Contains(result.Errors[0], "user snippet at index 4 for user") {
		t.Errorf("message without a snippet name = %q", result.Errors[0])
	}
}

func TestAdminEquivalenceGate_ManyClausesAreCapped(t *testing.T) {
	users, groups := liveAccounts()
	groups = append(groups,
		row{"uuid": "gg-x1", "gid": "2160", "name": "nd-hm-x1", "scope": "user", "priv": "page-all", "member": "", "description": ""},
		row{"uuid": "gg-x2", "gid": "2161", "name": "nd-hm-x2", "scope": "user", "priv": "page-all", "member": "", "description": ""},
	)
	f := newFakeAccounts(t, users, groups)

	// Only the live rows know these groups, so the reasons are found after
	// discovery: four groups and the takeover make five, and three are spelled out.
	user := opnapi.APIUserPayload{
		Name:     "alice-admin",
		Password: "pw",
		Groups:   []string{"nd-hm-all", "nd-hm-usermgr", "nd-hm-x1", "nd-hm-x2"},
	}
	result := runGate(t, f, []opnapi.APIUserPayload{user}, nil, false)
	if len(result.Errors) != 1 {
		t.Fatalf("errors = %v, want one", result.Errors)
	}
	want := `would add membership in administrator-equivalent group "nd-hm-all" and would add membership in administrator-equivalent group "nd-hm-usermgr" ` +
		`and would add membership in administrator-equivalent group "nd-hm-x1" and 2 more. It carries no Superuser clearance`
	if !strings.Contains(result.Errors[0], want) {
		t.Errorf("message = %q, want it to contain %q", result.Errors[0], want)
	}
}

// TestAdminEquivalenceGate_NeverFailsFastAndNeverDeletes is the house rule for
// per-element checks: a refusal drops the element from the apply pass and keeps
// it in the desired set, so the sweep still runs and deletes only what is no
// longer wanted.
func TestAdminEquivalenceGate_NeverFailsFastAndNeverDeletes(t *testing.T) {
	users, groups := liveAccounts()
	users = append(users,
		row{"uuid": "uu-managed-admin", "uid": "2050", "name": "managed-admin", "scope": "user", "priv": "", "group_memberships": "1999", "is_admin": "1", "descr": "[nd-template:ops]"},
		row{"uuid": "uu-orphan", "uid": "2051", "name": "old-orphan", "scope": "user", "priv": "", "group_memberships": "", "is_admin": "0", "descr": "[nd-template:ops]"},
	)
	groups = append(groups,
		row{"uuid": "gg-managed-um", "gid": "2150", "name": "managed-usermgr", "scope": "user", "priv": "page-system-usermanager", "member": "", "description": "[nd-template:ops]"},
		row{"uuid": "gg-orphan", "gid": "2151", "name": "old-orphan-group", "scope": "user", "priv": "", "member": "", "description": "[nd-template:ops]"},
	)
	// 1999's member list names the managed admin, as a Superuser's earlier sync left it.
	groups[0]["member"] = "0,2003,2050,2099"
	f := newFakeAccounts(t, users, groups)

	desiredUsers := []opnapi.APIUserPayload{
		{Name: "managed-admin", Password: "pw-rw", Templates: []string{"ops"}}, // refused: takes over an administrator
		{Name: "sibling", Password: "pw-1", Templates: []string{"ops"}},        // a sibling that must still apply
		{Name: "svc-elevated", Password: "pw-2", Priv: []string{"page-all"}},   // refused
		{Name: "carol", Password: "pw-3", Groups: []string{"monitors"}},        // a sibling update
	}
	desiredGroups := []opnapi.APIGroupPayload{
		{Name: "managed-usermgr", Templates: []string{"ops"}},           // refused: rewrites an administrator group
		{Name: "sibling-group", Priv: []string{"page-status-services"}}, // a sibling that must still apply
	}
	result := runGate(t, f, desiredUsers, desiredGroups, false)

	if result.Success {
		t.Error("two refusals must fail the task")
	}
	for _, name := range []string{"managed-admin", "svc-elevated"} {
		if f.wroteAnythingFor("user", name) {
			t.Errorf("the refused user %s reached OPNsense", name)
		}
	}
	if f.wroteAnythingFor("group", "managed-usermgr") {
		t.Error("the refused group reached OPNsense")
	}
	for _, name := range []string{"sibling", "carol"} {
		if !f.wroteAnythingFor("user", name) {
			t.Errorf("the sibling user %s must still apply, writes = %v", name, f.writes)
		}
	}
	if !f.wroteAnythingFor("group", "sibling-group") {
		t.Errorf("the sibling group must still apply, writes = %v", f.writes)
	}

	if f.wrote("del", "user", "managed-admin") || f.wrote("del", "group", "managed-usermgr") {
		t.Errorf("a refused element that already exists must never be swept, writes = %v", f.writes)
	}
	if !f.wrote("del", "user", "old-orphan") || !f.wrote("del", "group", "old-orphan-group") {
		t.Errorf("the sweep must still delete what is no longer wanted, writes = %v", f.writes)
	}
	assertErrorHasMatchingResultItem(t, "refusals", result.Errors, result.Results)
}

func TestAdminEquivalenceGate_RejectOnlyCycleWritesNothing(t *testing.T) {
	users, groups := liveAccounts()
	f := newFakeAccounts(t, users, groups)

	result := runGate(t, f,
		[]opnapi.APIUserPayload{{Name: "svc", Groups: []string{"admins"}}, {Name: "alice-admin", Password: "pw"}},
		[]opnapi.APIGroupPayload{{Name: "nd-hm-usermgr"}, {Name: "new-g", Priv: []string{"page-all"}}},
		false,
	)

	if result.Success {
		t.Error("refusals must fail the task")
	}
	if n := len(refusedItems(result)); n != 4 {
		t.Errorf("refused items = %d, want 4", n)
	}
	if n := f.writeCount(); n != 0 {
		t.Errorf("a cycle in which everything is refused made %d writes: %v", n, f.writes)
	}
}

// TestAdminEquivalenceGate_StaticRefusalSurvivesDiscoveryFailure: what needs no
// live rows is refused and reported before discovery, so the early return of a
// discovery failure keeps it.
func TestAdminEquivalenceGate_StaticRefusalSurvivesDiscoveryFailure(t *testing.T) {
	users, groups := liveAccounts()
	f := newFakeAccounts(t, users, groups)
	f.failed["search user"] = true

	result := runGate(t, f,
		[]opnapi.APIUserPayload{{Name: "svc", Groups: []string{"admins"}}, {Name: "svc2", Priv: []string{"page-system-usermanager"}}, {Name: "svc3", Groups: []string{"monitors"}}},
		[]opnapi.APIGroupPayload{{Name: "new-g", Priv: []string{"page-all"}}},
		false,
	)

	if n := len(refusedItems(result)); n != 3 {
		t.Errorf("refused items = %d, want 3 (the static refusals), results = %+v", n, result.Results)
	}
	assertErrorHasMatchingResultItem(t, "discovery failure", result.Errors, result.Results)
	if n := f.writeCount(); n != 0 {
		t.Errorf("a failed discovery wrote %d times", n)
	}
}

// TestAdminEquivalenceGate_SameSyncGroupThenUser: a USER is judged against what
// a group of the same sync is about to be, not only what it is now.
func TestAdminEquivalenceGate_SameSyncGroupThenUser(t *testing.T) {
	t.Run("a Superuser-cleared elevated group, and a user without clearance naming it", func(t *testing.T) {
		users, groups := liveAccounts()
		f := newFakeAccounts(t, users, groups)

		result := runGate(t, f,
			[]opnapi.APIUserPayload{{Name: "svc", Password: "pw", Groups: []string{"new-ops"}}},
			[]opnapi.APIGroupPayload{{Name: "new-ops", Priv: []string{"page-system-usermanager"}, SuperuserCleared: true}},
			false,
		)

		if !f.wrote("add", "group", "new-ops") {
			t.Errorf("the cleared group must be created, writes = %v", f.writes)
		}
		if f.wroteAnythingFor("user", "svc") {
			t.Errorf("the user must not join a group this sync makes administrator-equivalent, writes = %v", f.writes)
		}
		items := refusedItems(result)
		if len(items) != 1 || items[0].Name != "svc" || !strings.Contains(items[0].Error, `group "new-ops"`) {
			t.Errorf("refused items = %+v, want svc refused for joining new-ops", items)
		}
	})

	t.Run("an ordinary group of the same sync is no obstacle", func(t *testing.T) {
		users, groups := liveAccounts()
		f := newFakeAccounts(t, users, groups)

		result := runGate(t, f,
			[]opnapi.APIUserPayload{{Name: "svc", Password: "pw", Groups: []string{"new-ops"}}},
			[]opnapi.APIGroupPayload{{Name: "new-ops", Priv: []string{"page-status-services"}}},
			false,
		)
		if !result.Success || len(refusedItems(result)) != 0 {
			t.Fatalf("unexpected result: %+v", result)
		}
		if !f.wrote("add", "group", "new-ops") || !f.wrote("add", "user", "svc") {
			t.Errorf("both must be applied, writes = %v", f.writes)
		}
	})

	t.Run("a group that was itself refused is not planned", func(t *testing.T) {
		users, groups := liveAccounts()
		f := newFakeAccounts(t, users, groups)

		result := runGate(t, f,
			[]opnapi.APIUserPayload{{Name: "svc", Password: "pw", Groups: []string{"new-ops"}}},
			[]opnapi.APIGroupPayload{{Name: "new-ops", Priv: []string{"page-system-usermanager"}}},
			false,
		)
		items := refusedItems(result)
		if len(items) != 1 || items[0].Type != "group" {
			t.Fatalf("refused items = %+v, want only the group", items)
		}
		if f.wroteAnythingFor("group", "new-ops") || !f.wrote("add", "user", "svc") {
			t.Errorf("the group is refused and the user, which joins nothing, is applied; writes = %v", f.writes)
		}
	})
}

// TestAdminEquivalenceGate_ClearanceDoesNotDependOnTheLocalPolicy: the owner's
// switch neither lifts a refusal for missing clearance nor is told to.
func TestAdminEquivalenceGate_ClearanceDoesNotDependOnTheLocalPolicy(t *testing.T) {
	tests := []struct {
		name            string
		cleared         bool
		rejectDangerous bool
		wantRefused     bool
		wantClearance   bool // the clearance message and code, as opposed to the local policy's
	}{
		{"no clearance, local policy off", false, false, true, true},
		{"no clearance, local policy on", false, true, true, true},
		{"cleared, local policy off", true, false, false, false},
		{"cleared, local policy on", true, true, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			users, groups := liveAccounts()
			f := newFakeAccounts(t, users, groups)
			user := opnapi.APIUserPayload{Name: "svc", Password: "pw", Priv: []string{"page-all"}, SuperuserCleared: tt.cleared}

			result := runGate(t, f, []opnapi.APIUserPayload{user}, nil, tt.rejectDangerous)

			items := refusedItems(result)
			if !tt.wantRefused {
				if len(items) != 0 || !f.wrote("add", "user", "svc") {
					t.Fatalf("the element must be applied: items %+v, writes %v", items, f.writes)
				}
				return
			}
			if len(items) != 1 {
				t.Fatalf("refused items = %+v, want one", items)
			}
			if tt.wantClearance {
				if items[0].Code != adminEquivalentCode || !strings.Contains(items[0].Error, "Superuser clearance required") {
					t.Errorf("item = %+v, want the clearance refusal", items[0])
				}
				return
			}
			if items[0].Code != "" || !strings.Contains(items[0].Error, "rejected by local policy reject_dangerous_snippets") {
				t.Errorf("item = %+v, want the owner's own policy refusal, unchanged and without a code", items[0])
			}
		})
	}
}

// TestAdminEquivalenceGate_FloorDependentPrivsFollowThePolicy runs the whole
// executor under a policy that elevates the catalog's floor-dependent IDs.
func TestAdminEquivalenceGate_FloorDependentPrivsFollowThePolicy(t *testing.T) {
	user := opnapi.APIUserPayload{Name: "svc", Password: "pw", Priv: []string{"page-filter-api"}}

	users, groups := liveAccounts()
	f := newFakeAccounts(t, users, groups)
	result := executeSyncUsersGroupsWithPolicy(context.Background(), f.client, []opnapi.APIUserPayload{user}, nil, false, authDeferralInfo{}, opnapi.PrivPolicy{})
	if len(refusedItems(result)) != 0 || !f.wrote("add", "user", "svc") {
		t.Errorf("default policy: page-filter-api is ordinary, result %+v writes %v", result.Results, f.writes)
	}

	users, groups = liveAccounts()
	f = newFakeAccounts(t, users, groups)
	result = executeSyncUsersGroupsWithPolicy(context.Background(), f.client, []opnapi.APIUserPayload{user}, nil, false, authDeferralInfo{}, opnapi.PrivPolicy{FloorDependentElevated: true})
	if len(refusedItems(result)) != 1 || f.wroteAnythingFor("user", "svc") {
		t.Errorf("elevating policy: page-filter-api is administrator-equivalent, result %+v writes %v", result.Results, f.writes)
	}
}

// TestParseAPIUsersGroups_ClearanceAndProvenance: the clearance is read from the
// snippet dict exactly, and the snippet's name and index ride along.
func TestParseAPIUsersGroups_ClearanceAndProvenance(t *testing.T) {
	values := []struct {
		name    string
		set     bool
		value   interface{}
		cleared bool
	}{
		{"exactly org:su", true, "org:su", true},
		{"absent", false, nil, false},
		{"null", true, nil, false},
		{"empty", true, "", false},
		{"org:rw", true, "org:rw", false},
		{"bare su", true, "su", false},
		{"upper case", true, "SU", false},
		{"mixed case", true, "Org:Su", false},
		{"padded before", true, " org:su", false},
		{"padded after", true, "org:su ", false},
		{"a boolean", true, true, false},
		{"a number", true, 1, false},
		{"a list", true, []interface{}{"org:su"}, false},
	}

	for _, tt := range values {
		t.Run(tt.name, func(t *testing.T) {
			userSnippet := map[string]interface{}{
				"config_type":   "USER",
				"snippet_name":  "user-snip",
				"template_name": []interface{}{"t1"},
				"content":       `{"name":"svc","password":"pw"}`,
			}
			groupSnippet := map[string]interface{}{
				"config_type":   "GROUP",
				"snippet_name":  "group-snip",
				"template_name": []interface{}{"t1"},
				"content":       `{"name":"ops"}`,
			}
			if tt.set {
				userSnippet["content_clearance"] = tt.value
				groupSnippet["content_clearance"] = tt.value
			}
			payload := map[string]interface{}{"snippets": []interface{}{
				map[string]interface{}{"config_type": "ALIAS", "snippet_name": "an-alias", "content": `{}`},
				userSnippet,
				groupSnippet,
			}}

			users, err := parseAPIUsers(payload)
			if err != nil || len(users) != 1 {
				t.Fatalf("parseAPIUsers = %v, %v", users, err)
			}
			groups, err := parseAPIGroups(payload)
			if err != nil || len(groups) != 1 {
				t.Fatalf("parseAPIGroups = %v, %v", groups, err)
			}

			if users[0].SuperuserCleared != tt.cleared {
				t.Errorf("user cleared = %v, want %v", users[0].SuperuserCleared, tt.cleared)
			}
			if groups[0].SuperuserCleared != tt.cleared {
				t.Errorf("group cleared = %v, want %v", groups[0].SuperuserCleared, tt.cleared)
			}
			if users[0].SnippetName != "user-snip" || users[0].SnippetIndex != 1 {
				t.Errorf("user provenance = %q/%d, want user-snip/1", users[0].SnippetName, users[0].SnippetIndex)
			}
			if groups[0].SnippetName != "group-snip" || groups[0].SnippetIndex != 2 {
				t.Errorf("group provenance = %q/%d, want group-snip/2", groups[0].SnippetName, groups[0].SnippetIndex)
			}
		})
	}
}

// TestSnippetClearanceKeyIsTheDocumentedLiteral pins the wire contract literally
// instead of through the constants: NDManager writes exactly this key and value.
func TestSnippetClearanceKeyIsTheDocumentedLiteral(t *testing.T) {
	if snippetClearanceKey != "content_clearance" || snippetClearanceSuperuser != "org:su" {
		t.Fatalf("clearance wire contract = %q/%q, want content_clearance/org:su", snippetClearanceKey, snippetClearanceSuperuser)
	}
	if !snippetSuperuserCleared(map[string]interface{}{"content_clearance": "org:su"}) {
		t.Error("the documented literal must clear")
	}
}

func TestAccountPayloadProvenanceIsNotSerialised(t *testing.T) {
	user, _ := json.Marshal(opnapi.APIUserPayload{Name: "u", SuperuserCleared: true, SnippetName: "s", SnippetIndex: 3})
	group, _ := json.Marshal(opnapi.APIGroupPayload{Name: "g", SuperuserCleared: true, SnippetName: "s", SnippetIndex: 3})
	for _, raw := range []string{string(user), string(group)} {
		for _, leaked := range []string{"SuperuserCleared", "SnippetName", "SnippetIndex", "clearance"} {
			if strings.Contains(raw, leaked) {
				t.Errorf("%s leaks %s", raw, leaked)
			}
		}
	}
}

// TestAdminEquivalenceGate_ParsedPayloadEndToEnd runs a SYNC-shaped payload
// through the parser and the executor: the same content is applied when the
// snippet carries the clearance and refused when it does not.
func TestAdminEquivalenceGate_ParsedPayloadEndToEnd(t *testing.T) {
	build := func(clearance interface{}) map[string]interface{} {
		snippet := map[string]interface{}{
			"config_type":  "USER",
			"snippet_name": "breakglass",
			"content":      `{"name":"breakglass","password":"pw-literal","groups":["admins"]}`,
		}
		if clearance != nil {
			snippet["content_clearance"] = clearance
		}
		return map[string]interface{}{"snippets": []interface{}{snippet}}
	}

	for _, tt := range []struct {
		name      string
		clearance interface{}
		applied   bool
	}{
		{"cleared by a Superuser", "org:su", true},
		{"key absent", nil, false},
		{"explicit org:rw", "org:rw", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			users, err := parseAPIUsers(build(tt.clearance))
			if err != nil {
				t.Fatal(err)
			}
			liveUsers, liveGroups := liveAccounts()
			f := newFakeAccounts(t, liveUsers, liveGroups)
			result := runGate(t, f, users, nil, false)

			if got := f.wrote("add", "user", "breakglass"); got != tt.applied {
				t.Errorf("applied = %v, want %v (result %+v)", got, tt.applied, result)
			}
			if tt.applied != result.Success {
				t.Errorf("success = %v, want %v", result.Success, tt.applied)
			}
		})
	}
}

// TestLocalPolicy_RefusesAdministratorEquivalentMembership: with
// reject_dangerous_snippets on, the owner's policy also refuses membership in an
// administrator-equivalent group, found by name or only in the live rows, and
// refuses it for a Superuser-cleared element too. With the policy off a cleared
// element may do it.
func TestLocalPolicy_RefusesAdministratorEquivalentMembership(t *testing.T) {
	const localPrefix = "rejected by local policy reject_dangerous_snippets: groups in user"
	tests := []struct {
		name   string
		groups []string
	}{
		{name: "admins by name", groups: []string{"admins"}},
		{name: "admins, other case", groups: []string{"Admins"}},
		{name: "the read-only group", groups: []string{"netdefense-readonly"}},
		{name: "a hand-made page-all group only the device knows", groups: []string{"nd-hm-all"}},
		{name: "a hand-made user-manager group only the device knows", groups: []string{"nd-hm-usermgr"}},
	}

	for _, tt := range tests {
		run := func(cleared, rejectDangerous bool) (*fakeAccounts, SyncAPIResult) {
			users, groups := liveAccounts()
			f := newFakeAccounts(t, users, groups)
			user := opnapi.APIUserPayload{Name: "svc", Password: "pw", Groups: tt.groups, SuperuserCleared: cleared}
			return f, runGate(t, f, []opnapi.APIUserPayload{user}, nil, rejectDangerous)
		}

		t.Run(tt.name+"/cleared, policy on", func(t *testing.T) {
			f, result := run(true, true)
			items := refusedItems(result)
			if len(items) != 1 || items[0].Name != "svc" {
				t.Fatalf("refused items = %+v, want svc refused", items)
			}
			wantText := localPrefix + ` "svc"; set reject_dangerous_snippets=false in the agent's local configuration to allow`
			if items[0].Error != wantText || items[0].Code != "" {
				t.Errorf("item = %+v\nwant the owner's policy message %q with no code", items[0], wantText)
			}
			assertErrorHasMatchingResultItem(t, "local policy", result.Errors, result.Results)
			if f.wroteAnythingFor("user", "svc") {
				t.Errorf("the refused user reached OPNsense: %v", f.writes)
			}
		})

		t.Run(tt.name+"/cleared, policy off", func(t *testing.T) {
			f, result := run(true, false)
			if len(refusedItems(result)) != 0 || !f.wrote("add", "user", "svc") {
				t.Errorf("a cleared element is applied with the policy off: items %+v, writes %v", refusedItems(result), f.writes)
			}
		})

		t.Run(tt.name+"/not cleared, policy on", func(t *testing.T) {
			_, result := run(false, true)
			items := refusedItems(result)
			if len(items) != 1 || items[0].Code != adminEquivalentCode {
				t.Fatalf("refused items = %+v, want the clearance refusal, which comes first", items)
			}
			if strings.Contains(items[0].Error, "reject_dangerous_snippets: groups") {
				t.Errorf("the owner is not told to flip a switch that would not help: %q", items[0].Error)
			}
		})
	}
}

func TestLocalPolicy_OrdinaryMembershipIsLeftAlone(t *testing.T) {
	users, groups := liveAccounts()
	f := newFakeAccounts(t, users, groups)

	user := opnapi.APIUserPayload{Name: "svc", Password: "pw", Groups: []string{"monitors"}, SuperuserCleared: true}
	result := runGate(t, f, []opnapi.APIUserPayload{user}, nil, true)
	if !result.Success || len(refusedItems(result)) != 0 || !f.wrote("add", "user", "svc") {
		t.Errorf("membership in an ordinary group must pass the owner's policy: %+v, writes %v", result, f.writes)
	}
}

// TestLocalPolicy_UsesTheCatalogForPrivileges: a Superuser-cleared element that
// grants a catalog privilege the old structural rules missed is refused by the
// owner's policy, and applied without it.
func TestLocalPolicy_UsesTheCatalogForPrivileges(t *testing.T) {
	for _, priv := range []string{"page-system-usermanager", "page-system-groupmanager", "page-diagnostics-backup-restore", "page-never-reviewed"} {
		t.Run(priv, func(t *testing.T) {
			users, groups := liveAccounts()
			f := newFakeAccounts(t, users, groups)
			user := opnapi.APIUserPayload{Name: "svc", Password: "pw", Priv: []string{priv}, SuperuserCleared: true}

			result := runGate(t, f, []opnapi.APIUserPayload{user}, nil, true)
			items := refusedItems(result)
			if len(items) != 1 || !strings.Contains(items[0].Error, "reject_dangerous_snippets: priv in user") {
				t.Fatalf("policy on: items %+v, want the owner's priv refusal", items)
			}

			users, groups = liveAccounts()
			f = newFakeAccounts(t, users, groups)
			result = runGate(t, f, []opnapi.APIUserPayload{user}, nil, false)
			if len(refusedItems(result)) != 0 || !f.wrote("add", "user", "svc") {
				t.Errorf("policy off: a cleared element is applied, items %+v writes %v", refusedItems(result), f.writes)
			}
		})
	}
}

// TestLocalPolicy_RefusedMembershipNeverDeletesWhatIsThere: same rule as every
// refusal, for the owner's own policy.
func TestLocalPolicy_RefusedMembershipNeverDeletesWhatIsThere(t *testing.T) {
	users, groups := liveAccounts()
	users = append(users, row{"uuid": "uu-managed", "uid": "2060", "name": "svc-managed", "scope": "user", "priv": "", "group_memberships": "", "is_admin": "0", "descr": "[nd-template:ops]"})
	f := newFakeAccounts(t, users, groups)

	user := opnapi.APIUserPayload{Name: "svc-managed", Password: "pw", Groups: []string{"admins"}, SuperuserCleared: true, Templates: []string{"ops"}}
	result := runGate(t, f, []opnapi.APIUserPayload{user}, nil, true)

	if len(refusedItems(result)) != 1 {
		t.Fatalf("items = %+v, want one refusal", result.Results)
	}
	if f.wrote("del", "user", "svc-managed") || f.wroteAnythingFor("user", "svc-managed") {
		t.Errorf("the refused element that already exists was touched: %v", f.writes)
	}
}

// useInstalledRelease makes the device report the release; "" leaves it
// unreadable, which the gates read as below the floor.
func useInstalledRelease(t *testing.T, version string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "core")
	if version != "" {
		if err := os.WriteFile(path, []byte(`{"product_version":"`+version+`"}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	useLocalReleaseSources(t, path, nil)
}

// The privilege IDs that are ordinary only on a release that carries OPNsense's
// escalation fixes (the catalog's floor-dependent IDs) count as administrator-
// equivalent on a device below the supported floor, or one that cannot say what
// it runs, and are ordinary at and above it.
func TestAdminEquivalenceGate_FloorDependentPrivsFollowTheRelease(t *testing.T) {
	releases := []struct {
		name    string
		version string
		below   bool
	}{
		{"below the floor", "26.1.10", true},
		{"an older series", "25.7.11_9", true},
		{"a release that cannot be read", "", true},
		{"at the floor", "26.1.11", false},
		{"a later series", "26.7.4", false},
	}
	elements := []struct {
		name   string
		users  []opnapi.APIUserPayload
		groups []opnapi.APIGroupPayload
		clause string
	}{
		{
			name:   "a user that is given one",
			users:  []opnapi.APIUserPayload{{Name: "svc", Password: "pw-1", Priv: []string{"page-filter-api"}}},
			clause: `privilege "page-filter-api"`,
		},
		{
			name:   "a group that is given one",
			groups: []opnapi.APIGroupPayload{{Name: "new-g", Priv: []string{"page-openvpn-instances"}}},
			clause: `privilege "page-openvpn-instances"`,
		},
		{
			name:   "a user that joins a group that holds one",
			users:  []opnapi.APIUserPayload{{Name: "svc", Password: "pw-1", Groups: []string{"ops-ipsec"}}},
			clause: `group "ops-ipsec"`,
		},
	}
	for _, rel := range releases {
		for _, el := range elements {
			t.Run(rel.name+"/"+el.name, func(t *testing.T) {
				useInstalledRelease(t, rel.version)
				users, groups := liveAccounts()
				groups = append(groups, row{"uuid": "gg-ipsec", "gid": "2130", "name": "ops-ipsec", "scope": "user", "priv": "page-vpn-ipsec-connections", "member": "", "description": ""})
				f := newFakeAccounts(t, users, groups)

				result := runGate(t, f, el.users, el.groups, false)

				items := refusedItems(result)
				if !rel.below {
					if len(items) != 0 || !result.Success {
						t.Fatalf("at or above the floor nothing is refused, got %+v, errors %v", items, result.Errors)
					}
					return
				}
				if len(items) != 1 || items[0].Code != adminEquivalentCode || !strings.Contains(items[0].Error, el.clause) {
					t.Fatalf("below the floor the element is refused for %s, got %+v", el.clause, items)
				}
				assertErrorHasMatchingResultItem(t, "refused element", result.Errors, result.Results)
			})
		}
	}
}

// The owner's own policy reads the privilege the same way, for an element that
// is Superuser-cleared too.
func TestDangerousSnippetGate_FloorDependentPrivFollowsTheRelease(t *testing.T) {
	for _, tt := range []struct {
		version string
		reject  bool
	}{
		{"26.1.10", true},
		{"26.1.11", false},
	} {
		t.Run(tt.version, func(t *testing.T) {
			useInstalledRelease(t, tt.version)
			users, groups := liveAccounts()
			f := newFakeAccounts(t, users, groups)
			user := opnapi.APIUserPayload{Name: "svc", Password: "pw-1", Priv: []string{"page-services-unbound"}, SuperuserCleared: true}

			result := runGate(t, f, []opnapi.APIUserPayload{user}, nil, true)

			rejected := false
			for _, item := range result.Results {
				if item.Action == "rejected" && strings.Contains(item.Error, "reject_dangerous_snippets") {
					rejected = true
				}
			}
			if rejected != tt.reject {
				t.Errorf("rejected = %v, want %v (errors %v)", rejected, tt.reject, result.Errors)
			}
		})
	}
}
