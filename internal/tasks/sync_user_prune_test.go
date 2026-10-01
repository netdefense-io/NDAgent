package tasks

import (
	"context"
	"strings"
	"testing"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// managedUserRow is a NetDefense-managed user (its description carries the
// template tag) that belongs to the given groups.
func managedUserRow(name, uid, gids string) row {
	return row{"uuid": "uu-" + name, "uid": uid, "name": name, "scope": "user", "priv": "", "group_memberships": gids, "is_admin": "0", "descr": "[nd-template:ops]"}
}

func TestOrphanDelete_TakesTheUserOutOfItsGroupsFirst(t *testing.T) {
	users, groups := liveAccounts()
	users = append(users, managedUserRow("svc-admin", "2070", "1999,2111"))
	groups[0]["member"] = "0,2003,2070,2099" // admins
	groups[3]["member"] = "2004,2010,2070"   // nd-hm-usermgr
	f := newFakeAccounts(t, users, groups)

	result := runGate(t, f, nil, nil, false)

	if !result.Success {
		t.Fatalf("unexpected failure: %v", result.Errors)
	}
	bodies := f.bodies["set user svc-admin"]
	if len(bodies) != 1 {
		t.Fatalf("set calls = %d, want exactly 1", len(bodies))
	}
	if gm, present := bodies[0]["group_memberships"]; !present || gm != "" {
		t.Errorf("group_memberships = %v (present %v), want an explicit empty string", gm, present)
	}
	if _, sent := bodies[0]["password"]; sent {
		t.Error("no password may be sent: the account is about to be deleted and the stored one must stay untouched")
	}
	if bodies[0]["name"] != "svc-admin" {
		t.Errorf("name = %v", bodies[0]["name"])
	}

	setAt, delAt := f.writeIndex("set", "user", "svc-admin"), f.writeIndex("del", "user", "svc-admin")
	if setAt < 0 || delAt < 0 || setAt > delAt {
		t.Errorf("the membership removal must come before the delete, writes = %v", f.writes)
	}
	if left := f.memberListsHolding("2070"); len(left) != 0 {
		t.Errorf("uid 2070 is still in the member list of %v: a dangling uid the next local account inherits", left)
	}
	// Only the deleted user's memberships go: the other administrators keep theirs.
	if left := f.memberListsHolding("2003"); len(left) != 2 {
		t.Errorf("alice-admin must stay in admins and nd-hm-all, found in %v", left)
	}
	if left := f.memberListsHolding("0"); len(left) != 1 || left[0] != "admins" {
		t.Errorf("root must stay in admins, found in %v", left)
	}
}

func TestOrphanDelete_NoMembershipNoExtraCall(t *testing.T) {
	users, groups := liveAccounts()
	users = append(users, managedUserRow("svc-loner", "2071", ""))
	f := newFakeAccounts(t, users, groups)

	result := runGate(t, f, nil, nil, false)

	if !result.Success {
		t.Fatalf("unexpected failure: %v", result.Errors)
	}
	if f.wrote("set", "user", "svc-loner") {
		t.Errorf("a user that belongs to no group needs no extra call (every write cuts a config revision): %v", f.writes)
	}
	if !f.wrote("del", "user", "svc-loner") {
		t.Errorf("the user must still be deleted: %v", f.writes)
	}
}

// TestOrphanDelete_MembershipIsReadFromEitherSide: the user's own group list and
// a group's member list are two views of one fact, and the prune follows either.
func TestOrphanDelete_MembershipIsReadFromEitherSide(t *testing.T) {
	tests := []struct {
		name      string
		userGIDs  string
		groupList string // what monitors' member list holds besides 2005
	}{
		{"only the user's own list says so", "2120", "2005"},
		{"only the group's member list says so", "", "2005,2072"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			users, groups := liveAccounts()
			users = append(users, managedUserRow("svc-one-sided", "2072", tt.userGIDs))
			groups[4]["member"] = tt.groupList // monitors
			f := newFakeAccounts(t, users, groups)

			runGate(t, f, nil, nil, false)

			if !f.wrote("set", "user", "svc-one-sided") || !f.wrote("del", "user", "svc-one-sided") {
				t.Errorf("the user must be pruned and deleted: %v", f.writes)
			}
		})
	}
}

// TestOrphanDelete_PrunesAMembershipThisSyncWrote: a GROUP of the sync lists a
// managed user that no USER snippet wants any more, so the group update writes
// its uid into the member list and the sweep then deletes the user. That uid must
// not dangle either.
func TestOrphanDelete_PrunesAMembershipThisSyncWrote(t *testing.T) {
	users, groups := liveAccounts()
	users = append(users, managedUserRow("svc-orphan", "2073", ""))
	f := newFakeAccounts(t, users, groups)

	desiredGroups := []opnapi.APIGroupPayload{{Name: "monitors", Priv: []string{"page-status-services"}, Members: []string{"carol", "svc-orphan"}}}
	result := runGate(t, f, nil, desiredGroups, false)

	if !result.Success {
		t.Fatalf("unexpected failure: %v", result.Errors)
	}
	if !f.wrote("set", "user", "svc-orphan") {
		t.Errorf("the membership this sync just wrote must be pruned: %v", f.writes)
	}
	if left := f.memberListsHolding("2073"); len(left) != 0 {
		t.Errorf("uid 2073 dangles in %v", left)
	}
}

func TestOrphanDelete_PruneFailureNeverBlocksTheDelete(t *testing.T) {
	t.Run("an administrator-equivalent group fails the task", func(t *testing.T) {
		users, groups := liveAccounts()
		users = append(users, managedUserRow("svc-admin", "2070", "1999"))
		groups[0]["member"] = "0,2003,2070,2099"
		f := newFakeAccounts(t, users, groups)
		f.failed["set user"] = true

		result := runGate(t, f, nil, nil, false)

		if !f.wrote("del", "user", "svc-admin") {
			t.Errorf("the delete must still go ahead: %v", f.writes)
		}
		if result.Success {
			t.Error("a uid left in admins must fail the task visibly")
		}
		if len(result.Errors) != 1 || !strings.Contains(result.Errors[0], "administrator-equivalent group") || !strings.Contains(result.Errors[0], "svc-admin") {
			t.Errorf("errors = %v, want one naming the user and the group kind", result.Errors)
		}
		assertErrorHasMatchingResultItem(t, "prune failure", result.Errors, result.Results)
	})

	t.Run("an ordinary group is a warning", func(t *testing.T) {
		users, groups := liveAccounts()
		users = append(users, managedUserRow("svc-mon", "2074", "2120"))
		groups[4]["member"] = "2005,2074"
		f := newFakeAccounts(t, users, groups)
		f.failed["set user"] = true

		result := runGate(t, f, nil, nil, false)

		if !f.wrote("del", "user", "svc-mon") {
			t.Errorf("the delete must still go ahead: %v", f.writes)
		}
		if !result.Success || len(result.Errors) != 0 {
			t.Errorf("an ordinary group must not fail the task: %+v", result)
		}
		var warned bool
		for _, r := range result.Results {
			if r.Action == "remove_group_memberships" && r.Status == "warning" && r.Name == "svc-mon" {
				warned = true
			}
		}
		if !warned {
			t.Errorf("a warning item must say so: %+v", result.Results)
		}
		assertNoUnpairedErrors(t, result)
	})
}

// assertNoUnpairedErrors is the parity invariant for a result that may hold
// warnings: every error has an item and every non-warning, non-success item an error.
func assertNoUnpairedErrors(t *testing.T, result SyncAPIResult) {
	t.Helper()
	if len(result.Errors) == 0 {
		for _, r := range countNonSuccessResults(result.Results) {
			t.Errorf("an item without an error: %+v", r)
		}
		return
	}
	assertErrorHasMatchingResultItem(t, "parity", result.Errors, result.Results)
}

func TestOrphanDelete_ProtectedUsersAreNeverPrunedOrDeleted(t *testing.T) {
	users, groups := liveAccounts()
	for _, u := range users {
		if u["name"] == "netdefense-agent" || u["name"] == "netdefense-readonly" {
			u["descr"] = "[nd-template:base]"
		}
	}
	f := newFakeAccounts(t, users, groups)

	runGate(t, f, nil, nil, false)

	if n := f.writeCount(); n != 0 {
		t.Errorf("protected accounts are managed by the plugin, never the sweep: %v", f.writes)
	}
}

// TestOrphanDelete_DecommissionShape: the decommission reconciles every managed
// family to an empty desired state through this same executor.
func TestOrphanDelete_DecommissionShape(t *testing.T) {
	users, groups := liveAccounts()
	users = append(users,
		managedUserRow("svc-a", "2080", "1999"),
		managedUserRow("svc-b", "2081", ""),
		managedUserRow("svc-c", "2082", "2120"),
	)
	groups[0]["member"] = "0,2003,2080,2099"
	groups[4]["member"] = "2005,2082"
	f := newFakeAccounts(t, users, groups)

	result := executeSyncUsersGroups(context.Background(), f.client, nil, nil, false, authDeferralInfo{})

	if !result.Success {
		t.Fatalf("unexpected failure: %v", result.Errors)
	}
	for _, uid := range []string{"2080", "2081", "2082"} {
		if left := f.memberListsHolding(uid); len(left) != 0 {
			t.Errorf("uid %s still in %v after a decommission", uid, left)
		}
	}
	if f.wrote("set", "user", "svc-b") {
		t.Error("svc-b belongs to no group and needs no prune")
	}
	for _, name := range []string{"svc-a", "svc-b", "svc-c"} {
		if !f.wrote("del", "user", name) {
			t.Errorf("%s must be deleted", name)
		}
	}
}

// TestOrphanDelete_GroupRefreshFailureLeavesTheUsersOwnList: the groups are
// re-read after Phase 2 and that error is not fatal. Without it the sweep still
// has the user's own group list, which OPNsense derives from the member lists.
func TestOrphanDelete_GroupRefreshFailureLeavesTheUsersOwnList(t *testing.T) {
	users, groups := liveAccounts()
	users = append(users, managedUserRow("svc-admin", "2070", "1999"))
	groups[0]["member"] = "0,2003,2070,2099"
	f := newFakeAccounts(t, users, groups)

	// The first group listing (Phase 1) succeeds; the refresh after Phase 2 fails.
	calls := 0
	f.onGroupSearch = func() bool {
		calls++
		return calls >= 2
	}

	result := runGate(t, f, nil, nil, false)

	if !f.wrote("set", "user", "svc-admin") || !f.wrote("del", "user", "svc-admin") {
		t.Errorf("the user's own group list still shows the membership: %v", f.writes)
	}
	if !result.Success {
		t.Errorf("unexpected failure: %v", result.Errors)
	}
}

// TestOrphanDelete_ChecksThatThePruneLeftNoUidBehind: OPNsense takes one
// occurrence of the uid out of a member list per save (array_search and unset),
// and a list can hold it twice, so a save that succeeds can leave the uid there.
// The sweep reads the groups again and saves again, a few times at most, and says
// so when the uid is still listed.
func TestOrphanDelete_ChecksThatThePruneLeftNoUidBehind(t *testing.T) {
	t.Run("a uid listed twice is taken out of the list once for each", func(t *testing.T) {
		users, groups := liveAccounts()
		users = append(users, managedUserRow("svc-dup", "2090", "2120"))
		groups[4]["member"] = "2005,2090,2090" // monitors
		f := newFakeAccounts(t, users, groups)

		result := runGate(t, f, nil, nil, false)

		if !result.Success || len(result.Errors) != 0 {
			t.Fatalf("unexpected failure: %v", result.Errors)
		}
		if n := len(f.bodies["set user svc-dup"]); n != 2 {
			t.Errorf("set calls = %d, want 2: one save per occurrence", n)
		}
		if left := f.memberListsHolding("2090"); len(left) != 0 {
			t.Errorf("uid 2090 still listed in %v", left)
		}
		if !f.wrote("del", "user", "svc-dup") {
			t.Errorf("the user must be deleted: %v", f.writes)
		}
		if f.writeIndex("set", "user", "svc-dup") > f.writeIndex("del", "user", "svc-dup") {
			t.Errorf("the prune comes before the delete: %v", f.writes)
		}
	})

	t.Run("a prune that changes nothing is reported, in an ordinary group a warning", func(t *testing.T) {
		users, groups := liveAccounts()
		users = append(users, managedUserRow("svc-stuck", "2091", "2120"))
		groups[4]["member"] = "2005,2091"
		f := newFakeAccounts(t, users, groups)
		f.keepMemberLists = true

		result := runGate(t, f, nil, nil, false)

		if n := len(f.bodies["set user svc-stuck"]); n != 3 {
			t.Errorf("set calls = %d, want the 3 attempts and no more", n)
		}
		if !f.wrote("del", "user", "svc-stuck") {
			t.Errorf("a prune that did not work never blocks the delete: %v", f.writes)
		}
		if !result.Success {
			t.Errorf("a uid left in an ordinary group must not fail the task: %v", result.Errors)
		}
		var warned bool
		for _, r := range result.Results {
			if r.Action == "remove_group_memberships" && r.Status == "warning" && r.Name == "svc-stuck" && strings.Contains(r.Error, `"monitors"`) {
				warned = true
			}
		}
		if !warned {
			t.Errorf("a warning item naming the group must say so: %+v", result.Results)
		}
		assertNoUnpairedErrors(t, result)
	})

	t.Run("a prune that changes nothing fails the task in an administrator-equivalent group", func(t *testing.T) {
		users, groups := liveAccounts()
		users = append(users, managedUserRow("svc-admin", "2092", "1999"))
		groups[0]["member"] = "0,2003,2092,2099"
		f := newFakeAccounts(t, users, groups)
		f.keepMemberLists = true

		result := runGate(t, f, nil, nil, false)

		if !f.wrote("del", "user", "svc-admin") {
			t.Errorf("the delete goes ahead: %v", f.writes)
		}
		if result.Success {
			t.Error("a uid left in admins must fail the task visibly")
		}
		if len(result.Errors) != 1 || !strings.Contains(result.Errors[0], "administrator-equivalent group") || !strings.Contains(result.Errors[0], "svc-admin") {
			t.Errorf("errors = %v, want one naming the user and the group kind", result.Errors)
		}
		assertErrorHasMatchingResultItem(t, "prune left the uid", result.Errors, result.Results)
	})

	t.Run("a group listing that fails cannot say, and is not an error", func(t *testing.T) {
		users, groups := liveAccounts()
		users = append(users, managedUserRow("svc-blind", "2093", "2120"))
		groups[4]["member"] = "2005,2093"
		f := newFakeAccounts(t, users, groups)
		f.keepMemberLists = true
		calls := 0
		f.onGroupSearch = func() bool {
			calls++
			return calls >= 3 // Phase 1 and the refresh after Phase 2 succeed, the check does not
		}

		result := runGate(t, f, nil, nil, false)

		if !result.Success || len(result.Errors) != 0 {
			t.Errorf("an unverifiable prune is not a failure: %v", result.Errors)
		}
		if n := len(f.bodies["set user svc-blind"]); n != 1 {
			t.Errorf("set calls = %d, want 1: there is nothing to repeat without a reading", n)
		}
		if !f.wrote("del", "user", "svc-blind") {
			t.Errorf("the delete goes ahead: %v", f.writes)
		}
	})

	t.Run("a user that belongs to no group costs no reading either", func(t *testing.T) {
		users, groups := liveAccounts()
		users = append(users, managedUserRow("svc-loner", "2094", ""))
		f := newFakeAccounts(t, users, groups)
		searches := 0
		f.onGroupSearch = func() bool { searches++; return false }

		runGate(t, f, nil, nil, false)

		if searches != 2 {
			t.Errorf("group listings = %d, want the two the sync itself makes", searches)
		}
	})
}
