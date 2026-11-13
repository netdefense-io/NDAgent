package tasks

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// groupsOf is the sorted names of the groups whose member list holds the user.
func groupsOf(f *fakeAccounts, name string) []string {
	uid, _ := f.userRow(name)["uid"].(string)
	out := f.memberListsHolding(uid)
	sort.Strings(out)
	if out == nil {
		out = []string{}
	}
	return out
}

func lastBody(t *testing.T, f *fakeAccounts, verb, kind, name string) map[string]interface{} {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	bodies := f.bodies[verb+" "+kind+" "+name]
	if len(bodies) == 0 {
		t.Fatalf("no %s of %s %q", verb, kind, name)
	}
	return bodies[len(bodies)-1]
}

// The operator's ruling (2026-11-12, #192): a USER that leaves out `groups` or
// `priv` declares none, so the user leaves every group no GROUP of the sync
// keeps it in and loses its direct privileges, and an explicit [] does the same.
func TestUserSnippet_ALeftOutListClears(t *testing.T) {
	for _, content := range []string{
		`{"name":"carol","password":"pw"}`,
		`{"name":"carol","password":"pw","groups":[],"priv":[]}`,
	} {
		t.Run(content, func(t *testing.T) {
			users, groups := liveAccounts()
			for _, u := range users {
				if u["name"] == "carol" {
					u["priv"] = "page-status-services"
				}
			}
			f := newFakeAccounts(t, users, groups)
			user, err := parseUserContent(content, nil)
			if err != nil {
				t.Fatal(err)
			}
			result := runGate(t, f, []opnapi.APIUserPayload{user}, nil, false)
			if !result.Success {
				t.Fatalf("errors = %v", result.Errors)
			}
			body := lastBody(t, f, "set", "user", "carol")
			if gm, sent := body["group_memberships"]; !sent || gm != "" {
				t.Errorf("group_memberships = %v (sent %v), want an explicit empty value", gm, sent)
			}
			if priv, sent := body["priv"]; !sent || priv != "" {
				t.Errorf("priv = %v (sent %v), want an explicit empty value", priv, sent)
			}
			if got := groupsOf(f, "carol"); len(got) != 0 {
				t.Errorf("carol is still in %v", got)
			}
		})
	}
}

// The account gate still protects an administrator-equivalent account: clearing
// its groups is a change to it, which needs Superuser clearance.
func TestUserSnippet_ClearingAnAdministratorsGroupsNeedsClearance(t *testing.T) {
	users, groups := liveAccounts()
	f := newFakeAccounts(t, users, groups)
	result := runGate(t, f, []opnapi.APIUserPayload{{Name: "alice-admin", Password: "pw"}}, nil, false)
	if items := refusedItems(result); len(items) != 1 || items[0].Code != adminEquivalentCode {
		t.Fatalf("refused items = %+v, want the clearance refusal", items)
	}
	if f.wroteAnythingFor("user", "alice-admin") || !reflect.DeepEqual(groupsOf(f, "alice-admin"), []string{"admins", "nd-hm-all"}) {
		t.Errorf("an uncleared element changed an administrator: writes %v, groups %v", f.writes, groupsOf(f, "alice-admin"))
	}

	users, groups = liveAccounts()
	f = newFakeAccounts(t, users, groups)
	result = runGate(t, f, []opnapi.APIUserPayload{{Name: "alice-admin", Password: "pw", SuperuserCleared: true}}, nil, false)
	if !result.Success || len(refusedItems(result)) != 0 {
		t.Fatalf("a cleared element is applied: %+v", result)
	}
	if got := groupsOf(f, "alice-admin"); len(got) != 0 {
		t.Errorf("alice-admin is still in %v", got)
	}
}

// The union (operator ruling, 2026-11-12): a group's members are the members its
// GROUP declares plus every USER that names it, and neither side removes what
// the other declares. A group no GROUP of the sync writes members for follows
// the USERs.
func TestMemberships_AreTheUnionOfBothSides(t *testing.T) {
	users, groups := liveAccounts()
	f := newFakeAccounts(t, users, groups)
	sync := func() SyncAPIResult {
		return runGate(t, f,
			[]opnapi.APIUserPayload{
				{Name: "carol", Password: "pw"},
				{Name: "nd-hm-plain", Password: "pw", Groups: []string{"ops"}},
			},
			[]opnapi.APIGroupPayload{{Name: "ops", Priv: []string{"page-status-services"}, Members: []string{"carol"}}},
			false,
		)
	}
	for round := 1; round <= 2; round++ {
		if result := sync(); !result.Success {
			t.Fatalf("round %d: errors = %v", round, result.Errors)
		}
		if got := groupsOf(f, "carol"); !reflect.DeepEqual(got, []string{"ops"}) {
			t.Errorf("round %d: carol is in %v, want only ops (declared by the GROUP; monitors follows her USER, which names none)", round, got)
		}
		if got := groupsOf(f, "nd-hm-plain"); !reflect.DeepEqual(got, []string{"ops"}) {
			t.Errorf("round %d: nd-hm-plain is in %v, want ops (declared by the USER, kept by the GROUP's write)", round, got)
		}
	}
}

// An element the gate refused declares nothing: the memberships it has stay.
func TestMemberships_ARefusedElementKeepsWhatItHas(t *testing.T) {
	t.Run("a refused GROUP keeps its members", func(t *testing.T) {
		users, groups := liveAccounts()
		f := newFakeAccounts(t, users, groups)
		result := runGate(t, f,
			[]opnapi.APIUserPayload{{Name: "carol", Password: "pw"}},
			[]opnapi.APIGroupPayload{{Name: "monitors", Priv: []string{"page-system-usermanager"}, Members: []string{"nd-hm-plain"}}},
			false,
		)
		if items := refusedItems(result); len(items) != 1 || items[0].Name != "monitors" {
			t.Fatalf("refused items = %+v, want the group", items)
		}
		if got := groupsOf(f, "carol"); !reflect.DeepEqual(got, []string{"monitors"}) {
			t.Errorf("carol is in %v, want to stay in monitors, whose GROUP was refused", got)
		}
	})

	t.Run("a refused USER keeps its memberships in a group the sync writes", func(t *testing.T) {
		users, groups := liveAccounts()
		f := newFakeAccounts(t, users, groups)
		result := runGate(t, f,
			[]opnapi.APIUserPayload{{Name: "carol", Password: "pw", Groups: []string{"no-such-group"}}},
			[]opnapi.APIGroupPayload{{Name: "monitors", Priv: []string{"page-status-services"}, Members: []string{"nd-hm-plain"}}},
			false,
		)
		if items := refusedItems(result); len(items) != 1 || items[0].Name != "carol" || items[0].Code != userGroupUnknownCode {
			t.Fatalf("refused items = %+v, want carol, for the group that is not there", items)
		}
		if got := groupsOf(f, "carol"); !reflect.DeepEqual(got, []string{"monitors"}) {
			t.Errorf("carol is in %v, want to stay in monitors", got)
		}
		if got := groupsOf(f, "nd-hm-plain"); !reflect.DeepEqual(got, []string{"monitors"}) {
			t.Errorf("nd-hm-plain is in %v, want monitors", got)
		}
	})
}

// A USER that names a group the device does not have and the sync does not
// create is refused, and the user is not changed.
func TestUserSnippet_AnUnknownGroupIsRefused(t *testing.T) {
	users, groups := liveAccounts()
	f := newFakeAccounts(t, users, groups)
	result := runGate(t, f,
		[]opnapi.APIUserPayload{
			{Name: "carol", Password: "pw", Groups: []string{"monitors", "Monitors", "ops"}},
			{Name: "newbie", Password: "pw", Groups: []string{"ops"}},
		},
		[]opnapi.APIGroupPayload{{Name: "ops", Priv: []string{"page-status-services"}}},
		false,
	)
	items := refusedItems(result)
	if len(items) != 1 || items[0].Name != "carol" || items[0].Code != userGroupUnknownCode || items[0].Status != "error" {
		t.Fatalf("refused items = %+v, want carol refused for \"Monitors\"", items)
	}
	if want := `user snippet at index 0 for user "carol" names group "Monitors", which the device does not have and this sync does not create; the user was not changed`; items[0].Error != want {
		t.Errorf("message = %q, want %q", items[0].Error, want)
	}
	if result.Success {
		t.Error("the refusal must fail the task")
	}
	assertErrorHasMatchingResultItem(t, "unknown group", result.Errors, result.Results)
	if f.wroteAnythingFor("user", "carol") {
		t.Errorf("carol was written: %v", f.writes)
	}
	if !f.wrote("add", "user", "newbie") || !reflect.DeepEqual(groupsOf(f, "newbie"), []string{"ops"}) {
		t.Errorf("a group this sync creates is known: writes %v, newbie in %v", f.writes, groupsOf(f, "newbie"))
	}
}

// A member new to a group whose members the sync writes waits for the AUTH
// exclusion to cover its name, whichever side declares it, and the wait is
// reported and fails the task.
func TestMemberships_ANewMemberWaitsForTheExclusionWhicheverSideDeclaresIt(t *testing.T) {
	for _, members := range [][]string{{"carol", "newbie"}, {"carol"}} {
		t.Run(strings.Join(members, ","), func(t *testing.T) {
			users, groups := liveAccounts()
			f := newFakeAccounts(t, users, groups)
			auth := authDeferralInfo{Active: true, StaleNames: map[string]bool{"nd-hm-plain": true, "newbie": true}}
			result := executeSyncUsersGroups(context.Background(), f.client,
				[]opnapi.APIUserPayload{{Name: "nd-hm-plain", Password: "pw", Groups: []string{"ops", "monitors"}}, {Name: "newbie", Password: "pw"}},
				[]opnapi.APIGroupPayload{{Name: "ops", Priv: []string{"page-status-services"}, Members: members}},
				false, auth)
			if got := groupsOf(f, "nd-hm-plain"); !reflect.DeepEqual(got, []string{"monitors"}) {
				t.Errorf("nd-hm-plain is in %v, want monitors only: ops is written by this sync and its name is not covered yet", got)
			}
			if got := groupsOf(f, "carol"); !reflect.DeepEqual(got, []string{"monitors", "ops"}) {
				t.Errorf("carol is in %v, want monitors and ops", got)
			}
			var deferred []string
			for _, r := range result.Results {
				if r.Action == "deferred" {
					deferred = append(deferred, r.Name)
				}
			}
			sort.Strings(deferred)
			want := []string{"newbie", "ops/nd-hm-plain"}
			if containsName(members, "newbie") {
				want = []string{"newbie", "ops/nd-hm-plain", "ops/newbie"}
			}
			if !reflect.DeepEqual(deferred, want) {
				t.Errorf("deferred items = %v, want %v", deferred, want)
			}
			if result.Success {
				t.Error("a withheld membership must fail the task")
			}
			assertErrorHasMatchingResultItem(t, "deferred member", result.Errors, result.Results)
		})
	}
}

// A user's own write adds a membership only its GROUP declares once that
// GROUP's write went through, so a group's new privileges and its new members
// land together: a GROUP that fails to drop page-all does not let an uncleared
// user in under it.
func TestMemberships_AGroupDeclaredMemberJoinsOnlyWithItsGroup(t *testing.T) {
	for _, groupWriteFails := range []bool{true, false} {
		t.Run(fmt.Sprintf("group write fails %v", groupWriteFails), func(t *testing.T) {
			users, groups := liveAccounts()
			f := newFakeAccounts(t, users, groups)
			f.failed["set group"] = groupWriteFails
			runGate(t, f,
				[]opnapi.APIUserPayload{{Name: "carol", Password: "pw", Groups: []string{"monitors"}}},
				[]opnapi.APIGroupPayload{{Name: "nd-hm-all", Priv: []string{"page-status-services"}, Members: []string{"alice-admin", "gina-groupcsv", "carol"}, SuperuserCleared: true}},
				false,
			)
			in := containsName(groupsOf(f, "carol"), "nd-hm-all")
			if groupWriteFails && in {
				t.Errorf("carol joined nd-hm-all, whose write failed and which still grants %v", f.groupRow("nd-hm-all")["priv"])
			}
			if !groupWriteFails && !in {
				t.Errorf("carol is not in nd-hm-all after its write went through: %v", groupsOf(f, "carol"))
			}
		})
	}
}

// Two GROUP elements of one name write the same group in turn, so one's write
// going through says nothing about the privileges the group is left with: a
// user's own write never adds a membership only such a GROUP declares.
func TestMemberships_TwoGroupsOfOneNameNeverLandAMember(t *testing.T) {
	users, groups := liveAccounts()
	f := newFakeAccounts(t, users, groups)
	f.failed["set group"] = true
	runGate(t, f,
		[]opnapi.APIUserPayload{{Name: "carol", Password: "pw", Groups: []string{"monitors"}}},
		[]opnapi.APIGroupPayload{
			{Name: "nd-new", Priv: []string{"page-all"}, SuperuserCleared: true},
			{Name: "nd-new", Priv: []string{"page-status-services"}, Members: []string{"carol"}, SuperuserCleared: true},
		},
		false,
	)
	if !f.wrote("add", "group", "nd-new") {
		t.Fatalf("the first element must be created: %v", f.writes)
	}
	if got := groupsOf(f, "carol"); containsName(got, "nd-new") {
		t.Errorf("carol joined nd-new, which grants %v, through her own uncleared write", f.groupRow("nd-new")["priv"])
	}
}

// A user listing that fails after the users are written skips the member writes
// and the orphan sweep, and says so.
func TestMemberships_AFailedUserListingIsReported(t *testing.T) {
	users, groups := liveAccounts()
	users = append(users, row{"uuid": "uu-old", "uid": "2050", "name": "old-managed", "scope": "user", "priv": "", "group_memberships": "", "is_admin": "0", "descr": opnapi.AddTemplateTag("", "t1")})
	f := newFakeAccounts(t, users, groups)
	searches := 0
	f.onUserSearch = func() bool { searches++; return searches > 1 }
	result := runGate(t, f,
		[]opnapi.APIUserPayload{{Name: "newbie", Password: "pw"}},
		[]opnapi.APIGroupPayload{{Name: "monitors", Priv: []string{"page-status-services"}, Members: []string{"newbie"}}},
		false,
	)
	if result.Success {
		t.Error("a sync whose member writes were skipped must fail")
	}
	found := false
	for _, r := range result.Results {
		found = found || (r.Type == "user_discovery" && r.Status == "error")
	}
	if !found {
		t.Errorf("no item says the users could not be listed: %+v", result.Results)
	}
	assertErrorHasMatchingResultItem(t, "user listing", result.Errors, result.Results)
	if f.wrote("del", "user", "old-managed") {
		t.Errorf("the orphan sweep ran on rows read before the writes: %v", f.writes)
	}
}

// A user phase 3 did not write is treated like a refused one: a group the sync
// writes keeps it if it was there and adds it nowhere, whatever its snippet asks.
func TestMemberships_AUserThatWasNotWrittenKeepsItsMemberships(t *testing.T) {
	users, groups := liveAccounts()
	f := newFakeAccounts(t, users, groups)
	f.failed["set user"] = true
	result := runGate(t, f,
		[]opnapi.APIUserPayload{
			{Name: "carol", Password: "pw", Groups: []string{"ops"}},
			{Name: "nd-hm-plain", Password: "pw", Groups: []string{"ops", "monitors"}},
		},
		[]opnapi.APIGroupPayload{{Name: "monitors", Priv: []string{"page-status-services"}}, {Name: "ops", Priv: []string{"page-status-services"}}},
		false,
	)
	if result.Success {
		t.Fatal("the failed user writes must fail the task")
	}
	if got := groupsOf(f, "carol"); !reflect.DeepEqual(got, []string{"monitors"}) {
		t.Errorf("carol is in %v, want monitors kept: her write failed", got)
	}
	if got := groupsOf(f, "nd-hm-plain"); len(got) != 0 {
		t.Errorf("nd-hm-plain is in %v, want nowhere: her write failed, so no group's write adds her", got)
	}
}

// A USER that names a group the live device grants page-all through is judged
// against that group, whatever the sync plans for it.
func TestMemberships_AUserNamingALiveElevatedGroupNeedsClearance(t *testing.T) {
	users, groups := liveAccounts()
	f := newFakeAccounts(t, users, groups)
	f.failed["set group"] = true
	result := runGate(t, f,
		[]opnapi.APIUserPayload{{Name: "carol", Password: "pw", Groups: []string{"monitors", "nd-hm-all"}}},
		[]opnapi.APIGroupPayload{{Name: "nd-hm-all", Priv: []string{"page-status-services"}, Members: []string{"alice-admin", "gina-groupcsv"}, SuperuserCleared: true}},
		false,
	)
	if items := refusedItems(result); len(items) != 1 || items[0].Name != "carol" || items[0].Code != adminEquivalentCode {
		t.Fatalf("refused items = %+v, want carol refused", items)
	}
	if containsName(groupsOf(f, "carol"), "nd-hm-all") {
		t.Errorf("carol joined nd-hm-all")
	}
}

// A group listing that fails after the groups are written leaves the lookups as
// they were: no user is posted without the groups it has, and one that names a
// group created in this sync waits.
func TestMemberships_AFailedGroupListingStripsNobody(t *testing.T) {
	users, groups := liveAccounts()
	f := newFakeAccounts(t, users, groups)
	searches := 0
	f.onGroupSearch = func() bool { searches++; return searches > 1 }
	result := runGate(t, f,
		[]opnapi.APIUserPayload{
			{Name: "alice-admin", Password: "pw", Groups: []string{"admins", "nd-hm-all"}, SuperuserCleared: true},
			{Name: "carol", Password: "pw", Groups: []string{"monitors"}},
			{Name: "newbie", Password: "pw", Groups: []string{"ops"}},
		},
		[]opnapi.APIGroupPayload{{Name: "ops", Priv: []string{"page-status-services"}}},
		false,
	)
	if got := groupsOf(f, "alice-admin"); !reflect.DeepEqual(got, []string{"admins", "nd-hm-all"}) {
		t.Errorf("alice-admin is in %v, want admins and nd-hm-all", got)
	}
	if got := groupsOf(f, "carol"); !reflect.DeepEqual(got, []string{"monitors"}) {
		t.Errorf("carol is in %v, want monitors", got)
	}
	if !f.wrote("set", "user", "carol") || !f.wrote("set", "user", "alice-admin") {
		t.Errorf("the users whose groups were in hand must still be written: %v", f.writes)
	}
	if f.wroteAnythingFor("user", "newbie") || result.Success {
		t.Errorf("newbie names a group that has no gid in hand and must wait, failing the task: writes %v, success %v", f.writes, result.Success)
	}
	assertErrorHasMatchingResultItem(t, "unresolved group", result.Errors, result.Results)
}

// A GROUP that leaves out `members`, or gives [], declares none (#194): the
// group's members are the USERs of the sync that name it, so an account no
// snippet of the sync puts in it leaves it, and a USER that names it stays.
func TestMemberships_AGroupWithoutMembersDeclaresNone(t *testing.T) {
	for _, members := range [][]string{nil, {}} {
		users, groups := liveAccounts()
		f := newFakeAccounts(t, users, groups)
		result := runGate(t, f,
			[]opnapi.APIUserPayload{{Name: "nd-hm-plain", Password: "pw", Groups: []string{"monitors"}}},
			[]opnapi.APIGroupPayload{{Name: "monitors", Priv: []string{"page-status-services"}, Members: members}},
			false,
		)
		if !result.Success {
			t.Fatalf("errors = %v", result.Errors)
		}
		if got := groupsOf(f, "carol"); len(got) != 0 {
			t.Errorf("members %v: carol is in %v, want out of monitors: no snippet of the sync puts her there", members, got)
		}
		if got := groupsOf(f, "nd-hm-plain"); !reflect.DeepEqual(got, []string{"monitors"}) {
			t.Errorf("members %v: nd-hm-plain is in %v, want monitors: her USER names it", members, got)
		}
	}
}

// A groups or priv that is not a list of names refuses that element, not read
// as left out, which would clear it; the rest of the sync applies, and the
// element stays desired.
func TestUserSnippet_GroupsAndPrivMustBeListsOfNames(t *testing.T) {
	for _, content := range []string{
		`{"name":"carol","groups":"monitors"}`,
		`{"name":"carol","groups":["monitors",5]}`,
		`{"name":"carol","priv":"page-status-services"}`,
		`{"name":"carol","priv":{"a":1}}`,
	} {
		u, err := parseUserContent(content, nil)
		if err != nil || u.ContentError == "" {
			t.Errorf("%s: err %v, ContentError %q; want the element marked, the parse going on", content, err, u.ContentError)
		}
	}
	if u, err := parseUserContent(`{"name":"carol","groups":null,"priv":null}`, nil); err != nil || u.Groups != nil || u.Priv != nil || u.ContentError != "" {
		t.Errorf("null is left out: %+v %v", u, err)
	}

	users, groups := liveAccounts()
	users = append(users, row{"uuid": "uu-old", "uid": "2050", "name": "old-managed", "scope": "user", "priv": "", "group_memberships": "", "is_admin": "0", "descr": opnapi.AddTemplateTag("", "t1")})
	f := newFakeAccounts(t, users, groups)
	bad, _ := parseUserContent(`{"name":"old-managed","groups":"monitors"}`, nil)
	result := runGate(t, f, []opnapi.APIUserPayload{bad, {Name: "nd-hm-plain", Password: "pw"}}, nil, false)
	items := refusedItems(result)
	if len(items) != 1 || items[0].Name != "old-managed" || items[0].Code != userContentInvalidCode {
		t.Fatalf("refused items = %+v, want old-managed refused for its content", items)
	}
	assertErrorHasMatchingResultItem(t, "invalid content", result.Errors, result.Results)
	if f.wroteAnythingFor("user", "old-managed") || f.wrote("del", "user", "old-managed") {
		t.Errorf("the refused element was written or swept: %v", f.writes)
	}
	if !f.wrote("set", "user", "nd-hm-plain") {
		t.Errorf("the rest of the sync must apply: %v", f.writes)
	}
}

// A GROUP that names a member the device does not have and the sync does not
// create is refused (#194): the name used to be left out without a word. A
// member this sync creates is known.
func TestGroupSnippet_AnUnknownMemberIsRefused(t *testing.T) {
	users, groups := liveAccounts()
	groups = append(groups, row{"uuid": "gg-old", "gid": "2150", "name": "old-managed", "scope": "user", "priv": "page-status-services", "member": "2005", "description": opnapi.AddTemplateTag("", "t1")})
	f := newFakeAccounts(t, users, groups)
	result := runGate(t, f,
		[]opnapi.APIUserPayload{{Name: "newbie", Password: "pw"}},
		[]opnapi.APIGroupPayload{
			{Name: "old-managed", Priv: []string{"page-status-services"}, Members: []string{"carol", "ghost"}, SnippetName: "ops-group", SnippetIndex: 3},
			{Name: "ops", Priv: []string{"page-status-services"}, Members: []string{"newbie"}},
		},
		false,
	)
	items := refusedItems(result)
	if len(items) != 1 || items[0].Name != "old-managed" || items[0].Code != groupMemberUnknownCode || items[0].Status != "error" {
		t.Fatalf("refused items = %+v, want old-managed refused for \"ghost\"", items)
	}
	if want := `group snippet "ops-group" (index 3) for group "old-managed" names member "ghost", which the device does not have and this sync does not create; the group was not changed`; items[0].Error != want {
		t.Errorf("message = %q, want %q", items[0].Error, want)
	}
	assertErrorHasMatchingResultItem(t, "unknown member", result.Errors, result.Results)
	if f.wroteAnythingFor("group", "old-managed") || f.wrote("del", "group", "old-managed") {
		t.Errorf("the refused group was written or swept: %v", f.writes)
	}
	if !containsName(groupsOf(f, "carol"), "old-managed") {
		t.Errorf("the refused group's members changed: carol is in %v", groupsOf(f, "carol"))
	}
	if !reflect.DeepEqual(groupsOf(f, "newbie"), []string{"ops"}) {
		t.Errorf("a member this sync creates is known: newbie is in %v", groupsOf(f, "newbie"))
	}
}

// A member whose USER this sync does not apply leaves the GROUP applying
// without it, and is reported; the USER has its own refusal. That holds for a
// USER refused before the groups are planned and for one only the second gate
// pass refuses (a new account with a hash for a password).
func TestGroupSnippet_AMemberWhoseUserIsNotApplied(t *testing.T) {
	for name, tc := range map[string]struct {
		user opnapi.APIUserPayload
		code string
	}{
		"refused by clearance":         {opnapi.APIUserPayload{Name: "svc-new", Password: "pw", Priv: []string{"page-all"}}, adminEquivalentCode},
		"refused by the password rule": {opnapi.APIUserPayload{Name: "svc-new", Password: "$2y$11$./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxy"}, passwordIsHashCode},
	} {
		user := tc.user
		t.Run(name, func(t *testing.T) {
			users, groups := liveAccounts()
			f := newFakeAccounts(t, users, groups)
			result := runGate(t, f,
				[]opnapi.APIUserPayload{user},
				[]opnapi.APIGroupPayload{{Name: "ops", Priv: []string{"page-status-services"}, Members: []string{"svc-new", "carol"}}},
				false,
			)
			var member *SyncAPIItemResult
			for _, it := range result.Results {
				if it.Type == "group_member" && it.Name == "ops/svc-new" {
					it := it
					member = &it
				}
			}
			if member == nil || member.Code != groupMemberNotAppliedCode || !strings.Contains(member.Error, "the group does not get it") {
				t.Fatalf("results = %+v, want ops/svc-new reported as not applied", result.Results)
			}
			assertErrorHasMatchingResultItem(t, "member not applied", result.Errors, result.Results)
			if !f.wrote("add", "group", "ops") || !reflect.DeepEqual(groupsOf(f, "carol"), []string{"monitors", "ops"}) {
				t.Errorf("the group must apply with carol: writes %v, carol in %v", f.writes, groupsOf(f, "carol"))
			}
			if result.Success {
				t.Error("the task must fail")
			}
			refused := false
			for _, it := range result.Results {
				refused = refused || it.Name == "svc-new" && it.Code == tc.code
			}
			if !refused {
				t.Errorf("svc-new is not refused with %s: %+v", tc.code, result.Results)
			}
		})
	}
}

// A members or priv that is not a list of names refuses the GROUP, not read as
// left out, which would empty it.
func TestGroupSnippet_MembersAndPrivMustBeListsOfNames(t *testing.T) {
	for _, content := range []string{
		`{"name":"monitors","members":"carol"}`,
		`{"name":"monitors","members":[{"name":"carol"}]}`,
		`{"name":"monitors","priv":"page-status-services"}`,
	} {
		g, err := parseGroupContent(content, nil)
		if err != nil || g.ContentError == "" {
			t.Fatalf("%s: err %v, ContentError %q; want the element marked", content, err, g.ContentError)
		}
		users, groups := liveAccounts()
		f := newFakeAccounts(t, users, groups)
		result := runGate(t, f, nil, []opnapi.APIGroupPayload{g}, false)
		items := refusedItems(result)
		if len(items) != 1 || items[0].Code != groupContentInvalidCode || f.wroteAnythingFor("group", "monitors") {
			t.Errorf("%s: refused %+v, writes %v; want the group refused and untouched", content, items, f.writes)
		}
		if !reflect.DeepEqual(groupsOf(f, "carol"), []string{"monitors"}) {
			t.Errorf("%s: carol is in %v, want to stay in monitors", content, groupsOf(f, "carol"))
		}
	}
}

// "" in a name list is the empty list: the snippet parses exactly as it does
// without the key, so everything after the parse treats the two alike.
// NDDataModels accepts "" as an empty GROUP members, and older stored snippets
// may carry it in the other lists.
func TestNameLists_EmptyStringIsTheEmptyList(t *testing.T) {
	users := []struct{ with, without string }{
		{`{"name":"carol","groups":"","priv":["page-status-services"]}`, `{"name":"carol","priv":["page-status-services"]}`},
		{`{"name":"carol","groups":["monitors"],"priv":""}`, `{"name":"carol","groups":["monitors"]}`},
	}
	for _, c := range users {
		got, err := parseUserContent(c.with, []string{"t1"})
		want, werr := parseUserContent(c.without, []string{"t1"})
		if werr != nil || want.Name == "" || want.ContentError != "" {
			t.Fatalf("reference %s: %+v %v", c.without, want, werr)
		}
		if err != nil || got.ContentError != "" || !reflect.DeepEqual(got, want) {
			t.Errorf("%s: %+v (err %v); want it parsed as %s: %+v", c.with, got, err, c.without, want)
		}
	}
	groups := []struct{ with, without string }{
		{`{"name":"ops","members":"","priv":["page-status-services"]}`, `{"name":"ops","priv":["page-status-services"]}`},
		{`{"name":"ops","members":["carol"],"priv":""}`, `{"name":"ops","members":["carol"]}`},
		{`{"name":"ops","external_members":true,"members":""}`, `{"name":"ops","external_members":true}`},
	}
	for _, c := range groups {
		got, err := parseGroupContent(c.with, []string{"t1"})
		want, werr := parseGroupContent(c.without, []string{"t1"})
		if werr != nil || want.Name == "" || want.ContentError != "" {
			t.Fatalf("reference %s: %+v %v", c.without, want, werr)
		}
		if err != nil || got.ContentError != "" || !reflect.DeepEqual(got, want) {
			t.Errorf("%s: %+v (err %v); want it parsed as %s: %+v", c.with, got, err, c.without, want)
		}
	}
}

// A GROUP saved with "members": "" syncs: no GROUP_CONTENT_INVALID, and the
// group is written as one that leaves members out, external or not.
func TestGroupSnippet_EmptyStringMembersSyncs(t *testing.T) {
	for _, content := range []string{
		`{"name":"lane-ops","members":"","priv":["page-status-services"]}`,
		`{"name":"lane-ops","external_members":true,"members":""}`,
	} {
		g, err := parseGroupContent(content, []string{"t1"})
		if err != nil {
			t.Fatal(err)
		}
		users, groups := liveAccounts()
		f := newFakeAccounts(t, users, groups)
		result := runGate(t, f, nil, []opnapi.APIGroupPayload{g}, false)
		if items := refusedItems(result); len(items) != 0 || len(result.Errors) != 0 {
			t.Fatalf("%s: refused %+v, errors %v; want it applied", content, items, result.Errors)
		}
		if !f.wrote("add", "group", "lane-ops") {
			t.Fatalf("%s: the group was not created: %+v", content, result.Results)
		}
		if m, _ := f.groupRow("lane-ops")["member"].(string); m != "" {
			t.Errorf("%s: members %q; want none", content, m)
		}
	}
}

// On a group the device already holds with a member, "members": "" is what an
// absent key is: a member-managed group is left with the USERs that name it
// (none here), and an external group keeps its member and is never sent one.
func TestGroupSnippet_EmptyStringMembersOnAnExistingGroup(t *testing.T) {
	cases := []struct {
		content    string
		wantMember string
	}{
		{`{"name":"monitors","members":"","priv":["page-status-services"]}`, ""},
		{`{"name":"monitors","external_members":true,"members":"","priv":["page-status-services"]}`, "2005"},
	}
	for _, c := range cases {
		g, err := parseGroupContent(c.content, []string{"t1"})
		if err != nil {
			t.Fatal(err)
		}
		users, groups := liveAccounts()
		f := newFakeAccounts(t, users, groups)
		if m, _ := f.groupRow("monitors")["member"].(string); m != "2005" {
			t.Fatalf("fixture: monitors members %q, want carol (2005)", m)
		}
		result := runGate(t, f, nil, []opnapi.APIGroupPayload{g}, false)
		if items := refusedItems(result); len(items) != 0 || len(result.Errors) != 0 {
			t.Fatalf("%s: refused %+v, errors %v; want it applied", c.content, items, result.Errors)
		}
		if !f.wrote("set", "group", "monitors") {
			t.Fatalf("%s: monitors was not written: %+v", c.content, result.Results)
		}
		if m, _ := f.groupRow("monitors")["member"].(string); m != c.wantMember {
			t.Errorf("%s: members %q, want %q", c.content, m, c.wantMember)
		}
		body := lastBody(t, f, "set", "group", "monitors")
		if _, sent := body["member"]; sent == (c.wantMember != "") {
			t.Errorf("%s: member in the set body: %v, sent %v; want it sent only to a member-managed group", c.content, body["member"], sent)
		}
	}
}

// Before the users are written, a member whose USER is in the sync stays where
// it is: its own write decides, so a write that fails, with nothing after it to
// put things right, loses no membership.
func TestMemberships_AMemberWhoseOwnWriteFailsStays(t *testing.T) {
	users, groups := liveAccounts()
	f := newFakeAccounts(t, users, groups)
	f.failed["set user"] = true
	searches := 0
	f.onUserSearch = func() bool { searches++; return searches > 1 }
	runGate(t, f,
		[]opnapi.APIUserPayload{{Name: "carol", Password: "pw"}},
		[]opnapi.APIGroupPayload{{Name: "monitors", Priv: []string{"page-status-services"}}},
		false,
	)
	if got := groupsOf(f, "carol"); !reflect.DeepEqual(got, []string{"monitors"}) {
		t.Errorf("carol is in %v, want to stay in monitors: her own write failed", got)
	}
}

// A group whose member list phase 2 already wrote is not written again in
// phase 4: every write cuts a config revision.
func TestMemberships_AnUnchangedMemberListIsWrittenOnce(t *testing.T) {
	users, groups := liveAccounts()
	f := newFakeAccounts(t, users, groups)
	result := runGate(t, f, nil,
		[]opnapi.APIGroupPayload{{Name: "monitors", Priv: []string{"page-status-services"}, Members: []string{"carol", "nd-hm-plain"}}},
		false,
	)
	if !result.Success {
		t.Fatalf("errors = %v", result.Errors)
	}
	n := 0
	for _, w := range f.writes {
		if w == "set group monitors" {
			n++
		}
	}
	if n != 1 || !reflect.DeepEqual(groupsOf(f, "nd-hm-plain"), []string{"monitors"}) {
		t.Errorf("monitors written %d times (want 1), nd-hm-plain in %v", n, groupsOf(f, "nd-hm-plain"))
	}
}

// With no USER naming it, a GROUP that declares no members is left with none.
func TestMemberships_AGroupWithoutMembersOrUsersIsEmptied(t *testing.T) {
	users, groups := liveAccounts()
	f := newFakeAccounts(t, users, groups)
	result := runGate(t, f, nil, []opnapi.APIGroupPayload{{Name: "monitors", Priv: []string{"page-status-services"}}}, false)
	if !result.Success {
		t.Fatalf("errors = %v", result.Errors)
	}
	if body := lastBody(t, f, "set", "group", "monitors"); body["member"] != "" {
		t.Errorf("member = %v, want an explicit empty list", body["member"])
	}
	if got := groupsOf(f, "carol"); len(got) != 0 {
		t.Errorf("carol is in %v", got)
	}
}

// A USER that names a group the sync writes joins it through its own write,
// not the group's earlier one, so a user whose write fails never joins, even
// when nothing runs after it to take it out again.
func TestMemberships_AUserDeclaredNewcomerJoinsOnlyThroughItsOwnWrite(t *testing.T) {
	users, groups := liveAccounts()
	f := newFakeAccounts(t, users, groups)
	f.failed["set user"] = true
	searches := 0
	f.onUserSearch = func() bool { searches++; return searches > 1 }
	runGate(t, f,
		[]opnapi.APIUserPayload{{Name: "nd-hm-plain", Password: "pw", Groups: []string{"monitors"}}},
		[]opnapi.APIGroupPayload{{Name: "monitors", Priv: []string{"page-status-services"}, Members: []string{"carol"}}},
		false,
	)
	if got := groupsOf(f, "nd-hm-plain"); len(got) != 0 {
		t.Errorf("nd-hm-plain is in %v, want nowhere: her write failed", got)
	}
}

// An existing ordinary account a GROUP declares is a member, whatever its own
// USER element is refused for: the GROUP declares it. An administrator-
// equivalent one is another matter (TestGroupSnippet_AnUnclearedGroupDoesNotMoveAnAdministrator).
func TestMemberships_AGroupDeclaresAnExistingAccountWhoseUserIsRefused(t *testing.T) {
	users, groups := liveAccounts()
	f := newFakeAccounts(t, users, groups)
	result := runGate(t, f,
		[]opnapi.APIUserPayload{{Name: "carol", Password: "pw", Priv: []string{"page-all"}}},
		[]opnapi.APIGroupPayload{{Name: "ops", Priv: []string{"page-status-services"}, Members: []string{"carol"}}},
		false,
	)
	if items := refusedItems(result); len(items) != 1 || items[0].Name != "carol" {
		t.Fatalf("refused items = %+v, want carol", items)
	}
	if got := groupsOf(f, "carol"); !reflect.DeepEqual(got, []string{"monitors", "ops"}) {
		t.Errorf("carol is in %v, want monitors and ops", got)
	}
	for _, it := range result.Results {
		if it.Type == "group_member" {
			t.Errorf("an existing account is not reported as not applied: %+v", it)
		}
	}
}

// The operator's decision (2026-11-12, #194): an uncleared GROUP whose member
// write would add or take out an administrator-equivalent account is refused,
// like any change to such an account; a cleared one applies.
func TestGroupSnippet_AnUnclearedGroupDoesNotMoveAnAdministrator(t *testing.T) {
	withAdminsInMonitors := func() (users, groups []row) {
		users, groups = liveAccounts()
		for _, g := range groups {
			if g["name"] == "monitors" {
				g["member"] = "0,2003,2005"
			}
		}
		return users, groups
	}
	tests := []struct {
		name   string
		users  []opnapi.APIUserPayload
		group  opnapi.APIGroupPayload
		clause string
		check  func(t *testing.T, f *fakeAccounts, cleared bool)
	}{
		{
			name:   "a member it declares",
			group:  opnapi.APIGroupPayload{Name: "ops", Priv: []string{"page-status-services"}, Members: []string{"carol", "alice-admin"}},
			clause: `would add administrator-equivalent user "alice-admin" as a member`,
			check: func(t *testing.T, f *fakeAccounts, cleared bool) {
				if in := containsName(groupsOf(f, "alice-admin"), "ops"); in != cleared {
					t.Errorf("alice-admin in ops: %v, want %v", in, cleared)
				}
			},
		},
		{
			name:   "a member it leaves out",
			group:  opnapi.APIGroupPayload{Name: "monitors", Priv: []string{"page-status-services"}, Members: []string{"carol"}},
			clause: `would take administrator-equivalent user "alice-admin" out of the group`,
			check: func(t *testing.T, f *fakeAccounts, cleared bool) {
				if in := containsName(groupsOf(f, "alice-admin"), "monitors"); in == cleared {
					t.Errorf("alice-admin in monitors: %v, want %v", in, !cleared)
				}
			},
		},
		{
			name:   "root, by a list left out",
			group:  opnapi.APIGroupPayload{Name: "monitors", Priv: []string{"page-status-services"}},
			clause: `would take administrator-equivalent user "root" out of the group`,
			check: func(t *testing.T, f *fakeAccounts, cleared bool) {
				if in := containsName(groupsOf(f, "root"), "monitors"); in == cleared {
					t.Errorf("root in monitors: %v, want %v", in, !cleared)
				}
			},
		},
	}
	for _, tt := range tests {
		for _, cleared := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/cleared=%v", tt.name, cleared), func(t *testing.T) {
				users, groups := withAdminsInMonitors()
				f := newFakeAccounts(t, users, groups)
				group := tt.group
				group.SuperuserCleared = cleared
				result := runGate(t, f, tt.users, []opnapi.APIGroupPayload{group}, false)
				items := refusedItems(result)
				if !cleared {
					if len(items) != 1 || items[0].Name != group.Name || items[0].Code != adminEquivalentCode || !strings.Contains(items[0].Error, tt.clause) {
						t.Fatalf("refused items = %+v, want %q refused saying %q", items, group.Name, tt.clause)
					}
					if f.wroteAnythingFor("group", group.Name) {
						t.Errorf("the refused group was written: %v", f.writes)
					}
				} else if len(items) != 0 {
					t.Fatalf("a cleared GROUP may: %+v", items)
				}
				tt.check(t, f, cleared)
			})
		}
	}
}

// An administrator-equivalent account that is a USER of the sync and names the
// group itself is kept by its own write, so the GROUP does not move it. One whose
// USER does not name the group would leave it, and the uncleared GROUP that
// leaves it out is refused.
func TestGroupSnippet_AnAdministratorThatIsAUserOfTheSync(t *testing.T) {
	for _, tc := range []struct {
		name         string
		groups       []string
		groupRefused bool
	}{
		{"names the group", []string{"admins", "monitors", "nd-hm-all"}, false},
		{"does not name it", []string{"admins", "nd-hm-all"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			users, groups := liveAccounts()
			for _, g := range groups {
				if g["name"] == "monitors" {
					g["member"] = "2003,2005"
				}
			}
			f := newFakeAccounts(t, users, groups)
			result := runGate(t, f,
				[]opnapi.APIUserPayload{{Name: "alice-admin", Password: "pw", Groups: tc.groups, SuperuserCleared: true}},
				[]opnapi.APIGroupPayload{{Name: "monitors", Priv: []string{"page-status-services"}, Members: []string{"carol"}}},
				false,
			)
			refused := false
			for _, it := range refusedItems(result) {
				refused = refused || it.Name == "monitors"
			}
			if refused != tc.groupRefused {
				t.Fatalf("monitors refused: %v, want %v (%+v)", refused, tc.groupRefused, refusedItems(result))
			}
			if !containsName(groupsOf(f, "alice-admin"), "monitors") {
				t.Errorf("alice-admin left monitors: %v", groupsOf(f, "alice-admin"))
			}
		})
	}
}

// The check reads the group of the write's exact name, and counts an account
// an elevated GROUP of the sync declares.
func TestGroupSnippet_TheMemberCheckSeesWhatTheWriteDoes(t *testing.T) {
	t.Run("a group spelled other than the live one", func(t *testing.T) {
		users, groups := liveAccounts()
		for _, g := range groups {
			if g["name"] == "monitors" {
				g["member"] = "2003,2005"
			}
		}
		f := newFakeAccounts(t, users, groups)
		result := runGate(t, f, nil,
			[]opnapi.APIGroupPayload{{Name: "Monitors", Priv: []string{"page-status-services"}, Members: []string{"alice-admin"}}},
			false,
		)
		if items := refusedItems(result); len(items) != 1 || !strings.Contains(items[0].Error, `would add administrator-equivalent user "alice-admin"`) {
			t.Fatalf("refused items = %+v, want Monitors refused for adding alice-admin", items)
		}
	})

	t.Run("an account another GROUP of the sync makes administrator-equivalent", func(t *testing.T) {
		users, groups := liveAccounts()
		f := newFakeAccounts(t, users, groups)
		result := runGate(t, f, nil,
			[]opnapi.APIGroupPayload{
				{Name: "ops2", Priv: []string{"page-all"}, Members: []string{"carol"}, SuperuserCleared: true},
				{Name: "monitors", Priv: []string{"page-status-services"}},
			},
			false,
		)
		var monitors *SyncAPIItemResult
		for _, it := range refusedItems(result) {
			if it.Name == "monitors" {
				it := it
				monitors = &it
			}
		}
		if monitors == nil || !strings.Contains(monitors.Error, `would take administrator-equivalent user "carol" out of the group`) {
			t.Fatalf("refused items = %+v, want monitors refused for carol", refusedItems(result))
		}
	})
}

// A USER of the sync spelled other than the account is not that account: it
// does not exempt the account from the GROUP's member check, since the GROUP's
// write would still take it out.
func TestGroupSnippet_ACaseVariantUserDoesNotShieldAnAdministrator(t *testing.T) {
	users, groups := liveAccounts()
	for _, g := range groups {
		if g["name"] == "monitors" {
			g["member"] = "2003,2005"
		}
	}
	f := newFakeAccounts(t, users, groups)
	result := runGate(t, f,
		[]opnapi.APIUserPayload{{Name: "Alice-Admin", Password: "pw"}},
		[]opnapi.APIGroupPayload{{Name: "monitors", Priv: []string{"page-status-services"}, Members: []string{"carol"}}},
		false,
	)
	var groupRefused bool
	for _, it := range refusedItems(result) {
		groupRefused = groupRefused || it.Type == "group" && it.Name == "monitors" && strings.Contains(it.Error, `would take administrator-equivalent user "alice-admin" out of the group`)
	}
	if !groupRefused {
		t.Fatalf("refused items = %+v, want monitors refused for alice-admin", refusedItems(result))
	}
	if !containsName(groupsOf(f, "alice-admin"), "monitors") {
		t.Errorf("alice-admin was taken out of monitors")
	}
}

// An uncleared GROUP with an administrator-equivalent privilege is refused, so
// the accounts it declares are not about to be elevated: a sibling GROUP that
// moves them applies.
func TestGroupSnippet_ARefusedElevatedGroupElevatesNobody(t *testing.T) {
	users, groups := liveAccounts()
	f := newFakeAccounts(t, users, groups)
	result := runGate(t, f, nil,
		[]opnapi.APIGroupPayload{
			{Name: "ops2", Priv: []string{"page-all"}, Members: []string{"carol"}},
			{Name: "monitors", Priv: []string{"page-status-services"}},
		},
		false,
	)
	for _, it := range refusedItems(result) {
		if it.Name == "monitors" {
			t.Fatalf("monitors refused: %s", it.Error)
		}
	}
	if containsName(groupsOf(f, "carol"), "monitors") {
		t.Errorf("monitors did not apply: carol is still in it")
	}
}

// A declared name that is not the account's own spelling is not added by the
// write, so it is no "would add".
func TestGroupSnippet_ANameThatDoesNotResolveIsNoAdd(t *testing.T) {
	users, groups := liveAccounts()
	for _, g := range groups {
		if g["name"] == "monitors" {
			g["member"] = "2003,2005"
		}
	}
	f := newFakeAccounts(t, users, groups)
	result := runGate(t, f,
		[]opnapi.APIUserPayload{{Name: "Alice-Admin", Password: "pw"}},
		[]opnapi.APIGroupPayload{{Name: "monitors", Priv: []string{"page-status-services"}, Members: []string{"carol", "Alice-Admin"}}},
		false,
	)
	for _, it := range refusedItems(result) {
		if it.Name == "monitors" && strings.Contains(it.Error, "would add") {
			t.Errorf("message = %q, want no add: Alice-Admin is not the account's spelling", it.Error)
		}
	}
}

// A key the element does not know refuses it, naming the key (#191): a left-out
// list clears, so a misspelt "group" or "member" read as left out would strip
// the account or empty the group. The rest of the sync applies, and nothing is
// deleted.
func TestUserAndGroupSnippets_AnUnknownKeyRefusesTheElement(t *testing.T) {
	u, err := parseUserContent(`{"name":"old-managed","group":["monitors"],"Descr":"x"}`, nil)
	if err != nil || !strings.Contains(u.ContentError, `unknown key "Descr", "group"`) {
		t.Fatalf("user: err %v, ContentError %q; want both keys named", err, u.ContentError)
	}
	g, err := parseGroupContent(`{"name":"monitors","member":["carol"]}`, nil)
	if err != nil || !strings.Contains(g.ContentError, `unknown key "member"`) {
		t.Fatalf("group: err %v, ContentError %q", err, g.ContentError)
	}

	users, groups := liveAccounts()
	users = append(users, row{"uuid": "uu-old", "uid": "2050", "name": "old-managed", "scope": "user", "priv": "", "group_memberships": "", "is_admin": "0", "descr": opnapi.AddTemplateTag("", "t1")})
	f := newFakeAccounts(t, users, groups)
	result := runGate(t, f, []opnapi.APIUserPayload{u, {Name: "nd-hm-plain", Password: "pw"}}, []opnapi.APIGroupPayload{g}, false)
	codes := map[string]string{}
	for _, item := range refusedItems(result) {
		codes[item.Name] = item.Code
	}
	if codes["old-managed"] != userContentInvalidCode || codes["monitors"] != groupContentInvalidCode {
		t.Fatalf("refused %+v, want the user and the group refused for their content", codes)
	}
	assertErrorHasMatchingResultItem(t, "unknown key", result.Errors, result.Results)
	if f.wroteAnythingFor("user", "old-managed") || f.wrote("del", "user", "old-managed") || f.wroteAnythingFor("group", "monitors") {
		t.Errorf("a refused element was written or swept: %v", f.writes)
	}
	if !reflect.DeepEqual(groupsOf(f, "carol"), []string{"monitors"}) {
		t.Errorf("carol is in %v, want to stay in monitors", groupsOf(f, "carol"))
	}
	if !f.wrote("set", "user", "nd-hm-plain") {
		t.Errorf("the rest of the sync must apply: %v", f.writes)
	}
}

// Every key a PULL writes into a USER or GROUP snippet is a key the sync knows,
// so a pulled snippet syncs back: what pullUser and pullGroup return, and the
// payloads' json tags, so a field added to either struct is checked too.
func TestUserAndGroupSnippets_EveryPulledKeyIsKnown(t *testing.T) {
	users, groups := liveAccounts()
	f := newFakeAccounts(t, users, groups)
	pulledUser, _, err := pullUser(context.Background(), f.client, "carol")
	if err != nil || pulledUser == nil {
		t.Fatalf("pullUser: %v %v", pulledUser, err)
	}
	pulledGroup, _, err := pullGroup(context.Background(), f.client, "monitors")
	if err != nil || pulledGroup == nil {
		t.Fatalf("pullGroup: %v %v", pulledGroup, err)
	}
	for name, pulled := range map[string]struct {
		content map[string]interface{}
		known   map[string]bool
	}{"user": {pulledUser, userContentKeys}, "group": {pulledGroup, groupContentKeys}} {
		for key := range pulled.content {
			if !pulled.known[key] {
				t.Errorf("%s: PULL writes %q, which the sync would refuse", name, key)
			}
		}
	}

	for name, tc := range map[string]struct {
		typ   reflect.Type
		known map[string]bool
	}{
		"user":  {reflect.TypeOf(opnapi.APIUserPayload{}), userContentKeys},
		"group": {reflect.TypeOf(opnapi.APIGroupPayload{}), groupContentKeys},
	} {
		for i := 0; i < tc.typ.NumField(); i++ {
			tag := strings.Split(tc.typ.Field(i).Tag.Get("json"), ",")[0]
			if tag == "" || tag == "-" {
				continue
			}
			if !tc.known[tag] {
				t.Errorf("%s: a pulled snippet carries %q, which the sync would refuse", name, tag)
			}
		}
	}
}

// Each parser takes a content holding every key it is said to know with no
// content error: the known-key lists say what the parsers read, no more.
func TestUserAndGroupSnippets_TheKnownKeysAreAccepted(t *testing.T) {
	user := map[string]interface{}{}
	for key := range userContentKeys {
		user[key] = "x"
	}
	user["name"], user["disabled"], user["groups"], user["priv"], user["templates"] = "carol", false, []string{}, []string{}, []string{}
	raw, _ := json.Marshal(user)
	if u, err := parseUserContent(string(raw), nil); err != nil || u.ContentError != "" {
		t.Errorf("user with every known key: err %v, ContentError %q", err, u.ContentError)
	}

	group := map[string]interface{}{}
	for key := range groupContentKeys {
		group[key] = "x"
	}
	group["name"], group["external_members"], group["members"], group["priv"], group["templates"] = "monitors", false, []string{}, []string{}, []string{}
	raw, _ = json.Marshal(group)
	if g, err := parseGroupContent(string(raw), nil); err != nil || g.ContentError != "" {
		t.Errorf("group with every known key: err %v, ContentError %q", err, g.ContentError)
	}
}

// A USER whose row already holds what its write would send is not written
// again, and is reported unchanged; one that differs is written (#195).
func TestUserSnippet_WhatIsAlreadyOnTheDeviceIsNotWritten(t *testing.T) {
	users, groups := liveAccounts()
	users = append(users, row{"uuid": "uu-old", "uid": "2050", "name": "old-managed", "scope": "user", "priv": "", "group_memberships": "", "is_admin": "0", "descr": opnapi.AddTemplateTag("", "t1")})
	f := newFakeAccounts(t, users, groups)
	user := opnapi.APIUserPayload{Name: "old-managed", Scope: "user", Descr: "ops", Groups: []string{"monitors"}, Templates: []string{"t1"}}

	runGate(t, f, []opnapi.APIUserPayload{user}, nil, false)
	if !f.wrote("set", "user", "old-managed") {
		t.Fatalf("the first sync should write the user: %v", f.writes)
	}

	f.mu.Lock()
	f.writes = nil
	f.mu.Unlock()
	result := runGate(t, f, []opnapi.APIUserPayload{user}, nil, false)
	if f.wrote("set", "user", "old-managed") {
		t.Errorf("a sync with nothing new wrote the user: %v", f.writes)
	}
	unchanged := false
	for _, item := range result.Results {
		if item.Type == "user" && item.Name == "old-managed" {
			unchanged = item.Action == "unchanged" && item.Status == "success"
		}
	}
	if !unchanged {
		t.Errorf("results %+v, want old-managed unchanged", result.Results)
	}

	user.Descr = "ops, renamed"
	f.mu.Lock()
	f.writes = nil
	f.mu.Unlock()
	runGate(t, f, []opnapi.APIUserPayload{user}, nil, false)
	if !f.wrote("set", "user", "old-managed") {
		t.Errorf("a changed description was not written: %v", f.writes)
	}
}

func TestUserRowHolds(t *testing.T) {
	user := opnapi.User{Name: "carol", Disabled: "0", Scope: "user", Descr: "d", GroupMemberships: "2000,2001", Priv: "a,b"}
	row := map[string]interface{}{"name": "carol", "disabled": "0", "scope": "user", "descr": "d", "group_memberships": "2001,2000", "priv": "b,a",
		"shell": "", "authorizedkeys": "", "expires": "", "email": "", "comment": "", "language": "", "landing_page": "", "otp_seed": "x"}
	if !opnapi.UserRowHolds(user, row) {
		t.Error("the same groups and privileges in another order, and a field the write does not send, should match")
	}
	for key, value := range map[string]string{"group_memberships": "2000", "priv": "a", "descr": "other", "disabled": "1", "shell": "/bin/sh", "authorizedkeys": "a2V5", "expires": "12/31/2099", "email": "c@example.com", "comment": "c", "language": "de_DE", "landing_page": "/ui/x"} {
		other := map[string]interface{}{}
		for k, v := range row {
			other[k] = v
		}
		other[key] = value
		if opnapi.UserRowHolds(user, other) {
			t.Errorf("%s: a row that differs there matched", key)
		}
	}
	withPassword := user
	withPassword.Password = "secret"
	if opnapi.UserRowHolds(withPassword, row) {
		t.Error("a password the write sends never matches the row, which holds a hash")
	}
}

// Two USERs of the same name both write, so the last one wins on every sync:
// compared with the row listed before the writes, the second would match the
// old row and be skipped, and the device would flip between the two.
func TestUserSnippet_ASecondUserOfTheSameNameAlwaysWrites(t *testing.T) {
	users, groups := liveAccounts()
	users = append(users, row{"uuid": "uu-old", "uid": "2050", "name": "old-managed", "scope": "user", "priv": "", "group_memberships": "", "is_admin": "0", "descr": opnapi.AddTemplateTag("", "t1")})
	f := newFakeAccounts(t, users, groups)
	last := opnapi.APIUserPayload{Name: "old-managed", Scope: "user", Descr: "last", Templates: []string{"t1"}}
	runGate(t, f, []opnapi.APIUserPayload{last}, nil, false)

	first := last
	first.Descr = "first"
	f.mu.Lock()
	f.writes = nil
	f.mu.Unlock()
	runGate(t, f, []opnapi.APIUserPayload{first, last}, nil, false)
	n := 0
	for _, w := range f.writes {
		if strings.HasPrefix(w, "set user old-managed") {
			n++
		}
	}
	if n != 2 {
		t.Errorf("%d writes of old-managed, want both: %v", n, f.writes)
	}
}

func TestUserRowHolds_ListEntriesAreComparedAsWritten(t *testing.T) {
	user := opnapi.User{Name: "carol", Disabled: "0", Scope: "user", Descr: "d", GroupMemberships: "2000", Priv: "page-x"}
	row := map[string]interface{}{"name": "carol", "disabled": "0", "scope": "user", "descr": "d", "group_memberships": "2000", "priv": "page-x",
		"shell": "", "authorizedkeys": "", "expires": "", "email": "", "comment": "", "language": "", "landing_page": ""}
	if !opnapi.UserRowHolds(user, row) {
		t.Fatal("the row the write would leave did not match")
	}
	for _, priv := range []string{"page-x,", " page-x", "page-x,,page-x"} {
		other := user
		other.Priv = priv
		if opnapi.UserRowHolds(other, row) {
			t.Errorf("priv %q matched %q: a write OPNsense would refuse was skipped", priv, row["priv"])
		}
	}
	twice := user
	twice.GroupMemberships = "2000,2000"
	if !opnapi.UserRowHolds(twice, row) {
		t.Error("a gid listed twice should match the row that lists it once")
	}
}

func TestUserExpired(t *testing.T) {
	zone := time.FixedZone("device", -3*3600)
	at := func(s string) time.Time {
		tm, err := time.ParseInLocation("01/02/2006 15:04:05", s, zone)
		if err != nil {
			t.Fatal(err)
		}
		return tm
	}
	for _, c := range []struct {
		expires string
		now     string
		want    bool
	}{
		{"", "11/12/2026 12:00:00", false},
		{"11/12/2026", "11/12/2026 23:59:59", false},
		{"11/12/2026", "11/13/2026 00:00:00", false},
		{"11/12/2026", "11/13/2026 00:00:01", true},
		{"01/01/2020", "11/12/2026 12:00:00", true},
		{"12/31/2099", "11/12/2026 12:00:00", false},
		{"2099-12-31", "11/12/2026 12:00:00", true},
		{"+1 day", "11/12/2026 12:00:00", true},
	} {
		if got := opnapi.UserExpired(map[string]interface{}{"expires": c.expires}, at(c.now)); got != c.want {
			t.Errorf("expires %q at %s: %v, want %v", c.expires, c.now, got, c.want)
		}
	}
}

func clearWrites(f *fakeAccounts) {
	f.mu.Lock()
	f.writes = nil
	f.mu.Unlock()
}

// OPNsense locks an expired account's shell and removes its authorized keys
// only when the user is written, so a user past its expiry is written on every
// sync even when nothing changed: here the keys were added on the device and
// the snippet does not send them.
func TestUserSnippet_AnExpiredUserIsWrittenEverySync(t *testing.T) {
	users, groups := liveAccounts()
	users = append(users, row{"uuid": "uu-old", "uid": "2050", "name": "old-managed", "scope": "user", "priv": "", "group_memberships": "", "is_admin": "0",
		"descr": opnapi.AddTemplateTag("", "t1"), "shell": "/bin/sh", "authorizedkeys": "c3NoLWVkMjU1MTkgQUFBQUMzTnphQzFsWkRJMU5URTVBQUFBSUFCQyBvcHNAbGFwdG9w"})
	f := newFakeAccounts(t, users, groups)
	user := opnapi.APIUserPayload{Name: "old-managed", Scope: "user", Descr: "ops", Expires: "01/01/2020", Templates: []string{"t1"}}

	for sync := 1; sync <= 2; sync++ {
		clearWrites(f)
		runGate(t, f, []opnapi.APIUserPayload{user}, nil, false)
		if !f.wrote("set", "user", "old-managed") {
			t.Fatalf("sync %d: an expired user was not written: %v", sync, f.writes)
		}
	}

	user.Expires = "12/31/2099"
	runGate(t, f, []opnapi.APIUserPayload{user}, nil, false)
	clearWrites(f)
	runGate(t, f, []opnapi.APIUserPayload{user}, nil, false)
	if f.wrote("set", "user", "old-managed") {
		t.Errorf("a user whose expiry has not passed was written with nothing new: %v", f.writes)
	}
}

func TestUserSnippet_AGroupTheUserLeavesIsWritten(t *testing.T) {
	users, groups := liveAccounts()
	users = append(users, row{"uuid": "uu-old", "uid": "2050", "name": "old-managed", "scope": "user", "priv": "", "group_memberships": "", "is_admin": "0", "descr": opnapi.AddTemplateTag("", "t1")})
	f := newFakeAccounts(t, users, groups)
	f.deriveMemberships = true
	user := opnapi.APIUserPayload{Name: "old-managed", Scope: "user", Descr: "ops", Groups: []string{"monitors"}, Templates: []string{"t1"}}

	runGate(t, f, []opnapi.APIUserPayload{user}, nil, false)
	clearWrites(f)
	runGate(t, f, []opnapi.APIUserPayload{user}, nil, false)
	if f.wrote("set", "user", "old-managed") {
		t.Fatalf("a sync with nothing new wrote the user: %v", f.writes)
	}

	user.Groups = nil
	clearWrites(f)
	runGate(t, f, []opnapi.APIUserPayload{user}, nil, false)
	if !f.wrote("set", "user", "old-managed") {
		t.Fatalf("a user that left a group was not written: %v", f.writes)
	}
	if held := f.memberListsHolding("2050"); len(held) != 0 {
		t.Errorf("the user is still listed by %v", held)
	}
}

// The compare uses the user rows listed before the GROUP writes, so a user a
// GROUP adds to a group is written, and the next sync finds it unchanged.
func TestUserSnippet_AUserAGroupAddsIsWritten(t *testing.T) {
	users, groups := liveAccounts()
	users = append(users, row{"uuid": "uu-old", "uid": "2050", "name": "old-managed", "scope": "user", "priv": "", "group_memberships": "", "is_admin": "0", "descr": opnapi.AddTemplateTag("", "t1")})
	f := newFakeAccounts(t, users, groups)
	f.deriveMemberships = true
	user := opnapi.APIUserPayload{Name: "old-managed", Scope: "user", Descr: "ops", Templates: []string{"t1"}}

	runGate(t, f, []opnapi.APIUserPayload{user}, nil, false)
	clearWrites(f)
	runGate(t, f, []opnapi.APIUserPayload{user}, nil, false)
	if f.wrote("set", "user", "old-managed") {
		t.Fatalf("a sync with nothing new wrote the user: %v", f.writes)
	}

	group := []opnapi.APIGroupPayload{{Name: "monitors", Priv: []string{"page-status-services"}, Members: []string{"carol", "old-managed"}}}
	clearWrites(f)
	runGate(t, f, []opnapi.APIUserPayload{user}, group, false)
	if !f.wrote("set", "user", "old-managed") {
		t.Fatalf("a user the GROUP added was not written: %v", f.writes)
	}
	if held := f.memberListsHolding("2050"); !reflect.DeepEqual(held, []string{"monitors"}) {
		t.Errorf("member lists holding the user: %v, want [monitors]", held)
	}

	clearWrites(f)
	runGate(t, f, []opnapi.APIUserPayload{user}, group, false)
	if f.wrote("set", "user", "old-managed") {
		t.Errorf("the next sync wrote the user again: %v", f.writes)
	}
}

// A USER that leaves out shell, keys, expiry, e-mail, comment, language or
// landing page sets each to the model's default, empty (the operator's rule,
// 2026-11-12): what was set on the device by hand is cleared, and the next
// sync finds the user unchanged.
func TestUserSnippet_ALeftOutFieldTakesTheDefault(t *testing.T) {
	users, groups := liveAccounts()
	users = append(users, row{"uuid": "uu-old", "uid": "2050", "name": "old-managed", "scope": "user", "priv": "", "group_memberships": "", "is_admin": "0",
		"descr": opnapi.AddTemplateTag("ops", "t1"), "disabled": "0", "shell": "/bin/sh", "authorizedkeys": "c3NoLWVkMjU1MTkgQUFBQQ==", "expires": "12/31/2099",
		"email": "old@example.com", "comment": "set by hand", "language": "de_DE", "landing_page": "/ui/diagnostics"})
	f := newFakeAccounts(t, users, groups)
	user := opnapi.APIUserPayload{Name: "old-managed", Scope: "user", Descr: "ops", Templates: []string{"t1"}}

	runGate(t, f, []opnapi.APIUserPayload{user}, nil, false)
	bodies := f.bodies["set user old-managed"]
	if len(bodies) != 1 {
		t.Fatalf("writes %v, want one set of the user", f.writes)
	}
	sent := bodies[0]
	for _, key := range []string{"shell", "authorizedkeys", "expires", "email", "comment", "language", "landing_page"} {
		if v, ok := sent[key]; !ok || v != "" {
			t.Errorf("%s: sent %v (present %v), want the default, empty", key, v, ok)
		}
	}

	clearWrites(f)
	runGate(t, f, []opnapi.APIUserPayload{user}, nil, false)
	if f.wrote("set", "user", "old-managed") {
		t.Errorf("the next sync wrote the user again: %v", f.writes)
	}
}

// OPNsense keeps authorized keys in base64 and the grid sends them so: PULL
// decodes them, a pulled snippet syncs back to the same stored value, and a
// user whose keys are unchanged is not written again.
func TestUserSnippet_AuthorizedKeysSurviveAPullAndAreCompared(t *testing.T) {
	const keys = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIABC ops@laptop"
	stored := base64.StdEncoding.EncodeToString([]byte(keys))
	users, groups := liveAccounts()
	users = append(users, row{"uuid": "uu-old", "uid": "2050", "name": "old-managed", "scope": "user", "priv": "", "group_memberships": "", "is_admin": "0",
		"descr": opnapi.AddTemplateTag("ops", "t1"), "disabled": "0", "shell": "/bin/sh", "authorizedkeys": stored,
		"expires": "", "email": "", "comment": "", "language": "", "landing_page": ""})
	f := newFakeAccounts(t, users, groups)

	pulled, _, err := pullUser(context.Background(), f.client, "old-managed")
	if err != nil || pulled == nil {
		t.Fatalf("pullUser: %v %v", pulled, err)
	}
	raw, _ := json.Marshal(pulled)
	user, err := parseUserContent(string(raw), []string{"t1"})
	if err != nil || user.ContentError != "" {
		t.Fatalf("the pulled snippet does not parse: %v %q (%s)", err, user.ContentError, raw)
	}
	if user.AuthorizedKeys != keys {
		t.Fatalf("pulled keys %q, want the plain text %q", user.AuthorizedKeys, keys)
	}

	runGate(t, f, []opnapi.APIUserPayload{user}, nil, false)
	if f.wrote("set", "user", "old-managed") {
		t.Errorf("a pulled user synced back was written: %v", f.writes)
	}
	if got := f.userRow("old-managed")["authorizedkeys"]; got != stored {
		t.Errorf("stored keys %v, want %v", got, stored)
	}

	user.AuthorizedKeys = keys + "\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDEF second@laptop"
	clearWrites(f)
	runGate(t, f, []opnapi.APIUserPayload{user}, nil, false)
	if !f.wrote("set", "user", "old-managed") {
		t.Errorf("changed keys were not written: %v", f.writes)
	}
}

// A GROUP whose row already holds what its write would send is not written
// again (#195): its privileges and members in another order are the same.
// One that differs is written.
func TestGroupSnippet_WhatIsAlreadyOnTheDeviceIsNotWritten(t *testing.T) {
	users, groups := liveAccounts()
	f := newFakeAccounts(t, users, groups)
	group := opnapi.APIGroupPayload{Name: "monitors", Priv: []string{"page-status-services", "page-system-login-logout"}, Members: []string{"carol", "nd-hm-plain"}, Templates: []string{"t1"}}

	runGate(t, f, nil, []opnapi.APIGroupPayload{group}, false)
	if !f.wrote("set", "group", "monitors") {
		t.Fatalf("the first sync should write the group: %v", f.writes)
	}

	f.mu.Lock()
	for _, row := range f.groups {
		if row["name"] == "monitors" {
			row["priv"] = "page-system-login-logout,page-status-services"
			members := strings.Split(row["member"].(string), ",")
			sort.Sort(sort.Reverse(sort.StringSlice(members)))
			row["member"] = strings.Join(members, ",")
		}
	}
	f.mu.Unlock()
	clearWrites(f)
	result := runGate(t, f, nil, []opnapi.APIGroupPayload{group}, false)
	if f.wrote("set", "group", "monitors") {
		t.Errorf("a sync with nothing new wrote the group: %v", f.writes)
	}
	unchanged := false
	for _, item := range result.Results {
		if item.Type == "group" && item.Name == "monitors" {
			unchanged = item.Action == "unchanged" && item.Status == "success"
		}
	}
	if !unchanged {
		t.Errorf("results %+v, want monitors unchanged", result.Results)
	}

	group.Priv = []string{"page-status-services"}
	clearWrites(f)
	runGate(t, f, nil, []opnapi.APIGroupPayload{group}, false)
	if !f.wrote("set", "group", "monitors") {
		t.Errorf("a changed privilege list was not written: %v", f.writes)
	}

	group.Members = []string{"carol"}
	clearWrites(f)
	runGate(t, f, nil, []opnapi.APIGroupPayload{group}, false)
	if !f.wrote("set", "group", "monitors") {
		t.Errorf("a changed member list was not written: %v", f.writes)
	}
}

// A GROUP that names a user this sync creates is not written in phase 2 when
// its row holds the members that already exist, and phase 4 still adds the
// new user.
func TestGroupSnippet_AMemberTheSyncCreatesIsAddedLater(t *testing.T) {
	users, groups := liveAccounts()
	f := newFakeAccounts(t, users, groups)
	group := opnapi.APIGroupPayload{Name: "monitors", Priv: []string{"page-status-services"}, Members: []string{"carol"}, Templates: []string{"t1"}}
	runGate(t, f, nil, []opnapi.APIGroupPayload{group}, false)

	group.Members = []string{"carol", "newbie"}
	newbie := opnapi.APIUserPayload{Name: "newbie", Password: "pw-newbie-1", Scope: "user", Templates: []string{"t1"}}
	clearWrites(f)
	result := runGate(t, f, []opnapi.APIUserPayload{newbie}, []opnapi.APIGroupPayload{group}, false)
	if !result.Success {
		t.Fatalf("sync failed: %v", result.Errors)
	}
	uid, _ := f.userRow("newbie")["uid"].(string)
	if uid == "" || !reflect.DeepEqual(f.memberListsHolding(uid), []string{"monitors"}) {
		t.Errorf("newbie (uid %q) is listed by %v, want monitors", uid, f.memberListsHolding(uid))
	}
}

func TestGroupRowHolds(t *testing.T) {
	member := "2005,2050"
	group := opnapi.Group{Name: "monitors", Description: "d", Priv: "page-a,page-b", Member: &member, SourceNetworks: ""}
	row := map[string]interface{}{"name": "monitors", "description": "d", "priv": "page-b,page-a", "member": "2050,2005", "source_networks": "", "gid": "2120"}
	if !opnapi.GroupRowHolds(group, row) {
		t.Fatal("the same privileges and members in another order, and a field the write does not send, should match")
	}
	for key, value := range map[string]string{"name": "other", "description": "x", "priv": "page-a", "member": "2005", "source_networks": "10.0.0.0/8"} {
		other := map[string]interface{}{}
		for k, v := range row {
			other[k] = v
		}
		other[key] = value
		if opnapi.GroupRowHolds(group, other) {
			t.Errorf("%s: a row that differs there matched", key)
		}
		delete(other, key)
		if opnapi.GroupRowHolds(group, other) {
			t.Errorf("%s: a row without it matched", key)
		}
	}
	for _, entry := range []string{"2005,", " 2005,2050", "2005,,2050"} {
		bad := entry
		g := group
		g.Member = &bad
		if opnapi.GroupRowHolds(g, row) {
			t.Errorf("member %q matched %q: entries are compared as written", entry, row["member"])
		}
	}
	external := group
	external.Member = nil
	noMember := map[string]interface{}{}
	for k, v := range row {
		if k != "member" {
			noMember[k] = v
		}
	}
	noMember["member"] = "9999"
	if !opnapi.GroupRowHolds(external, noMember) {
		t.Error("a member the write does not send (an external group) is not compared")
	}
}
