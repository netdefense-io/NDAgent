package tasks

import (
	"fmt"
	"strings"
	"testing"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// Elements of one payload are judged one by one, and the device also has to
// judge them against each other: the control plane refuses some pairs at build
// time, but the agent does not depend on it, because an older or different
// control plane sends what it sends and the gate is the last line.

// TestAccountGate_SameNamePairs: an element without clearance that shares its
// name with a cleared element of the same type would edit what a Superuser
// provisioned, and whichever is written last wins. It is refused whichever
// comes first.
func TestAccountGate_SameNamePairs(t *testing.T) {
	cleared := func(u opnapi.APIUserPayload) opnapi.APIUserPayload {
		u.SuperuserCleared, u.SnippetName, u.SnippetIndex = true, "su-snip", 0
		return u
	}
	uncleared := func(u opnapi.APIUserPayload) opnapi.APIUserPayload {
		u.SnippetName, u.SnippetIndex = "rw-snip", 1
		return u
	}

	t.Run("two USER elements, either order, any spelling of the name", func(t *testing.T) {
		for _, names := range [][2]string{
			{"svc-new-admin", "svc-new-admin"},
			{"svc-new-admin", "SVC-New-Admin"},
			{"svc-new-admin", "  svc-new-admin "},
			{"SVC-NEW-ADMIN", "svc-new-admin"},
			{" Svc-New-Admin\t", "svc-new-admin"},
		} {
			suName, rwName := names[0], names[1]
			for _, rwFirst := range []bool{false, true} {
				t.Run(fmt.Sprintf("%q and %q/rwFirst=%v", suName, rwName, rwFirst), func(t *testing.T) {
					users, groups := liveAccounts()
					f := newFakeAccounts(t, users, groups)
					su := cleared(opnapi.APIUserPayload{Name: suName, Password: "SU-chosen-pw", Groups: []string{"admins"}})
					rw := uncleared(opnapi.APIUserPayload{Name: rwName, Password: "RW-chosen-pw"})
					payload := []opnapi.APIUserPayload{su, rw}
					if rwFirst {
						payload = []opnapi.APIUserPayload{rw, su}
					}

					result := runGate(t, f, payload, nil, false)

					items := refusedItems(result)
					if len(items) != 1 || items[0].Type != "user" || items[0].Name != rwName || items[0].Code != adminEquivalentCode || items[0].Status != "blocked" {
						t.Fatalf("refused items = %+v, want exactly the element without clearance", items)
					}
					if want := `shares its name with the Superuser-cleared user snippet "su-snip" (index 0)`; !strings.Contains(items[0].Error, want) {
						t.Errorf("message %q does not say %q", items[0].Error, want)
					}
					assertErrorHasMatchingResultItem(t, "same-name pair", result.Errors, result.Results)

					adds := f.bodies["add user "+suName]
					if len(adds) != 1 || adds[0]["password"] != "SU-chosen-pw" {
						t.Errorf("add bodies = %v, want only the cleared element's", adds)
					}
					for _, w := range f.writes {
						if strings.HasPrefix(w, "set user") || (strings.HasPrefix(w, "add user") && w != "add user "+suName) {
							t.Errorf("the refused element must not write besides the cleared one: %v", f.writes)
						}
					}
				})
			}
		}
	})

	t.Run("two GROUP elements, either order", func(t *testing.T) {
		for _, rwFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("rwFirst=%v", rwFirst), func(t *testing.T) {
				users, groups := liveAccounts()
				f := newFakeAccounts(t, users, groups)
				rw := opnapi.APIGroupPayload{Name: "it-admins", Members: []string{"nd-hm-plain"}, SnippetName: "rw-group", SnippetIndex: 1}
				su := opnapi.APIGroupPayload{Name: "it-admins", Priv: []string{"page-all"}, Members: []string{"not-a-local-user"}, SuperuserCleared: true, SnippetName: "su-group", SnippetIndex: 0}
				payload := []opnapi.APIGroupPayload{su, rw}
				if rwFirst {
					payload = []opnapi.APIGroupPayload{rw, su}
				}

				result := runGate(t, f, nil, payload, false)

				items := refusedItems(result)
				if len(items) != 1 || items[0].Type != "group" || items[0].Code != adminEquivalentCode {
					t.Fatalf("refused items = %+v, want exactly the element without clearance", items)
				}
				if want := `shares its name with the Superuser-cleared group snippet "su-group" (index 0)`; !strings.Contains(items[0].Error, want) {
					t.Errorf("message %q does not say %q", items[0].Error, want)
				}
				if f.administratorEquivalent("user", "nd-hm-plain") {
					t.Error("an ordinary account became administrator-equivalent through an element without clearance")
				}
				if row := f.groupRow("it-admins"); row == nil || row["priv"] != "page-all" || strings.Contains(fmt.Sprint(row["member"]), "2008") {
					t.Errorf("it-admins row = %v, want the cleared element's content alone", row)
				}
			})
		}
	})

	t.Run("a USER and a GROUP of one name are different accounts", func(t *testing.T) {
		users, groups := liveAccounts()
		f := newFakeAccounts(t, users, groups)

		result := runGate(t, f,
			[]opnapi.APIUserPayload{{Name: "ops", Password: "pw"}},
			[]opnapi.APIGroupPayload{{Name: "ops", Priv: []string{"page-system-usermanager"}, SuperuserCleared: true}},
			false,
		)
		if len(refusedItems(result)) != 0 || !f.wrote("add", "user", "ops") || !f.wrote("add", "group", "ops") {
			t.Errorf("unexpected refusal: %+v, writes %v", refusedItems(result), f.writes)
		}
	})

	t.Run("elements that are both cleared, or both not, are not this check's business", func(t *testing.T) {
		users, groups := liveAccounts()
		f := newFakeAccounts(t, users, groups)
		result := runGate(t, f, []opnapi.APIUserPayload{
			cleared(opnapi.APIUserPayload{Name: "both-su", Password: "pw-1"}),
			cleared(opnapi.APIUserPayload{Name: "both-su", Password: "pw-2"}),
			uncleared(opnapi.APIUserPayload{Name: "both-rw", Password: "pw-3"}),
			uncleared(opnapi.APIUserPayload{Name: "both-rw", Password: "pw-4"}),
		}, nil, false)
		if items := refusedItems(result); len(items) != 0 {
			t.Errorf("unexpected refusals: %+v", items)
		}
	})

	t.Run("a refused element that is already on the device is never swept", func(t *testing.T) {
		users, groups := liveAccounts()
		users = append(users, row{"uuid": "uu-twin", "uid": "2070", "name": "twin", "scope": "user", "priv": "", "group_memberships": "", "is_admin": "0", "descr": "[nd-template:ops]"})
		f := newFakeAccounts(t, users, groups)

		result := runGate(t, f, []opnapi.APIUserPayload{
			uncleared(opnapi.APIUserPayload{Name: "twin", Password: "rw-pw", Templates: []string{"ops"}}),
			cleared(opnapi.APIUserPayload{Name: "twin", Password: "su-pw", Templates: []string{"ops"}}),
		}, nil, false)

		if f.wrote("del", "user", "twin") {
			t.Errorf("a same-name pair must never be swept: %v", f.writes)
		}
		if len(refusedItems(result)) != 1 {
			t.Errorf("refused items = %+v, want one", refusedItems(result))
		}
	})

	t.Run("the refusal needs no live rows, so a discovery failure keeps it", func(t *testing.T) {
		users, groups := liveAccounts()
		f := newFakeAccounts(t, users, groups)
		f.failed["search user"] = true

		result := runGate(t, f, []opnapi.APIUserPayload{
			cleared(opnapi.APIUserPayload{Name: "svc", Password: "su-pw"}),
			uncleared(opnapi.APIUserPayload{Name: "svc", Password: "rw-pw"}),
		}, nil, false)

		if n := len(refusedItems(result)); n != 1 {
			t.Errorf("refused items = %d, want the pair's refusal found before discovery: %+v", n, result.Results)
		}
		assertErrorHasMatchingResultItem(t, "discovery failure", result.Errors, result.Results)
	})
}

// TestAccountGate_ElementsOfOneSyncThatMakeAnAccountAdministratorEquivalent: a
// Superuser-cleared GROUP with administrator-equivalent privileges makes every
// member of the group administrator-equivalent when it is applied, the members
// it declares and the ones it already has. An element without clearance that
// changes one of those accounts in the same sync is judged against what the
// account is about to be, as a USER naming the group already is.
func TestAccountGate_ElementsOfOneSyncThatMakeAnAccountAdministratorEquivalent(t *testing.T) {
	const why = `which this sync makes administrator-equivalent through group `

	t.Run("a declared member that does not exist yet", func(t *testing.T) {
		users, groups := liveAccounts()
		f := newFakeAccounts(t, users, groups)

		result := runGate(t, f,
			[]opnapi.APIUserPayload{{Name: "svc-new", Password: "RW-chosen-pw", SnippetName: "rw-user", SnippetIndex: 2}},
			[]opnapi.APIGroupPayload{{Name: "it-admins", Priv: []string{"page-system-usermanager"}, Members: []string{"svc-new"}, SuperuserCleared: true}},
			false,
		)

		items := refusedItems(result)
		if len(items) != 1 || items[0].Type != "user" || items[0].Name != "svc-new" || items[0].Code != adminEquivalentCode {
			t.Fatalf("refused items = %+v, want svc-new", items)
		}
		if want := `would change user "svc-new", ` + why + `"it-admins"`; !strings.Contains(items[0].Error, want) {
			t.Errorf("message %q does not say %q", items[0].Error, want)
		}
		if strings.Contains(items[0].Error, "RW-chosen-pw") {
			t.Error("the message echoes the password")
		}
		if f.wroteAnythingFor("user", "svc-new") {
			t.Errorf("the account must not be created with a password a Read-Write member chose: %v", f.writes)
		}
		if !f.wrote("add", "group", "it-admins") {
			t.Errorf("the cleared group must still be created: %v", f.writes)
		}
		assertErrorHasMatchingResultItem(t, "planned member", result.Errors, result.Results)
	})

	t.Run("a declared member that exists", func(t *testing.T) {
		users, groups := liveAccounts()
		f := newFakeAccounts(t, users, groups)

		result := runGate(t, f,
			[]opnapi.APIUserPayload{{Name: "Nd-HM-Plain", Password: "RW-chosen-pw"}},
			[]opnapi.APIGroupPayload{{Name: "it-admins", Priv: []string{"page-all"}, Members: []string{" nd-hm-plain "}, SuperuserCleared: true}},
			false,
		)
		if len(refusedItems(result)) != 1 || f.wroteAnythingFor("user", "Nd-HM-Plain") || f.wroteAnythingFor("user", "nd-hm-plain") {
			t.Errorf("refused %+v, writes %v", refusedItems(result), f.writes)
		}
	})

	t.Run("a member the group already has", func(t *testing.T) {
		users, groups := liveAccounts()
		f := newFakeAccounts(t, users, groups)

		// monitors holds carol. The cleared element gives the group the user
		// manager privilege and declares no members, which leaves the list as it is.
		result := runGate(t, f,
			[]opnapi.APIUserPayload{{Name: "carol", Password: "RW-chosen-pw", SnippetName: "rw-user", SnippetIndex: 2}},
			[]opnapi.APIGroupPayload{{Name: "monitors", Priv: []string{"page-system-usermanager"}, SuperuserCleared: true}},
			false,
		)

		items := refusedItems(result)
		if len(items) != 1 || items[0].Name != "carol" {
			t.Fatalf("refused items = %+v, want carol", items)
		}
		if want := `would change user "carol", ` + why + `"monitors"`; !strings.Contains(items[0].Error, want) {
			t.Errorf("message %q does not say %q", items[0].Error, want)
		}
		if f.wroteAnythingFor("user", "carol") {
			t.Errorf("carol must not be written in the sync that makes her an administrator: %v", f.writes)
		}
		if !f.wrote("set", "group", "monitors") {
			t.Errorf("the cleared group must still apply: %v", f.writes)
		}
	})

	t.Run("a member known only from the account's own group list", func(t *testing.T) {
		users, groups := liveAccounts()
		users = append(users, row{"uuid": "uu-ivy", "uid": "2080", "name": "ivy-gidlist", "scope": "user", "priv": "", "group_memberships": "2120", "is_admin": "0", "descr": ""})
		f := newFakeAccounts(t, users, groups)

		result := runGate(t, f,
			[]opnapi.APIUserPayload{{Name: "ivy-gidlist", Password: "RW-chosen-pw"}},
			[]opnapi.APIGroupPayload{{Name: "monitors", Priv: []string{"page-system-usermanager"}, SuperuserCleared: true}},
			false,
		)
		if len(refusedItems(result)) != 1 || f.wroteAnythingFor("user", "ivy-gidlist") {
			t.Errorf("refused %+v, writes %v", refusedItems(result), f.writes)
		}
	})

	t.Run("an external group's members", func(t *testing.T) {
		users, groups := liveAccounts()
		f := newFakeAccounts(t, users, groups)

		result := runGate(t, f,
			[]opnapi.APIUserPayload{{Name: "carol", Password: "RW-chosen-pw"}},
			[]opnapi.APIGroupPayload{{Name: "monitors", ExternalMembers: true, Priv: []string{"page-system-usermanager"}, SuperuserCleared: true}},
			false,
		)
		if len(refusedItems(result)) != 1 || f.wroteAnythingFor("user", "carol") {
			t.Errorf("an external group's live members are members all the same: %+v, writes %v", refusedItems(result), f.writes)
		}
	})

	t.Run("a Superuser-cleared USER is not held back", func(t *testing.T) {
		users, groups := liveAccounts()
		f := newFakeAccounts(t, users, groups)

		result := runGate(t, f,
			[]opnapi.APIUserPayload{{Name: "svc-new", Password: "su-pw", SuperuserCleared: true}},
			[]opnapi.APIGroupPayload{{Name: "it-admins", Priv: []string{"page-system-usermanager"}, Members: []string{"svc-new"}, SuperuserCleared: true}},
			false,
		)
		if len(refusedItems(result)) != 0 || !f.wrote("add", "user", "svc-new") {
			t.Errorf("unexpected refusal: %+v, writes %v", refusedItems(result), f.writes)
		}
	})

	t.Run("a group that is not elevated makes nobody elevated", func(t *testing.T) {
		users, groups := liveAccounts()
		f := newFakeAccounts(t, users, groups)

		result := runGate(t, f,
			[]opnapi.APIUserPayload{{Name: "svc-new", Password: "pw"}, {Name: "carol", Password: "pw"}},
			[]opnapi.APIGroupPayload{{Name: "monitors", Priv: []string{"page-status-services"}, Members: []string{"svc-new"}, SuperuserCleared: true}},
			false,
		)
		if len(refusedItems(result)) != 0 || !result.Success {
			t.Errorf("an ordinary group is no obstacle: %+v", result)
		}
	})

	t.Run("an unrelated account of the same sync is no obstacle", func(t *testing.T) {
		users, groups := liveAccounts()
		f := newFakeAccounts(t, users, groups)

		result := runGate(t, f,
			[]opnapi.APIUserPayload{{Name: "svc-other", Password: "pw"}},
			[]opnapi.APIGroupPayload{{Name: "it-admins", Priv: []string{"page-system-usermanager"}, Members: []string{"svc-new"}, SuperuserCleared: true}},
			false,
		)
		if len(refusedItems(result)) != 0 || !f.wrote("add", "user", "svc-other") {
			t.Errorf("unexpected refusal: %+v, writes %v", refusedItems(result), f.writes)
		}
	})

	t.Run("a group that was itself refused makes nobody elevated", func(t *testing.T) {
		users, groups := liveAccounts()
		f := newFakeAccounts(t, users, groups)

		result := runGate(t, f,
			[]opnapi.APIUserPayload{{Name: "svc-new", Password: "pw"}},
			[]opnapi.APIGroupPayload{{Name: "it-admins", Priv: []string{"page-system-usermanager"}, Members: []string{"svc-new"}}},
			false,
		)
		items := refusedItems(result)
		if len(items) != 1 || items[0].Type != "group" {
			t.Fatalf("refused items = %+v, want only the group", items)
		}
		if !f.wrote("add", "user", "svc-new") {
			t.Errorf("the group never applies, so the user does: %v", f.writes)
		}
	})
}

// TestAccountGate_SystemScopeNeedsClearance: an account with the system scope
// counts as administrator-equivalent, so an element without clearance may not
// create one. If it could, the sync that created it would succeed and every later
// one would be refused for modifying an administrator-equivalent account, with
// OPNsense refusing to delete it.
func TestAccountGate_SystemScopeNeedsClearance(t *testing.T) {
	for _, scope := range []string{"system", "System", " system "} {
		t.Run(fmt.Sprintf("%q", scope), func(t *testing.T) {
			users, groups := liveAccounts()
			f := newFakeAccounts(t, users, groups)
			user := opnapi.APIUserPayload{Name: "rw-made", Password: "pw", Scope: scope, SnippetName: "rw-snip", SnippetIndex: 2}

			result := runGate(t, f, []opnapi.APIUserPayload{user}, nil, false)
			items := refusedItems(result)
			if len(items) != 1 || items[0].Code != adminEquivalentCode || !strings.Contains(items[0].Error, `user "rw-made" would give the account the system scope`) {
				t.Fatalf("refused items = %+v, want the clearance refusal naming the system scope", items)
			}
			if f.wroteAnythingFor("user", "rw-made") {
				t.Errorf("the account must not be created: %v", f.writes)
			}

			users, groups = liveAccounts()
			f = newFakeAccounts(t, users, groups)
			user.SuperuserCleared = true
			result = runGate(t, f, []opnapi.APIUserPayload{user}, nil, false)
			if len(refusedItems(result)) != 0 || !f.wrote("add", "user", "rw-made") {
				t.Errorf("a cleared element may: %+v, writes %v", refusedItems(result), f.writes)
			}
		})
	}

	t.Run("the ordinary scope is left alone", func(t *testing.T) {
		users, groups := liveAccounts()
		f := newFakeAccounts(t, users, groups)
		result := runGate(t, f, []opnapi.APIUserPayload{{Name: "svc", Password: "pw", Scope: "user"}}, nil, false)
		if len(refusedItems(result)) != 0 || !f.wrote("add", "user", "svc") {
			t.Errorf("unexpected refusal: %+v", refusedItems(result))
		}
	})
}

// TestAccountGate_SameSyncRulesFromAParsedPayload runs a SYNC-shaped payload
// through the parsers and the executor: the clearance is the snippet's own
// content_clearance, and a refusal names the snippet by the name and the index it
// has in the payload.
func TestAccountGate_SameSyncRulesFromAParsedPayload(t *testing.T) {
	payload := map[string]interface{}{"snippets": []interface{}{
		map[string]interface{}{"config_type": "ALIAS", "snippet_name": "an-alias", "content": `{}`},
		map[string]interface{}{
			"config_type": "GROUP", "snippet_name": "it-admins-su", "content_clearance": "org:su",
			"content": `{"name":"it-admins","priv":["page-system-usermanager"],"members":["svc-new"]}`,
		},
		map[string]interface{}{"config_type": "USER", "snippet_name": "svc-new-rw", "content": `{"name":"svc-new","password":"RW-chosen-pw"}`},
		map[string]interface{}{
			"config_type": "USER", "snippet_name": "ops-su", "content_clearance": "org:su",
			"content": `{"name":"ops","password":"SU-chosen-pw"}`,
		},
		map[string]interface{}{"config_type": "USER", "snippet_name": "ops-rw", "content": `{"name":"Ops","password":"RW-chosen-pw"}`},
	}}
	users, err := parseAPIUsers(payload)
	if err != nil {
		t.Fatal(err)
	}
	groups, err := parseAPIGroups(payload)
	if err != nil {
		t.Fatal(err)
	}

	liveUsers, liveGroups := liveAccounts()
	f := newFakeAccounts(t, liveUsers, liveGroups)
	result := runGate(t, f, users, groups, false)

	var messages []string
	for _, item := range refusedItems(result) {
		messages = append(messages, item.Error)
	}
	joined := strings.Join(messages, "\n")
	for _, want := range []string{
		`user snippet "svc-new-rw" (index 2) for user "svc-new" would change user "svc-new", which this sync makes administrator-equivalent through group "it-admins"`,
		`user snippet "ops-rw" (index 4) for user "Ops" shares its name with the Superuser-cleared user snippet "ops-su" (index 3)`,
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("no refusal says %q:\n%s", want, joined)
		}
	}
	if len(messages) != 2 {
		t.Errorf("refusals = %d, want 2:\n%s", len(messages), joined)
	}
	if !f.wrote("add", "group", "it-admins") || !f.wrote("add", "user", "ops") || f.wroteAnythingFor("user", "svc-new") || f.wroteAnythingFor("user", "Ops") {
		t.Errorf("the cleared elements apply and the others do not: %v", f.writes)
	}
}
