package tasks

import (
	"context"
	"strings"
	"testing"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// These tests hold the verdicts on the live rows to the device's own privilege
// catalog (auth/priv/search, which lists ACL::getPrivList()): an ID the device
// does not define grants nothing there and makes nothing administrator-
// equivalent; an ID it defines that NetDefense's catalog does not know still
// does; with no readable catalog every unknown ID does. What a snippet writes is
// judged by the catalog alone, before the device is asked.

// withDevicePrivGroups adds two live groups to liveAccounts: one that holds a
// privilege the running release no longer defines, one that holds a plugin's
// privilege that it does define and NetDefense has never reviewed.
func withDevicePrivGroups() (users, groups []row) {
	users, groups = liveAccounts()
	groups = append(groups,
		row{"uuid": "gg-legacy", "gid": "2150", "name": "legacy-ops", "scope": "user", "priv": "page-gone-in-this-release,page-status-services", "member": "", "description": ""},
		row{"uuid": "gg-plugin", "gid": "2160", "name": "plugin-ops", "scope": "user", "priv": "page-plugin-foo", "member": "", "description": ""},
	)
	return users, groups
}

func joins(group string) opnapi.APIUserPayload {
	return opnapi.APIUserPayload{Name: "svc", Password: "pw-1", Groups: []string{group}}
}

func TestDevicePrivs_AnUndefinedPrivilegeMakesNothingElevated(t *testing.T) {
	t.Run("an element that joins the group is applied", func(t *testing.T) {
		users, groups := withDevicePrivGroups()
		f := newFakeAccounts(t, users, groups)
		f.privs = devicePrivIDs("page-plugin-foo")

		result := runGate(t, f, []opnapi.APIUserPayload{joins("legacy-ops")}, nil, false)

		if items := refusedItems(result); len(items) != 0 || !result.Success {
			t.Fatalf("refused %+v, errors %v", items, result.Errors)
		}
		if !f.wroteAnythingFor("user", "svc") {
			t.Errorf("the element must be applied: %v", f.writes)
		}
	})

	t.Run("an element that rewrites the group is applied", func(t *testing.T) {
		users, groups := withDevicePrivGroups()
		f := newFakeAccounts(t, users, groups)
		f.privs = devicePrivIDs("page-plugin-foo")

		result := runGate(t, f, nil, []opnapi.APIGroupPayload{{Name: "legacy-ops", Priv: []string{"page-status-services"}}}, false)

		if items := refusedItems(result); len(items) != 0 || !result.Success {
			t.Fatalf("refused %+v, errors %v", items, result.Errors)
		}
	})

	t.Run("without a catalog the same element is refused", func(t *testing.T) {
		users, groups := withDevicePrivGroups()
		f := newFakeAccounts(t, users, groups) // /auth/priv/search answers 404

		result := runGate(t, f, []opnapi.APIUserPayload{joins("legacy-ops")}, nil, false)

		items := refusedItems(result)
		if len(items) != 1 || !strings.Contains(items[0].Error, `group "legacy-ops"`) || !strings.Contains(items[0].Error, "a privilege ID the catalog does not know") {
			t.Fatalf("refused %+v, want the group and the unknown ID named", items)
		}
	})

	t.Run("a catalog that is not the real one reads as no catalog", func(t *testing.T) {
		users, groups := withDevicePrivGroups()
		f := newFakeAccounts(t, users, groups)
		f.privs = []string{"page-all", "user-config-readonly", "page-status-services"}

		result := runGate(t, f, []opnapi.APIUserPayload{joins("legacy-ops")}, nil, false)

		if items := refusedItems(result); len(items) != 1 {
			t.Fatalf("refused %+v, want the element refused: a short catalog is not evidence that nothing is defined", items)
		}
	})
}

func TestDevicePrivs_ADefinedPluginPrivilegeStaysElevated(t *testing.T) {
	users, groups := withDevicePrivGroups()
	f := newFakeAccounts(t, users, groups)
	f.privs = devicePrivIDs("page-plugin-foo")

	result := runGate(t, f, []opnapi.APIUserPayload{joins("plugin-ops")}, nil, false)

	items := refusedItems(result)
	if len(items) != 1 || items[0].Code != adminEquivalentCode {
		t.Fatalf("refused %+v, want the element refused", items)
	}
	if !strings.Contains(items[0].Error, `group "plugin-ops" (it holds a privilege ID the catalog does not know)`) {
		t.Errorf("message %q does not say why", items[0].Error)
	}
}

// What a snippet writes is judged before the device is asked, so an ID the device
// does not define is still administrator-equivalent there.
func TestDevicePrivs_SnippetContentKeepsTheCatalogRule(t *testing.T) {
	users, groups := withDevicePrivGroups()
	f := newFakeAccounts(t, users, groups)
	f.privs = devicePrivIDs("page-plugin-foo")

	user := opnapi.APIUserPayload{Name: "svc", Password: "pw-1", Priv: []string{"page-gone-in-this-release"}}
	group := opnapi.APIGroupPayload{Name: "new-g", Priv: []string{"page-gone-in-this-release"}}
	result := runGate(t, f, []opnapi.APIUserPayload{user}, []opnapi.APIGroupPayload{group}, false)

	items := refusedItems(result)
	if len(items) != 2 {
		t.Fatalf("refused %+v, want the user and the group refused", items)
	}
	for _, item := range items {
		if !strings.Contains(item.Error, "1 privilege ID(s) the catalog does not know") {
			t.Errorf("message %q", item.Error)
		}
	}
	if f.wroteAnythingFor("user", "svc") || f.wroteAnythingFor("group", "new-g") {
		t.Errorf("a refused element must not reach OPNsense: %v", f.writes)
	}
}

// The catalog is read once for a sync, whatever it does with the live rows.
func TestDevicePrivs_TheCatalogIsReadOncePerSync(t *testing.T) {
	users, groups := withDevicePrivGroups()
	users = append(users, managedUserRow("svc-orphan", "2080", "2150"))
	groups[len(groups)-2]["member"] = "2080"
	f := newFakeAccounts(t, users, groups)
	f.privs = devicePrivIDs("page-plugin-foo")

	desired := []opnapi.APIUserPayload{{Name: "carol", Password: "pw-new"}}
	desiredGroups := []opnapi.APIGroupPayload{{Name: "monitors", Priv: []string{"page-status-services"}, Members: []string{"carol"}}}
	result := runGate(t, f, desired, desiredGroups, false)

	if !result.Success {
		t.Fatalf("unexpected failure: %v", result.Errors)
	}
	if !f.wrote("del", "user", "svc-orphan") {
		t.Fatalf("the orphan must be deleted, which is the second consumer of the catalog: %v", f.writes)
	}
	if got := f.privSearchCount(); got != 1 {
		t.Errorf("auth/priv/search was read %d times, want once", got)
	}
}

// A uid that a failed prune leaves in a group that holds only an undefined
// privilege is an ordinary leftover, not one in an administrator-equivalent group.
func TestDevicePrivs_PruneFailureInAGroupThatGrantsNothing(t *testing.T) {
	for _, tt := range []struct {
		name       string
		privs      []string
		wantFailed bool
	}{
		{"the device does not define the privilege", devicePrivIDs("page-plugin-foo"), false},
		{"the catalog cannot be read", nil, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			users, groups := withDevicePrivGroups()
			users = append(users, managedUserRow("svc-leg", "2081", "2150"))
			groups[len(groups)-2]["member"] = "2081"
			groups[len(groups)-2]["priv"] = "page-gone-in-this-release"
			f := newFakeAccounts(t, users, groups)
			f.privs = tt.privs
			f.failed["set user"] = true

			result := runGate(t, f, nil, nil, false)

			if !f.wrote("del", "user", "svc-leg") {
				t.Errorf("the delete must still go ahead: %v", f.writes)
			}
			if result.Success == tt.wantFailed {
				t.Errorf("Success = %v, want %v (errors %v)", result.Success, !tt.wantFailed, result.Errors)
			}
		})
	}
}

func TestDevicePrivs_PullVerdicts(t *testing.T) {
	for _, tt := range []struct {
		name  string
		privs []string
		group bool // the group's verdict
		user  bool // the verdict for a member
	}{
		{"the device does not define the privilege", devicePrivIDs(), false, false},
		{"the device defines it", devicePrivIDs("page-gone-in-this-release"), true, true},
		{"the catalog cannot be read", nil, true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			users, groups := pullFixtures()
			groups = append(groups, row{"uuid": "gg-stale", "gid": "2170", "name": "stale-ops", "scope": "user", "priv": "page-gone-in-this-release", "member": "2005", "description": ""})
			f := newFakeAccounts(t, users, groups)
			f.privs = tt.privs

			_, group, err := pullGroup(context.Background(), f.client, "stale-ops")
			if err != nil || group != tt.group {
				t.Errorf("group verdict = %v, %v; want %v", group, err, tt.group)
			}
			_, user, err := pullUser(context.Background(), f.client, "carol")
			if err != nil || user != tt.user {
				t.Errorf("a member's verdict = %v, %v; want %v", user, err, tt.user)
			}
		})
	}
}
