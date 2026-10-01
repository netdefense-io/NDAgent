package tasks

import (
	"strings"
	"testing"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// A refusal names what the element would do. For most of what makes an account
// administrator-equivalent that is enough: the message names the group, or the
// catalog's privilege, and the operator can see the group and its privileges on
// the device. Two causes the operator cannot see there get one more phrase. A
// privilege ID the catalog does not know counts as administrator-equivalent, but
// OPNsense ignores one its ACL does not define, does not list it, and the group
// looks ordinary in the GUI. And a row the agent could not read at all.

func TestAccountGate_RefusalsExplainWhatTheOperatorCannotSee(t *testing.T) {
	const unknownPriv = "holds a privilege ID the catalog does not know"

	withLegacyGroup := func() (users, groups []row) {
		users, groups = liveAccounts()
		// A group left over from OPNsense 25.x: nothing but IDs its ACL no longer
		// defines, with a member who looks ordinary everywhere.
		groups = append(groups, row{"uuid": "gg-legacy", "gid": "2140", "name": "dhcp-helpdesk", "scope": "user", "priv": "page-firewall-nat-portforward,page-vpn-ipsec-editphase1", "member": "2008", "description": ""})
		return users, groups
	}

	t.Run("a member of a group whose only privileges are IDs the catalog does not know", func(t *testing.T) {
		users, groups := withLegacyGroup()
		f := newFakeAccounts(t, users, groups)

		result := runGate(t, f, []opnapi.APIUserPayload{{Name: "nd-hm-plain", Password: "pw"}}, nil, false)

		items := refusedItems(result)
		if len(items) != 1 {
			t.Fatalf("refused items = %+v, want one", items)
		}
		want := `would modify existing administrator-equivalent user "nd-hm-plain" (group "dhcp-helpdesk" ` + unknownPriv + `)`
		if !strings.Contains(items[0].Error, want) {
			t.Errorf("message %q does not say %q", items[0].Error, want)
		}
	})

	t.Run("joining such a group", func(t *testing.T) {
		users, groups := withLegacyGroup()
		f := newFakeAccounts(t, users, groups)

		result := runGate(t, f, []opnapi.APIUserPayload{{Name: "svc", Password: "pw", Groups: []string{"dhcp-helpdesk"}}}, nil, false)

		items := refusedItems(result)
		want := `would add membership in administrator-equivalent group "dhcp-helpdesk" (it ` + unknownPriv + `)`
		if len(items) != 1 || !strings.Contains(items[0].Error, want) {
			t.Errorf("refused items = %+v, want a message saying %q", items, want)
		}
	})

	t.Run("editing such a group", func(t *testing.T) {
		users, groups := withLegacyGroup()
		f := newFakeAccounts(t, users, groups)

		result := runGate(t, f, nil, []opnapi.APIGroupPayload{{Name: "dhcp-helpdesk", Priv: []string{"page-status-services"}}}, false)

		items := refusedItems(result)
		want := `would modify existing administrator-equivalent group "dhcp-helpdesk" (it ` + unknownPriv + `)`
		if len(items) != 1 || !strings.Contains(items[0].Error, want) {
			t.Errorf("refused items = %+v, want a message saying %q", items, want)
		}
	})

	t.Run("an account that holds such an ID itself", func(t *testing.T) {
		users, groups := liveAccounts()
		users = append(users, row{"uuid": "uu-legacy", "uid": "2095", "name": "legacy-holder", "scope": "user", "priv": "page-openvpn-client", "group_memberships": "", "is_admin": "0", "descr": ""})
		f := newFakeAccounts(t, users, groups)

		result := runGate(t, f, []opnapi.APIUserPayload{{Name: "legacy-holder", Password: "pw"}}, nil, false)

		items := refusedItems(result)
		want := `would modify existing administrator-equivalent user "legacy-holder" (it ` + unknownPriv + `)`
		if len(items) != 1 || !strings.Contains(items[0].Error, want) {
			t.Errorf("refused items = %+v, want a message saying %q", items, want)
		}
	})

	t.Run("a reason the message already spells out gets no note", func(t *testing.T) {
		users, groups := liveAccounts()
		groups = append(groups, row{"uuid": "gg-mixed", "gid": "2141", "name": "mixed", "scope": "user", "priv": "page-openvpn-client,page-system-usermanager", "member": "2008", "description": ""})
		f := newFakeAccounts(t, users, groups)

		result := runGate(t, f, []opnapi.APIUserPayload{
			{Name: "nd-hm-plain", Password: "pw"}, // member of a group that also holds a catalog privilege
			{Name: "alice-admin", Password: "pw"}, // admins
			{Name: "dave-direct", Password: "pw"}, // a direct catalog privilege
			{Name: "svc", Password: "pw", Groups: []string{"nd-hm-all", "mixed"}},
		}, nil, false)

		for _, item := range refusedItems(result) {
			if strings.Contains(item.Error, "(") && strings.Contains(item.Error, "catalog does not know)") {
				t.Errorf("the note is for a cause the message does not name, got %q", item.Error)
			}
		}
		if n := len(refusedItems(result)); n != 4 {
			t.Errorf("refused items = %d, want 4", n)
		}
	})

	t.Run("a row the agent could not read", func(t *testing.T) {
		users, groups := liveAccounts()
		users = append(users, row{"uuid": "uu-odd", "uid": "2096", "name": "odd-priv", "scope": "user", "priv": []interface{}{"page-all"}, "group_memberships": "", "is_admin": "0", "descr": ""})
		groups = append(groups, row{"uuid": "gg-odd", "gid": "2142", "name": "odd-group", "scope": "user", "priv": map[string]interface{}{"page-all": 1}, "member": "2008", "description": ""})
		f := newFakeAccounts(t, users, groups)

		result := runGate(t, f, []opnapi.APIUserPayload{
			{Name: "odd-priv", Password: "pw"},
			{Name: "nd-hm-plain", Password: "pw", Groups: []string{"monitors"}},
			{Name: "svc", Password: "pw", Groups: []string{"odd-group"}},
		}, nil, false)

		var said []string
		for _, item := range refusedItems(result) {
			said = append(said, item.Name+": "+item.Error)
		}
		joined := strings.Join(said, "\n")
		for _, want := range []string{
			`user "odd-priv" (it has a row the agent could not read)`,
			`user "nd-hm-plain" (group "odd-group" has a row the agent could not read)`,
			`group "odd-group" (it has a row the agent could not read)`,
		} {
			if !strings.Contains(joined, want) {
				t.Errorf("no refusal says %q:\n%s", want, joined)
			}
		}
		if f.wroteAnythingFor("user", "odd-priv") {
			t.Error("an account whose row cannot be read must not be rewritten by an element without clearance")
		}
	})
}
