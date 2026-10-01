package tasks

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// A search row as OPNsense returns it carries the stored password hash
// (auth/user/get masks it, search does not).
const storedHash60 = "$2y$11$./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxy"

func pullFixtures() (users, groups []row) {
	users, groups = liveAccounts()
	for _, u := range users {
		u["password"] = storedHash60
	}
	return users, groups
}

func TestPullUser_ReportsTheLiveVerdictAndNeverThePassword(t *testing.T) {
	tests := []struct {
		user string
		want bool
		why  string
	}{
		{"alice-admin", true, "in admins and a hand-made page-all group"},
		{"bob-usermgr", true, "member of a hand-made user-manager group, is_admin 0"},
		{"gina-groupcsv", true, "elevated only because a group row lists the uid"},
		{"hank-gidonly", true, "elevated only because its own row lists the gid"},
		{"dave-direct", true, "a direct catalog privilege"},
		{"erin-isadmin", true, "flagged is_admin by OPNsense"},
		{"root", true, "uid 0"},
		{"nd-hm-plain", false, "no groups, no privileges"},
		{"carol", false, "member of an ordinary group"},
	}
	for _, tt := range tests {
		t.Run(tt.user, func(t *testing.T) {
			users, groups := pullFixtures()
			f := newFakeAccounts(t, users, groups)

			content, adminEquivalent, err := pullUser(context.Background(), f.client, tt.user)
			if err != nil || content == nil {
				t.Fatalf("pullUser = %v, %v, %v", content, adminEquivalent, err)
			}
			if adminEquivalent != tt.want {
				t.Errorf("admin_equivalent = %v, want %v (%s)", adminEquivalent, tt.want, tt.why)
			}
			if _, present := content["password"]; present {
				t.Error("a pulled USER must not carry a password, the stored value is a hash")
			}
			for k, v := range content {
				if s, ok := v.(string); ok && strings.Contains(s, storedHash60) {
					t.Errorf("the stored hash leaked through %q", k)
				}
			}
			if content["name"] != tt.user {
				t.Errorf("name = %v, want %s", content["name"], tt.user)
			}
		})
	}
}

func TestPullUser_ContentKeepsEverythingButThePassword(t *testing.T) {
	users, groups := pullFixtures()
	users[4]["shell"] = "/bin/sh"
	users[4]["authorizedkeys"] = "ssh-ed25519 AAAAtest"
	f := newFakeAccounts(t, users, groups)

	content, _, err := pullUser(context.Background(), f.client, "bob-usermgr")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(content["groups"], []string{"nd-hm-usermgr"}) {
		t.Errorf("groups = %v, want [nd-hm-usermgr]", content["groups"])
	}
	if content["shell"] != "/bin/sh" || content["authorizedkeys"] != "ssh-ed25519 AAAAtest" {
		t.Errorf("shell/authorizedkeys not carried: %v", content)
	}
	for _, key := range []string{"name", "disabled", "scope", "descr", "groups", "priv", "shell", "authorizedkeys", "expires", "email", "comment", "language", "landing_page"} {
		if _, ok := content[key]; !ok {
			t.Errorf("content lost %q", key)
		}
	}
}

func TestPullUser_NotFoundHasNoVerdict(t *testing.T) {
	users, groups := pullFixtures()
	f := newFakeAccounts(t, users, groups)

	content, adminEquivalent, err := pullConfig(context.Background(), f.client, "user", "nobody-by-that-name")
	if err != nil || content != nil || adminEquivalent != nil {
		t.Errorf("pullConfig = %v, %v, %v, want nothing", content, adminEquivalent, err)
	}
}

func TestPullUser_GroupListFailureFailsThePull(t *testing.T) {
	users, groups := pullFixtures()
	f := newFakeAccounts(t, users, groups)
	f.failed["search group"] = true

	if _, _, err := pullUser(context.Background(), f.client, "carol"); err == nil {
		t.Error("a verdict that cannot be computed must fail the pull, never be guessed")
	}
}

func TestPullGroup_ReportsTheLiveVerdict(t *testing.T) {
	tests := []struct {
		group string
		want  bool
	}{
		{"admins", true},
		{"netdefense-readonly", true},
		{"nd-hm-all", true},
		{"nd-hm-usermgr", true},
		{"monitors", false},
	}
	for _, tt := range tests {
		t.Run(tt.group, func(t *testing.T) {
			users, groups := pullFixtures()
			f := newFakeAccounts(t, users, groups)

			content, adminEquivalent, err := pullGroup(context.Background(), f.client, tt.group)
			if err != nil || content == nil {
				t.Fatalf("pullGroup = %v, %v, %v", content, adminEquivalent, err)
			}
			if adminEquivalent != tt.want {
				t.Errorf("admin_equivalent = %v, want %v", adminEquivalent, tt.want)
			}
			if _, inside := content["admin_equivalent"]; inside {
				t.Error("the verdict must not be inside the content: content becomes the stored snippet")
			}
		})
	}
}

func TestPullConfig_VerdictOnlyForUsersAndGroups(t *testing.T) {
	users, groups := pullFixtures()
	f := newFakeAccounts(t, users, groups)

	for _, configType := range []string{"user", "group"} {
		name := map[string]string{"user": "carol", "group": "monitors"}[configType]
		content, adminEquivalent, err := pullConfig(context.Background(), f.client, configType, name)
		if err != nil || content == nil || adminEquivalent == nil {
			t.Fatalf("%s: pullConfig = %v, %v, %v", configType, content, adminEquivalent, err)
		}
		if *adminEquivalent {
			t.Errorf("%s %s is ordinary", configType, name)
		}
	}

	if _, _, err := pullConfig(context.Background(), f.client, "auth_server", "x"); !errors.Is(err, errUnsupportedConfigType) {
		t.Errorf("an unsupported config type = %v, want errUnsupportedConfigType", err)
	}
}

func TestPullResultData(t *testing.T) {
	content := map[string]interface{}{"name": "carol"}
	yes, no := true, false

	if got := pullResultData(content, nil); !reflect.DeepEqual(got, map[string]interface{}{"content": content}) {
		t.Errorf("no verdict: %v, want content only (a PULL of an alias carries none)", got)
	}
	if got := pullResultData(content, &yes); got["admin_equivalent"] != true {
		t.Errorf("a true verdict = %v, want it beside the content", got)
	}
	if got := pullResultData(content, &no); got["admin_equivalent"] != false {
		t.Errorf("a false verdict must be sent too, it is what vouches for a user's groups: %v", got)
	}
}

// A group that holds only a floor-dependent privilege is administrator-equivalent
// on a device below the supported floor and ordinary at and above it.
func TestPullGroup_FloorDependentPrivFollowsTheRelease(t *testing.T) {
	for _, tt := range []struct {
		version string
		want    bool
	}{
		{"26.1.10", true},
		{"", true},
		{"26.1.11", false},
		{"26.7.4", false},
	} {
		t.Run(tt.version, func(t *testing.T) {
			useInstalledRelease(t, tt.version)
			users, groups := pullFixtures()
			groups = append(groups, row{"uuid": "gg-dns", "gid": "2140", "name": "dns-ops", "scope": "user", "priv": "page-services-dnsresolver", "member": "2005", "description": ""})
			f := newFakeAccounts(t, users, groups)

			_, adminEquivalent, err := pullGroup(context.Background(), f.client, "dns-ops")
			if err != nil {
				t.Fatal(err)
			}
			if adminEquivalent != tt.want {
				t.Errorf("admin_equivalent = %v, want %v", adminEquivalent, tt.want)
			}
			_, userVerdict, err := pullUser(context.Background(), f.client, "carol")
			if err != nil {
				t.Fatal(err)
			}
			if userVerdict != tt.want {
				t.Errorf("a member of that group: admin_equivalent = %v, want %v", userVerdict, tt.want)
			}
		})
	}
}
