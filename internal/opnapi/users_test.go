package opnapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

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

// TestConvertUserToAPI_NeverCarriesThePassword: a search row holds the stored
// hash, which is neither a password nor usable as one, and a portable snippet
// that carried it would set the hash as the password on whatever device applied
// it.
func TestConvertUserToAPI_NeverCarriesThePassword(t *testing.T) {
	const hash = "$2y$11$./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxy"
	raw := map[string]interface{}{
		"name":              "svc",
		"password":          hash,
		"scope":             "user",
		"descr":             "svc [nd-template:base]",
		"priv":              "page-status-services",
		"group_memberships": "2001",
	}
	groups := []map[string]interface{}{{"gid": "2001", "name": "monitors"}}

	payload := ConvertUserToAPI(raw, groups)

	if payload.Password != "" {
		t.Errorf("Password = %q, want empty", payload.Password)
	}
	if payload.Name != "svc" || len(payload.Groups) != 1 || payload.Groups[0] != "monitors" || len(payload.Priv) != 1 {
		t.Errorf("the rest of the row must still convert: %+v", payload)
	}
}

// TestClearUserGroupMemberships_SendsAnExplicitEmptyList: OPNsense removes the
// user from every group only when group_memberships is posted, and posted empty.
// User.GroupMemberships is omitempty, so the ordinary client call could never
// send it; the body here is checked key by key on the wire.
func TestClearUserGroupMemberships_SendsAnExplicitEmptyList(t *testing.T) {
	var path string
	var raw map[string]map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&raw)
		_ = json.NewEncoder(w).Encode(SetUserResponse{Result: "saved"})
	}))
	defer server.Close()
	client := NewClient(server.URL, "key", "secret", true)

	if err := client.ClearUserGroupMemberships(context.Background(), "uuid-1", "svc"); err != nil {
		t.Fatal(err)
	}

	if path != "/auth/user/set/uuid-1" {
		t.Errorf("path = %q, want /auth/user/set/uuid-1", path)
	}
	user, ok := raw["user"]
	if !ok || len(raw) != 1 {
		t.Fatalf("body = %v, want the single wrapper key user", raw)
	}
	if gm, present := user["group_memberships"]; !present || gm != "" {
		t.Errorf("group_memberships = %v (present %v), want an explicit empty string", gm, present)
	}
	if user["name"] != "svc" {
		t.Errorf("name = %v, want svc", user["name"])
	}
	if len(user) != 2 {
		t.Errorf("user = %v, want only name and group_memberships: no password, nothing else may change", user)
	}
}

func TestClearUserGroupMemberships_ReportsFailures(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{
		"http error": func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusInternalServerError) },
		"failed result": func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(SetUserResponse{Result: "failed"})
		},
		"validation failure": func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"result":"failed","validations":{"user.group_memberships":"Option [2099] not in list."}}`))
		},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(handler)
			defer server.Close()
			client := NewClient(server.URL, "key", "secret", true)

			if err := client.ClearUserGroupMemberships(context.Background(), "uuid-1", "svc"); err == nil {
				t.Error("want an error")
			}
		})
	}
}
