package tasks

// sync_alias_collision_test.go — Community #10: an alias whose name is
// already taken on the device must fail with an actionable message, not
// OPNsense's raw "An alias with this name already exists."

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// aliasCollisionMock serves the alias endpoints executeSyncAPI touches and
// records which aliases were actually written, so a blocked one can be
// distinguished from an applied one.
type aliasCollisionMock struct {
	// deviceAliases is what the device already holds, keyed by name.
	deviceAliases map[string]string // name -> uuid

	aliasSetCalls    []string
	aliasDeleteCalls []string
	searchFail       bool
}

func (m *aliasCollisionMock) client(t *testing.T) *opnapi.Client {
	t.Helper()

	mux := http.NewServeMux()

	mux.HandleFunc("/firewall/alias/searchItem", func(w http.ResponseWriter, r *http.Request) {
		if m.searchFail {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		phrase, _ := req["searchPhrase"].(string)

		var rows []map[string]interface{}
		for name, uuid := range m.deviceAliases {
			// SearchAliases is a phrase search; ListAllAliases sends "".
			if phrase == "" || strings.Contains(name, phrase) {
				rows = append(rows, map[string]interface{}{"uuid": uuid, "name": name})
			}
		}
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{Rows: rows, RowCount: len(rows), Total: len(rows)})
	})
	mux.HandleFunc("/firewall/alias/setItem/", func(w http.ResponseWriter, r *http.Request) {
		m.aliasSetCalls = append(m.aliasSetCalls, strings.TrimPrefix(r.URL.Path, "/firewall/alias/setItem/"))
		_ = json.NewEncoder(w).Encode(map[string]string{"result": "saved"})
	})
	mux.HandleFunc("/firewall/alias/delItem/", func(w http.ResponseWriter, r *http.Request) {
		m.aliasDeleteCalls = append(m.aliasDeleteCalls, strings.TrimPrefix(r.URL.Path, "/firewall/alias/delItem/"))
		_ = json.NewEncoder(w).Encode(opnapi.APIResult{Result: "deleted"})
	})
	mux.HandleFunc("/firewall/alias/reconfigure", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.APIResult{Result: "ok"})
	})
	mux.HandleFunc("/firewall/filter/searchRule", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{})
	})
	mux.HandleFunc("/firewall/filter/getRule", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"rule": map[string]interface{}{"interface": map[string]interface{}{
				"lan": map[string]interface{}{"value": "lan"},
			}},
		})
	})
	mux.HandleFunc("/firewall/filter/apply", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "OK\n\n"})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return opnapi.NewClient(srv.URL, "key", "secret", true)
}

const managedAliasUUID = "221f3268-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

func aliasPayload(name string) APIAliasPayload {
	return APIAliasPayload{
		UUID:    managedAliasUUID,
		Enabled: true,
		Name:    name,
		Type:    "host",
		Content: []string{"192.168.50.0/24"},
	}
}

// TestAliasCollisionWithUnmanagedObject is the reported scenario: the user
// followed the documented `snippet pull` workflow against a device, then
// synced the resulting snippet back to that same device. Pull copies an
// object as a starting point rather than adopting it, so the snippet has a
// fresh managed UUID and the device still holds the original — same name,
// different UUID.
func TestAliasCollisionWithUnmanagedObject(t *testing.T) {
	mock := &aliasCollisionMock{
		deviceAliases: map[string]string{
			// A device-native alias: no managed prefix.
			"nd_lab_admins": "d86d7ee4-170f-4037-9361-a53b7406742c",
		},
	}
	client := mock.client(t)

	result := executeSyncAPI(context.Background(), client, []APIAliasPayload{aliasPayload("nd_lab_admins")}, nil)

	if result.Success {
		t.Error("expected the sync to fail on a name collision")
	}
	for _, uuid := range mock.aliasSetCalls {
		if uuid == managedAliasUUID {
			t.Error("the colliding alias was written; OPNsense would have rejected it, so the call must be skipped")
		}
	}

	var blocked *SyncAPIItemResult
	for i := range result.Results {
		if result.Results[i].Status == "blocked" {
			blocked = &result.Results[i]
		}
	}
	if blocked == nil {
		t.Fatalf("expected a blocked alias item, got %+v", result.Results)
	}

	// The message must say what is wrong AND what to do — the whole point is
	// that "An alias with this name already exists." said neither.
	for _, want := range []string{"unmanaged alias", `"nd_lab_admins"`, "delete it on the device", "rename the snippet"} {
		if !strings.Contains(blocked.Error, want) {
			t.Errorf("blocked message %q is missing %q", blocked.Error, want)
		}
	}
	if !strings.Contains(blocked.Error, "snippet pull") {
		t.Errorf("blocked message %q should point at the pull workflow that produces this", blocked.Error)
	}

	var surfaced bool
	for _, e := range result.Errors {
		if strings.Contains(e, "nd_lab_admins") {
			surfaced = true
		}
	}
	if !surfaced {
		t.Errorf("the collision must reach the task errors list, got %v", result.Errors)
	}
}

// TestAliasCollisionWithAnotherManagedSnippet covers two snippets claiming
// the same alias name. The remedy differs — neither object is the user's to
// delete on the device — so the message must differ too.
func TestAliasCollisionWithAnotherManagedSnippet(t *testing.T) {
	mock := &aliasCollisionMock{
		deviceAliases: map[string]string{
			"nd_shared": "221f3268-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		},
	}
	client := mock.client(t)

	result := executeSyncAPI(context.Background(), client, []APIAliasPayload{aliasPayload("nd_shared")}, nil)

	if result.Success {
		t.Error("expected the sync to fail on a managed-vs-managed collision")
	}

	var blocked string
	for _, r := range result.Results {
		if r.Status == "blocked" {
			blocked = r.Error
		}
	}
	if blocked == "" {
		t.Fatalf("expected a blocked alias item, got %+v", result.Results)
	}
	if !strings.Contains(blocked, "already managed by another snippet") {
		t.Errorf("message %q should say the name is taken by another snippet", blocked)
	}
	if strings.Contains(blocked, "delete it on the device") {
		t.Errorf("message %q must not tell the user to delete a NetDefense-managed object from the device", blocked)
	}
}

// TestAliasNoCollisionOnOwnUUID pins the ordinary update: the device already
// holds THIS alias, under the same managed UUID. That is not a collision and
// must be applied exactly as before.
func TestAliasNoCollisionOnOwnUUID(t *testing.T) {
	mock := &aliasCollisionMock{
		deviceAliases: map[string]string{"nd_lab_admins": managedAliasUUID},
	}
	client := mock.client(t)

	result := executeSyncAPI(context.Background(), client, []APIAliasPayload{aliasPayload("nd_lab_admins")}, nil)

	if !result.Success {
		t.Errorf("re-applying an alias the device already holds must succeed, got %v", result.Errors)
	}
	if len(mock.aliasSetCalls) != 1 || mock.aliasSetCalls[0] != managedAliasUUID {
		t.Errorf("expected the alias to be written, got set calls %v", mock.aliasSetCalls)
	}
}

// TestAliasNoCollisionWhenNameIsFree covers the plain create path.
func TestAliasNoCollisionWhenNameIsFree(t *testing.T) {
	mock := &aliasCollisionMock{deviceAliases: map[string]string{}}
	client := mock.client(t)

	result := executeSyncAPI(context.Background(), client, []APIAliasPayload{aliasPayload("nd_brand_new")}, nil)

	if !result.Success {
		t.Errorf("expected a clean create, got %v", result.Errors)
	}
	if len(mock.aliasSetCalls) != 1 {
		t.Errorf("expected exactly one alias write, got %v", mock.aliasSetCalls)
	}
}

// TestAliasCollisionCheckFailsOpen pins that a broken lookup does not block a
// sync that would otherwise work. The check exists to improve a message; if
// it cannot run, OPNsense's own validation is still there as the backstop.
func TestAliasCollisionCheckFailsOpen(t *testing.T) {
	mock := &aliasCollisionMock{deviceAliases: map[string]string{}, searchFail: true}
	client := mock.client(t)

	// The lookup fails, so checkAliasNameCollision must return "" rather
	// than inventing a collision.
	if got := checkAliasNameCollision(context.Background(), client, aliasPayload("nd_lab_admins")); got != "" {
		t.Errorf("a failed lookup must not report a collision, got %q", got)
	}
}
