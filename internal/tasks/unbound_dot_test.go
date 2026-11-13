package tasks

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

const (
	dotForwardUUID  = "221f3268-0d07-4000-8000-000000000001"
	dotOrphanUUID   = "221f3268-0d07-4000-8000-000000000002"
	dotPlainUUID    = "221f3268-0d07-4000-8000-000000000003"
	dotUntouchedRow = "0b9f0f9e-0000-4000-8000-000000000009"
)

// dotDevice is an OPNsense that keeps forwards and DNS-over-TLS forwards in one
// table, the way the vendor does: an endpoint stores and lists the type it
// names, whatever the body says.
type dotDevice struct {
	mu      sync.Mutex
	rows    map[string]map[string]interface{}
	calls   []string
	deleted []string
}

func newDotDevice(rows ...map[string]interface{}) (*dotDevice, *opnapi.Client) {
	d := &dotDevice{rows: map[string]map[string]interface{}{}}
	for _, r := range rows {
		d.rows[r["uuid"].(string)] = r
	}
	mux := http.NewServeMux()
	empty := func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{Rows: []map[string]interface{}{}})
	}
	for _, path := range []string{"searchHostOverride", "searchHostAlias", "searchAcl"} {
		mux.HandleFunc("/unbound/settings/"+path, empty)
	}
	mux.HandleFunc("/unbound/service/reconfigure", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("/unbound/service/status", func(w http.ResponseWriter, r *http.Request) {
		writeServiceStatus(w, "running")
	})
	mux.HandleFunc("/unbound/settings/", func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		defer d.mu.Unlock()
		d.calls = append(d.calls, r.URL.Path)
		rest := strings.TrimPrefix(r.URL.Path, "/unbound/settings/")
		action, uuid, _ := strings.Cut(rest, "/")
		switch action {
		case "searchForward", "searchDot":
			kind := map[string]string{"searchForward": "forward", "searchDot": "dot"}[action]
			out := []map[string]interface{}{}
			for _, row := range d.rows {
				if row["type"] == kind {
					out = append(out, row)
				}
			}
			_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{Rows: out})
		case "setForward", "setDot":
			var body struct {
				Dot map[string]interface{} `json:"dot"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			row := body.Dot
			row["uuid"] = uuid
			row["type"] = map[string]string{"setForward": "forward", "setDot": "dot"}[action]
			d.rows[uuid] = row
			_, _ = w.Write([]byte(`{"result":"saved"}`))
		case "delForward":
			delete(d.rows, uuid)
			d.deleted = append(d.deleted, uuid)
			_, _ = w.Write([]byte(`{"result":"deleted"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	server := httptest.NewServer(mux)
	return d, opnapi.NewClient(server.URL, "key", "secret", true)
}

func forwardPayload(t *testing.T, content string) opnapi.APIDomainForwardPayload {
	t.Helper()
	forward, err := parseDomainForwardContent(content, []string{"dns"})
	if err != nil {
		t.Fatal(err)
	}
	return forward
}

func itemActions(result SyncAPIResult) map[string]string {
	actions := map[string]string{}
	for _, r := range result.Results {
		if r.Type == "domain_forward" && r.Status == "success" {
			actions[r.UUID] = r.Action
		}
	}
	return actions
}

// TestSyncUnbound_DotForwards pins what SYNC does with DNS-over-TLS forwards:
// the dot endpoint for a dot forward and the forward endpoint for the rest, a
// dot row on the device found as current (updated, not created) and as an
// orphan (deleted), and a row that changes type keeping its uuid.
func TestSyncUnbound_DotForwards(t *testing.T) {
	shortServiceStartWait(t)
	device, client := newDotDevice(
		map[string]interface{}{"uuid": dotForwardUUID, "type": "dot", "domain": "secure.example.com", "server": "192.0.2.53", "description": "old [nd-template:dns]"},
		map[string]interface{}{"uuid": dotOrphanUUID, "type": "dot", "domain": "gone.example.com", "server": "192.0.2.54", "description": "[nd-template:dns]"},
		map[string]interface{}{"uuid": dotPlainUUID, "type": "forward", "domain": "corp.example.com", "server": "192.0.2.55", "description": "[nd-template:dns]"},
		map[string]interface{}{"uuid": dotUntouchedRow, "type": "dot", "domain": "mine.example.com", "server": "192.0.2.56"},
	)

	desired := []opnapi.APIDomainForwardPayload{
		forwardPayload(t, `{"uuid":"`+dotForwardUUID+`","type":"dot","domain":"secure.example.com","server":"192.0.2.53","port":"853","verify":"dns.example.com"}`),
		// the forward row becomes a dot forward, keeping its uuid
		forwardPayload(t, `{"uuid":"`+dotPlainUUID+`","type":"dot","domain":"corp.example.com","server":"192.0.2.55","port":"853"}`),
	}
	result := executeSyncUnbound(context.Background(), client, nil, desired, nil, nil)
	if !result.Success {
		t.Fatalf("sync failed: %v", result.Errors)
	}

	actions := itemActions(result)
	if actions[dotForwardUUID] != "updated" || actions[dotPlainUUID] != "updated" || actions[dotOrphanUUID] != "deleted" {
		t.Errorf("actions = %v, want the dot row and the retyped row updated and the orphan deleted", actions)
	}
	if len(device.deleted) != 1 || device.deleted[0] != dotOrphanUUID {
		t.Errorf("deleted = %v, want only the orphan dot row", device.deleted)
	}
	if _, kept := device.rows[dotUntouchedRow]; !kept {
		t.Error("an unmanaged dot row was deleted")
	}
	for _, uuid := range []string{dotForwardUUID, dotPlainUUID} {
		if device.rows[uuid]["type"] != "dot" || device.rows[uuid]["port"] != "853" {
			t.Errorf("%s = %v, want a dot row with port 853", uuid, device.rows[uuid])
		}
	}
	for _, call := range device.calls {
		if strings.HasPrefix(call, "/unbound/settings/setForward/") {
			t.Errorf("a dot forward was sent to %s", call)
		}
	}

	// and back: a forward on the same uuid lands as a forward
	back := []opnapi.APIDomainForwardPayload{
		forwardPayload(t, `{"uuid":"`+dotForwardUUID+`","type":"forward","domain":"secure.example.com","server":"192.0.2.53"}`),
	}
	result = executeSyncUnbound(context.Background(), client, nil, back, nil, nil)
	if !result.Success {
		t.Fatalf("second sync failed: %v", result.Errors)
	}
	if device.rows[dotForwardUUID]["type"] != "forward" {
		t.Errorf("type after dot -> forward = %v", device.rows[dotForwardUUID]["type"])
	}
}

// TestPullDomainForward_DotRoundTrips: PULL finds a DNS-over-TLS forward by its
// domain and returns it as dot content that SYNC writes back as dot.
func TestPullDomainForward_DotRoundTrips(t *testing.T) {
	shortServiceStartWait(t)
	device, client := newDotDevice(
		map[string]interface{}{"uuid": dotForwardUUID, "enabled": "1", "type": "dot", "domain": "secure.example.com", "server": "192.0.2.53", "port": "853", "verify": "dns.example.com", "forward_tcp_upstream": "0", "forward_first": "0", "description": "Secure [nd-template:dns]"},
	)
	content, err := pullDomainForward(context.Background(), client, "secure.example.com")
	if err != nil || content == nil {
		t.Fatalf("pull = %v, %v", content, err)
	}
	if content["type"] != "dot" || content["port"] != "853" || content["verify"] != "dns.example.com" {
		t.Fatalf("pulled content = %v", content)
	}

	raw, _ := json.Marshal(content)
	pulled, err := parseDomainForwardContent(string(raw), nil)
	if err != nil {
		t.Fatal(err)
	}
	delete(device.rows, dotForwardUUID)
	result := executeSyncUnbound(context.Background(), client, nil, []opnapi.APIDomainForwardPayload{pulled}, nil, nil)
	if !result.Success {
		t.Fatalf("sync failed: %v", result.Errors)
	}
	if got := device.rows[dotForwardUUID]; got == nil || got["type"] != "dot" || got["verify"] != "dns.example.com" {
		t.Errorf("round trip landed as %v", got)
	}
}
