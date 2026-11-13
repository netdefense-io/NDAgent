package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// wireGuardStore keeps the servers and clients it is given and serves them back
// in its search grids, as OPNsense's UIModelGrid does (each field's stored
// value). The master switch is on.
type wireGuardStore struct {
	mu       sync.Mutex
	rows     map[string]map[string]map[string]interface{} // "server"/"client" -> uuid -> row
	next     int
	writes   []string
	setUUIDs []string
}

func newWireGuardStore(t *testing.T) (*wireGuardStore, *opnapi.Client) {
	t.Helper()
	s := &wireGuardStore{rows: map[string]map[string]map[string]interface{}{"server": {}, "client": {}}}
	mux := http.NewServeMux()
	mux.HandleFunc("/wireguard/general/get", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.WireGuardGeneralWrapper{General: opnapi.WireGuardGeneral{Enabled: "1"}})
	})
	mux.HandleFunc("/wireguard/service/reconfigure", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.APIResult{Result: "ok"})
	})
	for _, kind := range []string{"server", "client"} {
		kind := kind
		mux.HandleFunc("/wireguard/"+kind+"/search_"+kind, func(w http.ResponseWriter, r *http.Request) {
			s.mu.Lock()
			defer s.mu.Unlock()
			out := []map[string]interface{}{}
			for _, row := range s.rows[kind] {
				out = append(out, row)
			}
			_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{Rows: out})
		})
		store := func(r *http.Request, uuid string) {
			var body map[string]map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			row := map[string]interface{}{"uuid": uuid}
			for k, v := range body[kind] {
				row[k] = v
			}
			s.rows[kind][uuid] = row
		}
		mux.HandleFunc("/wireguard/"+kind+"/add_"+kind, func(w http.ResponseWriter, r *http.Request) {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.next++
			uuid := fmt.Sprintf("%s-uuid-%d", kind, s.next)
			store(r, uuid)
			s.writes = append(s.writes, "add_"+kind)
			_ = json.NewEncoder(w).Encode(opnapi.WireGuardAddResponse{Result: "saved", UUID: uuid})
		})
		mux.HandleFunc("/wireguard/"+kind+"/set_"+kind+"/", func(w http.ResponseWriter, r *http.Request) {
			s.mu.Lock()
			defer s.mu.Unlock()
			uuid := strings.TrimPrefix(r.URL.Path, "/wireguard/"+kind+"/set_"+kind+"/")
			store(r, uuid)
			s.writes = append(s.writes, "set_"+kind)
			s.setUUIDs = append(s.setUUIDs, uuid)
			_ = json.NewEncoder(w).Encode(opnapi.APIResult{Result: "saved"})
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return s, opnapi.NewClient(srv.URL, "key", "secret", true)
}

func (s *wireGuardStore) takeWrites() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.writes
	s.writes = nil
	return w
}

// A WireGuard server or client that already holds what the sync would write is
// not written again, and is reported unchanged; one that differs is written
// (#195).
func TestExecuteSyncVPN_WhatIsAlreadyOnTheDeviceIsNotWritten(t *testing.T) {
	s, client := newWireGuardStore(t)

	if result := executeSyncVPN(context.Background(), client, testVPNNetworks()); !result.Success {
		t.Fatalf("first sync failed: %v", result.Errors)
	}
	if got := s.takeWrites(); len(got) != 2 {
		t.Fatalf("first sync wrote %v, want the server and the client added", got)
	}

	result := executeSyncVPN(context.Background(), client, testVPNNetworks())
	if !result.Success {
		t.Fatalf("second sync failed: %v", result.Errors)
	}
	if got := s.takeWrites(); len(got) != 0 {
		t.Errorf("a sync with nothing new wrote %v", got)
	}
	seen := map[string]bool{}
	for _, item := range result.Results {
		if item.Type == "wg_server" || item.Type == "wg_client" {
			seen[item.Type] = true
			if item.Action != "unchanged" || item.Status != "ok" {
				t.Errorf("%s %s: %s/%s, want unchanged/ok", item.Type, item.Name, item.Action, item.Status)
			}
		}
	}
	if !seen["wg_server"] || !seen["wg_client"] {
		t.Errorf("results %+v, want a server and a client item", result.Results)
	}

	changed := testVPNNetworks()
	changed[0].Peers[0].AllowedIPs = []string{"10.221.0.3/32"}
	if result := executeSyncVPN(context.Background(), client, changed); !result.Success {
		t.Fatalf("third sync failed: %v", result.Errors)
	}
	if got := s.takeWrites(); len(got) != 1 || got[0] != "set_client" {
		t.Errorf("a changed peer wrote %v, want only the client", got)
	}

	changed[0].Interface.ListenPort = portOf(51821)
	if result := executeSyncVPN(context.Background(), client, changed); !result.Success {
		t.Fatalf("fourth sync failed: %v", result.Errors)
	}
	if got := s.takeWrites(); len(got) != 1 || got[0] != "set_server" {
		t.Errorf("a changed port wrote %v, want only the server", got)
	}
}

// A client is written when the server it names is no longer the one on the
// device: a server deleted by hand comes back with a new uuid, and the client
// row, otherwise the same, still names the old one.
func TestExecuteSyncVPN_AClientOfARecreatedServerIsWritten(t *testing.T) {
	s, client := newWireGuardStore(t)
	if result := executeSyncVPN(context.Background(), client, testVPNNetworks()); !result.Success {
		t.Fatalf("first sync failed: %v", result.Errors)
	}
	s.takeWrites()

	s.mu.Lock()
	s.rows["server"] = map[string]map[string]interface{}{}
	s.mu.Unlock()
	if result := executeSyncVPN(context.Background(), client, testVPNNetworks()); !result.Success {
		t.Fatalf("second sync failed: %v", result.Errors)
	}
	if got := s.takeWrites(); len(got) != 2 || got[0] != "add_server" || got[1] != "set_client" {
		t.Errorf("writes %v, want the server added and the client set to it", got)
	}
}

// Of two peers that get the same client name, the last one always writes, so
// the client the sync manages under that name ends with the last peer, as it
// did without the comparison. (Such peers already create two rows at first.)
func TestExecuteSyncVPN_TheLastClientOfTheSameNameAlwaysWrites(t *testing.T) {
	s, client := newWireGuardStore(t)
	networks := testVPNNetworks()
	twin := networks[0].Peers[0]
	twin.AllowedIPs = []string{"10.221.0.9/32"}
	networks[0].Peers = append(networks[0].Peers, twin)

	for round := 0; round < 3; round++ {
		s.mu.Lock()
		s.setUUIDs = nil
		s.mu.Unlock()
		if result := executeSyncVPN(context.Background(), client, networks); !result.Success {
			t.Fatalf("round %d failed: %v", round, result.Errors)
		}
		s.takeWrites()
		if round == 0 {
			continue
		}
		s.mu.Lock()
		if len(s.setUUIDs) == 0 {
			t.Errorf("round %d: the last peer was not written", round)
		} else if got := s.rows["client"][s.setUUIDs[len(s.setUUIDs)-1]]["tunneladdress"]; got != "10.221.0.9/32" {
			t.Errorf("round %d: the managed client holds %v, want the last peer's", round, got)
		}
		s.mu.Unlock()
	}
}

func TestRowHolds(t *testing.T) {
	type wire struct {
		A string `json:"a"`
		B string `json:"b,omitempty"`
	}
	row := map[string]interface{}{"uuid": "u1", "a": "x", "b": "kept", "%a": "X described"}
	if !opnapi.RowHolds(wire{A: "x"}, row) {
		t.Error("a row holding every sent key did not match")
	}
	if opnapi.RowHolds(wire{A: "x", B: "other"}, row) {
		t.Error("a row that differs in a sent key matched")
	}
	if opnapi.RowHolds(wire{A: "y"}, row) {
		t.Error("a row that differs matched")
	}
	if opnapi.RowHolds(wire{A: "x"}, map[string]interface{}{"b": "kept"}) {
		t.Error("a row without a sent key matched")
	}
	if opnapi.RowHolds(wire{A: "1"}, map[string]interface{}{"a": float64(1)}) {
		t.Error("a value that is not a string matched")
	}
	if opnapi.RowHolds(struct {
		N int `json:"n"`
	}{1}, map[string]interface{}{"n": "1"}) {
		t.Error("a wire value that is not a string matched")
	}
}

func portOf(p int) *int { return &p }

// A listen port the snippet leaves out takes the model's default, empty, which
// WireGuard reads as a port of its own choosing. It used to be sent as "0",
// which OPNsense's PortField refuses (1-65535), so the server was not written.
func TestSyncVPN_ALeftOutListenPortIsSentEmpty(t *testing.T) {
	s, client := newWireGuardStore(t)
	networks := testVPNNetworks()
	networks[0].Interface.ListenPort = nil
	if result := executeSyncVPN(context.Background(), client, networks); !result.Success {
		t.Fatalf("sync failed: %v", result.Errors)
	}
	s.takeWrites()
	s.mu.Lock()
	var ports []interface{}
	for _, row := range s.rows["server"] {
		ports = append(ports, row["port"])
	}
	s.mu.Unlock()
	if len(ports) != 1 || ports[0] != "" {
		t.Errorf("server ports %v, want one, empty", ports)
	}

	if result := executeSyncVPN(context.Background(), client, networks); !result.Success {
		t.Fatalf("second sync failed: %v", result.Errors)
	}
	if got := s.takeWrites(); len(got) != 0 {
		t.Errorf("the next sync wrote %v", got)
	}
}
