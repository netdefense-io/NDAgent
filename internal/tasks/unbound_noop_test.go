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

// unboundStore is an Unbound that keeps what is written and serves it back in
// its search grids, as OPNsense's UIModelGrid does (each field's stored value).
type unboundStore struct {
	mu     sync.Mutex
	rows   map[string]map[string]map[string]interface{} // kind -> uuid -> row
	writes []string
	client *opnapi.Client
}

func newUnboundStore(t *testing.T) *unboundStore {
	t.Helper()
	s := &unboundStore{rows: map[string]map[string]map[string]interface{}{
		"host": {}, "forward": {}, "alias": {}, "acl": {},
	}}
	search := map[string]string{"searchHostOverride": "host", "searchHostAlias": "alias", "searchAcl": "acl", "searchForward": "forward", "searchDot": "forward"}
	set := map[string]string{"setHostOverride": "host", "setHostAlias": "alias", "setAcl": "acl", "setForward": "forward", "setDot": "forward"}
	mux := http.NewServeMux()
	mux.HandleFunc("/unbound/service/reconfigure", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("/unbound/settings/", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		action, uuid, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/unbound/settings/"), "/")
		if kind, ok := search[action]; ok {
			out := []map[string]interface{}{}
			for _, row := range s.rows[kind] {
				if kind != "forward" || (action == "searchDot") == (row["type"] == "dot") {
					out = append(out, row)
				}
			}
			_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{Rows: out})
			return
		}
		if kind, ok := set[action]; ok {
			var body map[string]map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			row := map[string]interface{}{"uuid": uuid}
			if old, ok := s.rows[kind][uuid]; ok {
				for k, v := range old {
					row[k] = v
				}
			}
			for _, fields := range body {
				for k, v := range fields {
					row[k] = v
				}
			}
			s.rows[kind][uuid] = row
			s.writes = append(s.writes, action+" "+uuid)
			_, _ = w.Write([]byte(`{"result":"saved"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	s.client = opnapi.NewClient(server.URL, "key", "secret", true)
	return s
}

func (s *unboundStore) takeWrites() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.writes
	s.writes = nil
	return w
}

const (
	noopHostUUID    = "221f3268-0b00-4000-8000-000000000001"
	noopForwardUUID = "221f3268-0b00-4000-8000-000000000002"
	noopAliasUUID   = "221f3268-0b00-4000-8000-000000000003"
	noopACLUUID     = "221f3268-0b00-4000-8000-000000000004"
)

type unboundSnippets struct {
	hosts    []opnapi.APIHostOverridePayload
	forwards []opnapi.APIDomainForwardPayload
	aliases  []opnapi.APIHostAliasPayload
	acls     []opnapi.APIUnboundACLPayload
}

func noopUnboundSnippets(t *testing.T, aclNetworks string) unboundSnippets {
	t.Helper()
	host, err := parseHostOverrideContent(`{"uuid":"`+noopHostUUID+`","enabled":true,"hostname":"www","domain":"example.lan","rr":"A","server":"192.0.2.10","description":"web"}`, []string{"dns"})
	if err != nil {
		t.Fatal(err)
	}
	forward, err := parseDomainForwardContent(`{"uuid":"`+noopForwardUUID+`","enabled":true,"type":"dot","domain":"corp.example","server":"192.0.2.53","port":"853","verify":"dns.corp.example"}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	alias, err := parseHostAliasContent(`{"uuid":"`+noopAliasUUID+`","enabled":true,"parent_hostname":"www","parent_domain":"example.lan","hostname":"web","domain":"example.lan"}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	acl, err := parseUnboundACLContent(`{"uuid":"`+noopACLUUID+`","enabled":true,"name":"lan","action":"allow","networks":`+aclNetworks+`}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	return unboundSnippets{
		hosts:    []opnapi.APIHostOverridePayload{host},
		forwards: []opnapi.APIDomainForwardPayload{forward},
		aliases:  []opnapi.APIHostAliasPayload{alias},
		acls:     []opnapi.APIUnboundACLPayload{acl},
	}
}

func syncUnbound(t *testing.T, s *unboundStore, in unboundSnippets) SyncAPIResult {
	t.Helper()
	result := executeSyncUnbound(context.Background(), s.client, in.hosts, in.forwards, in.aliases, in.acls)
	if !result.Success {
		t.Fatalf("sync failed: %+v", result.Errors)
	}
	return result
}

// An Unbound row that already holds what the sync would write is not written
// again, and is reported unchanged; a row that differs is written (#195).
func TestSyncUnbound_WhatIsAlreadyOnTheDeviceIsNotWritten(t *testing.T) {
	s := newUnboundStore(t)
	snippets := noopUnboundSnippets(t, `["192.168.1.0/24","192.168.2.0/24"]`)

	syncUnbound(t, s, snippets)
	if got := s.takeWrites(); len(got) != 4 {
		t.Fatalf("first sync wrote %v, want the four rows", got)
	}

	result := syncUnbound(t, s, snippets)
	if got := s.takeWrites(); len(got) != 0 {
		t.Errorf("a sync with nothing new wrote %v", got)
	}
	for _, item := range result.Results {
		if item.Status == "success" && item.Action != "unchanged" {
			t.Errorf("%s %s: %s, want unchanged", item.Type, item.UUID, item.Action)
		}
	}
	if len(result.Results) != 4 {
		t.Errorf("results %+v, want an item per row", result.Results)
	}

	changed := noopUnboundSnippets(t, `["192.168.1.0/24"]`)
	syncUnbound(t, s, changed)
	if got := s.takeWrites(); len(got) != 1 || got[0] != "setAcl "+noopACLUUID {
		t.Errorf("a changed ACL wrote %v, want only it", got)
	}

	s.mu.Lock()
	s.rows["acl"][noopACLUUID]["description"] = "set by hand"
	s.mu.Unlock()
	syncUnbound(t, s, changed)
	if got := s.takeWrites(); len(got) != 1 || got[0] != "setAcl "+noopACLUUID {
		t.Errorf("an ACL whose description the snippet leaves empty wrote %v, want the ACL: an empty value sent is a value", got)
	}
}

// A host alias that moves to another parent is written: it compares the parent
// uuid it would send.
func TestSyncUnbound_AnAliasMovedToAnotherParentIsWritten(t *testing.T) {
	s := newUnboundStore(t)
	snippets := noopUnboundSnippets(t, `["192.168.1.0/24"]`)
	syncUnbound(t, s, snippets)
	s.takeWrites()

	s.mu.Lock()
	s.rows["alias"][noopAliasUUID]["host"] = "221f3268-0b00-4000-8000-0000000000ff"
	s.mu.Unlock()
	syncUnbound(t, s, snippets)
	if got := s.takeWrites(); len(got) != 1 || got[0] != "setHostAlias "+noopAliasUUID {
		t.Errorf("an alias under another parent wrote %v, want the alias", got)
	}
}

// Two snippets with the same uuid both write, so the last one wins on every
// sync, as it did before the comparison. Compared with the row read before
// the writes, the second would match the old row and be skipped, and the device
// would flip between the two on alternate syncs.
func TestSyncUnbound_ASecondSnippetWithTheSameUUIDAlwaysWrites(t *testing.T) {
	s := newUnboundStore(t)
	snippets := noopUnboundSnippets(t, `["192.168.1.0/24"]`)
	syncUnbound(t, s, snippets)
	s.takeWrites()

	other := snippets.hosts[0]
	other.Server = "192.0.2.20"
	twice := snippets
	twice.hosts = []opnapi.APIHostOverridePayload{other, snippets.hosts[0]}
	for round := 0; round < 3; round++ {
		syncUnbound(t, s, twice)
		writes := 0
		for _, w := range s.takeWrites() {
			if w == "setHostOverride "+noopHostUUID {
				writes++
			}
		}
		if writes != 2 {
			t.Errorf("round %d: %d writes of the shared uuid, want both", round, writes)
		}
		s.mu.Lock()
		got := s.rows["host"][noopHostUUID]["server"]
		s.mu.Unlock()
		if got != "192.0.2.10" {
			t.Errorf("round %d: the device holds %v, want the last snippet's 192.0.2.10", round, got)
		}
	}
}

// A field the snippet leaves out takes the model's default, so a device value
// there is put back to it (the operator's rule, 2026-11-12): a TTL set by hand
// is cleared, and a row that already holds the default is left alone.
func TestSyncUnbound_AFieldTheSnippetLeavesOutTakesTheDefault(t *testing.T) {
	s := newUnboundStore(t)
	snippets := noopUnboundSnippets(t, `["192.168.1.0/24"]`)
	syncUnbound(t, s, snippets)
	s.takeWrites()

	s.mu.Lock()
	s.rows["host"][noopHostUUID]["ttl"] = "300"
	s.mu.Unlock()
	syncUnbound(t, s, snippets)
	if got := s.takeWrites(); len(got) != 1 || got[0] != "setHostOverride "+noopHostUUID {
		t.Errorf("a TTL the snippet leaves out was not put back to its default: %v", got)
	}
	s.mu.Lock()
	ttl := s.rows["host"][noopHostUUID]["ttl"]
	s.mu.Unlock()
	if ttl != "" {
		t.Errorf("ttl %v, want the model's default (empty)", ttl)
	}

	syncUnbound(t, s, snippets)
	if got := s.takeWrites(); len(got) != 0 {
		t.Errorf("a row at the default was written again: %v", got)
	}

	s.mu.Lock()
	want := s.rows["host"][noopHostUUID]["server"]
	s.rows["host"][noopHostUUID]["server"] = "192.0.2.99"
	s.mu.Unlock()
	syncUnbound(t, s, snippets)
	if got := s.takeWrites(); len(got) != 1 || got[0] != "setHostOverride "+noopHostUUID {
		t.Errorf("a server the device changed was not written back: %v", got)
	}
	s.mu.Lock()
	server := s.rows["host"][noopHostUUID]["server"]
	s.mu.Unlock()
	if server != want {
		t.Errorf("server %v, want %v", server, want)
	}
}

func TestUnboundRowHoldsAHostOverride(t *testing.T) {
	wire := opnapi.HostOverride{Enabled: "1", Hostname: "www", Domain: "example.lan", RR: "A", Server: "192.0.2.10", Description: "web", AddPTR: "1"}
	row := map[string]interface{}{"uuid": noopHostUUID, "enabled": "1", "hostname": "www", "domain": "example.lan", "rr": "A", "%rr": "A (IPv4 address)", "server": "192.0.2.10", "description": "web",
		"ttl": "", "mx": "", "mxprio": "", "txtdata": "", "addptr": "1"}
	if !opnapi.RowHolds(wire, row) {
		t.Error("the row the write would leave did not match")
	}
	for _, key := range []string{"enabled", "hostname", "domain", "rr", "server", "description"} {
		other := map[string]interface{}{}
		for k, v := range row {
			other[k] = v
		}
		other[key] = "changed"
		if opnapi.RowHolds(wire, other) {
			t.Errorf("%s: a row that differs there matched", key)
		}
		delete(other, key)
		if opnapi.RowHolds(wire, other) {
			t.Errorf("%s: a row without it matched", key)
		}
	}
	numeric := map[string]interface{}{}
	for k, v := range row {
		numeric[k] = v
	}
	numeric["enabled"] = float64(1)
	if opnapi.RowHolds(wire, numeric) {
		t.Error("a value that is not a string matched")
	}
}

// A DoT forward switched back to a plain forward by a snippet without a port
// or verify name loses both, so it no longer sends plain DNS to port 853
// (#197), and the next sync finds it unchanged.
func TestSyncUnbound_AForwardSwitchedFromDoTLosesItsPort(t *testing.T) {
	s := newUnboundStore(t)
	snippets := noopUnboundSnippets(t, `["192.168.1.0/24"]`)
	syncUnbound(t, s, snippets)
	s.takeWrites()

	forward, err := parseDomainForwardContent(`{"uuid":"`+noopForwardUUID+`","enabled":true,"type":"forward","domain":"corp.example","server":"192.0.2.53"}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	snippets.forwards = []opnapi.APIDomainForwardPayload{forward}
	syncUnbound(t, s, snippets)
	s.takeWrites()
	s.mu.Lock()
	row := s.rows["forward"][noopForwardUUID]
	got := []interface{}{row["type"], row["port"], row["verify"]}
	s.mu.Unlock()
	if got[0] != "forward" || got[1] != "" || got[2] != "" {
		t.Errorf("type, port, verify %v, want forward and both empty", got)
	}

	syncUnbound(t, s, snippets)
	if writes := s.takeWrites(); len(writes) != 0 {
		t.Errorf("the next sync wrote again: %v", writes)
	}
}

// A host override that turns its PTR record off keeps it off, and is not
// written again.
func TestSyncUnbound_AnAddPTRTurnedOffStaysOff(t *testing.T) {
	s := newUnboundStore(t)
	snippets := noopUnboundSnippets(t, `["192.168.1.0/24"]`)
	host, err := parseHostOverrideContent(`{"uuid":"`+noopHostUUID+`","enabled":true,"hostname":"www","domain":"example.lan","rr":"A","server":"192.0.2.10","description":"web","addptr":false}`, []string{"dns"})
	if err != nil {
		t.Fatal(err)
	}
	snippets.hosts = []opnapi.APIHostOverridePayload{host}
	syncUnbound(t, s, snippets)
	s.takeWrites()
	s.mu.Lock()
	addptr := s.rows["host"][noopHostUUID]["addptr"]
	s.mu.Unlock()
	if addptr != "0" {
		t.Errorf("addptr %v, want 0", addptr)
	}

	syncUnbound(t, s, snippets)
	if writes := s.takeWrites(); len(writes) != 0 {
		t.Errorf("the next sync wrote again: %v", writes)
	}
}
