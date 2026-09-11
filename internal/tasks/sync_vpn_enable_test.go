package tasks

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// testWireGuardPrivateKey is a throwaway 32-byte Curve25519 private key in
// the base64 form the sync payload carries. Its only job is to satisfy
// DeriveWireGuardPublicKey so the executor reaches the phases under test.
var testWireGuardPrivateKey = base64.StdEncoding.EncodeToString([]byte(
	"0123456789abcdef0123456789abcdef"))

// wireGuardMock records the master-switch traffic executeSyncVPN generates
// and serves the minimum set of WireGuard endpoints the executor touches.
type wireGuardMock struct {
	generalGetCalls int
	generalSetCalls []opnapi.WireGuardGeneral
	reconfigured    bool

	// currentEnabled is what general/get reports.
	currentEnabled string
}

func (m *wireGuardMock) server(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()

	mux.HandleFunc("/wireguard/general/get", func(w http.ResponseWriter, r *http.Request) {
		m.generalGetCalls++
		_ = json.NewEncoder(w).Encode(opnapi.WireGuardGeneralWrapper{
			General: opnapi.WireGuardGeneral{Enabled: m.currentEnabled},
		})
	})
	mux.HandleFunc("/wireguard/general/set", func(w http.ResponseWriter, r *http.Request) {
		var wrapper opnapi.WireGuardGeneralWrapper
		if err := json.NewDecoder(r.Body).Decode(&wrapper); err != nil {
			t.Errorf("general/set: bad request body: %v", err)
		}
		m.generalSetCalls = append(m.generalSetCalls, wrapper.General)
		m.currentEnabled = wrapper.General.Enabled
		_ = json.NewEncoder(w).Encode(opnapi.APIResult{Result: "saved"})
	})
	mux.HandleFunc("/wireguard/server/search_server", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{})
	})
	mux.HandleFunc("/wireguard/client/search_client", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{})
	})
	mux.HandleFunc("/wireguard/server/add_server", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.WireGuardAddResponse{Result: "saved", UUID: "server-uuid-1"})
	})
	mux.HandleFunc("/wireguard/client/add_client", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.WireGuardAddResponse{Result: "saved", UUID: "client-uuid-1"})
	})
	mux.HandleFunc("/wireguard/service/reconfigure", func(w http.ResponseWriter, r *http.Request) {
		m.reconfigured = true
		_ = json.NewEncoder(w).Encode(opnapi.APIResult{Result: "ok"})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func testVPNNetworks() []VPNNetwork {
	return []VPNNetwork{{
		NetworkName: "net-1",
		Interface: VPNInterface{
			PrivateKey: testWireGuardPrivateKey,
			Address:    "10.221.0.1/24",
			ListenPort: 51820,
		},
		Peers: []VPNPeer{{
			PeerName:   "peer-1",
			PublicKey:  testWireGuardPrivateKey,
			AllowedIPs: []string{"10.221.0.2/32"},
		}},
	}}
}

// TestExecuteSyncVPN_EnablesMasterSwitchWhenOff is the device-side
// reproduction of Community #9: a device whose WireGuard plugin is disabled
// receives a VPN network. Materializing the wg_server/wg_client objects and
// reconfiguring is not enough -- with the master switch off the plugin
// creates no wgN interface, so OPNsense never creates the `wireguard`
// interface group and any rule targeting it is rejected. The sync must turn
// the switch on.
func TestExecuteSyncVPN_EnablesMasterSwitchWhenOff(t *testing.T) {
	mock := &wireGuardMock{currentEnabled: "0"}
	srv := mock.server(t)
	client := opnapi.NewClient(srv.URL, "key", "secret", true)

	result := executeSyncVPN(context.Background(), client, testVPNNetworks())

	if !result.Success {
		t.Fatalf("expected VPN sync to succeed, got errors: %v", result.Errors)
	}
	if len(mock.generalSetCalls) != 1 {
		t.Fatalf("expected exactly one general/set call, got %d", len(mock.generalSetCalls))
	}
	if got := mock.generalSetCalls[0].Enabled; got != "1" {
		t.Errorf("general/set enabled = %q, want \"1\"", got)
	}
	if !mock.reconfigured {
		t.Error("expected WireGuard reconfigure after enabling the master switch")
	}
}

// TestExecuteSyncVPN_EnableIsUnconditionalAcrossSyncs pins the operator's
// model: NetDefense config is authoritative. A device hand-disabled between
// syncs is re-enabled on the next sync -- there is deliberately no one-shot
// guard, no local state tracking, and no attempt to read a local disable as
// operator intent. The supported way to leave a VPN is to detach the
// network in NetDefense, which empties the desired list instead.
func TestExecuteSyncVPN_EnableIsUnconditionalAcrossSyncs(t *testing.T) {
	mock := &wireGuardMock{currentEnabled: "0"}
	srv := mock.server(t)
	client := opnapi.NewClient(srv.URL, "key", "secret", true)

	if result := executeSyncVPN(context.Background(), client, testVPNNetworks()); !result.Success {
		t.Fatalf("first sync failed: %v", result.Errors)
	}

	// Operator flips the plugin off by hand on the device.
	mock.currentEnabled = "0"

	if result := executeSyncVPN(context.Background(), client, testVPNNetworks()); !result.Success {
		t.Fatalf("second sync failed: %v", result.Errors)
	}

	if len(mock.generalSetCalls) != 2 {
		t.Fatalf("expected the second sync to re-enable the master switch (2 set calls), got %d", len(mock.generalSetCalls))
	}
	if got := mock.currentEnabled; got != "1" {
		t.Errorf("master switch after second sync = %q, want \"1\"", got)
	}
}

// TestExecuteSyncVPN_SkipsRedundantEnableWrite covers the write-elision:
// an already-enabled device must not have its config.xml rewritten (and a
// config revision cut) on every sync. This is purely about avoiding a
// no-op write -- see TestExecuteSyncVPN_EnableIsUnconditionalAcrossSyncs
// for the behaviour when the switch is actually off.
func TestExecuteSyncVPN_SkipsRedundantEnableWrite(t *testing.T) {
	mock := &wireGuardMock{currentEnabled: "1"}
	srv := mock.server(t)
	client := opnapi.NewClient(srv.URL, "key", "secret", true)

	result := executeSyncVPN(context.Background(), client, testVPNNetworks())

	if !result.Success {
		t.Fatalf("expected VPN sync to succeed, got errors: %v", result.Errors)
	}
	if mock.generalGetCalls != 1 {
		t.Errorf("general/get calls = %d, want 1", mock.generalGetCalls)
	}
	if len(mock.generalSetCalls) != 0 {
		t.Errorf("expected no general/set call when already enabled, got %v", mock.generalSetCalls)
	}
}

// TestExecuteSyncVPN_NoNetworksLeavesMasterSwitchAlone pins that a sync
// carrying zero VPN networks (the device was detached from every network)
// neither enables nor disables the plugin. The orphan-delete pass still
// runs; the master switch is simply not this sync's business -- a device
// may carry a hand-made WireGuard tunnel NetDefense does not manage.
func TestExecuteSyncVPN_NoNetworksLeavesMasterSwitchAlone(t *testing.T) {
	mock := &wireGuardMock{currentEnabled: "0"}
	srv := mock.server(t)
	client := opnapi.NewClient(srv.URL, "key", "secret", true)

	result := executeSyncVPN(context.Background(), client, nil)

	if !result.Success {
		t.Fatalf("expected VPN sync to succeed, got errors: %v", result.Errors)
	}
	if mock.generalGetCalls != 0 || len(mock.generalSetCalls) != 0 {
		t.Errorf("expected the master switch to be untouched with zero desired networks, got %d get(s) / %d set(s)",
			mock.generalGetCalls, len(mock.generalSetCalls))
	}
}

// interfaceListServer serves the `GET /firewall/filter/getRule` template
// GetInterfaceList reads, with the given interface options.
func interfaceListServer(t *testing.T, interfaces ...string) *opnapi.Client {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/firewall/filter/getRule", func(w http.ResponseWriter, r *http.Request) {
		options := map[string]map[string]interface{}{}
		for _, iface := range interfaces {
			options[iface] = map[string]interface{}{"value": iface, "selected": 0}
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"rule": map[string]interface{}{"interface": options},
		})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return opnapi.NewClient(srv.URL, "key", "secret", true)
}

// TestCheckRuleInterfaces_MissingWireGuardGroup covers the reporter's third
// suggestion: a rule targeting the `wireguard` interface group on a device
// that has no active WireGuard network must produce a message naming the
// rule and the missing group, not OPNsense's bare
// `Option [wireguard] not in list.`
func TestCheckRuleInterfaces_MissingWireGuardGroup(t *testing.T) {
	client := interfaceListServer(t, "lan", "wan", "opt1")

	rules := []APIRulePayload{{
		UUID:        "221f3268-rule-1",
		Description: "Allow VPN to LAN",
		Interface:   "wireguard",
	}}

	errs := checkRuleInterfaces(context.Background(), client, rules)

	if len(errs) != 1 {
		t.Fatalf("expected 1 validation error, got %d: %+v", len(errs), errs)
	}
	got := errs[0]
	if got.ErrorCode != "INTERFACE_NOT_FOUND" {
		t.Errorf("ErrorCode = %q, want INTERFACE_NOT_FOUND", got.ErrorCode)
	}
	if got.UUID != "221f3268-rule-1" {
		t.Errorf("UUID = %q, want the offending rule's UUID", got.UUID)
	}
	for _, want := range []string{"Allow VPN to LAN", "wireguard", "lan, opt1, wan", "attach the VPN network"} {
		if !strings.Contains(got.Message, want) {
			t.Errorf("message %q missing %q", got.Message, want)
		}
	}
}

// TestCheckRuleInterfaces_AcceptsValidAndFloatingRules pins that the
// pre-flight does not invent failures: present interfaces, an empty
// interface (floating rule), and OPNsense's comma-separated multi-interface
// form must all pass.
func TestCheckRuleInterfaces_AcceptsValidAndFloatingRules(t *testing.T) {
	client := interfaceListServer(t, "lan", "wan", "wireguard")

	rules := []APIRulePayload{
		{UUID: "221f3268-a", Description: "on lan", Interface: "lan"},
		{UUID: "221f3268-b", Description: "floating", Interface: ""},
		{UUID: "221f3268-c", Description: "multi", Interface: "lan, wan"},
		{UUID: "221f3268-d", Description: "vpn", Interface: "wireguard"},
	}

	if errs := checkRuleInterfaces(context.Background(), client, rules); len(errs) != 0 {
		t.Errorf("expected no validation errors, got %+v", errs)
	}
}

// TestCheckRuleInterfaces_UnreadableListDoesNotBlockSync pins that the
// pre-flight degrades to a no-op rather than failing the sync when the
// interface list cannot be read. It is a diagnostic that improves an error
// message; losing it must never block a sync that would otherwise succeed.
func TestCheckRuleInterfaces_UnreadableListDoesNotBlockSync(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/firewall/filter/getRule", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	client := opnapi.NewClient(srv.URL, "key", "secret", true)

	rules := []APIRulePayload{{UUID: "221f3268-a", Description: "vpn", Interface: "wireguard"}}

	if errs := checkRuleInterfaces(context.Background(), client, rules); len(errs) != 0 {
		t.Errorf("expected the pre-flight to no-op on an unreadable interface list, got %+v", errs)
	}
}

// TestCheckRuleInterfaces_EmptyOptionListDoesNotBlockSync guards the same
// fail-open property for a well-formed response with no options: treating
// "nothing is valid" literally would block every rule on the device.
func TestCheckRuleInterfaces_EmptyOptionListDoesNotBlockSync(t *testing.T) {
	client := interfaceListServer(t)

	rules := []APIRulePayload{{UUID: "221f3268-a", Description: "vpn", Interface: "wireguard"}}

	if errs := checkRuleInterfaces(context.Background(), client, rules); len(errs) != 0 {
		t.Errorf("expected the pre-flight to no-op on an empty option list, got %+v", errs)
	}
}

// teardownMock serves the endpoints executeSyncVPN and executeSyncAPI touch,
// and records the rule writes and deletes they issue.
//
// It models the one device behaviour the teardown ordering turns on: the
// `wireguard` interface group exists only while a WireGuard instance does.
// Deleting the last managed server removes it from the interface option list,
// exactly as OPNsense does after the reconfigure.
type teardownMock struct {
	ruleSetCalls    []string
	ruleDeleteCalls []string

	// currentRules is what the device reports as existing filter rules.
	currentRules []map[string]interface{}
	// baseInterfaces are the device's real interfaces, always present.
	baseInterfaces []string
	// wgServers are the managed WireGuard servers still on the device; while
	// any remains, the `wireguard` group is offered as an interface option.
	wgServers []map[string]interface{}
}

// interfaceOptions is what GET /firewall/filter/getRule offers right now.
func (m *teardownMock) interfaceOptions() []string {
	out := append([]string(nil), m.baseInterfaces...)
	if len(m.wgServers) > 0 {
		out = append(out, wireGuardInterfaceGroup)
	}
	return out
}

func (m *teardownMock) client(t *testing.T) *opnapi.Client {
	t.Helper()

	mux := http.NewServeMux()

	mux.HandleFunc("/firewall/alias/searchItem", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{})
	})
	mux.HandleFunc("/firewall/alias/reconfigure", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.APIResult{Result: "ok"})
	})
	// Honours the `interface` search parameter, matching OPNsense 26.1's
	// controller: a non-empty filter returns only rules bound to those
	// interfaces, and an ABSENT key returns every rule whatever it is bound
	// to. (26.1 treats a present-but-empty value differently again — the
	// floating view — but NDAgent never sends that shape; see
	// opnapi.RuleSearchRequest and its dedicated test.)
	//
	// This mock previously ignored the parameter and returned every rule for
	// any query, which meant the teardown test reported that discovery worked
	// no matter what was asked for — it could not have failed. Discovery
	// surviving the disappearance of the `wireguard` group is the whole
	// property the teardown depends on, so the mock has to be able to break
	// it.
	mux.HandleFunc("/firewall/filter/searchRule", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		raw, present := req["interface"]
		filter, _ := raw.(string)

		var rows []map[string]interface{}
		for _, rule := range m.currentRules {
			if !present || filter == "" {
				rows = append(rows, rule)
				continue
			}
			ruleIface, _ := rule["interface"].(string)
			for _, want := range strings.Split(filter, ",") {
				want = strings.TrimSpace(want)
				matched := false
				for _, bound := range strings.Split(ruleIface, ",") {
					if strings.TrimSpace(bound) == want {
						matched = true
						break
					}
				}
				if matched {
					rows = append(rows, rule)
					break
				}
			}
		}
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{Rows: rows, RowCount: len(rows), Total: len(rows)})
	})
	// Bare path (no UUID) is the interface-option template GetInterfaceList reads.
	mux.HandleFunc("/firewall/filter/getRule", func(w http.ResponseWriter, r *http.Request) {
		options := map[string]map[string]interface{}{}
		for _, iface := range m.interfaceOptions() {
			options[iface] = map[string]interface{}{"value": iface, "selected": 0}
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"rule": map[string]interface{}{"interface": options},
		})
	})

	// WireGuard endpoints, so a test can drive the real executor order
	// (executeSyncVPN then executeSyncAPI) rather than asserting the
	// post-teardown state by hand.
	mux.HandleFunc("/wireguard/general/get", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.WireGuardGeneralWrapper{
			General: opnapi.WireGuardGeneral{Enabled: "1"},
		})
	})
	mux.HandleFunc("/wireguard/server/search_server", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{
			Rows: m.wgServers, RowCount: len(m.wgServers), Total: len(m.wgServers),
		})
	})
	mux.HandleFunc("/wireguard/client/search_client", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{})
	})
	mux.HandleFunc("/wireguard/server/del_server/", func(w http.ResponseWriter, r *http.Request) {
		uuid := strings.TrimPrefix(r.URL.Path, "/wireguard/server/del_server/")
		kept := m.wgServers[:0]
		for _, s := range m.wgServers {
			if id, _ := s["uuid"].(string); id != uuid {
				kept = append(kept, s)
			}
		}
		m.wgServers = kept
		_ = json.NewEncoder(w).Encode(opnapi.APIResult{Result: "deleted"})
	})
	mux.HandleFunc("/wireguard/service/reconfigure", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.APIResult{Result: "ok"})
	})
	mux.HandleFunc("/firewall/filter/setRule/", func(w http.ResponseWriter, r *http.Request) {
		m.ruleSetCalls = append(m.ruleSetCalls, strings.TrimPrefix(r.URL.Path, "/firewall/filter/setRule/"))
		_ = json.NewEncoder(w).Encode(opnapi.APIResult{Result: "saved"})
	})
	mux.HandleFunc("/firewall/filter/delRule/", func(w http.ResponseWriter, r *http.Request) {
		m.ruleDeleteCalls = append(m.ruleDeleteCalls, strings.TrimPrefix(r.URL.Path, "/firewall/filter/delRule/"))
		_ = json.NewEncoder(w).Encode(opnapi.APIResult{Result: "deleted"})
	})
	mux.HandleFunc("/firewall/filter/apply", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "OK\n\n"})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return opnapi.NewClient(srv.URL, "key", "secret", true)
}

// TestExecuteSyncAPI_VPNTeardownSweepsAutoRulesAndFailsOnUserRule pins the
// two outcomes the operator specified for a VPN teardown, which must both
// happen in the SAME sync:
//
//   - The auto-generated rule ([nd-vpn:...], emitted by NDManager only while
//     an enabled membership exists) drops out of the desired set when the
//     network goes away. It is an NDAgent-managed object and must be DELETED
//     by the orphan sweep — no dangling rule, and not a failure.
//   - A user-authored template rule still pointing at the now-missing
//     `wireguard` group must FAIL LOUDLY, naming the rule and the group.
//
// This drives the REAL executor order — executeSyncVPN first, then
// executeSyncAPI — against a mock whose `wireguard` interface option
// disappears when the last WireGuard server is deleted, as OPNsense's does.
// An earlier version called executeSyncAPI alone against a hand-set
// post-teardown state, so it never exercised the ordering it claimed to
// validate, and its mock ignored the interface search filter, which made
// rule discovery succeed regardless of what was queried.
//
// Discovery surviving the group's disappearance is the load-bearing part:
// ListAllRules' first call omits the interface filter, so rules bound to the
// vanished group are still enumerated and can still be swept. See
// opnapi.TestListAllRulesFindsRulesOnUnlistedInterfaces.
func TestExecuteSyncAPI_VPNTeardownSweepsAutoRulesAndFailsOnUserRule(t *testing.T) {
	const (
		autoRuleUUID = "221f3268-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		userRuleUUID = "221f3268-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	)

	mock := &teardownMock{
		// Both rules are on the device, both bound to the wireguard group.
		currentRules: []map[string]interface{}{
			{"uuid": autoRuleUUID, "interface": wireGuardInterfaceGroup, "description": "[nd-vpn:lab] auto peer", "sequence": "100"},
			{"uuid": userRuleUUID, "interface": wireGuardInterfaceGroup, "description": "Ops VPN access", "sequence": "200"},
		},
		baseInterfaces: []string{"lan", "wan"},
		// One managed WireGuard server, so the group is offered up front.
		wgServers: []map[string]interface{}{
			{"uuid": "wg-server-1", "name": opnapi.BuildServerName("lab")},
		},
	}
	client := mock.client(t)
	ctx := context.Background()

	// Precondition: while the instance exists, the group is a valid option.
	if !containsString(mock.interfaceOptions(), wireGuardInterfaceGroup) {
		t.Fatal("precondition: the wireguard group should be offered while a server exists")
	}

	// Phase one of the real order: the network is detached, so the desired
	// VPN set is empty and the orphan sweep removes the instance.
	vpnResult := executeSyncVPN(ctx, client, nil)
	if !vpnResult.Success {
		t.Fatalf("VPN teardown failed: %v", vpnResult.Errors)
	}
	if containsString(mock.interfaceOptions(), wireGuardInterfaceGroup) {
		t.Fatal("the wireguard group should be gone once the last server is deleted")
	}

	// Phase two: NDManager no longer emits the auto rule; the user's template
	// rule is still attached and still targets the now-missing group.
	desired := []APIRulePayload{{
		UUID:        userRuleUUID,
		Enabled:     true,
		Description: "Ops VPN access",
		Interface:   wireGuardInterfaceGroup,
	}}

	result := executeSyncAPI(ctx, client, nil, desired)

	// The auto rule must be swept, even though the group it is bound to no
	// longer appears in the interface list.
	if len(mock.ruleDeleteCalls) != 1 || mock.ruleDeleteCalls[0] != autoRuleUUID {
		t.Errorf("expected the orphaned auto VPN rule %s to be deleted, got deletes %v",
			autoRuleUUID, mock.ruleDeleteCalls)
	}

	// The user rule must not be written (OPNsense would reject it) and must
	// not be deleted either — it stays on the device for the operator.
	for _, uuid := range mock.ruleSetCalls {
		if uuid == userRuleUUID {
			t.Errorf("user rule %s was written despite targeting a missing interface", userRuleUUID)
		}
	}
	for _, uuid := range mock.ruleDeleteCalls {
		if uuid == userRuleUUID {
			t.Errorf("user rule %s was deleted; a blocked rule must be left alone, not orphan-deleted", userRuleUUID)
		}
	}

	// And the task must fail loudly, naming the rule and the group.
	if result.Success {
		t.Error("expected the sync to FAIL because a user rule targets a missing interface")
	}
	if len(result.ValidationErrors) != 1 || result.ValidationErrors[0].ErrorCode != "INTERFACE_NOT_FOUND" {
		t.Errorf("expected one INTERFACE_NOT_FOUND validation error, got %+v", result.ValidationErrors)
	}
	var found bool
	for _, e := range result.Errors {
		if strings.Contains(e, "Ops VPN access") && strings.Contains(e, wireGuardInterfaceGroup) {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an error naming the rule and the missing group, got %v", result.Errors)
	}
}

// TestExecuteSyncAPI_VPNTeardownWithNoUserRuleSucceeds is the ordinary
// teardown: the network goes away, its auto rules go with it, and nothing
// else references the interface. That must be a clean success — removing
// managed objects is part of the teardown, not an error.
func TestExecuteSyncAPI_VPNTeardownWithNoUserRuleSucceeds(t *testing.T) {
	const autoRuleUUID = "221f3268-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

	mock := &teardownMock{
		currentRules: []map[string]interface{}{
			{"uuid": autoRuleUUID, "interface": wireGuardInterfaceGroup, "description": "[nd-vpn:lab] auto peer", "sequence": "100"},
		},
		baseInterfaces: []string{"lan", "wan"},
		wgServers: []map[string]interface{}{
			{"uuid": "wg-server-1", "name": opnapi.BuildServerName("lab")},
		},
	}
	client := mock.client(t)
	ctx := context.Background()

	if vpnResult := executeSyncVPN(ctx, client, nil); !vpnResult.Success {
		t.Fatalf("VPN teardown failed: %v", vpnResult.Errors)
	}

	result := executeSyncAPI(ctx, client, nil, nil)

	if len(mock.ruleDeleteCalls) != 1 || mock.ruleDeleteCalls[0] != autoRuleUUID {
		t.Errorf("expected the orphaned auto VPN rule to be deleted, got %v", mock.ruleDeleteCalls)
	}
	if !result.Success {
		t.Errorf("expected a clean teardown to succeed, got errors: %v", result.Errors)
	}
	if len(result.ValidationErrors) != 0 {
		t.Errorf("expected no validation errors, got %+v", result.ValidationErrors)
	}
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// TestExecuteSyncVPN_MalformedPayloadDoesNotEnable pins that the master
// switch is only flipped for a payload that can actually be realized. The
// enable used to run before any network was validated, so a payload whose
// networks all carry an unusable private key turned the plugin on and then
// failed every network — leaving it enabled with nothing behind it, which is
// worse than where the device started and is not what "if config is synced,
// enable it" asks for: nothing is being synced if nothing is realizable.
func TestExecuteSyncVPN_MalformedPayloadDoesNotEnable(t *testing.T) {
	mock := &wireGuardMock{currentEnabled: "0"}
	srv := mock.server(t)
	client := opnapi.NewClient(srv.URL, "key", "secret", true)

	bad := []VPNNetwork{{
		NetworkName: "broken",
		Interface:   VPNInterface{PrivateKey: "not-a-valid-key", Address: "10.0.0.1/24", ListenPort: 51820},
	}}

	result := executeSyncVPN(context.Background(), client, bad)

	if result.Success {
		t.Error("expected the sync to fail when no network can be realized")
	}
	if len(mock.generalSetCalls) != 0 {
		t.Errorf("master switch was enabled for an unrealizable payload: %v", mock.generalSetCalls)
	}
	if mock.currentEnabled != "0" {
		t.Errorf("master switch = %q, want it left off", mock.currentEnabled)
	}
}

// TestExecuteSyncVPN_PartiallyValidPayloadStillEnables is the other side of
// that guard: one realizable network is enough. The enable is gated on
// "anything can be realized", not "everything is perfect", so a single bad
// network in a larger payload must not suppress the VPN the others describe.
func TestExecuteSyncVPN_PartiallyValidPayloadStillEnables(t *testing.T) {
	mock := &wireGuardMock{currentEnabled: "0"}
	srv := mock.server(t)
	client := opnapi.NewClient(srv.URL, "key", "secret", true)

	networks := append([]VPNNetwork{{
		NetworkName: "broken",
		Interface:   VPNInterface{PrivateKey: "not-a-valid-key", Address: "10.0.0.1/24", ListenPort: 51820},
	}}, testVPNNetworks()...)

	result := executeSyncVPN(context.Background(), client, networks)

	if result.Success {
		t.Error("expected failure to be reported for the malformed network")
	}
	if len(mock.generalSetCalls) != 1 || mock.generalSetCalls[0].Enabled != "1" {
		t.Errorf("expected the master switch to be enabled for the realizable network, got %v", mock.generalSetCalls)
	}
}

// TestExecuteSyncVPN_EnableFailureStillRunsOrphanSweep pins that a failure to
// enable does not abort the executor before its teardown half.
//
// The orphan sweep does not depend on the master switch, so skipping it
// because an unrelated call failed would strand managed servers and clients
// on the device — the same abort-before-the-sweep anti-pattern that
// checkRuleInterfaces is deliberately written to avoid. The task still fails;
// it just fails after doing the cleanup it could do.
func TestExecuteSyncVPN_EnableFailureStillRunsOrphanSweep(t *testing.T) {
	var deletedServers []string

	mux := http.NewServeMux()
	mux.HandleFunc("/wireguard/general/get", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	mux.HandleFunc("/wireguard/server/search_server", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{
			Rows: []map[string]interface{}{
				{"uuid": "stale-server", "name": opnapi.BuildServerName("gone")},
			},
			RowCount: 1, Total: 1,
		})
	})
	mux.HandleFunc("/wireguard/client/search_client", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{})
	})
	mux.HandleFunc("/wireguard/server/add_server", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.WireGuardAddResponse{Result: "saved", UUID: "server-uuid-1"})
	})
	mux.HandleFunc("/wireguard/client/add_client", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.WireGuardAddResponse{Result: "saved", UUID: "client-uuid-1"})
	})
	mux.HandleFunc("/wireguard/server/del_server/", func(w http.ResponseWriter, r *http.Request) {
		deletedServers = append(deletedServers, strings.TrimPrefix(r.URL.Path, "/wireguard/server/del_server/"))
		_ = json.NewEncoder(w).Encode(opnapi.APIResult{Result: "deleted"})
	})
	mux.HandleFunc("/wireguard/service/reconfigure", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.APIResult{Result: "ok"})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	client := opnapi.NewClient(srv.URL, "key", "secret", true)

	result := executeSyncVPN(context.Background(), client, testVPNNetworks())

	if result.Success {
		t.Error("expected the task to fail when the master switch could not be read")
	}
	if len(deletedServers) != 1 || deletedServers[0] != "stale-server" {
		t.Errorf("expected the orphaned server to be swept despite the enable failure, got %v", deletedServers)
	}
}
