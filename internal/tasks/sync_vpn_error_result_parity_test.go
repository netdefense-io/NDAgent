package tasks

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// This file extends sync_error_result_parity_test.go's invariant to
// executeSyncVPN's discovery/enable/apply call sites. See that file's
// doc comment for the shared invariant and
// assertErrorHasMatchingResultItem/countNonSuccessResults.

// TestExecuteSyncVPN_SearchServersFailure_HasMatchingResultItem covers
// executeSyncVPN's Phase 1 SearchServers discovery call.
func TestExecuteSyncVPN_SearchServersFailure_HasMatchingResultItem(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wireguard/server/search_server", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := opnapi.NewClient(server.URL, "key", "secret", true)

	result := executeSyncVPN(context.Background(), client, testVPNNetworks())

	assertErrorHasMatchingResultItem(t, "VPN search servers", result.Errors, result.Results)
}

// TestExecuteSyncVPN_SearchClientsFailure_HasMatchingResultItem covers
// executeSyncVPN's Phase 1 SearchClients discovery call.
func TestExecuteSyncVPN_SearchClientsFailure_HasMatchingResultItem(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wireguard/server/search_server", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{})
	})
	mux.HandleFunc("/wireguard/client/search_client", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := opnapi.NewClient(server.URL, "key", "secret", true)

	result := executeSyncVPN(context.Background(), client, testVPNNetworks())

	assertErrorHasMatchingResultItem(t, "VPN search clients", result.Errors, result.Results)
}

// TestExecuteSyncVPN_EnableFailure_HasMatchingResultItem covers
// executeSyncVPN's Phase 1.5 master-switch enable (ensureWireGuardEnabled),
// which also must not abort before the orphan sweep -- so this test also
// confirms the failure doesn't short-circuit the rest of the executor.
func TestExecuteSyncVPN_EnableFailure_HasMatchingResultItem(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wireguard/server/search_server", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{})
	})
	mux.HandleFunc("/wireguard/client/search_client", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{})
	})
	mux.HandleFunc("/wireguard/general/get", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.WireGuardGeneralWrapper{General: opnapi.WireGuardGeneral{Enabled: "0"}})
	})
	mux.HandleFunc("/wireguard/general/set", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	mux.HandleFunc("/wireguard/server/add_server", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.WireGuardAddResponse{Result: "saved", UUID: "server-uuid-1"})
	})
	mux.HandleFunc("/wireguard/client/add_client", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.WireGuardAddResponse{Result: "saved", UUID: "client-uuid-1"})
	})
	mux.HandleFunc("/wireguard/service/reconfigure", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.APIResult{Result: "ok"})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := opnapi.NewClient(server.URL, "key", "secret", true)

	result := executeSyncVPN(context.Background(), client, testVPNNetworks())

	assertErrorHasMatchingResultItem(t, "VPN enable master switch", result.Errors, result.Results)

	// The enable failure must not have aborted the executor: the server
	// create item should still be present and successful, proving the
	// orphan-sweep-adjacent phases still ran (checkRuleInterfaces rule:
	// a check that coexists with an orphan sweep must not abort before it).
	found := false
	for _, item := range result.Results {
		if item.Type == "wg_server" && isSyncSuccessStatus(item.Status) {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the server create/update to still run after the enable failure, got %+v", result.Results)
	}
}

// TestExecuteSyncVPN_ReconfigureFailure_HasMatchingResultItem covers
// executeSyncVPN's final Phase 6 ReconfigureWireGuard apply call.
func TestExecuteSyncVPN_ReconfigureFailure_HasMatchingResultItem(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wireguard/server/search_server", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{})
	})
	mux.HandleFunc("/wireguard/client/search_client", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{})
	})
	mux.HandleFunc("/wireguard/general/get", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.WireGuardGeneralWrapper{General: opnapi.WireGuardGeneral{Enabled: "1"}})
	})
	mux.HandleFunc("/wireguard/server/add_server", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.WireGuardAddResponse{Result: "saved", UUID: "server-uuid-1"})
	})
	mux.HandleFunc("/wireguard/client/add_client", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.WireGuardAddResponse{Result: "saved", UUID: "client-uuid-1"})
	})
	mux.HandleFunc("/wireguard/service/reconfigure", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := opnapi.NewClient(server.URL, "key", "secret", true)

	result := executeSyncVPN(context.Background(), client, testVPNNetworks())

	assertErrorHasMatchingResultItem(t, "VPN reconfigure", result.Errors, result.Results)
}
