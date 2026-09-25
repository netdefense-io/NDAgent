package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// This file and its sibling sync_vpn_error_result_parity_test.go cover
// every SYNC_API call site that appends to `errors` on failure: each must
// also append a matching item to `results`, since the task's
// success/failure and the summary's "(N errors)" count are derived from
// `errors` while a consumer of the persisted task only ever sees
// `results`.
//
// Each test below drives the real function (no mock of the function
// itself) with an OPNsense stub that fails exactly one call, and asserts
// the invariant via assertErrorHasMatchingResultItem: every entry in the
// returned SyncAPIResult.Errors has exactly one corresponding non-success
// item in SyncAPIResult.Results, and vice versa.

// countNonSuccessResults returns the SyncAPIItemResult entries that are
// neither a clean success ("success", or VPN's "ok") nor a "warning".
func countNonSuccessResults(results []SyncAPIItemResult) []SyncAPIItemResult {
	var out []SyncAPIItemResult
	for _, r := range results {
		if !isSyncSuccessStatus(r.Status) && r.Status != "warning" {
			out = append(out, r)
		}
	}
	return out
}

// TestExecuteSyncAPI_AliasReconfigureFailure_HasMatchingResultItem covers
// executeSyncAPI's Phase 6 "Alias reconfigure" call.
func TestExecuteSyncAPI_AliasReconfigureFailure_HasMatchingResultItem(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/firewall/alias/searchItem", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{Rows: []map[string]interface{}{}})
	})
	mux.HandleFunc("/firewall/filter/searchRule", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{Rows: []map[string]interface{}{}})
	})
	mux.HandleFunc("/firewall/alias/reconfigure", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	mux.HandleFunc("/firewall/filter/apply", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.APIResult{Result: "ok"})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := opnapi.NewClient(server.URL, "key", "secret", true)

	result := executeSyncAPI(context.Background(), client, nil, nil)

	assertErrorHasMatchingResultItem(t, "Alias reconfigure", result.Errors, result.Results)
}

// TestExecuteSyncAPI_RuleApplyFailure_HasMatchingResultItem covers
// executeSyncAPI's Phase 6 "Rule apply" call.
func TestExecuteSyncAPI_RuleApplyFailure_HasMatchingResultItem(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/firewall/alias/searchItem", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{Rows: []map[string]interface{}{}})
	})
	mux.HandleFunc("/firewall/filter/searchRule", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{Rows: []map[string]interface{}{}})
	})
	mux.HandleFunc("/firewall/alias/reconfigure", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.APIResult{Result: "ok"})
	})
	mux.HandleFunc("/firewall/filter/apply", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := opnapi.NewClient(server.URL, "key", "secret", true)

	result := executeSyncAPI(context.Background(), client, nil, nil)

	assertErrorHasMatchingResultItem(t, "Rule apply", result.Errors, result.Results)
}

// TestExecuteSyncAPI_ListAliasesFailure_HasMatchingResultItem covers
// executeSyncAPI's Phase 1 ListAllAliases discovery call.
func TestExecuteSyncAPI_ListAliasesFailure_HasMatchingResultItem(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/firewall/alias/searchItem", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := opnapi.NewClient(server.URL, "key", "secret", true)

	result := executeSyncAPI(context.Background(), client, nil, nil)

	assertErrorHasMatchingResultItem(t, "List aliases", result.Errors, result.Results)
}

// TestExecuteSyncAPI_ListRulesFailure_HasMatchingResultItem covers
// executeSyncAPI's Phase 1 ListAllRules discovery call.
func TestExecuteSyncAPI_ListRulesFailure_HasMatchingResultItem(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/firewall/alias/searchItem", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{Rows: []map[string]interface{}{}})
	})
	mux.HandleFunc("/firewall/filter/searchRule", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := opnapi.NewClient(server.URL, "key", "secret", true)

	result := executeSyncAPI(context.Background(), client, nil, nil)

	assertErrorHasMatchingResultItem(t, "List rules", result.Errors, result.Results)
}

// TestExecuteSyncUnbound_ReconfigureFailure_HasMatchingResultItem covers
// executeSyncUnbound's Phase 10 "Unbound reconfigure" call.
func TestExecuteSyncUnbound_ReconfigureFailure_HasMatchingResultItem(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/unbound/settings/searchHostOverride", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{Rows: []map[string]interface{}{}})
	})
	mux.HandleFunc("/unbound/settings/searchHostAlias", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{Rows: []map[string]interface{}{}})
	})
	mux.HandleFunc("/unbound/settings/searchForward", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{Rows: []map[string]interface{}{}})
	})
	mux.HandleFunc("/unbound/settings/searchAcl", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{Rows: []map[string]interface{}{}})
	})
	mux.HandleFunc("/unbound/service/reconfigure", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := opnapi.NewClient(server.URL, "key", "secret", true)

	result := executeSyncUnbound(context.Background(), client, nil, nil, nil, nil)

	assertErrorHasMatchingResultItem(t, "Unbound reconfigure", result.Errors, result.Results)
}

// TestExecuteSyncUnbound_ListHostOverridesFailure_HasMatchingResultItem
// covers executeSyncUnbound's Phase 1 ListAllHostOverrides discovery call.
func TestExecuteSyncUnbound_ListHostOverridesFailure_HasMatchingResultItem(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/unbound/settings/searchHostOverride", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := opnapi.NewClient(server.URL, "key", "secret", true)

	result := executeSyncUnbound(context.Background(), client, nil, nil, nil, nil)

	assertErrorHasMatchingResultItem(t, "List host overrides", result.Errors, result.Results)
}

// TestExecuteSyncUnbound_ListForwardsFailure_HasMatchingResultItem covers
// executeSyncUnbound's Phase 1 ListAllForwards discovery call.
func TestExecuteSyncUnbound_ListForwardsFailure_HasMatchingResultItem(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/unbound/settings/searchHostOverride", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{Rows: []map[string]interface{}{}})
	})
	mux.HandleFunc("/unbound/settings/searchForward", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := opnapi.NewClient(server.URL, "key", "secret", true)

	result := executeSyncUnbound(context.Background(), client, nil, nil, nil, nil)

	assertErrorHasMatchingResultItem(t, "List forwards", result.Errors, result.Results)
}

// TestExecuteSyncUnbound_ListHostAliasesFailure_HasMatchingResultItem
// covers executeSyncUnbound's Phase 1 ListAllHostAliases discovery call.
func TestExecuteSyncUnbound_ListHostAliasesFailure_HasMatchingResultItem(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/unbound/settings/searchHostOverride", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{Rows: []map[string]interface{}{}})
	})
	mux.HandleFunc("/unbound/settings/searchForward", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{Rows: []map[string]interface{}{}})
	})
	mux.HandleFunc("/unbound/settings/searchHostAlias", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := opnapi.NewClient(server.URL, "key", "secret", true)

	result := executeSyncUnbound(context.Background(), client, nil, nil, nil, nil)

	assertErrorHasMatchingResultItem(t, "List host aliases", result.Errors, result.Results)
}

// TestExecuteSyncUnbound_ListACLsFailure_HasMatchingResultItem covers
// executeSyncUnbound's Phase 1 ListAllACLs discovery call.
func TestExecuteSyncUnbound_ListACLsFailure_HasMatchingResultItem(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/unbound/settings/searchHostOverride", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{Rows: []map[string]interface{}{}})
	})
	mux.HandleFunc("/unbound/settings/searchForward", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{Rows: []map[string]interface{}{}})
	})
	mux.HandleFunc("/unbound/settings/searchHostAlias", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{Rows: []map[string]interface{}{}})
	})
	mux.HandleFunc("/unbound/settings/searchAcl", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := opnapi.NewClient(server.URL, "key", "secret", true)

	result := executeSyncUnbound(context.Background(), client, nil, nil, nil, nil)

	assertErrorHasMatchingResultItem(t, "List ACLs", result.Errors, result.Results)
}

// TestExecuteSyncZabbix_ListUserparametersFailure_HasMatchingResultItem
// covers executeSyncZabbix's Phase 0 plugin-presence probe
// (ListAllZabbixUserParameters) on a non-404 (real) failure -- distinct
// from the 404 "plugin not installed" no-op path, which stays a silent
// success.
func TestExecuteSyncZabbix_ListUserparametersFailure_HasMatchingResultItem(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/zabbixagent/settings/searchUserparameters/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := opnapi.NewClient(server.URL, "key", "secret", true)

	result := executeSyncZabbix(context.Background(), client, nil, nil, nil, false)

	assertErrorHasMatchingResultItem(t, "Zabbix list userparameters", result.Errors, result.Results)
}

// TestExecuteSyncZabbix_ListAliasesFailure_HasMatchingResultItem covers
// executeSyncZabbix's Phase 4-5 ListAllZabbixAliases discovery call.
func TestExecuteSyncZabbix_ListAliasesFailure_HasMatchingResultItem(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/zabbixagent/settings/searchUserparameters/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{Rows: []map[string]interface{}{}})
	})
	mux.HandleFunc("/zabbixagent/settings/searchAliases/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := opnapi.NewClient(server.URL, "key", "secret", true)

	result := executeSyncZabbix(context.Background(), client, nil, nil, nil, false)

	assertErrorHasMatchingResultItem(t, "Zabbix list aliases", result.Errors, result.Results)
}

// TestExecuteSyncZabbix_ReconfigureFailure_HasMatchingResultItem covers
// executeSyncZabbix's Phase 6 "Zabbix reconfigure" call. A settings
// snippet is included so the "touched" guard lets the call fire.
func TestExecuteSyncZabbix_ReconfigureFailure_HasMatchingResultItem(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/zabbixagent/settings/searchUserparameters/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{Rows: []map[string]interface{}{}})
	})
	mux.HandleFunc("/zabbixagent/settings/searchAliases/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{Rows: []map[string]interface{}{}})
	})
	mux.HandleFunc("/zabbixagent/settings/get", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{})
	})
	mux.HandleFunc("/zabbixagent/settings/set", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SetZabbixResponse{Result: "saved"})
	})
	mux.HandleFunc("/zabbixagent/service/reconfigure", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := opnapi.NewClient(server.URL, "key", "secret", true)

	settings := &opnapi.APIZabbixSettingsPayload{
		Hostname:   "e2e-b",
		Enabled:    true,
		ServerList: []string{"10.0.0.1"},
	}
	result := executeSyncZabbix(context.Background(), client, settings, nil, nil, false)

	assertErrorHasMatchingResultItem(t, "Zabbix reconfigure", result.Errors, result.Results)
}

// TestExecuteSyncUsersGroups_ListUsersFailure_HasMatchingResultItem covers
// executeSyncUsersGroups's Phase 1 ListAllUsers discovery call. A
// dangerous USER is included to prove a dangerous-snippet rejection
// recorded earlier in the same pass survives this early return.
func TestExecuteSyncUsersGroups_ListUsersFailure_HasMatchingResultItem(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/user/search", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := opnapi.NewClient(server.URL, "key", "secret", true)

	dangerousUser := opnapi.APIUserPayload{Name: "svc-mon", Priv: []string{"page-all"}}
	result := executeSyncUsersGroups(context.Background(), client, []opnapi.APIUserPayload{dangerousUser}, nil, true, authDeferralInfo{})

	assertErrorHasMatchingResultItem(t, "List users", result.Errors, result.Results)

	found := false
	for _, item := range result.Results {
		if item.Type == "user" && item.Name == "svc-mon" && item.Status == "blocked" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the dangerous-snippet rejection recorded before the discovery failure to survive the early return, got %+v", result.Results)
	}
}

// TestExecuteSyncUsersGroups_ListGroupsFailure_HasMatchingResultItem
// covers executeSyncUsersGroups's Phase 1 ListAllGroups discovery call.
func TestExecuteSyncUsersGroups_ListGroupsFailure_HasMatchingResultItem(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/user/search", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{Rows: []map[string]interface{}{}})
	})
	mux.HandleFunc("/auth/group/search", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := opnapi.NewClient(server.URL, "key", "secret", true)

	result := executeSyncUsersGroups(context.Background(), client, nil, nil, false, authDeferralInfo{})

	assertErrorHasMatchingResultItem(t, "List groups", result.Errors, result.Results)
}

// TestExecuteSyncUsersGroups_MemberUpdateFailure_HasMatchingResultItem
// covers executeSyncUsersGroups's Phase 4 member-CSV update for a
// member-managed group, distinct from the Phase 2 create/update item for
// the same group (which must stay "success").
func TestExecuteSyncUsersGroups_MemberUpdateFailure_HasMatchingResultItem(t *testing.T) {
	setCalls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/user/search", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{
			Rows: []map[string]interface{}{
				{"uuid": "u1", "name": "e2e-tests", "uid": "2004"},
			},
		})
	})
	mux.HandleFunc("/auth/group/search", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{
			Rows: []map[string]interface{}{
				{"uuid": "g1", "name": "eng-team", "description": "[nd-template:base]", "gid": "2000", "member": "2004"},
			},
		})
	})
	mux.HandleFunc("/auth/group/set/g1", func(w http.ResponseWriter, r *http.Request) {
		setCalls++
		if setCalls == 1 {
			// Phase 2's create/update call succeeds.
			_ = json.NewEncoder(w).Encode(opnapi.SetGroupResponse{Result: "saved"})
			return
		}
		// Phase 4's member-CSV update call fails.
		_ = json.NewEncoder(w).Encode(opnapi.SetGroupResponse{Result: "failed"})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := opnapi.NewClient(server.URL, "key", "secret", true)

	groupPayload := opnapi.APIGroupPayload{Name: "eng-team", Members: []string{"e2e-tests"}}
	result := executeSyncUsersGroups(context.Background(), client, nil, []opnapi.APIGroupPayload{groupPayload}, false, authDeferralInfo{})

	if setCalls != 2 {
		t.Fatalf("auth/group/set calls = %d, want exactly 2 (Phase 2 create/update + Phase 4 member update)", setCalls)
	}

	assertErrorHasMatchingResultItem(t, "Group member update", result.Errors, result.Results)

	// The Phase 2 item for this same group must still read success --
	// only the Phase 4 member-update item should show the failure.
	var successCount, errorCount int
	for _, r := range result.Results {
		if r.Type != "group" || r.Name != "eng-team" {
			continue
		}
		switch r.Status {
		case "success":
			successCount++
		case "error":
			errorCount++
		}
	}
	if successCount != 1 {
		t.Errorf("group %q success items = %d, want 1 (the Phase 2 create/update)", "eng-team", successCount)
	}
	if errorCount != 1 {
		t.Errorf("group %q error items = %d, want 1 (the Phase 4 member update)", "eng-team", errorCount)
	}
}

// assertErrorHasMatchingResultItem is the reusable core of every test
// above: for every string in errs, at least one non-success/non-warning
// item in results must exist to explain it, and vice versa -- neither
// list may outrun the other. It also re-derives the "(N errors)" summary
// suffix exactly like HandleSyncAPI does, and confirms it is never
// printed against a clean-looking results array.
func assertErrorHasMatchingResultItem(t *testing.T, label string, errs []string, results []SyncAPIItemResult) {
	t.Helper()

	if len(errs) == 0 {
		t.Fatalf("%s: test setup did not actually trigger a failure (errs is empty)", label)
	}

	nonSuccess := countNonSuccessResults(results)
	if len(nonSuccess) == 0 {
		t.Fatalf("%s: errs = %v but every result item is success/warning: "+
			"a FAILED task whose own results array shows nothing wrong", label, errs)
	}

	// Neither list may outrun the other: every `errs` entry must have
	// exactly one matching non-success result item (matched on Error
	// text, then consumed), and every non-success result item must be
	// accounted for by some `errs` entry. A regression that pairs only
	// some of them -- or adds an unpaired warning-turned-error on one
	// side -- must fail this, not just "at least one item exists".
	remaining := make([]string, len(nonSuccess))
	for i, r := range nonSuccess {
		remaining[i] = r.Error
	}
	for _, e := range errs {
		idx := -1
		for i, r := range remaining {
			if r == e {
				idx = i
				break
			}
		}
		if idx == -1 {
			t.Fatalf("%s: errs contains %q with no matching non-success result item (unmatched result errors: %v)", label, e, remaining)
			return
		}
		remaining = append(remaining[:idx], remaining[idx+1:]...)
	}
	if len(remaining) != 0 {
		t.Fatalf("%s: %d non-success result item(s) have no matching errs entry: %v", label, len(remaining), remaining)
	}

	// Re-derive the "(N errors)" summary suffix exactly like HandleSyncAPI
	// does and confirm it actually carries the count -- not just that it
	// was reachable when results were empty.
	summary := buildSyncSummary(results, len(errs))
	wantSuffix := fmt.Sprintf("(%d errors)", len(errs))
	if !strings.Contains(summary, wantSuffix) {
		t.Fatalf("%s: summary %q does not carry the expected %q suffix", label, summary, wantSuffix)
	}
}
