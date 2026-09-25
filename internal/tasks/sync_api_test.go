package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

func TestNewSequenceCalculator_NoRules(t *testing.T) {
	calc := NewSequenceCalculator(nil)

	if calc.MinUnmanaged != 100000 {
		t.Errorf("MinUnmanaged = %d, want 100000", calc.MinUnmanaged)
	}
	if calc.MaxUnmanaged != 100000 {
		t.Errorf("MaxUnmanaged = %d, want 100000", calc.MaxUnmanaged)
	}
}

func TestNewSequenceCalculator_OnlyManagedRules(t *testing.T) {
	// Given: Only managed rules (with NDAgent UUID prefix)
	allRules := []map[string]interface{}{
		{"uuid": opnapi.NDAgentUUIDPrefix + "-aaaa-4abc-9001-000000000001", "sequence": "100"},
		{"uuid": opnapi.NDAgentUUIDPrefix + "-bbbb-4abc-9001-000000000002", "sequence": "200"},
	}

	calc := NewSequenceCalculator(allRules)

	// Then: Should use defaults since no unmanaged rules exist
	if calc.MinUnmanaged != 100000 {
		t.Errorf("MinUnmanaged = %d, want 100000 (default)", calc.MinUnmanaged)
	}
	if calc.MaxUnmanaged != 100000 {
		t.Errorf("MaxUnmanaged = %d, want 100000 (default)", calc.MaxUnmanaged)
	}
}

func TestNewSequenceCalculator_WithUnmanagedRules(t *testing.T) {
	// Given: Mix of managed and unmanaged rules
	allRules := []map[string]interface{}{
		{"uuid": opnapi.NDAgentUUIDPrefix + "-aaaa-4abc-9001-000000000001", "sequence": "100"}, // managed
		{"uuid": "other-uuid-1", "sequence": "5000"},                                           // unmanaged
		{"uuid": "other-uuid-2", "sequence": "10000"},                                          // unmanaged
		{"uuid": "other-uuid-3", "sequence": "7500"},                                           // unmanaged
	}

	calc := NewSequenceCalculator(allRules)

	// Then: Should find unmanaged bounds
	if calc.MinUnmanaged != 5000 {
		t.Errorf("MinUnmanaged = %d, want 5000", calc.MinUnmanaged)
	}
	if calc.MaxUnmanaged != 10000 {
		t.Errorf("MaxUnmanaged = %d, want 10000", calc.MaxUnmanaged)
	}
}

func TestNewSequenceCalculator_SequenceAsFloat64(t *testing.T) {
	// Given: Sequence as float64 (common when parsing JSON)
	allRules := []map[string]interface{}{
		{"uuid": "other-uuid-1", "sequence": float64(3000)},
	}

	calc := NewSequenceCalculator(allRules)

	if calc.MinUnmanaged != 3000 {
		t.Errorf("MinUnmanaged = %d, want 3000", calc.MinUnmanaged)
	}
}

func TestComputeSequences_PrependOnly(t *testing.T) {
	calc := &SequenceCalculator{MinUnmanaged: 100000, MaxUnmanaged: 100000}

	rules := []APIRulePayload{
		{UUID: "221f3268-1", Position: RulePositionPrepend, Priority: 200},
		{UUID: "221f3268-2", Position: RulePositionPrepend, Priority: 100},
		{UUID: "221f3268-3", Position: RulePositionPrepend, Priority: 300},
	}

	sequences := calc.ComputeSequences(rules)

	// Sorted by priority: 100, 200, 300 -> sequences 100, 200, 300
	if sequences["221f3268-2"] != 100 {
		t.Errorf("Rule with priority 100 got sequence %d, want 100", sequences["221f3268-2"])
	}
	if sequences["221f3268-1"] != 200 {
		t.Errorf("Rule with priority 200 got sequence %d, want 200", sequences["221f3268-1"])
	}
	if sequences["221f3268-3"] != 300 {
		t.Errorf("Rule with priority 300 got sequence %d, want 300", sequences["221f3268-3"])
	}
}

func TestComputeSequences_AppendOnly(t *testing.T) {
	calc := &SequenceCalculator{MinUnmanaged: 5000, MaxUnmanaged: 10000}

	rules := []APIRulePayload{
		{UUID: "221f3268-1", Position: RulePositionAppend, Priority: 200},
		{UUID: "221f3268-2", Position: RulePositionAppend, Priority: 100},
	}

	sequences := calc.ComputeSequences(rules)

	// APPEND starts at MaxUnmanaged + 1000 = 11000
	// Sorted by priority: 100, 200 -> sequences 11000, 11100
	if sequences["221f3268-2"] != 11000 {
		t.Errorf("Rule with priority 100 got sequence %d, want 11000", sequences["221f3268-2"])
	}
	if sequences["221f3268-1"] != 11100 {
		t.Errorf("Rule with priority 200 got sequence %d, want 11100", sequences["221f3268-1"])
	}
}

func TestComputeSequences_PrependAndAppend(t *testing.T) {
	calc := &SequenceCalculator{MinUnmanaged: 5000, MaxUnmanaged: 10000}

	rules := []APIRulePayload{
		{UUID: "221f3268-prepend-1", Position: RulePositionPrepend, Priority: 200},
		{UUID: "221f3268-prepend-2", Position: RulePositionPrepend, Priority: 100},
		{UUID: "221f3268-append-1", Position: RulePositionAppend, Priority: 100},
		{UUID: "221f3268-append-2", Position: RulePositionAppend, Priority: 200},
	}

	sequences := calc.ComputeSequences(rules)

	// PREPEND rules sorted by priority: 100, 200 -> sequences 100, 200
	if sequences["221f3268-prepend-2"] != 100 {
		t.Errorf("PREPEND rule with priority 100 got sequence %d, want 100", sequences["221f3268-prepend-2"])
	}
	if sequences["221f3268-prepend-1"] != 200 {
		t.Errorf("PREPEND rule with priority 200 got sequence %d, want 200", sequences["221f3268-prepend-1"])
	}

	// APPEND rules sorted by priority: 100, 200 -> sequences 11000, 11100
	if sequences["221f3268-append-1"] != 11000 {
		t.Errorf("APPEND rule with priority 100 got sequence %d, want 11000", sequences["221f3268-append-1"])
	}
	if sequences["221f3268-append-2"] != 11100 {
		t.Errorf("APPEND rule with priority 200 got sequence %d, want 11100", sequences["221f3268-append-2"])
	}
}

func TestComputeSequences_DefaultPosition(t *testing.T) {
	calc := &SequenceCalculator{MinUnmanaged: 100000, MaxUnmanaged: 100000}

	// Rule without explicit position should default to PREPEND (empty string treated as PREPEND)
	rules := []APIRulePayload{
		{UUID: "221f3268-1", Position: "", Priority: 100},
	}

	sequences := calc.ComputeSequences(rules)

	// Should be treated as PREPEND -> sequence 100
	if sequences["221f3268-1"] != 100 {
		t.Errorf("Default position rule got sequence %d, want 100 (PREPEND)", sequences["221f3268-1"])
	}
}

func TestComputeSequences_SamePriority(t *testing.T) {
	calc := &SequenceCalculator{MinUnmanaged: 100000, MaxUnmanaged: 100000}

	// Multiple rules with same priority - order should be stable
	rules := []APIRulePayload{
		{UUID: "221f3268-a", Position: RulePositionPrepend, Priority: 100},
		{UUID: "221f3268-b", Position: RulePositionPrepend, Priority: 100},
		{UUID: "221f3268-c", Position: RulePositionPrepend, Priority: 100},
	}

	sequences := calc.ComputeSequences(rules)

	// All should get distinct sequences (100, 200, 300 in some order)
	seqSet := make(map[int]bool)
	for _, r := range rules {
		seq := sequences[r.UUID]
		if seqSet[seq] {
			t.Errorf("Duplicate sequence %d found", seq)
		}
		seqSet[seq] = true
	}
}

func TestParseAPIRules_WithPositionAndPriority(t *testing.T) {
	payload := map[string]interface{}{
		"snippets": []interface{}{
			map[string]interface{}{
				"config_type": "RULE",
				"position":    "APPEND",
				"priority":    float64(500),
				"content":     `{"uuid": "221f3268-test-uuid", "action": "block", "interface": "lan"}`,
			},
		},
	}

	rules, err := parseAPIRules(payload)
	if err != nil {
		t.Fatalf("parseAPIRules failed: %v", err)
	}

	if len(rules) != 1 {
		t.Fatalf("Expected 1 rule, got %d", len(rules))
	}

	if rules[0].Position != RulePositionAppend {
		t.Errorf("Position = %s, want APPEND", rules[0].Position)
	}
	if rules[0].Priority != 500 {
		t.Errorf("Priority = %d, want 500", rules[0].Priority)
	}
}

func TestParseAPIRules_DefaultPositionAndPriority(t *testing.T) {
	payload := map[string]interface{}{
		"snippets": []interface{}{
			map[string]interface{}{
				"config_type": "RULE",
				// No position or priority specified
				"content": `{"uuid": "221f3268-test-uuid", "action": "pass"}`,
			},
		},
	}

	rules, err := parseAPIRules(payload)
	if err != nil {
		t.Fatalf("parseAPIRules failed: %v", err)
	}

	if len(rules) != 1 {
		t.Fatalf("Expected 1 rule, got %d", len(rules))
	}

	// Should have defaults
	if rules[0].Position != RulePositionPrepend {
		t.Errorf("Default Position = %s, want PREPEND", rules[0].Position)
	}
	if rules[0].Priority != 1000 {
		t.Errorf("Default Priority = %d, want 1000", rules[0].Priority)
	}
}

func TestParseAPIRules_InvalidPosition(t *testing.T) {
	payload := map[string]interface{}{
		"snippets": []interface{}{
			map[string]interface{}{
				"config_type": "RULE",
				"position":    "INVALID",
				"content":     `{"uuid": "221f3268-test-uuid"}`,
			},
		},
	}

	_, err := parseAPIRules(payload)
	if err == nil {
		t.Error("Expected error for invalid position, got nil")
	}
}

func TestParseAPIRules_CaseInsensitivePosition(t *testing.T) {
	testCases := []struct {
		input    string
		expected RulePosition
	}{
		{"prepend", RulePositionPrepend},
		{"PREPEND", RulePositionPrepend},
		{"Prepend", RulePositionPrepend},
		{"append", RulePositionAppend},
		{"APPEND", RulePositionAppend},
		{"Append", RulePositionAppend},
	}

	for _, tc := range testCases {
		payload := map[string]interface{}{
			"snippets": []interface{}{
				map[string]interface{}{
					"config_type": "RULE",
					"position":    tc.input,
					"content":     `{"uuid": "221f3268-test-uuid"}`,
				},
			},
		}

		rules, err := parseAPIRules(payload)
		if err != nil {
			t.Errorf("Position %q: unexpected error: %v", tc.input, err)
			continue
		}

		if rules[0].Position != tc.expected {
			t.Errorf("Position %q: got %s, want %s", tc.input, rules[0].Position, tc.expected)
		}
	}
}

// TestParseUserContent_RejectsProtectedIdentities is revert-sensitive for the
// SYNC_API protected-identity list: a snippet naming the agent's own
// provisioned users must be rejected at parse time, before any add/set call.
func TestParseUserContent_RejectsProtectedIdentities(t *testing.T) {
	protected := []string{"root", "netdefense-agent", "netdefense-readonly"}

	for _, name := range protected {
		t.Run(name, func(t *testing.T) {
			content := `{"name": "` + name + `", "password": "$2y$hash", "scope": "user"}`
			_, err := parseUserContent(content, nil)
			if err == nil {
				t.Fatalf("parseUserContent(%q) expected error for protected user, got nil", name)
			}
		})
	}

	// Sanity: a non-protected user still parses fine.
	_, err := parseUserContent(`{"name": "regularuser", "password": "$2y$hash", "scope": "user"}`, nil)
	if err != nil {
		t.Errorf("parseUserContent(regularuser) unexpected error: %v", err)
	}
}

// TestParseGroupContent_RejectsProtectedIdentities mirrors the user case for
// group snippets.
func TestParseGroupContent_RejectsProtectedIdentities(t *testing.T) {
	protected := []string{"admins", "netdefense-readonly"}

	for _, name := range protected {
		t.Run(name, func(t *testing.T) {
			content := `{"name": "` + name + `", "description": "test"}`
			_, err := parseGroupContent(content, nil)
			if err == nil {
				t.Fatalf("parseGroupContent(%q) expected error for protected group, got nil", name)
			}
		})
	}

	// Sanity: a non-protected group still parses fine.
	_, err := parseGroupContent(`{"name": "regulargroup", "description": "test"}`, nil)
	if err != nil {
		t.Errorf("parseGroupContent(regulargroup) unexpected error: %v", err)
	}
}

// TestExecuteSyncUsersGroups_OrphanDeleteSkipsProtectedIdentities exercises
// the full SYNC_API orphan-delete phase (5/6) against a fake OPNsense API
// server: netdefense-agent and netdefense-readonly are reported as
// "managed" (tagged) but absent from the desired set, which is exactly the
// orphan-delete trigger condition. If ProtectedUsernames/ProtectedGroupNames
// is reverted, this test fails by observing a DELETE call against the
// provisioned identities.
func TestExecuteSyncUsersGroups_OrphanDeleteSkipsProtectedIdentities(t *testing.T) {
	var userDeleteCalls, groupDeleteCalls []string

	mux := http.NewServeMux()
	mux.HandleFunc("/auth/user/search", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{
			Rows: []map[string]interface{}{
				{
					"uuid":  "user-uuid-1",
					"name":  "netdefense-agent",
					"descr": "NDAgent API user [nd-template:base]",
					"uid":   "1001",
				},
			},
			RowCount: 1,
			Total:    1,
		})
	})
	mux.HandleFunc("/auth/group/search", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{
			Rows: []map[string]interface{}{
				{
					"uuid":        "group-uuid-1",
					"name":        "netdefense-readonly",
					"description": "NDAgent read-only group [nd-template:base]",
					"gid":         "2001",
				},
			},
			RowCount: 1,
			Total:    1,
		})
	})
	mux.HandleFunc("/auth/user/del/", func(w http.ResponseWriter, r *http.Request) {
		userDeleteCalls = append(userDeleteCalls, r.URL.Path)
		_ = json.NewEncoder(w).Encode(opnapi.APIResult{Result: "deleted"})
	})
	mux.HandleFunc("/auth/group/del/", func(w http.ResponseWriter, r *http.Request) {
		groupDeleteCalls = append(groupDeleteCalls, r.URL.Path)
		_ = json.NewEncoder(w).Encode(opnapi.APIResult{Result: "deleted"})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := opnapi.NewClient(server.URL, "key", "secret", true)

	// Empty desired sets: both the protected user and the protected group
	// are "managed but not desired", the exact orphan-delete condition.
	result := executeSyncUsersGroups(context.Background(), client, nil, nil, false, authDeferralInfo{})

	if len(userDeleteCalls) != 0 {
		t.Errorf("expected no user delete calls, got %v (protected user netdefense-agent must never be orphan-deleted)", userDeleteCalls)
	}
	if len(groupDeleteCalls) != 0 {
		t.Errorf("expected no group delete calls, got %v (protected group netdefense-readonly must never be orphan-deleted)", groupDeleteCalls)
	}
	if !result.Success {
		t.Errorf("expected sync to succeed (protected skip is not an error), got errors: %+v", result)
	}
}

// TestExecuteSyncUsersGroups_OrphanDeleteAtZeroDesiredCount reproduces the
// "detach the last USER/GROUP template" scenario: a device carries a
// previously-applied, non-protected managed user and group (e.g. from a
// permissive sync before the template was removed), and the current sync
// carries zero desired users and zero desired groups. executeSyncUsersGroups
// itself has always handled an empty desired set correctly (see
// TestExecuteSyncUsersGroups_OrphanDeleteSkipsProtectedIdentities, which
// calls it directly with nil/nil) -- the bug lived one level up, in
// HandleSyncAPI's now-removed `if len(users) > 0 || len(groups) > 0` gate,
// which skipped calling this function at all when the payload had zero
// user/group entries, so the orphan-delete pass never ran and stale managed
// identities were left stranded on the device. This test guards the
// function-level contract that a future regression (e.g. reintroducing a
// count-based gate anywhere in the call chain) would violate: given a
// zero-count desired set, a pre-existing non-protected managed user/group
// must be deleted, not silently skipped.
func TestExecuteSyncUsersGroups_OrphanDeleteAtZeroDesiredCount(t *testing.T) {
	var userDeleteCalls, groupDeleteCalls []string

	mux := http.NewServeMux()
	mux.HandleFunc("/auth/user/search", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{
			Rows: []map[string]interface{}{
				{
					"uuid":  "user-uuid-1",
					"name":  "svc-monitor",
					"descr": "Monitoring service account [nd-template:base]",
					"uid":   "1005",
				},
			},
			RowCount: 1,
			Total:    1,
		})
	})
	mux.HandleFunc("/auth/group/search", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{
			Rows: []map[string]interface{}{
				{
					"uuid":        "group-uuid-1",
					"name":        "svc-monitors",
					"description": "Monitoring service group [nd-template:base]",
					"gid":         "2005",
				},
			},
			RowCount: 1,
			Total:    1,
		})
	})
	mux.HandleFunc("/auth/user/del/", func(w http.ResponseWriter, r *http.Request) {
		userDeleteCalls = append(userDeleteCalls, r.URL.Path)
		_ = json.NewEncoder(w).Encode(opnapi.APIResult{Result: "deleted"})
	})
	mux.HandleFunc("/auth/group/del/", func(w http.ResponseWriter, r *http.Request) {
		groupDeleteCalls = append(groupDeleteCalls, r.URL.Path)
		_ = json.NewEncoder(w).Encode(opnapi.APIResult{Result: "deleted"})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := opnapi.NewClient(server.URL, "key", "secret", true)

	// Zero desired users and zero desired groups -- the exact payload
	// shape produced by detaching the last USER/GROUP template.
	result := executeSyncUsersGroups(context.Background(), client, nil, nil, false, authDeferralInfo{})

	if len(userDeleteCalls) != 1 || !strings.Contains(userDeleteCalls[0], "user-uuid-1") {
		t.Errorf("expected exactly one delete call for orphaned user user-uuid-1, got %v", userDeleteCalls)
	}
	if len(groupDeleteCalls) != 1 || !strings.Contains(groupDeleteCalls[0], "group-uuid-1") {
		t.Errorf("expected exactly one delete call for orphaned group group-uuid-1, got %v", groupDeleteCalls)
	}
	if !result.Success {
		t.Errorf("expected sync to succeed, got errors: %+v", result.Errors)
	}

	var deletedNames []string
	for _, r := range result.Results {
		if r.Action == "deleted" && r.Status == "success" {
			deletedNames = append(deletedNames, r.Name)
		}
	}
	wantDeleted := []string{"svc-monitor", "svc-monitors"}
	if got, want := sortedCopy(deletedNames), sortedCopy(wantDeleted); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("deleted names = %v, want %v", got, want)
	}
}

func sortedCopy(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

// newUserGroupTestServer stands up a fake OPNsense API that supports the
// create path (empty search results, add always succeeds) executeSyncUsersGroups
// needs. Returns the server plus slices capturing every name passed to
// AddUser/AddGroup, in call order.
func newUserGroupTestServer(t *testing.T) (client *opnapi.Client, addedUsers, addedGroups *[]string) {
	t.Helper()
	var users, groups []string

	mux := http.NewServeMux()
	mux.HandleFunc("/auth/user/search", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{})
	})
	mux.HandleFunc("/auth/group/search", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{})
	})
	mux.HandleFunc("/auth/user/add", func(w http.ResponseWriter, r *http.Request) {
		var wrapper opnapi.UserWrapper
		_ = json.NewDecoder(r.Body).Decode(&wrapper)
		users = append(users, wrapper.User.Name)
		_ = json.NewEncoder(w).Encode(opnapi.SetUserResponse{Result: "saved", UUID: "u-" + wrapper.User.Name})
	})
	mux.HandleFunc("/auth/group/add", func(w http.ResponseWriter, r *http.Request) {
		var wrapper opnapi.GroupWrapper
		_ = json.NewDecoder(r.Body).Decode(&wrapper)
		groups = append(groups, wrapper.Group.Name)
		_ = json.NewEncoder(w).Encode(opnapi.SetGroupResponse{Result: "saved", UUID: "g-" + wrapper.Group.Name})
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	return opnapi.NewClient(server.URL, "key", "secret", true), &users, &groups
}

// TestExecuteSyncUsersGroups_DangerousFieldGate is the revert guard for the
// device-local dangerous-field gate. Table-driven over each dangerous USER
// field individually (mirrors NDManager's producer-side dangerous-field set):
// with the gate OFF, a dangerous user is applied same as any other (no
// regression versus pre-gate behavior); with the gate ON, the dangerous user
// is rejected (never reaches AddUser) while an unrelated safe user in the
// same sync is still applied, the rejection shows up as a telemetry-visible
// "rejected" result, and the overall task result is a FAILED sync (a policy
// rejection is a FAILED task with a clear reason, not a silently-successful
// one with a buried "blocked" item).
func TestExecuteSyncUsersGroups_DangerousFieldGate(t *testing.T) {
	safeUser := opnapi.APIUserPayload{
		Name:     "safe-user",
		Password: "$2y$hash",
		Scope:    "user",
		Shell:    "/usr/sbin/nologin",
	}

	dangerousUsers := []struct {
		field string
		user  opnapi.APIUserPayload
	}{
		{"priv", opnapi.APIUserPayload{Name: "priv-user", Password: "$2y$hash", Scope: "user", Priv: []string{"page-all"}}},
		{"scope", opnapi.APIUserPayload{Name: "scope-user", Password: "$2y$hash", Scope: "system"}},
		{"shell", opnapi.APIUserPayload{Name: "shell-user", Password: "$2y$hash", Scope: "user", Shell: "/bin/sh"}},
		{"authorizedkeys", opnapi.APIUserPayload{Name: "keys-user", Password: "$2y$hash", Scope: "user", AuthorizedKeys: "ssh-ed25519 AAAAtest"}},
	}

	for _, du := range dangerousUsers {
		for _, rejectDangerous := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/reject=%v", du.field, rejectDangerous), func(t *testing.T) {
				client, addedUsers, _ := newUserGroupTestServer(t)

				users := []opnapi.APIUserPayload{safeUser, du.user}
				result := executeSyncUsersGroups(context.Background(), client, users, nil, rejectDangerous, authDeferralInfo{})

				if rejectDangerous {
					if result.Success {
						t.Error("expected failure: a dangerous-field rejection must fail the task")
					}
				} else if !result.Success {
					t.Errorf("expected success (gate off, nothing rejected), got errors: %+v", result.Errors)
				}

				var wantAdded []string
				if rejectDangerous {
					wantAdded = []string{safeUser.Name}
				} else {
					wantAdded = []string{safeUser.Name, du.user.Name}
				}
				if got, want := sortedCopy(*addedUsers), sortedCopy(wantAdded); fmt.Sprint(got) != fmt.Sprint(want) {
					t.Errorf("AddUser calls = %v, want %v", got, want)
				}

				var rejectedNames []string
				for _, r := range result.Results {
					if r.Action == "rejected" {
						rejectedNames = append(rejectedNames, r.Name)
					}
				}
				if rejectDangerous {
					if fmt.Sprint(rejectedNames) != fmt.Sprint([]string{du.user.Name}) {
						t.Errorf("rejected results = %v, want [%s]", rejectedNames, du.user.Name)
					}
					if len(result.Errors) != 1 || !strings.Contains(result.Errors[0], "rejected by local policy reject_dangerous_snippets") {
						t.Errorf("errors = %v, want a policy-rejection message naming reject_dangerous_snippets", result.Errors)
					}
					if !strings.Contains(result.Errors[0], "reject_dangerous_snippets=false") {
						t.Errorf("errors = %v, want the message to name the opt-out (reject_dangerous_snippets=false)", result.Errors)
					}
				} else if len(rejectedNames) != 0 {
					t.Errorf("gate off must never produce a rejected result, got %v", rejectedNames)
				}
			})
		}
	}
}

// TestExecuteSyncUsersGroups_DangerousGroupPrivGate mirrors the USER case
// for GROUP snippets: a group carrying a page-all/all-pages/system-admin
// priv is rejected only when the gate is on, and a safe group in the same
// sync is unaffected either way.
func TestExecuteSyncUsersGroups_DangerousGroupPrivGate(t *testing.T) {
	safeGroup := opnapi.APIGroupPayload{Name: "safe-group", Priv: []string{"page-status-services"}}
	dangerousGroup := opnapi.APIGroupPayload{Name: "dangerous-group", Priv: []string{"page-all"}}

	for _, rejectDangerous := range []bool{false, true} {
		t.Run(fmt.Sprintf("reject=%v", rejectDangerous), func(t *testing.T) {
			client, _, addedGroups := newUserGroupTestServer(t)

			groups := []opnapi.APIGroupPayload{safeGroup, dangerousGroup}
			result := executeSyncUsersGroups(context.Background(), client, nil, groups, rejectDangerous, authDeferralInfo{})

			if rejectDangerous {
				if result.Success {
					t.Error("expected failure: a dangerous-field rejection must fail the task")
				}
			} else if !result.Success {
				t.Errorf("expected success (gate off, nothing rejected), got errors: %+v", result.Errors)
			}

			var wantAdded []string
			if rejectDangerous {
				wantAdded = []string{safeGroup.Name}
			} else {
				wantAdded = []string{safeGroup.Name, dangerousGroup.Name}
			}
			if got, want := sortedCopy(*addedGroups), sortedCopy(wantAdded); fmt.Sprint(got) != fmt.Sprint(want) {
				t.Errorf("AddGroup calls = %v, want %v", got, want)
			}
		})
	}
}

// TestExecuteSyncUsersGroups_DangerousFieldRejectionDoesNotOrphanDeletePreExisting
// locks the "no silent deletion" half of the dangerous-field gate's safety
// contract: a USER/GROUP element that carries a dangerous field is rejected
// (never reaches AddUser/AddGroup/SetUser/SetGroup) but must not be treated
// as absent-from-desired either — a pre-existing managed object of the same
// name has to survive the orphan-delete phase untouched. If the gate ever
// stopped counting a rejected element as "desired" (e.g. by building the
// orphan-delete desired-set from the post-filter applyUsers/applyGroups
// slice instead of the full users/groups slice), this test would observe a
// DELETE call against device state the sync never touched.
func TestExecuteSyncUsersGroups_DangerousFieldRejectionDoesNotOrphanDeletePreExisting(t *testing.T) {
	var userDeleteCalls, groupDeleteCalls []string

	mux := http.NewServeMux()
	mux.HandleFunc("/auth/user/search", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{
			Rows: []map[string]interface{}{
				{
					"uuid":  "user-uuid-1",
					"name":  "priv-user",
					"descr": "svc account [nd-template:base]",
					"uid":   "1001",
				},
			},
			RowCount: 1,
			Total:    1,
		})
	})
	mux.HandleFunc("/auth/group/search", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{
			Rows: []map[string]interface{}{
				{
					"uuid":        "group-uuid-1",
					"name":        "dangerous-group",
					"description": "svc group [nd-template:base]",
					"gid":         "2001",
				},
			},
			RowCount: 1,
			Total:    1,
		})
	})
	mux.HandleFunc("/auth/user/del/", func(w http.ResponseWriter, r *http.Request) {
		userDeleteCalls = append(userDeleteCalls, r.URL.Path)
		_ = json.NewEncoder(w).Encode(opnapi.APIResult{Result: "deleted"})
	})
	mux.HandleFunc("/auth/group/del/", func(w http.ResponseWriter, r *http.Request) {
		groupDeleteCalls = append(groupDeleteCalls, r.URL.Path)
		_ = json.NewEncoder(w).Encode(opnapi.APIResult{Result: "deleted"})
	})
	// Add/Set handlers are wired defensively: if a regression let the
	// rejected element through, the test fails on a clean "wrong calls
	// happened" assertion rather than a 404 from an unhandled route.
	mux.HandleFunc("/auth/user/add", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SetUserResponse{Result: "saved", UUID: "new-user"})
	})
	mux.HandleFunc("/auth/group/add", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SetGroupResponse{Result: "saved", UUID: "new-group"})
	})
	mux.HandleFunc("/auth/user/set/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SetUserResponse{Result: "saved"})
	})
	mux.HandleFunc("/auth/group/set/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SetGroupResponse{Result: "saved"})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := opnapi.NewClient(server.URL, "key", "secret", true)

	// Same names as the pre-existing managed rows above; both carry a
	// dangerous priv so the gate rejects them.
	dangerousUser := opnapi.APIUserPayload{Name: "priv-user", Password: "$2y$hash", Scope: "user", Priv: []string{"page-all"}}
	dangerousGroup := opnapi.APIGroupPayload{Name: "dangerous-group", Priv: []string{"page-all"}}

	result := executeSyncUsersGroups(context.Background(), client,
		[]opnapi.APIUserPayload{dangerousUser},
		[]opnapi.APIGroupPayload{dangerousGroup},
		true, /* gate on */
		authDeferralInfo{},
	)

	if result.Success {
		t.Error("expected failure: a dangerous-field rejection must fail the task")
	}
	if len(userDeleteCalls) != 0 {
		t.Errorf("expected no user delete calls, got %v (pre-existing managed user with a rejected dangerous field must survive the sync)", userDeleteCalls)
	}
	if len(groupDeleteCalls) != 0 {
		t.Errorf("expected no group delete calls, got %v (pre-existing managed group with a rejected dangerous field must survive the sync)", groupDeleteCalls)
	}

	var rejectedNames []string
	for _, r := range result.Results {
		if r.Action == "rejected" {
			rejectedNames = append(rejectedNames, r.Name)
		}
	}
	wantRejected := []string{"dangerous-group", "priv-user"}
	if got := sortedCopy(rejectedNames); fmt.Sprint(got) != fmt.Sprint(wantRejected) {
		t.Errorf("rejected results = %v, want %v", got, wantRejected)
	}
}

// -----------------------------------------------------------------
// GROUP external_members and the
// stale-exclusion deferral, exercised through executeSyncUsersGroups.
// -----------------------------------------------------------------

// TestExecuteSyncUsersGroups_DefersNewUserWhenStale is the revert guard: a
// brand-new USER whose name the AUTH pass could not (yet)
// exclude from every managed directory server never reaches AddUser this
// pass, while an unrelated safe USER in the same sync is created as usual.
func TestExecuteSyncUsersGroups_DefersNewUserWhenStale(t *testing.T) {
	client, addedUsers, _ := newUserGroupTestServer(t)

	safeUser := opnapi.APIUserPayload{Name: "safe-user", Password: "$2y$hash", Scope: "user"}
	staleUser := opnapi.APIUserPayload{Name: "new-admin", Password: "$2y$hash", Scope: "user"}

	auth := authDeferralInfo{Active: true, StaleNames: map[string]bool{"new-admin": true}}
	result := executeSyncUsersGroups(context.Background(), client,
		[]opnapi.APIUserPayload{safeUser, staleUser}, nil, false, auth)

	if got, want := sortedCopy(*addedUsers), []string{"safe-user"}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("AddUser calls = %v, want only %v (the stale name must never reach AddUser)", got, want)
	}

	var deferredNames []string
	for _, r := range result.Results {
		if r.Action == "deferred" {
			deferredNames = append(deferredNames, r.Name)
		}
	}
	if fmt.Sprint(deferredNames) != fmt.Sprint([]string{"new-admin"}) {
		t.Errorf("deferred results = %v, want [new-admin]", deferredNames)
	}

	// Every AUTH result item carries a structured Code a consumer can key
	// on together with Status, never on free-text parsing of Error --
	// this deferral item is no exception, even though
	// until now it existed only inside the free-text Error.
	for _, r := range result.Results {
		if r.Action == "deferred" && r.Code != authCodeUserDeferredExclusionStale {
			t.Errorf("deferred item %q: Code = %q, want %q", r.Name, r.Code, authCodeUserDeferredExclusionStale)
		}
	}

	// A deferral is a policy-driven withholding, same shape as the
	// dangerous-field rejection gate (sync-reject-gates.md): it must FAIL
	// the task with an actionable reason, never report a silent COMPLETED
	// with the withholding buried in the per-item results. It is expected
	// to self-heal on a LATER sync, which is why it is safe to leave
	// FAILED rather than something more drastic -- but this pass must
	// still say so.
	if result.Success {
		t.Error("expected failure (a deferral must fail the task, per sync-reject-gates.md), got success")
	}
	foundErr := false
	for _, e := range result.Errors {
		if strings.Contains(e, "new-admin") && strings.Contains(e, "USER_DEFERRED_EXCLUSION_STALE") {
			foundErr = true
		}
	}
	if !foundErr {
		t.Errorf("errors = %v, want one naming new-admin and USER_DEFERRED_EXCLUSION_STALE", result.Errors)
	}
}

// TestExecuteSyncUsersGroups_ExistingUserUpdateNeverDeferred proves the
// deferral is about NEW identities only: an EXISTING user being merely
// updated is unaffected even if its name is (now) stale-excluded -- there
// is nothing new to shadow, and withholding an update to an already-live
// user would just leave it stale in a different way.
func TestExecuteSyncUsersGroups_ExistingUserUpdateNeverDeferred(t *testing.T) {
	var setCalls []string
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/user/search", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{
			Rows: []map[string]interface{}{
				{"uuid": "u1", "name": "existing-admin", "descr": "[nd-template:base]", "uid": "1000"},
			},
		})
	})
	mux.HandleFunc("/auth/group/search", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{})
	})
	mux.HandleFunc("/auth/user/set/", func(w http.ResponseWriter, r *http.Request) {
		setCalls = append(setCalls, r.URL.Path)
		_ = json.NewEncoder(w).Encode(opnapi.SetUserResponse{Result: "saved"})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := opnapi.NewClient(server.URL, "key", "secret", true)

	auth := authDeferralInfo{Active: true, StaleNames: map[string]bool{"existing-admin": true}}
	result := executeSyncUsersGroups(context.Background(), client,
		[]opnapi.APIUserPayload{{Name: "existing-admin", Scope: "user"}}, nil, false, auth)

	if len(setCalls) != 1 {
		t.Errorf("SetUser calls = %v, want exactly one update (an existing user must never be deferred)", setCalls)
	}
	for _, r := range result.Results {
		if r.Action == "deferred" {
			t.Errorf("unexpected deferred result for an existing user: %+v", r)
		}
	}
}

// TestExecuteSyncUsersGroups_DefersNewGroupMemberWhenStale covers the
// per-member granularity of the deferral: a member-managed GROUP's
// already-live member is re-sent untouched, a brand-new safe member is
// added, and a brand-new stale-named member is withheld and reported --
// all in the same save.
func TestExecuteSyncUsersGroups_DefersNewGroupMemberWhenStale(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/user/search", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{
			Rows: []map[string]interface{}{
				{"uuid": "u1", "name": "existing-user", "uid": "1000"},
				{"uuid": "u2", "name": "new-safe-user", "uid": "1002"},
			},
		})
	})
	mux.HandleFunc("/auth/group/search", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{
			Rows: []map[string]interface{}{
				{"uuid": "g1", "name": "eng", "description": "[nd-template:base]", "gid": "2000", "member": "1000"},
			},
		})
	})
	var setBodies []map[string]interface{}
	mux.HandleFunc("/auth/group/set/", func(w http.ResponseWriter, r *http.Request) {
		var raw map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&raw)
		setBodies = append(setBodies, raw)
		_ = json.NewEncoder(w).Encode(opnapi.SetGroupResponse{Result: "saved"})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := opnapi.NewClient(server.URL, "key", "secret", true)

	auth := authDeferralInfo{Active: true, StaleNames: map[string]bool{"new-stale-user": true}}
	groupPayload := opnapi.APIGroupPayload{
		Name:    "eng",
		Members: []string{"existing-user", "new-safe-user", "new-stale-user"},
	}
	result := executeSyncUsersGroups(context.Background(), client, nil, []opnapi.APIGroupPayload{groupPayload}, false, auth)

	if len(setBodies) == 0 {
		t.Fatal("expected at least one SetGroup call")
	}
	groupRaw, _ := setBodies[0]["group"].(map[string]interface{})
	memberCSV, _ := groupRaw["member"].(string)
	memberUIDs := opnapi.CSVToStrings(memberCSV)
	wantUIDs := map[string]bool{"1000": true, "1002": true}
	if len(memberUIDs) != len(wantUIDs) {
		t.Fatalf("member = %q, want exactly uids 1000 and 1002 (not the stale new member)", memberCSV)
	}
	for _, uid := range memberUIDs {
		if !wantUIDs[uid] {
			t.Errorf("unexpected uid %q in member list %q", uid, memberCSV)
		}
	}

	var deferredNames []string
	for _, r := range result.Results {
		if r.Action == "deferred" {
			deferredNames = append(deferredNames, r.Name)
		}
	}
	if len(deferredNames) != 1 || !strings.Contains(deferredNames[0], "new-stale-user") {
		t.Errorf("deferred results = %v, want exactly one naming new-stale-user", deferredNames)
	}
	for _, r := range result.Results {
		if r.Action == "deferred" && r.Code != authCodeUserDeferredExclusionStale {
			t.Errorf("deferred item %q: Code = %q, want %q", r.Name, r.Code, authCodeUserDeferredExclusionStale)
		}
	}
	if result.Success {
		t.Error("expected failure -- a deferred group member must fail the task, per sync-reject-gates.md")
	}
}

// TestExecuteSyncUsersGroups_ExternalGroupNeverSendsMemberField is the
// full end-to-end version of the opnapi-level unit test: an
// external_members GROUP's create call must never carry a "member" key at
// all on the wire, even though Members is non-empty in the payload
// (defense-in-depth; NDManager's schema is the primary enforcement).
func TestExecuteSyncUsersGroups_ExternalGroupNeverSendsMemberField(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/user/search", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{})
	})
	mux.HandleFunc("/auth/group/search", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{})
	})
	var addBody map[string]interface{}
	mux.HandleFunc("/auth/group/add", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&addBody)
		_ = json.NewEncoder(w).Encode(opnapi.SetGroupResponse{Result: "saved", UUID: "g-eng-external"})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := opnapi.NewClient(server.URL, "key", "secret", true)

	groupPayload := opnapi.APIGroupPayload{
		Name:            "eng-external",
		Members:         []string{"alice"}, // must never reach the wire
		ExternalMembers: true,
	}
	result := executeSyncUsersGroups(context.Background(), client, nil, []opnapi.APIGroupPayload{groupPayload}, false, authDeferralInfo{})

	if !result.Success {
		t.Fatalf("expected success, got errors: %v", result.Errors)
	}
	groupRaw, _ := addBody["group"].(map[string]interface{})
	if _, present := groupRaw["member"]; present {
		t.Errorf("AddGroup body = %+v, want no \"member\" key for an external group", addBody)
	}
	privVal, privPresent := groupRaw["priv"]
	if !privPresent || privVal != "" {
		t.Errorf("AddGroup body priv = %#v (present=%v), want \"\" present", privVal, privPresent)
	}
}

// TestExecuteSyncUsersGroups_ExternalGroupUpdate_CleanMemberNeverRepaired
// is the negative control for the external-GROUP member repair: an existing external
// group whose stored member CSV is already clean must go through the
// plain SetGroup path, unchanged from before the fix -- no repair read,
// no "member" key on the wire. The repair path must never fire for the
// overwhelming majority (healthy) case.
func TestExecuteSyncUsersGroups_ExternalGroupUpdate_CleanMemberNeverRepaired(t *testing.T) {
	var setBodies []map[string]interface{}
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
				{"uuid": "g1", "name": "eng-external", "description": "[nd-template:base]", "gid": "2000", "member": "2004"},
			},
		})
	})
	mux.HandleFunc("/auth/group/set/", func(w http.ResponseWriter, r *http.Request) {
		var raw map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&raw)
		setBodies = append(setBodies, raw)
		_ = json.NewEncoder(w).Encode(opnapi.SetGroupResponse{Result: "saved"})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := opnapi.NewClient(server.URL, "key", "secret", true)

	groupPayload := opnapi.APIGroupPayload{Name: "eng-external", ExternalMembers: true, Priv: []string{"page-status-interfaces"}}
	result := executeSyncUsersGroups(context.Background(), client, nil, []opnapi.APIGroupPayload{groupPayload}, false, authDeferralInfo{})

	if !result.Success {
		t.Fatalf("expected success, got errors: %v", result.Errors)
	}
	if len(setBodies) != 1 {
		t.Fatalf("SetGroup calls = %d, want exactly 1", len(setBodies))
	}
	groupRaw, _ := setBodies[0]["group"].(map[string]interface{})
	if _, present := groupRaw["member"]; present {
		t.Errorf("body = %+v, want no \"member\" key when the stored value was already clean", setBodies[0])
	}
}

// TestExecuteSyncUsersGroups_ExternalGroupUpdate_RepairsEmptyTokenArtifact
// is the repro-and-fix proof for an external group whose stored `member`
// carries a leading-comma empty-token artifact (",2004" instead of
// "2004"). That exact shape arises from ANY link into a group whose
// stored `<member>` is present-but-empty -- most simply, a brand-new
// external group's very first directory login (its `<member>` starts
// empty, since NDAgent never sends one for an external group either), not
// only a revoke-immediately-followed-by-restore cycle. Before this fix,
// that artifact fails EVERY subsequent SetGroup call forever with
// OPNsense's own "validation failed: {\"group.member\":\"Option [] not
// in list.\"}", because OPNsense revalidates the group's full,
// already-poisoned stored state on every update, regardless of what
// NDAgent's own request body contains. With the fix, the sync succeeds:
// NDAgent detects the artifact from a fresh read, sends an explicit
// sanitized `member` that repairs it (without adding or removing the
// real member, uid 2004), and the task reports success.
func TestExecuteSyncUsersGroups_ExternalGroupUpdate_RepairsEmptyTokenArtifact(t *testing.T) {
	var setBodies []map[string]interface{}
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
				// The bad stored shape: a link into a present-but-empty
				// <member> (a fresh group's first login, or a
				// revoke-then-restore cycle) leaves a LEADING COMMA, not
				// a clean "2004".
				{"uuid": "g1", "name": "eng-external", "description": "[nd-template:base]", "gid": "2000", "member": ",2004"},
			},
		})
	})
	mux.HandleFunc("/auth/group/set/", func(w http.ResponseWriter, r *http.Request) {
		var raw map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&raw)
		setBodies = append(setBodies, raw)
		// A real OPNsense would reject a request that omits `member` here
		// with the leading-comma validation error, because it revalidates the
		// STORED (poisoned) value regardless of the request body. This
		// mock instead asserts directly on what NDAgent actually sent,
		// which is the reproducible, code-level claim this test needs.
		_ = json.NewEncoder(w).Encode(opnapi.SetGroupResponse{Result: "saved"})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := opnapi.NewClient(server.URL, "key", "secret", true)

	groupPayload := opnapi.APIGroupPayload{Name: "eng-external", ExternalMembers: true, Priv: []string{"page-status-interfaces"}}
	result := executeSyncUsersGroups(context.Background(), client, nil, []opnapi.APIGroupPayload{groupPayload}, false, authDeferralInfo{})

	if !result.Success {
		t.Fatalf("expected success (the whole point of the fix), got errors: %v", result.Errors)
	}
	if len(setBodies) != 1 {
		t.Fatalf("SetGroup/RepairGroupMember calls = %d, want exactly 1", len(setBodies))
	}
	groupRaw, _ := setBodies[0]["group"].(map[string]interface{})
	memberVal, present := groupRaw["member"]
	if !present {
		t.Fatalf("body = %+v, want an explicit \"member\" key to repair the poisoned value", setBodies[0])
	}
	if memberVal != "2004" {
		t.Errorf("member = %v, want the sanitized \"2004\" -- the real member uid, artifact-free, never invented and never dropped", memberVal)
	}
	if groupRaw["priv"] != "page-status-interfaces" {
		t.Errorf("priv = %v, want the ordinary update's priv carried through unchanged by the repair", groupRaw["priv"])
	}
}

// TestExecuteSyncUsersGroups_ExternalGroupUpdate_RepairsStaleUID covers the
// second, independent artifact: a stored member CSV can also name a uid
// whose user was deleted (UserController::delAction never scrubs other
// groups' member CSV), which fails the same "Option [<uid>] not in
// list." validation forever, even with no empty token at all. The repair
// must drop only the stale uid (2999, no matching user) and keep the
// still-current one (2004) untouched.
func TestExecuteSyncUsersGroups_ExternalGroupUpdate_RepairsStaleUID(t *testing.T) {
	var setBodies []map[string]interface{}
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
				// 2999 has no matching user row above -- its owner was
				// deleted without OPNsense scrubbing this group.
				{"uuid": "g1", "name": "eng-external", "description": "[nd-template:base]", "gid": "2000", "member": "2004,2999"},
			},
		})
	})
	mux.HandleFunc("/auth/group/set/", func(w http.ResponseWriter, r *http.Request) {
		var raw map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&raw)
		setBodies = append(setBodies, raw)
		_ = json.NewEncoder(w).Encode(opnapi.SetGroupResponse{Result: "saved"})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := opnapi.NewClient(server.URL, "key", "secret", true)

	groupPayload := opnapi.APIGroupPayload{Name: "eng-external", ExternalMembers: true, Priv: []string{"page-status-interfaces"}}
	result := executeSyncUsersGroups(context.Background(), client, nil, []opnapi.APIGroupPayload{groupPayload}, false, authDeferralInfo{})

	if !result.Success {
		t.Fatalf("expected success, got errors: %v", result.Errors)
	}
	if len(setBodies) != 1 {
		t.Fatalf("SetGroup/RepairGroupMember calls = %d, want exactly 1", len(setBodies))
	}
	groupRaw, _ := setBodies[0]["group"].(map[string]interface{})
	memberVal, present := groupRaw["member"]
	if !present {
		t.Fatalf("body = %+v, want an explicit \"member\" key to repair the stale uid", setBodies[0])
	}
	if memberVal != "2004" {
		t.Errorf("member = %v, want the stale uid 2999 dropped and the current uid 2004 kept", memberVal)
	}
}

// TestExecuteSyncUsersGroups_ExternalGroupUpdate_SearchErrorFailsOpen
// covers updateExternalGroup's fail-open branch: if the fresh member read
// itself fails (transport/decode error, not just a "group not found"),
// the update must still go through as a plain SetGroup with no "member"
// key -- the repair is a bonus recovery path, never a precondition for an
// otherwise-healthy update.
func TestExecuteSyncUsersGroups_ExternalGroupUpdate_SearchErrorFailsOpen(t *testing.T) {
	var setBodies []map[string]interface{}
	groupSearchCalls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/user/search", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{})
	})
	mux.HandleFunc("/auth/group/search", func(w http.ResponseWriter, r *http.Request) {
		groupSearchCalls++
		if groupSearchCalls == 1 {
			// Phase 1's ListAllGroups call -- needs to find the group so
			// the update path is taken at all.
			_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{
				Rows: []map[string]interface{}{
					{"uuid": "g1", "name": "eng-external", "description": "[nd-template:base]", "gid": "2000", "member": "2004"},
				},
			})
			return
		}
		// updateExternalGroup's own fresh read fails.
		w.WriteHeader(http.StatusInternalServerError)
	})
	mux.HandleFunc("/auth/group/set/", func(w http.ResponseWriter, r *http.Request) {
		var raw map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&raw)
		setBodies = append(setBodies, raw)
		_ = json.NewEncoder(w).Encode(opnapi.SetGroupResponse{Result: "saved"})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := opnapi.NewClient(server.URL, "key", "secret", true)

	groupPayload := opnapi.APIGroupPayload{Name: "eng-external", ExternalMembers: true, Priv: []string{"page-status-interfaces"}}
	result := executeSyncUsersGroups(context.Background(), client, nil, []opnapi.APIGroupPayload{groupPayload}, false, authDeferralInfo{})

	if !result.Success {
		t.Fatalf("expected success (fail-open), got errors: %v", result.Errors)
	}
	if len(setBodies) != 1 {
		t.Fatalf("SetGroup calls = %d, want exactly 1", len(setBodies))
	}
	groupRaw, _ := setBodies[0]["group"].(map[string]interface{})
	if _, present := groupRaw["member"]; present {
		t.Errorf("body = %+v, want no \"member\" key when the repair's own read failed", setBodies[0])
	}
}
