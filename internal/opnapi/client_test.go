package opnapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewClient(t *testing.T) {
	client := NewClient("https://example.com/api", "testkey", "testsecret", true)

	if client == nil {
		t.Fatal("NewClient returned nil")
	}
	if client.baseURL != "https://example.com/api" {
		t.Errorf("baseURL = %s, want https://example.com/api", client.baseURL)
	}
	if client.apiKey != "testkey" {
		t.Errorf("apiKey = %s, want testkey", client.apiKey)
	}
	if client.apiSecret != "testsecret" {
		t.Errorf("apiSecret = %s, want testsecret", client.apiSecret)
	}
}

func TestSearchAliases(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify method
		if r.Method != "POST" {
			t.Errorf("Method = %s, want POST", r.Method)
		}

		// Verify path
		if r.URL.Path != "/firewall/alias/searchItem" {
			t.Errorf("Path = %s, want /firewall/alias/searchItem", r.URL.Path)
		}

		// Verify Basic Auth
		user, pass, ok := r.BasicAuth()
		if !ok {
			t.Error("Expected Basic Auth")
		}
		if user != "testkey" || pass != "testsecret" {
			t.Errorf("Auth = %s:%s, want testkey:testsecret", user, pass)
		}

		// Verify Content-Type
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %s, want application/json", r.Header.Get("Content-Type"))
		}

		// Return mock response
		resp := SearchResponse{
			Rows: []map[string]interface{}{
				{"uuid": "221f3268-0001-4abc-9001-000000000001", "name": "TestAlias"},
			},
			RowCount: 1,
			Total:    1,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "testkey", "testsecret", true)
	aliases, err := client.SearchAliases(context.Background(), "221f3268")

	if err != nil {
		t.Fatalf("SearchAliases() error = %v", err)
	}
	if len(aliases) != 1 {
		t.Errorf("len(aliases) = %d, want 1", len(aliases))
	}
	if aliases[0]["name"] != "TestAlias" {
		t.Errorf("aliases[0][name] = %v, want TestAlias", aliases[0]["name"])
	}
}

func TestSetAlias(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify path contains UUID
		if r.URL.Path != "/firewall/alias/setItem/221f3268-0001-4abc-9001-000000000001" {
			t.Errorf("Path = %s, want /firewall/alias/setItem/221f3268-0001-4abc-9001-000000000001", r.URL.Path)
		}

		// Return success
		resp := APIResult{Result: "saved"}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "testkey", "testsecret", true)
	alias := map[string]string{
		"enabled":     "1",
		"name":        "TestAlias",
		"type":        "host",
		"content":     "example.com",
		"description": "Test description",
	}

	err := client.SetAlias(context.Background(), "221f3268-0001-4abc-9001-000000000001", alias)
	if err != nil {
		t.Fatalf("SetAlias() error = %v", err)
	}
}

func TestDeleteAlias(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return success
		resp := APIResult{Result: "deleted"}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "testkey", "testsecret", true)
	err := client.DeleteAlias(context.Background(), "221f3268-0001-4abc-9001-000000000001")
	if err != nil {
		t.Fatalf("DeleteAlias() error = %v", err)
	}
}

// TestListAllRules_ReadsEveryPage pins the paging: one unfiltered search,
// page by page in pages small enough to arrive intact, until a short page.
func TestListAllRules_ReadsEveryPage(t *testing.T) {
	const total = 95
	var requests []map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		requests = append(requests, req)

		page := int(req["current"].(float64))
		size := int(req["rowCount"].(float64))
		var rows []map[string]interface{}
		for i := (page - 1) * size; i < page*size && i < total; i++ {
			rows = append(rows, map[string]interface{}{"uuid": fmt.Sprintf("221f3268-0002-4abc-9001-%012d", i)})
		}
		_ = json.NewEncoder(w).Encode(SearchResponse{Rows: rows, RowCount: len(rows), Total: total})
	}))
	defer server.Close()

	rules, err := NewClient(server.URL, "testkey", "testsecret", true).ListAllRules(context.Background())
	if err != nil {
		t.Fatalf("ListAllRules() error = %v", err)
	}
	if len(rules) != total {
		t.Errorf("len(rules) = %d, want %d", len(rules), total)
	}
	if len(requests) != 3 {
		t.Fatalf("requests = %d, want 3 pages of %d", len(requests), ruleSearchPageSize)
	}
	for i, req := range requests {
		if req["current"] != float64(i+1) || req["rowCount"] != float64(ruleSearchPageSize) {
			t.Errorf("request %d = %v", i, req)
		}
		if _, filtered := req["interface"]; filtered {
			t.Errorf("request %d carries an interface filter: %v", i, req)
		}
	}
}

// TestListAllRules_StopsWhenAPageAddsNothing: a device that ignores the page
// number answers the first page again; the search ends there rather than
// asking for every page up to the limit.
func TestListAllRules_StopsWhenAPageAddsNothing(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		var rows []map[string]interface{}
		for i := 0; i < ruleSearchPageSize; i++ {
			rows = append(rows, map[string]interface{}{"uuid": fmt.Sprintf("221f3268-0002-4abc-9001-%012d", i)})
		}
		_ = json.NewEncoder(w).Encode(SearchResponse{Rows: rows, RowCount: len(rows), Total: 1000})
	}))
	defer server.Close()

	rules, err := NewClient(server.URL, "testkey", "testsecret", true).ListAllRules(context.Background())
	if err != nil {
		t.Fatalf("ListAllRules() error = %v", err)
	}
	if len(rules) != ruleSearchPageSize || requests != 2 {
		t.Errorf("rules = %d after %d requests, want the %d rows of the first page after 2", len(rules), requests, ruleSearchPageSize)
	}
}

// TestListAllRules_EndsOnTheRowsNotTheTotal: the search ends at a short or
// empty page, whatever total the device reports: a missing or stale total
// must not cut the list short.
func TestListAllRules_EndsOnTheRowsNotTheTotal(t *testing.T) {
	cases := []struct {
		name         string
		rows, total  int
		wantRequests int
	}{
		{"an exact multiple of the page size", 80, 80, 3},
		{"one full page", 40, 40, 2},
		{"no rules", 0, 0, 1},
		{"no total", 95, 0, 3},
		{"a total too small", 95, 50, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				var req map[string]interface{}
				_ = json.NewDecoder(r.Body).Decode(&req)
				page, size := int(req["current"].(float64)), int(req["rowCount"].(float64))
				var rows []map[string]interface{}
				for i := (page - 1) * size; i < page*size && i < tc.rows; i++ {
					rows = append(rows, map[string]interface{}{"uuid": fmt.Sprintf("221f3268-0002-4abc-9001-%012d", i)})
				}
				_ = json.NewEncoder(w).Encode(SearchResponse{Rows: rows, RowCount: len(rows), Total: tc.total})
			}))
			defer server.Close()

			rules, err := NewClient(server.URL, "testkey", "testsecret", true).ListAllRules(context.Background())
			if err != nil {
				t.Fatalf("ListAllRules() error = %v", err)
			}
			if len(rules) != tc.rows || requests != tc.wantRequests {
				t.Errorf("rules = %d after %d requests, want %d after %d", len(rules), requests, tc.rows, tc.wantRequests)
			}
		})
	}
}

// TestToggleRule: toggleRule/<uuid>/<0|1> answers the state it set, and
// "failed" for a uuid the device does not hold, which it never creates.
func TestToggleRule(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		if strings.Contains(r.URL.Path, "missing") {
			_ = json.NewEncoder(w).Encode(APIResult{Result: "failed"})
			return
		}
		_ = json.NewEncoder(w).Encode(APIResult{Result: "Disabled"})
	}))
	defer server.Close()
	client := NewClient(server.URL, "testkey", "testsecret", true)

	if err := client.ToggleRule(context.Background(), "221f3268-0002-4abc-9001-000000000001", false); err != nil {
		t.Errorf("disable: %v", err)
	}
	if err := client.ToggleRule(context.Background(), "missing", false); err == nil {
		t.Error("a uuid the device does not hold was toggled")
	}
	if err := client.ToggleRule(context.Background(), "221f3268-0002-4abc-9001-000000000001", true); err == nil {
		t.Error("an enable answered Disabled was taken as done")
	}
	if want := "POST /firewall/filter/toggleRule/221f3268-0002-4abc-9001-000000000001/0"; len(paths) == 0 || paths[0] != want {
		t.Errorf("requests = %v, want %s first", paths, want)
	}
}

func TestSetRule(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return success
		resp := APIResult{Result: "saved"}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "testkey", "testsecret", true)
	rule := map[string]string{
		"enabled":         "1",
		"sequence":        "100",
		"action":          "pass",
		"interface":       "lan",
		"direction":       "in",
		"ipprotocol":      "inet",
		"protocol":        "TCP",
		"source_net":      "any",
		"destination_net": "any",
		"description":     "Test rule",
	}

	err := client.SetRule(context.Background(), "221f3268-0002-4abc-9001-000000000001", rule)
	if err != nil {
		t.Fatalf("SetRule() error = %v", err)
	}
}

func TestAPIError(t *testing.T) {
	// Create mock server that returns an error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message": "Invalid credentials"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "badkey", "badsecret", true)
	_, err := client.SearchAliases(context.Background(), "test")

	if err == nil {
		t.Error("Expected error for unauthorized request")
	}
}
