package opnapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	alias := Alias{
		Enabled:     "1",
		Name:        "TestAlias",
		Type:        "host",
		Content:     "example.com",
		Description: "Test description",
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

func TestSearchRules(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return mock response
		resp := SearchResponse{
			Rows: []map[string]interface{}{
				{"uuid": "221f3268-0002-4abc-9001-000000000001", "description": "TestRule"},
			},
			RowCount: 1,
			Total:    1,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "testkey", "testsecret", true)
	rules, err := client.SearchRules(context.Background(), "221f3268")

	if err != nil {
		t.Fatalf("SearchRules() error = %v", err)
	}
	if len(rules) != 1 {
		t.Errorf("len(rules) = %d, want 1", len(rules))
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
	rule := Rule{
		Enabled:        "1",
		Sequence:       "100",
		Action:         "pass",
		Interface:      "lan",
		Direction:      "in",
		IPProtocol:     "inet",
		Protocol:       "TCP",
		SourceNet:      "any",
		DestinationNet: "any",
		Description:    "Test rule",
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
