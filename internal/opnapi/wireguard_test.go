package opnapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSearchServers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/wireguard/server/search_server" {
			t.Errorf("Path = %s, want /wireguard/server/search_server", r.URL.Path)
		}

		var req WireGuardSearchRequest
		json.NewDecoder(r.Body).Decode(&req)
		if req.SearchPhrase != "nd-vpn__" {
			t.Errorf("SearchPhrase = %s, want nd-vpn__", req.SearchPhrase)
		}
		if req.RowCount != -1 {
			t.Errorf("RowCount = %d, want -1", req.RowCount)
		}

		resp := SearchResponse{
			Rows: []map[string]interface{}{
				{"uuid": "abc-123", "name": "nd-vpn__site1"},
				{"uuid": "def-456", "name": "nd-vpn__site2"},
			},
			RowCount: 2,
			Total:    2,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "testkey", "testsecret", true)
	results, err := client.SearchServers(context.Background(), "nd-vpn__")

	if err != nil {
		t.Fatalf("SearchServers() error = %v", err)
	}
	if len(results) != 2 {
		t.Errorf("len(results) = %d, want 2", len(results))
	}
}

func TestSearchClients(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/wireguard/client/search_client" {
			t.Errorf("Path = %s, want /wireguard/client/search_client", r.URL.Path)
		}

		resp := SearchResponse{
			Rows: []map[string]interface{}{
				{"uuid": "peer-1", "name": "nd-vpn__site1__peer-a"},
			},
			RowCount: 1,
			Total:    1,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "testkey", "testsecret", true)
	results, err := client.SearchClients(context.Background(), "nd-vpn__")

	if err != nil {
		t.Fatalf("SearchClients() error = %v", err)
	}
	if len(results) != 1 {
		t.Errorf("len(results) = %d, want 1", len(results))
	}
}

func TestAddServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/wireguard/server/add_server" {
			t.Errorf("Path = %s, want /wireguard/server/add_server", r.URL.Path)
		}

		var wrapper WireGuardServerWrapper
		json.NewDecoder(r.Body).Decode(&wrapper)
		if wrapper.Server.Name != "nd-vpn__test" {
			t.Errorf("Server.Name = %s, want nd-vpn__test", wrapper.Server.Name)
		}

		resp := WireGuardAddResponse{
			Result: "saved",
			UUID:   "new-uuid-123",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "testkey", "testsecret", true)
	uuid, err := client.AddServer(context.Background(), WireGuardServer{
		Enabled: "1",
		Name:    "nd-vpn__test",
		Port:    "51820",
	})

	if err != nil {
		t.Fatalf("AddServer() error = %v", err)
	}
	if uuid != "new-uuid-123" {
		t.Errorf("uuid = %s, want new-uuid-123", uuid)
	}
}

func TestSetServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/wireguard/server/set_server/existing-uuid" {
			t.Errorf("Path = %s, want /wireguard/server/set_server/existing-uuid", r.URL.Path)
		}

		resp := WireGuardAddResponse{Result: "saved"}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "testkey", "testsecret", true)
	err := client.SetServer(context.Background(), "existing-uuid", WireGuardServer{
		Enabled: "1",
		Name:    "nd-vpn__test",
	})

	if err != nil {
		t.Fatalf("SetServer() error = %v", err)
	}
}

func TestDeleteServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/wireguard/server/del_server/del-uuid" {
			t.Errorf("Path = %s, want /wireguard/server/del_server/del-uuid", r.URL.Path)
		}

		resp := APIResult{Result: "deleted"}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "testkey", "testsecret", true)
	err := client.DeleteServer(context.Background(), "del-uuid")

	if err != nil {
		t.Fatalf("DeleteServer() error = %v", err)
	}
}

func TestAddClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/wireguard/client/add_client" {
			t.Errorf("Path = %s, want /wireguard/client/add_client", r.URL.Path)
		}

		var wrapper WireGuardClientWrapper
		json.NewDecoder(r.Body).Decode(&wrapper)
		if wrapper.Client.Name != "nd-vpn__test__peer1" {
			t.Errorf("Client.Name = %s, want nd-vpn__test__peer1", wrapper.Client.Name)
		}
		if wrapper.Client.Servers != "server-uuid-1" {
			t.Errorf("Client.Servers = %s, want server-uuid-1", wrapper.Client.Servers)
		}

		resp := WireGuardAddResponse{
			Result: "saved",
			UUID:   "client-uuid-1",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "testkey", "testsecret", true)
	uuid, err := client.AddClient(context.Background(), WireGuardClient{
		Enabled: "1",
		Name:    "nd-vpn__test__peer1",
		PubKey:  "base64pubkey==",
		Servers: "server-uuid-1",
	})

	if err != nil {
		t.Fatalf("AddClient() error = %v", err)
	}
	if uuid != "client-uuid-1" {
		t.Errorf("uuid = %s, want client-uuid-1", uuid)
	}
}

func TestSetClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/wireguard/client/set_client/client-uuid" {
			t.Errorf("Path = %s, want /wireguard/client/set_client/client-uuid", r.URL.Path)
		}

		resp := WireGuardAddResponse{Result: "saved"}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "testkey", "testsecret", true)
	err := client.SetClient(context.Background(), "client-uuid", WireGuardClient{
		Enabled: "1",
		Name:    "nd-vpn__test__peer1",
	})

	if err != nil {
		t.Fatalf("SetClient() error = %v", err)
	}
}

func TestDeleteClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/wireguard/client/del_client/client-uuid" {
			t.Errorf("Path = %s, want /wireguard/client/del_client/client-uuid", r.URL.Path)
		}

		resp := APIResult{Result: "deleted"}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "testkey", "testsecret", true)
	err := client.DeleteClient(context.Background(), "client-uuid")

	if err != nil {
		t.Fatalf("DeleteClient() error = %v", err)
	}
}

func TestReconfigureWireGuard(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/wireguard/service/reconfigure" {
			t.Errorf("Path = %s, want /wireguard/service/reconfigure", r.URL.Path)
		}

		resp := APIResult{Result: "ok"}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "testkey", "testsecret", true)
	err := client.ReconfigureWireGuard(context.Background())

	if err != nil {
		t.Fatalf("ReconfigureWireGuard() error = %v", err)
	}
}

func TestFilterManagedWireGuardServers(t *testing.T) {
	servers := []map[string]interface{}{
		{"uuid": "aaa", "name": "nd-vpn__managed1"},
		{"uuid": "bbb", "name": "manual-server"},
		{"uuid": "ccc", "name": "nd-vpn__managed2"},
		{"uuid": "ddd", "name": "other-server"},
	}

	managed := FilterManagedWireGuardServers(servers)

	if len(managed) != 2 {
		t.Fatalf("len(managed) = %d, want 2", len(managed))
	}
	if managed[0]["name"] != "nd-vpn__managed1" {
		t.Errorf("managed[0][name] = %v, want nd-vpn__managed1", managed[0]["name"])
	}
	if managed[1]["name"] != "nd-vpn__managed2" {
		t.Errorf("managed[1][name] = %v, want nd-vpn__managed2", managed[1]["name"])
	}
}

func TestFilterManagedWireGuardClients(t *testing.T) {
	clients := []map[string]interface{}{
		{"uuid": "aaa", "name": "nd-vpn__net__peer1"},
		{"uuid": "bbb", "name": "manual-peer"},
	}

	managed := FilterManagedWireGuardClients(clients)

	if len(managed) != 1 {
		t.Fatalf("len(managed) = %d, want 1", len(managed))
	}
	if managed[0]["name"] != "nd-vpn__net__peer1" {
		t.Errorf("managed[0][name] = %v, want nd-vpn__net__peer1", managed[0]["name"])
	}
}

func TestFilterManagedWireGuardServersEmpty(t *testing.T) {
	servers := []map[string]interface{}{
		{"uuid": "aaa", "name": "manual-server"},
	}

	managed := FilterManagedWireGuardServers(servers)

	if len(managed) != 0 {
		t.Errorf("len(managed) = %d, want 0", len(managed))
	}
}

func TestFilterManagedWireGuardServersNil(t *testing.T) {
	managed := FilterManagedWireGuardServers(nil)

	if managed != nil {
		t.Errorf("expected nil, got %v", managed)
	}
}

func TestDeriveWireGuardPublicKey(t *testing.T) {
	// Known test vector: private key → public key (verified with Go's curve25519)
	privKey := "YAnezQfXMJPGbZhHJJwLaBZWGmJMMJoQdS0JA35Oyms="
	expectedPub := "W8jjUb/godh7igKYGB6myrpQKtWRU2uwEs5MuCRSWSk="

	pubKey, err := DeriveWireGuardPublicKey(privKey)
	if err != nil {
		t.Fatalf("DeriveWireGuardPublicKey() error = %v", err)
	}
	if pubKey != expectedPub {
		t.Errorf("pubKey = %s, want %s", pubKey, expectedPub)
	}
}

func TestDeriveWireGuardPublicKeyInvalidBase64(t *testing.T) {
	_, err := DeriveWireGuardPublicKey("not-valid-base64!!!")
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}

func TestDeriveWireGuardPublicKeyWrongLength(t *testing.T) {
	_, err := DeriveWireGuardPublicKey("dG9vc2hvcnQ=") // "tooshort"
	if err == nil {
		t.Error("expected error for wrong key length")
	}
}

func TestBuildServerName(t *testing.T) {
	tests := []struct {
		network string
		want    string
	}{
		{"site-to-site", "nd-vpn__site-to-site"},
		{"hq", "nd-vpn__hq"},
		{"branch.office", "nd-vpn__branch.office"},
	}

	for _, tt := range tests {
		got := BuildServerName(tt.network)
		if got != tt.want {
			t.Errorf("BuildServerName(%q) = %q, want %q", tt.network, got, tt.want)
		}
	}
}

func TestBuildClientName(t *testing.T) {
	tests := []struct {
		network string
		peer    string
		want    string
	}{
		{"site-to-site", "branch-01", "nd-vpn__site-to-site__branch-01"},
		{"hq", "peer1", "nd-vpn__hq__peer1"},
	}

	for _, tt := range tests {
		got := BuildClientName(tt.network, tt.peer)
		if got != tt.want {
			t.Errorf("BuildClientName(%q, %q) = %q, want %q", tt.network, tt.peer, got, tt.want)
		}
	}
}

func TestAddServerValidationError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := WireGuardAddResponse{
			Result:           "failed",
			ValidationErrors: FlexibleValidation{Message: "name is required"},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "testkey", "testsecret", true)
	_, err := client.AddServer(context.Background(), WireGuardServer{})

	if err == nil {
		t.Error("expected error for validation failure")
	}
}

func TestAddClientValidationError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := WireGuardAddResponse{
			Result:           "failed",
			ValidationErrors: FlexibleValidation{Message: "pubkey is required"},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "testkey", "testsecret", true)
	_, err := client.AddClient(context.Background(), WireGuardClient{})

	if err == nil {
		t.Error("expected error for validation failure")
	}
}
