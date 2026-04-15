package opnapi

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"golang.org/x/crypto/curve25519"
)

// NDAgentWireGuardPrefix marks all NDAgent-managed WireGuard resources.
// Since OPNsense ignores custom UUIDs for WireGuard, we identify managed
// resources by name prefix instead.
const NDAgentWireGuardPrefix = "nd-vpn__"

// WireGuardServer represents a WireGuard server for create/update API calls.
type WireGuardServer struct {
	Enabled       string `json:"enabled"`
	Name          string `json:"name"`
	PubKey        string `json:"pubkey"`
	PrivKey       string `json:"privkey"`
	Port          string `json:"port"`
	TunnelAddress string `json:"tunneladdress"`
	MTU           string `json:"mtu"`
	DNS           string `json:"dns"`
	DisableRoutes string `json:"disableroutes"`
	Gateway       string `json:"gateway"`
}

// WireGuardServerWrapper wraps a server for API operations.
type WireGuardServerWrapper struct {
	Server WireGuardServer `json:"server"`
}

// WireGuardClient represents a WireGuard client/peer for create/update API calls.
type WireGuardClient struct {
	Enabled       string `json:"enabled"`
	Name          string `json:"name"`
	PubKey        string `json:"pubkey"`
	PSK           string `json:"psk"`
	TunnelAddress string `json:"tunneladdress"`
	ServerAddress string `json:"serveraddress"`
	ServerPort    string `json:"serverport"`
	KeepAlive     string `json:"keepalive"`
	Servers       string `json:"servers"`
}

// WireGuardClientWrapper wraps a client for API operations.
type WireGuardClientWrapper struct {
	Client WireGuardClient `json:"client"`
}

// WireGuardAddResponse is the response from add_server/add_client endpoints.
type WireGuardAddResponse struct {
	Result           string             `json:"result"`
	UUID             string             `json:"uuid"`
	ValidationErrors FlexibleValidation `json:"validations,omitempty"`
}

// WireGuardSearchRequest is the request body for WireGuard search endpoints.
// WireGuard uses current/rowCount pagination unlike the simpler firewall search.
type WireGuardSearchRequest struct {
	SearchPhrase string `json:"searchPhrase"`
	Current      int    `json:"current"`
	RowCount     int    `json:"rowCount"`
}

// SearchServers searches for WireGuard servers matching the search phrase.
func (c *Client) SearchServers(ctx context.Context, searchPhrase string) ([]map[string]interface{}, error) {
	req := WireGuardSearchRequest{
		SearchPhrase: searchPhrase,
		Current:      1,
		RowCount:     -1, // Return all results
	}

	respBody, err := c.doRequest(ctx, "POST", "/wireguard/server/search_server", req)
	if err != nil {
		return nil, err
	}

	var resp SearchResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse search response: %w", err)
	}

	c.log.Debugw("SearchServers completed",
		"search_phrase", searchPhrase,
		"count", len(resp.Rows),
	)

	return resp.Rows, nil
}

// SearchClients searches for WireGuard clients matching the search phrase.
func (c *Client) SearchClients(ctx context.Context, searchPhrase string) ([]map[string]interface{}, error) {
	req := WireGuardSearchRequest{
		SearchPhrase: searchPhrase,
		Current:      1,
		RowCount:     -1,
	}

	respBody, err := c.doRequest(ctx, "POST", "/wireguard/client/search_client", req)
	if err != nil {
		return nil, err
	}

	var resp SearchResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse search response: %w", err)
	}

	c.log.Debugw("SearchClients completed",
		"search_phrase", searchPhrase,
		"count", len(resp.Rows),
	)

	return resp.Rows, nil
}

// AddServer creates a new WireGuard server and returns the OPNsense-assigned UUID.
func (c *Client) AddServer(ctx context.Context, server WireGuardServer) (string, error) {
	wrapper := WireGuardServerWrapper{Server: server}

	respBody, err := c.doRequest(ctx, "POST", "/wireguard/server/add_server", wrapper)
	if err != nil {
		return "", err
	}

	var result WireGuardAddResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if result.Result != "saved" {
		if result.ValidationErrors.HasErrors() {
			return "", fmt.Errorf("validation failed: %s", result.ValidationErrors.String())
		}
		return "", fmt.Errorf("unexpected result: %s (response: %s)", result.Result, string(respBody))
	}

	c.log.Debugw("AddServer completed",
		"uuid", result.UUID,
		"name", server.Name,
	)

	return result.UUID, nil
}

// SetServer updates an existing WireGuard server.
func (c *Client) SetServer(ctx context.Context, uuid string, server WireGuardServer) error {
	path := fmt.Sprintf("/wireguard/server/set_server/%s", uuid)
	wrapper := WireGuardServerWrapper{Server: server}

	respBody, err := c.doRequest(ctx, "POST", path, wrapper)
	if err != nil {
		return err
	}

	var result WireGuardAddResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if result.Result != "saved" {
		if result.ValidationErrors.HasErrors() {
			return fmt.Errorf("validation failed: %s", result.ValidationErrors.String())
		}
		return fmt.Errorf("unexpected result: %s (response: %s)", result.Result, string(respBody))
	}

	c.log.Debugw("SetServer completed",
		"uuid", uuid,
		"name", server.Name,
	)

	return nil
}

// DeleteServer deletes a WireGuard server by UUID.
func (c *Client) DeleteServer(ctx context.Context, uuid string) error {
	path := fmt.Sprintf("/wireguard/server/del_server/%s", uuid)

	respBody, err := c.doRequest(ctx, "POST", path, struct{}{})
	if err != nil {
		return err
	}

	var result APIResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if result.Result != "deleted" {
		return fmt.Errorf("unexpected result: %s", result.Result)
	}

	c.log.Debugw("DeleteServer completed", "uuid", uuid)

	return nil
}

// AddClient creates a new WireGuard client and returns the OPNsense-assigned UUID.
func (c *Client) AddClient(ctx context.Context, client WireGuardClient) (string, error) {
	wrapper := WireGuardClientWrapper{Client: client}

	respBody, err := c.doRequest(ctx, "POST", "/wireguard/client/add_client", wrapper)
	if err != nil {
		return "", err
	}

	var result WireGuardAddResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if result.Result != "saved" {
		if result.ValidationErrors.HasErrors() {
			return "", fmt.Errorf("validation failed: %s", result.ValidationErrors.String())
		}
		return "", fmt.Errorf("unexpected result: %s (response: %s)", result.Result, string(respBody))
	}

	c.log.Debugw("AddClient completed",
		"uuid", result.UUID,
		"name", client.Name,
	)

	return result.UUID, nil
}

// SetClient updates an existing WireGuard client.
func (c *Client) SetClient(ctx context.Context, uuid string, client WireGuardClient) error {
	path := fmt.Sprintf("/wireguard/client/set_client/%s", uuid)
	wrapper := WireGuardClientWrapper{Client: client}

	respBody, err := c.doRequest(ctx, "POST", path, wrapper)
	if err != nil {
		return err
	}

	var result WireGuardAddResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if result.Result != "saved" {
		if result.ValidationErrors.HasErrors() {
			return fmt.Errorf("validation failed: %s", result.ValidationErrors.String())
		}
		return fmt.Errorf("unexpected result: %s (response: %s)", result.Result, string(respBody))
	}

	c.log.Debugw("SetClient completed",
		"uuid", uuid,
		"name", client.Name,
	)

	return nil
}

// DeleteClient deletes a WireGuard client by UUID.
func (c *Client) DeleteClient(ctx context.Context, uuid string) error {
	path := fmt.Sprintf("/wireguard/client/del_client/%s", uuid)

	respBody, err := c.doRequest(ctx, "POST", path, struct{}{})
	if err != nil {
		return err
	}

	var result APIResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if result.Result != "deleted" {
		return fmt.Errorf("unexpected result: %s", result.Result)
	}

	c.log.Debugw("DeleteClient completed", "uuid", uuid)

	return nil
}

// ReconfigureWireGuard applies pending WireGuard changes.
func (c *Client) ReconfigureWireGuard(ctx context.Context) error {
	_, err := c.doRequest(ctx, "POST", "/wireguard/service/reconfigure", struct{}{})
	if err != nil {
		return fmt.Errorf("wireguard reconfigure failed: %w", err)
	}

	c.log.Debug("ReconfigureWireGuard completed")

	return nil
}

// FilterManagedWireGuardServers filters servers by nd-vpn__ name prefix.
func FilterManagedWireGuardServers(servers []map[string]interface{}) []map[string]interface{} {
	var managed []map[string]interface{}
	for _, s := range servers {
		if name, ok := s["name"].(string); ok {
			if strings.HasPrefix(name, NDAgentWireGuardPrefix) {
				managed = append(managed, s)
			}
		}
	}
	return managed
}

// FilterManagedWireGuardClients filters clients by nd-vpn__ name prefix.
func FilterManagedWireGuardClients(clients []map[string]interface{}) []map[string]interface{} {
	var managed []map[string]interface{}
	for _, c := range clients {
		if name, ok := c["name"].(string); ok {
			if strings.HasPrefix(name, NDAgentWireGuardPrefix) {
				managed = append(managed, c)
			}
		}
	}
	return managed
}

// DeriveWireGuardPublicKey derives a Curve25519 public key from a base64-encoded private key.
func DeriveWireGuardPublicKey(privateKeyBase64 string) (string, error) {
	privBytes, err := base64.StdEncoding.DecodeString(privateKeyBase64)
	if err != nil {
		return "", fmt.Errorf("failed to decode private key: %w", err)
	}

	if len(privBytes) != 32 {
		return "", fmt.Errorf("invalid private key length: got %d, want 32", len(privBytes))
	}

	// Clamp the private key per WireGuard spec (same as X25519)
	// curve25519.X25519 handles clamping internally
	pubBytes, err := curve25519.X25519(privBytes, curve25519.Basepoint)
	if err != nil {
		return "", fmt.Errorf("failed to derive public key: %w", err)
	}

	// Verify result is not zero (degenerate key)
	var zero [32]byte
	if subtle.ConstantTimeCompare(pubBytes, zero[:]) == 1 {
		return "", fmt.Errorf("derived public key is zero (degenerate private key)")
	}

	return base64.StdEncoding.EncodeToString(pubBytes), nil
}

// BuildServerName constructs the managed server name from a network name.
func BuildServerName(networkName string) string {
	return NDAgentWireGuardPrefix + networkName
}

// BuildClientName constructs the managed client name from network and peer names.
func BuildClientName(networkName, peerName string) string {
	return NDAgentWireGuardPrefix + networkName + "__" + peerName
}
