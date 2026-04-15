package opnapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/netdefense-io/ndagent/internal/logging"
	"go.uber.org/zap"
)

// Client is the OPNsense REST API client.
type Client struct {
	baseURL    string
	apiKey     string
	apiSecret  string
	httpClient *http.Client
	log        *zap.SugaredLogger
}

// NewClient creates a new OPNsense API client.
func NewClient(baseURL, apiKey, apiSecret string, skipTLSVerify bool) *Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: skipTLSVerify,
			MinVersion:         tls.VersionTLS12,
		},
	}

	return &Client{
		baseURL:   baseURL,
		apiKey:    apiKey,
		apiSecret: apiSecret,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
		log: logging.Named("opnapi"),
	}
}

// doRequest performs an authenticated API request and returns the response body.
func (c *Client) doRequest(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
	url := c.baseURL + path

	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.SetBasicAuth(c.apiKey, c.apiSecret)
	// Only set Content-Type for requests with a body
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	c.log.Debugw("API request",
		"method", method,
		"path", path,
	)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	c.log.Debugw("API response",
		"status", resp.StatusCode,
		"body_length", len(respBody),
	)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("API error: status %d, body: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// Ping tests connectivity to the OPNsense API.
// It performs a simple search to verify credentials work.
func (c *Client) Ping(ctx context.Context) error {
	// Use an empty search to test connectivity
	req := SearchRequest{SearchPhrase: ""}

	_, err := c.doRequest(ctx, "POST", "/firewall/alias/searchItem", req)
	if err != nil {
		return fmt.Errorf("ping failed: %w", err)
	}

	return nil
}
