package opnapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/netdefense-io/ndagent/internal/logging"
	"go.uber.org/zap"
)

// APIError is the typed error returned by doRequest for non-2xx responses.
// Callers can use errors.As / IsNotFound to dispatch on status code — most
// commonly to detect 404 (plugin endpoint missing because the OPNsense
// plugin isn't installed on this device) and silently skip the sync block
// for that plugin group.
type APIError struct {
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("API error: status %d, body: %s", e.StatusCode, e.Body)
}

// IsNotFound returns true if err wraps an APIError with HTTP 404.
// Used by sync executors to silently skip a sync block when the underlying
// OPNsense plugin isn't installed on this device.
func IsNotFound(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound
}

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
//
// A read whose response arrives corrupt (see read_retry.go) is repeated up to
// maxReadRetries times. Every other request is sent exactly once.
func (c *Client) doRequest(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
	}

	if !isIdempotentRead(method, path) {
		return c.send(ctx, method, path, payload)
	}

	for attempt := 0; ; attempt++ {
		respBody, err := c.send(ctx, method, path, payload)
		if attempt == maxReadRetries || !isCorruptResponse(respBody, err) {
			return respBody, err
		}

		c.log.Debugw("Retrying read after a corrupt response",
			"method", method,
			"path", path,
			"retry", attempt+1,
			"max_retries", maxReadRetries,
			"error", err,
		)
		if sleepErr := retrySleep(ctx, time.Duration(attempt+1)*readRetryBackoff); sleepErr != nil {
			return nil, fmt.Errorf("request failed: %w", sleepErr)
		}
	}
}

// send performs one authenticated request attempt.
func (c *Client) send(ctx context.Context, method, path string, payload []byte) ([]byte, error) {
	url := c.baseURL + path

	var bodyReader io.Reader
	if payload != nil {
		bodyReader = bytes.NewReader(payload)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.SetBasicAuth(c.apiKey, c.apiSecret)
	// Only set Content-Type for requests with a body
	if payload != nil {
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
		return nil, &APIError{StatusCode: resp.StatusCode, Body: string(respBody)}
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
