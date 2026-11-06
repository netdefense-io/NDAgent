package opnapi

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// CrowdsecValidationError is a refused os-crowdsec settings write: OPNsense
// answers HTTP 200 {"result":"failed","validations":{"general.<field>":msg}}
// and stores nothing.
type CrowdsecValidationError struct {
	Fields map[string]string
}

func (e *CrowdsecValidationError) Error() string {
	names := make([]string, 0, len(e.Fields))
	for name := range e.Fields {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, fmt.Sprintf("%s: %s", name, e.Fields[name]))
	}
	return "validation failed: " + strings.Join(parts, "; ")
}

// GetCrowdsecGeneral reads the os-crowdsec settings model as strings
// (booleans are "0"/"1" on the wire; a JSON bool is folded to the same).
func (c *Client) GetCrowdsecGeneral(ctx context.Context) (map[string]string, error) {
	respBody, err := c.doRequest(ctx, "GET", "/crowdsec/general/get", nil)
	if err != nil {
		return nil, err
	}

	var resp struct {
		General map[string]interface{} `json:"general"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	if resp.General == nil {
		return nil, fmt.Errorf("response has no general settings")
	}

	out := make(map[string]string, len(resp.General))
	for key, value := range resp.General {
		switch v := value.(type) {
		case string:
			out[key] = v
		case bool:
			if v {
				out[key] = "1"
			} else {
				out[key] = "0"
			}
		case float64:
			out[key] = fmt.Sprintf("%v", v)
		case nil:
			out[key] = ""
		default:
			// A nested value is not a scalar setting; leave it out of the
			// view so it can never be compared or written.
		}
	}
	return out, nil
}

// SetCrowdsecGeneral writes only the given keys: the plugin merges a partial
// body into the model. A set alone changes nothing on the running device.
func (c *Client) SetCrowdsecGeneral(ctx context.Context, values map[string]string) error {
	body := map[string]map[string]string{"general": values}

	respBody, err := c.doRequest(ctx, "POST", "/crowdsec/general/set", body)
	if err != nil {
		return err
	}

	var result struct {
		Result      string            `json:"result"`
		Validations map[string]string `json:"validations"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	if result.Result == "saved" {
		return nil
	}
	if len(result.Validations) > 0 {
		fields := make(map[string]string, len(result.Validations))
		for name, msg := range result.Validations {
			fields[strings.TrimPrefix(name, "general.")] = msg
		}
		return &CrowdsecValidationError{Fields: fields}
	}
	return fmt.Errorf("unexpected result %q", result.Result)
}

// ReconfigureCrowdsec re-renders the plugin's templates and restarts crowdsec
// and the bouncer. It runs a full hub update against CrowdSec's servers, so
// callers run it only for a real change.
func (c *Client) ReconfigureCrowdsec(ctx context.Context) error {
	respBody, err := c.doRequest(ctx, "POST", "/crowdsec/service/reconfigure", struct{}{})
	if err != nil {
		return fmt.Errorf("reconfigure failed: %w", err)
	}

	var resp struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return fmt.Errorf("failed to parse reconfigure response: %w", err)
	}
	if resp.Status != "ok" {
		return fmt.Errorf("reconfigure returned status=%q", resp.Status)
	}
	return nil
}

// CrowdsecServiceStatus returns "running", "stopped" or "disabled" (all three
// of agent, LAPI and bouncer off).
func (c *Client) CrowdsecServiceStatus(ctx context.Context) (string, error) {
	respBody, err := c.doRequest(ctx, "GET", "/crowdsec/service/status", nil)
	if err != nil {
		return "", err
	}

	var resp struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return "", fmt.Errorf("failed to parse status response: %w", err)
	}
	return resp.Status, nil
}
