package opnapi

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// checkApplyAnswer reads the one field an apply call answers with. OPNsense
// answers HTTP 200 whether or not the apply worked, so this field is the only
// sign of a failure: "ok" from a service controller, configd's "OK" (with its
// trailing newlines) from the filter apply. "filter reload" is a configd
// script action, whose answer is "OK" or an error, never the script's output.
func checkApplyAnswer(respBody []byte, field string) error {
	var answer map[string]interface{}
	if err := json.Unmarshal(respBody, &answer); err != nil {
		return fmt.Errorf("unreadable answer: %w", err)
	}
	got, _ := answer[field].(string)
	if !strings.EqualFold(strings.TrimSpace(got), "ok") {
		return fmt.Errorf("answered %s=%q", field, got)
	}
	return nil
}

// serviceStatus reads the status OPNsense's service base reports for a
// service: "running", "stopped", "disabled" (not enabled, and not running) or
// "unknown".
func (c *Client) serviceStatus(ctx context.Context, path string) (string, error) {
	respBody, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return "", err
	}
	var answer struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(respBody, &answer); err != nil {
		return "", fmt.Errorf("unreadable answer: %w", err)
	}
	return answer.Status, nil
}

// UnboundStatus is Unbound's status (serviceStatus).
func (c *Client) UnboundStatus(ctx context.Context) (string, error) {
	return c.serviceStatus(ctx, "/unbound/service/status")
}

// ZabbixStatus is the Zabbix agent's status (serviceStatus).
func (c *Client) ZabbixStatus(ctx context.Context) (string, error) {
	return c.serviceStatus(ctx, "/zabbixagent/service/status")
}
