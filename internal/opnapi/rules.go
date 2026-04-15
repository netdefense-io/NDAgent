package opnapi

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// SearchRules searches for filter rules matching the search phrase.
// Note: This only searches floating rules (no interface). Use SearchRulesOnInterface
// for interface-specific rules.
func (c *Client) SearchRules(ctx context.Context, searchPhrase string) ([]map[string]interface{}, error) {
	req := SearchRequest{SearchPhrase: searchPhrase}

	respBody, err := c.doRequest(ctx, "POST", "/firewall/filter/searchRule", req)
	if err != nil {
		return nil, err
	}

	var resp SearchResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse search response: %w", err)
	}

	c.log.Debugw("SearchRules completed",
		"search_phrase", searchPhrase,
		"count", len(resp.Rows),
	)

	return resp.Rows, nil
}

// SearchRulesOnInterface searches for filter rules on a specific interface.
// OPNsense organizes rules by interface with different priority groups:
// - No interface = floating rules (prio_group 200000)
// - With interface = interface rules (prio_group 400000)
func (c *Client) SearchRulesOnInterface(ctx context.Context, iface, searchPhrase string) ([]map[string]interface{}, error) {
	req := RuleSearchRequest{
		Current:      1,
		RowCount:     -1, // All results
		Sort:         map[string]string{},
		SearchPhrase: searchPhrase,
		Interface:    iface,
	}

	respBody, err := c.doRequest(ctx, "POST", "/firewall/filter/searchRule", req)
	if err != nil {
		return nil, err
	}

	var resp SearchResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse search response: %w", err)
	}

	c.log.Debugw("SearchRulesOnInterface completed",
		"interface", iface,
		"search_phrase", searchPhrase,
		"count", len(resp.Rows),
	)

	return resp.Rows, nil
}

// ListAllRules retrieves ALL rules from OPNsense across all interfaces.
// Makes 2 API calls: floating rules + all interface rules (comma-separated).
// Returns raw results; caller must filter by UUID prefix for managed objects.
func (c *Client) ListAllRules(ctx context.Context) ([]map[string]interface{}, error) {
	seenUUIDs := make(map[string]bool)
	var allRules []map[string]interface{}

	// Call 1: Get floating rules (no interface)
	floatingRules, err := c.searchRulesWithParams(ctx, "", "")
	if err != nil {
		return nil, fmt.Errorf("list floating rules: %w", err)
	}
	for _, rule := range floatingRules {
		if uuid, ok := rule["uuid"].(string); ok && !seenUUIDs[uuid] {
			seenUUIDs[uuid] = true
			allRules = append(allRules, rule)
		}
	}

	// Get interface list for combined query
	interfaces, err := c.GetInterfaceList(ctx)
	if err != nil {
		c.log.Warnw("Failed to get interface list, using defaults", "error", err)
		interfaces = []string{"lan", "wan"}
	}

	// Call 2: Get all interface rules with comma-separated list
	// OPNsense API accepts: interface=lan,wan,opt1
	interfaceList := strings.Join(interfaces, ",")
	interfaceRules, err := c.searchRulesWithParams(ctx, interfaceList, "")
	if err != nil {
		// Fallback: iterate interfaces individually
		c.log.Warnw("Comma-separated interface search failed, falling back to iteration", "error", err)
		for _, iface := range interfaces {
			rules, err := c.searchRulesWithParams(ctx, iface, "")
			if err != nil {
				c.log.Warnw("Failed to list rules on interface", "interface", iface, "error", err)
				continue
			}
			for _, rule := range rules {
				if uuid, ok := rule["uuid"].(string); ok && !seenUUIDs[uuid] {
					seenUUIDs[uuid] = true
					allRules = append(allRules, rule)
				}
			}
		}
	} else {
		for _, rule := range interfaceRules {
			if uuid, ok := rule["uuid"].(string); ok && !seenUUIDs[uuid] {
				seenUUIDs[uuid] = true
				allRules = append(allRules, rule)
			}
		}
	}

	c.log.Infow("ListAllRules completed", "total", len(allRules))

	return allRules, nil
}

// FilterManagedRules filters rules by NDAgent UUID prefix.
// This is a local filter - must be applied to results from ListAllRules.
func FilterManagedRules(rules []map[string]interface{}) []map[string]interface{} {
	var managed []map[string]interface{}
	for _, rule := range rules {
		if uuid, ok := rule["uuid"].(string); ok {
			if strings.HasPrefix(uuid, NDAgentUUIDPrefix+"-") {
				managed = append(managed, rule)
			}
		}
	}
	return managed
}

// searchRulesWithParams searches rules with interface and search phrase parameters.
func (c *Client) searchRulesWithParams(ctx context.Context, iface, searchPhrase string) ([]map[string]interface{}, error) {
	req := RuleSearchRequest{
		Current:      1,
		RowCount:     -1, // All results
		Sort:         map[string]string{},
		SearchPhrase: searchPhrase,
		Interface:    iface,
	}

	respBody, err := c.doRequest(ctx, "POST", "/firewall/filter/searchRule", req)
	if err != nil {
		return nil, err
	}

	var resp SearchResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse search response: %w", err)
	}

	return resp.Rows, nil
}

// GetRule retrieves a single rule by UUID.
func (c *Client) GetRule(ctx context.Context, uuid string) (map[string]interface{}, error) {
	path := fmt.Sprintf("/firewall/filter/getRule/%s", uuid)

	respBody, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return resp, nil
}

// SetRuleResponse is the response from setRule endpoint.
type SetRuleResponse struct {
	Result           string             `json:"result"`
	UUID             string             `json:"uuid,omitempty"`
	ValidationErrors FlexibleValidation `json:"validations,omitempty"`
}

// SetRule creates or updates a filter rule (upsert operation).
func (c *Client) SetRule(ctx context.Context, uuid string, rule Rule) error {
	path := fmt.Sprintf("/firewall/filter/setRule/%s", uuid)
	wrapper := RuleWrapper{Rule: rule}

	respBody, err := c.doRequest(ctx, "POST", path, wrapper)
	if err != nil {
		return err
	}

	var result SetRuleResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if result.Result != "saved" {
		// Check for validation errors
		if result.ValidationErrors.HasErrors() {
			c.log.Debugw("Validation errors", "errors", result.ValidationErrors.String())
			return fmt.Errorf("validation failed: %s", result.ValidationErrors.String())
		}
		return fmt.Errorf("unexpected result: %s (response: %s)", result.Result, string(respBody))
	}

	c.log.Debugw("SetRule completed",
		"uuid", uuid,
	)

	return nil
}

// DeleteRule deletes a filter rule by UUID.
func (c *Client) DeleteRule(ctx context.Context, uuid string) error {
	path := fmt.Sprintf("/firewall/filter/delRule/%s", uuid)

	// OPNsense API requires an empty JSON object, not nil
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

	c.log.Debugw("DeleteRule completed", "uuid", uuid)

	return nil
}

// ApplyRules applies pending filter rule changes.
// This is the simple version without savepoint/rollback.
func (c *Client) ApplyRules(ctx context.Context) error {
	// OPNsense API requires an empty JSON object, not nil
	_, err := c.doRequest(ctx, "POST", "/firewall/filter/apply", struct{}{})
	if err != nil {
		return fmt.Errorf("apply failed: %w", err)
	}

	c.log.Debug("ApplyRules completed")

	return nil
}

// GetInterfaceList retrieves available interfaces from OPNsense.
// Returns actual interface names (lan, wan, opt1, etc.) for rule search.
// Extracts from the getRule template which contains valid interface options.
func (c *Client) GetInterfaceList(ctx context.Context) ([]string, error) {
	// Get the rule template which contains interface options
	respBody, err := c.doRequest(ctx, "GET", "/firewall/filter/getRule", nil)
	if err != nil {
		return nil, err
	}

	// Parse the response to extract interface options
	var resp struct {
		Rule struct {
			Interface map[string]struct {
				Value    string `json:"value"`
				Selected int    `json:"selected"`
			} `json:"interface"`
		} `json:"rule"`
	}

	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse rule template: %w", err)
	}

	var interfaces []string
	for iface := range resp.Rule.Interface {
		interfaces = append(interfaces, iface)
	}

	c.log.Debugw("GetInterfaceList completed", "count", len(interfaces))

	return interfaces, nil
}

// ErrMultipleRulesMatch is returned when a partial description search matches multiple rules.
type ErrMultipleRulesMatch struct {
	SearchTerm string
	MatchCount int
}

func (e *ErrMultipleRulesMatch) Error() string {
	return fmt.Sprintf("multiple rules match description '%s': found %d rules. Please use a more specific description to identify a unique rule", e.SearchTerm, e.MatchCount)
}

// GetRuleByDescription searches for a rule by partial description match.
// Searches both floating rules and interface-specific rules.
// Returns an error if multiple rules match the description (requires unique match).
func (c *Client) GetRuleByDescription(ctx context.Context, description string) (map[string]interface{}, error) {
	var matchingRules []map[string]interface{}

	// Search floating rules first
	rules, err := c.SearchRules(ctx, description)
	if err != nil {
		return nil, err
	}

	// Collect all rules whose description contains the search term (case-insensitive)
	searchLower := strings.ToLower(description)
	for _, rule := range rules {
		if ruleDesc, ok := rule["description"].(string); ok {
			if strings.Contains(strings.ToLower(ruleDesc), searchLower) {
				matchingRules = append(matchingRules, rule)
			}
		}
	}

	// Get available interfaces and search each one
	interfaces, err := c.GetInterfaceList(ctx)
	if err != nil {
		c.log.Warnw("Failed to get interface list, using common defaults", "error", err)
		interfaces = []string{"lan", "wan"}
	}

	for _, iface := range interfaces {
		rules, err := c.SearchRulesOnInterface(ctx, iface, description)
		if err != nil {
			continue
		}
		for _, rule := range rules {
			if ruleDesc, ok := rule["description"].(string); ok {
				if strings.Contains(strings.ToLower(ruleDesc), searchLower) {
					// Avoid duplicates (rules may appear in multiple searches)
					uuid, _ := rule["uuid"].(string)
					isDuplicate := false
					for _, existing := range matchingRules {
						if existingUUID, ok := existing["uuid"].(string); ok && existingUUID == uuid {
							isDuplicate = true
							break
						}
					}
					if !isDuplicate {
						matchingRules = append(matchingRules, rule)
					}
				}
			}
		}
	}

	// Check results
	if len(matchingRules) == 0 {
		return nil, nil // Not found
	}

	if len(matchingRules) > 1 {
		return nil, &ErrMultipleRulesMatch{
			SearchTerm: description,
			MatchCount: len(matchingRules),
		}
	}

	return matchingRules[0], nil
}
