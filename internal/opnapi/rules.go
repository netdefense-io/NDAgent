package opnapi

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// ruleSearchPageSize bounds one page of a rule search. A rule row is about
// 1 KB of JSON, and responses near 100 KB can arrive corrupted over the
// loopback connection the agent uses (see read_retry.go), so the ruleset is
// read in pages rather than with rowCount -1.
const ruleSearchPageSize = 40

// maxRuleSearchPages stops a search whose pages never end, rather than
// looping on a device that ignores the page number.
const maxRuleSearchPages = 2500

// searchRulePage reads one page of the unfiltered rule search.
func (c *Client) searchRulePage(ctx context.Context, searchPhrase string, page, rowCount int) (SearchResponse, error) {
	req := RuleSearchRequest{
		Current:      page,
		RowCount:     rowCount,
		Sort:         map[string]string{},
		SearchPhrase: searchPhrase,
	}

	respBody, err := c.doRequest(ctx, "POST", "/firewall/filter/searchRule", req)
	if err != nil {
		return SearchResponse{}, err
	}

	var resp SearchResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return SearchResponse{}, fmt.Errorf("failed to parse search response: %w", err)
	}
	return resp, nil
}

// searchRules reads every rule the search phrase matches, page by page, in
// OPNsense's evaluation order (sort_order). A rule listed twice because the
// ruleset changed between pages is kept once. The search ends at a short page
// (an empty one included) or at a page that adds no rule (a device that
// ignores the page number answers the first page again). The total the device
// reports does not end it: a missing or stale one would cut the list short.
func (c *Client) searchRules(ctx context.Context, searchPhrase string) ([]map[string]interface{}, error) {
	seen := make(map[string]bool)
	var rows []map[string]interface{}
	for page := 1; page <= maxRuleSearchPages; page++ {
		resp, err := c.searchRulePage(ctx, searchPhrase, page, ruleSearchPageSize)
		if err != nil {
			return nil, err
		}
		added := 0
		for _, row := range resp.Rows {
			uuid, _ := row["uuid"].(string)
			if uuid != "" && seen[uuid] {
				continue
			}
			seen[uuid] = true
			rows = append(rows, row)
			added++
		}
		if len(resp.Rows) < ruleSearchPageSize || added == 0 {
			return rows, nil
		}
	}
	return nil, fmt.Errorf("rule search did not end after %d pages", maxRuleSearchPages)
}

// ListAllRules retrieves ALL rules from OPNsense: MVC rules wherever they are
// bound, legacy rules and the rules OPNsense generates (both listed with
// "legacy": true). One unfiltered search returns them all on 26.1 and later;
// see RuleSearchRequest.
// Returns raw results; caller must filter by UUID prefix for managed objects.
func (c *Client) ListAllRules(ctx context.Context) ([]map[string]interface{}, error) {
	rules, err := c.searchRules(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("list rules: %w", err)
	}

	c.log.Infow("ListAllRules completed", "total", len(rules))

	return rules, nil
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

// GetRule reads one rule as the device holds it: every field's value in
// OPNsense's string form, a list field's as its selected keys, comma-joined.
// found is false when the device holds no rule with this uuid, which getRule
// answers with [].
func (c *Client) GetRule(ctx context.Context, uuid string) (values map[string]string, found bool, err error) {
	path := fmt.Sprintf("/firewall/filter/getRule/%s", uuid)

	respBody, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, false, err
	}

	var resp interface{}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, false, fmt.Errorf("failed to parse response: %w", err)
	}
	switch answer := resp.(type) {
	case []interface{}:
		if len(answer) == 0 {
			return nil, false, nil
		}
	case map[string]interface{}:
		if rule, ok := answer["rule"].(map[string]interface{}); ok {
			return ParseEntityModel(rule).Values(), true, nil
		}
	}
	return nil, false, fmt.Errorf("getRule answered neither a rule nor []")
}

// SetRuleResponse is the response from setRule endpoint.
type SetRuleResponse struct {
	Result           string             `json:"result"`
	UUID             string             `json:"uuid,omitempty"`
	ValidationErrors FlexibleValidation `json:"validations,omitempty"`
}

// SetRule creates or updates a filter rule (upsert operation) from a flat body
// of OPNsense string values. A refusal with field validations is a
// *ValidationFailedError; only "saved" is success.
func (c *Client) SetRule(ctx context.Context, uuid string, rule map[string]string) error {
	path := fmt.Sprintf("/firewall/filter/setRule/%s", uuid)
	wrapper := RuleWrapper{Rule: rule}

	c.log.Debugw("SetRule request", "uuid", uuid, "body", wrapper)

	respBody, err := c.doRequest(ctx, "POST", path, wrapper)
	if err != nil {
		return err
	}

	var result SetRuleResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if result.Result != "saved" {
		if result.ValidationErrors.HasErrors() {
			c.log.Debugw("Validation errors", "errors", result.ValidationErrors.String())
			return &ValidationFailedError{Entity: "rule", Validations: result.ValidationErrors}
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

// ToggleRule sets a filter rule's enabled flag. Unlike setRule it never creates
// a rule: for a uuid the device does not hold OPNsense answers "failed".
func (c *Client) ToggleRule(ctx context.Context, uuid string, enabled bool) error {
	path := fmt.Sprintf("/firewall/filter/toggleRule/%s/%s", uuid, BoolToOPNsense(enabled))

	// OPNsense API requires an empty JSON object, not nil
	respBody, err := c.doRequest(ctx, "POST", path, struct{}{})
	if err != nil {
		return err
	}

	var result APIResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	want := "Disabled"
	if enabled {
		want = "Enabled"
	}
	if result.Result != want {
		return fmt.Errorf("unexpected result: %s", result.Result)
	}
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

// GetRuleModel reads the device's filter rule model: getRule without a uuid
// answers every field with its default, and every list field with the options
// this device offers (its interfaces and groups, gateways, aliases, ...).
func (c *Client) GetRuleModel(ctx context.Context) (EntityModel, error) {
	respBody, err := c.doRequest(ctx, "GET", "/firewall/filter/getRule", nil)
	if err != nil {
		return EntityModel{}, err
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return EntityModel{}, fmt.Errorf("failed to parse rule template: %w", err)
	}
	template, ok := resp["rule"].(map[string]interface{})
	if !ok {
		return EntityModel{}, fmt.Errorf("rule template has no %q object", "rule")
	}
	model := ParseEntityModel(template)
	if model.Len() == 0 {
		return EntityModel{}, fmt.Errorf("rule template has no fields")
	}

	c.log.Debugw("GetRuleModel completed", "fields", model.Len())

	return model, nil
}

// InterfaceGroup is one interface group, as the group search lists it.
type InterfaceGroup struct {
	Name     string
	Sequence int
	Members  []string
}

// GetInterfaceTypes reads which rule interface options are interface groups:
// the interface list the rule editor offers, keyed by interface, with "group"
// or "interface" as the value. OPNsense ranks a rule bound to a single group
// by the same test (FilterRuleField::getPriority).
func (c *Client) GetInterfaceTypes(ctx context.Context) (map[string]string, error) {
	respBody, err := c.doRequest(ctx, "GET", "/firewall/filter/get_interface_list", nil)
	if err != nil {
		return nil, err
	}

	var sections map[string]struct {
		Items []struct {
			Value string `json:"value"`
			Type  string `json:"type"`
		} `json:"items"`
	}
	if err := json.Unmarshal(respBody, &sections); err != nil {
		return nil, fmt.Errorf("failed to parse interface list: %w", err)
	}

	types := make(map[string]string)
	for _, section := range sections {
		for _, item := range section.Items {
			if item.Type == "group" || item.Type == "interface" {
				types[item.Value] = item.Type
			}
		}
	}
	if len(types) == 0 {
		return nil, fmt.Errorf("interface list has no interfaces")
	}
	return types, nil
}

// ListInterfaceGroups reads every interface group with its sequence and
// members, the plugin groups (openvpn, enc0, wireguard) included.
func (c *Client) ListInterfaceGroups(ctx context.Context) ([]InterfaceGroup, error) {
	respBody, err := c.doRequest(ctx, "POST", "/firewall/group/search_item", SearchRequest{})
	if err != nil {
		return nil, err
	}

	var resp SearchResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse group search: %w", err)
	}

	groups := make([]InterfaceGroup, 0, len(resp.Rows))
	for _, row := range resp.Rows {
		name, _ := row["ifname"].(string)
		if name == "" {
			continue
		}
		group := InterfaceGroup{Name: name}
		switch seq := row["sequence"].(type) {
		case string:
			group.Sequence, _ = strconv.Atoi(seq)
		case float64:
			group.Sequence = int(seq)
		}
		members, _ := row["members"].(string)
		group.Members = CSVToStrings(members)
		groups = append(groups, group)
	}
	return groups, nil
}

// ErrMultipleRulesMatch is returned when a partial description search matches multiple rules.
type ErrMultipleRulesMatch struct {
	SearchTerm string
	MatchCount int
}

func (e *ErrMultipleRulesMatch) Error() string {
	return fmt.Sprintf("multiple rules match description '%s': found %d rules. Please use a more specific description to identify a unique rule", e.SearchTerm, e.MatchCount)
}

// GetRuleByDescription searches for a rule by partial description match,
// case-insensitive, over every rule the device lists.
// Returns an error if multiple rules match the description (requires unique match).
func (c *Client) GetRuleByDescription(ctx context.Context, description string) (map[string]interface{}, error) {
	rules, err := c.searchRules(ctx, description)
	if err != nil {
		return nil, err
	}

	var matchingRules []map[string]interface{}
	searchLower := strings.ToLower(description)
	for _, rule := range rules {
		if ruleDesc, ok := rule["description"].(string); ok {
			if strings.Contains(strings.ToLower(ruleDesc), searchLower) {
				matchingRules = append(matchingRules, rule)
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
