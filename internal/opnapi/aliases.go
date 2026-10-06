package opnapi

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// SearchAliases searches for aliases matching the search phrase.
func (c *Client) SearchAliases(ctx context.Context, searchPhrase string) ([]map[string]interface{}, error) {
	req := SearchRequest{SearchPhrase: searchPhrase}

	respBody, err := c.doRequest(ctx, "POST", "/firewall/alias/searchItem", req)
	if err != nil {
		return nil, err
	}

	var resp SearchResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse search response: %w", err)
	}

	c.log.Debugw("SearchAliases completed",
		"search_phrase", searchPhrase,
		"count", len(resp.Rows),
	)

	return resp.Rows, nil
}

// ListAllAliases retrieves ALL aliases from OPNsense.
// Returns raw results; caller must filter by UUID prefix for managed objects.
func (c *Client) ListAllAliases(ctx context.Context) ([]map[string]interface{}, error) {
	// Empty search phrase returns all items
	return c.SearchAliases(ctx, "")
}

// FilterManagedAliases filters aliases by NDAgent UUID prefix.
// This is a local filter - must be applied to results from ListAllAliases.
func FilterManagedAliases(aliases []map[string]interface{}) []map[string]interface{} {
	var managed []map[string]interface{}
	for _, alias := range aliases {
		if uuid, ok := alias["uuid"].(string); ok {
			if strings.HasPrefix(uuid, NDAgentUUIDPrefix+"-") {
				managed = append(managed, alias)
			}
		}
	}
	return managed
}

// GetAlias retrieves a single alias by UUID.
func (c *Client) GetAlias(ctx context.Context, uuid string) (map[string]interface{}, error) {
	path := fmt.Sprintf("/firewall/alias/getItem/%s", uuid)

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

// SetAliasResponse is the response from setItem endpoint.
type SetAliasResponse struct {
	Result           string             `json:"result"`
	UUID             string             `json:"uuid,omitempty"`
	ValidationErrors FlexibleValidation `json:"validations,omitempty"`
}

// SetAlias creates or updates an alias (upsert operation) from a flat body of
// OPNsense string values. A refusal with field validations is a
// *ValidationFailedError; only "saved" is success.
func (c *Client) SetAlias(ctx context.Context, uuid string, alias map[string]string) error {
	path := fmt.Sprintf("/firewall/alias/setItem/%s", uuid)
	wrapper := AliasWrapper{Alias: alias}

	respBody, err := c.doRequest(ctx, "POST", path, wrapper)
	if err != nil {
		return err
	}

	var result SetAliasResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if result.Result != "saved" {
		if result.ValidationErrors.HasErrors() {
			c.log.Debugw("Validation errors", "errors", result.ValidationErrors.String())
			return &ValidationFailedError{Entity: "alias", Validations: result.ValidationErrors}
		}
		return fmt.Errorf("unexpected result: %s (response: %s)", result.Result, string(respBody))
	}

	c.log.Debugw("SetAlias completed",
		"uuid", uuid,
		"name", alias["name"],
	)

	return nil
}

// GetAliasModel reads the device's alias model: getItem without a uuid
// answers every field with its default, and every list field with the
// options this device offers. Its "content" options are only suggestions
// (every alias name), not the field's valid values.
func (c *Client) GetAliasModel(ctx context.Context) (EntityModel, error) {
	respBody, err := c.doRequest(ctx, "GET", "/firewall/alias/getItem", nil)
	if err != nil {
		return EntityModel{}, err
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return EntityModel{}, fmt.Errorf("failed to parse alias template: %w", err)
	}
	template, ok := resp["alias"].(map[string]interface{})
	if !ok {
		return EntityModel{}, fmt.Errorf("alias template has no %q object", "alias")
	}
	model := ParseEntityModel(template)
	if model.Len() == 0 {
		return EntityModel{}, fmt.Errorf("alias template has no fields")
	}

	c.log.Debugw("GetAliasModel completed", "fields", model.Len())

	return model, nil
}

// DeleteAlias deletes an alias by UUID.
func (c *Client) DeleteAlias(ctx context.Context, uuid string) error {
	path := fmt.Sprintf("/firewall/alias/delItem/%s", uuid)

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

	c.log.Debugw("DeleteAlias completed", "uuid", uuid)

	return nil
}

// ReconfigureAliases applies pending alias changes.
func (c *Client) ReconfigureAliases(ctx context.Context) error {
	// OPNsense API requires an empty JSON object, not nil
	_, err := c.doRequest(ctx, "POST", "/firewall/alias/reconfigure", struct{}{})
	if err != nil {
		return fmt.Errorf("reconfigure failed: %w", err)
	}

	c.log.Debug("ReconfigureAliases completed")

	return nil
}

// GetAliasByName searches for an alias by exact name match.
func (c *Client) GetAliasByName(ctx context.Context, name string) (map[string]interface{}, error) {
	aliases, err := c.SearchAliases(ctx, name)
	if err != nil {
		return nil, err
	}

	for _, alias := range aliases {
		if aliasName, ok := alias["name"].(string); ok && aliasName == name {
			return alias, nil
		}
	}

	return nil, nil // Not found
}

// FindAliasUsage searches all rules for references to the given alias name.
// Returns rule descriptions that reference this alias in source_net or destination_net.
func (c *Client) FindAliasUsage(ctx context.Context, aliasName string) ([]string, error) {
	allRules, err := c.ListAllRules(ctx)
	if err != nil {
		return nil, err
	}

	var references []string
	for _, rule := range allRules {
		sourceNet, _ := rule["source_net"].(string)
		destNet, _ := rule["destination_net"].(string)

		if sourceNet == aliasName || destNet == aliasName {
			desc, _ := rule["description"].(string)
			uuid, _ := rule["uuid"].(string)
			references = append(references, fmt.Sprintf("%s (%s)", desc, uuid))
		}
	}

	c.log.Debugw("FindAliasUsage completed",
		"alias_name", aliasName,
		"reference_count", len(references),
	)

	return references, nil
}
