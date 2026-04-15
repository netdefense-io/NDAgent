package opnapi

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// ============================================================================
// Host Override Operations
// ============================================================================

// SearchHostOverrides searches for host overrides matching the search phrase.
func (c *Client) SearchHostOverrides(ctx context.Context, searchPhrase string) ([]map[string]interface{}, error) {
	req := SearchRequest{SearchPhrase: searchPhrase}

	respBody, err := c.doRequest(ctx, "POST", "/unbound/settings/searchHostOverride", req)
	if err != nil {
		return nil, err
	}

	var resp SearchResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse search response: %w", err)
	}

	c.log.Debugw("SearchHostOverrides completed",
		"search_phrase", searchPhrase,
		"count", len(resp.Rows),
	)

	return resp.Rows, nil
}

// ListAllHostOverrides retrieves ALL host overrides from OPNsense.
// Returns raw results; caller must filter by UUID prefix for managed objects.
func (c *Client) ListAllHostOverrides(ctx context.Context) ([]map[string]interface{}, error) {
	return c.SearchHostOverrides(ctx, "")
}

// FilterManagedHostOverrides filters host overrides by NDAgent UUID prefix.
func FilterManagedHostOverrides(overrides []map[string]interface{}) []map[string]interface{} {
	var managed []map[string]interface{}
	for _, override := range overrides {
		if uuid, ok := override["uuid"].(string); ok {
			if strings.HasPrefix(uuid, NDAgentUUIDPrefix+"-") {
				managed = append(managed, override)
			}
		}
	}
	return managed
}

// GetHostOverride retrieves a single host override by UUID.
func (c *Client) GetHostOverride(ctx context.Context, uuid string) (map[string]interface{}, error) {
	path := fmt.Sprintf("/unbound/settings/getHostOverride/%s", uuid)

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

// GetHostOverrideByName searches for a host override by exact hostname+domain match.
func (c *Client) GetHostOverrideByName(ctx context.Context, hostname, domain string) (map[string]interface{}, error) {
	overrides, err := c.SearchHostOverrides(ctx, hostname)
	if err != nil {
		return nil, err
	}

	for _, override := range overrides {
		h, _ := override["hostname"].(string)
		d, _ := override["domain"].(string)
		if h == hostname && d == domain {
			return override, nil
		}
	}

	return nil, nil // Not found
}

// SetHostOverride creates or updates a host override (upsert operation).
func (c *Client) SetHostOverride(ctx context.Context, uuid string, override HostOverride) error {
	path := fmt.Sprintf("/unbound/settings/setHostOverride/%s", uuid)
	wrapper := HostOverrideWrapper{Host: override}

	respBody, err := c.doRequest(ctx, "POST", path, wrapper)
	if err != nil {
		return err
	}

	var result SetHostOverrideResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if result.Result != "saved" {
		if result.ValidationErrors.HasErrors() {
			c.log.Debugw("Validation errors", "errors", result.ValidationErrors.String())
			return fmt.Errorf("validation failed: %s", result.ValidationErrors.String())
		}
		return fmt.Errorf("unexpected result: %s (response: %s)", result.Result, string(respBody))
	}

	c.log.Debugw("SetHostOverride completed",
		"uuid", uuid,
		"hostname", override.Hostname,
		"domain", override.Domain,
	)

	return nil
}

// DeleteHostOverride deletes a host override by UUID.
func (c *Client) DeleteHostOverride(ctx context.Context, uuid string) error {
	path := fmt.Sprintf("/unbound/settings/delHostOverride/%s", uuid)

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

	c.log.Debugw("DeleteHostOverride completed", "uuid", uuid)

	return nil
}

// ============================================================================
// Domain Forward Operations
// ============================================================================

// SearchForwards searches for domain forwards matching the search phrase.
func (c *Client) SearchForwards(ctx context.Context, searchPhrase string) ([]map[string]interface{}, error) {
	req := SearchRequest{SearchPhrase: searchPhrase}

	respBody, err := c.doRequest(ctx, "POST", "/unbound/settings/searchForward", req)
	if err != nil {
		return nil, err
	}

	var resp SearchResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse search response: %w", err)
	}

	c.log.Debugw("SearchForwards completed",
		"search_phrase", searchPhrase,
		"count", len(resp.Rows),
	)

	return resp.Rows, nil
}

// ListAllForwards retrieves ALL domain forwards from OPNsense.
func (c *Client) ListAllForwards(ctx context.Context) ([]map[string]interface{}, error) {
	return c.SearchForwards(ctx, "")
}

// FilterManagedForwards filters domain forwards by NDAgent UUID prefix.
func FilterManagedForwards(forwards []map[string]interface{}) []map[string]interface{} {
	var managed []map[string]interface{}
	for _, forward := range forwards {
		if uuid, ok := forward["uuid"].(string); ok {
			if strings.HasPrefix(uuid, NDAgentUUIDPrefix+"-") {
				managed = append(managed, forward)
			}
		}
	}
	return managed
}

// GetForward retrieves a single domain forward by UUID.
func (c *Client) GetForward(ctx context.Context, uuid string) (map[string]interface{}, error) {
	path := fmt.Sprintf("/unbound/settings/getForward/%s", uuid)

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

// GetForwardByDomain searches for a domain forward by exact domain match.
func (c *Client) GetForwardByDomain(ctx context.Context, domain string) (map[string]interface{}, error) {
	forwards, err := c.SearchForwards(ctx, domain)
	if err != nil {
		return nil, err
	}

	for _, forward := range forwards {
		d, _ := forward["domain"].(string)
		if d == domain {
			return forward, nil
		}
	}

	return nil, nil // Not found
}

// SetForward creates or updates a domain forward (upsert operation).
func (c *Client) SetForward(ctx context.Context, uuid string, forward DomainForward) error {
	path := fmt.Sprintf("/unbound/settings/setForward/%s", uuid)
	wrapper := DomainForwardWrapper{Forward: forward}

	respBody, err := c.doRequest(ctx, "POST", path, wrapper)
	if err != nil {
		return err
	}

	var result SetForwardResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if result.Result != "saved" {
		if result.ValidationErrors.HasErrors() {
			c.log.Debugw("Validation errors", "errors", result.ValidationErrors.String())
			return fmt.Errorf("validation failed: %s", result.ValidationErrors.String())
		}
		return fmt.Errorf("unexpected result: %s (response: %s)", result.Result, string(respBody))
	}

	c.log.Debugw("SetForward completed",
		"uuid", uuid,
		"domain", forward.Domain,
	)

	return nil
}

// DeleteForward deletes a domain forward by UUID.
func (c *Client) DeleteForward(ctx context.Context, uuid string) error {
	path := fmt.Sprintf("/unbound/settings/delForward/%s", uuid)

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

	c.log.Debugw("DeleteForward completed", "uuid", uuid)

	return nil
}

// ============================================================================
// Host Alias Operations
// ============================================================================

// SearchHostAliases searches for host aliases matching the search phrase.
func (c *Client) SearchHostAliases(ctx context.Context, searchPhrase string) ([]map[string]interface{}, error) {
	req := SearchRequest{SearchPhrase: searchPhrase}

	respBody, err := c.doRequest(ctx, "POST", "/unbound/settings/searchHostAlias", req)
	if err != nil {
		return nil, err
	}

	var resp SearchResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse search response: %w", err)
	}

	c.log.Debugw("SearchHostAliases completed",
		"search_phrase", searchPhrase,
		"count", len(resp.Rows),
	)

	return resp.Rows, nil
}

// ListAllHostAliases retrieves ALL host aliases from OPNsense.
func (c *Client) ListAllHostAliases(ctx context.Context) ([]map[string]interface{}, error) {
	return c.SearchHostAliases(ctx, "")
}

// FilterManagedHostAliases filters host aliases by NDAgent UUID prefix.
func FilterManagedHostAliases(aliases []map[string]interface{}) []map[string]interface{} {
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

// GetHostAlias retrieves a single host alias by UUID.
func (c *Client) GetHostAlias(ctx context.Context, uuid string) (map[string]interface{}, error) {
	path := fmt.Sprintf("/unbound/settings/getHostAlias/%s", uuid)

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

// GetHostAliasByName searches for a host alias by exact hostname+domain match.
func (c *Client) GetHostAliasByName(ctx context.Context, hostname, domain string) (map[string]interface{}, error) {
	aliases, err := c.SearchHostAliases(ctx, hostname)
	if err != nil {
		return nil, err
	}

	for _, alias := range aliases {
		h, _ := alias["hostname"].(string)
		d, _ := alias["domain"].(string)
		if h == hostname && d == domain {
			return alias, nil
		}
	}

	return nil, nil // Not found
}

// SetHostAlias creates or updates a host alias (upsert operation).
func (c *Client) SetHostAlias(ctx context.Context, uuid string, alias HostAlias) error {
	path := fmt.Sprintf("/unbound/settings/setHostAlias/%s", uuid)
	wrapper := HostAliasWrapper{Alias: alias}

	respBody, err := c.doRequest(ctx, "POST", path, wrapper)
	if err != nil {
		return err
	}

	var result SetHostAliasResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if result.Result != "saved" {
		if result.ValidationErrors.HasErrors() {
			c.log.Debugw("Validation errors", "errors", result.ValidationErrors.String())
			return fmt.Errorf("validation failed: %s", result.ValidationErrors.String())
		}
		return fmt.Errorf("unexpected result: %s (response: %s)", result.Result, string(respBody))
	}

	c.log.Debugw("SetHostAlias completed",
		"uuid", uuid,
		"hostname", alias.Hostname,
		"domain", alias.Domain,
	)

	return nil
}

// DeleteHostAlias deletes a host alias by UUID.
func (c *Client) DeleteHostAlias(ctx context.Context, uuid string) error {
	path := fmt.Sprintf("/unbound/settings/delHostAlias/%s", uuid)

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

	c.log.Debugw("DeleteHostAlias completed", "uuid", uuid)

	return nil
}

// ============================================================================
// ACL Operations
// ============================================================================

// SearchACLs searches for ACLs matching the search phrase.
func (c *Client) SearchACLs(ctx context.Context, searchPhrase string) ([]map[string]interface{}, error) {
	req := SearchRequest{SearchPhrase: searchPhrase}

	respBody, err := c.doRequest(ctx, "POST", "/unbound/settings/searchAcl", req)
	if err != nil {
		return nil, err
	}

	var resp SearchResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse search response: %w", err)
	}

	c.log.Debugw("SearchACLs completed",
		"search_phrase", searchPhrase,
		"count", len(resp.Rows),
	)

	return resp.Rows, nil
}

// ListAllACLs retrieves ALL ACLs from OPNsense.
func (c *Client) ListAllACLs(ctx context.Context) ([]map[string]interface{}, error) {
	return c.SearchACLs(ctx, "")
}

// FilterManagedACLs filters ACLs by NDAgent UUID prefix.
func FilterManagedACLs(acls []map[string]interface{}) []map[string]interface{} {
	var managed []map[string]interface{}
	for _, acl := range acls {
		if uuid, ok := acl["uuid"].(string); ok {
			if strings.HasPrefix(uuid, NDAgentUUIDPrefix+"-") {
				managed = append(managed, acl)
			}
		}
	}
	return managed
}

// GetACL retrieves a single ACL by UUID.
func (c *Client) GetACL(ctx context.Context, uuid string) (map[string]interface{}, error) {
	path := fmt.Sprintf("/unbound/settings/getAcl/%s", uuid)

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

// GetACLByName searches for an ACL by exact name match.
func (c *Client) GetACLByName(ctx context.Context, name string) (map[string]interface{}, error) {
	acls, err := c.SearchACLs(ctx, name)
	if err != nil {
		return nil, err
	}

	for _, acl := range acls {
		aclName, _ := acl["name"].(string)
		if aclName == name {
			return acl, nil
		}
	}

	return nil, nil // Not found
}

// SetACL creates or updates an ACL (upsert operation).
func (c *Client) SetACL(ctx context.Context, uuid string, acl UnboundACL) error {
	path := fmt.Sprintf("/unbound/settings/setAcl/%s", uuid)
	wrapper := UnboundACLWrapper{ACL: acl}

	respBody, err := c.doRequest(ctx, "POST", path, wrapper)
	if err != nil {
		return err
	}

	var result SetACLResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if result.Result != "saved" {
		if result.ValidationErrors.HasErrors() {
			c.log.Debugw("Validation errors", "errors", result.ValidationErrors.String())
			return fmt.Errorf("validation failed: %s", result.ValidationErrors.String())
		}
		return fmt.Errorf("unexpected result: %s (response: %s)", result.Result, string(respBody))
	}

	c.log.Debugw("SetACL completed",
		"uuid", uuid,
		"name", acl.Name,
	)

	return nil
}

// DeleteACL deletes an ACL by UUID.
func (c *Client) DeleteACL(ctx context.Context, uuid string) error {
	path := fmt.Sprintf("/unbound/settings/delAcl/%s", uuid)

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

	c.log.Debugw("DeleteACL completed", "uuid", uuid)

	return nil
}

// ============================================================================
// Reconfigure / Apply Changes
// ============================================================================

// ReconfigureUnbound applies pending Unbound configuration changes.
func (c *Client) ReconfigureUnbound(ctx context.Context) error {
	_, err := c.doRequest(ctx, "POST", "/unbound/service/reconfigure", struct{}{})
	if err != nil {
		return fmt.Errorf("reconfigure failed: %w", err)
	}

	c.log.Debug("ReconfigureUnbound completed")

	return nil
}

// ============================================================================
// Conversion Functions
// ============================================================================

// ConvertToOPNHostOverride converts APIHostOverridePayload to HostOverride.
func ConvertToOPNHostOverride(payload APIHostOverridePayload) HostOverride {
	enabled := "0"
	if payload.Enabled {
		enabled = "1"
	}

	// Build description with template tags
	desc := payload.Description
	for _, t := range payload.Templates {
		desc = AddTemplateTag(desc, t)
	}

	return HostOverride{
		Enabled:     enabled,
		Hostname:    payload.Hostname,
		Domain:      payload.Domain,
		RR:          payload.RR,
		Server:      payload.Server,
		MXPrio:      payload.MXPrio,
		MX:          payload.MX,
		TTL:         payload.TTL,
		TXTData:     payload.TXTData,
		Description: strings.TrimSpace(desc),
	}
}

// ConvertToOPNDomainForward converts APIDomainForwardPayload to DomainForward.
func ConvertToOPNDomainForward(payload APIDomainForwardPayload) DomainForward {
	enabled := "0"
	if payload.Enabled {
		enabled = "1"
	}

	forwardTCP := "0"
	if payload.ForwardTCPUpstream {
		forwardTCP = "1"
	}

	forwardFirst := "0"
	if payload.ForwardFirst {
		forwardFirst = "1"
	}

	// Build description with template tags
	desc := payload.Description
	for _, t := range payload.Templates {
		desc = AddTemplateTag(desc, t)
	}

	return DomainForward{
		Enabled:            enabled,
		Type:               payload.Type,
		Domain:             payload.Domain,
		Server:             payload.Server,
		Port:               payload.Port,
		Verify:             payload.Verify,
		ForwardTCPUpstream: forwardTCP,
		ForwardFirst:       forwardFirst,
		Description:        strings.TrimSpace(desc),
	}
}

// ConvertToOPNHostAlias converts APIHostAliasPayload to HostAlias.
// The parentUUID must be resolved before calling this function.
func ConvertToOPNHostAlias(payload APIHostAliasPayload, parentUUID string) HostAlias {
	enabled := "0"
	if payload.Enabled {
		enabled = "1"
	}

	// Build description with template tags
	desc := payload.Description
	for _, t := range payload.Templates {
		desc = AddTemplateTag(desc, t)
	}

	return HostAlias{
		Enabled:     enabled,
		Host:        parentUUID,
		Hostname:    payload.Hostname,
		Domain:      payload.Domain,
		Description: strings.TrimSpace(desc),
	}
}

// ConvertToOPNACL converts APIUnboundACLPayload to UnboundACL.
func ConvertToOPNACL(payload APIUnboundACLPayload) UnboundACL {
	enabled := "0"
	if payload.Enabled {
		enabled = "1"
	}

	// Build description with template tags
	desc := payload.Description
	for _, t := range payload.Templates {
		desc = AddTemplateTag(desc, t)
	}

	return UnboundACL{
		Enabled:     enabled,
		Name:        payload.Name,
		Action:      payload.Action,
		Networks:    strings.Join(payload.Networks, ","),
		Description: strings.TrimSpace(desc),
	}
}

// ConvertHostOverrideToAPI converts raw host override map to portable API format.
func ConvertHostOverrideToAPI(raw map[string]interface{}) APIHostOverridePayload {
	uuid, _ := raw["uuid"].(string)
	enabled, _ := raw["enabled"].(string)
	hostname, _ := raw["hostname"].(string)
	domain, _ := raw["domain"].(string)
	rr, _ := raw["rr"].(string)
	server, _ := raw["server"].(string)
	mxprio, _ := raw["mxprio"].(string)
	mx, _ := raw["mx"].(string)
	ttl, _ := raw["ttl"].(string)
	txtdata, _ := raw["txtdata"].(string)
	description, _ := raw["description"].(string)

	return APIHostOverridePayload{
		UUID:        uuid,
		Enabled:     OPNsenseToBool(enabled),
		Hostname:    hostname,
		Domain:      domain,
		RR:          rr,
		Server:      server,
		MXPrio:      mxprio,
		MX:          mx,
		TTL:         ttl,
		TXTData:     txtdata,
		Description: StripTemplateTags(description),
		Templates:   ParseTemplateTags(description),
	}
}

// ConvertDomainForwardToAPI converts raw domain forward map to portable API format.
func ConvertDomainForwardToAPI(raw map[string]interface{}) APIDomainForwardPayload {
	uuid, _ := raw["uuid"].(string)
	enabled, _ := raw["enabled"].(string)
	fwdType, _ := raw["type"].(string)
	domain, _ := raw["domain"].(string)
	server, _ := raw["server"].(string)
	port, _ := raw["port"].(string)
	verify, _ := raw["verify"].(string)
	forwardTCP, _ := raw["forward_tcp_upstream"].(string)
	forwardFirst, _ := raw["forward_first"].(string)
	description, _ := raw["description"].(string)

	return APIDomainForwardPayload{
		UUID:               uuid,
		Enabled:            OPNsenseToBool(enabled),
		Type:               fwdType,
		Domain:             domain,
		Server:             server,
		Port:               port,
		Verify:             verify,
		ForwardTCPUpstream: OPNsenseToBool(forwardTCP),
		ForwardFirst:       OPNsenseToBool(forwardFirst),
		Description:        StripTemplateTags(description),
		Templates:          ParseTemplateTags(description),
	}
}

// ConvertHostAliasToAPI converts raw host alias map to portable API format.
// Requires the list of all host overrides to resolve parent UUID to hostname+domain.
func ConvertHostAliasToAPI(raw map[string]interface{}, hostOverrides []map[string]interface{}) APIHostAliasPayload {
	uuid, _ := raw["uuid"].(string)
	enabled, _ := raw["enabled"].(string)
	hostUUID, _ := raw["host"].(string)
	hostname, _ := raw["hostname"].(string)
	domain, _ := raw["domain"].(string)
	description, _ := raw["description"].(string)

	// Resolve parent UUID to hostname+domain
	var parentHostname, parentDomain string
	for _, override := range hostOverrides {
		if ouuid, _ := override["uuid"].(string); ouuid == hostUUID {
			parentHostname, _ = override["hostname"].(string)
			parentDomain, _ = override["domain"].(string)
			break
		}
	}

	return APIHostAliasPayload{
		UUID:           uuid,
		Enabled:        OPNsenseToBool(enabled),
		ParentHostname: parentHostname,
		ParentDomain:   parentDomain,
		Hostname:       hostname,
		Domain:         domain,
		Description:    StripTemplateTags(description),
		Templates:      ParseTemplateTags(description),
	}
}

// ConvertACLToAPI converts raw ACL map to portable API format.
func ConvertACLToAPI(raw map[string]interface{}) APIUnboundACLPayload {
	uuid, _ := raw["uuid"].(string)
	enabled, _ := raw["enabled"].(string)
	name, _ := raw["name"].(string)
	action, _ := raw["action"].(string)
	networks, _ := raw["networks"].(string)
	description, _ := raw["description"].(string)

	return APIUnboundACLPayload{
		UUID:        uuid,
		Enabled:     OPNsenseToBool(enabled),
		Name:        name,
		Action:      action,
		Networks:    CSVToStrings(networks),
		Description: StripTemplateTags(description),
		Templates:   ParseTemplateTags(description),
	}
}

// BuildHostOverrideUUIDLookup creates a map of hostname+domain to UUID.
func BuildHostOverrideUUIDLookup(overrides []map[string]interface{}) map[string]string {
	lookup := make(map[string]string)
	for _, override := range overrides {
		hostname, _ := override["hostname"].(string)
		domain, _ := override["domain"].(string)
		uuid, _ := override["uuid"].(string)
		if hostname != "" && domain != "" && uuid != "" {
			key := hostname + "." + domain
			lookup[key] = uuid
		}
	}
	return lookup
}
