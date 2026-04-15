package tasks

import (
	"context"
	"fmt"

	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/network"
	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// HandlePullAPI handles the PULL task using OPNsense REST API.
// Uses API calls to fetch aliases by name or rules by description (partial match).
func HandlePullAPI(ctx context.Context, ws *network.WebSocketClient, cmd network.Command) error {
	log := logging.Named("PULL")

	log.Infow("Received PULL command", "task_id", cmd.TaskID)

	// Validate API client is configured
	apiClient := ws.GetAPIClient()
	if apiClient == nil {
		result := NewFailureResult("PULL not available: API credentials not configured")
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	// Parse payload
	if cmd.Payload == nil {
		result := NewFailureResult("No payload provided")
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	configType, _ := cmd.Payload["config_type"].(string)
	name, _ := cmd.Payload["name"].(string)

	if configType == "" || name == "" {
		result := NewFailureResult("Missing required payload fields: config_type and name")
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	log.Infow("Executing PULL",
		"config_type", configType,
		"name", name,
	)

	// Fetch by config type
	var content map[string]interface{}
	var err error

	switch configType {
	case "alias":
		content, err = pullAlias(ctx, apiClient, name)
	case "rule":
		content, err = pullRule(ctx, apiClient, name)
	case "user":
		content, err = pullUser(ctx, apiClient, name)
	case "group":
		content, err = pullGroup(ctx, apiClient, name)
	case "unbound_host_override":
		content, err = pullHostOverride(ctx, apiClient, name)
	case "unbound_domain_forward":
		content, err = pullDomainForward(ctx, apiClient, name)
	case "unbound_host_alias":
		content, err = pullHostAlias(ctx, apiClient, name)
	case "unbound_acl":
		content, err = pullUnboundACL(ctx, apiClient, name)
	default:
		result := NewFailureResult(fmt.Sprintf("Unsupported config_type: %s", configType))
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	if err != nil {
		log.Errorw("Failed to pull config",
			"config_type", configType,
			"name", name,
			"error", err,
		)
		result := NewFailureResult(fmt.Sprintf("Failed to pull %s: %v", configType, err))
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	if content == nil {
		log.Infow("Config not found",
			"config_type", configType,
			"name", name,
		)
		result := NewFailureResult(fmt.Sprintf("%s '%s' not found", configType, name))
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	log.Infow("PULL successful",
		"config_type", configType,
		"name", name,
	)

	// Return success with content
	data := map[string]interface{}{
		"content": content,
	}
	result := NewSuccessResultWithData(fmt.Sprintf("Found %s '%s'", configType, name), data)
	return SendTaskResponse(ws, cmd.TaskID, result)
}

// pullAlias searches for an alias by exact name match.
func pullAlias(ctx context.Context, client *opnapi.Client, name string) (map[string]interface{}, error) {
	return client.GetAliasByName(ctx, name)
}

// pullRule searches for a rule by partial description match.
// Returns error if multiple rules match (uniqueness required).
func pullRule(ctx context.Context, client *opnapi.Client, description string) (map[string]interface{}, error) {
	return client.GetRuleByDescription(ctx, description)
}

// pullUser searches for a user by exact name match and returns portable format.
func pullUser(ctx context.Context, client *opnapi.Client, name string) (map[string]interface{}, error) {
	// Find user by name
	rawUser, err := client.GetUserByName(ctx, name)
	if err != nil {
		return nil, err
	}
	if rawUser == nil {
		return nil, nil // Not found
	}

	// Get all groups for name resolution
	groups, err := client.ListAllGroups(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list groups for resolution: %w", err)
	}

	// Convert to portable format
	payload := opnapi.ConvertUserToAPI(rawUser, groups)

	// Return as map for consistent API response
	return map[string]interface{}{
		"name":           payload.Name,
		"password":       payload.Password,
		"disabled":       payload.Disabled,
		"scope":          payload.Scope,
		"descr":          payload.Descr,
		"groups":         payload.Groups,
		"priv":           payload.Priv,
		"shell":          payload.Shell,
		"authorizedkeys": payload.AuthorizedKeys,
		"expires":        payload.Expires,
		"email":          payload.Email,
		"comment":        payload.Comment,
		"language":       payload.Language,
		"landing_page":   payload.LandingPage,
	}, nil
}

// pullGroup searches for a group by exact name match and returns portable format.
func pullGroup(ctx context.Context, client *opnapi.Client, name string) (map[string]interface{}, error) {
	// Find group by name
	rawGroup, err := client.GetGroupByName(ctx, name)
	if err != nil {
		return nil, err
	}
	if rawGroup == nil {
		return nil, nil // Not found
	}

	// Get all users for member name resolution
	users, err := client.ListAllUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list users for resolution: %w", err)
	}

	// Convert to portable format
	payload := opnapi.ConvertGroupToAPI(rawGroup, users)

	// Return as map for consistent API response
	return map[string]interface{}{
		"name":            payload.Name,
		"description":     payload.Description,
		"priv":            payload.Priv,
		"members":         payload.Members,
		"source_networks": payload.SourceNetworks,
	}, nil
}

// pullHostOverride searches for a host override by hostname.domain and returns portable format.
func pullHostOverride(ctx context.Context, client *opnapi.Client, name string) (map[string]interface{}, error) {
	// Parse hostname.domain format
	hostname, domain := parseHostDomainName(name)

	rawOverride, err := client.GetHostOverrideByName(ctx, hostname, domain)
	if err != nil {
		return nil, err
	}
	if rawOverride == nil {
		return nil, nil // Not found
	}

	// Convert to portable format
	payload := opnapi.ConvertHostOverrideToAPI(rawOverride)

	return map[string]interface{}{
		"uuid":        payload.UUID,
		"enabled":     payload.Enabled,
		"hostname":    payload.Hostname,
		"domain":      payload.Domain,
		"rr":          payload.RR,
		"server":      payload.Server,
		"mxprio":      payload.MXPrio,
		"mx":          payload.MX,
		"ttl":         payload.TTL,
		"txtdata":     payload.TXTData,
		"description": payload.Description,
		"templates":   payload.Templates,
	}, nil
}

// pullDomainForward searches for a domain forward by domain name.
func pullDomainForward(ctx context.Context, client *opnapi.Client, domain string) (map[string]interface{}, error) {
	rawForward, err := client.GetForwardByDomain(ctx, domain)
	if err != nil {
		return nil, err
	}
	if rawForward == nil {
		return nil, nil // Not found
	}

	// Convert to portable format
	payload := opnapi.ConvertDomainForwardToAPI(rawForward)

	return map[string]interface{}{
		"uuid":                 payload.UUID,
		"enabled":              payload.Enabled,
		"type":                 payload.Type,
		"domain":               payload.Domain,
		"server":               payload.Server,
		"port":                 payload.Port,
		"verify":               payload.Verify,
		"forward_tcp_upstream": payload.ForwardTCPUpstream,
		"forward_first":        payload.ForwardFirst,
		"description":          payload.Description,
		"templates":            payload.Templates,
	}, nil
}

// pullHostAlias searches for a host alias by hostname.domain and returns portable format.
func pullHostAlias(ctx context.Context, client *opnapi.Client, name string) (map[string]interface{}, error) {
	// Parse hostname.domain format
	hostname, domain := parseHostDomainName(name)

	rawAlias, err := client.GetHostAliasByName(ctx, hostname, domain)
	if err != nil {
		return nil, err
	}
	if rawAlias == nil {
		return nil, nil // Not found
	}

	// Get all host overrides for parent resolution
	hostOverrides, err := client.ListAllHostOverrides(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list host overrides for parent resolution: %w", err)
	}

	// Convert to portable format (resolves parent UUID to hostname+domain)
	payload := opnapi.ConvertHostAliasToAPI(rawAlias, hostOverrides)

	return map[string]interface{}{
		"uuid":            payload.UUID,
		"enabled":         payload.Enabled,
		"parent_hostname": payload.ParentHostname,
		"parent_domain":   payload.ParentDomain,
		"hostname":        payload.Hostname,
		"domain":          payload.Domain,
		"description":     payload.Description,
		"templates":       payload.Templates,
	}, nil
}

// pullUnboundACL searches for an Unbound ACL by name.
func pullUnboundACL(ctx context.Context, client *opnapi.Client, name string) (map[string]interface{}, error) {
	rawACL, err := client.GetACLByName(ctx, name)
	if err != nil {
		return nil, err
	}
	if rawACL == nil {
		return nil, nil // Not found
	}

	// Convert to portable format
	payload := opnapi.ConvertACLToAPI(rawACL)

	return map[string]interface{}{
		"uuid":        payload.UUID,
		"enabled":     payload.Enabled,
		"name":        payload.Name,
		"action":      payload.Action,
		"networks":    payload.Networks,
		"description": payload.Description,
		"templates":   payload.Templates,
	}, nil
}

// parseHostDomainName parses "hostname.domain" format into separate parts.
// If no domain part is found, returns the full name as hostname and empty domain.
func parseHostDomainName(name string) (hostname, domain string) {
	// Find the first dot - everything before is hostname, after is domain
	idx := -1
	for i, c := range name {
		if c == '.' {
			idx = i
			break
		}
	}
	if idx == -1 {
		return name, ""
	}
	return name[:idx], name[idx+1:]
}
