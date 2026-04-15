package opnapi

import (
	"context"
	"encoding/json"
	"fmt"
)

// SearchUsers searches for users matching the search phrase.
func (c *Client) SearchUsers(ctx context.Context, searchPhrase string) ([]map[string]interface{}, error) {
	req := SearchRequest{SearchPhrase: searchPhrase}

	respBody, err := c.doRequest(ctx, "POST", "/auth/user/search", req)
	if err != nil {
		return nil, err
	}

	var resp SearchResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse search response: %w", err)
	}

	c.log.Debugw("SearchUsers completed",
		"search_phrase", searchPhrase,
		"count", len(resp.Rows),
	)

	return resp.Rows, nil
}

// ListAllUsers retrieves ALL users from OPNsense.
// Returns raw results; caller should filter for managed users.
func (c *Client) ListAllUsers(ctx context.Context) ([]map[string]interface{}, error) {
	return c.SearchUsers(ctx, "")
}

// FilterManagedUsers filters users by NDAgent managed tag in description.
func FilterManagedUsers(users []map[string]interface{}) []map[string]interface{} {
	var managed []map[string]interface{}
	for _, user := range users {
		desc, _ := user["descr"].(string)
		if IsManagedByDescription(desc) {
			managed = append(managed, user)
		}
	}
	return managed
}

// GetUser retrieves a single user by UUID.
func (c *Client) GetUser(ctx context.Context, uuid string) (map[string]interface{}, error) {
	path := fmt.Sprintf("/auth/user/get/%s", uuid)

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

// GetUserByName searches for a user by exact name match.
func (c *Client) GetUserByName(ctx context.Context, name string) (map[string]interface{}, error) {
	users, err := c.SearchUsers(ctx, name)
	if err != nil {
		return nil, err
	}

	for _, user := range users {
		if userName, ok := user["name"].(string); ok && userName == name {
			return user, nil
		}
	}

	return nil, nil // Not found
}

// AddUser creates a new user. Returns the new UUID.
// Password is required for user creation.
func (c *Client) AddUser(ctx context.Context, user User) (string, error) {
	wrapper := UserWrapper{User: user}

	respBody, err := c.doRequest(ctx, "POST", "/auth/user/add", wrapper)
	if err != nil {
		return "", err
	}

	var result SetUserResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if result.Result != "saved" {
		if result.ValidationErrors.HasErrors() {
			c.log.Debugw("Validation errors", "errors", result.ValidationErrors.String())
			return "", fmt.Errorf("validation failed: %s", result.ValidationErrors.String())
		}
		return "", fmt.Errorf("unexpected result: %s (response: %s)", result.Result, string(respBody))
	}

	c.log.Debugw("AddUser completed",
		"uuid", result.UUID,
		"name", user.Name,
	)

	return result.UUID, nil
}

// SetUser updates an existing user by UUID.
// Password can be omitted to keep existing password.
func (c *Client) SetUser(ctx context.Context, uuid string, user User) error {
	path := fmt.Sprintf("/auth/user/set/%s", uuid)
	wrapper := UserWrapper{User: user}

	respBody, err := c.doRequest(ctx, "POST", path, wrapper)
	if err != nil {
		return err
	}

	var result SetUserResponse
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

	c.log.Debugw("SetUser completed",
		"uuid", uuid,
		"name", user.Name,
	)

	return nil
}

// DeleteUser deletes a user by UUID.
func (c *Client) DeleteUser(ctx context.Context, uuid string) error {
	path := fmt.Sprintf("/auth/user/del/%s", uuid)

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

	c.log.Debugw("DeleteUser completed", "uuid", uuid)

	return nil
}

// BuildUIDLookup creates a map of username to UID from a list of users.
func BuildUIDLookup(users []map[string]interface{}) map[string]string {
	lookup := make(map[string]string)
	for _, user := range users {
		name, _ := user["name"].(string)
		uid, _ := user["uid"].(string)
		if name != "" && uid != "" {
			lookup[name] = uid
		}
	}
	return lookup
}

// BuildUserUUIDLookup creates a map of username to UUID from a list of users.
func BuildUserUUIDLookup(users []map[string]interface{}) map[string]string {
	lookup := make(map[string]string)
	for _, user := range users {
		name, _ := user["name"].(string)
		uuid, _ := user["uuid"].(string)
		if name != "" && uuid != "" {
			lookup[name] = uuid
		}
	}
	return lookup
}

// ConvertUserToAPI converts a raw user map to the portable API format.
func ConvertUserToAPI(rawUser map[string]interface{}, groups []map[string]interface{}) APIUserPayload {
	name, _ := rawUser["name"].(string)
	disabled, _ := rawUser["disabled"].(string)
	scope, _ := rawUser["scope"].(string)
	descr, _ := rawUser["descr"].(string)
	groupMemberships, _ := rawUser["group_memberships"].(string)
	priv, _ := rawUser["priv"].(string)
	shell, _ := rawUser["shell"].(string)
	authorizedKeys, _ := rawUser["authorizedkeys"].(string)
	expires, _ := rawUser["expires"].(string)
	email, _ := rawUser["email"].(string)
	comment, _ := rawUser["comment"].(string)
	language, _ := rawUser["language"].(string)
	landingPage, _ := rawUser["landing_page"].(string)
	password, _ := rawUser["password"].(string)

	// Resolve group GIDs to names
	groupNames := ResolveGIDsToGroupNames(groupMemberships, groups)

	return APIUserPayload{
		Name:           name,
		Password:       password, // Bcrypt hash
		Disabled:       OPNsenseToBool(disabled),
		Scope:          scope,
		Descr:          StripTemplateTags(descr),
		Groups:         groupNames,
		Priv:           CSVToStrings(priv),
		Shell:          shell,
		AuthorizedKeys: authorizedKeys,
		Expires:        expires,
		Email:          email,
		Comment:        comment,
		Language:       language,
		LandingPage:    landingPage,
		Templates:      ParseTemplateTags(descr),
	}
}

// ConvertAPIToUser converts the portable API format to OPNsense User format.
func ConvertAPIToUser(payload APIUserPayload, templates []string, gidLookup map[string]string) User {
	// Build description with template tags (presence of [nd-template:*] marks it as managed)
	descr := payload.Descr
	for _, t := range templates {
		descr = AddTemplateTag(descr, t)
	}

	// Resolve group names to GIDs
	groupGIDs, _ := ResolveGroupNamesToGIDs(payload.Groups, gidLookup)

	return User{
		Name:             payload.Name,
		Password:         payload.Password,
		Disabled:         BoolToOPNsense(payload.Disabled),
		Scope:            payload.Scope,
		Descr:            descr,
		GroupMemberships: groupGIDs,
		Priv:             StringsToCSV(payload.Priv),
		Shell:            payload.Shell,
		AuthorizedKeys:   payload.AuthorizedKeys,
		Expires:          payload.Expires,
		Email:            payload.Email,
		Comment:          payload.Comment,
		Language:         payload.Language,
		LandingPage:      payload.LandingPage,
	}
}

// IsProtectedUser checks if a username is protected from modification.
func IsProtectedUser(username string) bool {
	return ProtectedUsernames[username]
}

// IsProtectedGroup checks if a group name is protected from modification.
func IsProtectedGroup(groupName string) bool {
	return ProtectedGroupNames[groupName]
}
