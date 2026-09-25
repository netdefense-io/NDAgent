package opnapi

import (
	"context"
	"encoding/json"
	"fmt"
)

// SearchGroups searches for groups matching the search phrase.
func (c *Client) SearchGroups(ctx context.Context, searchPhrase string) ([]map[string]interface{}, error) {
	req := SearchRequest{SearchPhrase: searchPhrase}

	respBody, err := c.doRequest(ctx, "POST", "/auth/group/search", req)
	if err != nil {
		return nil, err
	}

	var resp SearchResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse search response: %w", err)
	}

	c.log.Debugw("SearchGroups completed",
		"search_phrase", searchPhrase,
		"count", len(resp.Rows),
	)

	return resp.Rows, nil
}

// ListAllGroups retrieves ALL groups from OPNsense.
// Returns raw results; caller should filter for managed groups.
func (c *Client) ListAllGroups(ctx context.Context) ([]map[string]interface{}, error) {
	return c.SearchGroups(ctx, "")
}

// FilterManagedGroups filters groups by NDAgent managed tag in description.
func FilterManagedGroups(groups []map[string]interface{}) []map[string]interface{} {
	var managed []map[string]interface{}
	for _, group := range groups {
		desc, _ := group["description"].(string)
		if IsManagedByDescription(desc) {
			managed = append(managed, group)
		}
	}
	return managed
}

// GetGroup retrieves a single group by UUID.
func (c *Client) GetGroup(ctx context.Context, uuid string) (map[string]interface{}, error) {
	path := fmt.Sprintf("/auth/group/get/%s", uuid)

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

// GetGroupByName searches for a group by exact name match.
func (c *Client) GetGroupByName(ctx context.Context, name string) (map[string]interface{}, error) {
	groups, err := c.SearchGroups(ctx, name)
	if err != nil {
		return nil, err
	}

	for _, group := range groups {
		if groupName, ok := group["name"].(string); ok && groupName == name {
			return group, nil
		}
	}

	return nil, nil // Not found
}

// GetGroupRawMemberByName does a fresh, exact-name lookup of a group's raw
// stored `member` CSV.
//
// It goes through GetGroupByName (search rows), deliberately NOT GetGroup
// (/auth/group/get/<uuid>): BaseListField.getNodeOptions() -- what that
// endpoint returns for a Multiple field -- only ever emits entries for
// uids in its own valid-option list, so a structurally-invalid empty or
// stale token in the stored value (see SanitizeMemberCSV) is invisible
// there; search rows carry the raw string untouched. found is false if no
// group with this exact name exists (e.g. it was deleted out from under
// this sync); err is any transport/decode failure.
func (c *Client) GetGroupRawMemberByName(ctx context.Context, name string) (member string, found bool, err error) {
	group, err := c.GetGroupByName(ctx, name)
	if err != nil {
		return "", false, err
	}
	if group == nil {
		return "", false, nil
	}
	m, _ := group["member"].(string)
	return m, true, nil
}

// AddGroup creates a new group. Returns the new UUID.
func (c *Client) AddGroup(ctx context.Context, group Group) (string, error) {
	wrapper := GroupWrapper{Group: group}

	respBody, err := c.doRequest(ctx, "POST", "/auth/group/add", wrapper)
	if err != nil {
		return "", err
	}

	var result SetGroupResponse
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

	c.log.Debugw("AddGroup completed",
		"uuid", result.UUID,
		"name", group.Name,
	)

	return result.UUID, nil
}

// SetGroup updates an existing group by UUID.
func (c *Client) SetGroup(ctx context.Context, uuid string, group Group) error {
	path := fmt.Sprintf("/auth/group/set/%s", uuid)
	wrapper := GroupWrapper{Group: group}

	respBody, err := c.doRequest(ctx, "POST", path, wrapper)
	if err != nil {
		return err
	}

	var result SetGroupResponse
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

	c.log.Debugw("SetGroup completed",
		"uuid", uuid,
		"name", group.Name,
	)

	return nil
}

// groupMemberRepairWrapper mirrors GroupWrapper/Group but its Member field
// carries no `omitempty`. It exists only for RepairGroupMember: repairing
// the empty-token artifact SanitizeMemberCSV detects requires being able
// to send an explicit "member":"" when every stored token was an
// artifact, and Group.Member's `omitempty` (needed everywhere else, so an
// external group's normal update never sends "member" at all) would
// silently drop exactly that value.
type groupMemberRepairWrapper struct {
	Group struct {
		Name           string `json:"name"`
		Description    string `json:"description"`
		Priv           string `json:"priv"`
		Member         string `json:"member"`
		SourceNetworks string `json:"source_networks"`
	} `json:"group"`
}

// RepairGroupMember sends an explicit `member` value that repairs the
// empty-token or stale-uid artifact SanitizeMemberCSV/
// SanitizeMemberCSVAgainstUsers detects in a group's stored member CSV.
//
// sanitizedMember is always the caller's own sanitized copy of a value it
// just read fresh from the device -- never a value NDAgent invents -- and
// is always a subset of that read's real tokens, so this can only ever
// remove an artifact, never a member the directory (or a local admin)
// actually granted at read time.
//
// This is NOT fully race-safe: the read (a separate request) and this
// write are not atomic, so a directory login landing in between can have
// this call overwrite that login's own change with the caller's
// now-stale value -- most concretely, re-adding a uid a concurrent revoke
// just removed. That reinstated membership then self-heals only on that
// user's OWN next interactive login (which re-evaluates and re-corrects
// it), NOT on NDAgent's next sync: once the stored value is clean again,
// no future sync sends `member` for it at all. This residual read-then-
// write race is an accepted risk: it can only reinstate a membership the
// directory itself re-evaluates on that user's next login.
//
// group's other fields (Priv, SourceNetworks, Description) are carried
// through unchanged from the caller's already-computed update, so this
// call has no effect beyond the member repair plus whatever that update
// was already going to send.
func (c *Client) RepairGroupMember(ctx context.Context, uuid string, group Group, sanitizedMember string) error {
	path := fmt.Sprintf("/auth/group/set/%s", uuid)
	var wrapper groupMemberRepairWrapper
	wrapper.Group.Name = group.Name
	wrapper.Group.Description = group.Description
	wrapper.Group.Priv = group.Priv
	wrapper.Group.SourceNetworks = group.SourceNetworks
	wrapper.Group.Member = sanitizedMember

	respBody, err := c.doRequest(ctx, "POST", path, wrapper)
	if err != nil {
		return err
	}

	var result SetGroupResponse
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

	c.log.Infow("RepairGroupMember completed: sanitized a stale empty-token member artifact",
		"uuid", uuid,
		"name", group.Name,
	)

	return nil
}

// DeleteGroup deletes a group by UUID.
func (c *Client) DeleteGroup(ctx context.Context, uuid string) error {
	path := fmt.Sprintf("/auth/group/del/%s", uuid)

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

	c.log.Debugw("DeleteGroup completed", "uuid", uuid)

	return nil
}

// BuildGIDLookup creates a map of group name to GID from a list of groups.
func BuildGIDLookup(groups []map[string]interface{}) map[string]string {
	lookup := make(map[string]string)
	for _, group := range groups {
		name, _ := group["name"].(string)
		gid, _ := group["gid"].(string)
		if name != "" && gid != "" {
			lookup[name] = gid
		}
	}
	return lookup
}

// BuildGroupUUIDLookup creates a map of group name to UUID from a list of groups.
func BuildGroupUUIDLookup(groups []map[string]interface{}) map[string]string {
	lookup := make(map[string]string)
	for _, group := range groups {
		name, _ := group["name"].(string)
		uuid, _ := group["uuid"].(string)
		if name != "" && uuid != "" {
			lookup[name] = uuid
		}
	}
	return lookup
}

// ResolveGroupNamesToGIDs converts group names to GIDs using a lookup map.
func ResolveGroupNamesToGIDs(names []string, lookup map[string]string) (string, []string) {
	var gids []string
	var missing []string
	for _, name := range names {
		if gid, ok := lookup[name]; ok {
			gids = append(gids, gid)
		} else {
			missing = append(missing, name)
		}
	}
	return StringsToCSV(gids), missing
}

// ResolveGIDsToGroupNames converts GIDs to group names using a reverse lookup.
func ResolveGIDsToGroupNames(gidCSV string, groups []map[string]interface{}) []string {
	gids := CSVToStrings(gidCSV)
	if len(gids) == 0 {
		return nil
	}

	// Build reverse lookup: GID -> name
	gidToName := make(map[string]string)
	for _, group := range groups {
		name, _ := group["name"].(string)
		gid, _ := group["gid"].(string)
		if name != "" && gid != "" {
			gidToName[gid] = name
		}
	}

	var names []string
	for _, gid := range gids {
		if name, ok := gidToName[gid]; ok {
			names = append(names, name)
		}
	}
	return names
}

// ConvertGroupToAPI converts a raw group map to the portable API format.
func ConvertGroupToAPI(rawGroup map[string]interface{}, users []map[string]interface{}) APIGroupPayload {
	name, _ := rawGroup["name"].(string)
	desc, _ := rawGroup["description"].(string)
	privCSV, _ := rawGroup["priv"].(string)
	memberCSV, _ := rawGroup["member"].(string)
	sourceNetworks, _ := rawGroup["source_networks"].(string)

	// Build UID to username lookup
	uidToName := make(map[string]string)
	for _, user := range users {
		uname, _ := user["name"].(string)
		uid, _ := user["uid"].(string)
		if uname != "" && uid != "" {
			uidToName[uid] = uname
		}
	}

	// Resolve member UIDs to usernames
	var memberNames []string
	for _, uid := range CSVToStrings(memberCSV) {
		if uname, ok := uidToName[uid]; ok {
			memberNames = append(memberNames, uname)
		}
	}

	return APIGroupPayload{
		Name:           name,
		Description:    StripTemplateTags(desc),
		Priv:           CSVToStrings(privCSV),
		Members:        memberNames,
		SourceNetworks: sourceNetworks,
		Templates:      ParseTemplateTags(desc),
	}
}

// ConvertAPIToGroup converts the portable API format to OPNsense Group format.
//
// For an external GROUP, `member` is never built or
// sent, whatever Members holds -- the directory owns membership, and
// OPNsense confirms an omitted `member` key leaves its existing members
// untouched. This check is defense-in-depth: NDManager's schema already
// requires Members to be empty for an external group, so this only matters
// if that invariant is ever violated upstream.
func ConvertAPIToGroup(payload APIGroupPayload, templates []string, uidLookup map[string]string) Group {
	// Build description with template tags (presence of [nd-template:*] marks it as managed)
	desc := payload.Description
	for _, t := range templates {
		desc = AddTemplateTag(desc, t)
	}

	group := Group{
		Name:           payload.Name,
		Description:    desc,
		Priv:           StringsToCSV(payload.Priv),
		SourceNetworks: payload.SourceNetworks,
	}

	if payload.ExternalMembers {
		return group
	}

	// Resolve member names to UIDs
	var memberUIDs []string
	for _, name := range payload.Members {
		if uid, ok := uidLookup[name]; ok {
			memberUIDs = append(memberUIDs, uid)
		}
		// Skip members that don't exist locally
	}
	group.Member = StringsToCSV(memberUIDs)
	return group
}
