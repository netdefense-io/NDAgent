package opnapi

import "strings"

// NDAgentTemplateTagPrefix is the prefix for template tags in descriptions.
// Resources with [nd-template:*] tags are considered managed by NDAgent.
const NDAgentTemplateTagPrefix = "[nd-template:"

// ProtectedUsernames lists usernames that cannot be modified via SYNC.
// netdefense-agent and netdefense-readonly are provisioned by the plugin
// itself (API credentials and the forged-session read-only identity,
// respectively) and must never be reachable through SYNC_API create/modify
// or orphan-delete.
var ProtectedUsernames = map[string]bool{
	"root":                true,
	"netdefense-agent":    true,
	"netdefense-readonly": true,
}

// ProtectedGroupNames lists group names that cannot be modified via SYNC.
// netdefense-readonly is provisioned alongside the same-named user above;
// both the user and the group must be protected or the co-named group's
// priv set (the read-only ACL allowlist) would remain SYNC-writable.
var ProtectedGroupNames = map[string]bool{
	"admins":              true,
	"netdefense-readonly": true,
}

// User represents an OPNsense user for API operations.
// Fields match the OPNsense auth/user API structure.
type User struct {
	Name             string `json:"name"`
	Password         string `json:"password,omitempty"`
	Disabled         string `json:"disabled"`
	Scope            string `json:"scope"`
	Descr            string `json:"descr"`
	GroupMemberships string `json:"group_memberships,omitempty"` // Comma-separated GIDs
	Priv             string `json:"priv,omitempty"`              // Comma-separated privileges
	Shell            string `json:"shell,omitempty"`
	AuthorizedKeys   string `json:"authorizedkeys,omitempty"`
	Expires          string `json:"expires,omitempty"`
	Email            string `json:"email,omitempty"`
	Comment          string `json:"comment,omitempty"`
	Language         string `json:"language,omitempty"`
	LandingPage      string `json:"landing_page,omitempty"`
}

// UserWrapper wraps a user for API set operations.
type UserWrapper struct {
	User User `json:"user"`
}

// Group represents an OPNsense group for API operations.
// Fields match the OPNsense auth/group API structure.
//
// Priv and SourceNetworks are deliberately NOT omitempty: an empty
// string is OPNsense's own "clear this field" signal, so omitting the
// key on a template-driven revoke would leave stale
// privileges/networks on the device forever. Member stays omitempty: for a
// member-managed GROUP an empty desired list still goes through the
// existing len(Members)==0 skip in executeSyncUsersGroups (unrelated to
// this struct tag), and for an external GROUP (external_members: true)
// Member must never be sent at all -- see ConvertAPIToGroup, which never
// populates it for those.
type Group struct {
	Name           string `json:"name"`
	Description    string `json:"description"`
	Priv           string `json:"priv"`             // Comma-separated privileges -- always sent, even ""
	Member         string `json:"member,omitempty"` // Comma-separated UIDs
	SourceNetworks string `json:"source_networks"`  // Always sent, even ""
}

// GroupWrapper wraps a group for API set operations.
type GroupWrapper struct {
	Group Group `json:"group"`
}

// APIUserPayload is the portable format for users in templates/snippets.
// Uses names instead of IDs for cross-firewall portability.
type APIUserPayload struct {
	Name           string   `json:"name"`
	Password       string   `json:"password,omitempty"` // Bcrypt hash
	Disabled       bool     `json:"disabled"`
	Scope          string   `json:"scope"`
	Descr          string   `json:"descr"`
	Groups         []string `json:"groups,omitempty"` // Group NAMES (not GIDs)
	Priv           []string `json:"priv,omitempty"`   // Privileges as array
	Shell          string   `json:"shell,omitempty"`
	AuthorizedKeys string   `json:"authorizedkeys,omitempty"`
	Expires        string   `json:"expires,omitempty"`
	Email          string   `json:"email,omitempty"`
	Comment        string   `json:"comment,omitempty"`
	Language       string   `json:"language,omitempty"`
	LandingPage    string   `json:"landing_page,omitempty"`
	Templates      []string `json:"templates,omitempty"` // Template metadata
}

// APIGroupPayload is the portable format for groups in templates/snippets.
// Uses names instead of IDs for cross-firewall portability.
type APIGroupPayload struct {
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	Priv           []string `json:"priv,omitempty"`    // Privileges as array
	Members        []string `json:"members,omitempty"` // User NAMES (not UIDs)
	SourceNetworks string   `json:"source_networks,omitempty"`
	Templates      []string `json:"templates,omitempty"` // Template metadata

	// ExternalMembers marks a GROUP whose membership the directory owns
	// (org:su). NetDefense owns the group's
	// existence, Priv and SourceNetworks only -- Members must be empty for
	// an external group (enforced by NDManager's schema), and NDAgent never
	// sends the `member` field for one regardless of what Members holds,
	// see ConvertAPIToGroup and executeSyncUsersGroups's member phases.
	ExternalMembers bool `json:"external_members,omitempty"`
}

// SetUserResponse is the response from user add/set endpoints.
type SetUserResponse struct {
	Result           string             `json:"result"`
	UUID             string             `json:"uuid,omitempty"`
	ValidationErrors FlexibleValidation `json:"validations,omitempty"`
}

// SetGroupResponse is the response from group add/set endpoints.
type SetGroupResponse struct {
	Result           string             `json:"result"`
	UUID             string             `json:"uuid,omitempty"`
	ValidationErrors FlexibleValidation `json:"validations,omitempty"`
}

// IsManagedByDescription checks if a description contains any NDAgent template tag.
// Resources with [nd-template:*] tags are considered managed by NDAgent.
func IsManagedByDescription(description string) bool {
	return strings.Contains(description, NDAgentTemplateTagPrefix)
}

// HasTemplateTag checks if a description has a specific template tag.
func HasTemplateTag(description, templateName string) bool {
	tag := NDAgentTemplateTagPrefix + templateName + "]"
	return strings.Contains(description, tag)
}

// AddTemplateTag adds a template tag to a description.
func AddTemplateTag(description, templateName string) string {
	tag := NDAgentTemplateTagPrefix + templateName + "]"
	if strings.Contains(description, tag) {
		return description
	}
	if description == "" {
		return tag
	}
	return description + " " + tag
}

// ParseTemplateTags extracts template names from description tags.
func ParseTemplateTags(description string) []string {
	var templates []string
	parts := strings.Split(description, NDAgentTemplateTagPrefix)
	for i := 1; i < len(parts); i++ {
		endIdx := strings.Index(parts[i], "]")
		if endIdx > 0 {
			templates = append(templates, parts[i][:endIdx])
		}
	}
	return templates
}

// StripTemplateTags removes NDAgent template tags from description, returning clean description.
func StripTemplateTags(description string) string {
	result := description
	// Remove all [nd-template:*] tags
	for {
		startIdx := strings.Index(result, NDAgentTemplateTagPrefix)
		if startIdx == -1 {
			break
		}
		endIdx := strings.Index(result[startIdx:], "]")
		if endIdx == -1 {
			break
		}
		result = result[:startIdx] + result[startIdx+endIdx+1:]
	}
	return strings.TrimSpace(result)
}

// BoolToOPNsense converts a bool to OPNsense's "0"/"1" format.
func BoolToOPNsense(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// OPNsenseToBool converts OPNsense's "0"/"1" format to bool.
func OPNsenseToBool(s string) bool {
	return s == "1"
}

// StringsToCSV converts a string slice to comma-separated string.
func StringsToCSV(items []string) string {
	return strings.Join(items, ",")
}

// CSVToStrings converts a comma-separated string to string slice.
func CSVToStrings(csv string) []string {
	if csv == "" {
		return nil
	}
	parts := strings.Split(csv, ",")
	var result []string
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// SanitizeMemberCSV strips structurally-empty tokens from a stored GROUP
// "member" CSV, without altering any real member UID.
//
// OPNsense's own `Auth\Base::setGroupMembership` (login-time memberOf sync)
// edits `<member>` directly via SimpleXMLElement, bypassing the MVC Group
// model entirely, and any group whose stored `<member>` is present but
// empty (e.g. a freshly created group's `<member></member>`, or one just
// emptied by a directory-membership revoke) hits the same PHP quirk on its
// next link: `explode(',', "")` returns `[""]`, not `[]`, so the merge
// writes back a LEADING comma (e.g. ",2004" instead of "2004"). OPNsense's
// `MemberField`/`BaseListField` validator then rejects the empty token
// ("Option [] not in list."), and because `setBase()` revalidates the
// WHOLE stored model on every `auth/group/set` call, this recurs on every
// later update to the group, whatever that update sends.
//
// SanitizeMemberCSV never removes or reorders a real token -- it only
// drops entries that are empty after TrimSpace, and returns the surviving
// tokens' original bytes unchanged. changed is false whenever there is
// nothing to repair, so a caller can decide whether an explicit repair
// write is needed at all rather than sending "member" on every sync.
func SanitizeMemberCSV(raw string) (sanitized string, changed bool) {
	if raw == "" {
		return "", false
	}
	parts := strings.Split(raw, ",")
	kept := make([]string, 0, len(parts))
	for _, p := range parts {
		if strings.TrimSpace(p) == "" {
			changed = true
			continue
		}
		kept = append(kept, p)
	}
	return strings.Join(kept, ","), changed
}

// SanitizeMemberCSVAgainstUsers extends SanitizeMemberCSV: besides
// structurally-empty tokens, it also drops any token naming a uid with no
// corresponding user left on the device. Deleting a user never scrubs
// other groups' stored `member` CSV (`UserController::delAction` has no
// safe-delete guard for this and never touches other groups), so a stale
// uid left behind fails the same "Option [<uid>] not in list." validation
// forever, exactly like the empty-token artifact, and needs the same kind
// of repair. validUIDs is the caller's own snapshot of every uid currently
// known to the device, taken in the same sync pass as this repair.
//
// Never drops a uid present in validUIDs, whatever its live membership
// state -- only a token that resolves to no user at all is considered an
// artifact here.
func SanitizeMemberCSVAgainstUsers(raw string, validUIDs map[string]bool) (sanitized string, changed bool) {
	deduped, emptyChanged := SanitizeMemberCSV(raw)
	if deduped == "" {
		return deduped, emptyChanged
	}
	parts := strings.Split(deduped, ",")
	kept := make([]string, 0, len(parts))
	staleChanged := false
	for _, p := range parts {
		if validUIDs[p] {
			kept = append(kept, p)
		} else {
			staleChanged = true
		}
	}
	return strings.Join(kept, ","), emptyChanged || staleChanged
}
