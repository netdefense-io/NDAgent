package opnapi

import "strings"

// NDAgentTemplateTagPrefix is the prefix for template tags in descriptions.
// Resources with [nd-template:*] tags are considered managed by NDAgent.
const NDAgentTemplateTagPrefix = "[nd-template:"

// ProtectedUsernames lists usernames that cannot be modified via SYNC.
var ProtectedUsernames = map[string]bool{
	"root": true,
}

// ProtectedGroupNames lists group names that cannot be modified via SYNC.
var ProtectedGroupNames = map[string]bool{
	"admins": true,
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
type Group struct {
	Name           string `json:"name"`
	Description    string `json:"description"`
	Priv           string `json:"priv,omitempty"`   // Comma-separated privileges
	Member         string `json:"member,omitempty"` // Comma-separated UIDs
	SourceNetworks string `json:"source_networks,omitempty"`
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
