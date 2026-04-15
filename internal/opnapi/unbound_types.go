package opnapi

// HostOverride represents an Unbound host override (DNS record) for API operations.
// Supports A, AAAA, MX, and TXT record types.
type HostOverride struct {
	Enabled     string `json:"enabled"`
	Hostname    string `json:"hostname"`
	Domain      string `json:"domain"`
	RR          string `json:"rr"`               // A, AAAA, MX, TXT
	Server      string `json:"server,omitempty"` // IP for A/AAAA
	MXPrio      string `json:"mxprio,omitempty"` // MX priority
	MX          string `json:"mx,omitempty"`     // MX target
	TTL         string `json:"ttl,omitempty"`    // Optional TTL
	TXTData     string `json:"txtdata,omitempty"`
	Description string `json:"description"`
}

// HostOverrideWrapper wraps a host override for API set operations.
type HostOverrideWrapper struct {
	Host HostOverride `json:"host"`
}

// DomainForward represents an Unbound domain forward for API operations.
// Supports standard forwarding and DNS-over-TLS (DoT).
type DomainForward struct {
	Enabled            string `json:"enabled"`
	Type               string `json:"type"` // forward, dot
	Domain             string `json:"domain"`
	Server             string `json:"server"`
	Port               string `json:"port,omitempty"`   // Optional custom port
	Verify             string `json:"verify,omitempty"` // DoT verification
	ForwardTCPUpstream string `json:"forward_tcp_upstream,omitempty"`
	ForwardFirst       string `json:"forward_first,omitempty"`
	Description        string `json:"description"`
}

// DomainForwardWrapper wraps a domain forward for API set operations.
type DomainForwardWrapper struct {
	Forward DomainForward `json:"forward"`
}

// HostAlias represents an Unbound host alias (CNAME-like) for API operations.
// Host aliases reference a parent host override by UUID.
type HostAlias struct {
	Enabled     string `json:"enabled"`
	Host        string `json:"host"` // UUID of parent host override
	Hostname    string `json:"hostname"`
	Domain      string `json:"domain"`
	Description string `json:"description"`
}

// HostAliasWrapper wraps a host alias for API set operations.
type HostAliasWrapper struct {
	Alias HostAlias `json:"alias"`
}

// UnboundACL represents an Unbound ACL for DNS query access control.
type UnboundACL struct {
	Enabled     string `json:"enabled"`
	Name        string `json:"name"`
	Action      string `json:"action"`   // allow, deny, refuse, allow_snoop, deny_non_local, refuse_non_local
	Networks    string `json:"networks"` // Comma-separated CIDRs
	Description string `json:"description"`
}

// UnboundACLWrapper wraps an ACL for API set operations.
type UnboundACLWrapper struct {
	ACL UnboundACL `json:"acl"`
}

// APIHostOverridePayload is the portable format for host overrides in templates/snippets.
type APIHostOverridePayload struct {
	UUID        string   `json:"uuid"`
	Enabled     bool     `json:"enabled"`
	Hostname    string   `json:"hostname"`
	Domain      string   `json:"domain"`
	RR          string   `json:"rr"`                // A, AAAA, MX, TXT
	Server      string   `json:"server,omitempty"`  // IP for A/AAAA
	MXPrio      string   `json:"mxprio,omitempty"`  // MX priority
	MX          string   `json:"mx,omitempty"`      // MX target
	TTL         string   `json:"ttl,omitempty"`     // Optional TTL
	TXTData     string   `json:"txtdata,omitempty"` // TXT record data
	Description string   `json:"description"`
	Templates   []string `json:"templates,omitempty"`
}

// APIDomainForwardPayload is the portable format for domain forwards in templates/snippets.
type APIDomainForwardPayload struct {
	UUID               string   `json:"uuid"`
	Enabled            bool     `json:"enabled"`
	Type               string   `json:"type"` // forward, dot
	Domain             string   `json:"domain"`
	Server             string   `json:"server"`
	Port               string   `json:"port,omitempty"`   // Optional custom port
	Verify             string   `json:"verify,omitempty"` // DoT verification
	ForwardTCPUpstream bool     `json:"forward_tcp_upstream,omitempty"`
	ForwardFirst       bool     `json:"forward_first,omitempty"`
	Description        string   `json:"description"`
	Templates          []string `json:"templates,omitempty"`
}

// APIHostAliasPayload is the portable format for host aliases in templates/snippets.
// Uses parent hostname+domain instead of UUID for portability.
type APIHostAliasPayload struct {
	UUID           string   `json:"uuid"`
	Enabled        bool     `json:"enabled"`
	ParentHostname string   `json:"parent_hostname"` // Resolved from host UUID
	ParentDomain   string   `json:"parent_domain"`   // Resolved from host UUID
	Hostname       string   `json:"hostname"`
	Domain         string   `json:"domain"`
	Description    string   `json:"description"`
	Templates      []string `json:"templates,omitempty"`
}

// APIUnboundACLPayload is the portable format for Unbound ACLs in templates/snippets.
type APIUnboundACLPayload struct {
	UUID        string   `json:"uuid"`
	Enabled     bool     `json:"enabled"`
	Name        string   `json:"name"`
	Action      string   `json:"action"`   // allow, deny, refuse, etc.
	Networks    []string `json:"networks"` // Networks as array (portable)
	Description string   `json:"description"`
	Templates   []string `json:"templates,omitempty"`
}

// SetHostOverrideResponse is the response from host override add/set endpoints.
type SetHostOverrideResponse struct {
	Result           string             `json:"result"`
	UUID             string             `json:"uuid,omitempty"`
	ValidationErrors FlexibleValidation `json:"validations,omitempty"`
}

// SetForwardResponse is the response from forward add/set endpoints.
type SetForwardResponse struct {
	Result           string             `json:"result"`
	UUID             string             `json:"uuid,omitempty"`
	ValidationErrors FlexibleValidation `json:"validations,omitempty"`
}

// SetHostAliasResponse is the response from host alias add/set endpoints.
type SetHostAliasResponse struct {
	Result           string             `json:"result"`
	UUID             string             `json:"uuid,omitempty"`
	ValidationErrors FlexibleValidation `json:"validations,omitempty"`
}

// SetACLResponse is the response from ACL add/set endpoints.
type SetACLResponse struct {
	Result           string             `json:"result"`
	UUID             string             `json:"uuid,omitempty"`
	ValidationErrors FlexibleValidation `json:"validations,omitempty"`
}
