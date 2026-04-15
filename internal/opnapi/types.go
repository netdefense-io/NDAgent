// Package opnapi provides a client for the OPNsense REST API.
package opnapi

import (
	"encoding/json"
	"fmt"
)

// NDAgentUUIDPrefix marks all NDAgent-managed objects in OPNsense.
// All aliases and rules created by NDAgent use UUIDs starting with this prefix.
const NDAgentUUIDPrefix = "221f3268"

// Alias represents an OPNsense alias for API operations.
type Alias struct {
	Enabled     string `json:"enabled"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Content     string `json:"content"`
	Description string `json:"description"`
}

// AliasWrapper wraps an alias for API set operations.
type AliasWrapper struct {
	Alias Alias `json:"alias"`
}

// Rule represents an OPNsense filter rule for API operations.
type Rule struct {
	Enabled         string `json:"enabled"`
	Sequence        string `json:"sequence"`
	Action          string `json:"action"`
	Interface       string `json:"interface"`
	Direction       string `json:"direction"`
	IPProtocol      string `json:"ipprotocol"`
	Protocol        string `json:"protocol"`
	SourceNet       string `json:"source_net"`
	SourcePort      string `json:"source_port,omitempty"`
	DestinationNet  string `json:"destination_net"`
	DestinationPort string `json:"destination_port,omitempty"`
	Description     string `json:"description"`
}

// RuleWrapper wraps a rule for API set operations.
type RuleWrapper struct {
	Rule Rule `json:"rule"`
}

// SearchRequest is the request body for search endpoints.
type SearchRequest struct {
	SearchPhrase string `json:"searchPhrase"`
}

// RuleSearchRequest is the request body for rule search with interface filter.
// Rules are organized by interface in OPNsense:
// - No interface = floating rules (prio_group 200000)
// - With interface = interface rules (prio_group 400000)
type RuleSearchRequest struct {
	Current      int               `json:"current"`
	RowCount     int               `json:"rowCount"`
	Sort         map[string]string `json:"sort"`
	SearchPhrase string            `json:"searchPhrase,omitempty"`
	Interface    string            `json:"interface,omitempty"`
}

// SearchResponse is the response from search endpoints.
type SearchResponse struct {
	Rows     []map[string]interface{} `json:"rows"`
	RowCount int                      `json:"rowCount"`
	Total    int                      `json:"total"`
}

// APIResult is the generic API response for set/delete operations.
type APIResult struct {
	Result string `json:"result"`
}

// SavepointResponse is the response from /api/firewall/filter/savepoint.
type SavepointResponse struct {
	Revision string `json:"revision"`
}

// FlexibleValidation handles OPNsense's inconsistent validation response format.
// OPNsense may return:
//   - Empty string "" when no errors
//   - Empty array [] when no errors
//   - String message when validation fails
//   - Map structure map[string][]map[string]string for detailed errors
type FlexibleValidation struct {
	Errors  map[string][]map[string]string
	Message string // For when OPNsense returns a plain string
}

// UnmarshalJSON handles flexible JSON parsing for validation responses.
func (fv *FlexibleValidation) UnmarshalJSON(data []byte) error {
	// Initialize
	fv.Errors = make(map[string][]map[string]string)
	fv.Message = ""

	// Handle empty/null cases
	if len(data) == 0 || string(data) == "null" || string(data) == `""` || string(data) == `[]` {
		return nil
	}

	// Try as string first (common error case)
	var strVal string
	if err := json.Unmarshal(data, &strVal); err == nil {
		if strVal != "" {
			fv.Message = strVal
		}
		return nil
	}

	// Try as expected map structure
	var mapVal map[string][]map[string]string
	if err := json.Unmarshal(data, &mapVal); err == nil {
		fv.Errors = mapVal
		return nil
	}

	// Fallback: store raw JSON as message for debugging
	fv.Message = string(data)
	return nil
}

// HasErrors returns true if there are any validation errors.
func (fv FlexibleValidation) HasErrors() bool {
	return len(fv.Errors) > 0 || fv.Message != ""
}

// String returns a human-readable representation of validation errors.
func (fv FlexibleValidation) String() string {
	if fv.Message != "" {
		return fv.Message
	}
	if len(fv.Errors) > 0 {
		return fmt.Sprintf("%v", fv.Errors)
	}
	return ""
}
