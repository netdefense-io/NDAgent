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
//
// **The semantics are OPNsense-version-dependent. NDAgent requires 26.1 or
// later.** From `FilterController::searchRuleAction`:
//
//   - Field present and non-empty (comma-separated accepted), any version:
//     returns only rules bound to one of those interfaces. A rule on an
//     interface NOT in the list is excluded.
//   - Field ABSENT (what `omitempty` produces for an empty string) on
//     **26.1+**: returns EVERY rule — floating, single-interface and
//     multi-interface alike, including rules bound to an interface or group
//     that is no longer in the interface option list.
//   - Field absent on **25.1 / 25.7**: takes the FLOATING VIEW — a rule is
//     returned only if bound to zero or to more than one interface. A rule
//     bound to exactly one interface (`"wireguard"`, `"lan"`) is EXCLUDED.
//   - Field present but empty, on 26.1+: still the floating view, not
//     everything. NDAgent never sends this shape because of `omitempty`, so
//     the distinction is latent here — but it is real, and a fixture or a
//     future caller that assumes "empty means everything" would be wrong.
//
// Why the version floor is load-bearing: ListAllRules' first call is the
// unfiltered one, and on 26.1+ that single call already returns everything,
// which is what keeps rule discovery — and therefore the SYNC_API orphan
// sweep — independent of the live interface list. Deleting the last WireGuard
// instance removes the `wireguard` group from that list, and the
// `[nd-vpn:...]` rules bound to it must still be discoverable or the sweep
// cannot delete them and a VPN teardown strands them on the device.
//
// On 25.x that does not hold: a single-interface rule is invisible to the
// unfiltered call, so the second, interface-scoped call is the ONLY way such
// a rule is ever discovered — which is why ListAllRules makes two calls and
// dedupes on `seenUUIDs`. Below 26.1 a VPN teardown would silently strand its
// auto rules, because the group is gone from the interface list before the
// rules bound to it are enumerated.
//
// The older comment here ("No interface = floating rules") was therefore not
// wrong when written — it described 25.x accurately and aged out when 26.1
// changed the semantics. See TestListAllRulesFindsRulesOnUnlistedInterfaces,
// whose fixture models the 26.1 controller rather than the assumption.
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
