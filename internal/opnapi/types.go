// Package opnapi provides a client for the OPNsense REST API.
package opnapi

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// NDAgentUUIDPrefix marks all NDAgent-managed objects in OPNsense.
// All aliases and rules created by NDAgent use UUIDs starting with this prefix.
const NDAgentUUIDPrefix = "221f3268"

// AliasWrapper wraps an alias for API set operations: a flat body of OPNsense
// string values keyed by field name, the field set being the device's (see
// EntityModel).
type AliasWrapper struct {
	Alias map[string]string `json:"alias"`
}

// RuleWrapper wraps a rule for API set operations. The rule is a flat body of
// OPNsense string values keyed by field name, because the field set is the
// device's (see EntityModel), not a list kept here.
type RuleWrapper struct {
	Rule map[string]string `json:"rule"`
}

// SearchRequest is the request body for search endpoints.
type SearchRequest struct {
	SearchPhrase string `json:"searchPhrase"`
}

// RuleSearchRequest is the request body for rule search. It never carries an
// interface filter, and that is load-bearing.
//
// **The semantics are OPNsense-version-dependent. NDAgent requires 26.1 or
// later.** From `FilterController::searchRuleAction`:
//
//   - Field ABSENT on **26.1+**: returns EVERY rule — floating,
//     single-interface and multi-interface alike, including rules bound to an
//     interface or group that is no longer in the interface option list, and
//     the legacy and generated rows.
//   - Field present and non-empty, any version: only rules bound to one of
//     those interfaces (plus the groups holding them).
//   - Field present but empty, on 26.1+: the FLOATING VIEW — only rules bound
//     to zero or more than one interface.
//   - Field absent on **25.1 / 25.7**: the floating view too, so a rule bound
//     to exactly one interface (`"wireguard"`, `"lan"`) was invisible to it.
//
// Discovery, and therefore the SYNC_API orphan sweep, must not depend on the
// live interface list. Deleting the last WireGuard instance removes the
// `wireguard` group from that list, and the `[nd-vpn:...]` rules bound to it
// must still be listed or the sweep cannot delete them and a VPN teardown
// strands them on the device. On 26.1+ the absent field gives exactly that in
// one search; below 26.1 no single search did, which is part of why 26.1 is
// the floor. See TestListAllRulesFindsRulesOnUnlistedInterfaces, whose
// fixture models the 26.1 controller rather than the assumption.
type RuleSearchRequest struct {
	Current      int               `json:"current"`
	RowCount     int               `json:"rowCount"`
	Sort         map[string]string `json:"sort"`
	SearchPhrase string            `json:"searchPhrase,omitempty"`
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
//   - Per field, keyed "<wrapper>.<field>": the field's message, or a list of
//     messages when it failed more than one check (ApiMutableModelControllerBase::validate)
//   - Map structure map[string][]map[string]string for detailed errors
type FlexibleValidation struct {
	Errors  map[string][]map[string]string
	Fields  map[string][]string
	Message string // For when OPNsense returns a plain string
}

// UnmarshalJSON handles flexible JSON parsing for validation responses.
func (fv *FlexibleValidation) UnmarshalJSON(data []byte) error {
	// Initialize
	fv.Errors = make(map[string][]map[string]string)
	fv.Fields = nil
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

	if fields, ok := parseFieldValidations(data); ok {
		fv.Fields = fields
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

// parseFieldValidations reads the per-field form, in which every value is a
// message or a list of messages.
func parseFieldValidations(data []byte) (map[string][]string, bool) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil || len(raw) == 0 {
		return nil, false
	}
	fields := make(map[string][]string, len(raw))
	for field, value := range raw {
		var one string
		if err := json.Unmarshal(value, &one); err == nil {
			fields[field] = []string{one}
			continue
		}
		var many []string
		if err := json.Unmarshal(value, &many); err == nil {
			fields[field] = many
			continue
		}
		return nil, false
	}
	return fields, true
}

// HasErrors returns true if there are any validation errors.
func (fv FlexibleValidation) HasErrors() bool {
	return len(fv.Errors) > 0 || len(fv.Fields) > 0 || fv.Message != ""
}

// String returns a human-readable representation of validation errors.
func (fv FlexibleValidation) String() string {
	if fv.Message != "" {
		return fv.Message
	}
	if len(fv.Fields) > 0 {
		return strings.Join(fv.FieldMessages(""), "; ")
	}
	if len(fv.Errors) > 0 {
		return fmt.Sprintf("%v", fv.Errors)
	}
	return ""
}

// FieldMessages renders the per-field form as "field: message", one entry per
// message, sorted by field, with prefix (the entity's wrapper, "rule.") dropped
// from each field name.
func (fv FlexibleValidation) FieldMessages(prefix string) []string {
	names := make([]string, 0, len(fv.Fields))
	for name := range fv.Fields {
		names = append(names, name)
	}
	sort.Strings(names)

	var out []string
	for _, name := range names {
		for _, msg := range fv.Fields[name] {
			out = append(out, strings.TrimPrefix(name, prefix)+": "+msg)
		}
	}
	return out
}

// ValidationFailedError is a setter call OPNsense refused with field
// validations: the request reached the model, and the model said no.
type ValidationFailedError struct {
	// Entity is the wrapper key the fields are prefixed with ("rule").
	Entity      string
	Validations FlexibleValidation
}

func (e *ValidationFailedError) Error() string {
	return "validation failed: " + strings.Join(e.Messages(), "; ")
}

// Messages renders each refusal as "field: message", without the wrapper
// prefix, or the whole response when OPNsense sent no per-field form.
func (e *ValidationFailedError) Messages() []string {
	if msgs := e.Validations.FieldMessages(e.Entity + "."); len(msgs) > 0 {
		return msgs
	}
	return []string{e.Validations.String()}
}
