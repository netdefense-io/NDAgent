package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/network"
	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// RulePosition defines where managed rules are placed relative to unmanaged rules.
type RulePosition string

const (
	// RulePositionPrepend places rules BEFORE unmanaged rules (lower sequence numbers).
	RulePositionPrepend RulePosition = "PREPEND"
	// RulePositionAppend places rules AFTER unmanaged rules (higher sequence numbers).
	RulePositionAppend RulePosition = "APPEND"
)

// SequenceCalculator computes OPNsense sequence values for managed rules
// based on their position (PREPEND/APPEND) relative to unmanaged rules.
type SequenceCalculator struct {
	MinUnmanaged int
	MaxUnmanaged int
}

// NewSequenceCalculator analyzes current OPNsense rules and creates a calculator.
// It finds the min/max sequence numbers of unmanaged rules to determine boundaries.
func NewSequenceCalculator(allRules []map[string]interface{}) *SequenceCalculator {
	calc := &SequenceCalculator{
		MinUnmanaged: 100000, // Default if no unmanaged rules
		MaxUnmanaged: 100000,
	}

	hasUnmanaged := false
	for _, rule := range allRules {
		uuid, _ := rule["uuid"].(string)
		if strings.HasPrefix(uuid, opnapi.NDAgentUUIDPrefix+"-") {
			continue // Skip managed rules
		}

		// Parse sequence from unmanaged rule
		var seq int
		switch s := rule["sequence"].(type) {
		case string:
			fmt.Sscanf(s, "%d", &seq)
		case float64:
			seq = int(s)
		}

		if seq > 0 {
			if !hasUnmanaged {
				calc.MinUnmanaged = seq
				calc.MaxUnmanaged = seq
				hasUnmanaged = true
			} else {
				if seq < calc.MinUnmanaged {
					calc.MinUnmanaged = seq
				}
				if seq > calc.MaxUnmanaged {
					calc.MaxUnmanaged = seq
				}
			}
		}
	}

	return calc
}

// ComputeSequences assigns sequence numbers to rules based on position and priority.
// Returns a map of UUID -> computed sequence.
// PREPEND rules get sequences before MinUnmanaged (100, 200, 300, ...)
// APPEND rules get sequences after MaxUnmanaged (max+1000, +100, ...)
func (c *SequenceCalculator) ComputeSequences(rules []APIRulePayload) map[string]int {
	// Separate rules by position
	var prependRules, appendRules []APIRulePayload
	for _, r := range rules {
		if r.Position == RulePositionAppend {
			appendRules = append(appendRules, r)
		} else {
			prependRules = append(prependRules, r)
		}
	}

	// Sort each group by priority (ascending = lower priority value = evaluated first)
	sort.Slice(prependRules, func(i, j int) bool {
		return prependRules[i].Priority < prependRules[j].Priority
	})
	sort.Slice(appendRules, func(i, j int) bool {
		return appendRules[i].Priority < appendRules[j].Priority
	})

	sequences := make(map[string]int)

	// PREPEND rules: sequences 100, 200, 300, ... (before unmanaged)
	// Start at 100 with gaps of 100 for future flexibility
	prependStart := 100
	for i, r := range prependRules {
		sequences[r.UUID] = prependStart + (i * 100)
	}

	// APPEND rules: sequences after max unmanaged with gaps of 100
	appendStart := c.MaxUnmanaged + 1000
	for i, r := range appendRules {
		sequences[r.UUID] = appendStart + (i * 100)
	}

	return sequences
}

// APIAliasPayload represents an alias in JSON-native format for SYNC_API.
type APIAliasPayload struct {
	UUID        string   `json:"uuid"`
	Enabled     bool     `json:"enabled"`
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Content     []string `json:"content"`
	Description string   `json:"description"`
	Templates   []string `json:"templates"`
}

// APIRulePayload represents a rule in JSON-native format for SYNC_API.
// Position and Priority are extracted from snippet metadata (not content JSON).
// Sequence is computed dynamically based on position relative to unmanaged rules.
type APIRulePayload struct {
	UUID            string       `json:"uuid"`
	Enabled         bool         `json:"enabled"`
	Position        RulePosition `json:"position"` // PREPEND or APPEND relative to unmanaged rules
	Priority        int          `json:"priority"` // Ordering within position group (lower = higher priority)
	Action          string       `json:"action"`
	Interface       string       `json:"interface"`
	Direction       string       `json:"direction"`
	IPProtocol      string       `json:"ipprotocol"`
	Protocol        string       `json:"protocol"`
	SourceNet       string       `json:"source_net"`
	SourcePort      string       `json:"source_port,omitempty"`
	DestinationNet  string       `json:"destination_net"`
	DestinationPort string       `json:"destination_port,omitempty"`
	Description     string       `json:"description"`
	Templates       []string     `json:"templates"`
}

// ValidationError represents a dependency or constraint violation.
type ValidationError struct {
	Type       string   `json:"type"` // "alias" or "rule"
	UUID       string   `json:"uuid"`
	Name       string   `json:"name"`
	ErrorCode  string   `json:"error_code"` // "ALIAS_IN_USE"
	Message    string   `json:"message"`
	References []string `json:"references,omitempty"`
}

// SyncAPIResult contains the result of a SYNC_API operation.
type SyncAPIResult struct {
	Success          bool
	Message          string
	Results          []SyncAPIItemResult
	Errors           []string
	ValidationErrors []ValidationError
}

// SyncAPIItemResult contains the result for a single item.
type SyncAPIItemResult struct {
	Type   string `json:"type"`
	UUID   string `json:"uuid"`
	Name   string `json:"name"`
	Action string `json:"action"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// HandleSyncAPI handles the SYNC_API task using OPNsense REST API.
func HandleSyncAPI(ctx context.Context, ws *network.WebSocketClient, cmd network.Command) error {
	log := logging.Named("SYNC_API")

	log.Infow("Received SYNC_API command", "task_id", cmd.TaskID)

	// Validate API credentials are configured
	apiClient := ws.GetAPIClient()
	if apiClient == nil {
		result := NewFailureResult("SYNC_API not available: API credentials not configured")
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	// Parse payload
	if cmd.Payload == nil {
		result := NewFailureResult("No payload provided")
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	// Verify payload hash
	payloadHash, _ := cmd.Payload["payload_hash"].(string)
	if payloadHash == "" {
		result := NewFailureResult("Payload integrity check failed: missing payload_hash")
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	if !verifyPayloadHash(cmd.Payload, payloadHash) {
		log.Warn("Payload hash mismatch")
		result := NewFailureResult("Payload integrity check failed: hash mismatch")
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	// Parse aliases and rules from payload
	aliases, err := parseAPIAliases(cmd.Payload)
	if err != nil {
		result := NewFailureResult(fmt.Sprintf("Failed to parse aliases: %v", err))
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	rules, err := parseAPIRules(cmd.Payload)
	if err != nil {
		result := NewFailureResult(fmt.Sprintf("Failed to parse rules: %v", err))
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	// Parse users and groups from payload
	users, err := parseAPIUsers(cmd.Payload)
	if err != nil {
		result := NewFailureResult(fmt.Sprintf("Failed to parse users: %v", err))
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	groups, err := parseAPIGroups(cmd.Payload)
	if err != nil {
		result := NewFailureResult(fmt.Sprintf("Failed to parse groups: %v", err))
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	// Parse Unbound DNS entities from payload
	hostOverrides, err := parseAPIHostOverrides(cmd.Payload)
	if err != nil {
		result := NewFailureResult(fmt.Sprintf("Failed to parse host_overrides: %v", err))
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	domainForwards, err := parseAPIDomainForwards(cmd.Payload)
	if err != nil {
		result := NewFailureResult(fmt.Sprintf("Failed to parse domain_forwards: %v", err))
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	hostAliases, err := parseAPIHostAliases(cmd.Payload)
	if err != nil {
		result := NewFailureResult(fmt.Sprintf("Failed to parse host_aliases: %v", err))
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	unboundACLs, err := parseAPIUnboundACLs(cmd.Payload)
	if err != nil {
		result := NewFailureResult(fmt.Sprintf("Failed to parse unbound_acls: %v", err))
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	vpnNetworks, err := parseVPNNetworks(cmd.Payload)
	if err != nil {
		result := NewFailureResult(fmt.Sprintf("Failed to parse vpn_networks: %v", err))
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	// Validate UUIDs have correct prefix
	for _, alias := range aliases {
		if !strings.HasPrefix(alias.UUID, opnapi.NDAgentUUIDPrefix) {
			result := NewFailureResult(fmt.Sprintf("Invalid alias UUID %s: must start with %s", alias.UUID, opnapi.NDAgentUUIDPrefix))
			return SendTaskResponse(ws, cmd.TaskID, result)
		}
	}
	for _, rule := range rules {
		if !strings.HasPrefix(rule.UUID, opnapi.NDAgentUUIDPrefix) {
			result := NewFailureResult(fmt.Sprintf("Invalid rule UUID %s: must start with %s", rule.UUID, opnapi.NDAgentUUIDPrefix))
			return SendTaskResponse(ws, cmd.TaskID, result)
		}
	}
	for _, ho := range hostOverrides {
		if !strings.HasPrefix(ho.UUID, opnapi.NDAgentUUIDPrefix) {
			result := NewFailureResult(fmt.Sprintf("Invalid host_override UUID %s: must start with %s", ho.UUID, opnapi.NDAgentUUIDPrefix))
			return SendTaskResponse(ws, cmd.TaskID, result)
		}
	}
	for _, df := range domainForwards {
		if !strings.HasPrefix(df.UUID, opnapi.NDAgentUUIDPrefix) {
			result := NewFailureResult(fmt.Sprintf("Invalid domain_forward UUID %s: must start with %s", df.UUID, opnapi.NDAgentUUIDPrefix))
			return SendTaskResponse(ws, cmd.TaskID, result)
		}
	}
	for _, ha := range hostAliases {
		if !strings.HasPrefix(ha.UUID, opnapi.NDAgentUUIDPrefix) {
			result := NewFailureResult(fmt.Sprintf("Invalid host_alias UUID %s: must start with %s", ha.UUID, opnapi.NDAgentUUIDPrefix))
			return SendTaskResponse(ws, cmd.TaskID, result)
		}
	}
	for _, acl := range unboundACLs {
		if !strings.HasPrefix(acl.UUID, opnapi.NDAgentUUIDPrefix) {
			result := NewFailureResult(fmt.Sprintf("Invalid unbound_acl UUID %s: must start with %s", acl.UUID, opnapi.NDAgentUUIDPrefix))
			return SendTaskResponse(ws, cmd.TaskID, result)
		}
	}

	log.Infow("Executing SYNC_API",
		"alias_count", len(aliases),
		"rule_count", len(rules),
		"user_count", len(users),
		"group_count", len(groups),
		"host_override_count", len(hostOverrides),
		"domain_forward_count", len(domainForwards),
		"host_alias_count", len(hostAliases),
		"unbound_acl_count", len(unboundACLs),
		"vpn_network_count", len(vpnNetworks),
	)

	// Execute sync for aliases and rules
	syncResult := executeSyncAPI(ctx, apiClient, aliases, rules)

	// Execute sync for users and groups if present
	if len(users) > 0 || len(groups) > 0 {
		userGroupResult := executeSyncUsersGroups(ctx, apiClient, users, groups)

		// Merge results
		syncResult.Results = append(syncResult.Results, userGroupResult.Results...)
		syncResult.Errors = append(syncResult.Errors, userGroupResult.Errors...)

		// Update success status
		if !userGroupResult.Success {
			syncResult.Success = false
		}

		// Update message
		if syncResult.Message == "No changes applied" && userGroupResult.Message != "No changes applied" {
			syncResult.Message = userGroupResult.Message
		} else if userGroupResult.Message != "No changes applied" {
			syncResult.Message = syncResult.Message + ". " + userGroupResult.Message
		}
	}

	// Execute sync for Unbound DNS entities if present
	if len(hostOverrides) > 0 || len(domainForwards) > 0 || len(hostAliases) > 0 || len(unboundACLs) > 0 {
		unboundResult := executeSyncUnbound(ctx, apiClient, hostOverrides, domainForwards, hostAliases, unboundACLs)

		// Merge results
		syncResult.Results = append(syncResult.Results, unboundResult.Results...)
		syncResult.Errors = append(syncResult.Errors, unboundResult.Errors...)

		// Update success status
		if !unboundResult.Success {
			syncResult.Success = false
		}

		// Update message
		if syncResult.Message == "No changes applied" && unboundResult.Message != "No changes applied" {
			syncResult.Message = unboundResult.Message
		} else if unboundResult.Message != "No changes applied" {
			syncResult.Message = syncResult.Message + ". " + unboundResult.Message
		}
	}

	// Execute sync for VPN networks if present
	if len(vpnNetworks) > 0 {
		vpnResult := executeSyncVPN(ctx, apiClient, vpnNetworks)

		// Merge results
		syncResult.Results = append(syncResult.Results, vpnResult.Results...)
		syncResult.Errors = append(syncResult.Errors, vpnResult.Errors...)

		// Update success status
		if !vpnResult.Success {
			syncResult.Success = false
		}

		// Update message
		if syncResult.Message == "No changes applied" && vpnResult.Message != "No changes applied" {
			syncResult.Message = vpnResult.Message
		} else if vpnResult.Message != "No changes applied" {
			syncResult.Message = syncResult.Message + ". " + vpnResult.Message
		}
	}

	// Build response
	data := map[string]interface{}{
		"results": syncResult.Results,
	}
	if len(syncResult.Errors) > 0 {
		data["errors"] = syncResult.Errors
	}
	if len(syncResult.ValidationErrors) > 0 {
		data["validation_errors"] = syncResult.ValidationErrors
	}

	if syncResult.Success {
		result := NewSuccessResultWithData(syncResult.Message, data)
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	result := TaskResult{
		Success: false,
		Message: syncResult.Message,
		Data:    data,
	}
	return SendTaskResponse(ws, cmd.TaskID, result)
}

// checkOrphanAliasUsage checks if orphan aliases are referenced by any rules.
// This includes:
// 1. Rules in the payload that reference orphan managed aliases
// 2. External rules (not in payload) that reference orphan managed aliases
// Returns validation errors for aliases that cannot be deleted.
func checkOrphanAliasUsage(
	ctx context.Context,
	client *opnapi.Client,
	desiredAliasUUIDs map[string]bool,
	currentAliases []map[string]interface{},
	rules []APIRulePayload,
) []ValidationError {
	log := logging.Named("SYNC_API")
	var validationErrors []ValidationError

	// Build map of orphan alias names (managed aliases being deleted)
	orphanAliasNames := make(map[string]string) // name -> UUID
	for _, current := range currentAliases {
		uuid, _ := current["uuid"].(string)
		if desiredAliasUUIDs[uuid] {
			continue // Not an orphan
		}
		name, _ := current["name"].(string)
		orphanAliasNames[name] = uuid
	}

	if len(orphanAliasNames) == 0 {
		return nil // No orphan aliases to check
	}

	log.Infow("Checking orphan alias usage",
		"orphan_count", len(orphanAliasNames),
	)

	// Check 1: Rules in the payload that reference orphan managed aliases
	for _, rule := range rules {
		if uuid, ok := orphanAliasNames[rule.SourceNet]; ok {
			validationErrors = append(validationErrors, ValidationError{
				Type:       "alias",
				UUID:       uuid,
				Name:       rule.SourceNet,
				ErrorCode:  "ALIAS_IN_USE",
				Message:    fmt.Sprintf("Cannot delete alias '%s': referenced by rule '%s' in sync payload", rule.SourceNet, rule.Description),
				References: []string{fmt.Sprintf("%s (%s) [in payload]", rule.Description, rule.UUID)},
			})
		}
		if uuid, ok := orphanAliasNames[rule.DestinationNet]; ok {
			validationErrors = append(validationErrors, ValidationError{
				Type:       "alias",
				UUID:       uuid,
				Name:       rule.DestinationNet,
				ErrorCode:  "ALIAS_IN_USE",
				Message:    fmt.Sprintf("Cannot delete alias '%s': referenced by rule '%s' in sync payload", rule.DestinationNet, rule.Description),
				References: []string{fmt.Sprintf("%s (%s) [in payload]", rule.Description, rule.UUID)},
			})
		}
	}

	// Check 2: External rules (non-managed) that reference orphan managed aliases
	// Note: Managed rules not in payload will also be deleted, so they don't block alias deletion
	for aliasName, aliasUUID := range orphanAliasNames {
		references, err := client.FindAliasUsage(ctx, aliasName)
		if err != nil {
			log.Warnw("Failed to check alias usage", "alias", aliasName, "error", err)
			continue // Will be caught during execution
		}

		// Filter out:
		// 1. Rules in the payload (already checked above)
		// 2. Managed rules (they will be deleted as orphans too)
		var externalRefs []string
		for _, ref := range references {
			// Check if it's a rule in the payload
			isPayloadRule := false
			for _, rule := range rules {
				if strings.Contains(ref, rule.UUID) {
					isPayloadRule = true
					break
				}
			}
			if isPayloadRule {
				continue
			}

			// Check if it's a managed rule (will be deleted as orphan)
			// Managed rules have UUID starting with NDAgentUUIDPrefix
			isManagedRule := strings.Contains(ref, opnapi.NDAgentUUIDPrefix)
			if isManagedRule {
				continue // This rule will also be deleted, doesn't block alias deletion
			}

			externalRefs = append(externalRefs, ref)
		}

		if len(externalRefs) > 0 {
			validationErrors = append(validationErrors, ValidationError{
				Type:       "alias",
				UUID:       aliasUUID,
				Name:       aliasName,
				ErrorCode:  "ALIAS_IN_USE",
				Message:    fmt.Sprintf("Cannot delete alias '%s': in use by %d external rule(s)", aliasName, len(externalRefs)),
				References: externalRefs,
			})
		}
	}

	return validationErrors
}

// executeSyncAPI performs the actual sync using declarative state model.
func executeSyncAPI(ctx context.Context, client *opnapi.Client, aliases []APIAliasPayload, rules []APIRulePayload) SyncAPIResult {
	log := logging.Named("SYNC_API")

	var results []SyncAPIItemResult
	var errors []string

	// Phase 1: Get ALL objects and filter for managed ones
	// OPNsense search API doesn't filter by UUID, only name/description,
	// so we must list all objects and filter locally by UUID prefix.
	allAliases, err := client.ListAllAliases(ctx)
	if err != nil {
		return SyncAPIResult{
			Success: false,
			Message: fmt.Sprintf("Failed to list aliases: %v", err),
		}
	}
	currentAliases := opnapi.FilterManagedAliases(allAliases)

	allRules, err := client.ListAllRules(ctx)
	if err != nil {
		return SyncAPIResult{
			Success: false,
			Message: fmt.Sprintf("Failed to list rules: %v", err),
		}
	}
	currentRules := opnapi.FilterManagedRules(allRules)

	log.Infow("Discovered managed objects",
		"total_aliases", len(allAliases),
		"managed_aliases", len(currentAliases),
		"total_rules", len(allRules),
		"managed_rules", len(currentRules),
	)

	// Compute sequences for rules based on position relative to unmanaged rules
	seqCalc := NewSequenceCalculator(allRules)
	computedSequences := seqCalc.ComputeSequences(rules)

	// Count rules by position for logging
	prependCount, appendCount := 0, 0
	for _, r := range rules {
		if r.Position == RulePositionAppend {
			appendCount++
		} else {
			prependCount++
		}
	}

	log.Infow("Computed rule sequences",
		"min_unmanaged_seq", seqCalc.MinUnmanaged,
		"max_unmanaged_seq", seqCalc.MaxUnmanaged,
		"prepend_rules", prependCount,
		"append_rules", appendCount,
	)

	// Build maps of current UUIDs
	currentAliasUUIDs := make(map[string]bool)
	for _, a := range currentAliases {
		if uuid, ok := a["uuid"].(string); ok {
			currentAliasUUIDs[uuid] = true
		}
	}

	currentRuleUUIDs := make(map[string]bool)
	for _, r := range currentRules {
		if uuid, ok := r["uuid"].(string); ok {
			currentRuleUUIDs[uuid] = true
		}
	}

	// Build maps of desired UUIDs
	desiredAliasUUIDs := make(map[string]APIAliasPayload)
	for _, a := range aliases {
		desiredAliasUUIDs[a.UUID] = a
	}

	desiredRuleUUIDs := make(map[string]APIRulePayload)
	for _, r := range rules {
		desiredRuleUUIDs[r.UUID] = r
	}

	// Phase 1.5: Pre-flight validation - check if orphan aliases can be deleted
	desiredAliasUUIDSet := make(map[string]bool)
	for uuid := range desiredAliasUUIDs {
		desiredAliasUUIDSet[uuid] = true
	}

	validationErrors := checkOrphanAliasUsage(ctx, client, desiredAliasUUIDSet, currentAliases, rules)
	if len(validationErrors) > 0 {
		// FAIL FAST - do not make any changes
		log.Warnw("Sync blocked by validation errors",
			"error_count", len(validationErrors),
		)
		return SyncAPIResult{
			Success:          false,
			Message:          "Sync blocked: cannot delete aliases that are in use",
			ValidationErrors: validationErrors,
		}
	}

	// Phase 2: Create/Update aliases (before rules, as rules may depend on aliases)
	for _, alias := range aliases {
		action := "created"
		if currentAliasUUIDs[alias.UUID] {
			action = "updated"
		}

		opnAlias := convertToOPNAlias(alias)
		err := client.SetAlias(ctx, alias.UUID, opnAlias)

		itemResult := SyncAPIItemResult{
			Type:   "alias",
			UUID:   alias.UUID,
			Name:   alias.Name,
			Action: action,
		}

		if err != nil {
			itemResult.Status = "error"
			itemResult.Error = err.Error()
			errors = append(errors, fmt.Sprintf("Alias %s: %v", alias.Name, err))
		} else {
			itemResult.Status = "success"
		}

		results = append(results, itemResult)
	}

	// Phase 3: Create/Update rules with computed sequences
	for _, rule := range rules {
		action := "created"
		if currentRuleUUIDs[rule.UUID] {
			action = "updated"
		}

		// Get the computed sequence for this rule
		computedSeq := computedSequences[rule.UUID]
		opnRule := convertToOPNRuleWithSequence(rule, computedSeq)
		err := client.SetRule(ctx, rule.UUID, opnRule)

		itemResult := SyncAPIItemResult{
			Type:   "rule",
			UUID:   rule.UUID,
			Name:   rule.Description,
			Action: action,
		}

		if err != nil {
			itemResult.Status = "error"
			itemResult.Error = err.Error()
			errors = append(errors, fmt.Sprintf("Rule %s: %v", rule.Description, err))
		} else {
			itemResult.Status = "success"
		}

		results = append(results, itemResult)
	}

	// Phase 4: Delete rules no longer in desired state (before aliases)
	for uuid := range currentRuleUUIDs {
		if _, exists := desiredRuleUUIDs[uuid]; !exists {
			err := client.DeleteRule(ctx, uuid)

			itemResult := SyncAPIItemResult{
				Type:   "rule",
				UUID:   uuid,
				Action: "deleted",
			}

			if err != nil {
				itemResult.Status = "error"
				itemResult.Error = err.Error()
				errors = append(errors, fmt.Sprintf("Delete rule %s: %v", uuid, err))
			} else {
				itemResult.Status = "success"
			}

			results = append(results, itemResult)
		}
	}

	// Phase 5: Delete aliases no longer in desired state
	for uuid := range currentAliasUUIDs {
		if _, exists := desiredAliasUUIDs[uuid]; !exists {
			err := client.DeleteAlias(ctx, uuid)

			itemResult := SyncAPIItemResult{
				Type:   "alias",
				UUID:   uuid,
				Action: "deleted",
			}

			if err != nil {
				itemResult.Status = "error"
				itemResult.Error = err.Error()
				errors = append(errors, fmt.Sprintf("Delete alias %s: %v", uuid, err))
			} else {
				itemResult.Status = "success"
			}

			results = append(results, itemResult)
		}
	}

	// Phase 6: Apply changes
	if err := client.ReconfigureAliases(ctx); err != nil {
		errors = append(errors, fmt.Sprintf("Alias reconfigure: %v", err))
	}

	if err := client.ApplyRules(ctx); err != nil {
		errors = append(errors, fmt.Sprintf("Rule apply: %v", err))
	}

	// Build final result with detailed counts
	success := len(errors) == 0

	// Count actions by type
	var aliasCreated, aliasUpdated, aliasDeleted int
	var ruleCreated, ruleUpdated, ruleDeleted int
	for _, r := range results {
		if r.Status != "success" {
			continue
		}
		switch r.Type {
		case "alias":
			switch r.Action {
			case "created":
				aliasCreated++
			case "updated":
				aliasUpdated++
			case "deleted":
				aliasDeleted++
			}
		case "rule":
			switch r.Action {
			case "created":
				ruleCreated++
			case "updated":
				ruleUpdated++
			case "deleted":
				ruleDeleted++
			}
		}
	}

	// Build descriptive message
	var parts []string
	if aliasCreated > 0 || aliasUpdated > 0 || aliasDeleted > 0 {
		parts = append(parts, fmt.Sprintf("Aliases: %d created, %d updated, %d deleted", aliasCreated, aliasUpdated, aliasDeleted))
	}
	if ruleCreated > 0 || ruleUpdated > 0 || ruleDeleted > 0 {
		parts = append(parts, fmt.Sprintf("Rules: %d created, %d updated, %d deleted", ruleCreated, ruleUpdated, ruleDeleted))
	}

	var message string
	if len(parts) == 0 {
		message = "No changes applied"
	} else {
		message = strings.Join(parts, ". ")
	}
	if !success {
		message = fmt.Sprintf("%s (%d errors)", message, len(errors))
	}

	log.Infow("SYNC_API completed",
		"success", success,
		"aliases_created", aliasCreated,
		"aliases_updated", aliasUpdated,
		"aliases_deleted", aliasDeleted,
		"rules_created", ruleCreated,
		"rules_updated", ruleUpdated,
		"rules_deleted", ruleDeleted,
		"error_count", len(errors),
	)

	return SyncAPIResult{
		Success: success,
		Message: message,
		Results: results,
		Errors:  errors,
	}
}

// convertToOPNAlias converts APIAliasPayload to opnapi.Alias.
func convertToOPNAlias(a APIAliasPayload) opnapi.Alias {
	enabled := "0"
	if a.Enabled {
		enabled = "1"
	}

	// Build template tags for description
	desc := a.Description
	for _, t := range a.Templates {
		desc += fmt.Sprintf(" [nd-template:%s]", t)
	}

	return opnapi.Alias{
		Enabled:     enabled,
		Name:        a.Name,
		Type:        a.Type,
		Content:     strings.Join(a.Content, "\n"),
		Description: strings.TrimSpace(desc),
	}
}

// convertToOPNRuleWithSequence converts APIRulePayload to opnapi.Rule with a computed sequence.
// The sequence is calculated based on the rule's position (PREPEND/APPEND) and priority.
func convertToOPNRuleWithSequence(r APIRulePayload, computedSequence int) opnapi.Rule {
	enabled := "0"
	if r.Enabled {
		enabled = "1"
	}

	// Build template tags for description
	desc := r.Description
	for _, t := range r.Templates {
		desc += fmt.Sprintf(" [nd-template:%s]", t)
	}

	return opnapi.Rule{
		Enabled:         enabled,
		Sequence:        fmt.Sprintf("%d", computedSequence),
		Action:          r.Action,
		Interface:       r.Interface,
		Direction:       r.Direction,
		IPProtocol:      r.IPProtocol,
		Protocol:        r.Protocol,
		SourceNet:       r.SourceNet,
		SourcePort:      r.SourcePort,
		DestinationNet:  r.DestinationNet,
		DestinationPort: r.DestinationPort,
		Description:     strings.TrimSpace(desc),
	}
}

// parseAPIAliases extracts aliases from the payload snippets array.
// NDManager sends snippets with config_type and content (JSON) fields.
func parseAPIAliases(payload map[string]interface{}) ([]APIAliasPayload, error) {
	snippetsRaw, ok := payload["snippets"]
	if !ok {
		return []APIAliasPayload{}, nil // Empty is valid
	}

	snippetsArray, ok := snippetsRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("snippets must be an array")
	}

	var aliases []APIAliasPayload
	for idx, s := range snippetsArray {
		snippetMap, ok := s.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("snippet at index %d must be an object", idx)
		}

		// Check config_type - only process ALIAS types
		configType, _ := snippetMap["config_type"].(string)
		if configType != "ALIAS" {
			continue
		}

		// Get template names array
		var templates []string
		if templateNames, ok := snippetMap["template_name"].([]interface{}); ok {
			for _, t := range templateNames {
				if ts, ok := t.(string); ok {
					templates = append(templates, ts)
				}
			}
		}

		// Parse the JSON content field
		snippetContent, _ := snippetMap["content"].(string)
		if snippetContent == "" {
			return nil, fmt.Errorf("alias snippet at index %d missing content", idx)
		}

		alias, err := parseAliasContent(snippetContent, templates)
		if err != nil {
			return nil, fmt.Errorf("alias snippet at index %d: %v", idx, err)
		}

		aliases = append(aliases, alias)
	}

	return aliases, nil
}

// parseAliasContent parses the JSON content of an alias snippet.
func parseAliasContent(jsonContent string, templates []string) (APIAliasPayload, error) {
	var contentMap map[string]interface{}
	if err := json.Unmarshal([]byte(jsonContent), &contentMap); err != nil {
		return APIAliasPayload{}, fmt.Errorf("failed to parse alias JSON: %v", err)
	}

	alias := APIAliasPayload{
		Templates: templates,
	}

	// Required fields
	alias.UUID, _ = contentMap["uuid"].(string)
	if alias.UUID == "" {
		return APIAliasPayload{}, fmt.Errorf("missing required field: uuid")
	}

	alias.Name, _ = contentMap["name"].(string)
	if alias.Name == "" {
		return APIAliasPayload{}, fmt.Errorf("missing required field: name")
	}

	alias.Type, _ = contentMap["type"].(string)
	if alias.Type == "" {
		return APIAliasPayload{}, fmt.Errorf("missing required field: type")
	}

	// Parse enabled - can be bool, string "1"/"0", or number
	alias.Enabled = parseEnabled(contentMap["enabled"])

	// Parse description
	alias.Description, _ = contentMap["description"].(string)

	// Parse content - can be string (single value) or already an array
	switch v := contentMap["content"].(type) {
	case string:
		// Single value - split by newlines if present, otherwise single item
		if strings.Contains(v, "\n") {
			alias.Content = strings.Split(v, "\n")
		} else if v != "" {
			alias.Content = []string{v}
		}
	case []interface{}:
		for _, c := range v {
			if cs, ok := c.(string); ok {
				alias.Content = append(alias.Content, cs)
			}
		}
	}

	return alias, nil
}

// parseAPIRules extracts rules from the payload snippets array.
// NDManager sends snippets with config_type, position, priority, and content fields.
// Position and priority are snippet-level metadata, not part of the rule content JSON.
func parseAPIRules(payload map[string]interface{}) ([]APIRulePayload, error) {
	snippetsRaw, ok := payload["snippets"]
	if !ok {
		return []APIRulePayload{}, nil // Empty is valid
	}

	snippetsArray, ok := snippetsRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("snippets must be an array")
	}

	var rules []APIRulePayload
	for idx, s := range snippetsArray {
		snippetMap, ok := s.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("snippet at index %d must be an object", idx)
		}

		// Check config_type - only process RULE types
		configType, _ := snippetMap["config_type"].(string)
		if configType != "RULE" {
			continue
		}

		// Extract position from snippet metadata (default: PREPEND)
		position := RulePositionPrepend
		if pos, ok := snippetMap["position"].(string); ok {
			switch strings.ToUpper(pos) {
			case "APPEND":
				position = RulePositionAppend
			case "PREPEND":
				position = RulePositionPrepend
			default:
				return nil, fmt.Errorf("snippet at index %d has invalid position: %s (must be PREPEND or APPEND)", idx, pos)
			}
		}

		// Extract priority from snippet metadata (default: 1000)
		priority := 1000
		if p, ok := snippetMap["priority"].(float64); ok {
			priority = int(p)
		}

		// Get template names array
		var templates []string
		if templateNames, ok := snippetMap["template_name"].([]interface{}); ok {
			for _, t := range templateNames {
				if ts, ok := t.(string); ok {
					templates = append(templates, ts)
				}
			}
		}

		// Parse the JSON content field
		snippetContent, _ := snippetMap["content"].(string)
		if snippetContent == "" {
			return nil, fmt.Errorf("rule snippet at index %d missing content", idx)
		}

		rule, err := parseRuleContent(snippetContent, templates)
		if err != nil {
			return nil, fmt.Errorf("rule snippet at index %d: %v", idx, err)
		}

		// Set position and priority from snippet metadata
		rule.Position = position
		rule.Priority = priority

		rules = append(rules, rule)
	}

	return rules, nil
}

// parseRuleContent parses the JSON content of a rule snippet.
// Note: Position and Priority are NOT parsed here - they come from snippet metadata.
// Sequence is computed dynamically and is not expected in content JSON.
func parseRuleContent(jsonContent string, templates []string) (APIRulePayload, error) {
	var contentMap map[string]interface{}
	if err := json.Unmarshal([]byte(jsonContent), &contentMap); err != nil {
		return APIRulePayload{}, fmt.Errorf("failed to parse rule JSON: %v", err)
	}

	rule := APIRulePayload{
		Templates: templates,
	}

	// Required fields
	rule.UUID, _ = contentMap["uuid"].(string)
	if rule.UUID == "" {
		return APIRulePayload{}, fmt.Errorf("missing required field: uuid")
	}

	// Parse enabled
	rule.Enabled = parseEnabled(contentMap["enabled"])

	// Note: sequence field is no longer parsed from content.
	// It is computed dynamically based on position and priority from snippet metadata.

	// Parse other fields
	rule.Action, _ = contentMap["action"].(string)
	rule.Interface, _ = contentMap["interface"].(string)
	rule.Direction, _ = contentMap["direction"].(string)
	rule.IPProtocol, _ = contentMap["ipprotocol"].(string)
	rule.Protocol, _ = contentMap["protocol"].(string)
	rule.SourceNet, _ = contentMap["source_net"].(string)
	rule.SourcePort, _ = contentMap["source_port"].(string)
	rule.DestinationNet, _ = contentMap["destination_net"].(string)
	rule.DestinationPort, _ = contentMap["destination_port"].(string)
	rule.Description, _ = contentMap["description"].(string)

	return rule, nil
}

// parseEnabled parses an enabled field that can be bool, string, or number.
func parseEnabled(v interface{}) bool {
	switch e := v.(type) {
	case bool:
		return e
	case string:
		return e == "1" || strings.ToLower(e) == "true"
	case float64:
		return e != 0
	default:
		return true // Default to enabled
	}
}

// parseAPIUsers extracts users from the payload snippets array.
func parseAPIUsers(payload map[string]interface{}) ([]opnapi.APIUserPayload, error) {
	snippetsRaw, ok := payload["snippets"]
	if !ok {
		return []opnapi.APIUserPayload{}, nil
	}

	snippetsArray, ok := snippetsRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("snippets must be an array")
	}

	var users []opnapi.APIUserPayload
	for idx, s := range snippetsArray {
		snippetMap, ok := s.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("snippet at index %d must be an object", idx)
		}

		configType, _ := snippetMap["config_type"].(string)
		if configType != "USER" {
			continue
		}

		// Get template names array
		var templates []string
		if templateNames, ok := snippetMap["template_name"].([]interface{}); ok {
			for _, t := range templateNames {
				if ts, ok := t.(string); ok {
					templates = append(templates, ts)
				}
			}
		}

		// Parse the JSON content field
		snippetContent, _ := snippetMap["content"].(string)
		if snippetContent == "" {
			return nil, fmt.Errorf("user snippet at index %d missing content", idx)
		}

		user, err := parseUserContent(snippetContent, templates)
		if err != nil {
			return nil, fmt.Errorf("user snippet at index %d: %v", idx, err)
		}

		users = append(users, user)
	}

	return users, nil
}

// parseUserContent parses the JSON content of a user snippet.
func parseUserContent(jsonContent string, templates []string) (opnapi.APIUserPayload, error) {
	var contentMap map[string]interface{}
	if err := json.Unmarshal([]byte(jsonContent), &contentMap); err != nil {
		return opnapi.APIUserPayload{}, fmt.Errorf("failed to parse user JSON: %v", err)
	}

	user := opnapi.APIUserPayload{
		Templates: templates,
	}

	// Required field
	user.Name, _ = contentMap["name"].(string)
	if user.Name == "" {
		return opnapi.APIUserPayload{}, fmt.Errorf("missing required field: name")
	}

	// Check for protected user
	if opnapi.IsProtectedUser(user.Name) {
		return opnapi.APIUserPayload{}, fmt.Errorf("cannot sync protected user: %s", user.Name)
	}

	// Optional fields
	user.Password, _ = contentMap["password"].(string)
	user.Disabled = parseBoolField(contentMap["disabled"])
	user.Scope, _ = contentMap["scope"].(string)
	if user.Scope == "" {
		user.Scope = "user" // Default scope
	}
	user.Descr, _ = contentMap["descr"].(string)
	user.Shell, _ = contentMap["shell"].(string)
	user.AuthorizedKeys, _ = contentMap["authorizedkeys"].(string)
	user.Expires, _ = contentMap["expires"].(string)
	user.Email, _ = contentMap["email"].(string)
	user.Comment, _ = contentMap["comment"].(string)
	user.Language, _ = contentMap["language"].(string)
	user.LandingPage, _ = contentMap["landing_page"].(string)

	// Parse groups (names)
	if groups, ok := contentMap["groups"].([]interface{}); ok {
		for _, g := range groups {
			if gs, ok := g.(string); ok {
				user.Groups = append(user.Groups, gs)
			}
		}
	}

	// Parse privileges
	if priv, ok := contentMap["priv"].([]interface{}); ok {
		for _, p := range priv {
			if ps, ok := p.(string); ok {
				user.Priv = append(user.Priv, ps)
			}
		}
	}

	return user, nil
}

// parseAPIGroups extracts groups from the payload snippets array.
func parseAPIGroups(payload map[string]interface{}) ([]opnapi.APIGroupPayload, error) {
	snippetsRaw, ok := payload["snippets"]
	if !ok {
		return []opnapi.APIGroupPayload{}, nil
	}

	snippetsArray, ok := snippetsRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("snippets must be an array")
	}

	var groups []opnapi.APIGroupPayload
	for idx, s := range snippetsArray {
		snippetMap, ok := s.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("snippet at index %d must be an object", idx)
		}

		configType, _ := snippetMap["config_type"].(string)
		if configType != "GROUP" {
			continue
		}

		// Get template names array
		var templates []string
		if templateNames, ok := snippetMap["template_name"].([]interface{}); ok {
			for _, t := range templateNames {
				if ts, ok := t.(string); ok {
					templates = append(templates, ts)
				}
			}
		}

		// Parse the JSON content field
		snippetContent, _ := snippetMap["content"].(string)
		if snippetContent == "" {
			return nil, fmt.Errorf("group snippet at index %d missing content", idx)
		}

		group, err := parseGroupContent(snippetContent, templates)
		if err != nil {
			return nil, fmt.Errorf("group snippet at index %d: %v", idx, err)
		}

		groups = append(groups, group)
	}

	return groups, nil
}

// parseGroupContent parses the JSON content of a group snippet.
func parseGroupContent(jsonContent string, templates []string) (opnapi.APIGroupPayload, error) {
	var contentMap map[string]interface{}
	if err := json.Unmarshal([]byte(jsonContent), &contentMap); err != nil {
		return opnapi.APIGroupPayload{}, fmt.Errorf("failed to parse group JSON: %v", err)
	}

	group := opnapi.APIGroupPayload{
		Templates: templates,
	}

	// Required field
	group.Name, _ = contentMap["name"].(string)
	if group.Name == "" {
		return opnapi.APIGroupPayload{}, fmt.Errorf("missing required field: name")
	}

	// Check for protected group
	if opnapi.IsProtectedGroup(group.Name) {
		return opnapi.APIGroupPayload{}, fmt.Errorf("cannot sync protected group: %s", group.Name)
	}

	// Optional fields
	group.Description, _ = contentMap["description"].(string)
	group.SourceNetworks, _ = contentMap["source_networks"].(string)

	// Parse members (names)
	if members, ok := contentMap["members"].([]interface{}); ok {
		for _, m := range members {
			if ms, ok := m.(string); ok {
				group.Members = append(group.Members, ms)
			}
		}
	}

	// Parse privileges
	if priv, ok := contentMap["priv"].([]interface{}); ok {
		for _, p := range priv {
			if ps, ok := p.(string); ok {
				group.Priv = append(group.Priv, ps)
			}
		}
	}

	return group, nil
}

// parseBoolField parses a field that can be bool, string, or number to bool.
func parseBoolField(v interface{}) bool {
	switch e := v.(type) {
	case bool:
		return e
	case string:
		return e == "1" || strings.ToLower(e) == "true"
	case float64:
		return e != 0
	default:
		return false
	}
}

// executeSyncUsersGroups performs sync for users and groups.
// Groups are synced first (users may reference groups).
func executeSyncUsersGroups(ctx context.Context, client *opnapi.Client, users []opnapi.APIUserPayload, groups []opnapi.APIGroupPayload) SyncAPIResult {
	log := logging.Named("SYNC_API")

	var results []SyncAPIItemResult
	var errors []string

	// Phase 1: Get all users and groups for lookups
	allUsers, err := client.ListAllUsers(ctx)
	if err != nil {
		return SyncAPIResult{
			Success: false,
			Message: fmt.Sprintf("Failed to list users: %v", err),
		}
	}

	allGroups, err := client.ListAllGroups(ctx)
	if err != nil {
		return SyncAPIResult{
			Success: false,
			Message: fmt.Sprintf("Failed to list groups: %v", err),
		}
	}

	// Filter for managed resources
	managedUsers := opnapi.FilterManagedUsers(allUsers)
	managedGroups := opnapi.FilterManagedGroups(allGroups)

	log.Infow("Discovered resources",
		"total_users", len(allUsers),
		"managed_users", len(managedUsers),
		"total_groups", len(allGroups),
		"managed_groups", len(managedGroups),
	)

	// Build lookup maps
	userUUIDLookup := opnapi.BuildUserUUIDLookup(allUsers)
	groupUUIDLookup := opnapi.BuildGroupUUIDLookup(allGroups)
	gidLookup := opnapi.BuildGIDLookup(allGroups)
	uidLookup := opnapi.BuildUIDLookup(allUsers)

	// Build sets of desired names
	desiredUserNames := make(map[string]opnapi.APIUserPayload)
	for _, u := range users {
		desiredUserNames[u.Name] = u
	}

	desiredGroupNames := make(map[string]opnapi.APIGroupPayload)
	for _, g := range groups {
		desiredGroupNames[g.Name] = g
	}

	// Phase 2: Create/Update groups first (users depend on groups)
	for _, groupPayload := range groups {
		existingUUID, exists := groupUUIDLookup[groupPayload.Name]

		action := "created"
		var syncErr error

		// Convert to OPNsense format (without member UIDs for now)
		opnGroup := opnapi.ConvertAPIToGroup(groupPayload, groupPayload.Templates, uidLookup)

		if exists {
			action = "updated"
			syncErr = client.SetGroup(ctx, existingUUID, opnGroup)
		} else {
			newUUID, addErr := client.AddGroup(ctx, opnGroup)
			syncErr = addErr
			if addErr == nil {
				// Update lookup for subsequent operations
				groupUUIDLookup[groupPayload.Name] = newUUID
			}
		}

		itemResult := SyncAPIItemResult{
			Type:   "group",
			Name:   groupPayload.Name,
			Action: action,
		}

		if syncErr != nil {
			itemResult.Status = "error"
			itemResult.Error = syncErr.Error()
			errors = append(errors, fmt.Sprintf("Group %s: %v", groupPayload.Name, syncErr))
		} else {
			itemResult.Status = "success"
		}

		results = append(results, itemResult)
	}

	// Refresh GID lookup after group changes
	allGroups, _ = client.ListAllGroups(ctx)
	gidLookup = opnapi.BuildGIDLookup(allGroups)
	groupUUIDLookup = opnapi.BuildGroupUUIDLookup(allGroups)

	// Phase 3: Create/Update users (after groups exist)
	for _, userPayload := range users {
		existingUUID, exists := userUUIDLookup[userPayload.Name]

		action := "created"
		var syncErr error

		// Convert to OPNsense format (resolves group names to GIDs)
		opnUser := opnapi.ConvertAPIToUser(userPayload, userPayload.Templates, gidLookup)

		if exists {
			action = "updated"
			// Don't send password on update if not provided
			if userPayload.Password == "" {
				opnUser.Password = ""
			}
			syncErr = client.SetUser(ctx, existingUUID, opnUser)
		} else {
			// Password required for new users
			if opnUser.Password == "" {
				syncErr = fmt.Errorf("password required for new user")
			} else {
				newUUID, addErr := client.AddUser(ctx, opnUser)
				syncErr = addErr
				if addErr == nil {
					userUUIDLookup[userPayload.Name] = newUUID
				}
			}
		}

		itemResult := SyncAPIItemResult{
			Type:   "user",
			Name:   userPayload.Name,
			Action: action,
		}

		if syncErr != nil {
			itemResult.Status = "error"
			itemResult.Error = syncErr.Error()
			errors = append(errors, fmt.Sprintf("User %s: %v", userPayload.Name, syncErr))
		} else {
			itemResult.Status = "success"
		}

		results = append(results, itemResult)
	}

	// Refresh UID lookup after user changes
	allUsers, _ = client.ListAllUsers(ctx)
	uidLookup = opnapi.BuildUIDLookup(allUsers)
	userUUIDLookup = opnapi.BuildUserUUIDLookup(allUsers)
	managedUsers = opnapi.FilterManagedUsers(allUsers)

	// Phase 4: Update groups with member UIDs (now that users exist)
	for _, groupPayload := range groups {
		if len(groupPayload.Members) == 0 {
			continue // No members to update
		}

		existingUUID, exists := groupUUIDLookup[groupPayload.Name]
		if !exists {
			continue // Group creation failed, skip
		}

		// Convert with updated UID lookup
		opnGroup := opnapi.ConvertAPIToGroup(groupPayload, groupPayload.Templates, uidLookup)

		if err := client.SetGroup(ctx, existingUUID, opnGroup); err != nil {
			errors = append(errors, fmt.Sprintf("Group %s member update: %v", groupPayload.Name, err))
		}
	}

	// Phase 5: Delete orphan users (managed but not in desired)
	for _, managedUser := range managedUsers {
		name, _ := managedUser["name"].(string)
		uuid, _ := managedUser["uuid"].(string)

		if _, desired := desiredUserNames[name]; desired {
			continue
		}

		// Skip protected users
		if opnapi.IsProtectedUser(name) {
			continue
		}

		err := client.DeleteUser(ctx, uuid)

		itemResult := SyncAPIItemResult{
			Type:   "user",
			UUID:   uuid,
			Name:   name,
			Action: "deleted",
		}

		if err != nil {
			itemResult.Status = "error"
			itemResult.Error = err.Error()
			errors = append(errors, fmt.Sprintf("Delete user %s: %v", name, err))
		} else {
			itemResult.Status = "success"
		}

		results = append(results, itemResult)
	}

	// Phase 6: Delete orphan groups (after users deleted)
	managedGroups = opnapi.FilterManagedGroups(allGroups)
	for _, managedGroup := range managedGroups {
		name, _ := managedGroup["name"].(string)
		uuid, _ := managedGroup["uuid"].(string)

		if _, desired := desiredGroupNames[name]; desired {
			continue
		}

		// Skip protected groups
		if opnapi.IsProtectedGroup(name) {
			continue
		}

		err := client.DeleteGroup(ctx, uuid)

		itemResult := SyncAPIItemResult{
			Type:   "group",
			UUID:   uuid,
			Name:   name,
			Action: "deleted",
		}

		if err != nil {
			itemResult.Status = "error"
			itemResult.Error = err.Error()
			errors = append(errors, fmt.Sprintf("Delete group %s: %v", name, err))
		} else {
			itemResult.Status = "success"
		}

		results = append(results, itemResult)
	}

	// Build final result
	success := len(errors) == 0

	var userCreated, userUpdated, userDeleted int
	var groupCreated, groupUpdated, groupDeleted int
	for _, r := range results {
		if r.Status != "success" {
			continue
		}
		switch r.Type {
		case "user":
			switch r.Action {
			case "created":
				userCreated++
			case "updated":
				userUpdated++
			case "deleted":
				userDeleted++
			}
		case "group":
			switch r.Action {
			case "created":
				groupCreated++
			case "updated":
				groupUpdated++
			case "deleted":
				groupDeleted++
			}
		}
	}

	var parts []string
	if groupCreated > 0 || groupUpdated > 0 || groupDeleted > 0 {
		parts = append(parts, fmt.Sprintf("Groups: %d created, %d updated, %d deleted", groupCreated, groupUpdated, groupDeleted))
	}
	if userCreated > 0 || userUpdated > 0 || userDeleted > 0 {
		parts = append(parts, fmt.Sprintf("Users: %d created, %d updated, %d deleted", userCreated, userUpdated, userDeleted))
	}

	var message string
	if len(parts) == 0 {
		message = "No changes applied"
	} else {
		message = strings.Join(parts, ". ")
	}
	if !success {
		message = fmt.Sprintf("%s (%d errors)", message, len(errors))
	}

	log.Infow("User/Group sync completed",
		"success", success,
		"groups_created", groupCreated,
		"groups_updated", groupUpdated,
		"groups_deleted", groupDeleted,
		"users_created", userCreated,
		"users_updated", userUpdated,
		"users_deleted", userDeleted,
		"error_count", len(errors),
	)

	return SyncAPIResult{
		Success: success,
		Message: message,
		Results: results,
		Errors:  errors,
	}
}

// ============================================================================
// Unbound DNS Parsing Functions
// ============================================================================

// parseAPIHostOverrides extracts host overrides from the payload snippets array.
func parseAPIHostOverrides(payload map[string]interface{}) ([]opnapi.APIHostOverridePayload, error) {
	snippetsRaw, ok := payload["snippets"]
	if !ok {
		return []opnapi.APIHostOverridePayload{}, nil
	}

	snippetsArray, ok := snippetsRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("snippets must be an array")
	}

	var overrides []opnapi.APIHostOverridePayload
	for idx, s := range snippetsArray {
		snippetMap, ok := s.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("snippet at index %d must be an object", idx)
		}

		configType, _ := snippetMap["config_type"].(string)
		if configType != "UNBOUND_HOST_OVERRIDE" {
			continue
		}

		// Get template names array
		var templates []string
		if templateNames, ok := snippetMap["template_name"].([]interface{}); ok {
			for _, t := range templateNames {
				if ts, ok := t.(string); ok {
					templates = append(templates, ts)
				}
			}
		}

		// Parse the JSON content field
		snippetContent, _ := snippetMap["content"].(string)
		if snippetContent == "" {
			return nil, fmt.Errorf("host_override snippet at index %d missing content", idx)
		}

		override, err := parseHostOverrideContent(snippetContent, templates)
		if err != nil {
			return nil, fmt.Errorf("host_override snippet at index %d: %v", idx, err)
		}

		overrides = append(overrides, override)
	}

	return overrides, nil
}

// parseHostOverrideContent parses the JSON content of a host override snippet.
func parseHostOverrideContent(jsonContent string, templates []string) (opnapi.APIHostOverridePayload, error) {
	var contentMap map[string]interface{}
	if err := json.Unmarshal([]byte(jsonContent), &contentMap); err != nil {
		return opnapi.APIHostOverridePayload{}, fmt.Errorf("failed to parse host_override JSON: %v", err)
	}

	override := opnapi.APIHostOverridePayload{
		Templates: templates,
	}

	// Required fields
	override.UUID, _ = contentMap["uuid"].(string)
	if override.UUID == "" {
		return opnapi.APIHostOverridePayload{}, fmt.Errorf("missing required field: uuid")
	}

	override.Hostname, _ = contentMap["hostname"].(string)
	if override.Hostname == "" {
		return opnapi.APIHostOverridePayload{}, fmt.Errorf("missing required field: hostname")
	}

	override.Domain, _ = contentMap["domain"].(string)
	if override.Domain == "" {
		return opnapi.APIHostOverridePayload{}, fmt.Errorf("missing required field: domain")
	}

	// Parse enabled
	override.Enabled = parseEnabled(contentMap["enabled"])

	// Optional fields
	override.RR, _ = contentMap["rr"].(string)
	if override.RR == "" {
		override.RR = "A" // Default to A record
	}
	override.Server, _ = contentMap["server"].(string)
	override.MXPrio, _ = contentMap["mxprio"].(string)
	override.MX, _ = contentMap["mx"].(string)
	override.TTL, _ = contentMap["ttl"].(string)
	override.TXTData, _ = contentMap["txtdata"].(string)
	override.Description, _ = contentMap["description"].(string)

	return override, nil
}

// parseAPIDomainForwards extracts domain forwards from the payload snippets array.
func parseAPIDomainForwards(payload map[string]interface{}) ([]opnapi.APIDomainForwardPayload, error) {
	snippetsRaw, ok := payload["snippets"]
	if !ok {
		return []opnapi.APIDomainForwardPayload{}, nil
	}

	snippetsArray, ok := snippetsRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("snippets must be an array")
	}

	var forwards []opnapi.APIDomainForwardPayload
	for idx, s := range snippetsArray {
		snippetMap, ok := s.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("snippet at index %d must be an object", idx)
		}

		configType, _ := snippetMap["config_type"].(string)
		if configType != "UNBOUND_DOMAIN_FORWARD" {
			continue
		}

		// Get template names array
		var templates []string
		if templateNames, ok := snippetMap["template_name"].([]interface{}); ok {
			for _, t := range templateNames {
				if ts, ok := t.(string); ok {
					templates = append(templates, ts)
				}
			}
		}

		// Parse the JSON content field
		snippetContent, _ := snippetMap["content"].(string)
		if snippetContent == "" {
			return nil, fmt.Errorf("domain_forward snippet at index %d missing content", idx)
		}

		forward, err := parseDomainForwardContent(snippetContent, templates)
		if err != nil {
			return nil, fmt.Errorf("domain_forward snippet at index %d: %v", idx, err)
		}

		forwards = append(forwards, forward)
	}

	return forwards, nil
}

// parseDomainForwardContent parses the JSON content of a domain forward snippet.
func parseDomainForwardContent(jsonContent string, templates []string) (opnapi.APIDomainForwardPayload, error) {
	var contentMap map[string]interface{}
	if err := json.Unmarshal([]byte(jsonContent), &contentMap); err != nil {
		return opnapi.APIDomainForwardPayload{}, fmt.Errorf("failed to parse domain_forward JSON: %v", err)
	}

	forward := opnapi.APIDomainForwardPayload{
		Templates: templates,
	}

	// Required fields
	forward.UUID, _ = contentMap["uuid"].(string)
	if forward.UUID == "" {
		return opnapi.APIDomainForwardPayload{}, fmt.Errorf("missing required field: uuid")
	}

	forward.Domain, _ = contentMap["domain"].(string)
	if forward.Domain == "" {
		return opnapi.APIDomainForwardPayload{}, fmt.Errorf("missing required field: domain")
	}

	forward.Server, _ = contentMap["server"].(string)
	if forward.Server == "" {
		return opnapi.APIDomainForwardPayload{}, fmt.Errorf("missing required field: server")
	}

	// Parse enabled
	forward.Enabled = parseEnabled(contentMap["enabled"])

	// Optional fields
	forward.Type, _ = contentMap["type"].(string)
	if forward.Type == "" {
		forward.Type = "forward" // Default to standard forwarding
	}
	forward.Port, _ = contentMap["port"].(string)
	forward.Verify, _ = contentMap["verify"].(string)
	forward.ForwardTCPUpstream = parseBoolField(contentMap["forward_tcp_upstream"])
	forward.ForwardFirst = parseBoolField(contentMap["forward_first"])
	forward.Description, _ = contentMap["description"].(string)

	return forward, nil
}

// parseAPIHostAliases extracts host aliases from the payload snippets array.
func parseAPIHostAliases(payload map[string]interface{}) ([]opnapi.APIHostAliasPayload, error) {
	snippetsRaw, ok := payload["snippets"]
	if !ok {
		return []opnapi.APIHostAliasPayload{}, nil
	}

	snippetsArray, ok := snippetsRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("snippets must be an array")
	}

	var aliases []opnapi.APIHostAliasPayload
	for idx, s := range snippetsArray {
		snippetMap, ok := s.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("snippet at index %d must be an object", idx)
		}

		configType, _ := snippetMap["config_type"].(string)
		if configType != "UNBOUND_HOST_ALIAS" {
			continue
		}

		// Get template names array
		var templates []string
		if templateNames, ok := snippetMap["template_name"].([]interface{}); ok {
			for _, t := range templateNames {
				if ts, ok := t.(string); ok {
					templates = append(templates, ts)
				}
			}
		}

		// Parse the JSON content field
		snippetContent, _ := snippetMap["content"].(string)
		if snippetContent == "" {
			return nil, fmt.Errorf("host_alias snippet at index %d missing content", idx)
		}

		alias, err := parseHostAliasContent(snippetContent, templates)
		if err != nil {
			return nil, fmt.Errorf("host_alias snippet at index %d: %v", idx, err)
		}

		aliases = append(aliases, alias)
	}

	return aliases, nil
}

// parseHostAliasContent parses the JSON content of a host alias snippet.
func parseHostAliasContent(jsonContent string, templates []string) (opnapi.APIHostAliasPayload, error) {
	var contentMap map[string]interface{}
	if err := json.Unmarshal([]byte(jsonContent), &contentMap); err != nil {
		return opnapi.APIHostAliasPayload{}, fmt.Errorf("failed to parse host_alias JSON: %v", err)
	}

	alias := opnapi.APIHostAliasPayload{
		Templates: templates,
	}

	// Required fields
	alias.UUID, _ = contentMap["uuid"].(string)
	if alias.UUID == "" {
		return opnapi.APIHostAliasPayload{}, fmt.Errorf("missing required field: uuid")
	}

	alias.Hostname, _ = contentMap["hostname"].(string)
	if alias.Hostname == "" {
		return opnapi.APIHostAliasPayload{}, fmt.Errorf("missing required field: hostname")
	}

	alias.Domain, _ = contentMap["domain"].(string)
	if alias.Domain == "" {
		return opnapi.APIHostAliasPayload{}, fmt.Errorf("missing required field: domain")
	}

	// Parent reference (for portability)
	alias.ParentHostname, _ = contentMap["parent_hostname"].(string)
	alias.ParentDomain, _ = contentMap["parent_domain"].(string)

	// Parse enabled
	alias.Enabled = parseEnabled(contentMap["enabled"])

	// Optional fields
	alias.Description, _ = contentMap["description"].(string)

	return alias, nil
}

// parseAPIUnboundACLs extracts Unbound ACLs from the payload snippets array.
func parseAPIUnboundACLs(payload map[string]interface{}) ([]opnapi.APIUnboundACLPayload, error) {
	snippetsRaw, ok := payload["snippets"]
	if !ok {
		return []opnapi.APIUnboundACLPayload{}, nil
	}

	snippetsArray, ok := snippetsRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("snippets must be an array")
	}

	var acls []opnapi.APIUnboundACLPayload
	for idx, s := range snippetsArray {
		snippetMap, ok := s.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("snippet at index %d must be an object", idx)
		}

		configType, _ := snippetMap["config_type"].(string)
		if configType != "UNBOUND_ACL" {
			continue
		}

		// Get template names array
		var templates []string
		if templateNames, ok := snippetMap["template_name"].([]interface{}); ok {
			for _, t := range templateNames {
				if ts, ok := t.(string); ok {
					templates = append(templates, ts)
				}
			}
		}

		// Parse the JSON content field
		snippetContent, _ := snippetMap["content"].(string)
		if snippetContent == "" {
			return nil, fmt.Errorf("unbound_acl snippet at index %d missing content", idx)
		}

		acl, err := parseUnboundACLContent(snippetContent, templates)
		if err != nil {
			return nil, fmt.Errorf("unbound_acl snippet at index %d: %v", idx, err)
		}

		acls = append(acls, acl)
	}

	return acls, nil
}

// parseUnboundACLContent parses the JSON content of an Unbound ACL snippet.
func parseUnboundACLContent(jsonContent string, templates []string) (opnapi.APIUnboundACLPayload, error) {
	var contentMap map[string]interface{}
	if err := json.Unmarshal([]byte(jsonContent), &contentMap); err != nil {
		return opnapi.APIUnboundACLPayload{}, fmt.Errorf("failed to parse unbound_acl JSON: %v", err)
	}

	acl := opnapi.APIUnboundACLPayload{
		Templates: templates,
	}

	// Required fields
	acl.UUID, _ = contentMap["uuid"].(string)
	if acl.UUID == "" {
		return opnapi.APIUnboundACLPayload{}, fmt.Errorf("missing required field: uuid")
	}

	acl.Name, _ = contentMap["name"].(string)
	if acl.Name == "" {
		return opnapi.APIUnboundACLPayload{}, fmt.Errorf("missing required field: name")
	}

	acl.Action, _ = contentMap["action"].(string)
	if acl.Action == "" {
		return opnapi.APIUnboundACLPayload{}, fmt.Errorf("missing required field: action")
	}

	// Parse enabled
	acl.Enabled = parseEnabled(contentMap["enabled"])

	// Parse networks - can be string (CSV) or array
	switch v := contentMap["networks"].(type) {
	case string:
		if v != "" {
			acl.Networks = strings.Split(v, ",")
			for i := range acl.Networks {
				acl.Networks[i] = strings.TrimSpace(acl.Networks[i])
			}
		}
	case []interface{}:
		for _, n := range v {
			if ns, ok := n.(string); ok {
				acl.Networks = append(acl.Networks, ns)
			}
		}
	}

	// Optional fields
	acl.Description, _ = contentMap["description"].(string)

	return acl, nil
}

// ============================================================================
// Unbound DNS Sync Execution
// ============================================================================

// executeSyncUnbound performs sync for Unbound DNS entities.
// Order of operations:
// 1. Create/Update host overrides (must exist before aliases)
// 2. Create/Update domain forwards
// 3. Create/Update ACLs
// 4. Create/Update host aliases (after host overrides exist)
// 5. Delete orphan host aliases (before parent host overrides)
// 6. Delete orphan host overrides, domain forwards, ACLs
// 7. Apply changes with ReconfigureUnbound()
func executeSyncUnbound(
	ctx context.Context,
	client *opnapi.Client,
	hostOverrides []opnapi.APIHostOverridePayload,
	domainForwards []opnapi.APIDomainForwardPayload,
	hostAliases []opnapi.APIHostAliasPayload,
	unboundACLs []opnapi.APIUnboundACLPayload,
) SyncAPIResult {
	log := logging.Named("SYNC_API")

	var results []SyncAPIItemResult
	var errors []string

	// Phase 1: Get ALL Unbound objects and filter for managed ones
	allHostOverrides, err := client.ListAllHostOverrides(ctx)
	if err != nil {
		return SyncAPIResult{
			Success: false,
			Message: fmt.Sprintf("Failed to list host overrides: %v", err),
		}
	}
	currentHostOverrides := opnapi.FilterManagedHostOverrides(allHostOverrides)

	allForwards, err := client.ListAllForwards(ctx)
	if err != nil {
		return SyncAPIResult{
			Success: false,
			Message: fmt.Sprintf("Failed to list domain forwards: %v", err),
		}
	}
	currentForwards := opnapi.FilterManagedForwards(allForwards)

	allHostAliases, err := client.ListAllHostAliases(ctx)
	if err != nil {
		return SyncAPIResult{
			Success: false,
			Message: fmt.Sprintf("Failed to list host aliases: %v", err),
		}
	}
	currentHostAliases := opnapi.FilterManagedHostAliases(allHostAliases)

	allACLs, err := client.ListAllACLs(ctx)
	if err != nil {
		return SyncAPIResult{
			Success: false,
			Message: fmt.Sprintf("Failed to list ACLs: %v", err),
		}
	}
	currentACLs := opnapi.FilterManagedACLs(allACLs)

	log.Infow("Discovered managed Unbound objects",
		"total_host_overrides", len(allHostOverrides),
		"managed_host_overrides", len(currentHostOverrides),
		"total_forwards", len(allForwards),
		"managed_forwards", len(currentForwards),
		"total_host_aliases", len(allHostAliases),
		"managed_host_aliases", len(currentHostAliases),
		"total_acls", len(allACLs),
		"managed_acls", len(currentACLs),
	)

	// Build maps of current UUIDs
	currentHostOverrideUUIDs := make(map[string]bool)
	for _, ho := range currentHostOverrides {
		if uuid, ok := ho["uuid"].(string); ok {
			currentHostOverrideUUIDs[uuid] = true
		}
	}

	currentForwardUUIDs := make(map[string]bool)
	for _, f := range currentForwards {
		if uuid, ok := f["uuid"].(string); ok {
			currentForwardUUIDs[uuid] = true
		}
	}

	currentHostAliasUUIDs := make(map[string]bool)
	for _, ha := range currentHostAliases {
		if uuid, ok := ha["uuid"].(string); ok {
			currentHostAliasUUIDs[uuid] = true
		}
	}

	currentACLUUIDs := make(map[string]bool)
	for _, acl := range currentACLs {
		if uuid, ok := acl["uuid"].(string); ok {
			currentACLUUIDs[uuid] = true
		}
	}

	// Build maps of desired UUIDs
	desiredHostOverrideUUIDs := make(map[string]opnapi.APIHostOverridePayload)
	for _, ho := range hostOverrides {
		desiredHostOverrideUUIDs[ho.UUID] = ho
	}

	desiredForwardUUIDs := make(map[string]opnapi.APIDomainForwardPayload)
	for _, f := range domainForwards {
		desiredForwardUUIDs[f.UUID] = f
	}

	desiredHostAliasUUIDs := make(map[string]opnapi.APIHostAliasPayload)
	for _, ha := range hostAliases {
		desiredHostAliasUUIDs[ha.UUID] = ha
	}

	desiredACLUUIDs := make(map[string]opnapi.APIUnboundACLPayload)
	for _, acl := range unboundACLs {
		desiredACLUUIDs[acl.UUID] = acl
	}

	// Phase 2: Create/Update host overrides (must exist before aliases)
	for _, ho := range hostOverrides {
		action := "created"
		if currentHostOverrideUUIDs[ho.UUID] {
			action = "updated"
		}

		opnOverride := opnapi.ConvertToOPNHostOverride(ho)
		err := client.SetHostOverride(ctx, ho.UUID, opnOverride)

		itemResult := SyncAPIItemResult{
			Type:   "host_override",
			UUID:   ho.UUID,
			Name:   ho.Hostname + "." + ho.Domain,
			Action: action,
		}

		if err != nil {
			itemResult.Status = "error"
			itemResult.Error = err.Error()
			errors = append(errors, fmt.Sprintf("Host override %s.%s: %v", ho.Hostname, ho.Domain, err))
		} else {
			itemResult.Status = "success"
		}

		results = append(results, itemResult)
	}

	// Phase 3: Create/Update domain forwards
	for _, fwd := range domainForwards {
		action := "created"
		if currentForwardUUIDs[fwd.UUID] {
			action = "updated"
		}

		opnForward := opnapi.ConvertToOPNDomainForward(fwd)
		err := client.SetForward(ctx, fwd.UUID, opnForward)

		itemResult := SyncAPIItemResult{
			Type:   "domain_forward",
			UUID:   fwd.UUID,
			Name:   fwd.Domain,
			Action: action,
		}

		if err != nil {
			itemResult.Status = "error"
			itemResult.Error = err.Error()
			errors = append(errors, fmt.Sprintf("Domain forward %s: %v", fwd.Domain, err))
		} else {
			itemResult.Status = "success"
		}

		results = append(results, itemResult)
	}

	// Phase 4: Create/Update ACLs
	for _, acl := range unboundACLs {
		action := "created"
		if currentACLUUIDs[acl.UUID] {
			action = "updated"
		}

		opnACL := opnapi.ConvertToOPNACL(acl)
		err := client.SetACL(ctx, acl.UUID, opnACL)

		itemResult := SyncAPIItemResult{
			Type:   "unbound_acl",
			UUID:   acl.UUID,
			Name:   acl.Name,
			Action: action,
		}

		if err != nil {
			itemResult.Status = "error"
			itemResult.Error = err.Error()
			errors = append(errors, fmt.Sprintf("ACL %s: %v", acl.Name, err))
		} else {
			itemResult.Status = "success"
		}

		results = append(results, itemResult)
	}

	// Refresh host override list for alias parent resolution
	// (in case new ones were created)
	allHostOverrides, _ = client.ListAllHostOverrides(ctx)
	hostOverrideLookup := opnapi.BuildHostOverrideUUIDLookup(allHostOverrides)

	// Also build a lookup for host overrides in the payload (for pending creates)
	for _, ho := range hostOverrides {
		key := ho.Hostname + "." + ho.Domain
		hostOverrideLookup[key] = ho.UUID
	}

	// Phase 5: Create/Update host aliases (after host overrides exist)
	for _, ha := range hostAliases {
		action := "created"
		if currentHostAliasUUIDs[ha.UUID] {
			action = "updated"
		}

		// Resolve parent hostname+domain to UUID
		parentKey := ha.ParentHostname + "." + ha.ParentDomain
		parentUUID, found := hostOverrideLookup[parentKey]
		if !found {
			itemResult := SyncAPIItemResult{
				Type:   "host_alias",
				UUID:   ha.UUID,
				Name:   ha.Hostname + "." + ha.Domain,
				Action: action,
				Status: "error",
				Error:  fmt.Sprintf("parent host override not found: %s", parentKey),
			}
			results = append(results, itemResult)
			errors = append(errors, fmt.Sprintf("Host alias %s.%s: parent not found: %s", ha.Hostname, ha.Domain, parentKey))
			continue
		}

		opnAlias := opnapi.ConvertToOPNHostAlias(ha, parentUUID)
		err := client.SetHostAlias(ctx, ha.UUID, opnAlias)

		itemResult := SyncAPIItemResult{
			Type:   "host_alias",
			UUID:   ha.UUID,
			Name:   ha.Hostname + "." + ha.Domain,
			Action: action,
		}

		if err != nil {
			itemResult.Status = "error"
			itemResult.Error = err.Error()
			errors = append(errors, fmt.Sprintf("Host alias %s.%s: %v", ha.Hostname, ha.Domain, err))
		} else {
			itemResult.Status = "success"
		}

		results = append(results, itemResult)
	}

	// Phase 6: Delete orphan host aliases (before deleting parent host overrides)
	for uuid := range currentHostAliasUUIDs {
		if _, exists := desiredHostAliasUUIDs[uuid]; !exists {
			err := client.DeleteHostAlias(ctx, uuid)

			itemResult := SyncAPIItemResult{
				Type:   "host_alias",
				UUID:   uuid,
				Action: "deleted",
			}

			if err != nil {
				itemResult.Status = "error"
				itemResult.Error = err.Error()
				errors = append(errors, fmt.Sprintf("Delete host alias %s: %v", uuid, err))
			} else {
				itemResult.Status = "success"
			}

			results = append(results, itemResult)
		}
	}

	// Phase 7: Delete orphan host overrides
	for uuid := range currentHostOverrideUUIDs {
		if _, exists := desiredHostOverrideUUIDs[uuid]; !exists {
			err := client.DeleteHostOverride(ctx, uuid)

			itemResult := SyncAPIItemResult{
				Type:   "host_override",
				UUID:   uuid,
				Action: "deleted",
			}

			if err != nil {
				itemResult.Status = "error"
				itemResult.Error = err.Error()
				errors = append(errors, fmt.Sprintf("Delete host override %s: %v", uuid, err))
			} else {
				itemResult.Status = "success"
			}

			results = append(results, itemResult)
		}
	}

	// Phase 8: Delete orphan domain forwards
	for uuid := range currentForwardUUIDs {
		if _, exists := desiredForwardUUIDs[uuid]; !exists {
			err := client.DeleteForward(ctx, uuid)

			itemResult := SyncAPIItemResult{
				Type:   "domain_forward",
				UUID:   uuid,
				Action: "deleted",
			}

			if err != nil {
				itemResult.Status = "error"
				itemResult.Error = err.Error()
				errors = append(errors, fmt.Sprintf("Delete domain forward %s: %v", uuid, err))
			} else {
				itemResult.Status = "success"
			}

			results = append(results, itemResult)
		}
	}

	// Phase 9: Delete orphan ACLs
	for uuid := range currentACLUUIDs {
		if _, exists := desiredACLUUIDs[uuid]; !exists {
			err := client.DeleteACL(ctx, uuid)

			itemResult := SyncAPIItemResult{
				Type:   "unbound_acl",
				UUID:   uuid,
				Action: "deleted",
			}

			if err != nil {
				itemResult.Status = "error"
				itemResult.Error = err.Error()
				errors = append(errors, fmt.Sprintf("Delete ACL %s: %v", uuid, err))
			} else {
				itemResult.Status = "success"
			}

			results = append(results, itemResult)
		}
	}

	// Phase 10: Apply changes
	if err := client.ReconfigureUnbound(ctx); err != nil {
		errors = append(errors, fmt.Sprintf("Unbound reconfigure: %v", err))
	}

	// Build final result with detailed counts
	success := len(errors) == 0

	var hoCreated, hoUpdated, hoDeleted int
	var fwdCreated, fwdUpdated, fwdDeleted int
	var haCreated, haUpdated, haDeleted int
	var aclCreated, aclUpdated, aclDeleted int

	for _, r := range results {
		if r.Status != "success" {
			continue
		}
		switch r.Type {
		case "host_override":
			switch r.Action {
			case "created":
				hoCreated++
			case "updated":
				hoUpdated++
			case "deleted":
				hoDeleted++
			}
		case "domain_forward":
			switch r.Action {
			case "created":
				fwdCreated++
			case "updated":
				fwdUpdated++
			case "deleted":
				fwdDeleted++
			}
		case "host_alias":
			switch r.Action {
			case "created":
				haCreated++
			case "updated":
				haUpdated++
			case "deleted":
				haDeleted++
			}
		case "unbound_acl":
			switch r.Action {
			case "created":
				aclCreated++
			case "updated":
				aclUpdated++
			case "deleted":
				aclDeleted++
			}
		}
	}

	// Build descriptive message
	var parts []string
	if hoCreated > 0 || hoUpdated > 0 || hoDeleted > 0 {
		parts = append(parts, fmt.Sprintf("Host Overrides: %d created, %d updated, %d deleted", hoCreated, hoUpdated, hoDeleted))
	}
	if fwdCreated > 0 || fwdUpdated > 0 || fwdDeleted > 0 {
		parts = append(parts, fmt.Sprintf("Domain Forwards: %d created, %d updated, %d deleted", fwdCreated, fwdUpdated, fwdDeleted))
	}
	if haCreated > 0 || haUpdated > 0 || haDeleted > 0 {
		parts = append(parts, fmt.Sprintf("Host Aliases: %d created, %d updated, %d deleted", haCreated, haUpdated, haDeleted))
	}
	if aclCreated > 0 || aclUpdated > 0 || aclDeleted > 0 {
		parts = append(parts, fmt.Sprintf("ACLs: %d created, %d updated, %d deleted", aclCreated, aclUpdated, aclDeleted))
	}

	var message string
	if len(parts) == 0 {
		message = "No changes applied"
	} else {
		message = strings.Join(parts, ". ")
	}
	if !success {
		message = fmt.Sprintf("%s (%d errors)", message, len(errors))
	}

	log.Infow("Unbound sync completed",
		"success", success,
		"host_overrides_created", hoCreated,
		"host_overrides_updated", hoUpdated,
		"host_overrides_deleted", hoDeleted,
		"domain_forwards_created", fwdCreated,
		"domain_forwards_updated", fwdUpdated,
		"domain_forwards_deleted", fwdDeleted,
		"host_aliases_created", haCreated,
		"host_aliases_updated", haUpdated,
		"host_aliases_deleted", haDeleted,
		"acls_created", aclCreated,
		"acls_updated", aclUpdated,
		"acls_deleted", aclDeleted,
		"error_count", len(errors),
	)

	return SyncAPIResult{
		Success: success,
		Message: message,
		Results: results,
		Errors:  errors,
	}
}
