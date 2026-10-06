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
	"go.uber.org/zap"
)

// RulePosition defines where managed rules are placed relative to the local
// rules of their section; see rule_placement.go.
type RulePosition string

const (
	// RulePositionPrepend places rules BEFORE the local rules of their section.
	RulePositionPrepend RulePosition = "PREPEND"
	// RulePositionAppend places rules AFTER the local MVC rules of their section.
	RulePositionAppend RulePosition = "APPEND"
)

// APIAliasPayload represents an alias in JSON-native format for SYNC_API.
//
// Content is the alias as the snippet holds it, checked against the device's
// alias model and converted once executeSyncAPI has read that model
// (buildAliasBody). Name and Type are read from it at parse time, where they
// are required.
type APIAliasPayload struct {
	UUID      string                 `json:"uuid"`
	Name      string                 `json:"name"`
	Type      string                 `json:"type"`
	Content   map[string]interface{} `json:"content"`
	Templates []string               `json:"templates"`

	// SnippetName and SnippetIndex record where in the SYNC payload this
	// object came from, so a validation failure can name the snippet the
	// user has to go and fix rather than just the object. Agent-internal
	// provenance, never serialised: this is not part of the portable
	// snippet format, and the wire contract is unchanged.
	SnippetName  string `json:"-"`
	SnippetIndex int    `json:"-"`
}

// APIRulePayload represents a rule in JSON-native format for SYNC_API.
// Position and Priority are extracted from snippet metadata (not content JSON).
// The sequence is placement's (rule_placement.go).
//
// Content is the rule as the snippet holds it. Its keys are checked against
// the device's rule model, and its values converted to OPNsense's string
// forms, once executeSyncAPI has read that model (buildRuleBody). Description,
// Interface, SourceNet and DestinationNet are read from it at parse time for
// the checks that run before then, and for messages.
type APIRulePayload struct {
	UUID           string                 `json:"uuid"`
	Position       RulePosition           `json:"position"` // PREPEND or APPEND relative to unmanaged rules
	Priority       int                    `json:"priority"` // Ordering within position group (lower = higher priority)
	Content        map[string]interface{} `json:"content"`
	Interface      string                 `json:"interface"`
	SourceNet      string                 `json:"source_net"`
	DestinationNet string                 `json:"destination_net"`
	Description    string                 `json:"description"`
	Templates      []string               `json:"templates"`

	// SnippetName and SnippetIndex record where in the SYNC payload this
	// object came from, so a validation failure can name the snippet the
	// user has to go and fix rather than just the object. Agent-internal
	// provenance, never serialised: this is not part of the portable
	// snippet format, and the wire contract is unchanged.
	SnippetName  string `json:"-"`
	SnippetIndex int    `json:"-"`
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
//
// Code, Before, After, Available and Risks are additive fields (all
// `omitempty`, so an item without them and every older control-plane
// consumer sees no shape change at all). Code is a structured outcome a
// consumer (NDBroker, NDCLI, NDWeb) keys on together with Status, never on
// free-text parsing of Error. Before/After/Available/Risks exist for the
// AUTH_SERVER/AUTH_ORDER family: Before/After/Available are names only
// (never a value) and are populated on the "auth_facility" item — see
// mapAuthResponseToResult.
type SyncAPIItemResult struct {
	Type   string `json:"type"`
	UUID   string `json:"uuid"`
	Name   string `json:"name"`
	Action string `json:"action"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
	// Code is the structured outcome code: for "auth"/"auth_server" it is
	// the fault/per-server code the PHP helper (or Go's own strict-parse
	// gate) reported; for "auth_facility" it is the facility's own code;
	// for "auth_local_server"/"auth_warning" it mirrors the code already
	// embedded in Error; for the "group_member"/"user" deferral items it
	// is authCodeUserDeferredExclusionStale; for a "user"/"group" element
	// refused for missing Superuser clearance it is
	// codeAdminEquivalentRequiresSuperuser, and a USER password refused as
	// a hash is USER_PASSWORD_IS_HASH; the trust family's items carry its
	// TRUST_* codes; a rule refused before its write, or by the device,
	// carries a RULE_* code or INTERFACE_NOT_FOUND (rule_content.go). A
	// refusal of a USER, GROUP or ZABBIX_* element by the owner's own
	// reject_dangerous_snippets policy carries none.
	Code string `json:"code,omitempty"`
	// Before/After are the auth_facility item's kept/written order, names
	// only. Available is the resolution set an unresolved
	// entry was checked against — reported only on a refused facility
	// write, never on success.
	Before    []string `json:"before,omitempty"`
	After     []string `json:"after,omitempty"`
	Available []string `json:"available,omitempty"`
	// Risks is the "auth_local_server" warning's structured risk list
	// (ORDER_NAMES_LOCAL_SERVER: cleartext/unscoped_sync/
	// protected_group/no_reserved_exclusion) — the same list that is also
	// joined into Error's free text for a human reading the log, so a
	// consumer can key on it without parsing "; risks: %s".
	Risks []string `json:"risks,omitempty"`
}

// dangerousSnippetRejectionMessage builds the explicit, actionable error
// text for a USER/GROUP/ZABBIX_* snippet element rejected by the
// reject_dangerous_snippets gate. Used for both the per-item
// SyncAPIItemResult.Error and the task-level errors slice (see
// executeSyncUsersGroups and executeSyncZabbix) — a rejection now fails the
// overall SYNC_API task rather than only showing up as a "blocked" item
// buried in an otherwise-COMPLETED result, per the house rule that a
// policy rejection is a FAILED task with a clear reason.
//
// snippetType matches the SyncAPIItemResult.Type values already in use
// ("user", "group", "zabbix_settings", "zabbix_userparameter") so the
// message and the structured result line up; name is the element's
// identity (username, group name, Zabbix hostname, or userparameter key).
func dangerousSnippetRejectionMessage(snippetType, name string, fields []string) string {
	return fmt.Sprintf(
		"rejected by local policy reject_dangerous_snippets: %s in %s %q; %s",
		strings.Join(fields, ", "), snippetType, name, dangerousSnippetOptOut,
	)
}

// dangerousSnippetOptOut tells the device owner how to allow what
// reject_dangerous_snippets refuses: the plugin setting that renders it.
// ndagent.conf is generated by the plugin and rewritten on every Apply and
// plugin upgrade, so an edit there does not stick. The key stays in the text
// so the logs can still be searched for it.
const dangerousSnippetOptOut = `to allow it, turn on "Allow All Snippet Content" (reject_dangerous_snippets=false) in Services > NetDefense > Settings, Advanced Settings, Configuration Sync, and apply`

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

	// A web GUI restart a previous SYNC scheduled takes the local API down
	// for a few seconds; this SYNC starts once it answers again.
	webGUIRestart.wait(ctx)

	// Visibility only — never blocks the sync. Below the 26.1 series a VPN
	// teardown silently strands its auto firewall rules, and below 26.1.11
	// some privileges treated as ordinary can lead to administrator rights;
	// shipping a known silent failure with only documentation to protect
	// users is not acceptable. At most one log line per category per agent
	// process, and no API call at all once the release is known to be
	// supported.
	warnIfOPNsenseBelowFloor(ctx, apiClient)

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

	// Parse Zabbix entities from payload. Settings is a singleton (pointer,
	// nil means no ZABBIX_SETTINGS snippet present); the other two are
	// per-entity lists. Key-prefix ownership is enforced inside
	// executeSyncZabbix on the userparameter/alias paths.
	zabbixSettings, err := parseAPIZabbixSettings(cmd.Payload)
	if err != nil {
		result := NewFailureResult(fmt.Sprintf("Failed to parse zabbix_settings: %v", err))
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	zabbixUserParams, err := parseAPIZabbixUserParameters(cmd.Payload)
	if err != nil {
		result := NewFailureResult(fmt.Sprintf("Failed to parse zabbix_userparameters: %v", err))
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	zabbixAliases, err := parseAPIZabbixAliases(cmd.Payload)
	if err != nil {
		result := NewFailureResult(fmt.Sprintf("Failed to parse zabbix_aliases: %v", err))
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	softwarePayload, err := parseSoftwarePayload(cmd.Payload)
	if err != nil {
		result := NewFailureResult(fmt.Sprintf("Failed to parse software: %v", err))
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	// Parse AUTH_SERVER/AUTH_ORDER content.
	//
	// Deliberately NOT the abort-the-whole-SYNC pattern every parse call
	// above uses: a parse failure here never returns early. Strict parsing
	// makes the AUTH family a no-op for THIS pass (AUTH_CONTENT_UNSUPPORTED)
	// while every other family — firewall delivery included — still
	// applies. See executeSyncAuth and authParseOutcome in
	// sync_authserver.go.
	authParsed := parseAPIAuthContent(cmd.Payload)

	// Parse TRUST_CA/TRUST_CERT content. Like AUTH, content this agent cannot
	// read makes the trust family a no-op for this pass
	// (TRUST_CONTENT_UNSUPPORTED) and never stops the other families.
	trustParsed := parseAPITrustContent(cmd.Payload)

	// Validate UUIDs have correct prefix
	for _, alias := range aliases {
		if !strings.HasPrefix(alias.UUID, opnapi.NDAgentUUIDPrefix) {
			result := NewFailureResult(invalidUUIDMessage("alias", alias.SnippetName, alias.SnippetIndex, alias.Templates, alias.UUID))
			return SendTaskResponse(ws, cmd.TaskID, result)
		}
	}
	for _, rule := range rules {
		if !strings.HasPrefix(rule.UUID, opnapi.NDAgentUUIDPrefix) {
			result := NewFailureResult(invalidUUIDMessage("rule", rule.SnippetName, rule.SnippetIndex, rule.Templates, rule.UUID))
			return SendTaskResponse(ws, cmd.TaskID, result)
		}
	}
	for _, ho := range hostOverrides {
		if !strings.HasPrefix(ho.UUID, opnapi.NDAgentUUIDPrefix) {
			result := NewFailureResult(invalidUUIDMessage("host_override", ho.SnippetName, ho.SnippetIndex, ho.Templates, ho.UUID))
			return SendTaskResponse(ws, cmd.TaskID, result)
		}
	}
	for _, df := range domainForwards {
		if !strings.HasPrefix(df.UUID, opnapi.NDAgentUUIDPrefix) {
			result := NewFailureResult(invalidUUIDMessage("domain_forward", df.SnippetName, df.SnippetIndex, df.Templates, df.UUID))
			return SendTaskResponse(ws, cmd.TaskID, result)
		}
	}
	for _, ha := range hostAliases {
		if !strings.HasPrefix(ha.UUID, opnapi.NDAgentUUIDPrefix) {
			result := NewFailureResult(invalidUUIDMessage("host_alias", ha.SnippetName, ha.SnippetIndex, ha.Templates, ha.UUID))
			return SendTaskResponse(ws, cmd.TaskID, result)
		}
	}
	for _, acl := range unboundACLs {
		if !strings.HasPrefix(acl.UUID, opnapi.NDAgentUUIDPrefix) {
			result := NewFailureResult(invalidUUIDMessage("unbound_acl", acl.SnippetName, acl.SnippetIndex, acl.Templates, acl.UUID))
			return SendTaskResponse(ws, cmd.TaskID, result)
		}
	}

	zabbixSettingsCount := 0
	if zabbixSettings != nil {
		zabbixSettingsCount = 1
	}
	softwarePresentCount, softwareAbsentCount := 0, 0
	if softwarePayload != nil {
		softwarePresentCount = len(softwarePayload.Present)
		softwareAbsentCount = len(softwarePayload.Absent)
	}
	log.Infow("Executing SYNC_API",
		"trust_ca_count", len(trustParsed.CAs),
		"trust_cert_count", len(trustParsed.Certs),
		"alias_count", len(aliases),
		"rule_count", len(rules),
		"auth_server_count", len(authParsed.Servers),
		"auth_facility_count", len(authParsed.Facilities),
		"user_count", len(users),
		"group_count", len(groups),
		"host_override_count", len(hostOverrides),
		"domain_forward_count", len(domainForwards),
		"host_alias_count", len(hostAliases),
		"unbound_acl_count", len(unboundACLs),
		"vpn_network_count", len(vpnNetworks),
		"zabbix_settings_count", zabbixSettingsCount,
		"zabbix_userparameter_count", len(zabbixUserParams),
		"zabbix_alias_count", len(zabbixAliases),
		"software_present_count", softwarePresentCount,
		"software_absent_count", softwareAbsentCount,
	)

	// The trust family runs first: a service another family touches may use
	// a certificate it renews. CAs before certificates on add, certificates
	// before CAs on removal.
	trustOutcome := executeSyncTrust(ctx, apiClient, trustParsed, ws.RejectDangerousSnippets(), ws.GetConfigXMLPath())

	// Execute sync for VPN networks before aliases and rules.
	//
	// Rules may target OPNsense's `wireguard` interface group, and that
	// group only exists once the WireGuard plugin has an enabled instance
	// and has been reconfigured. Realizing the VPN first is what lets a
	// first-time setup converge in a single `sync apply` instead of
	// requiring a second pass after the interface appears.
	//
	// Same orphan-cleanup-always semantics as the other executors.
	// executeSyncVPN handles the "plugin not installed" case by returning
	// a no-op success when the WireGuard search endpoints 404.
	vpnResult := executeSyncVPN(ctx, apiClient, vpnNetworks)

	// Execute sync for aliases and rules
	syncResult := executeSyncAPI(ctx, apiClient, aliases, rules)

	// Splice the trust and VPN results in front so the reported item list
	// reads in execution order.
	syncResult.Results = append(append(append([]SyncAPIItemResult{}, trustOutcome.Result.Results...), vpnResult.Results...), syncResult.Results...)
	syncResult.Errors = append(append(append([]string{}, trustOutcome.Result.Errors...), vpnResult.Errors...), syncResult.Errors...)
	// ValidationErrors too: executeSyncVPN sets none today, but every other
	// executor merge carries all three fields and dropping one here is a trap
	// for whoever adds VPN validation errors later — they would vanish from
	// the task response with nothing to explain why.
	syncResult.ValidationErrors = append(append([]ValidationError{}, vpnResult.ValidationErrors...), syncResult.ValidationErrors...)
	if !vpnResult.Success || !trustOutcome.Result.Success {
		syncResult.Success = false
	}

	// Execute the AUTH_SERVER/AUTH_ORDER family — after aliases/rules, and
	// BEFORE users/groups. One pass, before any new
	// privileged local identity can appear, so a directory account cannot
	// win a race against the reserved-name exclusion that is supposed to
	// shadow it (see the stale-exclusion deferral, authDeferralInfo).
	authOutcome := executeSyncAuth(ctx, apiClient, ws.GetDeviceUUID(), cmd.TaskID, ws.RejectDangerousSnippets(), ws.GetConfigXMLPath(), authParsed, users, groups)
	syncResult.Results = append(syncResult.Results, authOutcome.Result.Results...)
	syncResult.Errors = append(syncResult.Errors, authOutcome.Result.Errors...)
	if !authOutcome.Result.Success {
		syncResult.Success = false
	}

	// Execute sync for users and groups. Runs every sync (no len-based
	// gate) so that managed-but-undesired identities are reliably swept
	// off the device -- same "empty desired list means delete everything
	// managed" semantics as the firewall ALIAS/RULE path, and the same
	// fix already applied to Unbound/VPN/Zabbix (see the len-based gates
	// removed below). Detaching the last USER/GROUP template and
	// re-syncing must still orphan-delete previously-applied managed
	// users/groups, not leave them stranded on the device.
	userGroupResult := executeSyncUsersGroups(ctx, apiClient, users, groups, ws.RejectDangerousSnippets(), authOutcome.Deferral)
	syncResult.Results = append(syncResult.Results, userGroupResult.Results...)
	syncResult.Errors = append(syncResult.Errors, userGroupResult.Errors...)
	if !userGroupResult.Success {
		syncResult.Success = false
	}

	// Execute sync for Unbound DNS entities.
	//
	// Runs every sync (no len-based gate) so that managed-but-undesired
	// entries are reliably swept off the device. Empty desired lists are
	// the signal to delete all NDAgent-owned entries — same semantic the
	// firewall ALIAS/RULE path has always had.
	unboundResult := executeSyncUnbound(ctx, apiClient, hostOverrides, domainForwards, hostAliases, unboundACLs)
	syncResult.Results = append(syncResult.Results, unboundResult.Results...)
	syncResult.Errors = append(syncResult.Errors, unboundResult.Errors...)
	if !unboundResult.Success {
		syncResult.Success = false
	}

	// Execute sync for Zabbix entities. Same orphan-cleanup-always
	// semantics, with graceful skip when os-zabbix-agent isn't installed.
	zabbixResult := executeSyncZabbix(ctx, apiClient, zabbixSettings, zabbixUserParams, zabbixAliases, ws.RejectDangerousSnippets())
	syncResult.Results = append(syncResult.Results, zabbixResult.Results...)
	syncResult.Errors = append(syncResult.Errors, zabbixResult.Errors...)
	if !zabbixResult.Success {
		syncResult.Success = false
	}

	// Execute software policy reconciliation. Unlike the other executors,
	// this one doesn't need the OPNsense apiClient — it shells out to
	// pkg(8) directly. nil softwarePayload (no SoftwarePolicy attached)
	// short-circuits to a no-op.
	if softwarePayload != nil {
		softwareResult := executeSyncSoftware(ctx, softwarePayload)
		syncResult.Results = append(syncResult.Results, softwareResult.Results...)
		syncResult.Errors = append(syncResult.Errors, softwareResult.Errors...)
		if !softwareResult.Success {
			syncResult.Success = false
		}
	}

	// Compose the user-facing summary from the combined results so every
	// snippet family reports in the same "+A ~M -D" shape and untouched
	// sections drop out entirely. Sub-executors' per-section messages
	// are still used by their own structured logs.
	syncResult.Message = buildSyncSummary(syncResult.Results, len(syncResult.Errors))

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

	result := TaskResult{
		Success: syncResult.Success,
		Message: syncResult.Message,
		Data:    data,
	}
	var afterResponse func()
	if trustOutcome.RestartWebGUI {
		afterResponse = func() {
			webGUIRestart.schedule(localAPIProbe(apiClient))
			webGUIRestart.wait(ctx)
		}
	}
	return sendSyncResult(ws, cmd.TaskID, result, afterResponse)
}

// sendSyncResult reports a SYNC, then runs what must wait for the report: the
// web GUI restart cuts the local API, and with it nothing of this SYNC may
// still be in flight. The restart runs whether or not the report went out: the
// certificate on the device has changed either way.
func sendSyncResult(ws *network.WebSocketClient, taskID string, result TaskResult, afterResponse func()) error {
	err := SendTaskResponse(ws, taskID, result)
	if afterResponse != nil {
		afterResponse()
	}
	return err
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

// checkRuleInterfaces pre-flights every desired rule's `interface` field
// against the interfaces and interface groups OPNsense actually offers.
//
// Without this, a rule naming an interface the device does not have fails
// deep inside OPNsense's model validation with `Option [wireguard] not in
// list.` — the option name, no rule identity, no list of what IS valid, and
// no hint that the cause is a VPN network that was never realized on this
// device. interfaces is the rule model's own option list (`GET
// /firewall/filter/getRule`), the one OPNsense validates against, so the
// check is exact rather than an approximation.
func checkRuleInterfaces(rules []APIRulePayload, interfaces []string) []ValidationError {
	log := logging.Named("SYNC_API")

	if len(rules) == 0 {
		return nil
	}

	if len(interfaces) == 0 {
		// An empty list means the template shape changed; treating it as
		// "nothing is valid" would block every rule on the device.
		log.Warn("Skipping rule interface pre-flight: OPNsense returned no interface options")
		return nil
	}

	available := make(map[string]bool, len(interfaces))
	for _, iface := range interfaces {
		available[iface] = true
	}

	sortedAvailable := append([]string(nil), interfaces...)
	sort.Strings(sortedAvailable)
	availableList := strings.Join(sortedAvailable, ", ")

	var validationErrors []ValidationError
	for _, rule := range rules {
		// An empty interface is a floating rule — valid, nothing to check.
		// OPNsense accepts a comma-separated list for multi-interface rules;
		// collect every missing name but report the rule ONCE, so
		// "wireguard, opt9" is one blocked rule naming both rather than two
		// blocked rows for a single rule.
		var missing []string
		for _, token := range strings.Split(rule.Interface, ",") {
			iface := strings.TrimSpace(token)
			if iface == "" || available[iface] {
				continue
			}
			missing = append(missing, iface)
		}
		if len(missing) == 0 {
			continue
		}

		quoted := make([]string, 0, len(missing))
		for _, m := range missing {
			quoted = append(quoted, fmt.Sprintf("%q", m))
		}
		subject := fmt.Sprintf("interface or interface group %s does not", quoted[0])
		if len(missing) > 1 {
			subject = fmt.Sprintf("interfaces or interface groups %s do not", strings.Join(quoted, ", "))
		}

		message := fmt.Sprintf(
			"Cannot apply rule %q: %s exist on this device (available: %s)",
			rule.Description, subject, availableList,
		)
		for _, m := range missing {
			if m == wireGuardInterfaceGroup {
				message += "; this device is not carrying an active WireGuard network, so OPNsense has not created the \"wireguard\" interface group — attach the VPN network to this device in NetDefense"
				break
			}
		}

		validationErrors = append(validationErrors, ValidationError{
			Type:       "rule",
			UUID:       rule.UUID,
			Name:       rule.Description,
			ErrorCode:  codeRuleInterfaceNotFound,
			Message:    message,
			References: missing,
		})
	}

	return validationErrors
}

// wireGuardInterfaceGroup is the interface group OPNsense's WireGuard plugin
// creates for its wgN interfaces. Referenced here only to sharpen the
// pre-flight error message — the check itself is interface-agnostic.
const wireGuardInterfaceGroup = "wireguard"

// checkAliasNameCollision reports why applying this alias would collide with
// an object already on the device, or "" when it would not.
//
// OPNsense enforces a unique NAME on aliases, but NDAgent matches its managed
// objects by UUID. Those two facts disagree whenever a device already carries
// an alias with the same name under a different UUID, and OPNsense's answer
// is the bare validation string "An alias with this name already exists." —
// which names neither the alias nor anything to do about it.
//
// Community #10 hit this by following the documented authoring workflow:
// `snippet pull` extracts an existing device object as an example to base new
// configuration on. It does NOT adopt that object — pulling mints a new
// managed identity — so syncing the resulting snippet back to the SAME device
// means applying a snippet next to the unmanaged object it was copied from,
// and the names collide. Two objects is the correct outcome for types without
// a unique-name constraint; for aliases it is impossible, so the sync fails.
//
// Deliberately scoped to aliases:
//   - RULES are explicitly out (Community #10, maintainer correction on the
//     thread): rules have no device-side uniqueness constraint, so the same
//     flow correctly produces two rules rather than an error. Do not "fix"
//     that by adding a collision check here.
//   - USERS and GROUPS have unique names but are MATCHED by name
//     (`executeSyncUsersGroups` builds `userUUIDLookup`/`groupUUIDLookup`
//     keyed on name), so the UUID-vs-name mismatch that causes this cannot
//     arise for them — a same-named user is simply updated in place.
//   - Unbound and Zabbix entities are matched by UUID or key with no
//     equivalent unique-name constraint established, so adding speculative
//     checks there would be guessing at a constraint rather than reflecting
//     a known one.
//
// Fails OPEN: if the lookup itself errors we return "" and let the sync
// proceed to SetAlias, which will either succeed or produce OPNsense's own
// error. This check improves a message; losing it must never block a sync
// that would otherwise work.
func checkAliasNameCollision(ctx context.Context, client *opnapi.Client, alias APIAliasPayload) string {
	log := logging.Named("SYNC_API")

	existing, err := client.GetAliasByName(ctx, alias.Name)
	if err != nil {
		log.Warnw("Skipping alias name collision pre-flight: lookup failed",
			"name", alias.Name,
			"error", err,
		)
		return ""
	}
	if existing == nil {
		return ""
	}

	existingUUID, _ := existing["uuid"].(string)
	if existingUUID == alias.UUID {
		// The same object: this is an ordinary update, not a collision.
		return ""
	}

	if strings.HasPrefix(existingUUID, opnapi.NDAgentUUIDPrefix) {
		return fmt.Sprintf(
			"alias %q is already managed by another snippet on this device; rename one of the snippets so the two aliases do not share a name",
			alias.Name,
		)
	}

	return fmt.Sprintf(
		"an unmanaged alias named %q already exists on this device; delete it on the device or rename the snippet. "+
			"If this snippet came from `snippet pull` against this same device, the pulled object is that unmanaged alias — pull copies an object as a starting point, it does not adopt it",
		alias.Name,
	)
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
		msg := fmt.Sprintf("Failed to list aliases: %v", err)
		return SyncAPIResult{
			Success: false,
			Message: msg,
			Results: []SyncAPIItemResult{{
				Type:   "alias_discovery",
				Name:   "list_aliases",
				Action: "discover",
				Status: "error",
				Error:  msg,
			}},
			Errors: []string{msg},
		}
	}
	currentAliases := opnapi.FilterManagedAliases(allAliases)

	allRules, err := client.ListAllRules(ctx)
	if err != nil {
		msg := fmt.Sprintf("Failed to list rules: %v", err)
		return SyncAPIResult{
			Success: false,
			Message: msg,
			Results: []SyncAPIItemResult{{
				Type:   "rule_discovery",
				Name:   "list_rules",
				Action: "discover",
				Status: "error",
				Error:  msg,
			}},
			Errors: []string{msg},
		}
	}
	currentRules := opnapi.FilterManagedRules(allRules)

	log.Infow("Discovered managed objects",
		"total_aliases", len(allAliases),
		"managed_aliases", len(currentAliases),
		"total_rules", len(allRules),
		"managed_rules", len(currentRules),
	)

	// Build maps of current UUIDs
	currentAliasUUIDs := make(map[string]bool)
	currentAliasRows := make(map[string]map[string]interface{})
	for _, a := range currentAliases {
		if uuid, ok := a["uuid"].(string); ok {
			currentAliasUUIDs[uuid] = true
			currentAliasRows[uuid] = a
		}
	}

	currentRuleUUIDs := make(map[string]bool)
	currentRuleRows := make(map[string]map[string]interface{})
	for _, r := range currentRules {
		if uuid, ok := r["uuid"].(string); ok {
			currentRuleUUIDs[uuid] = true
			currentRuleRows[uuid] = r
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
		// Surface each validation error in the task's errors list too, so
		// the task summary carries a count and the reason is readable
		// without digging into the structured validation_errors payload.
		validationMessages := make([]string, 0, len(validationErrors))
		for _, ve := range validationErrors {
			validationMessages = append(validationMessages, ve.Message)
		}
		return SyncAPIResult{
			Success:          false,
			Message:          "Sync blocked: cannot delete aliases that are in use",
			Errors:           validationMessages,
			ValidationErrors: validationErrors,
		}
	}

	// Phase 2: Create/Update aliases (before rules, as rules may depend on aliases).
	// Like a rule, an alias may set any field of the device's alias model,
	// and is refused alone when its content does not fit the model (see the
	// rule pre-flight below for why a refusal never fails fast). An alias the
	// device already holds exactly as desired is not written.
	release := deviceRelease(ctx, client)
	if len(aliases) > 0 {
		writable := aliases
		aliasModel, err := client.GetAliasModel(ctx)
		if err != nil {
			msg := fmt.Sprintf("Cannot write aliases: failed to read this device's alias model: %v", err)
			log.Warnw("SYNC_API: alias model unavailable; no alias is written this pass", "error", err)
			results = append(results, SyncAPIItemResult{
				Type:   "alias_discovery",
				Name:   "alias_model",
				Action: "discover",
				Status: "error",
				Error:  msg,
				Code:   codeAliasModelUnavailable,
			})
			errors = append(errors, msg)
			writable = nil
		}

		for _, alias := range writable {
			action := "created"
			if currentAliasUUIDs[alias.UUID] {
				action = "updated"
			}

			body, refusal := buildAliasBody(alias, aliasModel, release)
			if refusal != nil {
				log.Warnw("SYNC_API: alias refused before it was written",
					"uuid", alias.UUID,
					"name", alias.Name,
					"code", refusal.Code,
					"message", refusal.Message,
				)
				results = append(results, SyncAPIItemResult{
					Type:   "alias",
					UUID:   alias.UUID,
					Name:   alias.Name,
					Action: "blocked",
					Status: "blocked",
					Error:  refusal.Message,
					Code:   refusal.Code,
				})
				errors = append(errors, refusal.Message)
				continue
			}

			// Pre-flight the device-side unique-name constraint, so a collision
			// reports what is wrong and what to do rather than OPNsense's raw
			// "An alias with this name already exists."
			if collision := checkAliasNameCollision(ctx, client, alias); collision != "" {
				log.Warnw("SYNC_API: alias name collides with an existing object on this device",
					"uuid", alias.UUID,
					"name", alias.Name,
					"message", collision,
				)
				results = append(results, SyncAPIItemResult{
					Type:   "alias",
					UUID:   alias.UUID,
					Name:   alias.Name,
					Action: "blocked",
					Status: "blocked",
					Error:  collision,
				})
				errors = append(errors, collision)
				continue
			}

			if row, exists := currentAliasRows[alias.UUID]; exists && aliasContract.rowMatches(body, row) {
				results = append(results, SyncAPIItemResult{
					Type:   "alias",
					UUID:   alias.UUID,
					Name:   alias.Name,
					Action: "unchanged",
					Status: "success",
				})
				continue
			}

			err := client.SetAlias(ctx, alias.UUID, body)

			itemResult := SyncAPIItemResult{
				Type:   "alias",
				UUID:   alias.UUID,
				Name:   alias.Name,
				Action: action,
			}

			refused, isRefusal := validationFailure(err)
			switch {
			case err == nil:
				itemResult.Status = "success"
			case isRefusal:
				msg := fmt.Sprintf("%s: %s", aliasLabel(alias), strings.Join(refused.Messages(), "; "))
				itemResult.Status = "error"
				itemResult.Error = msg
				itemResult.Code = codeAliasRejectedByDevice
				errors = append(errors, msg)
			default:
				msg := fmt.Sprintf("%s: %v", aliasLabel(alias), err)
				itemResult.Status = "error"
				itemResult.Error = msg
				errors = append(errors, msg)
			}

			results = append(results, itemResult)
		}
	}

	// Phase 2.5: Pre-flight every desired rule against the device's own rule
	// model, so a rule OPNsense would refuse, or would silently store wrong,
	// is reported by name instead: a key the model does not define, a value
	// of the wrong kind, an option the device does not offer, an interface
	// (group) that does not exist. The model is read after the aliases are
	// written because it offers them as overload tables.
	//
	// This deliberately does NOT fail fast, unlike the orphan-alias check
	// above. The two teardown outcomes have to happen in the SAME sync:
	//
	//   - An auto-generated VPN rule (`[nd-vpn:<network>]`, emitted by
	//     NDManager's vpn_firewall_renderer only while the device holds an
	//     enabled membership) drops out of the desired set when the network
	//     goes away. It is an NDAgent-managed object and must be DELETED by
	//     the orphan sweep in Phase 4 — no dangling rule.
	//   - A user-authored template rule still pointing at the interface
	//     that just disappeared must FAIL LOUDLY, naming the rule and the
	//     missing interface.
	//
	// A fail-fast return can only do the second: it would abort before
	// Phase 4 and strand exactly the auto rules that were supposed to be
	// swept. So an offending rule is instead dropped from the create/update
	// pass, recorded as a blocked item, and appended to `errors` (which is
	// what `success := len(errors) == 0` keys off) — the same shape the
	// dangerous-snippet gate uses. Everything else in the sync, orphan
	// deletion included, still runs.
	//
	// Offending rules stay OUT of the create/update pass but stay IN the
	// desired set, so they are not orphan-deleted. Same principle as the
	// dangerous-snippet gate: the check refuses to write a rule it knows
	// is wrong; it does not delete pre-existing device state. A rule whose
	// interface group vanished underneath it is left exactly as it is on the
	// device for the operator to fix.
	ruleBodies := make(map[string]map[string]string, len(rules))
	var applyRules []APIRulePayload
	var ruleModel opnapi.EntityModel
	if len(rules) > 0 {
		model, err := client.GetRuleModel(ctx)
		ruleModel = model
		if err != nil {
			// Without the model no body can be built or checked, so no rule
			// is written this pass; the sweep below still runs.
			msg := fmt.Sprintf("Cannot write rules: failed to read this device's rule model: %v", err)
			log.Warnw("SYNC_API: rule model unavailable; no rule is written this pass", "error", err)
			results = append(results, SyncAPIItemResult{
				Type:   "rule_discovery",
				Name:   "rule_model",
				Action: "discover",
				Status: "error",
				Error:  msg,
				Code:   codeRuleModelUnavailable,
			})
			errors = append(errors, msg)
		} else {
			var interfaceOptions []string
			if field, ok := model.Field("interface"); ok {
				interfaceOptions = field.OptionKeys()
			}
			interfaceErrors := map[string]ValidationError{}
			for _, ve := range checkRuleInterfaces(rules, interfaceOptions) {
				interfaceErrors[ve.UUID] = ve
			}

			for _, rule := range rules {
				body, refusal := buildRuleBody(rule, model, release)
				if refusal == nil {
					if ve, blocked := interfaceErrors[rule.UUID]; blocked {
						refusal = &contentRefusal{Code: codeRuleInterfaceNotFound, Message: ve.Message}
						validationErrors = append(validationErrors, ve)
					}
				}
				if refusal != nil {
					log.Warnw("SYNC_API: rule refused before it was written",
						"uuid", rule.UUID,
						"rule", rule.Description,
						"code", refusal.Code,
						"message", refusal.Message,
					)
					results = append(results, SyncAPIItemResult{
						Type:   "rule",
						UUID:   rule.UUID,
						Name:   rule.Description,
						Action: "blocked",
						Status: "blocked",
						Error:  refusal.Message,
						Code:   refusal.Code,
					})
					errors = append(errors, refusal.Message)
					continue
				}
				ruleBodies[rule.UUID] = body
				applyRules = append(applyRules, rule)
			}
		}
	}

	// Phase 3: Place and write the rules (ruleSync): PREPEND rules before the
	// local rules of their section and APPEND rules after them, raising local
	// rules' sequences when the PREPEND rules do not fit below them. applyRules
	// is `rules` minus anything the pre-flight refused. A rule the device
	// already holds exactly as desired is not written: every setRule is a
	// config save and a new /conf/backup revision.
	// A rule the pre-flight refused keeps its sequence: placement holds it
	// where it is and places the others around it.
	held := map[string]bool{}
	for _, rule := range rules {
		if _, applied := ruleBodies[rule.UUID]; !applied {
			held[rule.UUID] = true
		}
	}
	placement := newRuleSync(client, applyRules, ruleBodies, currentRuleUUIDs, held, ruleModel)
	placement.run(ctx, allRules)
	results = append(results, placement.results...)
	errors = append(errors, placement.errors...)

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

	// Phase 6: Apply changes. Every errors entry must have a matching
	// results item, or a FAILED task's own results array shows nothing
	// wrong.
	if err := client.ReconfigureAliases(ctx); err != nil {
		msg := fmt.Sprintf("Alias reconfigure: %v", err)
		errors = append(errors, msg)
		results = append(results, SyncAPIItemResult{
			Type:   "alias_apply",
			Name:   "reconfigure",
			Action: "apply",
			Status: "error",
			Error:  msg,
		})
	}

	if withheld := placement.withheld; len(withheld) > 0 {
		// A renumber may have re-created a local rule as a pass rule on every
		// interface: nothing is applied while it may be there.
		names := make([]string, len(withheld))
		reasons := make([]string, len(withheld))
		for i, w := range withheld {
			names[i], reasons[i] = w.name, w.why
		}
		msg := fmt.Sprintf("Firewall rules were not applied this SYNC. %s Check the device, then SYNC again", strings.Join(reasons, " "))
		log.Errorw("SYNC_API: firewall rules not applied", "local_rules", names)
		errors = append(errors, msg)
		results = append(results, SyncAPIItemResult{
			Type:   "rule_apply",
			Name:   "apply",
			Action: "skipped",
			Status: "error",
			Error:  msg,
			Code:   codeRuleApplyWithheld,
		})
	} else if err := client.ApplyRules(ctx); err != nil {
		msg := fmt.Sprintf("Rule apply: %v", err)
		errors = append(errors, msg)
		results = append(results, SyncAPIItemResult{
			Type:   "rule_apply",
			Name:   "apply",
			Action: "apply",
			Status: "error",
			Error:  msg,
		})
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
		// Carries any INTERFACE_NOT_FOUND entries from the Phase 2.5
		// pre-flight — the sync continued past them (so orphan sweeps ran),
		// but the structured detail still reaches the task response.
		ValidationErrors: validationErrors,
	}
}

// snippetLabel identifies a snippet in an error message by NAME, falling
// back to its position in the payload.
//
// Every parse and apply error used to say only "alias snippet at index 1",
// which a user cannot act on: the index is a position within the payload
// NDManager assembled, not anything visible in `ndcli snippet list`, and it
// shifts as templates change. Community #11 reported exactly this — a sync
// failing with "alias snippet at index 1: missing required field: uuid" and
// no way to tell which of their snippets was at fault.
//
// The name was already on the wire and simply never read: NDManager's
// payload builder sends `snippet_name` for every snippet
// (services/sync_service.py, "snippet_name": snippet['name']), including the
// synthetic VPN auto-firewall ones, which go through the same builder.
//
// The index is kept alongside the name rather than replaced by it, because
// two snippets can share a name across templates and the index is what
// disambiguates them. An absent or empty `snippet_name` falls back to the
// old form, so a device talking to an older control plane degrades to what
// it printed before rather than to an empty pair of quotes.
func snippetLabel(kind string, snippet map[string]interface{}, idx int) string {
	name, _ := snippet["snippet_name"].(string)
	return snippetLabelFrom(kind, name, idx)
}

// snippetLabelFrom is snippetLabel for callers that already carry the name
// and index as values rather than the raw snippet map — the UUID-prefix
// guards, which run after parsing and see only the parsed payloads.
func snippetLabelFrom(kind, snippetName string, idx int) string {
	if snippetName != "" {
		return fmt.Sprintf("%s snippet %q (index %d)", kind, snippetName, idx)
	}
	return fmt.Sprintf("%s snippet at index %d", kind, idx)
}

// invalidUUIDMessage explains a snippet whose content carries a UUID outside
// NDAgent's managed prefix, naming the snippet and the template that carried
// it rather than only the offending UUID.
//
// The old message was "Invalid rule UUID aaaaaaaa-...: must start with
// 221f3268" — no snippet, no index, no template, and it aborts the entire
// sync, so the user got an empty results list and one hex string to work
// from. Lab E2E on the snippet-naming pass found this family had been missed.
//
// The abort is deliberate and preserved: a foreign UUID means the agent
// cannot tell whether it owns the object, and guessing risks adopting or
// overwriting configuration that is not NetDefense's. The control plane will
// reject foreign UUIDs at create time, after which this path only serves
// legacy content — which is exactly when a message that names the snippet
// and the template matters, because the author may be long gone.
func invalidUUIDMessage(kind, snippetName string, idx int, templates []string, uuid string) string {
	msg := fmt.Sprintf("%s: invalid UUID %q — NetDefense-managed objects must use a UUID starting with %s",
		snippetLabelFrom(kind, snippetName, idx), uuid, opnapi.NDAgentUUIDPrefix)

	switch len(templates) {
	case 0:
	case 1:
		msg += fmt.Sprintf("; carried by template %q", templates[0])
	default:
		quoted := make([]string, 0, len(templates))
		for _, t := range templates {
			quoted = append(quoted, fmt.Sprintf("%q", t))
		}
		msg += fmt.Sprintf("; carried by templates %s", strings.Join(quoted, ", "))
	}

	return msg
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
			return nil, fmt.Errorf("%s: missing content", snippetLabel("alias", snippetMap, idx))
		}

		alias, err := parseAliasContent(snippetContent, templates)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", snippetLabel("alias", snippetMap, idx), err)
		}

		// Provenance for error messages; see invalidUUIDMessage.
		alias.SnippetName, _ = snippetMap["snippet_name"].(string)
		alias.SnippetIndex = idx
		aliases = append(aliases, alias)
	}

	return aliases, nil
}

// parseAliasContent parses the JSON content of an alias snippet. The uuid, the
// name and the type are required here; every other key is checked against the
// device's alias model at SYNC time (buildAliasBody), so a key the device does
// not define refuses this alias alone rather than the whole payload.
func parseAliasContent(jsonContent string, templates []string) (APIAliasPayload, error) {
	var contentMap map[string]interface{}
	if err := json.Unmarshal([]byte(jsonContent), &contentMap); err != nil {
		return APIAliasPayload{}, fmt.Errorf("failed to parse alias JSON: %v", err)
	}
	if contentMap == nil {
		return APIAliasPayload{}, fmt.Errorf("alias content must be a JSON object")
	}

	alias := APIAliasPayload{
		Content:   contentMap,
		Templates: templates,
	}

	// Required fields
	alias.UUID, _ = contentMap["uuid"].(string)
	if alias.UUID == "" {
		return APIAliasPayload{}, fmt.Errorf("missing required field: uuid")
	}

	alias.Name = contentText(contentMap, "name")
	if alias.Name == "" {
		return APIAliasPayload{}, fmt.Errorf("missing required field: name")
	}

	alias.Type = contentText(contentMap, "type")
	if alias.Type == "" {
		return APIAliasPayload{}, fmt.Errorf("missing required field: type")
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
				return nil, fmt.Errorf("%s: invalid position %q (must be PREPEND or APPEND)", snippetLabel("rule", snippetMap, idx), pos)
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
			return nil, fmt.Errorf("%s: missing content", snippetLabel("rule", snippetMap, idx))
		}

		rule, err := parseRuleContent(snippetContent, templates)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", snippetLabel("rule", snippetMap, idx), err)
		}

		// Set position and priority from snippet metadata
		rule.Position = position
		rule.Priority = priority

		// Provenance for error messages; see invalidUUIDMessage.
		rule.SnippetName, _ = snippetMap["snippet_name"].(string)
		rule.SnippetIndex = idx
		rules = append(rules, rule)
	}

	return rules, nil
}

// parseRuleContent parses the JSON content of a rule snippet.
// Note: Position and Priority are NOT parsed here - they come from snippet metadata.
// A sequence in content is ignored: placement sets it.
//
// Only the uuid is required here. Every other key is checked against the
// device's rule model at SYNC time (buildRuleBody), so a key the device does
// not define refuses this rule alone rather than the whole payload.
func parseRuleContent(jsonContent string, templates []string) (APIRulePayload, error) {
	var contentMap map[string]interface{}
	if err := json.Unmarshal([]byte(jsonContent), &contentMap); err != nil {
		return APIRulePayload{}, fmt.Errorf("failed to parse rule JSON: %v", err)
	}
	if contentMap == nil {
		return APIRulePayload{}, fmt.Errorf("rule content must be a JSON object")
	}

	rule := APIRulePayload{
		Content:   contentMap,
		Templates: templates,
	}

	// Required fields
	rule.UUID, _ = contentMap["uuid"].(string)
	if rule.UUID == "" {
		return APIRulePayload{}, fmt.Errorf("missing required field: uuid")
	}

	rule.Description = contentText(contentMap, "description")
	rule.Interface = contentText(contentMap, "interface")
	rule.SourceNet = contentText(contentMap, "source_net")
	rule.DestinationNet = contentText(contentMap, "destination_net")

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
			return nil, fmt.Errorf("%s: missing content", snippetLabel("user", snippetMap, idx))
		}

		user, err := parseUserContent(snippetContent, templates)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", snippetLabel("user", snippetMap, idx), err)
		}
		user.SuperuserCleared = snippetSuperuserCleared(snippetMap)
		user.SnippetName, _ = snippetMap["snippet_name"].(string)
		user.SnippetIndex = idx

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
			return nil, fmt.Errorf("%s: missing content", snippetLabel("group", snippetMap, idx))
		}

		group, err := parseGroupContent(snippetContent, templates)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", snippetLabel("group", snippetMap, idx), err)
		}
		group.SuperuserCleared = snippetSuperuserCleared(snippetMap)
		group.SnippetName, _ = snippetMap["snippet_name"].(string)
		group.SnippetIndex = idx

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
	group.ExternalMembers = parseBoolField(contentMap["external_members"])

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

// updateExternalGroup updates an external_members:true GROUP's own
// existence/priv/source_networks (member is never sent for it otherwise —
// see ConvertAPIToGroup), first self-healing an empty-token or stale-uid
// artifact in the group's stored `member` CSV, if one is present.
//
// The artifact: OPNsense's own Auth\Base::setGroupMembership (login-time
// memberOf sync) edits `<member>` directly via SimpleXMLElement, bypassing
// the MVC Group model entirely. Any group whose stored `<member>` is
// present but empty — a freshly created group's own `<member></member>`
// is exactly this shape, so the FIRST directory login into a brand-new
// external group hits it too, not only a revoke-then-restore cycle — gets
// a leading comma on its next link (see opnapi.SanitizeMemberCSV's doc
// comment for the PHP mechanics). Separately, deleting a user never
// scrubs other groups' stored member CSV, so a stale uid can be left
// behind the same way (opnapi.SanitizeMemberCSVAgainstUsers). Either
// artifact permanently fails OPNsense's own MemberField validation on
// EVERY subsequent auth/group/set call for the group — setBase validates
// the whole loaded model, not just the posted fields — so a plain
// client.SetGroup call would otherwise fail forever once the device
// reaches that state (every family but GROUP still applies; the group
// object itself is never corrupted, only permanently un-updatable).
//
// The repair never sends a member NDAgent invented: it is always a fresh
// read of what OPNsense currently has stored for this exact group,
// sanitized to drop only the empty/stale tokens. It is NOT fully
// race-safe against a login landing between that read and this repair's
// write — see opnapi.RepairGroupMember's doc comment for the accepted,
// bounded residual risk.
func updateExternalGroup(ctx context.Context, client *opnapi.Client, log *zap.SugaredLogger, uuid, name string, opnGroup opnapi.Group, validUIDs map[string]bool) error {
	rawMember, found, err := client.GetGroupRawMemberByName(ctx, name)
	if err != nil || !found {
		// Fail open: an unreadable or (racily) missing group falls through
		// to the plain update, exactly today's behavior and no worse — this
		// repair is a bonus recovery path, never a precondition for an
		// otherwise-healthy update.
		return client.SetGroup(ctx, uuid, opnGroup)
	}

	sanitized, changed := opnapi.SanitizeMemberCSVAgainstUsers(rawMember, validUIDs)
	if !changed {
		return client.SetGroup(ctx, uuid, opnGroup)
	}

	log.Warnw("SYNC_API: external GROUP's stored member CSV carried an empty-token or stale-uid artifact; repairing without adding or removing a real, current member",
		"group", name, "raw_member", rawMember, "sanitized_member", sanitized)
	return client.RepairGroupMember(ctx, uuid, opnGroup, sanitized)
}

// executeSyncUsersGroups performs sync for users and groups.
// Groups are synced first (users may reference groups).
//
// Every element first passes the accountGate (sync_account_gate.go): an
// element that would give an account administrator rights, or take one over,
// without the control plane's Superuser clearance is refused whatever the
// device-local config says, and rejectDangerous (config: reject_dangerous_
// snippets, default true) is the owner's own opt-in policy on top of it. A
// refused element is dropped from the create/update pass and recorded as a
// "rejected" result, but left OUT of the orphan-delete decision below — the
// gate refuses new mutations, it does not delete pre-existing device state
// that happens to match the same criteria.
//
// auth carries the AUTH_SERVER/AUTH_ORDER family's stale-exclusion deferral
// state (see sync_authserver.go). The
// zero value, authDeferralInfo{}, defers nothing and is exactly today's
// behavior, so every call site that has nothing to do with AUTH passes it
// unchanged.
func executeSyncUsersGroups(ctx context.Context, client *opnapi.Client, users []opnapi.APIUserPayload, groups []opnapi.APIGroupPayload, rejectDangerous bool, auth authDeferralInfo) SyncAPIResult {
	return executeSyncUsersGroupsWithPolicy(ctx, client, users, groups, rejectDangerous, auth, adminPrivPolicy(ctx, client))
}

func executeSyncUsersGroupsWithPolicy(ctx context.Context, client *opnapi.Client, users []opnapi.APIUserPayload, groups []opnapi.APIGroupPayload, rejectDangerous bool, auth authDeferralInfo, policy opnapi.PrivPolicy) SyncAPIResult {
	log := logging.Named("SYNC_API")

	var results []SyncAPIItemResult
	var errors []string

	gate := newAccountGate(policy, rejectDangerous, log)
	gate.noteCleared(users, groups)
	record := func(kind, name string, r refusal) {
		results = append(results, SyncAPIItemResult{
			Type:   kind,
			Name:   name,
			Action: "rejected",
			Status: "blocked",
			Code:   r.code,
			Error:  r.message,
		})
		errors = append(errors, r.message)
	}

	// applyUsers/applyGroups (the accepted subset) drive the create/update
	// phases below; the full, unfiltered users/groups slices still drive the
	// desired-name sets used for orphan deletion further down, so a refused
	// element is neither applied nor deleted — it's simply left alone.
	//
	// First pass: what needs no live rows. It runs before discovery so a
	// discovery failure, which returns early, still reports these refusals.
	applyUsers := gate.filterUsers(users, record)
	applyGroups := gate.filterGroups(groups, record)

	// Phase 1: Get all users and groups for lookups.
	//
	// A discovery failure here fails fast: this is a whole-pass
	// precondition (the orphan sweep can't run safely without knowing
	// what already exists), not a per-element validation, so failing
	// fast here is the correct exception rather than a violation of the
	// "never fail fast" rule the per-element checks below follow. It
	// must still preserve any refusals already recorded above.
	allUsers, err := client.ListAllUsers(ctx)
	if err != nil {
		msg := fmt.Sprintf("Failed to list users: %v", err)
		return SyncAPIResult{
			Success: false,
			Message: msg,
			Results: append(results, SyncAPIItemResult{
				Type:   "user_discovery",
				Name:   "list_users",
				Action: "discover",
				Status: "error",
				Error:  msg,
			}),
			Errors: append(errors, msg),
		}
	}

	allGroups, err := client.ListAllGroups(ctx)
	if err != nil {
		msg := fmt.Sprintf("Failed to list groups: %v", err)
		return SyncAPIResult{
			Success: false,
			Message: msg,
			Results: append(results, SyncAPIItemResult{
				Type:   "group_discovery",
				Name:   "list_groups",
				Action: "discover",
				Status: "error",
				Error:  msg,
			}),
			Errors: append(errors, msg),
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

	// Second pass: what the live rows decide. A GROUP is judged first, and the
	// groups that will be administrator-equivalent once applied are recorded, so
	// a USER of this sync that names one is judged against what it is about to be.
	// The device's own privilege catalog, read once for this sync: what a live
	// group holds that the device does not define grants nothing there.
	devicePrivs := livePrivCatalog(ctx, client)
	gate.useLiveRows(allUsers, allGroups, devicePrivs)
	applyGroups = gate.filterGroups(applyGroups, record)
	gate.planGroups(applyGroups)
	applyUsers = gate.filterUsers(applyUsers, record)

	// Build lookup maps
	userUUIDLookup := opnapi.BuildUserUUIDLookup(allUsers)
	groupUUIDLookup := opnapi.BuildGroupUUIDLookup(allGroups)
	gidLookup := opnapi.BuildGIDLookup(allGroups)
	uidLookup := opnapi.BuildUIDLookup(allUsers)

	// validUIDs is every uid the device currently knows about, used only
	// to detect a stale uid left behind in a GROUP's stored member CSV by
	// a since-deleted user (see updateExternalGroup).
	validUIDs := make(map[string]bool, len(uidLookup))
	for _, uid := range uidLookup {
		validUIDs[uid] = true
	}

	// liveGroupMembers is the BEFORE-this-sync member-name set per group,
	// captured once here rather than re-derived after each phase. The
	// stale-exclusion deferral is about NEW names only (a member added THIS pass) — a name
	// that was already a member before this sync started is never deferred,
	// whatever the exclusion coverage says.
	liveGroupMembers := make(map[string]map[string]bool, len(allGroups))
	for _, rawGroup := range allGroups {
		name, _ := rawGroup["name"].(string)
		if name == "" {
			continue
		}
		api := opnapi.ConvertGroupToAPI(rawGroup, allUsers)
		set := make(map[string]bool, len(api.Members))
		for _, m := range api.Members {
			set[m] = true
		}
		liveGroupMembers[name] = set
	}

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
	for _, groupPayload := range applyGroups {
		existingUUID, exists := groupUUIDLookup[groupPayload.Name]

		action := "created"
		var syncErr error

		// Drop any NEW member (not already live before this sync)
		// whose name is currently stale-excluded, before this group's
		// member list ever reaches ConvertAPIToGroup. External groups never
		// go through this at all — their Members must be empty already,
		// and ConvertAPIToGroup never builds `member` for them regardless.
		convertPayload := groupPayload
		var deferredMembers []string
		if !groupPayload.ExternalMembers {
			convertPayload.Members, deferredMembers = filterDeferredGroupMembers(groupPayload, liveGroupMembers[groupPayload.Name], auth)
		}

		// Convert to OPNsense format (without member UIDs for now)
		opnGroup := opnapi.ConvertAPIToGroup(convertPayload, groupPayload.Templates, uidLookup)

		if exists {
			action = "updated"
			if groupPayload.ExternalMembers {
				syncErr = updateExternalGroup(ctx, client, log, existingUUID, groupPayload.Name, opnGroup, validUIDs)
			} else {
				syncErr = client.SetGroup(ctx, existingUUID, opnGroup)
			}
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
		for _, name := range deferredMembers {
			log.Warnw("SYNC_API: deferred a new GROUP member pending AUTH exclusion coverage",
				"group", groupPayload.Name, "member", name)
			msg := authDeferredMessage("group member", name)
			results = append(results, SyncAPIItemResult{
				Type:   "group_member",
				Name:   groupPayload.Name + "/" + name,
				Action: "deferred",
				Status: "blocked",
				Code:   authCodeUserDeferredExclusionStale,
				Error:  msg,
			})
			// A policy-driven withholding fails the TASK with an
			// actionable reason — never a silent COMPLETED with the
			// withholding buried in the per-item results, which is
			// exactly what leaving `errors` untouched here would be
			// (`success := len(errors) == 0` further down keys off it).
			// The member stays out of THIS pass's create/update (above),
			// but is untouched by the orphan-delete pass — same shape as
			// every other reject-gate in this file.
			errors = append(errors, msg)
		}
	}

	// Refresh GID lookup after group changes
	allGroups, _ = client.ListAllGroups(ctx)
	gidLookup = opnapi.BuildGIDLookup(allGroups)
	groupUUIDLookup = opnapi.BuildGroupUUIDLookup(allGroups)

	// Phase 3: Create/Update users (after groups exist)
	for _, userPayload := range applyUsers {
		existingUUID, exists := userUUIDLookup[userPayload.Name]

		// A brand-new privileged/managed identity whose name the
		// AUTH pass could not (yet) exclude from every managed directory
		// server waits for a later sync — make-before-break. An EXISTING
		// user being merely updated is unaffected: it was already there
		// before this pass, so there is nothing new to shadow.
		if !exists && auth.isDeferred(userPayload.Name) {
			log.Warnw("SYNC_API: deferred a new USER pending AUTH exclusion coverage", "name", userPayload.Name)
			msg := authDeferredMessage("user", userPayload.Name)
			results = append(results, SyncAPIItemResult{
				Type:   "user",
				Name:   userPayload.Name,
				Action: "deferred",
				Status: "blocked",
				Code:   authCodeUserDeferredExclusionStale,
				Error:  msg,
			})
			// See the matching group-member comment above: a deferral is
			// a policy-driven withholding and must fail the task, not
			// report a silent COMPLETED with the withholding buried in
			// the item list.
			errors = append(errors, msg)
			continue
		}

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

	// Phase 4: Update groups with member UIDs (now that users exist). Uses
	// applyGroups, not groups — a rejected group's full priv/description
	// must not get re-pushed here under cover of "just updating members".
	for _, groupPayload := range applyGroups {
		if groupPayload.ExternalMembers || len(groupPayload.Members) == 0 {
			// External groups never send `member`; nothing else to update.
			// Known residual: a member-managed group with zero resolvable
			// Members (e.g. an unscoped hand-made AUTH_SERVER's memberOf
			// sync clearing it) hits this same branch and skips the update
			// too, so it can carry the identical empty-token/stale-uid
			// artifact updateExternalGroup repairs, unrepaired. Out of
			// scope here; not a regression from this fix.
			continue
		}

		existingUUID, exists := groupUUIDLookup[groupPayload.Name]
		if !exists {
			continue // Group creation failed, skip
		}

		// Same stale-exclusion deferral filter as Phase 2, against the same pre-sync
		// liveGroupMembers baseline — deterministic, so a name Phase 2
		// already withheld (and reported) is withheld again here without
		// a second "deferred" result. This is the phase that would
		// otherwise re-add it: Phase 3 may have just created the very
		// user this member name refers to, making it newly resolvable.
		convertPayload := groupPayload
		convertPayload.Members, _ = filterDeferredGroupMembers(groupPayload, liveGroupMembers[groupPayload.Name], auth)
		if len(convertPayload.Members) == 0 {
			continue
		}

		// Convert with updated UID lookup
		opnGroup := opnapi.ConvertAPIToGroup(convertPayload, groupPayload.Templates, uidLookup)

		if err := client.SetGroup(ctx, existingUUID, opnGroup); err != nil {
			// This member-update error needs its own result item, distinct
			// from Phase 2's create/update item for the same group.
			msg := fmt.Sprintf("Group %s member update: %v", groupPayload.Name, err)
			errors = append(errors, msg)
			results = append(results, SyncAPIItemResult{
				Type:   "group",
				UUID:   existingUUID,
				Name:   groupPayload.Name,
				Action: "member_update",
				Status: "error",
				Error:  msg,
			})
		}
	}

	// Phase 5: Delete orphan users (managed but not in desired)
	var orphanUsers []map[string]interface{}
	for _, managedUser := range managedUsers {
		name, _ := managedUser["name"].(string)

		if _, desired := desiredUserNames[name]; desired {
			continue
		}

		// Skip protected users
		if opnapi.IsProtectedUser(name) {
			continue
		}

		orphanUsers = append(orphanUsers, managedUser)
	}

	var memberships *orphanMemberships
	if len(orphanUsers) > 0 {
		memberships = newOrphanMemberships(allUsers, allGroups, policy, devicePrivs)
	}

	for _, managedUser := range orphanUsers {
		name, _ := managedUser["name"].(string)
		uuid, _ := managedUser["uuid"].(string)

		// Deleting a user leaves its uid in every group's member list (see
		// sync_user_prune.go). Take it out first; a failure never blocks the
		// delete, but it is reported.
		if member, elevated := memberships.of(managedUser); member {
			uid, _ := managedUser["uid"].(string)
			left, pruneErr := pruneMemberships(ctx, client, uuid, name, uid)
			if pruneErr == nil && len(left) > 0 {
				elevated = memberships.anyElevated(left)
				pruneErr = stillListedError(left)
			}
			if pruneErr != nil {
				log.Warnw("SYNC_API: could not remove a managed user from its groups before deleting it",
					"name", name,
					"administrator_equivalent_group", elevated,
					"error", pruneErr,
				)
				item, msg := pruneMembershipsFailure(name, uuid, elevated, pruneErr)
				results = append(results, item)
				if msg != "" {
					errors = append(errors, msg)
				}
			}
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

// unboundText reads a text field of UNBOUND content the way every snippet
// family reads values: a string as it is, a number in decimal ("ttl": 300 is
// "300"), a list of strings and numbers comma-joined. These used to be dropped
// without a word. A boolean or an object is no text field's value and is
// refused, naming the field: "ttl": true read as "1" would apply a TTL of one
// second. The boolean fields (enabled, addptr, the forward flags) have their
// own readers.
func unboundText(content map[string]interface{}, key string) (string, error) {
	value, problem := opnsenseValue(content[key], false, false)
	if problem != "" {
		return "", fmt.Errorf("%s: %s", key, problem)
	}
	return value, nil
}

// unboundBoolean reads a "0"/"1" field of UNBOUND content; the strings "true"
// and "false" are read as "1" and "0" too.
func unboundBoolean(content map[string]interface{}, key string) (string, error) {
	value, problem := opnsenseValue(content[key], true, false)
	if problem != "" {
		return "", fmt.Errorf("%s: %s", key, problem)
	}
	return value, nil
}

// unboundField is a text field of UNBOUND content and where it is read to.
type unboundField struct {
	key  string
	dest *string
}

// unboundTextFields reads text fields into their destinations, in order, so
// content with two bad values is always refused naming the first.
func unboundTextFields(content map[string]interface{}, fields []unboundField) error {
	for _, field := range fields {
		value, err := unboundText(content, field.key)
		if err != nil {
			return err
		}
		*field.dest = value
	}
	return nil
}

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
			return nil, fmt.Errorf("%s: missing content", snippetLabel("host_override", snippetMap, idx))
		}

		override, err := parseHostOverrideContent(snippetContent, templates)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", snippetLabel("host_override", snippetMap, idx), err)
		}

		// Provenance for error messages; see invalidUUIDMessage.
		override.SnippetName, _ = snippetMap["snippet_name"].(string)
		override.SnippetIndex = idx
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

	err := unboundTextFields(contentMap, []unboundField{
		{"hostname", &override.Hostname},
		{"domain", &override.Domain},
		{"rr", &override.RR},
		{"server", &override.Server},
		{"mxprio", &override.MXPrio},
		{"mx", &override.MX},
		{"ttl", &override.TTL},
		{"txtdata", &override.TXTData},
		{"description", &override.Description},
	})
	if err != nil {
		return opnapi.APIHostOverridePayload{}, err
	}
	if override.Hostname == "" {
		return opnapi.APIHostOverridePayload{}, fmt.Errorf("missing required field: hostname")
	}
	if override.Domain == "" {
		return opnapi.APIHostOverridePayload{}, fmt.Errorf("missing required field: domain")
	}

	// Parse enabled
	override.Enabled = parseEnabled(contentMap["enabled"])

	if override.RR == "" {
		override.RR = "A" // Default to A record
	}
	if override.AddPTR, err = unboundBoolean(contentMap, "addptr"); err != nil {
		return opnapi.APIHostOverridePayload{}, err
	}

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
			return nil, fmt.Errorf("%s: missing content", snippetLabel("domain_forward", snippetMap, idx))
		}

		forward, err := parseDomainForwardContent(snippetContent, templates)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", snippetLabel("domain_forward", snippetMap, idx), err)
		}

		// Provenance for error messages; see invalidUUIDMessage.
		forward.SnippetName, _ = snippetMap["snippet_name"].(string)
		forward.SnippetIndex = idx
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

	err := unboundTextFields(contentMap, []unboundField{
		{"domain", &forward.Domain},
		{"server", &forward.Server},
		{"type", &forward.Type},
		{"port", &forward.Port},
		{"verify", &forward.Verify},
		{"description", &forward.Description},
	})
	if err != nil {
		return opnapi.APIDomainForwardPayload{}, err
	}
	if forward.Domain == "" {
		return opnapi.APIDomainForwardPayload{}, fmt.Errorf("missing required field: domain")
	}
	if forward.Server == "" {
		return opnapi.APIDomainForwardPayload{}, fmt.Errorf("missing required field: server")
	}

	// Parse enabled
	forward.Enabled = parseEnabled(contentMap["enabled"])

	if forward.Type == "" {
		forward.Type = "forward" // Default to standard forwarding
	}
	forward.ForwardTCPUpstream = parseBoolField(contentMap["forward_tcp_upstream"])
	forward.ForwardFirst = parseBoolField(contentMap["forward_first"])

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
			return nil, fmt.Errorf("%s: missing content", snippetLabel("host_alias", snippetMap, idx))
		}

		alias, err := parseHostAliasContent(snippetContent, templates)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", snippetLabel("host_alias", snippetMap, idx), err)
		}

		// Provenance for error messages; see invalidUUIDMessage.
		alias.SnippetName, _ = snippetMap["snippet_name"].(string)
		alias.SnippetIndex = idx
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

	// The parent is referenced by hostname and domain, for portability.
	err := unboundTextFields(contentMap, []unboundField{
		{"hostname", &alias.Hostname},
		{"domain", &alias.Domain},
		{"parent_hostname", &alias.ParentHostname},
		{"parent_domain", &alias.ParentDomain},
		{"description", &alias.Description},
	})
	if err != nil {
		return opnapi.APIHostAliasPayload{}, err
	}
	if alias.Hostname == "" {
		return opnapi.APIHostAliasPayload{}, fmt.Errorf("missing required field: hostname")
	}
	if alias.Domain == "" {
		return opnapi.APIHostAliasPayload{}, fmt.Errorf("missing required field: domain")
	}

	// Parse enabled
	alias.Enabled = parseEnabled(contentMap["enabled"])

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
			return nil, fmt.Errorf("%s: missing content", snippetLabel("unbound_acl", snippetMap, idx))
		}

		acl, err := parseUnboundACLContent(snippetContent, templates)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", snippetLabel("unbound_acl", snippetMap, idx), err)
		}

		// Provenance for error messages; see invalidUUIDMessage.
		acl.SnippetName, _ = snippetMap["snippet_name"].(string)
		acl.SnippetIndex = idx
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

	var networks string
	err := unboundTextFields(contentMap, []unboundField{
		{"name", &acl.Name},
		{"action", &acl.Action},
		{"networks", &networks},
		{"description", &acl.Description},
	})
	if err != nil {
		return opnapi.APIUnboundACLPayload{}, err
	}
	if acl.Name == "" {
		return opnapi.APIUnboundACLPayload{}, fmt.Errorf("missing required field: name")
	}
	if acl.Action == "" {
		return opnapi.APIUnboundACLPayload{}, fmt.Errorf("missing required field: action")
	}

	// Parse enabled
	acl.Enabled = parseEnabled(contentMap["enabled"])

	// Networks may be a comma-separated string or a list.
	if networks != "" {
		acl.Networks = strings.Split(networks, ",")
		for i := range acl.Networks {
			acl.Networks[i] = strings.TrimSpace(acl.Networks[i])
		}
	}

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
		msg := fmt.Sprintf("Failed to list host overrides: %v", err)
		return SyncAPIResult{
			Success: false,
			Message: msg,
			Results: []SyncAPIItemResult{{
				Type:   "host_override_discovery",
				Name:   "list_host_overrides",
				Action: "discover",
				Status: "error",
				Error:  msg,
			}},
			Errors: []string{msg},
		}
	}
	currentHostOverrides := opnapi.FilterManagedHostOverrides(allHostOverrides)

	allForwards, err := client.ListAllForwards(ctx)
	if err != nil {
		msg := fmt.Sprintf("Failed to list domain forwards: %v", err)
		return SyncAPIResult{
			Success: false,
			Message: msg,
			Results: []SyncAPIItemResult{{
				Type:   "domain_forward_discovery",
				Name:   "list_forwards",
				Action: "discover",
				Status: "error",
				Error:  msg,
			}},
			Errors: []string{msg},
		}
	}
	currentForwards := opnapi.FilterManagedForwards(allForwards)

	allHostAliases, err := client.ListAllHostAliases(ctx)
	if err != nil {
		msg := fmt.Sprintf("Failed to list host aliases: %v", err)
		return SyncAPIResult{
			Success: false,
			Message: msg,
			Results: []SyncAPIItemResult{{
				Type:   "host_alias_discovery",
				Name:   "list_host_aliases",
				Action: "discover",
				Status: "error",
				Error:  msg,
			}},
			Errors: []string{msg},
		}
	}
	currentHostAliases := opnapi.FilterManagedHostAliases(allHostAliases)

	allACLs, err := client.ListAllACLs(ctx)
	if err != nil {
		msg := fmt.Sprintf("Failed to list ACLs: %v", err)
		return SyncAPIResult{
			Success: false,
			Message: msg,
			Results: []SyncAPIItemResult{{
				Type:   "unbound_acl_discovery",
				Name:   "list_acls",
				Action: "discover",
				Status: "error",
				Error:  msg,
			}},
			Errors: []string{msg},
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

	// Phase 10: Apply changes. Every errors entry must have a matching
	// results item, or a FAILED task's own results array shows nothing
	// wrong.
	if err := client.ReconfigureUnbound(ctx); err != nil {
		msg := fmt.Sprintf("Unbound reconfigure: %v", err)
		errors = append(errors, msg)
		results = append(results, SyncAPIItemResult{
			Type:   "unbound_apply",
			Name:   "reconfigure",
			Action: "apply",
			Status: "error",
			Error:  msg,
		})
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
