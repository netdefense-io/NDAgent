package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// ============================================================================
// Zabbix snippet parsers
// ============================================================================
//
// Snippet payload shape (set by NDManager's sync_service.build_payload):
//   {"config_type":"ZABBIX_SETTINGS"|"ZABBIX_USERPARAMETER"|"ZABBIX_ALIAS",
//    "snippet_name":"...", "template_name":[...], "content":"<json string>"}
//
// All three Zabbix types carry JSON content (vs the legacy XML types). The
// `template_name` array is captured for diagnostic logging only — Zabbix
// entities have no description field where the agent could stamp template
// origin, so the `[nd-template:X]` tag trick used elsewhere doesn't apply.

// parseAPIZabbixSettings extracts the Zabbix settings singleton from the
// snippets array. Returns nil if no ZABBIX_SETTINGS snippet is present.
// If multiple ZABBIX_SETTINGS arrive (admin/template misconfiguration), the
// last one wins — same precedence the underlying /settings/set wholesale
// replace would produce if we applied them all.
func parseAPIZabbixSettings(payload map[string]interface{}) (*opnapi.APIZabbixSettingsPayload, error) {
	snippetsRaw, ok := payload["snippets"]
	if !ok {
		return nil, nil
	}
	snippetsArray, ok := snippetsRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("snippets must be an array")
	}

	var last *opnapi.APIZabbixSettingsPayload
	for idx, s := range snippetsArray {
		snippetMap, ok := s.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("snippet at index %d must be an object", idx)
		}
		if ct, _ := snippetMap["config_type"].(string); ct != "ZABBIX_SETTINGS" {
			continue
		}

		content, _ := snippetMap["content"].(string)
		if content == "" {
			return nil, fmt.Errorf("zabbix_settings snippet at index %d missing content", idx)
		}

		var settings opnapi.APIZabbixSettingsPayload
		if err := json.Unmarshal([]byte(content), &settings); err != nil {
			return nil, fmt.Errorf("zabbix_settings snippet at index %d: invalid JSON: %v", idx, err)
		}
		settings.Templates = templateNames(snippetMap)
		last = &settings
	}

	return last, nil
}

// parseAPIZabbixUserParameters extracts all ZABBIX_USERPARAMETER snippets.
func parseAPIZabbixUserParameters(payload map[string]interface{}) ([]opnapi.APIZabbixUserParameterPayload, error) {
	snippetsRaw, ok := payload["snippets"]
	if !ok {
		return nil, nil
	}
	snippetsArray, ok := snippetsRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("snippets must be an array")
	}

	var out []opnapi.APIZabbixUserParameterPayload
	for idx, s := range snippetsArray {
		snippetMap, ok := s.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("snippet at index %d must be an object", idx)
		}
		if ct, _ := snippetMap["config_type"].(string); ct != "ZABBIX_USERPARAMETER" {
			continue
		}

		content, _ := snippetMap["content"].(string)
		if content == "" {
			return nil, fmt.Errorf("zabbix_userparameter snippet at index %d missing content", idx)
		}

		var up opnapi.APIZabbixUserParameterPayload
		if err := json.Unmarshal([]byte(content), &up); err != nil {
			return nil, fmt.Errorf("zabbix_userparameter snippet at index %d: invalid JSON: %v", idx, err)
		}
		if up.Key == "" {
			return nil, fmt.Errorf("zabbix_userparameter snippet at index %d: missing required field: key", idx)
		}
		up.Templates = templateNames(snippetMap)
		out = append(out, up)
	}
	return out, nil
}

// parseAPIZabbixAliases extracts all ZABBIX_ALIAS snippets.
func parseAPIZabbixAliases(payload map[string]interface{}) ([]opnapi.APIZabbixAliasPayload, error) {
	snippetsRaw, ok := payload["snippets"]
	if !ok {
		return nil, nil
	}
	snippetsArray, ok := snippetsRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("snippets must be an array")
	}

	var out []opnapi.APIZabbixAliasPayload
	for idx, s := range snippetsArray {
		snippetMap, ok := s.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("snippet at index %d must be an object", idx)
		}
		if ct, _ := snippetMap["config_type"].(string); ct != "ZABBIX_ALIAS" {
			continue
		}

		content, _ := snippetMap["content"].(string)
		if content == "" {
			return nil, fmt.Errorf("zabbix_alias snippet at index %d missing content", idx)
		}

		var a opnapi.APIZabbixAliasPayload
		if err := json.Unmarshal([]byte(content), &a); err != nil {
			return nil, fmt.Errorf("zabbix_alias snippet at index %d: invalid JSON: %v", idx, err)
		}
		if a.Key == "" {
			return nil, fmt.Errorf("zabbix_alias snippet at index %d: missing required field: key", idx)
		}
		a.Templates = templateNames(snippetMap)
		out = append(out, a)
	}
	return out, nil
}

// templateNames extracts the template_name string array from a snippet entry.
// Empty / missing array returns nil rather than an empty slice.
func templateNames(snippetMap map[string]interface{}) []string {
	raw, ok := snippetMap["template_name"].([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, t := range raw {
		if s, ok := t.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// validateZabbixManagedKey rejects userparameter/alias entries whose `key`
// doesn't carry the NDAgent ownership prefix. Without this, an admin
// template could create entries the agent's filter wouldn't recognise on
// the next sync — they'd become orphans that NDAgent wouldn't clean up.
func validateZabbixManagedKey(key string) error {
	if !strings.HasPrefix(key, opnapi.NDAgentZabbixKeyPrefix) {
		return fmt.Errorf("key %q must start with %q to be managed by NDAgent", key, opnapi.NDAgentZabbixKeyPrefix)
	}
	return nil
}

// ============================================================================
// executeSyncZabbix
// ============================================================================
//
// Apply order:
//   1. Settings (whole-tree replace; admin owns enabled/server/PSK/etc).
//   2. UserParameter upsert by `key` (server-assigned UUIDs).
//   3. UserParameter delete-orphans (managed entries no longer in desired).
//   4. Alias upsert by `key`.
//   5. Alias delete-orphans.
//   6. Single ReconfigureZabbix at the end.
//
// settings may be nil if no ZABBIX_SETTINGS snippet was in the payload —
// in that case userparameters/aliases are applied against whatever main
// settings already exist on the device.
func executeSyncZabbix(
	ctx context.Context,
	client *opnapi.Client,
	settings *opnapi.APIZabbixSettingsPayload,
	userParams []opnapi.APIZabbixUserParameterPayload,
	aliases []opnapi.APIZabbixAliasPayload,
) SyncAPIResult {
	log := logging.Named("SYNC_API")

	var results []SyncAPIItemResult
	var errors []string

	// Phase 0: Plugin-presence probe.
	//
	// The Zabbix executor runs every sync (so orphan cleanup is reliable),
	// but most devices don't have os-zabbix-agent installed. A single
	// ListAllZabbixUserParameters call doubles as the probe: a 404 means
	// the plugin's REST endpoints aren't mounted, which we treat as a
	// silent no-op rather than an error in the sync report.
	currentUPRows, err := client.ListAllZabbixUserParameters(ctx)
	if err != nil {
		if opnapi.IsNotFound(err) {
			log.Debug("Zabbix plugin not installed on this device; skipping zabbix sync")
			return SyncAPIResult{
				Success: true,
				Message: "No changes applied",
			}
		}
		return SyncAPIResult{
			Success: false,
			Message: fmt.Sprintf("Failed to list zabbix userparameters: %v", err),
			Results: results,
			Errors:  append(errors, err.Error()),
		}
	}

	// Phase 1: Settings (singleton, replace-in-full)
	//
	// OPNsense's settings/set rejects payloads where any Required field is
	// empty — even though we POST the whole tree on every apply, a sparse
	// snippet (admin only specified the fields they want to change) would
	// fail validation on tuning.* and main.logFileSize. To keep
	// wholesale-replace semantics ergonomic, we fetch the device's current
	// state first and use it as a baseline; any non-empty snippet field
	// overrides. Net effect: the snippet's value always wins; omitted
	// fields keep whatever the device currently has.
	if settings != nil {
		currentRaw, err := client.GetZabbixSettings(ctx)
		if err != nil {
			itemResult := SyncAPIItemResult{
				Type:   "zabbix_settings",
				Name:   settings.Hostname,
				Action: "skipped",
				Status: "error",
				Error:  fmt.Sprintf("failed to read current settings: %v", err),
			}
			results = append(results, itemResult)
			errors = append(errors, fmt.Sprintf("Zabbix settings (GET): %v", err))
		} else {
			body := opnapi.MergeZabbixSettings(*settings, currentRaw)
			err := client.SetZabbixSettings(ctx, body)
			itemResult := SyncAPIItemResult{
				Type:   "zabbix_settings",
				Name:   settings.Hostname,
				Action: "updated",
			}
			if err != nil {
				itemResult.Status = "error"
				itemResult.Error = err.Error()
				errors = append(errors, fmt.Sprintf("Zabbix settings: %v", err))
			} else {
				itemResult.Status = "success"
			}
			results = append(results, itemResult)
		}
	}

	// Phase 2-3: UserParameters.
	//
	// Runs every sync. Empty desired list = delete every NDAgent-managed
	// userparameter on the device (orphan cleanup is the whole point of
	// removing the if-len gate).
	{
		currentManaged := opnapi.FilterManagedZabbixUserParameters(currentUPRows)

		// Index current managed rows by key for O(1) match.
		currentByKey := make(map[string]map[string]interface{}, len(currentManaged))
		for _, r := range currentManaged {
			if k, ok := r["key"].(string); ok {
				currentByKey[k] = r
			}
		}

		desiredKeys := make(map[string]bool, len(userParams))
		for _, up := range userParams {
			if err := validateZabbixManagedKey(up.Key); err != nil {
				itemResult := SyncAPIItemResult{
					Type:   "zabbix_userparameter",
					Name:   up.Key,
					Action: "skipped",
					Status: "error",
					Error:  err.Error(),
				}
				results = append(results, itemResult)
				errors = append(errors, fmt.Sprintf("Zabbix userparameter %s: %v", up.Key, err))
				continue
			}
			desiredKeys[up.Key] = true

			wire := opnapi.ConvertToOPNZabbixUserParameter(up)
			action := "created"
			var uuid string
			var applyErr error
			if existing, ok := currentByKey[up.Key]; ok {
				action = "updated"
				uuid, _ = existing["uuid"].(string)
				applyErr = client.SetZabbixUserParameter(ctx, uuid, wire)
			} else {
				uuid, applyErr = client.AddZabbixUserParameter(ctx, wire)
			}

			itemResult := SyncAPIItemResult{
				Type:   "zabbix_userparameter",
				UUID:   uuid,
				Name:   up.Key,
				Action: action,
			}
			if applyErr != nil {
				itemResult.Status = "error"
				itemResult.Error = applyErr.Error()
				errors = append(errors, fmt.Sprintf("Zabbix userparameter %s: %v", up.Key, applyErr))
			} else {
				itemResult.Status = "success"
			}
			results = append(results, itemResult)
		}

		// Delete managed userparameters no longer in desired.
		for key, row := range currentByKey {
			if desiredKeys[key] {
				continue
			}
			uuid, _ := row["uuid"].(string)
			err := client.DeleteZabbixUserParameter(ctx, uuid)
			itemResult := SyncAPIItemResult{
				Type:   "zabbix_userparameter",
				UUID:   uuid,
				Name:   key,
				Action: "deleted",
			}
			if err != nil {
				itemResult.Status = "error"
				itemResult.Error = err.Error()
				errors = append(errors, fmt.Sprintf("Delete zabbix userparameter %s: %v", key, err))
			} else {
				itemResult.Status = "success"
			}
			results = append(results, itemResult)
		}
	}

	// Phase 4-5: Aliases (same pattern, runs every sync).
	{
		currentRows, err := client.ListAllZabbixAliases(ctx)
		if err != nil {
			return SyncAPIResult{
				Success: false,
				Message: fmt.Sprintf("Failed to list zabbix aliases: %v", err),
				Results: results,
				Errors:  append(errors, err.Error()),
			}
		}
		currentManaged := opnapi.FilterManagedZabbixAliases(currentRows)

		currentByKey := make(map[string]map[string]interface{}, len(currentManaged))
		for _, r := range currentManaged {
			if k, ok := r["key"].(string); ok {
				currentByKey[k] = r
			}
		}

		desiredKeys := make(map[string]bool, len(aliases))
		for _, a := range aliases {
			if err := validateZabbixManagedKey(a.Key); err != nil {
				itemResult := SyncAPIItemResult{
					Type:   "zabbix_alias",
					Name:   a.Key,
					Action: "skipped",
					Status: "error",
					Error:  err.Error(),
				}
				results = append(results, itemResult)
				errors = append(errors, fmt.Sprintf("Zabbix alias %s: %v", a.Key, err))
				continue
			}
			desiredKeys[a.Key] = true

			wire := opnapi.ConvertToOPNZabbixAlias(a)
			action := "created"
			var uuid string
			var applyErr error
			if existing, ok := currentByKey[a.Key]; ok {
				action = "updated"
				uuid, _ = existing["uuid"].(string)
				applyErr = client.SetZabbixAlias(ctx, uuid, wire)
			} else {
				uuid, applyErr = client.AddZabbixAlias(ctx, wire)
			}

			itemResult := SyncAPIItemResult{
				Type:   "zabbix_alias",
				UUID:   uuid,
				Name:   a.Key,
				Action: action,
			}
			if applyErr != nil {
				itemResult.Status = "error"
				itemResult.Error = applyErr.Error()
				errors = append(errors, fmt.Sprintf("Zabbix alias %s: %v", a.Key, applyErr))
			} else {
				itemResult.Status = "success"
			}
			results = append(results, itemResult)
		}

		for key, row := range currentByKey {
			if desiredKeys[key] {
				continue
			}
			uuid, _ := row["uuid"].(string)
			err := client.DeleteZabbixAlias(ctx, uuid)
			itemResult := SyncAPIItemResult{
				Type:   "zabbix_alias",
				UUID:   uuid,
				Name:   key,
				Action: "deleted",
			}
			if err != nil {
				itemResult.Status = "error"
				itemResult.Error = err.Error()
				errors = append(errors, fmt.Sprintf("Delete zabbix alias %s: %v", key, err))
			} else {
				itemResult.Status = "success"
			}
			results = append(results, itemResult)
		}
	}

	// Phase 6: Apply changes. Skip the reconfigure call if nothing
	// actually changed on the device — saves a service bounce on no-op
	// syncs (no settings push, no creates, no updates, no deletes). The
	// item count in `results` captures all four.
	touched := len(results) > 0
	if touched {
		if err := client.ReconfigureZabbix(ctx); err != nil {
			errors = append(errors, fmt.Sprintf("Zabbix reconfigure: %v", err))
		}
	}

	// Aggregate counts for logging
	var settingsApplied int
	var upCreated, upUpdated, upDeleted int
	var aliasCreated, aliasUpdated, aliasDeleted int
	for _, r := range results {
		if r.Status != "success" {
			continue
		}
		switch r.Type {
		case "zabbix_settings":
			settingsApplied++
		case "zabbix_userparameter":
			switch r.Action {
			case "created":
				upCreated++
			case "updated":
				upUpdated++
			case "deleted":
				upDeleted++
			}
		case "zabbix_alias":
			switch r.Action {
			case "created":
				aliasCreated++
			case "updated":
				aliasUpdated++
			case "deleted":
				aliasDeleted++
			}
		}
	}

	success := len(errors) == 0
	var message string
	switch {
	case !touched:
		message = "No changes applied"
	case success:
		message = fmt.Sprintf(
			"Zabbix sync OK (settings:%d, userparams +%d ~%d -%d, aliases +%d ~%d -%d)",
			settingsApplied, upCreated, upUpdated, upDeleted, aliasCreated, aliasUpdated, aliasDeleted,
		)
	default:
		message = fmt.Sprintf("Zabbix sync completed with %d error(s)", len(errors))
	}

	log.Infow("Zabbix sync completed",
		"success", success,
		"settings_applied", settingsApplied,
		"userparameters_created", upCreated,
		"userparameters_updated", upUpdated,
		"userparameters_deleted", upDeleted,
		"aliases_created", aliasCreated,
		"aliases_updated", aliasUpdated,
		"aliases_deleted", aliasDeleted,
		"error_count", len(errors),
	)

	return SyncAPIResult{
		Success: success,
		Message: message,
		Results: results,
		Errors:  errors,
	}
}
