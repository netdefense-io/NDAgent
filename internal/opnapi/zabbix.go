package opnapi

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// ============================================================================
// Settings (singleton)
// ============================================================================

// GetZabbixSettings reads the full zabbixagent settings tree.
//
// Returned as a raw map because OPNsense's GET form is asymmetric to the write
// form (SelectMultiple becomes a dict of options, Selection becomes a dict with
// `val_N` keys). Callers needing a typed view should walk the map or convert
// to ZabbixSettings via the helper functions in this package.
func (c *Client) GetZabbixSettings(ctx context.Context) (map[string]interface{}, error) {
	respBody, err := c.doRequest(ctx, "GET", "/zabbixagent/settings/get", nil)
	if err != nil {
		return nil, err
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return resp, nil
}

// SetZabbixSettings POSTs the full zabbixagent settings tree.
// The payload replaces local + main + tuning + features wholesale; OPNsense
// preserves nothing on the agent side that isn't in the body.
func (c *Client) SetZabbixSettings(ctx context.Context, body ZabbixSettingsBody) error {
	wrapper := ZabbixSettingsWrapper{ZabbixAgent: body}

	respBody, err := c.doRequest(ctx, "POST", "/zabbixagent/settings/set", wrapper)
	if err != nil {
		return err
	}

	var result SetZabbixResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if result.Result != "saved" {
		if result.ValidationErrors.HasErrors() {
			c.log.Debugw("Validation errors", "errors", result.ValidationErrors.String())
			return fmt.Errorf("validation failed: %s", result.ValidationErrors.String())
		}
		reqBody, _ := json.Marshal(wrapper)
		c.log.Debugw("SetZabbixSettings structural rejection",
			"request_body", string(reqBody),
			"response", string(respBody),
		)
		return fmt.Errorf("unexpected result: %s (response: %s, request: %s)", result.Result, string(respBody), string(reqBody))
	}

	c.log.Debugw("SetZabbixSettings completed",
		"hostname", body.Local.Hostname,
		"main_enabled", body.Settings.Main.Enabled,
	)

	return nil
}

// ============================================================================
// User Parameter Operations
// ============================================================================

// SearchZabbixUserParameters lists all UserParameter rows. The phrase argument
// is honoured by OPNsense's grid search; pass "" to fetch everything.
func (c *Client) SearchZabbixUserParameters(ctx context.Context, searchPhrase string) ([]map[string]interface{}, error) {
	path := "/zabbixagent/settings/searchUserparameters/"
	if searchPhrase != "" {
		path = path + "?searchPhrase=" + searchPhrase
	}
	respBody, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var resp SearchResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse search response: %w", err)
	}

	c.log.Debugw("SearchZabbixUserParameters completed",
		"search_phrase", searchPhrase,
		"count", len(resp.Rows),
	)

	return resp.Rows, nil
}

// ListAllZabbixUserParameters returns every UserParameter row.
func (c *Client) ListAllZabbixUserParameters(ctx context.Context) ([]map[string]interface{}, error) {
	return c.SearchZabbixUserParameters(ctx, "")
}

// FilterManagedZabbixUserParameters keeps rows whose `key` starts with
// NDAgentZabbixKeyPrefix. Admin-created entries without the prefix are
// untouched by NDAgent sync.
func FilterManagedZabbixUserParameters(rows []map[string]interface{}) []map[string]interface{} {
	var managed []map[string]interface{}
	for _, r := range rows {
		if key, ok := r["key"].(string); ok && strings.HasPrefix(key, NDAgentZabbixKeyPrefix) {
			managed = append(managed, r)
		}
	}
	return managed
}

// GetZabbixUserParameter fetches one row by UUID. Pass empty UUID to retrieve
// the blank template (useful for discovering wrapper key + default values).
func (c *Client) GetZabbixUserParameter(ctx context.Context, uuid string) (map[string]interface{}, error) {
	path := fmt.Sprintf("/zabbixagent/settings/getUserparameter/%s", uuid)
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

// GetZabbixUserParameterByKey scans search results for an exact `key` match.
// Returns (nil, nil) if absent — search by key is the only stable handle since
// OPNsense assigns UUIDs on `add`.
func (c *Client) GetZabbixUserParameterByKey(ctx context.Context, key string) (map[string]interface{}, error) {
	rows, err := c.SearchZabbixUserParameters(ctx, "")
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if k, _ := r["key"].(string); k == key {
			return r, nil
		}
	}
	return nil, nil
}

// AddZabbixUserParameter creates a new UserParameter. OPNsense ignores any
// caller-supplied UUID and returns its own — captured in the response.
func (c *Client) AddZabbixUserParameter(ctx context.Context, up ZabbixUserParameter) (string, error) {
	wrapper := ZabbixUserParameterWrapper{UserParameter: up}

	respBody, err := c.doRequest(ctx, "POST", "/zabbixagent/settings/addUserparameter", wrapper)
	if err != nil {
		return "", err
	}

	var result SetZabbixResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if result.Result != "saved" {
		if result.ValidationErrors.HasErrors() {
			c.log.Debugw("Validation errors", "errors", result.ValidationErrors.String())
			return "", fmt.Errorf("validation failed: %s", result.ValidationErrors.String())
		}
		reqBody, _ := json.Marshal(wrapper)
		c.log.Debugw("AddZabbixUserParameter structural rejection",
			"request_body", string(reqBody),
			"response", string(respBody),
		)
		return "", fmt.Errorf("unexpected result: %s (response: %s, request: %s)", result.Result, string(respBody), string(reqBody))
	}

	c.log.Debugw("AddZabbixUserParameter completed",
		"uuid", result.UUID,
		"key", up.Key,
	)
	return result.UUID, nil
}

// SetZabbixUserParameter updates an existing UserParameter. No upsert: a
// missing UUID returns "failed".
func (c *Client) SetZabbixUserParameter(ctx context.Context, uuid string, up ZabbixUserParameter) error {
	path := fmt.Sprintf("/zabbixagent/settings/setUserparameter/%s", uuid)
	wrapper := ZabbixUserParameterWrapper{UserParameter: up}

	respBody, err := c.doRequest(ctx, "POST", path, wrapper)
	if err != nil {
		return err
	}

	var result SetZabbixResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if result.Result != "saved" {
		if result.ValidationErrors.HasErrors() {
			c.log.Debugw("Validation errors", "errors", result.ValidationErrors.String())
			return fmt.Errorf("validation failed: %s", result.ValidationErrors.String())
		}
		reqBody, _ := json.Marshal(wrapper)
		c.log.Debugw("SetZabbixUserParameter structural rejection",
			"uuid", uuid,
			"request_body", string(reqBody),
			"response", string(respBody),
		)
		return fmt.Errorf("unexpected result: %s (response: %s, request: %s)", result.Result, string(respBody), string(reqBody))
	}

	c.log.Debugw("SetZabbixUserParameter completed",
		"uuid", uuid,
		"key", up.Key,
	)
	return nil
}

// DeleteZabbixUserParameter removes a UserParameter by UUID.
func (c *Client) DeleteZabbixUserParameter(ctx context.Context, uuid string) error {
	path := fmt.Sprintf("/zabbixagent/settings/delUserparameter/%s", uuid)
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

	c.log.Debugw("DeleteZabbixUserParameter completed", "uuid", uuid)
	return nil
}

// ToggleZabbixUserParameter flips the enabled flag, or forces a state when
// enable is non-nil.
func (c *Client) ToggleZabbixUserParameter(ctx context.Context, uuid string, enable *bool) error {
	path := fmt.Sprintf("/zabbixagent/settings/toggleUserparameter/%s", uuid)
	if enable != nil {
		if *enable {
			path += "/1"
		} else {
			path += "/0"
		}
	}

	respBody, err := c.doRequest(ctx, "POST", path, struct{}{})
	if err != nil {
		return err
	}

	var result ToggleZabbixResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	if result.Result != "Enabled" && result.Result != "Disabled" {
		return fmt.Errorf("unexpected toggle result: %s", result.Result)
	}

	c.log.Debugw("ToggleZabbixUserParameter completed",
		"uuid", uuid,
		"result", result.Result,
		"changed", result.Changed,
	)
	return nil
}

// ============================================================================
// Alias Operations
// ============================================================================

// SearchZabbixAliases lists all item-key alias rows.
func (c *Client) SearchZabbixAliases(ctx context.Context, searchPhrase string) ([]map[string]interface{}, error) {
	path := "/zabbixagent/settings/searchAliases/"
	if searchPhrase != "" {
		path = path + "?searchPhrase=" + searchPhrase
	}
	respBody, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var resp SearchResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse search response: %w", err)
	}

	c.log.Debugw("SearchZabbixAliases completed",
		"search_phrase", searchPhrase,
		"count", len(resp.Rows),
	)

	return resp.Rows, nil
}

// ListAllZabbixAliases returns every alias row.
func (c *Client) ListAllZabbixAliases(ctx context.Context) ([]map[string]interface{}, error) {
	return c.SearchZabbixAliases(ctx, "")
}

// FilterManagedZabbixAliases keeps rows whose `key` starts with
// NDAgentZabbixKeyPrefix.
func FilterManagedZabbixAliases(rows []map[string]interface{}) []map[string]interface{} {
	var managed []map[string]interface{}
	for _, r := range rows {
		if key, ok := r["key"].(string); ok && strings.HasPrefix(key, NDAgentZabbixKeyPrefix) {
			managed = append(managed, r)
		}
	}
	return managed
}

// GetZabbixAlias fetches a single alias row by UUID. Pass empty UUID for the
// blank template.
func (c *Client) GetZabbixAlias(ctx context.Context, uuid string) (map[string]interface{}, error) {
	path := fmt.Sprintf("/zabbixagent/settings/getAlias/%s", uuid)
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

// GetZabbixAliasByKey scans search results for an exact `key` match.
func (c *Client) GetZabbixAliasByKey(ctx context.Context, key string) (map[string]interface{}, error) {
	rows, err := c.SearchZabbixAliases(ctx, "")
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if k, _ := r["key"].(string); k == key {
			return r, nil
		}
	}
	return nil, nil
}

// AddZabbixAlias creates a new alias. Server-assigned UUID returned.
func (c *Client) AddZabbixAlias(ctx context.Context, a ZabbixAlias) (string, error) {
	wrapper := ZabbixAliasWrapper{Alias: a}

	respBody, err := c.doRequest(ctx, "POST", "/zabbixagent/settings/addAlias", wrapper)
	if err != nil {
		return "", err
	}

	var result SetZabbixResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if result.Result != "saved" {
		if result.ValidationErrors.HasErrors() {
			c.log.Debugw("Validation errors", "errors", result.ValidationErrors.String())
			return "", fmt.Errorf("validation failed: %s", result.ValidationErrors.String())
		}
		reqBody, _ := json.Marshal(wrapper)
		c.log.Debugw("AddZabbixAlias structural rejection",
			"request_body", string(reqBody),
			"response", string(respBody),
		)
		return "", fmt.Errorf("unexpected result: %s (response: %s, request: %s)", result.Result, string(respBody), string(reqBody))
	}

	c.log.Debugw("AddZabbixAlias completed",
		"uuid", result.UUID,
		"key", a.Key,
	)
	return result.UUID, nil
}

// SetZabbixAlias updates an existing alias.
func (c *Client) SetZabbixAlias(ctx context.Context, uuid string, a ZabbixAlias) error {
	path := fmt.Sprintf("/zabbixagent/settings/setAlias/%s", uuid)
	wrapper := ZabbixAliasWrapper{Alias: a}

	respBody, err := c.doRequest(ctx, "POST", path, wrapper)
	if err != nil {
		return err
	}

	var result SetZabbixResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if result.Result != "saved" {
		if result.ValidationErrors.HasErrors() {
			c.log.Debugw("Validation errors", "errors", result.ValidationErrors.String())
			return fmt.Errorf("validation failed: %s", result.ValidationErrors.String())
		}
		reqBody, _ := json.Marshal(wrapper)
		c.log.Debugw("SetZabbixAlias structural rejection",
			"uuid", uuid,
			"request_body", string(reqBody),
			"response", string(respBody),
		)
		return fmt.Errorf("unexpected result: %s (response: %s, request: %s)", result.Result, string(respBody), string(reqBody))
	}

	c.log.Debugw("SetZabbixAlias completed",
		"uuid", uuid,
		"key", a.Key,
	)
	return nil
}

// DeleteZabbixAlias removes an alias by UUID.
func (c *Client) DeleteZabbixAlias(ctx context.Context, uuid string) error {
	path := fmt.Sprintf("/zabbixagent/settings/delAlias/%s", uuid)
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

	c.log.Debugw("DeleteZabbixAlias completed", "uuid", uuid)
	return nil
}

// ToggleZabbixAlias flips the enabled flag, or forces a state when enable is
// non-nil.
func (c *Client) ToggleZabbixAlias(ctx context.Context, uuid string, enable *bool) error {
	path := fmt.Sprintf("/zabbixagent/settings/toggleAlias/%s", uuid)
	if enable != nil {
		if *enable {
			path += "/1"
		} else {
			path += "/0"
		}
	}

	respBody, err := c.doRequest(ctx, "POST", path, struct{}{})
	if err != nil {
		return err
	}

	var result ToggleZabbixResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	if result.Result != "Enabled" && result.Result != "Disabled" {
		return fmt.Errorf("unexpected toggle result: %s", result.Result)
	}

	c.log.Debugw("ToggleZabbixAlias completed",
		"uuid", uuid,
		"result", result.Result,
		"changed", result.Changed,
	)
	return nil
}

// ============================================================================
// Reconfigure / Apply
// ============================================================================

// ReconfigureZabbix applies pending Zabbix Agent configuration changes.
// Call once after a batch of settings/userparameter/alias writes.
func (c *Client) ReconfigureZabbix(ctx context.Context) error {
	respBody, err := c.doRequest(ctx, "POST", "/zabbixagent/service/reconfigure", struct{}{})
	if err != nil {
		return fmt.Errorf("reconfigure failed: %w", err)
	}

	// OPNsense returns {"status":"ok"} on success.
	var resp struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return fmt.Errorf("failed to parse reconfigure response: %w", err)
	}
	if resp.Status != "ok" {
		return fmt.Errorf("reconfigure returned status=%q", resp.Status)
	}

	c.log.Debug("ReconfigureZabbix completed")
	return nil
}

// ============================================================================
// Conversion helpers
// ============================================================================

// ZabbixDebugLevelToWire converts a bare digit ("0".."5") to the option key
// form ("val_0".."val_5") that /settings/set requires.
//
// Empty input passes through (caller may want to omit the field). Anything
// already in "val_*" form passes through unchanged. Unknown values fall back
// to "val_3" (warnings, the OPNsense default).
func ZabbixDebugLevelToWire(level string) string {
	if level == "" {
		return ""
	}
	if strings.HasPrefix(level, "val_") {
		return level
	}
	switch level {
	case "0", "1", "2", "3", "4", "5":
		return "val_" + level
	default:
		return "val_3"
	}
}

// ZabbixDebugLevelFromGet reduces the dict-of-options that /settings/get
// returns to a bare digit. Used when rebuilding a snippet view of current
// state. Returns "" if no option is marked selected.
func ZabbixDebugLevelFromGet(raw interface{}) string {
	m, ok := raw.(map[string]interface{})
	if !ok {
		return ""
	}
	for k, v := range m {
		opt, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		sel := opt["selected"]
		// OPNsense returns selected as either 1 (int) or "1" (string) depending on path.
		switch s := sel.(type) {
		case float64:
			if s == 1 {
				return strings.TrimPrefix(k, "val_")
			}
		case string:
			if s == "1" {
				return strings.TrimPrefix(k, "val_")
			}
		case bool:
			if s {
				return strings.TrimPrefix(k, "val_")
			}
		}
	}
	return ""
}

// ZabbixMultiSelectToCSV flattens a SelectMultiple field as returned by
// /settings/get ({"v1":{"selected":1},"v2":{"selected":0},...}) into the
// comma-separated form /settings/set wants.
func ZabbixMultiSelectToCSV(raw interface{}) string {
	m, ok := raw.(map[string]interface{})
	if !ok {
		return ""
	}
	var selected []string
	for k, v := range m {
		opt, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		s := opt["selected"]
		switch sv := s.(type) {
		case float64:
			if sv == 1 {
				selected = append(selected, k)
			}
		case string:
			if sv == "1" {
				selected = append(selected, k)
			}
		case bool:
			if sv {
				selected = append(selected, k)
			}
		}
	}
	return strings.Join(selected, ",")
}

// MergeZabbixSettings builds the wire-shape body from the snippet payload,
// using the device's current settings as a baseline. Any non-empty snippet
// field wins; empty/unset fields keep the device's current value.
//
// This is the path executeSyncZabbix uses on the SYNC side. The OPNsense
// plugin marks several main/tuning fields Required="Y" and rejects empty
// strings, so a sparse snippet (admin only specified a few fields) would
// 422 against /settings/set without this overlay. Wholesale-replace
// semantics are preserved at the wire level — every apply posts a full
// tree — but the admin's snippet only has to spell out what they want to
// change.
func MergeZabbixSettings(p APIZabbixSettingsPayload, currentRaw map[string]interface{}) ZabbixSettingsBody {
	base := flattenZabbixGet(currentRaw)
	snippet := ConvertToOPNZabbixSettings(p)
	return overlayZabbixSettings(base, snippet)
}

// flattenZabbixGet converts the GET shape (SelectMultiple dict-of-options,
// val_N Selection enum keys, raw scalars) into a ZabbixSettingsBody.
func flattenZabbixGet(raw map[string]interface{}) ZabbixSettingsBody {
	var out ZabbixSettingsBody
	za, ok := raw["zabbixagent"].(map[string]interface{})
	if !ok {
		return out
	}
	if local, ok := za["local"].(map[string]interface{}); ok {
		out.Local.Hostname, _ = local["hostname"].(string)
	}
	settings, ok := za["settings"].(map[string]interface{})
	if !ok {
		return out
	}
	if main, ok := settings["main"].(map[string]interface{}); ok {
		getStr := func(k string) string { v, _ := main[k].(string); return v }
		out.Settings.Main = ZabbixMain{
			Enabled:       getStr("enabled"),
			ServerList:    ZabbixMultiSelectToCSV(main["serverList"]),
			ListenPort:    getStr("listenPort"),
			ListenIP:      ZabbixMultiSelectToCSV(main["listenIP"]),
			SourceIP:      getStr("sourceIP"),
			ListenBacklog: getStr("listenBacklog"),
			SyslogEnable:  getStr("syslogEnable"),
			LogFileSize:   getStr("logFileSize"),
			// debugLevel is returned as a {val_0:...val_5:...} dict on GET;
			// flatten to the bare digit so MergeZabbixSettings can decide
			// whether to take it or the snippet's value, then re-encode at
			// POST time via ZabbixDebugLevelToWire.
			DebugLevel: ZabbixDebugLevelFromGet(main["debugLevel"]),
			SudoRoot:   getStr("sudoRoot"),
		}
	}
	if tuning, ok := settings["tuning"].(map[string]interface{}); ok {
		getStr := func(k string) string { v, _ := tuning[k].(string); return v }
		out.Settings.Tuning = ZabbixTuning{
			StartAgents:       getStr("startAgents"),
			BufferSend:        getStr("bufferSend"),
			BufferSize:        getStr("bufferSize"),
			MaxLinesPerSecond: getStr("maxLinesPerSecond"),
			Timeout:           getStr("timeout"),
		}
	}
	if features, ok := settings["features"].(map[string]interface{}); ok {
		getStr := func(k string) string { v, _ := features[k].(string); return v }
		out.Settings.Features = ZabbixFeatures{
			EnableActiveChecks:   getStr("enableActiveChecks"),
			ActiveCheckServers:   ZabbixMultiSelectToCSV(features["activeCheckServers"]),
			RefreshActiveChecks:  getStr("refreshActiveChecks"),
			EnableRemoteCommands: getStr("enableRemoteCommands"),
			LogRemoteCommands:    getStr("logRemoteCommands"),
			Encryption:           getStr("encryption"),
			EncryptionIdentity:   getStr("encryptionidentity"),
			EncryptionPSK:        getStr("encryptionpsk"),
		}
	}
	return out
}

// overlayZabbixSettings returns base with every non-empty field from snippet
// substituted in. Pure string-level overlay — fields the snippet left empty
// keep their device-current value.
func overlayZabbixSettings(base, snippet ZabbixSettingsBody) ZabbixSettingsBody {
	pick := func(want, fallback string) string {
		if want == "" {
			return fallback
		}
		return want
	}
	out := base
	if snippet.Local.Hostname != "" {
		out.Local.Hostname = snippet.Local.Hostname
	}
	m := &out.Settings.Main
	sm := snippet.Settings.Main
	m.Enabled = pick(sm.Enabled, m.Enabled)
	m.ServerList = pick(sm.ServerList, m.ServerList)
	m.ListenPort = pick(sm.ListenPort, m.ListenPort)
	m.ListenIP = pick(sm.ListenIP, m.ListenIP)
	m.SourceIP = pick(sm.SourceIP, m.SourceIP)
	m.ListenBacklog = pick(sm.ListenBacklog, m.ListenBacklog)
	m.SyslogEnable = pick(sm.SyslogEnable, m.SyslogEnable)
	m.LogFileSize = pick(sm.LogFileSize, m.LogFileSize)
	// DebugLevel on the snippet side has already been converted to val_N by
	// ConvertToOPNZabbixSettings; the base came from the GET via
	// ZabbixDebugLevelFromGet (bare digit). Re-encode the chosen value to
	// val_N exactly once, here.
	chosenDL := pick(sm.DebugLevel, m.DebugLevel)
	m.DebugLevel = ZabbixDebugLevelToWire(chosenDL)
	m.SudoRoot = pick(sm.SudoRoot, m.SudoRoot)

	t := &out.Settings.Tuning
	st := snippet.Settings.Tuning
	t.StartAgents = pick(st.StartAgents, t.StartAgents)
	t.BufferSend = pick(st.BufferSend, t.BufferSend)
	t.BufferSize = pick(st.BufferSize, t.BufferSize)
	t.MaxLinesPerSecond = pick(st.MaxLinesPerSecond, t.MaxLinesPerSecond)
	t.Timeout = pick(st.Timeout, t.Timeout)

	f := &out.Settings.Features
	sf := snippet.Settings.Features
	f.EnableActiveChecks = pick(sf.EnableActiveChecks, f.EnableActiveChecks)
	f.ActiveCheckServers = pick(sf.ActiveCheckServers, f.ActiveCheckServers)
	f.RefreshActiveChecks = pick(sf.RefreshActiveChecks, f.RefreshActiveChecks)
	f.EnableRemoteCommands = pick(sf.EnableRemoteCommands, f.EnableRemoteCommands)
	f.LogRemoteCommands = pick(sf.LogRemoteCommands, f.LogRemoteCommands)
	f.Encryption = pick(sf.Encryption, f.Encryption)
	f.EncryptionIdentity = pick(sf.EncryptionIdentity, f.EncryptionIdentity)
	f.EncryptionPSK = pick(sf.EncryptionPSK, f.EncryptionPSK)
	return out
}

// ConvertToOPNZabbixSettings converts the portable snippet payload to the
// wire-shape body that /settings/set accepts. Multi-value list fields are
// joined with commas; DebugLevel is converted to its val_* form.
func ConvertToOPNZabbixSettings(p APIZabbixSettingsPayload) ZabbixSettingsBody {
	return ZabbixSettingsBody{
		Local: ZabbixLocal{
			Hostname: p.Hostname,
		},
		Settings: ZabbixSettings{
			Main: ZabbixMain{
				Enabled:       BoolToOPNsense(p.Enabled),
				ServerList:    strings.Join(p.ServerList, ","),
				ListenPort:    p.ListenPort,
				ListenIP:      strings.Join(p.ListenIP, ","),
				SourceIP:      p.SourceIP,
				ListenBacklog: p.ListenBacklog,
				SyslogEnable:  BoolToOPNsense(p.SyslogEnable),
				LogFileSize:   p.LogFileSize,
				DebugLevel:    ZabbixDebugLevelToWire(p.DebugLevel),
				SudoRoot:      BoolToOPNsense(p.SudoRoot),
			},
			Tuning: ZabbixTuning{
				StartAgents:       p.StartAgents,
				BufferSend:        p.BufferSend,
				BufferSize:        p.BufferSize,
				MaxLinesPerSecond: p.MaxLinesPerSecond,
				Timeout:           p.Timeout,
			},
			Features: ZabbixFeatures{
				EnableActiveChecks:   BoolToOPNsense(p.EnableActiveChecks),
				ActiveCheckServers:   strings.Join(p.ActiveCheckServers, ","),
				RefreshActiveChecks:  p.RefreshActiveChecks,
				EnableRemoteCommands: BoolToOPNsense(p.EnableRemoteCommands),
				LogRemoteCommands:    BoolToOPNsense(p.LogRemoteCommands),
				Encryption:           p.Encryption,
				EncryptionIdentity:   p.EncryptionIdentity,
				EncryptionPSK:        p.EncryptionPSK,
			},
		},
	}
}

// ConvertToOPNZabbixUserParameter converts a snippet payload to the wire shape.
func ConvertToOPNZabbixUserParameter(p APIZabbixUserParameterPayload) ZabbixUserParameter {
	return ZabbixUserParameter{
		Enabled:      BoolToOPNsense(p.Enabled),
		Key:          p.Key,
		Command:      p.Command,
		AcceptParams: BoolToOPNsense(p.AcceptParams),
	}
}

// ConvertToOPNZabbixAlias converts a snippet payload to the wire shape.
func ConvertToOPNZabbixAlias(p APIZabbixAliasPayload) ZabbixAlias {
	return ZabbixAlias{
		Enabled:      BoolToOPNsense(p.Enabled),
		Key:          p.Key,
		SourceKey:    p.SourceKey,
		AcceptParams: BoolToOPNsense(p.AcceptParams),
	}
}

// ConvertZabbixUserParameterToAPI converts a raw search-result row to the
// portable snippet shape.
func ConvertZabbixUserParameterToAPI(raw map[string]interface{}) APIZabbixUserParameterPayload {
	enabled, _ := raw["enabled"].(string)
	key, _ := raw["key"].(string)
	command, _ := raw["command"].(string)
	acceptParams, _ := raw["acceptParams"].(string)

	return APIZabbixUserParameterPayload{
		Enabled:      OPNsenseToBool(enabled),
		Key:          key,
		Command:      command,
		AcceptParams: OPNsenseToBool(acceptParams),
	}
}

// ConvertZabbixAliasToAPI converts a raw search-result row to the portable
// snippet shape.
func ConvertZabbixAliasToAPI(raw map[string]interface{}) APIZabbixAliasPayload {
	enabled, _ := raw["enabled"].(string)
	key, _ := raw["key"].(string)
	sourceKey, _ := raw["sourceKey"].(string)
	acceptParams, _ := raw["acceptParams"].(string)

	return APIZabbixAliasPayload{
		Enabled:      OPNsenseToBool(enabled),
		Key:          key,
		SourceKey:    sourceKey,
		AcceptParams: OPNsenseToBool(acceptParams),
	}
}
