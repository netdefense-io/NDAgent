package opnapi

import (
	"encoding/json"
	"testing"
)

func TestFilterManagedZabbixUserParameters(t *testing.T) {
	rows := []map[string]interface{}{
		{"uuid": "u1", "key": "nd-cpu-temp"},
		{"uuid": "u2", "key": "test.key.name"}, // admin-owned (no nd- prefix)
		{"uuid": "u3", "key": "nd-wan-bw"},
		{"uuid": "u4", "key": "vfs.fs.size"}, // admin-owned
	}

	managed := FilterManagedZabbixUserParameters(rows)
	if len(managed) != 2 {
		t.Fatalf("expected 2 managed userparameters, got %d", len(managed))
	}
	for _, r := range managed {
		k := r["key"].(string)
		if k != "nd-cpu-temp" && k != "nd-wan-bw" {
			t.Errorf("unexpected managed key: %s", k)
		}
	}
}

func TestFilterManagedZabbixAliases(t *testing.T) {
	rows := []map[string]interface{}{
		{"uuid": "a1", "key": "nd-uname"},
		{"uuid": "a2", "key": "testaliasitemkey"}, // admin-owned
		{"uuid": "a3", "key": "nd-cpu-load"},
	}

	managed := FilterManagedZabbixAliases(rows)
	if len(managed) != 2 {
		t.Fatalf("expected 2 managed aliases, got %d", len(managed))
	}
}

func TestZabbixDebugLevelToWire(t *testing.T) {
	cases := map[string]string{
		"":       "",
		"0":      "val_0",
		"3":      "val_3",
		"5":      "val_5",
		"val_2":  "val_2",
		"bogus":  "val_3", // safe default = warnings
		"42":     "val_3",
	}
	for in, want := range cases {
		if got := ZabbixDebugLevelToWire(in); got != want {
			t.Errorf("ZabbixDebugLevelToWire(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestZabbixDebugLevelFromGet(t *testing.T) {
	// Shape mirrors what /settings/get returns for the debugLevel Selection.
	raw := `{
        "val_0":{"value":"basic information (0)","selected":0},
        "val_1":{"value":"critical (1)","selected":0},
        "val_3":{"value":"warnings (3, default)","selected":1},
        "val_5":{"value":"extended debugging (5)","selected":0}
    }`
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	if got := ZabbixDebugLevelFromGet(m); got != "3" {
		t.Errorf("expected '3', got %q", got)
	}
}

func TestZabbixDebugLevelFromGet_NothingSelected(t *testing.T) {
	raw := `{"val_0":{"value":"x","selected":0},"val_1":{"value":"y","selected":0}}`
	var m map[string]interface{}
	_ = json.Unmarshal([]byte(raw), &m)
	if got := ZabbixDebugLevelFromGet(m); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestZabbixMultiSelectToCSV(t *testing.T) {
	raw := `{
        "zbxsrv.pki.red":{"value":"zbxsrv.pki.red","selected":1},
        "10.0.0.5":{"value":"10.0.0.5","selected":1},
        "192.168.1.1":{"value":"192.168.1.1","selected":0}
    }`
	var m map[string]interface{}
	_ = json.Unmarshal([]byte(raw), &m)
	got := ZabbixMultiSelectToCSV(m)

	// Map iteration order isn't stable — check membership instead of literal string.
	parts := map[string]bool{}
	for _, p := range splitCSV(got) {
		parts[p] = true
	}
	if !parts["zbxsrv.pki.red"] || !parts["10.0.0.5"] {
		t.Errorf("missing selected values; got %q", got)
	}
	if parts["192.168.1.1"] {
		t.Errorf("unselected value leaked into csv: %q", got)
	}
}

func TestConvertToOPNZabbixSettings_MultiValueAndDebugLevel(t *testing.T) {
	p := APIZabbixSettingsPayload{
		Hostname:           "nd-lab",
		Enabled:            true,
		ServerList:         []string{"zbxsrv.pki.red", "10.0.0.5"},
		ListenPort:         "32050",
		ListenIP:           []string{"0.0.0.0"},
		DebugLevel:         "3",
		ActiveCheckServers: []string{"zbxsrv.pki.red:32051"},
		Encryption:         "1",
		EncryptionIdentity: "ID",
		EncryptionPSK:      "deadbeef",
	}
	body := ConvertToOPNZabbixSettings(p)

	if body.Settings.Main.ServerList != "zbxsrv.pki.red,10.0.0.5" {
		t.Errorf("serverList not joined: %q", body.Settings.Main.ServerList)
	}
	if body.Settings.Main.DebugLevel != "val_3" {
		t.Errorf("debugLevel not converted to val_3: %q", body.Settings.Main.DebugLevel)
	}
	if body.Settings.Main.Enabled != "1" {
		t.Errorf("enabled bool->str failed: %q", body.Settings.Main.Enabled)
	}
	if body.Settings.Features.ActiveCheckServers != "zbxsrv.pki.red:32051" {
		t.Errorf("activeCheckServers not joined: %q", body.Settings.Features.ActiveCheckServers)
	}
	if body.Settings.Features.EncryptionPSK != "deadbeef" {
		t.Errorf("psk not preserved verbatim: %q", body.Settings.Features.EncryptionPSK)
	}
}

func TestConvertZabbixUserParameterRoundTrip(t *testing.T) {
	raw := map[string]interface{}{
		"uuid":         "u1",
		"enabled":      "1",
		"key":          "nd-cpu",
		"command":      "sysctl -n hw.ncpu",
		"acceptParams": "0",
	}
	api := ConvertZabbixUserParameterToAPI(raw)
	if !api.Enabled || api.Key != "nd-cpu" || api.Command != "sysctl -n hw.ncpu" || api.AcceptParams {
		t.Fatalf("roundtrip API mismatch: %+v", api)
	}
	wire := ConvertToOPNZabbixUserParameter(api)
	if wire.Enabled != "1" || wire.Key != "nd-cpu" || wire.AcceptParams != "0" {
		t.Fatalf("roundtrip wire mismatch: %+v", wire)
	}
}

func TestConvertZabbixAliasRoundTrip(t *testing.T) {
	raw := map[string]interface{}{
		"uuid":         "a1",
		"enabled":      "1",
		"key":          "nd-uname",
		"sourceKey":    "system.uname",
		"acceptParams": "0",
	}
	api := ConvertZabbixAliasToAPI(raw)
	if !api.Enabled || api.Key != "nd-uname" || api.SourceKey != "system.uname" {
		t.Fatalf("roundtrip API mismatch: %+v", api)
	}
	wire := ConvertToOPNZabbixAlias(api)
	if wire.Enabled != "1" || wire.Key != "nd-uname" || wire.SourceKey != "system.uname" {
		t.Fatalf("roundtrip wire mismatch: %+v", wire)
	}
}

// MergeZabbixSettings overlays a (possibly sparse) snippet payload onto the
// device's current settings. Snippet fields that are non-empty win; empty
// fields keep the device's current value.
//
// This is the regression guard for the "A value is required" 422 we saw
// against clarence during the first DEV smoke test: OPNsense marks several
// main/tuning fields Required="Y" and rejects empty strings, so a sparse
// snippet (admin only specified e.g. enabled + hostname + server_list)
// would fail without this overlay.
func TestMergeZabbixSettings_OverlaysOntoCurrent(t *testing.T) {
	// Shape mirrors the GET /api/zabbixagent/settings/get response.
	currentRaw := map[string]interface{}{
		"zabbixagent": map[string]interface{}{
			"local": map[string]interface{}{"hostname": "preexisting"},
			"settings": map[string]interface{}{
				"main": map[string]interface{}{
					"enabled":      "1",
					"serverList":   map[string]interface{}{"old.example.com": map[string]interface{}{"value": "old.example.com", "selected": float64(1)}},
					"listenPort":   "10050",
					"listenIP":     map[string]interface{}{"0.0.0.0": map[string]interface{}{"value": "0.0.0.0", "selected": float64(1)}},
					"sourceIP":     "",
					"listenBacklog": "",
					"syslogEnable": "0",
					"logFileSize":  "100",
					"debugLevel":   map[string]interface{}{"val_3": map[string]interface{}{"value": "warnings", "selected": float64(1)}},
					"sudoRoot":     "1",
				},
				"tuning": map[string]interface{}{
					"startAgents": "0", "bufferSend": "5", "bufferSize": "100",
					"maxLinesPerSecond": "100", "timeout": "30",
				},
				"features": map[string]interface{}{
					"enableActiveChecks":   "1",
					"activeCheckServers":   map[string]interface{}{"old.example.com:10051": map[string]interface{}{"value": "old.example.com:10051", "selected": float64(1)}},
					"refreshActiveChecks":  "120",
					"enableRemoteCommands": "0",
					"logRemoteCommands":    "0",
					"encryption":           "0",
					"encryptionidentity":   "",
					"encryptionpsk":        "",
				},
			},
		},
	}
	// Sparse snippet: admin only wants to flip a few fields, leaves the
	// rest empty on the wire. Before the overlay, this 422'd against
	// OPNsense because main.logFileSize / tuning.* came in as empty.
	snippet := APIZabbixSettingsPayload{
		Hostname:           "clarence",
		Enabled:            true,
		ServerList:         []string{"zbx.new.example.com"},
		Encryption:         "1",
		EncryptionIdentity: "PSK_IDENTITY",
		EncryptionPSK:      "deadbeef",
		// Everything else (tuning, logFileSize, debug_level, listen_port,
		// listen_ip, active_check_servers) intentionally omitted.
	}
	body := MergeZabbixSettings(snippet, currentRaw)

	// Snippet fields win
	if body.Local.Hostname != "clarence" {
		t.Errorf("hostname: want clarence, got %q", body.Local.Hostname)
	}
	if body.Settings.Main.ServerList != "zbx.new.example.com" {
		t.Errorf("serverList: want override, got %q", body.Settings.Main.ServerList)
	}
	if body.Settings.Features.EncryptionPSK != "deadbeef" {
		t.Errorf("encryptionpsk: want deadbeef, got %q", body.Settings.Features.EncryptionPSK)
	}

	// Current-device fallbacks fill the Required gaps
	if body.Settings.Main.LogFileSize != "100" {
		t.Errorf("logFileSize fallback: want 100, got %q", body.Settings.Main.LogFileSize)
	}
	if body.Settings.Tuning.StartAgents != "0" || body.Settings.Tuning.BufferSend != "5" ||
		body.Settings.Tuning.BufferSize != "100" || body.Settings.Tuning.MaxLinesPerSecond != "100" ||
		body.Settings.Tuning.Timeout != "30" {
		t.Errorf("tuning fallbacks not applied: %+v", body.Settings.Tuning)
	}
	if body.Settings.Main.ListenPort != "10050" {
		t.Errorf("listenPort fallback: want 10050, got %q", body.Settings.Main.ListenPort)
	}
	if body.Settings.Features.ActiveCheckServers != "old.example.com:10051" {
		t.Errorf("activeCheckServers fallback: want old.example.com:10051, got %q", body.Settings.Features.ActiveCheckServers)
	}

	// debugLevel from GET is "3" (bare digit); snippet didn't specify;
	// result must be val_3 (the option-key form OPNsense expects on POST).
	if body.Settings.Main.DebugLevel != "val_3" {
		t.Errorf("debugLevel: want val_3, got %q", body.Settings.Main.DebugLevel)
	}
}

func TestMergeZabbixSettings_SnippetDebugLevelWins(t *testing.T) {
	currentRaw := map[string]interface{}{
		"zabbixagent": map[string]interface{}{
			"local":    map[string]interface{}{"hostname": "h"},
			"settings": map[string]interface{}{
				"main": map[string]interface{}{
					"logFileSize": "100",
					"debugLevel":  map[string]interface{}{"val_5": map[string]interface{}{"selected": float64(1)}},
				},
				"tuning":   map[string]interface{}{"startAgents": "0", "bufferSend": "5", "bufferSize": "100", "maxLinesPerSecond": "100", "timeout": "30"},
				"features": map[string]interface{}{},
			},
		},
	}
	snippet := APIZabbixSettingsPayload{DebugLevel: "1"}
	body := MergeZabbixSettings(snippet, currentRaw)
	if body.Settings.Main.DebugLevel != "val_1" {
		t.Errorf("snippet debug_level=1 should win over current val_5, got %q", body.Settings.Main.DebugLevel)
	}
}

func TestZabbixWrapperKeys(t *testing.T) {
	// Wire-format guard: wrapper keys must match what OPNsense's getX templates
	// return. These constants live in struct tags — if someone renames them,
	// this test catches the drift via the marshalled JSON.
	upWrap := ZabbixUserParameterWrapper{UserParameter: ZabbixUserParameter{Key: "nd-x"}}
	b, _ := json.Marshal(upWrap)
	if !contains(b, `"userparameter":`) {
		t.Errorf("userparameter wrapper key wrong: %s", string(b))
	}
	alWrap := ZabbixAliasWrapper{Alias: ZabbixAlias{Key: "nd-x"}}
	b, _ = json.Marshal(alWrap)
	if !contains(b, `"alias":`) {
		t.Errorf("alias wrapper key wrong: %s", string(b))
	}
	stWrap := ZabbixSettingsWrapper{ZabbixAgent: ZabbixSettingsBody{Local: ZabbixLocal{Hostname: "h"}}}
	b, _ = json.Marshal(stWrap)
	if !contains(b, `"zabbixagent":`) {
		t.Errorf("settings wrapper key wrong: %s", string(b))
	}
}

// --- small helpers (avoid pulling extra deps just for tests) ---

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

func contains(haystack []byte, needle string) bool {
	return indexOf(string(haystack), needle) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
