package opnapi

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
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
		"":      "",
		"0":     "val_0",
		"3":     "val_3",
		"5":     "val_5",
		"val_2": "val_2",
		"bogus": "val_3", // safe default = warnings
		"42":    "val_3",
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
	if api.Enabled == nil || !*api.Enabled || api.Key != "nd-cpu" || api.Command != "sysctl -n hw.ncpu" || api.AcceptParams {
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
	if api.Enabled == nil || !*api.Enabled || api.Key != "nd-uname" || api.SourceKey != "system.uname" {
		t.Fatalf("roundtrip API mismatch: %+v", api)
	}
	wire := ConvertToOPNZabbixAlias(api)
	if wire.Enabled != "1" || wire.Key != "nd-uname" || wire.SourceKey != "system.uname" {
		t.Fatalf("roundtrip wire mismatch: %+v", wire)
	}
}

// A sparse snippet: the fields it gives win, every field it leaves out takes
// the value a fresh install of the plugin has (the operator's rule,
// 2026-11-12), and no Required field goes out empty.
func TestBuildZabbixSettings_LeftOutFieldsTakeThePluginDefaults(t *testing.T) {
	body := BuildZabbixSettings(APIZabbixSettingsPayload{
		Hostname:           "clarence",
		Enabled:            true,
		ServerList:         []string{"zbx.new.example.com"},
		Timeout:            "30",
		Encryption:         "1",
		EncryptionIdentity: "PSK_IDENTITY",
		EncryptionPSK:      "deadbeef",
	})
	m, tu, f := body.Settings.Main, body.Settings.Tuning, body.Settings.Features
	for name, got := range map[string][2]string{
		"hostname":   {body.Local.Hostname, "clarence"},
		"enabled":    {m.Enabled, "1"},
		"serverList": {m.ServerList, "zbx.new.example.com"},
		"timeout":    {tu.Timeout, "30"},
		"encryption": {f.Encryption, "1"},
		"psk":        {f.EncryptionPSK, "deadbeef"},
		// left out: the model's defaults
		"listenPort":          {m.ListenPort, "10050"},
		"listenIP":            {m.ListenIP, "0.0.0.0"},
		"logFileSize":         {m.LogFileSize, "100"},
		"debugLevel":          {m.DebugLevel, "val_3"},
		"startAgents":         {tu.StartAgents, "3"},
		"bufferSend":          {tu.BufferSend, "5"},
		"bufferSize":          {tu.BufferSize, "100"},
		"maxLinesPerSecond":   {tu.MaxLinesPerSecond, "100"},
		"refreshActiveChecks": {f.RefreshActiveChecks, "120"},
		"sourceIP":            {m.SourceIP, ""},
		"activeCheckServers":  {f.ActiveCheckServers, ""},
		"enableActiveChecks":  {f.EnableActiveChecks, "1"},
		"syslogEnable":        {m.SyslogEnable, "0"},
		"sudoRoot":            {m.SudoRoot, "0"},
		"remoteCommands":      {f.EnableRemoteCommands, "0"},
	} {
		if got[0] != got[1] {
			t.Errorf("%s = %q, want %q", name, got[0], got[1])
		}
	}

	if got := BuildZabbixSettings(APIZabbixSettingsPayload{}).Local.Hostname; got != "Zabbix agent" {
		t.Errorf("a snippet without a hostname gets the model's default, got %q", got)
	}
	if got := BuildZabbixSettings(APIZabbixSettingsPayload{EnableActiveChecks: new(false)}).Settings.Features.EnableActiveChecks; got != "0" {
		t.Errorf("enable_active_checks written false: got %q, want \"0\"", got)
	}
}

func TestBuildZabbixSettings_SnippetDebugLevelWins(t *testing.T) {
	if got := BuildZabbixSettings(APIZabbixSettingsPayload{DebugLevel: "1"}).Settings.Main.DebugLevel; got != "val_1" {
		t.Errorf("snippet debug_level=1: got %q, want val_1", got)
	}
}

// zabbixDefaultsByModelPath maps every field of the plugin's model to the body
// field zabbixSettingsDefaults fills, so a field the plugin adds fails here.
func zabbixDefaultsByModelPath(d ZabbixSettingsBody) map[string]string {
	m, tu, f := d.Settings.Main, d.Settings.Tuning, d.Settings.Features
	return map[string]string{
		"local.hostname":                         d.Local.Hostname,
		"settings.main.enabled":                  m.Enabled,
		"settings.main.serverList":               m.ServerList,
		"settings.main.listenPort":               m.ListenPort,
		"settings.main.listenIP":                 m.ListenIP,
		"settings.main.sourceIP":                 m.SourceIP,
		"settings.main.listenBacklog":            m.ListenBacklog,
		"settings.main.syslogEnable":             m.SyslogEnable,
		"settings.main.logFileSize":              m.LogFileSize,
		"settings.main.debugLevel":               ZabbixDebugLevelToWire(m.DebugLevel),
		"settings.main.sudoRoot":                 m.SudoRoot,
		"settings.tuning.startAgents":            tu.StartAgents,
		"settings.tuning.bufferSend":             tu.BufferSend,
		"settings.tuning.bufferSize":             tu.BufferSize,
		"settings.tuning.maxLinesPerSecond":      tu.MaxLinesPerSecond,
		"settings.tuning.timeout":                tu.Timeout,
		"settings.features.enableActiveChecks":   f.EnableActiveChecks,
		"settings.features.activeCheckServers":   f.ActiveCheckServers,
		"settings.features.refreshActiveChecks":  f.RefreshActiveChecks,
		"settings.features.enableRemoteCommands": f.EnableRemoteCommands,
		"settings.features.logRemoteCommands":    f.LogRemoteCommands,
		"settings.features.encryption":           f.Encryption,
		"settings.features.encryptionidentity":   f.EncryptionIdentity,
		"settings.features.encryptionpsk":        f.EncryptionPSK,
	}
}

// zabbixModelField is one field of the plugin's model: its path below <items>,
// its type and its <Default>.
type zabbixModelField struct {
	path, typ, def string
}

// zabbixModelFields reads the fields of the vendored copy of the plugin's model.
func zabbixModelFields(t *testing.T) []zabbixModelField {
	t.Helper()
	data, err := os.ReadFile("testdata/zabbix/ZabbixAgent.xml")
	if err != nil {
		t.Fatal(err)
	}
	var fields []zabbixModelField
	dec := xml.NewDecoder(bytes.NewReader(data))
	var stack []string
	var cur *zabbixModelField
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		switch e := tok.(type) {
		case xml.StartElement:
			stack = append(stack, e.Name.Local)
			for _, a := range e.Attr {
				if a.Name.Local == "type" && len(stack) > 2 && stack[1] == "items" {
					fields = append(fields, zabbixModelField{path: strings.Join(stack[2:], "."), typ: a.Value})
					cur = &fields[len(fields)-1]
				}
			}
		case xml.CharData:
			if cur != nil && len(stack) > 0 && stack[len(stack)-1] == "Default" {
				cur.def = strings.TrimSpace(string(e))
			}
		case xml.EndElement:
			if cur != nil && strings.Join(stack[2:], ".") == cur.path {
				cur = nil
			}
			stack = stack[:len(stack)-1]
		}
	}
	return fields
}

// What a snippet that gives nothing posts is the model's: every field holds the
// model's <Default>, a boolean without one being off and any other field
// without one empty. It reads the body BuildZabbixSettings sends, not the
// table, because a boolean the snippet leaves out is written by the conversion.
func TestZabbixSettingsDefaultsAreTheModels(t *testing.T) {
	fields := zabbixModelFields(t)
	ours := zabbixDefaultsByModelPath(BuildZabbixSettings(APIZabbixSettingsPayload{}))
	seen := 0
	for _, f := range fields {
		if !strings.HasPrefix(f.path, "local.") && !strings.HasPrefix(f.path, "settings.") {
			continue // the userparameter and alias lists, which other snippets own
		}
		seen++
		got, ok := ours[f.path]
		if !ok {
			t.Errorf("model field %s (%s) has no place in the defaults table", f.path, f.typ)
			continue
		}
		want := f.def
		if f.typ == "BooleanField" && want == "" {
			want = "0"
		}
		if got != want {
			t.Errorf("%s: default %q, want %q", f.path, got, want)
		}
	}
	if seen != len(ours) {
		t.Errorf("the model has %d settings fields, the table %d", seen, len(ours))
	}
}

// A field a userparameter or alias snippet leaves out is sent with the model's
// <Default>, and every boolean of the two entries is covered.
func TestZabbixEntryDefaultsAreTheModels(t *testing.T) {
	up := ConvertToOPNZabbixUserParameter(APIZabbixUserParameterPayload{Key: "nd-x", Command: "true"})
	al := ConvertToOPNZabbixAlias(APIZabbixAliasPayload{Key: "nd-x", SourceKey: "agent.ping"})
	sent := map[string]string{
		"userparameters.userparameter.enabled":      up.Enabled,
		"userparameters.userparameter.acceptParams": up.AcceptParams,
		"aliases.alias.enabled":                     al.Enabled,
		"aliases.alias.acceptParams":                al.AcceptParams,
	}
	seen := 0
	for _, f := range zabbixModelFields(t) {
		if f.typ != "BooleanField" || !(strings.HasPrefix(f.path, "userparameters.") || strings.HasPrefix(f.path, "aliases.")) {
			continue
		}
		seen++
		got, ok := sent[f.path]
		if !ok {
			t.Errorf("model field %s has no default in the conversion", f.path)
			continue
		}
		if got != f.def {
			t.Errorf("%s left out: sent %q, the model's default is %q", f.path, got, f.def)
		}
	}
	if seen != len(sent) {
		t.Errorf("the model has %d entry booleans, the test %d", seen, len(sent))
	}
}

func TestAPIError_IsNotFound(t *testing.T) {
	err404 := &APIError{StatusCode: 404, Body: "endpoint not found"}
	if !IsNotFound(err404) {
		t.Error("IsNotFound(404) should be true")
	}
	wrapped := fmt.Errorf("list zabbix: %w", err404)
	if !IsNotFound(wrapped) {
		t.Error("IsNotFound on wrapped 404 should be true")
	}
	err500 := &APIError{StatusCode: 500, Body: "internal"}
	if IsNotFound(err500) {
		t.Error("IsNotFound(500) should be false")
	}
	if IsNotFound(nil) {
		t.Error("IsNotFound(nil) should be false")
	}
	if IsNotFound(errors.New("plain")) {
		t.Error("IsNotFound on plain error should be false")
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

// The operator's rule (2026-11-12), at the snippet's JSON: a boolean the
// ZABBIX_SETTINGS snippet leaves out takes the plugin's fresh-install value,
// which is off for five of them, enabled included, and on for active checks.
func TestBuildZabbixSettings_ALeftOutBooleanTakesThePluginDefault(t *testing.T) {
	var p APIZabbixSettingsPayload
	if err := json.Unmarshal([]byte(`{"server_list":["zbx.example.com"]}`), &p); err != nil {
		t.Fatal(err)
	}
	body := BuildZabbixSettings(p)
	m, f := body.Settings.Main, body.Settings.Features
	for name, got := range map[string][2]string{
		"enabled":              {m.Enabled, "0"},
		"syslogEnable":         {m.SyslogEnable, "0"},
		"sudoRoot":             {m.SudoRoot, "0"},
		"enableActiveChecks":   {f.EnableActiveChecks, "1"},
		"enableRemoteCommands": {f.EnableRemoteCommands, "0"},
		"logRemoteCommands":    {f.LogRemoteCommands, "0"},
	} {
		if got[0] != got[1] {
			t.Errorf("%s left out of the snippet: got %q, want %q", name, got[0], got[1])
		}
	}
}

// The operator's rule (2026-11-12) for the userparameter and alias entries: a
// field the snippet leaves out takes the model's default, which is what adding
// the entry in the GUI gives it. enabled is on and acceptParams off; a value the
// snippet gives is sent as given.
func TestConvertZabbixEntries_ALeftOutFieldTakesTheModelDefault(t *testing.T) {
	for _, tt := range []struct {
		content           string
		enabled, accepted string
	}{
		{`{"key":"nd-x","command":"true","source_key":"agent.ping"}`, "1", "0"},
		{`{"key":"nd-x","command":"true","source_key":"agent.ping","enabled":false}`, "0", "0"},
		{`{"key":"nd-x","command":"true","source_key":"agent.ping","enabled":true,"accept_params":true}`, "1", "1"},
	} {
		var up APIZabbixUserParameterPayload
		var al APIZabbixAliasPayload
		if err := json.Unmarshal([]byte(tt.content), &up); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(tt.content), &al); err != nil {
			t.Fatal(err)
		}
		u, a := ConvertToOPNZabbixUserParameter(up), ConvertToOPNZabbixAlias(al)
		if u.Enabled != tt.enabled || u.AcceptParams != tt.accepted || a.Enabled != tt.enabled || a.AcceptParams != tt.accepted {
			t.Errorf("%s: userparameter %+v, alias %+v; want enabled %q, acceptParams %q", tt.content, u, a, tt.enabled, tt.accepted)
		}
	}
}

// A disabled entry the device holds is pulled as disabled, and synced back so.
func TestConvertZabbixEntries_ADisabledEntryRoundTrips(t *testing.T) {
	raw := map[string]interface{}{"enabled": "0", "key": "nd-x", "command": "true", "sourceKey": "agent.ping", "acceptParams": "0"}
	up, al := ConvertZabbixUserParameterToAPI(raw), ConvertZabbixAliasToAPI(raw)
	for name, b := range map[string][]byte{"userparameter": mustJSON(t, up), "alias": mustJSON(t, al)} {
		if !strings.Contains(string(b), `"enabled":false`) {
			t.Errorf("the pulled %s does not say it is disabled: %s", name, b)
		}
	}
	if u, a := ConvertToOPNZabbixUserParameter(up), ConvertToOPNZabbixAlias(al); u.Enabled != "0" || a.Enabled != "0" {
		t.Errorf("a disabled entry is synced back as userparameter %+v, alias %+v", u, a)
	}
}

func mustJSON(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A JSON null is a field left out: enable_active_checks null is on.
func TestBuildZabbixSettings_ANullIsLeftOut(t *testing.T) {
	var p APIZabbixSettingsPayload
	if err := json.Unmarshal([]byte(`{"enable_active_checks":null,"server_list":["zbx.example.com"]}`), &p); err != nil {
		t.Fatal(err)
	}
	if got := BuildZabbixSettings(p).Settings.Features.EnableActiveChecks; got != "1" {
		t.Errorf("enableActiveChecks = %q, want the default \"1\"", got)
	}
}
