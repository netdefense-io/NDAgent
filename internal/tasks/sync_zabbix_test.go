package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

func TestParseAPIZabbixSettings_Singleton(t *testing.T) {
	payload := map[string]interface{}{
		"snippets": []interface{}{
			map[string]interface{}{"config_type": "RULE", "content": `{"uuid":"221f3268-x"}`},
			map[string]interface{}{
				"config_type":   "ZABBIX_SETTINGS",
				"template_name": []interface{}{"baseline"},
				"content":       `{"hostname":"murphy01","enabled":true,"server_list":["zbx.example.com"],"encryption":"1","encryption_psk":"abc","debug_level":"3"}`,
			},
		},
	}

	settings, err := parseAPIZabbixSettings(payload)
	if err != nil {
		t.Fatalf("parseAPIZabbixSettings failed: %v", err)
	}
	if settings == nil {
		t.Fatal("expected settings, got nil")
	}
	if settings.Hostname != "murphy01" || !settings.Enabled {
		t.Errorf("settings mismatch: %+v", settings)
	}
	if settings.DebugLevel != "3" || settings.EncryptionPSK != "abc" {
		t.Errorf("settings field mismatch: %+v", settings)
	}
	if len(settings.Templates) != 1 || settings.Templates[0] != "baseline" {
		t.Errorf("templates not captured: %+v", settings.Templates)
	}
}

func TestParseAPIZabbixSettings_LastWins(t *testing.T) {
	// Two ZABBIX_SETTINGS snippets — last one wins (same precedence as the
	// underlying /settings/set replace behaviour).
	payload := map[string]interface{}{
		"snippets": []interface{}{
			map[string]interface{}{
				"config_type": "ZABBIX_SETTINGS",
				"content":     `{"hostname":"first"}`,
			},
			map[string]interface{}{
				"config_type": "ZABBIX_SETTINGS",
				"content":     `{"hostname":"second"}`,
			},
		},
	}
	settings, err := parseAPIZabbixSettings(payload)
	if err != nil {
		t.Fatal(err)
	}
	if settings.Hostname != "second" {
		t.Errorf("expected last-wins, got %q", settings.Hostname)
	}
}

func TestParseAPIZabbixSettings_NoneReturnsNil(t *testing.T) {
	payload := map[string]interface{}{
		"snippets": []interface{}{
			map[string]interface{}{"config_type": "RULE", "content": `{"uuid":"x"}`},
		},
	}
	settings, err := parseAPIZabbixSettings(payload)
	if err != nil {
		t.Fatal(err)
	}
	if settings != nil {
		t.Errorf("expected nil, got %+v", settings)
	}
}

func TestParseAPIZabbixUserParameters(t *testing.T) {
	payload := map[string]interface{}{
		"snippets": []interface{}{
			map[string]interface{}{
				"config_type": "ZABBIX_USERPARAMETER",
				"content":     `{"key":"nd-cpu-temp","command":"sysctl -n dev.cpu.0.temperature","enabled":true}`,
			},
			map[string]interface{}{
				"config_type": "ZABBIX_USERPARAMETER",
				"content":     `{"key":"nd-wan-bw","command":"netstat -ibn","enabled":false}`,
			},
			map[string]interface{}{
				// Different type — must be ignored.
				"config_type": "ZABBIX_ALIAS",
				"content":     `{"key":"nd-uname","source_key":"system.uname"}`,
			},
		},
	}

	ups, err := parseAPIZabbixUserParameters(payload)
	if err != nil {
		t.Fatalf("parseAPIZabbixUserParameters failed: %v", err)
	}
	if len(ups) != 2 {
		t.Fatalf("expected 2 userparameters, got %d", len(ups))
	}
	if ups[0].Key != "nd-cpu-temp" || ups[0].Enabled == nil || !*ups[0].Enabled {
		t.Errorf("up[0] mismatch: %+v", ups[0])
	}
	if ups[1].Key != "nd-wan-bw" || ups[1].Enabled == nil || *ups[1].Enabled {
		t.Errorf("up[1] mismatch: %+v", ups[1])
	}
}

func TestParseAPIZabbixUserParameters_MissingKey(t *testing.T) {
	payload := map[string]interface{}{
		"snippets": []interface{}{
			map[string]interface{}{
				"config_type": "ZABBIX_USERPARAMETER",
				"content":     `{"command":"date","enabled":true}`,
			},
		},
	}
	_, err := parseAPIZabbixUserParameters(payload)
	if err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestParseAPIZabbixAliases(t *testing.T) {
	payload := map[string]interface{}{
		"snippets": []interface{}{
			map[string]interface{}{
				"config_type": "ZABBIX_ALIAS",
				"content":     `{"key":"nd-uname","source_key":"system.uname","enabled":true}`,
			},
		},
	}

	aliases, err := parseAPIZabbixAliases(payload)
	if err != nil {
		t.Fatalf("parseAPIZabbixAliases failed: %v", err)
	}
	if len(aliases) != 1 {
		t.Fatalf("expected 1 alias, got %d", len(aliases))
	}
	if aliases[0].Key != "nd-uname" || aliases[0].SourceKey != "system.uname" {
		t.Errorf("alias mismatch: %+v", aliases[0])
	}
}

func TestValidateZabbixManagedKey(t *testing.T) {
	cases := map[string]bool{
		"nd-cpu":        true,
		"nd-foo-bar":    true,
		"test.key.name": false, // admin-owned, no prefix → must fail
		"vfs.fs.size":   false,
		"":              false,
		"prefix-nd-foo": false, // prefix must be at start
	}
	for key, shouldPass := range cases {
		err := validateZabbixManagedKey(key)
		if shouldPass && err != nil {
			t.Errorf("validateZabbixManagedKey(%q) failed unexpectedly: %v", key, err)
		}
		if !shouldPass && err == nil {
			t.Errorf("validateZabbixManagedKey(%q) should have failed", key)
		}
	}
}

func TestParseAPIZabbixSettings_InvalidJSON(t *testing.T) {
	payload := map[string]interface{}{
		"snippets": []interface{}{
			map[string]interface{}{
				"config_type": "ZABBIX_SETTINGS",
				"content":     `not json`,
			},
		},
	}
	_, err := parseAPIZabbixSettings(payload)
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestZabbixParsersIgnoreOtherTypes(t *testing.T) {
	// All three Zabbix parsers must return nil/empty when only non-Zabbix
	// snippets are present.
	payload := map[string]interface{}{
		"snippets": []interface{}{
			map[string]interface{}{"config_type": "RULE", "content": `{"uuid":"221f3268-x"}`},
			map[string]interface{}{"config_type": "UNBOUND_HOST_OVERRIDE", "content": `{"uuid":"221f3268-y","hostname":"h","domain":"d"}`},
		},
	}
	settings, err := parseAPIZabbixSettings(payload)
	if err != nil || settings != nil {
		t.Errorf("zabbix settings parser leaked: settings=%+v err=%v", settings, err)
	}
	ups, err := parseAPIZabbixUserParameters(payload)
	if err != nil || len(ups) != 0 {
		t.Errorf("zabbix up parser leaked: ups=%+v err=%v", ups, err)
	}
	aliases, err := parseAPIZabbixAliases(payload)
	if err != nil || len(aliases) != 0 {
		t.Errorf("zabbix alias parser leaked: aliases=%+v err=%v", aliases, err)
	}
}

// zabbixDeviceSettings serves a device whose every setting differs from what
// the tests' snippets ask for. The sync reads it only to tell whether a write
// is needed, and must never carry a device value into what it posts.
func zabbixDeviceSettings(w http.ResponseWriter, r *http.Request) {
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"zabbixagent": map[string]interface{}{
		"local": map[string]interface{}{"hostname": "device-own-name"},
		"settings": map[string]interface{}{
			"main": map[string]interface{}{
				"enabled": "1", "serverList": "192.0.2.50", "listenPort": "20050", "listenIP": "192.0.2.1",
				"sourceIP": "192.0.2.1", "listenBacklog": "7", "syslogEnable": "1", "logFileSize": "9",
				"debugLevel": map[string]interface{}{"val_5": map[string]interface{}{"value": "extended debugging (5)", "selected": 1}},
				"sudoRoot":   "1",
			},
			"tuning": map[string]interface{}{
				"startAgents": "9", "bufferSend": "9", "bufferSize": "9", "maxLinesPerSecond": "9", "timeout": "9",
			},
			"features": map[string]interface{}{
				"enableActiveChecks": "0", "activeCheckServers": "192.0.2.50", "refreshActiveChecks": "60",
				"enableRemoteCommands": "1", "logRemoteCommands": "1", "encryption": "1",
				"encryptionidentity": "device", "encryptionpsk": "device",
			},
		},
	}})
}

// newZabbixTestServer stands up a fake OPNsense zabbixagent API sufficient
// for executeSyncZabbix's happy path: empty search results (no pre-existing
// managed rows), a device whose settings differ from every snippet
// (zabbixDeviceSettings), and every mutating endpoint succeeds. Returns the
// client plus counters/capture slices tests assert on.
func newZabbixTestServer(t *testing.T) (client *opnapi.Client, setSettingsCalls *int, addedUserParamKeys *[]string, reconfigureCalls *int) {
	t.Helper()
	var setCalls int
	var ups []string
	var reconfigures int

	mux := http.NewServeMux()
	mux.HandleFunc("/zabbixagent/settings/searchUserparameters/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{})
	})
	mux.HandleFunc("/zabbixagent/settings/searchAliases/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{})
	})
	mux.HandleFunc("/zabbixagent/settings/get", zabbixDeviceSettings)
	mux.HandleFunc("/zabbixagent/settings/set", func(w http.ResponseWriter, r *http.Request) {
		setCalls++
		_ = json.NewEncoder(w).Encode(opnapi.SetZabbixResponse{Result: "saved"})
	})
	mux.HandleFunc("/zabbixagent/settings/addUserparameter", func(w http.ResponseWriter, r *http.Request) {
		var wrapper opnapi.ZabbixUserParameterWrapper
		_ = json.NewDecoder(r.Body).Decode(&wrapper)
		ups = append(ups, wrapper.UserParameter.Key)
		_ = json.NewEncoder(w).Encode(opnapi.SetZabbixResponse{Result: "saved", UUID: "up-" + wrapper.UserParameter.Key})
	})
	mux.HandleFunc("/zabbixagent/service/reconfigure", func(w http.ResponseWriter, r *http.Request) {
		reconfigures++
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return opnapi.NewClient(server.URL, "key", "secret", true), &setCalls, &ups, &reconfigures
}

// TestExecuteSyncZabbix_DangerousUserParameterCommandGate is the revert
// guard for the ZABBIX_USERPARAMETER half of the device-local dangerous-
// field gate. With the gate off, a userparameter carrying a command is applied as
// today. With the gate on, it's rejected (never reaches addUserparameter)
// while an unrelated safe userparameter (empty command) in the same sync is
// still applied.
func TestExecuteSyncZabbix_DangerousUserParameterCommandGate(t *testing.T) {
	safe := opnapi.APIZabbixUserParameterPayload{Key: "nd-safe-check", Command: ""}
	dangerous := opnapi.APIZabbixUserParameterPayload{Key: "nd-dangerous-check", Command: "rm -rf /tmp/x"}

	for _, rejectDangerous := range []bool{false, true} {
		t.Run(fmt.Sprintf("reject=%v", rejectDangerous), func(t *testing.T) {
			client, _, addedKeys, _ := newZabbixTestServer(t)

			result := executeSyncZabbix(context.Background(), client, nil,
				[]opnapi.APIZabbixUserParameterPayload{safe, dangerous}, nil, rejectDangerous)

			if rejectDangerous {
				if result.Success {
					t.Error("expected failure: a dangerous-field rejection must fail the task")
				}
			} else if !result.Success {
				t.Errorf("expected success (gate off, nothing rejected), got errors: %+v", result.Errors)
			}

			var wantKeys []string
			if rejectDangerous {
				wantKeys = []string{safe.Key}
			} else {
				wantKeys = []string{safe.Key, dangerous.Key}
			}
			if got, want := sortedCopy(*addedKeys), sortedCopy(wantKeys); fmt.Sprint(got) != fmt.Sprint(want) {
				t.Errorf("addUserparameter calls = %v, want %v", got, want)
			}

			var rejected []string
			for _, r := range result.Results {
				if r.Action == "rejected" {
					rejected = append(rejected, r.Name)
				}
			}
			if rejectDangerous {
				if fmt.Sprint(rejected) != fmt.Sprint([]string{dangerous.Key}) {
					t.Errorf("rejected results = %v, want [%s]", rejected, dangerous.Key)
				}
			} else if len(rejected) != 0 {
				t.Errorf("gate off must never produce a rejected result, got %v", rejected)
			}
		})
	}
}

// TestExecuteSyncZabbix_DangerousSettingsFieldGate is the revert guard for
// the ZABBIX_SETTINGS half of the gate: enable_remote_commands and
// sudo_root each individually trigger rejection when the gate is on, and
// leave settings/set unhit; with the gate off, settings/set is called as
// today.
func TestExecuteSyncZabbix_DangerousSettingsFieldGate(t *testing.T) {
	tests := []struct {
		name     string
		settings opnapi.APIZabbixSettingsPayload
	}{
		{"enable_remote_commands", opnapi.APIZabbixSettingsPayload{Hostname: "fw1", ServerList: []string{"zbx.example.com"}, EnableRemoteCommands: true}},
		{"sudo_root", opnapi.APIZabbixSettingsPayload{Hostname: "fw1", ServerList: []string{"zbx.example.com"}, SudoRoot: true}},
	}

	for _, tt := range tests {
		for _, rejectDangerous := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/reject=%v", tt.name, rejectDangerous), func(t *testing.T) {
				client, setCalls, _, _ := newZabbixTestServer(t)

				settings := tt.settings
				result := executeSyncZabbix(context.Background(), client, &settings, nil, nil, rejectDangerous)

				if rejectDangerous {
					if result.Success {
						t.Error("expected failure: a dangerous-field rejection must fail the task")
					}
				} else if !result.Success {
					t.Errorf("expected success (gate off, nothing rejected), got errors: %+v", result.Errors)
				}

				wantSetCalls := 1
				if rejectDangerous {
					wantSetCalls = 0
				}
				if *setCalls != wantSetCalls {
					t.Errorf("settings/set calls = %d, want %d", *setCalls, wantSetCalls)
				}

				var rejected []string
				for _, r := range result.Results {
					if r.Action == "rejected" {
						rejected = append(rejected, r.Name)
					}
				}
				if rejectDangerous {
					if len(rejected) != 1 || rejected[0] != tt.settings.Hostname {
						t.Errorf("rejected results = %v, want [%s]", rejected, tt.settings.Hostname)
					}
				} else if len(rejected) != 0 {
					t.Errorf("gate off must never produce a rejected result, got %v", rejected)
				}
			})
		}
	}
}

// TestExecuteSyncZabbix_ServerListNotConstrained confirms server_list is
// never treated as dangerous, even off-LAN — a legitimate MSSP monitoring
// deployment. The gate must not reject on server_list alone.
func TestExecuteSyncZabbix_ServerListNotConstrained(t *testing.T) {
	client, setCalls, _, _ := newZabbixTestServer(t)

	settings := opnapi.APIZabbixSettingsPayload{
		Hostname:   "fw1",
		ServerList: []string{"monitor.mssp.example.com"},
	}
	result := executeSyncZabbix(context.Background(), client, &settings, nil, nil, true /* gate on */)

	if !result.Success {
		t.Errorf("expected success, got errors: %+v", result.Errors)
	}
	if *setCalls != 1 {
		t.Errorf("settings/set calls = %d, want 1 (off-LAN server_list alone must not be rejected)", *setCalls)
	}
	for _, r := range result.Results {
		if r.Action == "rejected" {
			t.Errorf("unexpected rejection for server_list-only settings: %+v", r)
		}
	}
}

// TestExecuteSyncZabbix_RejectOnlySyncDoesNotReconfigure locks the "no
// service bounce" half of the dangerous-field gate's safety contract: a
// sync whose only Zabbix change is a rejected element must never call
// ReconfigureZabbix. The "touched" gate in executeSyncZabbix only flips to
// true on a Status=="success" result, and a rejection is recorded with
// Status=="blocked" — this test fails if that ever regresses (e.g. a
// rejection being miscounted as a change).
func TestExecuteSyncZabbix_RejectOnlySyncDoesNotReconfigure(t *testing.T) {
	client, _, addedKeys, reconfigureCalls := newZabbixTestServer(t)

	dangerous := opnapi.APIZabbixUserParameterPayload{Key: "nd-dangerous-check", Command: "rm -rf /tmp/x"}

	result := executeSyncZabbix(context.Background(), client, nil,
		[]opnapi.APIZabbixUserParameterPayload{dangerous}, nil, true /* gate on */)

	if result.Success {
		t.Error("expected failure: a dangerous-field rejection must fail the task")
	}
	if len(*addedKeys) != 0 {
		t.Errorf("expected no addUserparameter calls, got %v", *addedKeys)
	}
	if *reconfigureCalls != 0 {
		t.Errorf("expected zero ReconfigureZabbix calls on a reject-only sync, got %d", *reconfigureCalls)
	}

	var rejected []string
	for _, r := range result.Results {
		if r.Action == "rejected" {
			rejected = append(rejected, r.Name)
		}
	}
	if fmt.Sprint(rejected) != fmt.Sprint([]string{dangerous.Key}) {
		t.Errorf("rejected results = %v, want [%s]", rejected, dangerous.Key)
	}
}

// TestExecuteSyncZabbix_DangerousUserParameterRejectionDoesNotOrphanDeletePreExisting
// is the ZABBIX_USERPARAMETER counterpart of the USER/GROUP orphan-delete
// regression test in sync_api_test.go: a pre-existing managed userparameter
// must survive a sync where the only desired element with that key is
// rejected for carrying a dangerous `command`. desiredKeys[up.Key] is set
// before the dangerous-field check runs, which is what keeps the rejected
// key out of the delete-orphans loop below — this test fails if that
// ordering ever regresses.
func TestExecuteSyncZabbix_DangerousUserParameterRejectionDoesNotOrphanDeletePreExisting(t *testing.T) {
	var deleteCalls []string
	var reconfigureCalls int

	mux := http.NewServeMux()
	mux.HandleFunc("/zabbixagent/settings/searchUserparameters/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{
			Rows: []map[string]interface{}{
				{
					"uuid": "up-uuid-1",
					"key":  "nd-dangerous-check",
				},
			},
			RowCount: 1,
			Total:    1,
		})
	})
	mux.HandleFunc("/zabbixagent/settings/searchAliases/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{})
	})
	mux.HandleFunc("/zabbixagent/settings/delUserparameter/", func(w http.ResponseWriter, r *http.Request) {
		deleteCalls = append(deleteCalls, r.URL.Path)
		_ = json.NewEncoder(w).Encode(opnapi.APIResult{Result: "deleted"})
	})
	mux.HandleFunc("/zabbixagent/service/reconfigure", func(w http.ResponseWriter, r *http.Request) {
		reconfigureCalls++
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	// add/set handlers are wired defensively: if a regression let the
	// rejected element through, the test fails on a clean "wrong calls
	// happened" assertion rather than a 404 from an unhandled route.
	mux.HandleFunc("/zabbixagent/settings/addUserparameter", func(w http.ResponseWriter, r *http.Request) {
		var wrapper opnapi.ZabbixUserParameterWrapper
		_ = json.NewDecoder(r.Body).Decode(&wrapper)
		_ = json.NewEncoder(w).Encode(opnapi.SetZabbixResponse{Result: "saved", UUID: "up-" + wrapper.UserParameter.Key})
	})
	mux.HandleFunc("/zabbixagent/settings/setUserparameter/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SetZabbixResponse{Result: "saved"})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := opnapi.NewClient(server.URL, "key", "secret", true)

	// Same key as the pre-existing managed row above; carries a command so
	// the gate rejects it.
	dangerous := opnapi.APIZabbixUserParameterPayload{Key: "nd-dangerous-check", Command: "rm -rf /tmp/x"}

	result := executeSyncZabbix(context.Background(), client, nil,
		[]opnapi.APIZabbixUserParameterPayload{dangerous}, nil, true /* gate on */)

	if result.Success {
		t.Error("expected failure: a dangerous-field rejection must fail the task")
	}
	if len(deleteCalls) != 0 {
		t.Errorf("expected no delUserparameter calls, got %v (pre-existing managed userparameter with a rejected dangerous field must survive the sync)", deleteCalls)
	}
	if reconfigureCalls != 0 {
		t.Errorf("expected zero ReconfigureZabbix calls, got %d", reconfigureCalls)
	}

	var rejected []string
	for _, r := range result.Results {
		if r.Action == "rejected" {
			rejected = append(rejected, r.Name)
		}
	}
	if fmt.Sprint(rejected) != fmt.Sprint([]string{dangerous.Key}) {
		t.Errorf("rejected results = %v, want [%s]", rejected, dangerous.Key)
	}
}

// The operator's rule (2026-11-12): a field the ZABBIX_SETTINGS snippet leaves
// out takes the plugin's default, so SYNC posts defaults for it. The device it
// reads to compare holds other values everywhere, and none of them may reach
// the body: the whole posted tree is the built one.
func TestSyncZabbix_LeftOutFieldsTakeThePluginDefaults(t *testing.T) {
	var posted map[string]map[string]interface{}
	mux := http.NewServeMux()
	mux.HandleFunc("/zabbixagent/settings/searchUserparameters/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{})
	})
	mux.HandleFunc("/zabbixagent/settings/searchAliases/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{})
	})
	mux.HandleFunc("/zabbixagent/settings/get", zabbixDeviceSettings)
	mux.HandleFunc("/zabbixagent/settings/set", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&posted)
		_ = json.NewEncoder(w).Encode(opnapi.SetZabbixResponse{Result: "saved"})
	})
	mux.HandleFunc("/zabbixagent/service/reconfigure", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	client := opnapi.NewClient(server.URL, "key", "secret", true)

	settings, err := parseAPIZabbixSettings(map[string]interface{}{"snippets": []interface{}{
		map[string]interface{}{"config_type": "ZABBIX_SETTINGS", "content": `{"server_list":["zbx.example.com"]}`},
	}})
	if err != nil || settings == nil {
		t.Fatalf("parse: %v %v", settings, err)
	}
	if result := executeSyncZabbix(context.Background(), client, settings, nil, nil, false); !result.Success {
		t.Fatalf("sync failed: %+v", result.Errors)
	}
	built, _ := json.Marshal(map[string]interface{}{"zabbixagent": opnapi.BuildZabbixSettings(*settings)})
	var want map[string]map[string]interface{}
	_ = json.Unmarshal(built, &want)
	if !reflect.DeepEqual(posted, want) {
		t.Errorf("posted %v, want exactly the built body %v", posted, want)
	}
	local, _ := posted["zabbixagent"]["local"].(map[string]interface{})
	s, _ := posted["zabbixagent"]["settings"].(map[string]interface{})
	main, _ := s["main"].(map[string]interface{})
	tuning, _ := s["tuning"].(map[string]interface{})
	features, _ := s["features"].(map[string]interface{})
	for name, got := range map[string][2]interface{}{
		"hostname":           {local["hostname"], "Zabbix agent"},
		"serverList":         {main["serverList"], "zbx.example.com"},
		"listenPort":         {main["listenPort"], "10050"},
		"enabled":            {main["enabled"], "0"},
		"timeout":            {tuning["timeout"], "3"},
		"enableActiveChecks": {features["enableActiveChecks"], "1"},
	} {
		if got[0] != got[1] {
			t.Errorf("posted %s = %v, want %v", name, got[0], got[1])
		}
	}
}

// A userparameter or alias snippet without `enabled` adds an entry that runs,
// as adding it in the GUI does; one that says false adds a disabled entry.
func TestSyncZabbix_AnEntryLeftWithoutEnabledIsOn(t *testing.T) {
	added := map[string]map[string]interface{}{}
	mux := http.NewServeMux()
	for _, list := range []string{"searchUserparameters", "searchAliases"} {
		mux.HandleFunc("/zabbixagent/settings/"+list+"/", func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(opnapi.SearchResponse{})
		})
	}
	for _, add := range []string{"addUserparameter", "addAlias"} {
		mux.HandleFunc("/zabbixagent/settings/"+add, func(w http.ResponseWriter, r *http.Request) {
			var body map[string]map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			for _, entry := range body {
				added[entry["key"].(string)] = entry
			}
			_ = json.NewEncoder(w).Encode(opnapi.SetZabbixResponse{Result: "saved", UUID: "u-" + addedKey(body)})
		})
	}
	mux.HandleFunc("/zabbixagent/service/reconfigure", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	client := opnapi.NewClient(server.URL, "key", "secret", true)

	payload := map[string]interface{}{"snippets": []interface{}{
		map[string]interface{}{"config_type": "ZABBIX_USERPARAMETER", "content": `{"key":"nd-on","command":"uptime"}`},
		map[string]interface{}{"config_type": "ZABBIX_USERPARAMETER", "content": `{"key":"nd-off","command":"uptime","enabled":false}`},
		map[string]interface{}{"config_type": "ZABBIX_ALIAS", "content": `{"key":"nd-ping","source_key":"agent.ping"}`},
	}}
	ups, err := parseAPIZabbixUserParameters(payload)
	if err != nil {
		t.Fatal(err)
	}
	aliases, err := parseAPIZabbixAliases(payload)
	if err != nil {
		t.Fatal(err)
	}
	if result := executeSyncZabbix(context.Background(), client, nil, ups, aliases, false); !result.Success {
		t.Fatalf("sync failed: %+v", result.Errors)
	}
	for key, want := range map[string]string{"nd-on": "1", "nd-off": "0", "nd-ping": "1"} {
		if got := added[key]["enabled"]; got != want {
			t.Errorf("%s added with enabled %v, want %q", key, got, want)
		}
	}
}

func addedKey(body map[string]map[string]interface{}) string {
	for _, e := range body {
		key, _ := e["key"].(string)
		return key
	}
	return ""
}

// zabbixNoopServer is a device holding settings, one userparameter and one
// alias; it counts every write and reconfigure.
type zabbixNoopServer struct {
	settings  map[string]interface{}
	upRow     map[string]interface{}
	aliasRow  map[string]interface{}
	writes    []string
	bodies    []string
	reconfigs int
	client    *opnapi.Client
}

func newZabbixNoopServer(t *testing.T, settings map[string]interface{}, upRow, aliasRow map[string]interface{}) *zabbixNoopServer {
	t.Helper()
	s := &zabbixNoopServer{settings: settings, upRow: upRow, aliasRow: aliasRow}
	mux := http.NewServeMux()
	rows := func(row map[string]interface{}) opnapi.SearchResponse {
		if row == nil {
			return opnapi.SearchResponse{}
		}
		return opnapi.SearchResponse{Rows: []map[string]interface{}{row}}
	}
	mux.HandleFunc("/zabbixagent/settings/searchUserparameters/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(rows(s.upRow))
	})
	mux.HandleFunc("/zabbixagent/settings/searchAliases/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(rows(s.aliasRow))
	})
	mux.HandleFunc("/zabbixagent/settings/get", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(s.settings)
	})
	saved := func(name string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			s.writes = append(s.writes, name)
			var body map[string]map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			for _, fields := range body {
				for _, key := range []string{"command", "sourceKey"} {
					if v, ok := fields[key].(string); ok {
						s.bodies = append(s.bodies, v)
					}
				}
			}
			_ = json.NewEncoder(w).Encode(opnapi.SetZabbixResponse{Result: "saved"})
		}
	}
	mux.HandleFunc("/zabbixagent/settings/set", saved("settings"))
	mux.HandleFunc("/zabbixagent/settings/setUserparameter/", saved("userparameter"))
	mux.HandleFunc("/zabbixagent/settings/setAlias/", saved("alias"))
	mux.HandleFunc("/zabbixagent/service/reconfigure", func(w http.ResponseWriter, r *http.Request) {
		s.reconfigs++
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	s.client = opnapi.NewClient(server.URL, "key", "secret", true)
	return s
}

// A sync whose settings, userparameter and alias are already on the device
// writes nothing and says each is unchanged; a change in any one is written
// (#195). Both reconfigure: a reconfigure that failed after an earlier write is
// only ever retried by the next sync.
func TestSyncZabbix_WhatIsAlreadyOnTheDeviceIsNotWritten(t *testing.T) {
	payload := map[string]interface{}{"snippets": []interface{}{
		map[string]interface{}{"config_type": "ZABBIX_SETTINGS", "content": `{"hostname":"fw1","server_list":["zbx.example.com"]}`},
		map[string]interface{}{"config_type": "ZABBIX_USERPARAMETER", "content": `{"key":"nd-cpu","command":"sysctl -n hw.ncpu"}`},
		map[string]interface{}{"config_type": "ZABBIX_ALIAS", "content": `{"key":"nd-ping","source_key":"agent.ping"}`},
	}}
	settings, err := parseAPIZabbixSettings(payload)
	if err != nil {
		t.Fatal(err)
	}
	ups, err := parseAPIZabbixUserParameters(payload)
	if err != nil {
		t.Fatal(err)
	}
	aliases, err := parseAPIZabbixAliases(payload)
	if err != nil {
		t.Fatal(err)
	}
	asStored := func() (map[string]interface{}, map[string]interface{}, map[string]interface{}) {
		body, _ := json.Marshal(map[string]interface{}{"zabbixagent": opnapi.BuildZabbixSettings(*settings)})
		var live map[string]interface{}
		_ = json.Unmarshal(body, &live)
		return live,
			map[string]interface{}{"uuid": "u1", "enabled": "1", "key": "nd-cpu", "command": "sysctl -n hw.ncpu", "acceptParams": "0"},
			map[string]interface{}{"uuid": "a1", "enabled": "1", "key": "nd-ping", "sourceKey": "agent.ping", "acceptParams": "0"}
	}

	live, upRow, aliasRow := asStored()
	s := newZabbixNoopServer(t, live, upRow, aliasRow)
	result := executeSyncZabbix(context.Background(), s.client, settings, ups, aliases, false)
	if !result.Success {
		t.Fatalf("sync failed: %+v", result.Errors)
	}
	if len(s.writes) != 0 {
		t.Errorf("an unchanged device was written %v", s.writes)
	}
	if s.reconfigs != 1 {
		t.Errorf("reconfigured %d times, want once: a reconfigure owed by an earlier sync must still run", s.reconfigs)
	}
	for _, item := range result.Results {
		if item.Action != "unchanged" || item.Status != "success" {
			t.Errorf("item %s %s: %s/%s, want unchanged/success", item.Type, item.Name, item.Action, item.Status)
		}
	}

	for _, tc := range []struct {
		name   string
		change func(settings, up, alias map[string]interface{})
		write  string
	}{
		{"settings", func(st, _, _ map[string]interface{}) {
			st["zabbixagent"].(map[string]interface{})["local"].(map[string]interface{})["hostname"] = "other"
		}, "settings"},
		{"userparameter", func(_, up, _ map[string]interface{}) { up["command"] = "sysctl -n hw.ncpu.old" }, "userparameter"},
		{"alias", func(_, _, alias map[string]interface{}) { alias["enabled"] = "0" }, "alias"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			live, upRow, aliasRow := asStored()
			tc.change(live, upRow, aliasRow)
			s := newZabbixNoopServer(t, live, upRow, aliasRow)
			if result := executeSyncZabbix(context.Background(), s.client, settings, ups, aliases, false); !result.Success {
				t.Fatalf("sync failed: %+v", result.Errors)
			}
			if len(s.writes) != 1 || s.writes[0] != tc.write || s.reconfigs != 1 {
				t.Errorf("writes %v, reconfigures %d; want one %s write and one reconfigure", s.writes, s.reconfigs, tc.write)
			}
		})
	}
}

// A settings read that fails costs only the write it would have saved.
func TestSyncZabbix_AnUnreadableDeviceIsWritten(t *testing.T) {
	settings, err := parseAPIZabbixSettings(map[string]interface{}{"snippets": []interface{}{
		map[string]interface{}{"config_type": "ZABBIX_SETTINGS", "content": `{"hostname":"fw1","server_list":["zbx.example.com"]}`},
	}})
	if err != nil {
		t.Fatal(err)
	}
	s := newZabbixNoopServer(t, map[string]interface{}{"result": "failed"}, nil, nil)
	if result := executeSyncZabbix(context.Background(), s.client, settings, nil, nil, false); !result.Success {
		t.Fatalf("sync failed: %+v", result.Errors)
	}
	if len(s.writes) != 1 || s.reconfigs != 1 {
		t.Errorf("writes %v, reconfigures %d; want the settings written and reconfigured", s.writes, s.reconfigs)
	}
}

// Two userparameter or alias snippets with the same key both write, so the last
// one wins on every sync. Compared with the row read before the writes, the
// second would match the old row and be skipped, and the device would flip
// between the two on alternate syncs.
func TestSyncZabbix_ASecondSnippetWithTheSameKeyAlwaysWrites(t *testing.T) {
	payload := map[string]interface{}{"snippets": []interface{}{
		map[string]interface{}{"config_type": "ZABBIX_USERPARAMETER", "content": `{"key":"nd-cpu","command":"first"}`},
		map[string]interface{}{"config_type": "ZABBIX_USERPARAMETER", "content": `{"key":"nd-cpu","command":"sysctl -n hw.ncpu"}`},
		map[string]interface{}{"config_type": "ZABBIX_ALIAS", "content": `{"key":"nd-ping","source_key":"first"}`},
		map[string]interface{}{"config_type": "ZABBIX_ALIAS", "content": `{"key":"nd-ping","source_key":"agent.ping"}`},
	}}
	ups, err := parseAPIZabbixUserParameters(payload)
	if err != nil {
		t.Fatal(err)
	}
	aliases, err := parseAPIZabbixAliases(payload)
	if err != nil {
		t.Fatal(err)
	}
	s := newZabbixNoopServer(t, nil,
		map[string]interface{}{"uuid": "u1", "enabled": "1", "key": "nd-cpu", "command": "sysctl -n hw.ncpu", "acceptParams": "0"},
		map[string]interface{}{"uuid": "a1", "enabled": "1", "key": "nd-ping", "sourceKey": "agent.ping", "acceptParams": "0"})
	if result := executeSyncZabbix(context.Background(), s.client, nil, ups, aliases, false); !result.Success {
		t.Fatalf("sync failed: %+v", result.Errors)
	}
	if got := fmt.Sprint(s.writes); got != "[userparameter userparameter alias alias]" {
		t.Errorf("writes %s, want both snippets of each key written", got)
	}
	if got := fmt.Sprint(s.bodies); got != "[first sysctl -n hw.ncpu first agent.ping]" {
		t.Errorf("written content %s, want each key's last snippet written last", got)
	}
}
