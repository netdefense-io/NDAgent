package tasks

import (
	"testing"
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
	if ups[0].Key != "nd-cpu-temp" || !ups[0].Enabled {
		t.Errorf("up[0] mismatch: %+v", ups[0])
	}
	if ups[1].Key != "nd-wan-bw" || ups[1].Enabled {
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
		"nd-cpu":         true,
		"nd-foo-bar":     true,
		"test.key.name":  false, // admin-owned, no prefix → must fail
		"vfs.fs.size":    false,
		"":               false,
		"prefix-nd-foo":  false, // prefix must be at start
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
