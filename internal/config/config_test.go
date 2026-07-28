package config

import (
	"os"
	"path/filepath"
	"testing"
)

func createTempConfigFile(t *testing.T, content string) string {
	t.Helper()
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.conf")
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create temp config file: %v", err)
	}
	return tmpFile
}

func TestLoad_ValidConfig(t *testing.T) {
	content := `
# Full valid configuration
enabled=true
token=my-token-123
device_uuid=device-uuid-456
server_host=api.example.com
server_port=8443
ssl_verify=true
config_xml_path=/conf/config.xml
pid_file=/var/run/ndagent.pid
log_level=INFO
test_mode=false
`
	configPath := createTempConfigFile(t, content)

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Check all fields
	if !cfg.Enabled {
		t.Error("Expected enabled=true")
	}
	if cfg.Token != "my-token-123" {
		t.Errorf("Token = %q, want %q", cfg.Token, "my-token-123")
	}
	if cfg.DeviceUUID != "device-uuid-456" {
		t.Errorf("DeviceUUID = %q, want %q", cfg.DeviceUUID, "device-uuid-456")
	}
	if cfg.ServerHost != "api.example.com" {
		t.Errorf("ServerHost = %q, want %q", cfg.ServerHost, "api.example.com")
	}
	if cfg.ServerPort != 8443 {
		t.Errorf("ServerPort = %d, want %d", cfg.ServerPort, 8443)
	}
	if !cfg.SSLVerify {
		t.Error("Expected ssl_verify=true")
	}
	if cfg.ConfigXMLPath != "/conf/config.xml" {
		t.Errorf("ConfigXMLPath = %q, want %q", cfg.ConfigXMLPath, "/conf/config.xml")
	}
	if cfg.LogLevel != "INFO" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "INFO")
	}
	if cfg.TestMode {
		t.Error("Expected test_mode=false")
	}
}

func TestLoad_BooleanParsing(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected bool
	}{
		{"true lowercase", "true", true},
		{"True mixed", "True", true},
		{"TRUE uppercase", "TRUE", true},
		{"yes", "yes", true},
		{"1", "1", true},
		{"false lowercase", "false", false},
		{"False mixed", "False", false},
		{"FALSE uppercase", "FALSE", false},
		{"no", "no", false},
		{"0", "0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := `
token=test-token
device_uuid=test-device
server_host=localhost
enabled=` + tt.value

			configPath := createTempConfigFile(t, content)
			cfg, err := Load(configPath)
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}

			if cfg.Enabled != tt.expected {
				t.Errorf("Enabled = %v, want %v for value %q", cfg.Enabled, tt.expected, tt.value)
			}
		})
	}
}

func TestLoad_QuotedValues(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected string
	}{
		{"double quotes", `"my-token"`, "my-token"},
		{"single quotes", `'my-token'`, "my-token"},
		{"no quotes", `my-token`, "my-token"},
		{"spaces in quotes", `"my token with spaces"`, "my token with spaces"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := `
token=` + tt.value + `
device_uuid=test-device
server_host=localhost
`
			configPath := createTempConfigFile(t, content)
			cfg, err := Load(configPath)
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}

			if cfg.Token != tt.expected {
				t.Errorf("Token = %q, want %q", cfg.Token, tt.expected)
			}
		})
	}
}

func TestLoad_DefaultValues(t *testing.T) {
	// Minimal config - should use defaults for optional fields
	content := `
token=test-token
device_uuid=test-device
server_host=localhost
`
	configPath := createTempConfigFile(t, content)
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Check defaults
	if cfg.ServerPort != 8443 {
		t.Errorf("ServerPort default = %d, want %d", cfg.ServerPort, 8443)
	}
	if !cfg.SSLVerify {
		t.Error("SSLVerify default should be true")
	}
	if !cfg.TOFUSSLVerify {
		t.Error("TOFUSSLVerify default should be true")
	}
	if cfg.ConfigXMLPath != "/conf/config.xml" {
		t.Errorf("ConfigXMLPath default = %q, want %q", cfg.ConfigXMLPath, "/conf/config.xml")
	}
	if cfg.LogLevel != "INFO" {
		t.Errorf("LogLevel default = %q, want %q", cfg.LogLevel, "INFO")
	}
	if cfg.TestMode {
		t.Error("TestMode default should be false")
	}
	if cfg.Enabled {
		t.Error("Enabled default should be false")
	}
	if !cfg.RejectDangerousSnippets {
		t.Error("RejectDangerousSnippets default should be true (secure-by-default)")
	}
}

// TestLoad_RejectDangerousSnippetsDefaultsTrue guards the device-local
// dangerous-snippet gate's secure-by-default posture: an omitted config
// line must reject dangerous SYNC_API snippet content. Fleets that relied
// on the previous permissive default are grandfathered by the OPNsense
// plugin's post-install reconcile writing an explicit
// reject_dangerous_snippets=false into ndagent.conf on upgrade — that
// grandfathering lives outside this Go binary (see ensure_readonly.php),
// so it isn't exercised by this test. This test only pins the Go-level
// default for a config that genuinely omits the line (e.g. a fresh install,
// or any config predating the grandfathering mechanism).
func TestLoad_RejectDangerousSnippetsDefaultsTrue(t *testing.T) {
	content := `
token=test-token
device_uuid=test-device
server_host=localhost
`
	configPath := createTempConfigFile(t, content)
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.RejectDangerousSnippets {
		t.Error("RejectDangerousSnippets should default to true when omitted")
	}
}

// TestLoad_RejectDangerousSnippetsExplicitlyEnabled confirms the setting
// still works when explicitly set to true (redundant with the default, but
// an operator or the grandfathering reconcile may write it explicitly).
func TestLoad_RejectDangerousSnippetsExplicitlyEnabled(t *testing.T) {
	content := `
token=test-token
device_uuid=test-device
server_host=localhost
reject_dangerous_snippets=true
`
	configPath := createTempConfigFile(t, content)
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.RejectDangerousSnippets {
		t.Error("expected reject_dangerous_snippets=true to be honored when explicitly set")
	}
}

// TestLoad_RejectDangerousSnippetsExplicitlyDisabled is the grandfathering
// escape hatch: a fleet upgrading from the previous permissive default must
// be able to carry an explicit reject_dangerous_snippets=false and have it
// honored, overriding the new secure-by-default.
func TestLoad_RejectDangerousSnippetsExplicitlyDisabled(t *testing.T) {
	content := `
token=test-token
device_uuid=test-device
server_host=localhost
reject_dangerous_snippets=false
`
	configPath := createTempConfigFile(t, content)
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.RejectDangerousSnippets {
		t.Error("expected reject_dangerous_snippets=false to be honored when explicitly set (grandfathering escape hatch)")
	}
}

// TestLoad_TOFUSSLVerifyDefaultsTrueEvenWhenSSLVerifyDisabled guards against
// the TOFU JWKS fetch silently inheriting a dev/lab ssl_verify=false — the
// two toggles must be independent, with TOFU secure by default.
func TestLoad_TOFUSSLVerifyDefaultsTrueEvenWhenSSLVerifyDisabled(t *testing.T) {
	content := `
token=test-token
device_uuid=test-device
server_host=localhost
ssl_verify=false
`
	configPath := createTempConfigFile(t, content)
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.SSLVerify {
		t.Fatal("expected ssl_verify=false to be honored")
	}
	if !cfg.TOFUSSLVerify {
		t.Error("TOFUSSLVerify should default to true regardless of ssl_verify=false")
	}
}

// TestLoad_TOFUSSLVerifyExplicitlyDisabled confirms the escape hatch still
// works when an operator explicitly opts out.
func TestLoad_TOFUSSLVerifyExplicitlyDisabled(t *testing.T) {
	content := `
token=test-token
device_uuid=test-device
server_host=localhost
tofu_ssl_verify=false
`
	configPath := createTempConfigFile(t, content)
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.TOFUSSLVerify {
		t.Error("expected tofu_ssl_verify=false to be honored when explicitly set")
	}
}

func TestLoad_ComputedURIs(t *testing.T) {
	content := `
token=test-token
device_uuid=test-device
server_host=api.example.com
server_port=9443
`
	configPath := createTempConfigFile(t, content)
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	expectedWS := "wss://api.example.com:9443/ws"
	if cfg.ServerURIWS != expectedWS {
		t.Errorf("ServerURIWS = %q, want %q", cfg.ServerURIWS, expectedWS)
	}

	expectedCheck := "https://api.example.com:9443/v1/DeviceRegistrationCheck"
	if cfg.ServerURICheck != expectedCheck {
		t.Errorf("ServerURICheck = %q, want %q", cfg.ServerURICheck, expectedCheck)
	}

	expectedStart := "https://api.example.com:9443/v1/DeviceRegistrationStart"
	if cfg.ServerURIStart != expectedStart {
		t.Errorf("ServerURIStart = %q, want %q", cfg.ServerURIStart, expectedStart)
	}
}

func TestLoad_MissingRequiredFields(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		errContains string
	}{
		{
			name: "missing token",
			content: `
device_uuid=test-device
server_host=localhost
`,
			errContains: "token is required",
		},
		{
			name: "empty token",
			content: `
token=
device_uuid=test-device
server_host=localhost
`,
			errContains: "token is required",
		},
		{
			name: "missing device_uuid",
			content: `
token=test-token
server_host=localhost
`,
			errContains: "device_uuid is required",
		},
		{
			name: "empty server_host",
			content: `
token=test-token
device_uuid=test-device
server_host=
`,
			errContains: "server_host cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := createTempConfigFile(t, tt.content)
			_, err := Load(configPath)
			if err == nil {
				t.Fatal("Expected error but got nil")
			}
			if !contains(err.Error(), tt.errContains) {
				t.Errorf("Error = %q, want to contain %q", err.Error(), tt.errContains)
			}
		})
	}
}

func TestLoad_InvalidLogLevel(t *testing.T) {
	content := `
token=test-token
device_uuid=test-device
server_host=localhost
log_level=VERBOSE
`
	configPath := createTempConfigFile(t, content)
	_, err := Load(configPath)
	if err == nil {
		t.Fatal("Expected error for invalid log level")
	}
	if !contains(err.Error(), "invalid log_level") {
		t.Errorf("Error = %q, want to contain 'invalid log_level'", err.Error())
	}
}

func TestLoad_ValidLogLevels(t *testing.T) {
	levels := []string{"DEBUG", "INFO", "WARNING", "WARN", "ERROR", "CRITICAL"}

	for _, level := range levels {
		t.Run(level, func(t *testing.T) {
			content := `
token=test-token
device_uuid=test-device
server_host=localhost
log_level=` + level

			configPath := createTempConfigFile(t, content)
			cfg, err := Load(configPath)
			if err != nil {
				t.Fatalf("Load() error = %v for log_level=%s", err, level)
			}
			if cfg.LogLevel != level {
				t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, level)
			}
		})
	}
}

func TestLoad_InvalidPort(t *testing.T) {
	tests := []struct {
		name string
		port string
	}{
		{"port too low", "0"},
		{"port negative", "-1"},
		{"port too high", "65536"},
		{"port way too high", "100000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := `
token=test-token
device_uuid=test-device
server_host=localhost
server_port=` + tt.port

			configPath := createTempConfigFile(t, content)
			_, err := Load(configPath)
			if err == nil {
				t.Fatal("Expected error for invalid port")
			}
			if !contains(err.Error(), "server_port") {
				t.Errorf("Error = %q, want to contain 'server_port'", err.Error())
			}
		})
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/config.conf")
	if err == nil {
		t.Fatal("Expected error for nonexistent file")
	}
	if !contains(err.Error(), "not found") {
		t.Errorf("Error = %q, want to contain 'not found'", err.Error())
	}
}

func TestLoad_CommentsAndEmptyLines(t *testing.T) {
	content := `
# This is a comment
token=test-token

# Another comment
device_uuid=test-device

server_host=localhost
# Trailing comment
`
	configPath := createTempConfigFile(t, content)
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Token != "test-token" {
		t.Errorf("Token = %q, want %q", cfg.Token, "test-token")
	}
	if cfg.DeviceUUID != "test-device" {
		t.Errorf("DeviceUUID = %q, want %q", cfg.DeviceUUID, "test-device")
	}
}

func TestGetTLSConfig_SSLVerifyTrue(t *testing.T) {
	cfg := &Config{SSLVerify: true}
	tlsConfig := cfg.GetTLSConfig()

	if tlsConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be false when ssl_verify=true")
	}
}

func TestGetTLSConfig_SSLVerifyFalse(t *testing.T) {
	cfg := &Config{SSLVerify: false}
	tlsConfig := cfg.GetTLSConfig()

	if !tlsConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be true when ssl_verify=false")
	}
}

// TestGetTOFUTLSConfig_VerifiesEvenWhenSSLVerifyFalse is the core
// revert guard: the TOFU JWKS fetch must stay verifying as long as
// TOFUSSLVerify is true, no matter what SSLVerify is set to.
func TestGetTOFUTLSConfig_VerifiesEvenWhenSSLVerifyFalse(t *testing.T) {
	cfg := &Config{SSLVerify: false, TOFUSSLVerify: true}
	tlsConfig := cfg.GetTOFUTLSConfig()

	if tlsConfig.InsecureSkipVerify {
		t.Error("GetTOFUTLSConfig InsecureSkipVerify should be false when TOFUSSLVerify=true, regardless of SSLVerify")
	}
}

func TestGetTOFUTLSConfig_SkipsVerifyOnlyWhenExplicitlyDisabled(t *testing.T) {
	cfg := &Config{SSLVerify: true, TOFUSSLVerify: false}
	tlsConfig := cfg.GetTOFUTLSConfig()

	if !tlsConfig.InsecureSkipVerify {
		t.Error("GetTOFUTLSConfig InsecureSkipVerify should be true when TOFUSSLVerify=false")
	}
}

func TestIsTestMode(t *testing.T) {
	tests := []struct {
		name      string
		testMode  bool
		envGoTest string
		expected  bool
	}{
		{"test_mode true", true, "", true},
		{"test_mode false, no env", false, "", false},
		{"test_mode false, GO_TEST set", false, "1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{TestMode: tt.testMode}

			if tt.envGoTest != "" {
				os.Setenv("GO_TEST", tt.envGoTest)
				defer os.Unsetenv("GO_TEST")
			} else {
				os.Unsetenv("GO_TEST")
			}

			if cfg.IsTestMode() != tt.expected {
				t.Errorf("IsTestMode() = %v, want %v", cfg.IsTestMode(), tt.expected)
			}
		})
	}
}

func TestIsEnabled(t *testing.T) {
	cfg := &Config{Enabled: true}
	if !cfg.IsEnabled() {
		t.Error("IsEnabled() = false, want true")
	}

	cfg.Enabled = false
	if cfg.IsEnabled() {
		t.Error("IsEnabled() = true, want false")
	}
}

func TestLogLevelNormalization(t *testing.T) {
	// Log level should be normalized to uppercase
	content := `
token=test-token
device_uuid=test-device
server_host=localhost
log_level=debug
`
	configPath := createTempConfigFile(t, content)
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.LogLevel != "DEBUG" {
		t.Errorf("LogLevel = %q, want %q (normalized to uppercase)", cfg.LogLevel, "DEBUG")
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestLoad_RemoteAccessPolicyDefaultsToFull pins the upgrade-safety
// property that matters most for the existing fleet: a config that omits
// remote_access_policy entirely must behave exactly as it did before the
// ceiling existed. The OPNsense Settings model's <Default> and the conf
// template's helpers.exists guard agree with this, so an absent config.xml
// node, an absent conf line, and an explicit "full" are all the same
// thing — which is why this setting needs no grandfathering migration.
// If this test ever fails, a package upgrade is silently restricting
// remote access on every device that has not saved its Settings since.
func TestLoad_RemoteAccessPolicyDefaultsToFull(t *testing.T) {
	content := `
token=test-token
device_uuid=test-device
server_host=localhost
`
	configPath := createTempConfigFile(t, content)
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.RemoteAccessPolicy != RemoteAccessFull {
		t.Errorf("RemoteAccessPolicy should default to %q when omitted, got %q",
			RemoteAccessFull, cfg.RemoteAccessPolicy)
	}
	if cfg.RemoteAccessPolicyInvalid != "" {
		t.Errorf("an omitted policy is not an invalid one; RemoteAccessPolicyInvalid = %q",
			cfg.RemoteAccessPolicyInvalid)
	}
}

// TestLoad_RemoteAccessPolicyExplicitValues confirms each of the three
// defined policies round-trips, including case-insensitively — the value
// is normally written by the plugin's Volt template from a dropdown, but
// an operator repairing a device by hand should not be defeated by case.
func TestLoad_RemoteAccessPolicyExplicitValues(t *testing.T) {
	cases := map[string]RemoteAccessPolicy{
		"full":     RemoteAccessFull,
		"readonly": RemoteAccessReadOnly,
		"disabled": RemoteAccessDisabled,
		"Disabled": RemoteAccessDisabled,
		"READONLY": RemoteAccessReadOnly,
		" full ":   RemoteAccessFull,
	}
	for raw, want := range cases {
		content := `
token=test-token
device_uuid=test-device
server_host=localhost
remote_access_policy=` + raw + `
`
		configPath := createTempConfigFile(t, content)
		cfg, err := Load(configPath)
		if err != nil {
			t.Fatalf("Load() with remote_access_policy=%q error = %v", raw, err)
		}
		if cfg.RemoteAccessPolicy != want {
			t.Errorf("remote_access_policy=%q → got %q, want %q", raw, cfg.RemoteAccessPolicy, want)
		}
		if cfg.RemoteAccessPolicyInvalid != "" {
			t.Errorf("remote_access_policy=%q should be valid, got invalid marker %q",
				raw, cfg.RemoteAccessPolicyInvalid)
		}
	}
}

// TestLoad_RemoteAccessPolicyInvalidClampsToDisabled pins the deliberate
// deviation from every other setting in this package: an unparseable value
// does NOT abort startup, it clamps to the most restrictive policy.
//
// Both halves matter. Clamping to "disabled" means a ceiling that cannot be
// read fails tight rather than wide. Not returning an error means the device
// stays online — refusing to start would take SYNC, telemetry and firmware
// down too, precisely because remote access broke, leaving no way to observe
// or repair the device short of physical access.
func TestLoad_RemoteAccessPolicyInvalidClampsToDisabled(t *testing.T) {
	for _, raw := range []string{"maybe", "off", "true", "yes", "read-only", "FULL_ACCESS"} {
		content := `
token=test-token
device_uuid=test-device
server_host=localhost
remote_access_policy=` + raw + `
`
		configPath := createTempConfigFile(t, content)
		cfg, err := Load(configPath)
		if err != nil {
			t.Fatalf("an invalid remote_access_policy=%q must not fail startup, got error = %v", raw, err)
		}
		if cfg.RemoteAccessPolicy != RemoteAccessDisabled {
			t.Errorf("remote_access_policy=%q should clamp to %q, got %q",
				raw, RemoteAccessDisabled, cfg.RemoteAccessPolicy)
		}
		if cfg.RemoteAccessPolicyInvalid == "" {
			t.Errorf("remote_access_policy=%q should record the raw value for the startup warning", raw)
		}
	}
}

// TestRemoteAccessPolicyValid guards the Valid() helper the proxy and the
// WebSocketClient accessor both key off. The zero value must not be valid —
// GetRemoteAccessPolicy relies on that to fall back to the tightest policy.
func TestRemoteAccessPolicyValid(t *testing.T) {
	for _, p := range []RemoteAccessPolicy{RemoteAccessFull, RemoteAccessReadOnly, RemoteAccessDisabled} {
		if !p.Valid() {
			t.Errorf("%q should be a valid policy", p)
		}
	}
	for _, p := range []RemoteAccessPolicy{"", "Full", "none", "off"} {
		if p.Valid() {
			t.Errorf("%q should not be a valid policy", p)
		}
	}
}
