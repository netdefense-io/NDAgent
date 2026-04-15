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
