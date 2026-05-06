// Package config provides configuration management for NDAgent.
package config

import (
	"crypto/tls"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
)

// Config holds the NDAgent configuration.
type Config struct {
	// Required fields
	Enabled    bool   `mapstructure:"enabled"`
	Token      string `mapstructure:"token"`
	DeviceUUID string `mapstructure:"device_uuid"`

	// Server settings
	ServerHost string `mapstructure:"server_host"`
	ServerPort int    `mapstructure:"server_port"`

	// SSL settings
	SSLVerify bool `mapstructure:"ssl_verify"`

	// File paths
	ConfigXMLPath string `mapstructure:"config_xml_path"`
	PIDFile       string `mapstructure:"pid_file"`

	// Logging
	LogLevel string `mapstructure:"log_level"`

	// Test mode
	TestMode bool `mapstructure:"test_mode"`

	// Binary path (for OPNsense plugin)
	BinaryPath string `mapstructure:"binary_path"`

	// OPNsense API credentials (for SYNC_API/PULL_API)
	APIKey         string `mapstructure:"api_key"`
	APISecret      string `mapstructure:"api_secret"`
	OPNsenseAPIURL string `mapstructure:"opnsense_api_url"`

	// Pathfinder settings (for CONNECT task)
	PathfinderHost      string `mapstructure:"pathfinder_host"`
	PathfinderTLSVerify bool   `mapstructure:"pathfinder_tls_verify"`
	PathfinderShell     string `mapstructure:"pathfinder_shell"`

	// Webadmin proxy settings (for pre-authenticated webadmin access)
	WebadminUser       string `mapstructure:"webadmin_user"`
	WebadminSessionDir string `mapstructure:"webadmin_session_dir"`

	// Detected from config.xml at startup (not from ndagent.conf)
	WebadminPort     int    // Detected webgui port (default: 443)
	WebadminProtocol string // Detected webgui protocol (default: "https")

	// Payload signing (PAYLOAD-SIGNATURES-DESIGN.md §12).
	// DevicePrivKey is the base64-encoded raw 32-byte Ed25519 seed that
	// signs outbound responses. Generated locally on first run if absent.
	DevicePrivKey string `mapstructure:"device_privkey"`
	// NDManager primary + emergency public keys are auto-discovered at
	// first connect via TOFU (TLS-anchored fetch from broker's public
	// /api/v1/.well-known/keys), persisted to /var/db/ndagent/ndm-keys.json,
	// and pinned thereafter. See ROTATION-DIRECTIVE.md at the CoreCode
	// root. They no longer ride in ndagent.conf.

	// BootstrapToken is the operator-issued one-time token used to bind
	// (or rebind) Device.device_pubkey when the broker's existing-device
	// row has device_pubkey=NULL — see PAYLOAD-SIGNATURES-FINDINGS-FIXES.md
	// §3 Finding 2. Sourced from ndagent.conf (rendered by the OPNsense
	// plugin from a GUI input). Cleared from the in-memory Config after
	// a successful StartRegistration response (single-use); the operator
	// is expected to clear the GUI field separately so subsequent rebinds
	// require a new token.
	BootstrapToken string `mapstructure:"bootstrap_token"`

	// Computed URIs (not from config file)
	ServerURIWS    string
	ServerURICheck string
	ServerURIStart string
}

// DefaultConfigPath is the default configuration file path.
const DefaultConfigPath = "/usr/local/etc/ndagent.conf"

// Load reads configuration from the specified file path.
func Load(configPath string) (*Config, error) {
	v := viper.New()

	// Set defaults
	v.SetDefault("server_host", "localhost")
	v.SetDefault("server_port", 8443)
	v.SetDefault("ssl_verify", true)
	v.SetDefault("config_xml_path", "/conf/config.xml")
	v.SetDefault("pid_file", "/var/run/ndagent.pid")
	v.SetDefault("log_level", "INFO")
	v.SetDefault("test_mode", false)
	v.SetDefault("enabled", false)
	v.SetDefault("opnsense_api_url", "https://127.0.0.1/api")
	v.SetDefault("pathfinder_host", "https://pathfinder.netdefense.io")
	v.SetDefault("pathfinder_tls_verify", true)
	v.SetDefault("pathfinder_shell", "/usr/local/sbin/opnsense-shell")
	v.SetDefault("webadmin_user", "root")
	v.SetDefault("webadmin_session_dir", "/var/lib/php/sessions")

	// Read config from file
	if configPath == "" {
		configPath = DefaultConfigPath
	}

	// Check if file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("configuration file not found: %s", configPath)
	}

	// Parse key=value config file
	if err := parseKeyValueFile(v, configPath); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Unmarshal into struct
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// First-run keypair generation moved out of config.Load — see issue #15.
	// state.LoadOrEnsureDevicePrivkey is invoked from lifecycle so the seed
	// lives in /var/db/ndagent/device.key (outside configctl's reach) rather
	// than in this conf file. cfg.DevicePrivKey is populated by lifecycle
	// from that file, with the value below treated as a one-time migration
	// source.

	// Validate and normalize
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	// Detect webadmin port/protocol from OPNsense config.xml
	wg := ReadWebGUIConfig(cfg.ConfigXMLPath)
	cfg.WebadminPort = wg.Port
	cfg.WebadminProtocol = wg.Protocol
	cfg.OPNsenseAPIURL = fmt.Sprintf("%s://127.0.0.1:%d/api", wg.Protocol, wg.Port)

	// Compute URIs
	cfg.computeURIs()

	return &cfg, nil
}

// parseKeyValueFile reads a key=value format config file into viper.
func parseKeyValueFile(v *viper.Viper, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	for lineNum, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse key=value
		idx := strings.Index(line, "=")
		if idx == -1 {
			// Log warning but continue (non-fatal)
			continue
		}

		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])

		// Remove quotes if present
		value = removeQuotes(value)

		// Parse and set value
		parsedValue := parseValue(value)
		v.Set(key, parsedValue)

		_ = lineNum // Avoid unused variable warning
	}

	return nil
}

// removeQuotes removes surrounding quotes from a string value.
func removeQuotes(value string) string {
	if len(value) >= 2 {
		if (strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`)) ||
			(strings.HasPrefix(value, `'`) && strings.HasSuffix(value, `'`)) {
			return value[1 : len(value)-1]
		}
	}
	return value
}

// parseValue converts a string value to an appropriate Go type.
func parseValue(value string) interface{} {
	lower := strings.ToLower(value)

	// Handle boolean values
	switch lower {
	case "true", "yes":
		return true
	case "false", "no":
		return false
	}

	// Handle 1/0 as boolean for single digit
	if value == "1" {
		return true
	}
	if value == "0" {
		return false
	}

	// Return as string (let viper handle type conversion)
	return value
}

// validate checks required fields and normalizes values.
func (c *Config) validate() error {
	// Validate required fields
	c.Token = strings.TrimSpace(c.Token)
	if c.Token == "" {
		return fmt.Errorf("token is required and cannot be empty")
	}

	c.DeviceUUID = strings.TrimSpace(c.DeviceUUID)
	if c.DeviceUUID == "" {
		return fmt.Errorf("device_uuid is required and cannot be empty")
	}

	c.ServerHost = strings.TrimSpace(c.ServerHost)
	if c.ServerHost == "" {
		return fmt.Errorf("server_host cannot be empty")
	}

	// Validate port range
	if c.ServerPort < 1 || c.ServerPort > 65535 {
		return fmt.Errorf("server_port must be between 1 and 65535, got %d", c.ServerPort)
	}

	// Normalize log level to uppercase
	c.LogLevel = strings.ToUpper(strings.TrimSpace(c.LogLevel))

	// Validate log level
	validLevels := map[string]bool{
		"DEBUG": true, "INFO": true, "WARNING": true, "WARN": true, "ERROR": true, "CRITICAL": true,
	}
	if !validLevels[c.LogLevel] {
		return fmt.Errorf("invalid log_level: %s (must be DEBUG, INFO, WARNING, ERROR, or CRITICAL)", c.LogLevel)
	}

	// device_privkey validation moved out of config.Load — see issue #15.
	// The seed is now persisted at /var/db/ndagent/device.key and loaded
	// by lifecycle (state.LoadOrEnsureDevicePrivkey) before Phase 1
	// registration. The cfg.DevicePrivKey field is left empty here and
	// populated by lifecycle from the key file (or migrated from any
	// legacy conf line on first run).
	c.DevicePrivKey = strings.TrimSpace(c.DevicePrivKey)

	return nil
}

// computeURIs calculates the server URIs from host and port.
func (c *Config) computeURIs() {
	baseURL := fmt.Sprintf("https://%s:%d", c.ServerHost, c.ServerPort)
	c.ServerURIWS = fmt.Sprintf("wss://%s:%d/ws", c.ServerHost, c.ServerPort)
	c.ServerURICheck = fmt.Sprintf("%s/v1/DeviceRegistrationCheck", baseURL)
	c.ServerURIStart = fmt.Sprintf("%s/v1/DeviceRegistrationStart", baseURL)
}

// GetTLSConfig returns a TLS configuration based on the ssl_verify setting.
func (c *Config) GetTLSConfig() *tls.Config {
	if c.SSLVerify {
		return &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}

	// Warning: Insecure - skips certificate verification
	return &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}
}

// GetPathfinderTLSConfig returns a TLS configuration for Pathfinder connections.
func (c *Config) GetPathfinderTLSConfig() *tls.Config {
	if c.PathfinderTLSVerify {
		return &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}

	// Warning: Insecure - skips certificate verification
	return &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}
}

// IsEnabled returns whether the agent is enabled.
func (c *Config) IsEnabled() bool {
	return c.Enabled
}

// IsTestMode returns whether the agent is running in test mode.
// Test mode can be enabled by:
// 1. Setting test_mode=true in configuration file
// 2. Having GO_TEST environment variable set
func (c *Config) IsTestMode() bool {
	if c.TestMode {
		return true
	}

	// Check for test indicators
	if os.Getenv("GO_TEST") != "" {
		return true
	}

	return false
}

// HasAPICreds returns whether OPNsense API credentials are configured.
// When true, the SYNC_API command can be used for API-based configuration sync.
func (c *Config) HasAPICreds() bool {
	return c.APIKey != "" && c.APISecret != ""
}
