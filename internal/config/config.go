// Package config provides configuration management for NDAgent.
package config

import (
	"crypto/tls"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
)

// RemoteAccessPolicy is the device-local ceiling on NetDefense-mediated
// remote access (CONNECT sessions). It is the device's final word: the
// control plane may request a session at or below this ceiling, never
// above it. Nothing reachable from the control plane can raise it — the
// value lives in the OPNsense Settings model, and the agent's OPNsense
// REST client has no writer for the netdefense/settings node (its
// endpoints are hardcoded per-plugin: unbound/*, zabbixagent/*,
// wireguard/*, core/service/search). Changing it requires access to the
// device itself.
type RemoteAccessPolicy string

const (
	// RemoteAccessFull permits whatever the control plane asks for:
	// shell, SSH, exec, and webadmin. This is the default and matches
	// behavior before the ceiling existed.
	RemoteAccessFull RemoteAccessPolicy = "full"

	// RemoteAccessReadOnly clamps every session to read-only regardless
	// of the CONNECT payload's read_only flag: webadmin only, no shell,
	// no SSH, no exec stream.
	RemoteAccessReadOnly RemoteAccessPolicy = "readonly"

	// RemoteAccessDisabled refuses CONNECT outright — no relay is dialed
	// and no stream is served.
	RemoteAccessDisabled RemoteAccessPolicy = "disabled"
)

// Valid reports whether p is one of the three defined policies.
func (p RemoteAccessPolicy) Valid() bool {
	switch p {
	case RemoteAccessFull, RemoteAccessReadOnly, RemoteAccessDisabled:
		return true
	}
	return false
}

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

	// TOFUSSLVerify governs TLS verification for the first-connect NDM
	// JWKS fetch (TOFU key pinning) independently of SSLVerify. It
	// defaults to true even when ssl_verify=false is set for dev/lab
	// convenience, so a MITM can't plant a rogue key at the one moment
	// nothing is pinned yet.
	TOFUSSLVerify bool `mapstructure:"tofu_ssl_verify"`

	// File paths
	ConfigXMLPath string `mapstructure:"config_xml_path"`
	PIDFile       string `mapstructure:"pid_file"`

	// Logging
	LogLevel string `mapstructure:"log_level"`

	// Test mode
	TestMode bool `mapstructure:"test_mode"`

	// RejectDangerousSnippets is a device-local defense-in-depth gate
	// against dangerous USER/GROUP/ZABBIX_* SYNC_API snippet content
	// (privileged priv, scope=system, non-nologin shell, authorizedkeys,
	// Zabbix remote commands, sudo_root). It mirrors NDManager's producer-
	// side dangerous-field validators (the primary control, gated by
	// org:su) — this is a second, local line of defense.
	//
	// Default true (secure-by-default) as of the flip in this field's
	// history: an omitted config line now means "reject". Fleets that were
	// already relying on the previous permissive default are grandfathered
	// via the OPNsense plugin's post-install reconcile
	// (ensure_readonly.php), which writes an explicit "false" into
	// config.xml for already-configured devices whose config predates this
	// field, on package upgrade — see that script and Settings.xml's
	// <rejectDangerousSnippets> Default for the other half of the
	// mechanism. Fresh installs get true with nothing to grandfather. See
	// internal/opnapi's DangerousUserFields and friends for the exact
	// field set this gate checks.
	RejectDangerousSnippets bool `mapstructure:"reject_dangerous_snippets"`

	// OPNsense API credentials (for SYNC_API/PULL_API)
	APIKey         string `mapstructure:"api_key"`
	APISecret      string `mapstructure:"api_secret"`
	OPNsenseAPIURL string `mapstructure:"opnsense_api_url"`

	// Pathfinder settings (for CONNECT task)
	PathfinderHost      string `mapstructure:"pathfinder_host"`
	PathfinderTLSVerify bool   `mapstructure:"pathfinder_tls_verify"`
	PathfinderShell     string `mapstructure:"pathfinder_shell"`

	// RemoteAccessPolicy is the device-local ceiling on CONNECT sessions:
	// "full" (default), "readonly", or "disabled". See the
	// RemoteAccessPolicy type for the trust argument. Enforced in two
	// places, deliberately: internal/tasks.HandleConnect refuses or clamps
	// before the relay is dialed, and internal/pathfinder's
	// ProxyStreamToLocal chokepoint re-checks per stream so no future
	// caller path can bypass the first gate.
	//
	// Default "full" — identical to pre-ceiling behavior, so a package
	// upgrade never silently disables remote access on an existing fleet.
	// The OPNsense Settings model's <Default> and the conf template's
	// helpers.exists guard agree with this default, so an absent config.xml
	// node, an absent conf line, and an explicit "full" all mean the same
	// thing and no grandfathering migration is needed.
	RemoteAccessPolicy RemoteAccessPolicy `mapstructure:"remote_access_policy"`

	// RemoteAccessPolicyInvalid carries the raw remote_access_policy value
	// when it failed validation and was clamped to "disabled". Empty when
	// the configured value was valid. Config loading happens before logging
	// is initialized, so validate() cannot warn; main logs this once the
	// logger exists.
	RemoteAccessPolicyInvalid string

	// Webadmin proxy settings (for pre-authenticated webadmin access)
	WebadminUser       string `mapstructure:"webadmin_user"`
	WebadminSessionDir string `mapstructure:"webadmin_session_dir"`

	// WebadminReadOnlyUser is the locally configured OPNsense username forged
	// into the PHP session when a CONNECT task carries read_only=true. It maps
	// to a curated read-only ACL (group netdefense-readonly). NDAgent picks
	// this username from local config only — the broker never supplies an
	// arbitrary username, which would be a privilege-escalation vector.
	WebadminReadOnlyUser string `mapstructure:"webadmin_readonly_user"`

	// Detected from config.xml at startup (not from ndagent.conf)
	WebadminPort     int    // Detected webgui port (default: 443)
	WebadminProtocol string // Detected webgui protocol (default: "https")

	// DevicePrivKey is the base64-encoded raw 32-byte Ed25519 seed that
	// signs outbound responses. Generated locally on first run if absent.
	DevicePrivKey string `mapstructure:"device_privkey"`

	// BootstrapToken is the operator-issued one-time token used to bind
	// (or rebind) Device.device_pubkey when the existing device row has
	// device_pubkey=NULL. Cleared from the in-memory Config after a
	// successful StartRegistration response (single-use); the operator is
	// expected to clear the GUI field separately so subsequent rebinds
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
	v.SetDefault("tofu_ssl_verify", true)
	v.SetDefault("config_xml_path", "/conf/config.xml")
	v.SetDefault("pid_file", "/var/run/ndagent.pid")
	v.SetDefault("log_level", "INFO")
	v.SetDefault("test_mode", false)
	v.SetDefault("reject_dangerous_snippets", true)
	v.SetDefault("enabled", false)
	v.SetDefault("opnsense_api_url", "https://127.0.0.1/api")
	v.SetDefault("pathfinder_host", "https://pathfinder.netdefense.io")
	v.SetDefault("pathfinder_tls_verify", true)
	v.SetDefault("pathfinder_shell", "/usr/local/sbin/opnsense-shell")
	v.SetDefault("webadmin_user", "root")
	v.SetDefault("remote_access_policy", string(RemoteAccessFull))
	v.SetDefault("webadmin_readonly_user", "netdefense-readonly")
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

	// First-run keypair generation lives in lifecycle (state.LoadOrEnsureDevicePrivkey)
	// so the seed sits at /var/db/ndagent/device.key — outside configctl's reach,
	// which would otherwise wipe the conf line on every GUI Save. cfg.DevicePrivKey
	// here is treated as a one-time migration source for legacy conf lines.

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

	// Normalize and validate the remote-access ceiling.
	//
	// Deliberate deviation from every other setting here: an unparseable
	// value does NOT abort startup, it clamps to the most restrictive
	// policy. Two reasons. A security ceiling that cannot be read should
	// be the tightest one, not the loosest. And refusing to start would
	// take the device entirely offline — no SYNC, no telemetry, no
	// firmware — precisely because remote access is the thing that broke,
	// leaving no way to observe or repair it short of physical access. A
	// clamped device stays manageable for everything else and surfaces the
	// bad value in its logs.
	//
	// The GUI renders this as a dropdown, so a bad value requires
	// hand-editing ndagent.conf, which is documented as unsupported (the
	// file is rendered from config.xml by the plugin's Volt template).
	rawPolicy := strings.TrimSpace(string(c.RemoteAccessPolicy))
	c.RemoteAccessPolicy = RemoteAccessPolicy(strings.ToLower(rawPolicy))
	if c.RemoteAccessPolicy == "" {
		c.RemoteAccessPolicy = RemoteAccessFull
	}
	if !c.RemoteAccessPolicy.Valid() {
		c.RemoteAccessPolicyInvalid = rawPolicy
		c.RemoteAccessPolicy = RemoteAccessDisabled
	}

	// DevicePrivKey is loaded by lifecycle from /var/db/ndagent/device.key;
	// any value here is only a legacy-conf migration source.
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

// GetTOFUTLSConfig returns a TLS configuration for the first-connect NDM
// JWKS fetch (TOFU key pinning). It honors TOFUSSLVerify independently of
// SSLVerify — the global toggle is not permitted to weaken the one fetch
// where nothing is pinned yet, so ssl_verify=false alone never disables
// verification here.
func (c *Config) GetTOFUTLSConfig() *tls.Config {
	if c.TOFUSSLVerify {
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
