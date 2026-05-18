package opnapi

// NDAgentZabbixKeyPrefix marks NDAgent-managed Zabbix entities (userparameters
// and aliases). OPNsense ignores caller-supplied UUIDs on addUserparameter /
// addAlias, so ownership has to be identified by the `key` field.
//
// The prefix `nd-` is the common ground between the two key validators:
//   - userparameter.key allows  A-Z a-z 0-9 . _ -   (no [ ])
//   - alias.key         allows  A-Z a-z 0-9   _ -   (no . and no [ ])
//
// A dot prefix (e.g. `nd.`) would fit userparameter keys but is rejected for
// aliases — so hyphen it is, mirroring the WireGuard `nd-vpn__` convention.
const NDAgentZabbixKeyPrefix = "nd-"

// ============================================================================
// Settings (singleton: local + main + tuning + features)
// ============================================================================

// ZabbixLocal mirrors zabbixagent.local in the OPNsense config tree.
type ZabbixLocal struct {
	Hostname string `json:"hostname"`
}

// ZabbixMain mirrors zabbixagent.settings.main.
//
// Multi-value fields (ServerList, ListenIP) are sent as comma-separated strings;
// OPNsense returns them as dict-of-options on GET — see ZabbixMultiSelectToCSV.
//
// DebugLevel is a Selection with numeric options. Write side requires the
// option key form ("val_3"), not the bare digit. Use ZabbixDebugLevelToWire
// when copying through a snippet payload.
type ZabbixMain struct {
	Enabled       string `json:"enabled"`
	ServerList    string `json:"serverList"`
	ListenPort    string `json:"listenPort"`
	ListenIP      string `json:"listenIP"`
	SourceIP      string `json:"sourceIP"`
	ListenBacklog string `json:"listenBacklog"`
	SyslogEnable  string `json:"syslogEnable"`
	LogFileSize   string `json:"logFileSize"`
	DebugLevel    string `json:"debugLevel"`
	SudoRoot      string `json:"sudoRoot"`
}

// ZabbixTuning mirrors zabbixagent.settings.tuning.
type ZabbixTuning struct {
	StartAgents       string `json:"startAgents"`
	BufferSend        string `json:"bufferSend"`
	BufferSize        string `json:"bufferSize"`
	MaxLinesPerSecond string `json:"maxLinesPerSecond"`
	Timeout           string `json:"timeout"`
}

// ZabbixFeatures mirrors zabbixagent.settings.features.
//
// EncryptionPSK flows through verbatim. NDAgent doesn't special-case it:
// admins use the existing snippet variable/secret substitution for per-device
// values.
type ZabbixFeatures struct {
	EnableActiveChecks   string `json:"enableActiveChecks"`
	ActiveCheckServers   string `json:"activeCheckServers"`
	RefreshActiveChecks  string `json:"refreshActiveChecks"`
	EnableRemoteCommands string `json:"enableRemoteCommands"`
	LogRemoteCommands    string `json:"logRemoteCommands"`
	Encryption           string `json:"encryption"`
	EncryptionIdentity   string `json:"encryptionidentity"`
	EncryptionPSK        string `json:"encryptionpsk"`
}

// ZabbixSettingsBody is the full `zabbixagent` subtree, used for
// /settings/set writes.
type ZabbixSettingsBody struct {
	Local    ZabbixLocal     `json:"local"`
	Settings ZabbixSettings  `json:"settings"`
}

// ZabbixSettings groups the main/tuning/features blocks.
type ZabbixSettings struct {
	Main     ZabbixMain     `json:"main"`
	Tuning   ZabbixTuning   `json:"tuning"`
	Features ZabbixFeatures `json:"features"`
}

// ZabbixSettingsWrapper wraps the full settings tree for /settings/set.
type ZabbixSettingsWrapper struct {
	ZabbixAgent ZabbixSettingsBody `json:"zabbixagent"`
}

// ============================================================================
// User Parameters (list)
// ============================================================================

// ZabbixUserParameter represents an OPNsense Zabbix UserParameter row for
// add/set wire calls.
type ZabbixUserParameter struct {
	Enabled      string `json:"enabled"`
	Key          string `json:"key"`
	Command      string `json:"command"`
	AcceptParams string `json:"acceptParams"`
}

// ZabbixUserParameterWrapper wraps a userparameter for API set/add operations.
// Wire wrapper key confirmed via GET /api/zabbixagent/settings/getUserparameter/.
type ZabbixUserParameterWrapper struct {
	UserParameter ZabbixUserParameter `json:"userparameter"`
}

// ============================================================================
// Aliases (list)
// ============================================================================

// ZabbixAlias represents an OPNsense Zabbix item-key alias for add/set calls.
type ZabbixAlias struct {
	Enabled      string `json:"enabled"`
	Key          string `json:"key"`
	SourceKey    string `json:"sourceKey"`
	AcceptParams string `json:"acceptParams"`
}

// ZabbixAliasWrapper wraps an alias for API set/add operations.
// Wire wrapper key confirmed via GET /api/zabbixagent/settings/getAlias/.
type ZabbixAliasWrapper struct {
	Alias ZabbixAlias `json:"alias"`
}

// ============================================================================
// Responses
// ============================================================================

// SetZabbixResponse is the response from settings/set (and addX/setX) endpoints.
type SetZabbixResponse struct {
	Result           string             `json:"result"`
	UUID             string             `json:"uuid,omitempty"`
	ValidationErrors FlexibleValidation `json:"validations,omitempty"`
}

// ToggleZabbixResponse is the response from toggleX endpoints.
//
// OPNsense replies with {"result":"Enabled"|"Disabled","changed":bool}, which
// doesn't fit APIResult's "saved"/"deleted" world.
type ToggleZabbixResponse struct {
	Result  string `json:"result"`
	Changed bool   `json:"changed"`
}

// ============================================================================
// Portable snippet payloads
// ============================================================================

// APIZabbixSettingsPayload is the portable snippet shape for the Zabbix
// settings singleton. NDAgent applies it wholesale to /settings/set — no
// field-level merging with non-managed defaults.
type APIZabbixSettingsPayload struct {
	Hostname             string   `json:"hostname"`
	Enabled              bool     `json:"enabled"`
	ServerList           []string `json:"server_list"`
	ListenPort           string   `json:"listen_port,omitempty"`
	ListenIP             []string `json:"listen_ip,omitempty"`
	SourceIP             string   `json:"source_ip,omitempty"`
	ListenBacklog        string   `json:"listen_backlog,omitempty"`
	SyslogEnable         bool     `json:"syslog_enable,omitempty"`
	LogFileSize          string   `json:"log_file_size,omitempty"`
	DebugLevel           string   `json:"debug_level,omitempty"` // bare digit "0".."5"
	SudoRoot             bool     `json:"sudo_root,omitempty"`
	StartAgents          string   `json:"start_agents,omitempty"`
	BufferSend           string   `json:"buffer_send,omitempty"`
	BufferSize           string   `json:"buffer_size,omitempty"`
	MaxLinesPerSecond    string   `json:"max_lines_per_second,omitempty"`
	Timeout              string   `json:"timeout,omitempty"`
	EnableActiveChecks   bool     `json:"enable_active_checks,omitempty"`
	ActiveCheckServers   []string `json:"active_check_servers,omitempty"`
	RefreshActiveChecks  string   `json:"refresh_active_checks,omitempty"`
	EnableRemoteCommands bool     `json:"enable_remote_commands,omitempty"`
	LogRemoteCommands    bool     `json:"log_remote_commands,omitempty"`
	Encryption           string   `json:"encryption,omitempty"` // "0" off, "1" PSK
	EncryptionIdentity   string   `json:"encryption_identity,omitempty"`
	EncryptionPSK        string   `json:"encryption_psk,omitempty"`
	Templates            []string `json:"templates,omitempty"`
}

// APIZabbixUserParameterPayload is the portable snippet shape for a Zabbix
// UserParameter. Key MUST start with NDAgentZabbixKeyPrefix for the entry to
// be considered managed.
type APIZabbixUserParameterPayload struct {
	Enabled      bool     `json:"enabled"`
	Key          string   `json:"key"`
	Command      string   `json:"command"`
	AcceptParams bool     `json:"accept_params,omitempty"`
	Templates    []string `json:"templates,omitempty"`
}

// APIZabbixAliasPayload is the portable snippet shape for a Zabbix item-key
// alias. Key MUST start with NDAgentZabbixKeyPrefix and must not contain `.`
// (OPNsense validator constraint).
type APIZabbixAliasPayload struct {
	Enabled      bool     `json:"enabled"`
	Key          string   `json:"key"`
	SourceKey    string   `json:"source_key"`
	AcceptParams bool     `json:"accept_params,omitempty"`
	Templates    []string `json:"templates,omitempty"`
}
