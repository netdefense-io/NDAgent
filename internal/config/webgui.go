package config

import (
	"encoding/xml"
	"os"
	"strconv"

	"go.uber.org/zap"
)

// WebGUIConfig holds the webadmin settings parsed from config.xml.
type WebGUIConfig struct {
	Protocol string // "https" or "http"
	Port     int    // e.g. 443, 8443
}

// xmlOPNsense is a minimal struct for parsing the handful of config.xml
// sections the agent cares about: the webgui settings (ReadWebGUIConfig)
// and the device-facts fields (ReadSystemFacts). One struct, one parse —
// do not add a second config.xml reader.
type xmlOPNsense struct {
	XMLName    xml.Name      `xml:"opnsense"`
	System     xmlSystem     `xml:"system"`
	Interfaces xmlInterfaces `xml:"interfaces"`
}

type xmlSystem struct {
	WebGUI xmlWebGUI `xml:"webgui"`
	// Timezone is the IANA name the GUI stores, e.g. "America/New_York".
	Timezone string `xml:"timezone"`
}

// xmlInterfaces captures every child of <interfaces> regardless of name,
// because the element name *is* the interface role (wan, lan, opt1, …).
type xmlInterfaces struct {
	Items []xmlInterface `xml:",any"`
}

type xmlInterface struct {
	XMLName xml.Name
	If      string `xml:"if"`
	Descr   string `xml:"descr"`
	// Enable is a pointer so an absent element (disabled) is
	// distinguishable from a present-but-empty one (enabled).
	Enable *string `xml:"enable"`
}

type xmlWebGUI struct {
	Protocol string `xml:"protocol"`
	Port     string `xml:"port"`
}

// ReadWebGUIConfig parses the OPNsense config.xml and returns webadmin settings.
// Falls back to protocol=https, port=443 if config.xml is unreadable or fields are empty.
func ReadWebGUIConfig(configXMLPath string) WebGUIConfig {
	log, _ := zap.NewNop().Sugar(), error(nil)
	if l := zap.L(); l != nil {
		log = l.Named("config.webgui").Sugar()
	}

	defaults := WebGUIConfig{Protocol: "https", Port: 443}

	data, err := os.ReadFile(configXMLPath)
	if err != nil {
		log.Warnw("Cannot read config.xml, using default webadmin settings",
			"path", configXMLPath,
			"error", err,
		)
		return defaults
	}

	var parsed xmlOPNsense
	if err := xml.Unmarshal(data, &parsed); err != nil {
		log.Warnw("Cannot parse config.xml, using default webadmin settings",
			"path", configXMLPath,
			"error", err,
		)
		return defaults
	}

	result := WebGUIConfig{}

	// Protocol
	if parsed.System.WebGUI.Protocol == "http" || parsed.System.WebGUI.Protocol == "https" {
		result.Protocol = parsed.System.WebGUI.Protocol
	} else {
		result.Protocol = "https"
	}

	// Port
	if parsed.System.WebGUI.Port != "" {
		port, err := strconv.Atoi(parsed.System.WebGUI.Port)
		if err == nil && port > 0 && port <= 65535 {
			result.Port = port
		} else {
			log.Warnw("Invalid webgui port in config.xml, using default",
				"port_value", parsed.System.WebGUI.Port,
			)
			result.Port = defaultPortForProtocol(result.Protocol)
		}
	} else {
		result.Port = defaultPortForProtocol(result.Protocol)
	}

	return result
}

func defaultPortForProtocol(protocol string) int {
	if protocol == "http" {
		return 80
	}
	return 443
}
