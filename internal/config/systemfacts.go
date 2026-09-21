package config

import (
	"encoding/xml"
	"fmt"
	"os"
	"strings"
)

// SystemFacts is the slice of config.xml that the device-facts collector
// reports. It is deliberately a curated subset: timezone and the
// role→device mapping of the configured interfaces. Nothing secret-bearing
// (API keys, VPN material, certificates) is ever read out of config.xml
// here, and the raw document never leaves the device.
type SystemFacts struct {
	// Timezone is the IANA zone name exactly as the OPNsense GUI stores
	// it in <system><timezone> (e.g. "America/Sao_Paulo"). Empty when the
	// node is absent, which happens on pre-migration configs.
	Timezone string
	// Interfaces is one entry per child of the <interfaces> block, in
	// document order.
	Interfaces []InterfaceEntry
}

// InterfaceEntry is one configured OPNsense interface. Role is the XML
// element name (wan, lan, opt1, …), If the underlying device name.
type InterfaceEntry struct {
	Role    string
	If      string
	Descr   string
	Enabled bool
}

// ReadSystemFacts parses config.xml once and returns the facts-relevant
// fields. Unlike ReadWebGUIConfig there is no sensible default to fall
// back to, so read/parse failures are returned to the caller, which omits
// the affected sub-objects rather than failing the heartbeat.
func ReadSystemFacts(configXMLPath string) (SystemFacts, error) {
	data, err := os.ReadFile(configXMLPath)
	if err != nil {
		return SystemFacts{}, fmt.Errorf("read %s: %w", configXMLPath, err)
	}

	var parsed xmlOPNsense
	if err := xml.Unmarshal(data, &parsed); err != nil {
		return SystemFacts{}, fmt.Errorf("parse %s: %w", configXMLPath, err)
	}

	out := SystemFacts{
		Timezone: strings.TrimSpace(parsed.System.Timezone),
	}

	for _, iface := range parsed.Interfaces.Items {
		role := strings.TrimSpace(iface.XMLName.Local)
		if role == "" {
			continue
		}
		out.Interfaces = append(out.Interfaces, InterfaceEntry{
			Role:    role,
			If:      strings.TrimSpace(iface.If),
			Descr:   strings.TrimSpace(iface.Descr),
			Enabled: interfaceEnabled(iface.Enable),
		})
	}

	return out, nil
}

// interfaceEnabled mirrors OPNsense's own convention: the <enable> element
// is written for enabled interfaces and dropped entirely for disabled
// ones. A present-but-empty element (older pfSense-era configs) counts as
// enabled; an explicit "0"/"false" does not.
func interfaceEnabled(enable *string) bool {
	if enable == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(*enable)) {
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}
