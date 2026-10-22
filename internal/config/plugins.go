package config

import (
	"context"
	"encoding/xml"
	"fmt"
	"strings"
)

// ReadRegisteredPlugins returns the plugins in OPNsense's plugin list
// (system.firmware.plugins). OPNsense installs a listed plugin again when it
// is missing, after a series upgrade or when the plugins are resynced; its
// firmware GUI keeps the list with register.php after every plugin install
// and removal.
func ReadRegisteredPlugins(ctx context.Context, configXMLPath string) (map[string]bool, error) {
	data, err := ReadConfigXML(ctx, configXMLPath)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Plugins string `xml:"system>firmware>plugins"`
	}
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", configXMLPath, err)
	}
	out := map[string]bool{}
	for _, name := range strings.Split(doc.Plugins, ",") {
		if name = strings.TrimSpace(name); name != "" {
			out[name] = true
		}
	}
	return out, nil
}
