package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadWebGUIConfig_ExplicitPort(t *testing.T) {
	xml := `<?xml version="1.0"?>
<opnsense>
  <system>
    <webgui>
      <protocol>https</protocol>
      <port>8443</port>
    </webgui>
  </system>
</opnsense>`

	path := writeTempXML(t, xml)
	wg := ReadWebGUIConfig(path)

	if wg.Protocol != "https" {
		t.Errorf("Protocol = %q, want %q", wg.Protocol, "https")
	}
	if wg.Port != 8443 {
		t.Errorf("Port = %d, want %d", wg.Port, 8443)
	}
}

func TestReadWebGUIConfig_HTTPProtocol(t *testing.T) {
	xml := `<?xml version="1.0"?>
<opnsense>
  <system>
    <webgui>
      <protocol>http</protocol>
      <port>8080</port>
    </webgui>
  </system>
</opnsense>`

	path := writeTempXML(t, xml)
	wg := ReadWebGUIConfig(path)

	if wg.Protocol != "http" {
		t.Errorf("Protocol = %q, want %q", wg.Protocol, "http")
	}
	if wg.Port != 8080 {
		t.Errorf("Port = %d, want %d", wg.Port, 8080)
	}
}

func TestReadWebGUIConfig_EmptyPort(t *testing.T) {
	xml := `<?xml version="1.0"?>
<opnsense>
  <system>
    <webgui>
      <protocol>https</protocol>
      <port/>
    </webgui>
  </system>
</opnsense>`

	path := writeTempXML(t, xml)
	wg := ReadWebGUIConfig(path)

	if wg.Protocol != "https" {
		t.Errorf("Protocol = %q, want %q", wg.Protocol, "https")
	}
	if wg.Port != 443 {
		t.Errorf("Port = %d, want %d (default for https)", wg.Port, 443)
	}
}

func TestReadWebGUIConfig_EmptyPortHTTP(t *testing.T) {
	xml := `<?xml version="1.0"?>
<opnsense>
  <system>
    <webgui>
      <protocol>http</protocol>
      <port/>
    </webgui>
  </system>
</opnsense>`

	path := writeTempXML(t, xml)
	wg := ReadWebGUIConfig(path)

	if wg.Port != 80 {
		t.Errorf("Port = %d, want %d (default for http)", wg.Port, 80)
	}
}

func TestReadWebGUIConfig_MissingWebGUI(t *testing.T) {
	xml := `<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>firewall</hostname>
  </system>
</opnsense>`

	path := writeTempXML(t, xml)
	wg := ReadWebGUIConfig(path)

	if wg.Protocol != "https" {
		t.Errorf("Protocol = %q, want %q", wg.Protocol, "https")
	}
	if wg.Port != 443 {
		t.Errorf("Port = %d, want %d", wg.Port, 443)
	}
}

func TestReadWebGUIConfig_UnreadableFile(t *testing.T) {
	wg := ReadWebGUIConfig("/nonexistent/config.xml")

	if wg.Protocol != "https" {
		t.Errorf("Protocol = %q, want %q", wg.Protocol, "https")
	}
	if wg.Port != 443 {
		t.Errorf("Port = %d, want %d", wg.Port, 443)
	}
}

func TestReadWebGUIConfig_InvalidXML(t *testing.T) {
	path := writeTempXML(t, "not valid xml at all <><>")
	wg := ReadWebGUIConfig(path)

	if wg.Protocol != "https" {
		t.Errorf("Protocol = %q, want %q", wg.Protocol, "https")
	}
	if wg.Port != 443 {
		t.Errorf("Port = %d, want %d", wg.Port, 443)
	}
}

func TestReadWebGUIConfig_InvalidPortValue(t *testing.T) {
	xml := `<?xml version="1.0"?>
<opnsense>
  <system>
    <webgui>
      <protocol>https</protocol>
      <port>notanumber</port>
    </webgui>
  </system>
</opnsense>`

	path := writeTempXML(t, xml)
	wg := ReadWebGUIConfig(path)

	if wg.Port != 443 {
		t.Errorf("Port = %d, want %d (fallback for invalid port)", wg.Port, 443)
	}
}

func TestReadWebGUIConfig_PortOutOfRange(t *testing.T) {
	xml := `<?xml version="1.0"?>
<opnsense>
  <system>
    <webgui>
      <protocol>https</protocol>
      <port>99999</port>
    </webgui>
  </system>
</opnsense>`

	path := writeTempXML(t, xml)
	wg := ReadWebGUIConfig(path)

	if wg.Port != 443 {
		t.Errorf("Port = %d, want %d (fallback for out-of-range port)", wg.Port, 443)
	}
}

func writeTempXML(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.xml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write temp XML: %v", err)
	}
	return path
}
