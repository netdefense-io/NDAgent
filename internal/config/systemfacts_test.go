package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeConfigXML(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.xml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config.xml: %v", err)
	}
	return path
}

func TestReadSystemFacts(t *testing.T) {
	path := writeConfigXML(t, `<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>fw01</hostname>
    <timezone>  America/New_York  </timezone>
    <webgui><protocol>https</protocol><port>8443</port></webgui>
  </system>
  <interfaces>
    <wan><if>em0</if><descr>WAN</descr><enable>1</enable></wan>
    <lan><if>em1</if><descr>LAN</descr><enable></enable></lan>
    <opt1><if>em2</if><descr>DMZ</descr><enable>0</enable></opt1>
    <opt2><if>em3</if><descr>Guest</descr></opt2>
  </interfaces>
</opnsense>`)

	got, err := ReadSystemFacts(path)
	if err != nil {
		t.Fatalf("ReadSystemFacts: %v", err)
	}
	if got.Timezone != "America/New_York" {
		t.Fatalf("timezone = %q", got.Timezone)
	}

	want := []InterfaceEntry{
		{Role: "wan", If: "em0", Descr: "WAN", Enabled: true},
		{Role: "lan", If: "em1", Descr: "LAN", Enabled: true},     // present but empty → enabled
		{Role: "opt1", If: "em2", Descr: "DMZ", Enabled: false},   // explicit 0
		{Role: "opt2", If: "em3", Descr: "Guest", Enabled: false}, // absent → disabled
	}
	if len(got.Interfaces) != len(want) {
		t.Fatalf("interfaces = %+v, want %d entries", got.Interfaces, len(want))
	}
	for i, w := range want {
		if got.Interfaces[i] != w {
			t.Fatalf("interface %d = %+v, want %+v", i, got.Interfaces[i], w)
		}
	}
}

// The webgui reader must keep working off the same extended struct.
func TestReadWebGUIConfigStillParsesTheSharedStruct(t *testing.T) {
	path := writeConfigXML(t, `<?xml version="1.0"?>
<opnsense><system><timezone>Etc/UTC</timezone><webgui><protocol>http</protocol><port>8080</port></webgui></system></opnsense>`)

	wg := ReadWebGUIConfig(path)
	if wg.Protocol != "http" || wg.Port != 8080 {
		t.Fatalf("webgui = %+v", wg)
	}
}

func TestReadSystemFactsReportsMissingFile(t *testing.T) {
	if _, err := ReadSystemFacts(filepath.Join(t.TempDir(), "absent.xml")); err == nil {
		t.Fatal("expected an error for a missing config.xml")
	}
}

func TestReadSystemFactsReportsMalformedXML(t *testing.T) {
	path := writeConfigXML(t, `<opnsense><system><timezone>X`)
	if _, err := ReadSystemFacts(path); err == nil {
		t.Fatal("expected an error for malformed XML")
	}
}
