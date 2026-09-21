package facts

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	// Embed the IANA database so the timezone assertions hold on build
	// hosts without /usr/share/zoneinfo. The agent itself relies on
	// FreeBSD's system tzdata and does not embed this.
	_ "time/tzdata"
)

// fixtureConfigXML mirrors a real OPNsense config.xml: timezone under
// <system>, one interface per role under <interfaces>, one of them
// disabled (no <enable> element), plus sections the collector must
// ignore.
const fixtureConfigXML = `<?xml version="1.0"?>
<opnsense>
  <version>26.1.9</version>
  <system>
    <hostname>fw01</hostname>
    <domain>example.local</domain>
    <timezone>America/New_York</timezone>
    <webgui>
      <protocol>https</protocol>
      <port>8443</port>
    </webgui>
  </system>
  <interfaces>
    <wan>
      <if>em0</if>
      <descr>WAN</descr>
      <enable>1</enable>
      <ipaddr>dhcp</ipaddr>
    </wan>
    <lan>
      <if>em1</if>
      <descr>LAN</descr>
      <enable>1</enable>
      <ipaddr>192.168.1.1</ipaddr>
    </lan>
    <opt2>
      <if>em3</if>
      <descr>Guest</descr>
      <ipaddr>192.168.2.1</ipaddr>
    </opt2>
  </interfaces>
  <filter>
    <rule><type>pass</type><interface>lan</interface></rule>
  </filter>
</opnsense>
`

func writeFixture(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.xml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

// testCollector returns a collector with every host-dependent probe
// stubbed, so the assertions hold on any build machine.
func testCollector(t *testing.T, body string, at time.Time) *Collector {
	t.Helper()
	c := New(writeFixture(t, body))
	c.now = func() time.Time { return at }
	c.hostInfo = func() (string, string, error) { return "freebsd", "15.0-RELEASE", nil }
	c.hostname = func() (string, error) { return "fw01", nil }
	c.SetOPNsenseVersionProvider(func() string { return "26.1.9" })
	return c
}

func TestCollectParsesTheFixture(t *testing.T) {
	// A January instant: America/New_York is on standard time (EST).
	at := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	f, err := testCollector(t, fixtureConfigXML, at).Collect()
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	if f.V != Version {
		t.Fatalf("v = %d, want %d", f.V, Version)
	}
	if f.Hash == "" {
		t.Fatal("hash not set")
	}
	if f.Timezone == nil || f.Timezone.Name != "America/New_York" {
		t.Fatalf("timezone = %+v", f.Timezone)
	}
	if f.Timezone.UTCOffsetSec != -18000 || f.Timezone.Abbrev != "EST" {
		t.Fatalf("winter offset = %+v, want -18000/EST", f.Timezone)
	}
	if f.OPNsense == nil || f.OPNsense.Version != "26.1.9" || f.OPNsense.Series != "26.1" {
		t.Fatalf("opnsense = %+v", f.OPNsense)
	}
	if f.OS == nil || f.OS.Platform != "freebsd" || f.OS.Version != "15.0-RELEASE" {
		t.Fatalf("os = %+v", f.OS)
	}
	if f.Hostname != "fw01" {
		t.Fatalf("hostname = %q", f.Hostname)
	}

	want := []Interface{
		{Role: "wan", If: "em0", Descr: "WAN", Enabled: true},
		{Role: "lan", If: "em1", Descr: "LAN", Enabled: true},
		{Role: "opt2", If: "em3", Descr: "Guest", Enabled: false},
	}
	if len(f.Interfaces) != len(want) {
		t.Fatalf("interfaces = %+v, want %d entries", f.Interfaces, len(want))
	}
	for i, w := range want {
		if f.Interfaces[i] != w {
			t.Fatalf("interface %d = %+v, want %+v", i, f.Interfaces[i], w)
		}
	}
}

// The offset is computed at collection time, so a DST transition is
// reported without restarting the agent.
func TestCollectOffsetIsDSTCorrect(t *testing.T) {
	summer := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	f, err := testCollector(t, fixtureConfigXML, summer).Collect()
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if f.Timezone.UTCOffsetSec != -14400 || f.Timezone.Abbrev != "EDT" {
		t.Fatalf("summer offset = %+v, want -14400/EDT", f.Timezone)
	}
}

func TestCollectOmitsTimezoneWhenTheNodeIsMissing(t *testing.T) {
	body := `<?xml version="1.0"?>
<opnsense><system><hostname>fw01</hostname></system><interfaces><wan><if>em0</if><enable>1</enable></wan></interfaces></opnsense>`
	f, err := testCollector(t, body, time.Now()).Collect()
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if f.Timezone != nil {
		t.Fatalf("timezone should be omitted, got %+v", f.Timezone)
	}
	if len(f.Interfaces) != 1 {
		t.Fatalf("interfaces = %+v", f.Interfaces)
	}
}

func TestCollectOmitsTimezoneWhenTheZoneIsUnknown(t *testing.T) {
	body := strings.Replace(fixtureConfigXML, "America/New_York", "Mars/Olympus_Mons", 1)
	f, err := testCollector(t, body, time.Now()).Collect()
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if f.Timezone != nil {
		t.Fatalf("timezone should be omitted, got %+v", f.Timezone)
	}
}

// An unreadable config.xml costs the timezone and interfaces, not the
// whole payload: the heartbeat must still go out.
func TestCollectSurvivesAnUnreadableConfigXML(t *testing.T) {
	c := New(filepath.Join(t.TempDir(), "absent.xml"))
	c.hostInfo = func() (string, string, error) { return "freebsd", "15.0-RELEASE", nil }
	c.hostname = func() (string, error) { return "fw01", nil }

	f, err := c.Collect()
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if f.Timezone != nil || f.Interfaces != nil {
		t.Fatalf("expected no config-derived facts, got %+v", f)
	}
	if f.OS == nil || f.Hostname != "fw01" {
		t.Fatalf("host-derived facts missing: %+v", f)
	}
	if f.Hash == "" {
		t.Fatal("hash not set")
	}
}

func TestCollectOmitsSubObjectsOnProbeFailure(t *testing.T) {
	c := testCollector(t, fixtureConfigXML, time.Now())
	c.hostInfo = func() (string, string, error) { return "", "", errors.New("boom") }
	c.hostname = func() (string, error) { return "", errors.New("boom") }
	c.SetOPNsenseVersionProvider(nil)

	f, err := c.Collect()
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if f.OS != nil || f.OPNsense != nil || f.Hostname != "" {
		t.Fatalf("expected omitted sub-objects, got %+v", f)
	}
	if f.Timezone == nil {
		t.Fatal("timezone should still be present")
	}
}

// Before the heavy-telemetry collector's first refresh the provider
// returns an empty version, and the sub-object stays out.
func TestCollectOmitsOPNsenseBeforeTheFirstHeavyRefresh(t *testing.T) {
	c := testCollector(t, fixtureConfigXML, time.Now())
	c.SetOPNsenseVersionProvider(func() string { return "" })
	f, err := c.Collect()
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if f.OPNsense != nil {
		t.Fatalf("opnsense should be omitted, got %+v", f.OPNsense)
	}
}

// A config.xml with absurd values must not produce a payload the server
// would reject: values clamp and the payload stays inside the budget.
func TestCollectClampsAnOversizedConfigXML(t *testing.T) {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?><opnsense><system><timezone>America/New_York</timezone></system><interfaces>`)
	for i := 0; i < 200; i++ {
		b.WriteString("<opt")
		b.WriteString(strings.Repeat("x", 80))
		b.WriteString("><if>")
		b.WriteString(strings.Repeat("e", 80))
		b.WriteString("</if><descr>")
		b.WriteString(strings.Repeat("d", 200))
		b.WriteString("</descr><enable>1</enable></opt")
		b.WriteString(strings.Repeat("x", 80))
		b.WriteString(">")
	}
	b.WriteString(`</interfaces></opnsense>`)

	f, err := testCollector(t, b.String(), time.Now()).Collect()
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(f.Interfaces) > MaxInterfaces {
		t.Fatalf("interfaces = %d, want <= %d", len(f.Interfaces), MaxInterfaces)
	}
	for _, iface := range f.Interfaces {
		if len(iface.Role) > MaxInterfaceRole || len(iface.If) > MaxInterfaceIf || len(iface.Descr) > MaxInterfaceDescr {
			t.Fatalf("interface exceeds the contract bounds: %+v", iface)
		}
	}
	if f.TooLarge() {
		t.Fatal("payload over the contract size limit")
	}
}

func TestSeriesOf(t *testing.T) {
	cases := map[string]string{
		"26.1.9":  "26.1",
		"26.1":    "26.1",
		"26":      "",
		"":        "",
		"26.7.1a": "26.7",
	}
	for in, want := range cases {
		if got := seriesOf(in); got != want {
			t.Errorf("seriesOf(%q) = %q, want %q", in, got, want)
		}
	}
}
