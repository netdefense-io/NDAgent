package facts

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "time/tzdata"
)

// updateGolden rewrites the committed sample payloads instead of
// comparing against them: `go test ./internal/facts -update`.
var updateGolden = flag.Bool("update", false, "rewrite the testdata sample payloads")

// labConfigXML is the shape the e2e lab VMs actually have: interfaces
// that were never given a description in the OPNsense GUI, so <descr>
// is absent (wan/lan) or present-but-blank (wireguard). This is the
// payload that used to be rejected wholesale by the shared validator
// because the agent serialized `"descr":""` for every entry.
const labConfigXML = `<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>e2e-b</hostname>
    <timezone>Etc/UTC</timezone>
  </system>
  <interfaces>
    <wan><if>vtnet0</if><enable>1</enable><ipaddr>dhcp</ipaddr></wan>
    <lan><if>vtnet1</if><enable>1</enable><ipaddr>192.168.2.1</ipaddr></lan>
    <wireguard><if>wg0</if><descr>   </descr><enable>1</enable></wireguard>
  </interfaces>
</opnsense>
`

// assertNoEmptyLeaves walks a serialized facts document and fails on any
// leaf the shared NDDataModels validator would reject or that the
// contract says must be omitted: an empty string value, an empty object
// or an empty array. Optional leaves are omitted, never sent as "".
func assertNoEmptyLeaves(t *testing.T, raw []byte) {
	t.Helper()

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	var walk func(path string, v any)
	walk = func(path string, v any) {
		switch value := v.(type) {
		case string:
			if value == "" {
				t.Fatalf("%s is present with an empty string value in %s", path, raw)
			}
		case map[string]any:
			if len(value) == 0 {
				t.Fatalf("%s is present with an empty object in %s", path, raw)
			}
			for k, child := range value {
				walk(path+"."+k, child)
			}
		case []any:
			if len(value) == 0 {
				t.Fatalf("%s is present with an empty array in %s", path, raw)
			}
			for i, child := range value {
				walk(fmt.Sprintf("%s[%d]", path, i), child)
			}
		}
	}
	walk("$", doc)
}

// golden compares the canonical payload against the committed sample,
// which NDDataModels consumes as a cross-repo compatibility vector.
func golden(t *testing.T, name string, f *Facts) []byte {
	t.Helper()

	raw, err := canonicalJSON(f)
	if err != nil {
		t.Fatalf("canonicalJSON: %v", err)
	}
	raw = append(raw, '\n')

	path := filepath.Join("testdata", name)
	if *updateGolden {
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		return raw
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s (run go test ./internal/facts -update): %v", path, err)
	}
	if !bytes.Equal(want, raw) {
		t.Fatalf("%s is stale:\n got: %s\nwant: %s", path, raw, want)
	}
	return raw
}

func TestFixturePayloadHasNoEmptyLeaves(t *testing.T) {
	at := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	f, err := testCollector(t, fixtureConfigXML, at).Collect()
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	assertNoEmptyLeaves(t, golden(t, "facts-fixture.json", f))
}

// The regression this fixes: on a lab-shaped config.xml every interface
// used to carry `"descr":""`, and NDDataModels' validator rejected the
// whole document on the first one ("facts interfaces entry 'descr' must
// not be empty"), so the broker dropped every connect/heartbeat payload.
func TestLabPayloadOmitsBlankOptionalLeaves(t *testing.T) {
	c := testCollector(t, labConfigXML, time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC))
	c.hostInfo = func() (string, string, error) { return "freebsd", "15.0-RELEASE", nil }
	c.hostname = func() (string, error) { return "e2e-b.internal", nil }
	c.SetOPNsenseVersionProvider(func() string { return "26.7.1" })

	f, err := c.Collect()
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	raw := golden(t, "facts-lab.json", f)
	assertNoEmptyLeaves(t, raw)
	if strings.Contains(string(raw), `"descr"`) {
		t.Fatalf("descr must be omitted when the device has none: %s", raw)
	}
	if len(f.Interfaces) != 3 {
		t.Fatalf("interfaces = %+v, want wan/lan/wireguard", f.Interfaces)
	}
	if f.Timezone == nil || f.Timezone.Name != "Etc/UTC" || f.Timezone.UTCOffsetSec != 0 {
		t.Fatalf("timezone = %+v", f.Timezone)
	}
	// utc_offset_sec is a required-when-present integer, not an optional
	// string: zero stays on the wire.
	if !strings.Contains(string(raw), `"utc_offset_sec":0`) {
		t.Fatalf("a zero offset must still be sent: %s", raw)
	}
}

// Every optional string leaf must drop out when it is blank, including
// whitespace-only values that clamp trims to "".
func TestNormalizeOmitsEveryBlankOptionalLeaf(t *testing.T) {
	f := &Facts{
		V:        Version,
		Timezone: &Timezone{Name: "Etc/UTC", UTCOffsetSec: 0, Abbrev: "  "},
		Interfaces: []Interface{
			{Role: "wan", If: "vtnet0", Descr: "", Enabled: true},
			{Role: "lan", If: "vtnet1", Descr: "   ", Enabled: false},
		},
		OPNsense: &OPNsense{Version: "26.7.1", Series: ""},
		OS:       &OS{Platform: "freebsd", Version: ""},
		Hostname: "  ",
	}
	f.Normalize()
	if err := f.SetHash(); err != nil {
		t.Fatalf("SetHash: %v", err)
	}

	raw, err := canonicalJSON(f)
	if err != nil {
		t.Fatalf("canonicalJSON: %v", err)
	}
	assertNoEmptyLeaves(t, raw)
	for _, key := range []string{`"abbrev"`, `"descr"`, `"series"`, `"hostname"`} {
		if strings.Contains(string(raw), key) {
			t.Fatalf("%s should be omitted when blank: %s", key, raw)
		}
	}
	if !strings.Contains(string(raw), `"version":"26.7.1"`) {
		t.Fatalf("a non-blank sibling must survive: %s", raw)
	}
}

// An interface whose identity leaf is missing is dropped rather than
// sent with an empty `if`, which the contract requires to be present.
func TestNormalizeDropsInterfacesWithoutAnIf(t *testing.T) {
	f := &Facts{Interfaces: []Interface{
		{Role: "wan", If: "vtnet0", Enabled: true},
		{Role: "opt1", If: "  ", Enabled: true},
	}}
	f.Normalize()
	if len(f.Interfaces) != 1 || f.Interfaces[0].If != "vtnet0" {
		t.Fatalf("interfaces = %+v, want only wan", f.Interfaces)
	}
}

// The hash covers the normalized document: recomputing it over what is
// actually serialized must reproduce the stored value, so the broker's
// "persist only when the hash changed" comparison stays sound.
func TestHashCoversTheNormalizedDocument(t *testing.T) {
	c := testCollector(t, labConfigXML, time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC))
	c.hostname = func() (string, error) { return "e2e-b.internal", nil }
	f, err := c.Collect()
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if f.Hash == "" {
		t.Fatal("hash not set")
	}

	// Round-trip the serialized payload — the exact bytes the broker
	// sees — and rehash it. Normalization ran before hashing, so this
	// is a no-op; if it were not, the hash would move here.
	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Facts
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if notes := back.Normalize(); len(notes) != 0 {
		t.Fatalf("serialized payload was not already normalized: %v", notes)
	}
	want := back.Hash
	if err := back.SetHash(); err != nil {
		t.Fatalf("SetHash: %v", err)
	}
	if back.Hash != want {
		t.Fatalf("hash does not cover the normalized document: %q -> %q", want, back.Hash)
	}
}
