package facts

import (
	"encoding/json"
	"strings"
	"testing"
)

func sampleFacts() *Facts {
	return &Facts{
		V:        Version,
		Timezone: &Timezone{Name: "America/Sao_Paulo", UTCOffsetSec: -10800, Abbrev: "-03"},
		Interfaces: []Interface{
			{Role: "wan", If: "em0", Descr: "WAN", Enabled: true},
			{Role: "lan", If: "em1", Descr: "LAN", Enabled: true},
		},
		OPNsense: &OPNsense{Version: "26.1.9", Series: "26.1"},
		OS:       &OS{Platform: "freebsd", Version: "15.0-RELEASE"},
		Hostname: "fw01",
	}
}

func TestSetHashIsDeterministic(t *testing.T) {
	a, b := sampleFacts(), sampleFacts()
	if err := a.SetHash(); err != nil {
		t.Fatalf("SetHash: %v", err)
	}
	if err := b.SetHash(); err != nil {
		t.Fatalf("SetHash: %v", err)
	}
	if a.Hash != b.Hash {
		t.Fatalf("hash not deterministic: %q vs %q", a.Hash, b.Hash)
	}
	if len(a.Hash) != 16 {
		t.Fatalf("hash length = %d, want 16", len(a.Hash))
	}
	for _, r := range a.Hash {
		if !strings.ContainsRune("0123456789abcdef", r) {
			t.Fatalf("hash %q is not lowercase hex", a.Hash)
		}
	}
}

// The contract hashes the object WITHOUT the hash key, so re-hashing a
// payload that already carries one must not change the value.
func TestSetHashExcludesTheHashField(t *testing.T) {
	f := sampleFacts()
	if err := f.SetHash(); err != nil {
		t.Fatalf("SetHash: %v", err)
	}
	first := f.Hash
	if err := f.SetHash(); err != nil {
		t.Fatalf("SetHash: %v", err)
	}
	if f.Hash != first {
		t.Fatalf("re-hashing changed the value: %q -> %q", first, f.Hash)
	}
}

func TestHashIndependentOfKeyOrder(t *testing.T) {
	f := sampleFacts()
	if err := f.SetHash(); err != nil {
		t.Fatalf("SetHash: %v", err)
	}

	// Round-trip through a generic map with a deliberately different
	// insertion order, then back into the struct.
	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	reordered, err := json.Marshal(generic)
	if err != nil {
		t.Fatalf("remarshal: %v", err)
	}
	var back Facts
	if err := json.Unmarshal(reordered, &back); err != nil {
		t.Fatalf("unmarshal back: %v", err)
	}
	want := back.Hash
	if err := back.SetHash(); err != nil {
		t.Fatalf("SetHash: %v", err)
	}
	if back.Hash != want {
		t.Fatalf("hash changed across a key-order round trip: %q -> %q", want, back.Hash)
	}
}

func TestHashChangesWithContent(t *testing.T) {
	a := sampleFacts()
	if err := a.SetHash(); err != nil {
		t.Fatalf("SetHash: %v", err)
	}
	b := sampleFacts()
	b.Timezone.Name = "Europe/Lisbon"
	if err := b.SetHash(); err != nil {
		t.Fatalf("SetHash: %v", err)
	}
	if a.Hash == b.Hash {
		t.Fatal("different facts produced the same hash")
	}
}

func TestCanonicalJSONHasSortedKeysAndNoWhitespace(t *testing.T) {
	f := sampleFacts()
	canonical, err := canonicalJSON(f)
	if err != nil {
		t.Fatalf("canonicalJSON: %v", err)
	}
	got := string(canonical)
	if strings.ContainsAny(got, " \n\t") {
		t.Fatalf("canonical JSON contains whitespace: %s", got)
	}
	// "hostname" sorts before "interfaces" before "opnsense" before "os".
	for _, pair := range [][2]string{
		{`"hostname"`, `"interfaces"`},
		{`"interfaces"`, `"opnsense"`},
		{`"opnsense"`, `"os"`},
		{`"os"`, `"timezone"`},
	} {
		if strings.Index(got, pair[0]) > strings.Index(got, pair[1]) {
			t.Fatalf("%s should precede %s in %s", pair[0], pair[1], got)
		}
	}
	// Integers must not gain a decimal point on the round trip.
	if !strings.Contains(got, `"utc_offset_sec":-10800`) {
		t.Fatalf("offset not serialized as an integer: %s", got)
	}
}

func TestNormalizeClampsStrings(t *testing.T) {
	f := &Facts{
		Timezone:   &Timezone{Name: strings.Repeat("z", MaxTimezoneName+10), UTCOffsetSec: 0, Abbrev: strings.Repeat("A", MaxTimezoneAbbrev+5)},
		Interfaces: []Interface{{Role: strings.Repeat("r", MaxInterfaceRole+5), If: strings.Repeat("i", MaxInterfaceIf+5), Descr: strings.Repeat("d", MaxInterfaceDescr+5)}},
		OPNsense:   &OPNsense{Version: strings.Repeat("v", MaxOPNsenseVersion+5), Series: strings.Repeat("s", MaxOPNsenseSeries+5)},
		OS:         &OS{Platform: strings.Repeat("p", MaxOSPlatform+5), Version: strings.Repeat("o", MaxOSVersion+5)},
		Hostname:   strings.Repeat("h", MaxHostname+5),
	}
	notes := f.Normalize()
	if len(notes) == 0 {
		t.Fatal("expected clamp notes")
	}
	if len(f.Timezone.Name) != MaxTimezoneName || len(f.Timezone.Abbrev) != MaxTimezoneAbbrev {
		t.Fatalf("timezone not clamped: %+v", f.Timezone)
	}
	if len(f.Interfaces[0].Role) != MaxInterfaceRole || len(f.Interfaces[0].If) != MaxInterfaceIf || len(f.Interfaces[0].Descr) != MaxInterfaceDescr {
		t.Fatalf("interface not clamped: %+v", f.Interfaces[0])
	}
	if len(f.OPNsense.Version) != MaxOPNsenseVersion || len(f.OPNsense.Series) != MaxOPNsenseSeries {
		t.Fatalf("opnsense not clamped: %+v", f.OPNsense)
	}
	if len(f.OS.Platform) != MaxOSPlatform || len(f.OS.Version) != MaxOSVersion {
		t.Fatalf("os not clamped: %+v", f.OS)
	}
	if len(f.Hostname) != MaxHostname {
		t.Fatalf("hostname not clamped: %d", len(f.Hostname))
	}
	if f.V != Version {
		t.Fatalf("v = %d, want %d", f.V, Version)
	}
}

func TestNormalizeStripsControlCharacters(t *testing.T) {
	f := &Facts{Hostname: "fw\x0001\n"}
	f.Normalize()
	if f.Hostname != "fw01" {
		t.Fatalf("hostname = %q, want %q", f.Hostname, "fw01")
	}
}

func TestNormalizeTruncatesInterfaceCount(t *testing.T) {
	f := &Facts{}
	for i := 0; i < MaxInterfaces+20; i++ {
		f.Interfaces = append(f.Interfaces, Interface{Role: "opt", If: "em0"})
	}
	f.Normalize()
	if len(f.Interfaces) != MaxInterfaces {
		t.Fatalf("interfaces = %d, want %d", len(f.Interfaces), MaxInterfaces)
	}
}

func TestNormalizeDropsOutOfRangeOffset(t *testing.T) {
	f := &Facts{Timezone: &Timezone{Name: "Bad/Zone", UTCOffsetSec: MaxUTCOffsetSec + 1}}
	f.Normalize()
	if f.Timezone != nil {
		t.Fatalf("timezone should be dropped, got %+v", f.Timezone)
	}
}

func TestNormalizeShedsInterfacesToFitSizeLimit(t *testing.T) {
	f := &Facts{}
	// 64 maximally long interfaces blow past the 8 KB budget.
	for i := 0; i < MaxInterfaces; i++ {
		f.Interfaces = append(f.Interfaces, Interface{
			Role:  strings.Repeat("r", MaxInterfaceRole),
			If:    strings.Repeat("i", MaxInterfaceIf),
			Descr: strings.Repeat("d", MaxInterfaceDescr),
		})
	}
	f.Normalize()
	if err := f.SetHash(); err != nil {
		t.Fatalf("SetHash: %v", err)
	}
	if f.TooLarge() {
		t.Fatal("payload still over the size limit after normalization")
	}
	if len(f.Interfaces) == 0 || len(f.Interfaces) >= MaxInterfaces {
		t.Fatalf("expected some interfaces shed, got %d", len(f.Interfaces))
	}
}

func TestNormalizedSampleFitsTheContract(t *testing.T) {
	f := sampleFacts()
	if notes := f.Normalize(); len(notes) != 0 {
		t.Fatalf("unexpected adjustments on a clean payload: %v", notes)
	}
	if err := f.SetHash(); err != nil {
		t.Fatalf("SetHash: %v", err)
	}
	if f.TooLarge() {
		t.Fatal("sample payload over the size limit")
	}
}
