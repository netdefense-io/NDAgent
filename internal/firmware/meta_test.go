package firmware

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

func status(upgrade, added []opnapi.FirmwarePackageEntry, needsReboot bool) *opnapi.FirmwareUpgradeStatus {
	return &opnapi.FirmwareUpgradeStatus{
		ProductVersion:  "26.7.3_8",
		ProductLatest:   "26.7.3_8", // the stale value: it never moves with the update
		UpgradePackages: upgrade,
		NewPackages:     added,
		NeedsReboot:     needsReboot,
	}
}

func entry(name, current, next string) opnapi.FirmwarePackageEntry {
	return opnapi.FirmwarePackageEntry{Name: name, CurrentVersion: current, NewVersionAlt: next}
}

func TestPlannedPackages_UpgradesAndNewOnes(t *testing.T) {
	st := status(
		[]opnapi.FirmwarePackageEntry{
			entry("opnsense", "26.7.3_8", "26.7.4_1"),
			entry("base", "26.7.3", "26.7.4"),
			entry("curl", "8.9.0", "8.9.1_1"),
			entry("", "x", "y"), // nameless: dropped
		},
		[]opnapi.FirmwarePackageEntry{
			{Name: "py311-newdep", NewVersion: "1.0"}, // new_packages carry "version"
			{Name: "curl", NewVersion: "9.9"},         // already planned as an upgrade: kept once
		},
		true,
	)
	st.ReinstallPackages = []opnapi.FirmwarePackageEntry{entry("reinstalled", "1", "1")}
	st.RemovePackages = []opnapi.FirmwarePackageEntry{entry("removed", "1", "")}

	want := []Package{
		{"opnsense", "26.7.4_1"}, {"base", "26.7.4"}, {"curl", "8.9.1_1"}, {"py311-newdep", "1.0"},
	}
	if got := PlannedPackages(st); !reflect.DeepEqual(got, want) {
		t.Fatalf("PlannedPackages = %+v, want %+v", got, want)
	}
	if PlannedPackages(nil) != nil {
		t.Fatal("no status means no plan")
	}
}

// to_version comes from the plan, not from product_latest, which is derived
// from the installed changelog and does not move with the update.
func TestCoreVersionAndPackagesApplied(t *testing.T) {
	plan := []Package{
		{"opnsense", "26.7.4_1"}, {"base", "26.7.4"}, {"kernel", "26.7.4"},
		{"curl", "8.9.1_1"}, {"py311-newdep", "1.0"},
	}
	if got := CoreVersion(plan); got != "26.7.4_1" {
		t.Errorf("CoreVersion = %q, want 26.7.4_1", got)
	}
	if got := CoreVersion([]Package{{"curl", "8.9.1_1"}}); got != "" {
		t.Errorf("CoreVersion of a plan without the core package = %q, want empty", got)
	}
	for _, name := range []string{"opnsense-business", "opnsense-devel"} {
		if got := CoreVersion([]Package{{name, "26.7.4_1"}}); got != "26.7.4_1" {
			t.Errorf("CoreVersion for %s = %q", name, got)
		}
	}
	// base and kernel are a reboot; new packages are installed by the update.
	if got := PackagesApplied(plan); got != 3 {
		t.Errorf("PackagesApplied = %d, want 3 (opnsense, curl, py311-newdep)", got)
	}
	if !HasBaseOrKernel(plan) || HasBaseOrKernel([]Package{{"curl", "1"}}) {
		t.Error("HasBaseOrKernel is wrong")
	}
}

func TestNewMeta(t *testing.T) {
	started := time.Date(2026, 9, 22, 9, 0, 0, 0, time.UTC)
	st := status([]opnapi.FirmwarePackageEntry{
		entry("opnsense", "26.7.3_8", "26.7.4_1"), entry("base", "26.7.3", "26.7.4"),
	}, nil, true)

	m := NewMeta("minor", true, "26.7.3_8", st, 1_780_000_000, started, started.Add(15*time.Minute))

	if m.Mode != "minor" || !m.Reboot || m.FromVersion != "26.7.3_8" || !m.NeedsReboot ||
		m.BootTime != 1_780_000_000 || m.StartedAt != started.Unix() || m.ExpiresAt != started.Add(15*time.Minute).Unix() {
		t.Fatalf("NewMeta = %+v", m)
	}
	if len(m.Packages) != 2 || m.PackagesTotal != 0 {
		t.Fatalf("plan = %+v (total %d), want the two packages and no truncation note", m.Packages, m.PackagesTotal)
	}

	// It survives the task store: JSON in, JSON out.
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Meta
	if err := json.Unmarshal(raw, &back); err != nil || !reflect.DeepEqual(back, m) {
		t.Fatalf("round trip: %+v, %v", back, err)
	}
}

func TestNewMeta_CapsThePlanKeepingWhatMattersMost(t *testing.T) {
	var upgrades []opnapi.FirmwarePackageEntry
	for i := 0; i < 300; i++ {
		upgrades = append(upgrades, entry(fmt.Sprintf("pkg%03d", i), "1", "2"))
	}
	// the important ones arrive last
	upgrades = append(upgrades,
		entry("os-netdefense", "1.19.4", "1.19.5"), entry("kernel", "1", "2"),
		entry("base", "1", "2"), entry("opnsense", "26.7.3_8", "26.7.4_1"))

	m := NewMeta("minor", true, "26.7.3_8", status(upgrades, nil, true), 0, t0, t0.Add(time.Minute))

	if len(m.Packages) != MaxPlannedPackages || m.PackagesTotal != 304 {
		t.Fatalf("stored %d packages of %d, want %d of 304", len(m.Packages), m.PackagesTotal, MaxPlannedPackages)
	}
	kept := map[string]bool{}
	for _, p := range m.Packages {
		kept[p.Name] = true
	}
	for _, name := range []string{"opnsense", "base", "kernel", "os-netdefense"} {
		if !kept[name] {
			t.Errorf("%s was dropped when the plan was cut", name)
		}
	}
	if !m.RebootExpected() {
		t.Error("the reboot expectation must survive the cut: base and kernel were kept")
	}
}

func TestMeta_RebootExpected(t *testing.T) {
	withBase := []Package{{"base", "2"}}
	cases := []struct {
		name string
		m    Meta
		want bool
	}{
		{"minor with base in the plan", Meta{Mode: "minor", Reboot: true, Packages: withBase}, true},
		{"minor packages only", Meta{Mode: "minor", Reboot: true, Packages: []Package{{"curl", "2"}}}, false},
		{"minor packages only, reboot announced", Meta{Mode: "minor", Reboot: true, RebootSeen: true}, true},
		{"major always", Meta{Mode: "major", Reboot: true}, true},
		{"reboot=false defers base and kernel by design", Meta{Mode: "minor", Reboot: false, Packages: withBase}, false},
	}
	for _, tc := range cases {
		if got := tc.m.RebootExpected(); got != tc.want {
			t.Errorf("%s: RebootExpected = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestMeta_ExpectedRebootsAndExpiry(t *testing.T) {
	if got := (Meta{Mode: "minor", Reboot: false}).ExpectedReboots(); got != 0 {
		t.Errorf("minor reboot=false: %d", got)
	}
	if got := (Meta{Mode: "minor", Reboot: true}).ExpectedReboots(); got != 1 {
		t.Errorf("minor reboot=true: %d", got)
	}
	if got := (Meta{Mode: "major", Reboot: true}).ExpectedReboots(); got != 2 {
		t.Errorf("major: %d", got)
	}

	signed := Meta{Mode: "minor", StartedAt: t0.Unix(), ExpiresAt: t0.Add(7 * time.Minute).Unix()}
	if got := signed.Expiry(); !got.Equal(t0.Add(7 * time.Minute)) {
		t.Errorf("a recorded expiry must be used as it is: %v", got)
	}
	if got := (Meta{Mode: "minor", StartedAt: t0.Unix()}).Expiry(); !got.Equal(t0.Add(MinorTTL)) {
		t.Errorf("without one, minor gets its TTL: %v", got)
	}
	if got := (Meta{Mode: "major", StartedAt: t0.Unix()}).Expiry(); !got.Equal(t0.Add(MajorTTL)) {
		t.Errorf("without one, major gets its TTL: %v", got)
	}
}

// A task that was taken up and has triggered nothing is recorded as such, and the
// record round-trips through the row's JSON with the trigger unset.
func TestNewMarker_IsARunThatNeverTriggered(t *testing.T) {
	started := time.Date(2026, 9, 27, 9, 0, 0, 0, time.UTC)
	m := NewMarker("minor", true, started, started.Add(MinorTTL))

	if m.Mode != "minor" || !m.Reboot || m.StartedAt != started.Unix() || m.ExpiresAt != started.Add(MinorTTL).Unix() {
		t.Fatalf("marker = %+v", m)
	}
	if m.Triggered() {
		t.Fatal("a marker is a task that has triggered nothing")
	}
	if len(m.Packages) != 0 || m.FromVersion != "" {
		t.Fatalf("a marker holds no plan: %+v", m)
	}

	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var back Meta
	if err := json.Unmarshal(raw, &back); err != nil || back.Triggered() || back.Mode != "minor" {
		t.Fatalf("round trip = %+v, %v (%s)", back, err, raw)
	}
	if want := `"triggered_at"`; strings.Contains(string(raw), want) {
		t.Fatalf("an untriggered record carries %s: %s", want, raw)
	}

	m.TriggeredAt = started.Add(time.Minute).Unix()
	if !m.Triggered() {
		t.Fatal("a record with a trigger time is a triggered run")
	}
}
