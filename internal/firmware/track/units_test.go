package track

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// --- flavours ----------------------------------------------------------------------

func TestFlavourRoundTrip(t *testing.T) {
	for _, tc := range []struct{ series, dir string }{
		{"26.7", "26.7"}, {"26.7", "26.7.3"}, {"24.7", "24.7.12_2"}, {"26.1", "26.1.11"},
	} {
		f := Flavour(tc.series, tc.dir)
		series, dir, ok := ParseFlavour(f)
		if !ok || series != tc.series || dir != tc.dir {
			t.Errorf("%q parsed as %q %q %v", f, series, dir, ok)
		}
	}
}

func TestParseFlavourRefusesWhatTheAgentDidNotWrite(t *testing.T) {
	for _, f := range []string{
		"", "OpenSSL", "26.7/latest", "26.7/MINT/26.7.3", "26.7/MINT/26.7.3/aux",
		"26.7/MINT/26.1.11/latest", // a directory outside its series
		"26.7/MINT/26.07.3/latest", "26.7/MINT/latest/latest", "26.7/MINT/26.7.3/latest\n",
		"../26.7/MINT/26.7.3/latest", "26.7/MINT/26.7.3/latest/", " 26.7/MINT/26.7.3/latest",
	} {
		if _, _, ok := ParseFlavour(f); ok {
			t.Errorf("%q was read as a pin", f)
		}
	}
}

func TestDirCoversAndCandidates(t *testing.T) {
	for _, tc := range []struct {
		dir, installed string
		covers         bool
	}{
		{"26.7.3", "26.7.3", true},
		{"26.7.3", "26.7.3_11", true}, // a release's directory takes hotfix revisions in place
		{"26.7.3_11", "26.7.3_11", true},
		{"26.7.3_9", "26.7.3_11", false}, // a hotfix directory holds that revision only
		{"26.7.3", "26.7.4", false},
		{"26.7", "26.7_1", true},
	} {
		if got := DirCovers(tc.dir, tc.installed); got != tc.covers {
			t.Errorf("DirCovers(%q, %q) = %v", tc.dir, tc.installed, got)
		}
	}
	if got := DirCandidates("26.7.3_11"); !equal(got, []string{"26.7.3_11", "26.7.3"}) {
		t.Errorf("candidates %v", got)
	}
	if got := DirCandidates("26.7"); !equal(got, []string{"26.7"}) {
		t.Errorf("candidates %v", got)
	}
}

// --- the pin assessment ------------------------------------------------------------

func TestAssessPin(t *testing.T) {
	pinned := func(flavour string) *State { return &State{Pinned: true, PinnedFlavour: flavour} }
	cases := []struct {
		name      string
		st        *State
		flavour   string
		repoPath  string
		installed string
		kind      pinKind
		drift     bool
		force     bool
	}{
		{"fine", pinned("26.7/MINT/26.7.3/latest"), "26.7/MINT/26.7.3/latest", "26.7/MINT/26.7.3/latest", "26.7.3_11", pinFine, false, false},
		{"fine, the file unreadable", pinned("26.7/MINT/26.7.3/latest"), "26.7/MINT/26.7.3/latest", "", "26.7.3", pinFine, false, false},
		{"reset to the default", pinned("26.7/MINT/26.7.3/latest"), "", "26.7/latest", "26.7.3", pinRepin, true, false},
		{"another pin by hand", pinned("26.7/MINT/26.7.3/latest"), "26.7/MINT/26.7.1/latest", "26.7/MINT/26.7.1/latest", "26.7.3", pinRepin, true, false},
		{"a file that diverged", pinned("26.7/MINT/26.7.3/latest"), "26.7/MINT/26.7.3/latest", "26.7/latest", "26.7.3", pinRepin, true, true},
		{"installed beyond the pin", pinned("26.7/MINT/26.7.3/latest"), "26.7/MINT/26.7.3/latest", "26.7/MINT/26.7.3/latest", "26.7.5", pinRepin, true, false},
		{"the pin ahead of the installed", pinned("26.7/MINT/26.7.5/latest"), "26.7/MINT/26.7.5/latest", "26.7/MINT/26.7.5/latest", "26.7.3_11", pinRepin, false, false},
		{"another series", pinned("26.7/MINT/26.7.3/latest"), "26.7/MINT/26.7.3/latest", "26.7/MINT/26.7.3/latest", "27.1", pinRepin, true, false},
		{"a hotfix directory covers only its revision", pinned("24.7/MINT/24.7.12_2/latest"), "24.7/MINT/24.7.12_2/latest", "24.7/MINT/24.7.12_2/latest", "24.7.12_3", pinRepin, true, false},
		{"the GA directory", pinned("26.7/MINT/26.7/latest"), "26.7/MINT/26.7/latest", "26.7/MINT/26.7/latest", "26.7", pinFine, false, false},
		{"an installed release the agent cannot read", pinned("26.7/MINT/26.7.3/latest"), "26.7/MINT/26.7.3/latest", "", "27.1.a", pinFine, false, false},
	}
	for _, tc := range cases {
		a := assessPin(tc.st, tc.flavour, tc.repoPath, tc.installed)
		if a.kind != tc.kind || a.drift != tc.drift || a.force != tc.force {
			t.Errorf("%s: kind=%v drift=%v force=%v (%s); want %v %v %v", tc.name, a.kind, a.drift, a.force, a.why, tc.kind, tc.drift, tc.force)
		}
	}
}

// --- the plan ----------------------------------------------------------------------

func entry(name, repo, cur, next string) opnapi.FirmwarePackageEntry {
	return opnapi.FirmwarePackageEntry{Name: name, Repository: repo, CurrentVersion: cur, NewVersionAlt: next}
}

// offerSets are the three sets a check lists for an offered series upgrade, as the
// 26.1 to 26.7 offer measured them: sizes in bytes.
func offerSets(series string) []opnapi.FirmwareUpgradeSet {
	return []opnapi.FirmwareUpgradeSet{
		{Name: "packages", Size: 1142865408, CurrentVersion: "26.1.6_2", NewVersion: series, Repository: "OPNsense"},
		{Name: "kernel", Size: 33428352, CurrentVersion: "26.1.11", NewVersion: series, Repository: "OPNsense"},
		{Name: "base", Size: 98926556, CurrentVersion: "26.1.11", NewVersion: series, Repository: "OPNsense"},
	}
}

func statusOf(upgrades ...opnapi.FirmwarePackageEntry) *opnapi.FirmwareUpgradeStatus {
	return &opnapi.FirmwareUpgradeStatus{UpgradePackages: upgrades, Connection: "ok", Repository: "ok", LastCheck: "x"}
}

func TestPlanForEnroll(t *testing.T) {
	const installed = "26.7.3_8"
	cases := []struct {
		name   string
		st     *opnapi.FirmwareUpgradeStatus
		reason string // "" accepted
	}{
		{"empty", statusOf(), ""},
		{"a hotfix revision of the installed release", statusOf(entry("opnsense", "OPNsense", "26.7.3_8", "26.7.3_11")), ""},
		{"an ordinary package", statusOf(entry("curl", "OPNsense", "8.21.0", "8.22.0")), ""},
		{"an upgrade from a repository the pin does not hold", statusOf(entry("os-netdefense-dev", "NetDefense", "1.22_1", "1.23_0")), ""},
		{"a component catching up to the release", statusOf(entry("opnsense-update", "OPNsense", "26.7.2", "26.7.3")), ""},
		{"the core beyond the installed release", statusOf(entry("opnsense", "OPNsense", "26.7.3_8", "26.7.4_1")), ReasonHeldUnexpectedPlan},
		{"opnsense-update beyond", statusOf(entry("opnsense-update", "OPNsense", "26.7.3", "26.7.4")), ReasonHeldUnexpectedPlan},
		{"base pending at the installed release", statusOf(entry("base", "OPNsense", "26.7.2", "26.7.3"), entry("kernel", "OPNsense", "26.7.2", "26.7.3")), ReasonHeldRebootPending},
		{"base beyond the installed release", statusOf(entry("base", "OPNsense", "26.7.3", "26.7.4"), entry("kernel", "OPNsense", "26.7.3", "26.7.4")), ReasonHeldUnexpectedPlan},
		{"a new package", func() *opnapi.FirmwareUpgradeStatus {
			s := statusOf()
			s.NewPackages = []opnapi.FirmwarePackageEntry{{Name: "x", Repository: "OPNsense", NewVersion: "1"}}
			return s
		}(), ReasonHeldUnexpectedPlan},
		{"a package removed", func() *opnapi.FirmwareUpgradeStatus {
			s := statusOf()
			s.RemovePackages = []opnapi.FirmwarePackageEntry{{Name: "x", Repository: "OPNsense", NewVersion: "1"}}
			return s
		}(), ReasonHeldUnexpectedPlan},
		{"a new package from another repository", func() *opnapi.FirmwareUpgradeStatus {
			s := statusOf()
			s.NewPackages = []opnapi.FirmwarePackageEntry{{Name: "x", Repository: "Other", NewVersion: "1"}}
			return s
		}(), ""},
		{"a downgrade, from any repository", func() *opnapi.FirmwareUpgradeStatus {
			s := statusOf()
			s.DowngradePackages = []opnapi.FirmwarePackageEntry{{Name: "x", Repository: "Other"}}
			return s
		}(), ReasonHeldDowngradeRisk},
		// The final build of a series is offered the next one whatever it is pinned to
		// (the offer is a file of that build), so an offer says nothing about the pin:
		// it holds no enroll, and its sets are no queued reboot.
		{"a major upgrade on offer", func() *opnapi.FirmwareUpgradeStatus {
			s := statusOf()
			s.UpgradeMajorVersion = "26.7"
			return s
		}(), ""},
		{"the sets of a major upgrade", func() *opnapi.FirmwareUpgradeStatus {
			s := statusOf()
			s.UpgradeMajorVersion = "26.7"
			s.UpgradeSets = offerSets("26.7")
			return s
		}(), ""},
		{"another ABI", func() *opnapi.FirmwareUpgradeStatus {
			s := statusOf()
			s.CheckABI, s.InstalledABI = "27.1", "26.7"
			return s
		}(), ReasonHeldUnexpectedPlan},
		{"a same-version reinstall", func() *opnapi.FirmwareUpgradeStatus {
			s := statusOf()
			s.ReinstallPackages = []opnapi.FirmwarePackageEntry{{Name: "opnsense", Repository: "OPNsense", NewVersion: "26.7.3_8"}}
			return s
		}(), ""},
	}
	for _, tc := range cases {
		h := NewPlan(tc.st).forEnroll(installed)
		switch {
		case tc.reason == "" && h != nil:
			t.Errorf("%s: held for %s (%s)", tc.name, h.Reason, h.Why)
		case tc.reason != "" && h == nil:
			t.Errorf("%s: accepted, want %s", tc.name, tc.reason)
		case tc.reason != "" && h.Reason != tc.reason:
			t.Errorf("%s: held for %s (%s), want %s", tc.name, h.Reason, h.Why, tc.reason)
		}
	}
}

func TestPlanForAdvance(t *testing.T) {
	core := func(cur, next string) opnapi.FirmwarePackageEntry { return entry("opnsense", "OPNsense", cur, next) }
	sets := func(cur, next string) []opnapi.FirmwarePackageEntry {
		return []opnapi.FirmwarePackageEntry{entry("base", "OPNsense", cur, next), entry("kernel", "OPNsense", cur, next)}
	}
	with := func(base *opnapi.FirmwareUpgradeStatus, extra ...opnapi.FirmwarePackageEntry) *opnapi.FirmwareUpgradeStatus {
		base.UpgradePackages = append(base.UpgradePackages, extra...)
		return base
	}
	cases := []struct {
		name        string
		st          *opnapi.FirmwareUpgradeStatus
		installed   string
		target      string
		needsCore   bool
		kind        advanceKind
		reason      string
		wantVersion string
	}{
		{"lands exactly", statusOf(core("26.7.3_11", "26.7.5"), entry("opnsense-update", "OPNsense", "26.7.3", "26.7.4_1")), "26.7.3_11", "26.7.5", true, planLands, "", "26.7.5"},
		{"lands with the sets", with(statusOf(core("26.7.3_11", "26.7.5"), entry("opnsense-update", "OPNsense", "26.7.3", "26.7.4_1")), sets("26.7.3", "26.7.4")...), "26.7.3_11", "26.7.5", true, planLands, "", "26.7.5"},
		{"lands on a hotfix revision of the target's release", statusOf(core("26.7.3_8", "26.7.3_11")), "26.7.3_8", "26.7.3", false, planLands, "", "26.7.3_11"},
		{"nothing newer", statusOf(), "26.7.3_11", "26.7.3", false, planNothingNewer, "", ""},
		{"only other packages in the target's directory", statusOf(entry("curl", "OPNsense", "8.21.0", "8.22.0")), "26.7.3_11", "26.7.3", false, planLands, "", ""},
		{"offers less than the target", statusOf(core("26.7.3_11", "26.7.4_1")), "26.7.3_11", "26.7.5", true, planBehindTarget, "", ""},
		{"offers nothing at all though the device is below the target", statusOf(), "26.7.3_11", "26.7.5", true, planBehindTarget, "", ""},
		{"a hotfix below a hotfix target", statusOf(core("24.7.12_2", "24.7.12_3")), "24.7.12_2", "24.7.12_4", true, planBehindTarget, "", ""},
		{"beyond the target", statusOf(core("26.7.3_11", "26.7.6")), "26.7.3_11", "26.7.5", true, planHeld, ReasonHeldUnexpectedPlan, ""},
		{"a core that is not above the installed one", statusOf(core("26.7.3_11", "26.7.3_9")), "26.7.3_11", "26.7.3", false, planHeld, ReasonHeldUnexpectedPlan, ""},
		{"a name the agent cannot compare", statusOf(core("26.7.3_11", "26.7.x")), "26.7.3_11", "26.7.5", true, planHeld, ReasonHeldUnexpectedPlan, ""},
		{"base without kernel", statusOf(core("26.7.3_11", "26.7.5"), entry("base", "OPNsense", "26.7.3", "26.7.4")), "26.7.3_11", "26.7.5", true, planHeld, ReasonHeldUnexpectedPlan, ""},
		{"base and kernel at different releases", statusOf(core("26.7.3_11", "26.7.5"), entry("base", "OPNsense", "26.7.3", "26.7.4"), entry("kernel", "OPNsense", "26.7.3", "26.7.5")), "26.7.3_11", "26.7.5", true, planHeld, ReasonHeldUnexpectedPlan, ""},
		{"base that does not match opnsense-update", statusOf(core("26.7.3_11", "26.7.5"), entry("opnsense-update", "OPNsense", "26.7.3", "26.7.4_1"), entry("base", "OPNsense", "26.7.3", "26.7.5"), entry("kernel", "OPNsense", "26.7.3", "26.7.5")), "26.7.3_11", "26.7.5", true, planHeld, ReasonHeldUnexpectedPlan, ""},
		{"a downgrade", func() *opnapi.FirmwareUpgradeStatus {
			s := statusOf(core("26.7.3_11", "26.7.5"))
			s.DowngradePackages = []opnapi.FirmwarePackageEntry{{Name: "curl"}}
			return s
		}(), "26.7.3_11", "26.7.5", true, planHeld, ReasonHeldDowngradeRisk, ""},
		{"a major upgrade on offer is no reason to hold a minor step", func() *opnapi.FirmwareUpgradeStatus {
			s := statusOf()
			s.UpgradeMajorVersion = "26.7"
			s.UpgradeSets = offerSets("26.7")
			return s
		}(), "26.1.11_10", "26.1.11_10", false, planNothingNewer, "", ""},
	}
	for _, tc := range cases {
		kind, h, version := NewPlan(tc.st).forAdvance(tc.installed, tc.target, tc.needsCore)
		if kind != tc.kind {
			why := ""
			if h != nil {
				why = h.Reason + ": " + h.Why
			}
			t.Errorf("%s: kind %v (%s), want %v", tc.name, kind, why, tc.kind)
			continue
		}
		if kind == planHeld && h.Reason != tc.reason {
			t.Errorf("%s: held for %s (%s), want %s", tc.name, h.Reason, h.Why, tc.reason)
		}
		if kind == planLands && tc.wantVersion != "" && version != tc.wantVersion {
			t.Errorf("%s: lands on %q, want %q", tc.name, version, tc.wantVersion)
		}
	}
}

func TestPlanCountsReinstallsWhateverTheirRepository(t *testing.T) {
	st := statusOf()
	st.ReinstallPackages = []opnapi.FirmwarePackageEntry{{Name: "a", Repository: "OPNsense"}, {Name: "b", Repository: "Other"}}
	if got := NewPlan(st).ReinstallEntries(); got != 2 {
		t.Errorf("reinstall entries %d", got)
	}
}

// --- the mirror --------------------------------------------------------------------

func TestParseRepoConf(t *testing.T) {
	conf := `OPNsense: {
  url: "https://pkg.opnsense.org/${ABI}/26.7/MINT/26.7.3/latest",
  signature_type: "fingerprints",
  fingerprints: "/usr/local/etc/pkg/fingerprints/OPNsense/trusted",
  mirror_type: "srv",
  enabled: yes,
  priority: 11
}
`
	m, err := ParseRepoConf(conf, "FreeBSD:15:amd64")
	if err != nil {
		t.Fatal(err)
	}
	want := RepoBase{Base: "https://pkg.opnsense.org", ABI: "FreeBSD:15:amd64", Series: "26.7", Path: "26.7/MINT/26.7.3/latest"}
	if m != want {
		t.Fatalf("got %+v, want %+v", m, want)
	}
	if got := m.FolderURL("26.7.5", false); got != "https://pkg.opnsense.org/FreeBSD:15:amd64/26.7/MINT/26.7.5/latest/meta.conf" {
		t.Errorf("folder url %q", got)
	}
	if got := m.FolderURL("26.7.5", true); got != "https://pkg.opnsense.org/FreeBSD:15:amd64/26.7/MINT/26.7.5/aux/meta.conf" {
		t.Errorf("aux url %q", got)
	}
	path, err := RepoPath(conf)
	if err != nil || path != "26.7/MINT/26.7.3/latest" {
		t.Errorf("RepoPath = %q, %v", path, err)
	}
}

func TestParseRepoConfVariants(t *testing.T) {
	good := map[string]RepoBase{
		`  url: "pkg+https://pkg.opnsense.org/${ABI}/26.1/latest",`:               {Base: "https://pkg.opnsense.org", Series: "26.1", Path: "26.1/latest"},
		`url: "https://mirror.ams1.nl.leaseweb.net/opnsense/${ABI}/26.7/latest",`: {Base: "https://mirror.ams1.nl.leaseweb.net/opnsense", Series: "26.7", Path: "26.7/latest"},
		`url: "http://10.0.0.5:8080/${ABI}/26.7/MINT/26.7/latest",`:               {Base: "http://10.0.0.5:8080", Series: "26.7", Path: "26.7/MINT/26.7/latest"},
		`url: "https://pkg.opnsense.org/${ABI}/26.7/latest/",`:                    {Base: "https://pkg.opnsense.org", Series: "26.7", Path: "26.7/latest"},
	}
	for conf, want := range good {
		got, err := ParseRepoConf(conf, "FreeBSD:15:amd64")
		want.ABI = "FreeBSD:15:amd64"
		if err != nil || got != want {
			t.Errorf("%q: got %+v, %v; want %+v", conf, got, err, want)
		}
	}
	for name, conf := range map[string]string{
		"no url line":          "OPNsense: {}",
		"no ABI placeholder":   `url: "https://pkg.opnsense.org/FreeBSD:15:amd64/26.7/latest",`,
		"a file URL":           `url: "file:///tmp/repo/${ABI}/26.7/latest",`,
		"userinfo":             `url: "https://user:pass@pkg.opnsense.org/${ABI}/26.7/latest",`,
		"a query":              `url: "https://pkg.opnsense.org?x=1/${ABI}/26.7/latest",`,
		"shell characters":     `url: "https://pkg.opnsense.org/$(id)/${ABI}/26.7/latest",`,
		"no series":            `url: "https://pkg.opnsense.org/${ABI}/latest",`,
		"a series with a typo": `url: "https://pkg.opnsense.org/${ABI}/26.07/latest",`,
		"an empty host":        `url: "https:///${ABI}/26.7/latest",`,
	} {
		if _, err := ParseRepoConf(conf, "FreeBSD:15:amd64"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for _, abi := range []string{"", "FreeBSD:15", "FreeBSD:15:amd64; rm -rf /", "freebsd:15:amd64"} {
		if _, err := ParseRepoConf(`url: "https://pkg.opnsense.org/${ABI}/26.7/latest",`, abi); err == nil {
			t.Errorf("ABI %q was accepted", abi)
		}
	}
}

func TestRedactURLHidesASubscriptionKey(t *testing.T) {
	got := redactURL("https://mirror.example/opnsense/11111111-2222-3333-4444-555555555555/FreeBSD:15:amd64/26.7/latest/meta.conf")
	if strings.Contains(got, "11111111") || !strings.Contains(got, "<subscription>") {
		t.Errorf("redacted: %s", got)
	}
}

func TestFetchSaysNotFound(t *testing.T) {
	yes := []string{"fetch: Not Found", "fetch: https://pkg.opnsense.org/x/meta.conf: Not Found\n",
		// The URL is not the message: a mirror whose host or path holds a word the
		// resolver's messages hold still answers 404 the same way.
		"fetch: https://host.example.net/FreeBSD:15:amd64/26.7/MINT/26.7.3/latest/meta.conf: Not Found",
		"fetch: https://mirror.example:8443/hostname/x/meta.conf: Not Found",
		"fetch: https://name.example/address/x/meta.conf: not found",
		"warning\nfetch: https://x/hostile/meta.conf: Not Found\n"}
	no := []string{"", "fetch: Unknown host", "fetch: https://x: No address record", "fetch: Host not found", "fetch: Forbidden",
		"fetch: Service Unavailable", "fetch: Operation timed out", "name not found",
		"fetch: https://not-found.example/x/meta.conf: Host not found", "fetch: https://x/not found/meta.conf: Forbidden"}
	for _, s := range yes {
		if !fetchSaysNotFound(s) {
			t.Errorf("%q not read as a 404", s)
		}
	}
	for _, s := range no {
		if fetchSaysNotFound(s) {
			t.Errorf("%q read as a 404", s)
		}
	}
}

func TestSystemDeviceProbeClassifiesFetchesAnswer(t *testing.T) {
	defer func(prev func(context.Context, string) (int, string, error)) { fetchFunc = prev }(fetchFunc)
	d := &SystemDevice{}
	for _, tc := range []struct {
		code   int
		output string
		err    error
		want   ProbeResult
	}{
		{0, "179\n", nil, ProbeFound},
		{1, "fetch: Not Found", nil, ProbeMissing},
		{1, "fetch: Forbidden", nil, ProbeUnreachable},
		{1, "fetch: Unknown host", nil, ProbeUnreachable},
		{0, "", errors.New("exec: no such file"), ProbeUnreachable},
	} {
		fetchFunc = func(context.Context, string) (int, string, error) { return tc.code, tc.output, tc.err }
		if got := d.Probe(context.Background(), "https://x/meta.conf"); got != tc.want {
			t.Errorf("code %d %q: %v, want %v", tc.code, tc.output, got, tc.want)
		}
	}
}

func TestSystemDeviceReadsTheMirrorFromTheRepositoryFile(t *testing.T) {
	defer func(path string, abi func(context.Context) (string, error)) { repoConfPath, pkgABIFunc = path, abi }(repoConfPath, pkgABIFunc)
	repoConfPath = filepath.Join(t.TempDir(), "OPNsense.conf")
	pkgABIFunc = func(context.Context) (string, error) { return "FreeBSD:15:amd64", nil }
	d := &SystemDevice{}

	if _, err := d.RepoBase(context.Background()); err == nil {
		t.Error("a missing file was read")
	}
	if err := os.WriteFile(repoConfPath, []byte(`OPNsense: { url: "https://pkg.opnsense.org/${ABI}/26.7/latest", }`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A conf with the url on its own line, the way OPNsense writes it.
	if err := os.WriteFile(repoConfPath, []byte("OPNsense: {\n  url: \"https://pkg.opnsense.org/${ABI}/26.7/latest\",\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := d.RepoBase(context.Background())
	if err != nil || m.Series != "26.7" || m.ABI != "FreeBSD:15:amd64" {
		t.Fatalf("got %+v, %v", m, err)
	}
	if path, err := d.RepoPath(context.Background()); err != nil || path != "26.7/latest" {
		t.Errorf("RepoPath = %q, %v", path, err)
	}
	pkgABIFunc = func(context.Context) (string, error) { return "", errors.New("pkg: not found") }
	if _, err := d.RepoBase(context.Background()); err == nil {
		t.Error("an unreadable ABI was accepted")
	}
}

func TestSystemDeviceApplyPackagesOnlyRunsOpnsenseUpdateOnTheCorePackage(t *testing.T) {
	defer func(prev func(context.Context) (ExecResult, error)) { packagesOnlyFunc = prev }(packagesOnlyFunc)
	packagesOnlyFunc = func(context.Context) (ExecResult, error) { return ExecResult{ExitCode: 2, Tail: "x"}, nil }
	res, err := (&SystemDevice{}).ApplyPackagesOnly(context.Background())
	if err != nil || res.ExitCode != 2 {
		t.Errorf("got %+v, %v", res, err)
	}
	if got := tailLines("a\nb\nc\nd", 2); got != "c\nd" {
		t.Errorf("tail %q", got)
	}
}

// --- the record --------------------------------------------------------------------

func TestStateStore(t *testing.T) {
	dir := t.TempDir()
	store := NewStateStore(filepath.Join(dir, "firmware-track.json"))

	if st, err := store.Load(); st != nil || err != nil {
		t.Fatalf("a missing file: %v, %v", st, err)
	}
	want := &State{
		Pinned: true, Track: TrackFast, OriginalFlavour: "", PinnedFlavour: "26.7/MINT/26.7.3/latest", PinnedVersion: "26.7.3_11",
		EnrolledAt: 1791429967, LastContact: 1791429999, FolderMisses: 1, DriftPending: true,
		Pending: &Pending{Op: ActionAdvance, TaskID: "101", FromFlavour: "26.7/MINT/26.7.3/latest", ToFlavour: "26.7/MINT/26.7.5/latest", Triggered: true, StartedAt: 1791430000},
	}
	if err := store.Save(want); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(store.Path())
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, %v", info.Mode(), err)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.V != 1 || !got.Pinned || got.PinnedFlavour != want.PinnedFlavour || got.Pending == nil || got.Pending.ToFlavour != want.Pending.ToFlavour || !got.Pending.Triggered {
		t.Fatalf("got %+v", got)
	}

	// A record that says nothing is not kept.
	if err := store.Save(&State{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(store.Path()); !os.IsNotExist(err) {
		t.Errorf("an empty record left a file: %v", err)
	}

	// Update starts from an empty record and keeps what it is given.
	if _, err := store.Update(func(s *State) { s.Released = &Released{Reason: "dead_man", At: 1} }); err != nil {
		t.Fatal(err)
	}
	if st, _ := store.Load(); st == nil || st.Released == nil || st.Pinned {
		t.Errorf("got %+v", st)
	}
	if err := store.Remove(); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove(); err != nil {
		t.Errorf("removing a file that is gone: %v", err)
	}
}

func TestStateStoreNeverTakesAnUnreadableFileForNoPin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "firmware-track.json")
	store := NewStateStore(path)
	for name, content := range map[string]string{
		"garbage":          "{not json",
		"a newer format":   `{"v":99,"pinned":true}`,
		"no format number": `{"pinned":true}`,
	} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if st, err := store.Load(); !errors.Is(err, ErrState) || st != nil {
			t.Errorf("%s: %v, %v", name, st, err)
		}
	}
}

func TestStateStoreDoesNotCreateItsDirectory(t *testing.T) {
	store := NewStateStore(filepath.Join(t.TempDir(), "gone", "firmware-track.json"))
	if err := store.Save(&State{Pinned: true}); err == nil {
		t.Error("the directory was created: a decommissioned agent would write its state back")
	}
}

func TestStateOwns(t *testing.T) {
	st := &State{Pinned: true, PinnedFlavour: "A", Pending: &Pending{ToFlavour: "B"}}
	for f, want := range map[string]bool{"A": true, "B": true, "C": false, "": false} {
		if got := st.Owns(f); got != want {
			t.Errorf("Owns(%q) = %v", f, got)
		}
	}
	if (&State{PinnedFlavour: "A"}).Owns("A") {
		t.Error("a record that holds no pin owns nothing")
	}
	var nilState *State
	if nilState.Owns("A") {
		t.Error("nil owns something")
	}
}

// The state file is read by the plugin's PHP helper, which restores the setting
// when the agent cannot. The golden file is the shape both sides test against.
func TestStateFileMatchesTheGoldenTheHelperReads(t *testing.T) {
	golden, err := os.ReadFile(filepath.Join("testdata", "state-pinned.json"))
	if err != nil {
		t.Fatal(err)
	}
	var st State
	if err := json.Unmarshal(golden, &st); err != nil {
		t.Fatal(err)
	}
	if !st.Pinned || st.PinnedFlavour != "26.7/MINT/26.7.3/latest" || st.OriginalFlavour != "" || st.Pending == nil || st.Pending.ToFlavour != "26.7/MINT/26.7.5/latest" {
		t.Fatalf("the golden state does not carry what the helper reads: %+v", st)
	}
	again, err := json.MarshalIndent(&st, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	var a, b map[string]interface{}
	_ = json.Unmarshal(golden, &a)
	_ = json.Unmarshal(again, &b)
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) {
		t.Errorf("the state this agent writes differs from the golden:\n%s\n%s", jb, ja)
	}
}

func TestEngineDefaultsToTheRightLifetimes(t *testing.T) {
	if AdvanceTTL != 20*time.Minute || EnrollTTL != 5*time.Minute {
		t.Errorf("advance %v, enroll %v", AdvanceTTL, EnrollTTL)
	}
}

// The series upgrade is judged from the offer and the plan, never from the status.
func TestPlanForMajor(t *testing.T) {
	offer := func(tweak func(*opnapi.FirmwareUpgradeStatus)) *opnapi.FirmwareUpgradeStatus {
		s := statusOf()
		s.Status = "upgrade"
		s.UpgradeMajorVersion = "26.7"
		s.UpgradeSets = offerSets("26.7")
		if tweak != nil {
			tweak(s)
		}
		return s
	}
	cases := []struct {
		name   string
		st     *opnapi.FirmwareUpgradeStatus
		kind   majorKind
		reason string
	}{
		{"the offer as measured", offer(nil), majorOffered, ""},
		{"no offer", statusOf(), majorNoOffer, ""},
		{"an offer under the status update: a same-version reinstall of the agent's record", offer(func(s *opnapi.FirmwareUpgradeStatus) {
			s.Status = "update"
			s.ReinstallPackages = []opnapi.FirmwarePackageEntry{{Name: "os-netdefense-dev", Repository: "NetDefense", NewVersion: "1.24_0"}}
		}), majorOffered, ""},
		{"an offer under the status update: the core's Vital flag reinstall", offer(func(s *opnapi.FirmwareUpgradeStatus) {
			s.Status = "update"
			s.ReinstallPackages = []opnapi.FirmwarePackageEntry{
				{Name: "opnsense", Repository: "OPNsense", NewVersion: "26.1.11_10"},
				{Name: "os-netdefense-dev", Repository: "NetDefense", NewVersion: "1.24_0"},
			}
		}), majorOffered, ""},
		{"an upgrade of the agent's own package from its own repository is not the pin's business", offer(func(s *opnapi.FirmwareUpgradeStatus) {
			s.UpgradePackages = []opnapi.FirmwarePackageEntry{entry("os-netdefense-dev", "NetDefense", "1.24_0", "1.25_0")}
		}), majorOffered, ""},
		{"another series on offer", offer(func(s *opnapi.FirmwareUpgradeStatus) {
			s.UpgradeMajorVersion = "27.1"
			s.UpgradeSets = offerSets("27.1")
		}), majorHeld, ReasonHeldUnexpectedPlan},
		{"an offer with no sets", offer(func(s *opnapi.FirmwareUpgradeStatus) { s.UpgradeSets = nil }), majorHeld, ReasonHeldUnexpectedPlan},
		{"two sets", offer(func(s *opnapi.FirmwareUpgradeStatus) { s.UpgradeSets = s.UpgradeSets[:2] }), majorHeld, ReasonHeldUnexpectedPlan},
		{"four sets", offer(func(s *opnapi.FirmwareUpgradeStatus) {
			s.UpgradeSets = append(s.UpgradeSets, opnapi.FirmwareUpgradeSet{Name: "extra", Size: 1, NewVersion: "26.7"})
		}), majorHeld, ReasonHeldUnexpectedPlan},
		{"a set listed twice", offer(func(s *opnapi.FirmwareUpgradeStatus) { s.UpgradeSets[2] = s.UpgradeSets[1] }), majorHeld, ReasonHeldUnexpectedPlan},
		{"a set of another name", offer(func(s *opnapi.FirmwareUpgradeStatus) { s.UpgradeSets[1].Name = "firmware" }), majorHeld, ReasonHeldUnexpectedPlan},
		{"a set at another release", offer(func(s *opnapi.FirmwareUpgradeStatus) { s.UpgradeSets[1].NewVersion = "26.7.1" }), majorHeld, ReasonHeldUnexpectedPlan},
		{"a set with no size", offer(func(s *opnapi.FirmwareUpgradeStatus) { s.UpgradeSets[0].Size = -1 }), majorHeld, ReasonHeldUnexpectedPlan},
		{"a set of size zero", offer(func(s *opnapi.FirmwareUpgradeStatus) { s.UpgradeSets[0].Size = 0 }), majorHeld, ReasonHeldUnexpectedPlan},
		{"a check against another ABI", offer(func(s *opnapi.FirmwareUpgradeStatus) { s.CheckABI, s.InstalledABI = "26.7", "26.1" }), majorHeld, ReasonHeldUnexpectedPlan},
		{"a downgrade", offer(func(s *opnapi.FirmwareUpgradeStatus) {
			s.DowngradePackages = []opnapi.FirmwarePackageEntry{{Name: "curl", Repository: "OPNsense"}}
		}), majorHeld, ReasonHeldDowngradeRisk},
		{"a minor reboot pending: base and kernel in the plan", offer(func(s *opnapi.FirmwareUpgradeStatus) {
			s.UpgradePackages = []opnapi.FirmwarePackageEntry{
				entry("base", "OPNsense", "26.1.10", "26.1.11"), entry("kernel", "OPNsense", "26.1.10", "26.1.11")}
		}), majorHeld, ReasonHeldRebootPending},
		{"a real upgrade pending: a hotfix race", offer(func(s *opnapi.FirmwareUpgradeStatus) {
			s.UpgradePackages = []opnapi.FirmwarePackageEntry{entry("opnsense", "OPNsense", "26.1.11_9", "26.1.11_10")}
		}), majorHeld, ReasonHeldUnexpectedPlan},
		{"an ordinary package upgrade pending", offer(func(s *opnapi.FirmwareUpgradeStatus) {
			s.UpgradePackages = []opnapi.FirmwarePackageEntry{entry("curl", "OPNsense", "8.21.0", "8.22.0")}
		}), majorHeld, ReasonHeldUnexpectedPlan},
		{"a new package", offer(func(s *opnapi.FirmwareUpgradeStatus) {
			s.NewPackages = []opnapi.FirmwarePackageEntry{{Name: "x", Repository: "OPNsense", NewVersion: "1"}}
		}), majorHeld, ReasonHeldUnexpectedPlan},
		{"a package removed", offer(func(s *opnapi.FirmwareUpgradeStatus) {
			s.RemovePackages = []opnapi.FirmwarePackageEntry{{Name: "x", Repository: "OPNsense", NewVersion: "1"}}
		}), majorHeld, ReasonHeldUnexpectedPlan},
	}
	for _, tc := range cases {
		kind, h := NewPlan(tc.st).forMajor("26.7")
		if kind != tc.kind {
			why := ""
			if h != nil {
				why = h.Reason + ": " + h.Why
			}
			t.Errorf("%s: kind %v (%s), want %v", tc.name, kind, why, tc.kind)
			continue
		}
		if kind == majorHeld && h.Reason != tc.reason {
			t.Errorf("%s: held for %s (%s), want %s", tc.name, h.Reason, h.Why, tc.reason)
		}
		if kind != majorHeld && h != nil {
			t.Errorf("%s: a verdict that holds nothing carries a hold: %+v", tc.name, h)
		}
	}
}

// The offer is the major and its sets; the status is no test of it (the status
// reads "update" as soon as one package entry is listed, a reinstall included).
func TestPlanReadsTheOfferWhateverTheStatusSays(t *testing.T) {
	for _, status := range []string{"none", "update", "upgrade", "error", ""} {
		s := statusOf()
		s.Status = status
		s.UpgradeMajorVersion = "26.7"
		s.UpgradeSets = offerSets("26.7")
		if kind, h := NewPlan(s).forMajor("26.7"); kind != majorOffered {
			t.Errorf("status %q: kind %v (%+v)", status, kind, h)
		}
		s.UpgradeMajorVersion, s.UpgradeSets = "", nil
		if kind, _ := NewPlan(s).forMajor("26.7"); kind != majorNoOffer {
			t.Errorf("status %q, no offer: kind %v", status, kind)
		}
	}
}
