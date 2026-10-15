package track

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/firmware"
	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// simCatalog is what one release directory of the mirror holds, as far as the
// pin cares: the core package, the opnsense-update package (whose version, with
// its hotfix suffix dropped, is the release of base and kernel) and the other
// packages.
type simCatalog struct {
	core   string
	update string
	pkgs   map[string]string
	// abi is the FreeBSD ABI tree the directory exists under; "" is any. A series
	// upgrade moves the box to another ABI, and the pin it leaves behind names a
	// directory of the old tree, which the new one does not have.
	abi string
}

// simDevice is a small OPNsense: the firmware settings, the installed release,
// a mirror of release directories, and the firmware backend (checks, updates,
// the progress log). It models what the lab proved and nothing more:
// the flavour replaces everything after the ABI; a check at a directory plans
// that directory's catalog against what is installed and never downgrades; a
// directory the mirror lacks fails the check closed; a set flushes the cached
// check result.
type simDevice struct {
	mu sync.Mutex
	t  *testing.T

	// settings
	flavour      string
	typ          string
	mirror       string
	subscription bool
	aux          bool

	// the installed release
	series    string
	core      string // the version file (26.7.3_11)
	updatePkg string // the opnsense-update package version
	sets      string // base and kernel
	pkgs      map[string]string
	boot      int64

	// abi is pkg's ABI on the box (pkg config ABI); a series upgrade changes it.
	abi string

	// hop is the series upgrade's side of the box: the offer, the stages and what
	// they leave on disk, the HA signals, the free space, the boot environments (see
	// sim_major_test.go).
	hop simHop

	// the mirror
	folders     map[string]simCatalog // release directories by name
	latest      simCatalog            // what the default flavour sees
	auxFolders  map[string]bool       // directories whose aux part is there; nil means all
	unreachable bool                  // the mirror cannot be asked
	probeErr    map[string]bool       // dirs that answer a failure rather than 404

	// the backend
	busyReads  int  // Running reads busy this many times before ready
	alwaysBusy bool // the backend never frees up
	dropChecks int  // the next N check requests are dropped without a word

	// busyAfterNextCheck: the backend turns busy for good (somebody else's job takes
	// the lock) as the next check's result is published.
	busyAfterNextCheck bool

	checkInFlight bool
	checked       *opnapi.FirmwareUpgradeStatus // the published result, nil after a flush
	checkSeq      int
	checkFailsAs  string // "repository" makes every check fail closed

	// things a test makes the plan contain
	extraDowngrade bool
	majorOffered   string
	reinstallCore  bool
	extraNew       bool
	foreignUpgrade bool   // an upgrade from the NetDefense repo, which the pin does not hold
	kernelSkew     string // a kernel version that does not match base

	// updates
	updating bool
	// progressGap: the next N progress reads answer what OPNsense answers while it
	// restarts its own services or right after a boot (status "error", empty log),
	// and progressDown the next N after that answer nothing at all.
	progressGap   int
	progressDown  int
	updateReads   int    // progress reads before the update ends
	updateOutcome string // "done" or "reboot"
	updateDropped bool   // the request is accepted and nothing starts
	updateAnswer  string
	updateFails   bool // the update ends with OPNsense's failure text
	// updateErr makes the request itself fail (a timeout, a reset); with
	// updateErrAfterStart OPNsense heard it and started the update, and only the
	// answer was lost.
	updateErr           error
	updateErrAfterStart bool
	updateNeverEnds     bool // the run goes on past any deadline
	// updateEarlyDone: the log carries ***DONE*** for a read before the run goes on
	// to its end (a transient marker): OPNsense reads the status "done" as
	// soon as the marker occurs anywhere in the log.
	updateEarlyDone bool
	powerCut        bool               // the box restarts after the core package, before base and kernel
	cancelOnUpdate  context.CancelFunc // the connection drops as the request is made
	progressText    string
	pendingCore     string
	pendingUpdate   string
	pendingSets     string
	pendingPkgs     map[string]string
	pkgToolsBusy    bool

	// onSet runs after every successful set, outside the lock.
	onSet func()
	// onRun runs when an update has been applied, inside the lock: something
	// else happens to the box while the run ends.
	onRun func(*simDevice)

	// repoDiverged: the generated repository file says the default whatever the
	// setting is (a command rewrote the file alone).
	repoDiverged bool
	repoErr      error

	// foreignOnUpdate makes the next N update requests find a foreign firmware job
	// (the GUI's check, OPNsense's cron job, a shell) holding OPNsense's lock: the
	// launcher drops the request and the API still answers ok (or the request
	// errors, with updateErr). The job holds the lock for foreignLife reads of the
	// backend (running or progress) and ends with its own ***DONE***. foreignLeft
	// is what is left of the one in flight.
	foreignOnUpdate int
	foreignLife     int
	foreignLeft     int

	// errors injected
	settingsErr      error
	setErr           error
	setFailures      int  // the next N writes of the flavour fail, then they work
	panicSettings    bool // reading the settings panics: a bug in the engine's reach
	setAppliedButErr bool
	installedErr     error
	// installedFailures: the next N reads of the installed release fail, then they
	// work; installedReads counts every read the engine makes.
	installedFailures int
	installedReads    int
	checkErr          error
	// settingsFailures: the next N reads of the settings fail, then they work (an
	// API that is not up yet). settingsReads counts every read.
	settingsFailures int
	settingsReads    int
	// ran says an update has been applied or opnsense-update has run. Once it
	// has, the next settingsFailuresAfterRun reads of the settings fail, and the
	// installed release cannot be read by the engine while installedErrAfterRun is
	// set (the reads Evaluate makes are not affected): the API settling after a
	// reboot.
	ran                      bool
	settingsFailuresAfterRun int
	installedErrAfterRun     bool
	// installedFailuresAfterRun: once an update has run, the next N reads of the
	// installed release fail, then they work (the API settling after the reboot).
	installedFailuresAfterRun int
	// busyAfterRun and runningErrAfterRun: once an update has run, the backend
	// reads busy (somebody else's job took the lock) or cannot be read.
	busyAfterRun       bool
	runningErrAfterRun bool
	// execLockRefusal makes `opnsense-update -pt` exit 1 with pkg's lock message
	// and install nothing; execFailsAfterInstalling makes it exit 1 with the same
	// message after it installed the release.
	execLockRefusal          bool
	execFailsAfterInstalling bool
	// execKilled: the command is killed after pkg installed what it was to (the agent
	// restarting under its own upgrade).
	execKilled bool

	// what happened, in order
	calls []string
	// flavours the device has had
	history []string
}

func newSim(t *testing.T) *simDevice {
	d := &simDevice{
		t:         t,
		series:    "26.7",
		core:      "26.7.3_11",
		updatePkg: "26.7.3",
		sets:      "26.7.3",
		pkgs:      map[string]string{"curl": "8.21.0", "pkg": "2.8.4_1"},
		boot:      1_780_000_000,
		abi:       "FreeBSD:15:amd64",
		folders: map[string]simCatalog{
			"26.7":   {core: "26.7", update: "26.7", pkgs: map[string]string{"curl": "8.20.0", "pkg": "2.3.1_1"}},
			"26.7.3": {core: "26.7.3_11", update: "26.7.3", pkgs: map[string]string{"curl": "8.21.0", "pkg": "2.3.1_1"}},
			"26.7.4": {core: "26.7.4_1", update: "26.7.4", pkgs: map[string]string{"curl": "8.21.0", "pkg": "2.3.1_1"}},
			"26.7.5": {core: "26.7.5", update: "26.7.4_1", pkgs: map[string]string{"curl": "8.22.0", "pkg": "2.8.4_1"}},
		},
		updateOutcome: "reboot",
		updateAnswer:  "ok",
		updateReads:   2,
	}
	d.latest = d.folders["26.7.5"]
	d.pkgs["opnsense"] = d.core
	d.pkgs["opnsense-update"] = d.updatePkg
	d.hop = newSimHop()
	return d
}

func (d *simDevice) record(format string, args ...interface{}) {
	d.calls = append(d.calls, fmt.Sprintf(format, args...))
}

// Calls returns the log, for assertions on what the engine did and in which order.
func (d *simDevice) Calls() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.calls...)
}

func (d *simDevice) count(prefix string) int {
	n := 0
	for _, c := range d.Calls() {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func (d *simDevice) do(fn func(*simDevice)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	fn(d)
}

func (d *simDevice) Flavour() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.flavour
}

func (d *simDevice) Core() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.core
}

// --- Device ----------------------------------------------------------------------

func (d *simDevice) Settings(context.Context) (opnapi.FirmwareSettings, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.panicSettings {
		panic("simulated bug")
	}
	d.settingsReads++
	if d.settingsFailures > 0 {
		d.settingsFailures--
		return opnapi.FirmwareSettings{}, errSim
	}
	if d.ran && d.settingsFailuresAfterRun > 0 {
		d.settingsFailuresAfterRun--
		return opnapi.FirmwareSettings{}, errSim
	}
	if d.settingsErr != nil {
		return opnapi.FirmwareSettings{}, d.settingsErr
	}
	return opnapi.FirmwareSettings{Flavour: d.flavour, Type: d.typ, Mirror: d.mirror, SubscriptionSet: d.subscription, Aux: d.aux}, nil
}

func (d *simDevice) SetFlavour(_ context.Context, flavour string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.record("set %s", flavour)
	if d.setFailures > 0 {
		d.setFailures--
		return errSim
	}
	if d.setErr != nil {
		if d.setAppliedButErr {
			d.flavour = flavour
			d.checked = nil
		}
		return d.setErr
	}
	d.flavour = flavour
	d.repoDiverged = false // a set replays the setting into the files
	d.history = append(d.history, flavour)
	d.checked = nil // firmware flush
	if d.onSet != nil {
		go d.onSet()
	}
	return nil
}

func (d *simDevice) Installed(context.Context) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.installedReads++
	if d.installedFailures > 0 {
		d.installedFailures--
		return "", errSim
	}
	if d.installedErr != nil {
		return "", d.installedErr
	}
	if d.ran && d.installedErrAfterRun {
		return "", errSim
	}
	if d.ran && d.installedFailuresAfterRun > 0 {
		d.installedFailuresAfterRun--
		return "", errSim
	}
	return d.core, nil
}

// RepoBase is what the generated repository file says. Its path after the ABI is
// the flavour when one is set (a pin replaces the series along with the rest), so
// after a series change made outside NetDefense the file keeps naming the old
// series until the setting is written again.
func (d *simDevice) RepoBase(context.Context) (RepoBase, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	series := d.series
	if d.flavour != "" && !d.repoDiverged {
		if s, _, ok := ParseFlavour(d.flavour); ok {
			series = s
		}
	}
	return RepoBase{Base: "https://pkg.example.test", ABI: d.abi, Series: series}, nil
}

// RepoPath is what the generated repository file holds after the ABI.
func (d *simDevice) RepoPath(context.Context) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.repoErr != nil {
		return "", d.repoErr
	}
	if d.repoDiverged || d.flavour == "" {
		return d.series + "/latest", nil
	}
	return d.flavour, nil
}

var simFolderRE = regexp.MustCompile(`^https://pkg\.example\.test/(FreeBSD:[0-9]+:amd64)/[^/]+/MINT/([^/]+)/(latest|aux)/meta\.conf$`)

// simTreeRE is the meta.conf of a series' own tree: the target of a series upgrade.
var simTreeRE = regexp.MustCompile(`^https://pkg\.example\.test/(FreeBSD:[0-9]+:amd64)/([^/]+)/latest/meta\.conf$`)

func (d *simDevice) Probe(_ context.Context, url string) ProbeResult {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.record("probe %s", strings.TrimPrefix(url, "https://pkg.example.test/"))
	if d.unreachable {
		return ProbeUnreachable
	}
	if m := simTreeRE.FindStringSubmatch(url); m != nil {
		return d.hop.treeProbe(m[1], m[2])
	}
	m := simFolderRE.FindStringSubmatch(url)
	if m == nil {
		return ProbeMissing
	}
	if d.probeErr[m[2]] {
		return ProbeUnreachable
	}
	cat, ok := d.folders[m[2]]
	if !ok || (cat.abi != "" && cat.abi != m[1]) {
		return ProbeMissing
	}
	if m[3] == "aux" && d.auxFolders != nil && !d.auxFolders[m[2]] {
		return ProbeMissing
	}
	return ProbeFound
}

func (d *simDevice) Running(context.Context) (firmware.RunState, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ran && d.runningErrAfterRun {
		return firmware.RunUnknown, errSim
	}
	if d.alwaysBusy || d.updating || (d.ran && d.busyAfterRun) {
		return firmware.RunBusy, nil
	}
	if d.foreignHoldsTheLock() {
		return firmware.RunBusy, nil
	}
	if d.busyReads > 0 {
		d.busyReads--
		return firmware.RunBusy, nil
	}
	if d.checkInFlight {
		d.checkInFlight = false
		d.publishCheck()
	}
	return firmware.RunReady, nil
}

// folderOf is the catalog the repository files point at.
func (d *simDevice) folderOf() (simCatalog, bool) {
	if d.flavour == "" || d.repoDiverged {
		return d.latest, true
	}
	_, dir, ok := ParseFlavour(d.flavour)
	if !ok {
		return simCatalog{}, false
	}
	c, ok := d.folders[dir]
	if ok && c.abi != "" && c.abi != d.abi {
		return simCatalog{}, false // the tree of another ABI: a 404 on this one
	}
	return c, ok
}

func (d *simDevice) TriggerCheck(context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.record("check")
	if d.checkErr != nil {
		return d.checkErr
	}
	if d.dropChecks > 0 {
		d.dropChecks--
		d.record("dropped: check")
		return nil
	}
	d.checkInFlight = true
	d.busyReads = 1
	return nil
}

// publishCheck writes the check result, as OPNsense does when its job ends.
func (d *simDevice) publishCheck() {
	d.checkSeq++
	if d.busyAfterNextCheck {
		d.busyAfterNextCheck, d.alwaysBusy = false, true
	}
	productVersion := d.core
	if d.hop.staleCheck != "" {
		productVersion = d.hop.staleCheck // a result made for another release than the installed one
	}
	st := &opnapi.FirmwareUpgradeStatus{
		ProductVersion: productVersion, InstalledVersion: d.core, ProductSeries: d.series,
		ProductABI: d.series, CheckABI: "", InstalledABI: d.series,
		Connection: "ok", Repository: "ok", Status: "none",
		LastCheck: fmt.Sprintf("Sun Oct  4 03:%02d:%02d UTC 2026", d.checkSeq/60, d.checkSeq%60),
	}
	cat, ok := d.folderOf()
	if !ok || d.checkFailsAs == "repository" {
		st.Repository, st.Status = "error", "error"
		d.checked = st
		return
	}
	entry := func(name, cur, next string) opnapi.FirmwarePackageEntry {
		return opnapi.FirmwarePackageEntry{Name: name, Repository: "OPNsense", CurrentVersion: cur, NewVersionAlt: next}
	}
	if k1, ok1 := ParseKey(cat.core); ok1 {
		if k0, ok0 := ParseKey(d.core); ok0 && k1.Compare(k0) > 0 {
			st.UpgradePackages = append(st.UpgradePackages, entry("opnsense", d.core, cat.core))
		}
	}
	if firmware.CompareVersions(cat.update, d.updatePkg) > 0 {
		st.UpgradePackages = append(st.UpgradePackages, entry("opnsense-update", d.updatePkg, cat.update))
	}
	if release := StripHotfix(cat.update); release != d.sets && firmware.CompareVersions(release, d.sets) > 0 {
		kernel := release
		if d.kernelSkew != "" {
			kernel = d.kernelSkew
		}
		st.UpgradePackages = append(st.UpgradePackages, entry("base", d.sets, release), entry("kernel", d.sets, kernel))
		st.NeedsReboot = true
	}
	for name, ver := range cat.pkgs {
		if cur := d.pkgs[name]; cur != "" && firmware.CompareVersions(ver, cur) > 0 {
			st.UpgradePackages = append(st.UpgradePackages, entry(name, cur, ver))
		}
	}
	if d.foreignUpgrade {
		st.UpgradePackages = append(st.UpgradePackages, opnapi.FirmwarePackageEntry{
			Name: "os-netdefense-dev", Repository: "NetDefense", CurrentVersion: "1.22_1", NewVersionAlt: "1.23_0"})
	}
	if d.extraDowngrade {
		st.DowngradePackages = []opnapi.FirmwarePackageEntry{{Name: "curl", Repository: "OPNsense", CurrentVersion: "8.22.0", NewVersionAlt: "8.21.0"}}
	}
	if d.extraNew {
		st.NewPackages = []opnapi.FirmwarePackageEntry{{Name: "py313-typing-extensions", Repository: "OPNsense", NewVersion: "4.16.0"}}
	}
	if d.reinstallCore {
		st.ReinstallPackages = []opnapi.FirmwarePackageEntry{{Name: "opnsense", Repository: "OPNsense", NewVersion: d.core}}
	}
	if d.hop.reinstallAgent {
		st.ReinstallPackages = append(st.ReinstallPackages,
			opnapi.FirmwarePackageEntry{Name: "os-netdefense-dev", Repository: "NetDefense", NewVersion: "1.24_0"})
	}
	st.UpgradeMajorVersion = d.majorOffered
	if d.majorOffered != "" {
		st.UpgradeSets = d.hop.offer(d.majorOffered)
		st.UpgradeMajorMessage = "OPNsense has reached its end of life."
		st.UpgradeNeedsReboot = true
		st.Status = "upgrade"
	}
	// A package entry of any kind keeps the status at "update", a same-version
	// reinstall included, while the major is still offered.
	if len(st.UpgradePackages) > 0 || len(st.NewPackages) > 0 || len(st.ReinstallPackages) > 0 {
		st.Status = "update"
	}
	d.checked = st
}

func (d *simDevice) Status(context.Context) (*opnapi.FirmwareUpgradeStatus, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.checked == nil {
		return &opnapi.FirmwareUpgradeStatus{Status: "none", InstalledVersion: d.core, InstalledABI: d.series}, nil
	}
	cp := *d.checked
	cp.InstalledVersion = d.core // the product block is live; the rest is the check's
	return &cp, nil
}

func (d *simDevice) TriggerUpdate(ctx context.Context) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.record("update")
	if d.cancelOnUpdate != nil {
		d.cancelOnUpdate()
	}
	if err := ctx.Err(); err != nil {
		return "", err // the request never left
	}
	if d.foreignOnUpdate > 0 && d.updateAnswer == "ok" && !d.updateDropped {
		d.foreignOnUpdate--
		d.foreignLeft = d.foreignLife
		d.progressText = "***GOT REQUEST TO CHECK FOR UPDATES***\nCurrently running OPNsense at now\nFetching changelog information, please wait... "
		if d.updateErr != nil && !d.updateErrAfterStart {
			return "", d.updateErr // the request was dropped, and the call failed as well
		}
		return "ok", nil
	}
	if d.updateErr != nil && !d.updateErrAfterStart {
		return "", d.updateErr
	}
	if d.updateAnswer != "ok" {
		return d.updateAnswer, nil
	}
	if d.updateDropped {
		return "ok", nil
	}
	cat, ok := d.folderOf()
	if !ok {
		return "ok", nil
	}
	d.updating = true
	d.progressText = "***GOT REQUEST TO UPDATE***\nCurrently running OPNsense at now\n"
	d.pendingCore, d.pendingUpdate, d.pendingSets, d.pendingPkgs = cat.core, cat.update, StripHotfix(cat.update), cat.pkgs
	d.updateReads = 2
	if d.updateErr != nil {
		return "", d.updateErr // accepted and started; the answer was lost
	}
	return "ok", nil
}

// foreignHoldsTheLock is read by every look at the backend: the foreign job
// lasts a number of them and writes its end marker as it ends. The caller holds
// the lock.
func (d *simDevice) foreignHoldsTheLock() bool {
	if d.foreignLeft <= 0 {
		return false
	}
	d.foreignLeft--
	if d.foreignLeft > 0 {
		return true
	}
	d.progressText += "done\n***DONE***\n"
	return false
}

func (d *simDevice) applyPending(withSets bool) {
	d.ran = true
	if k1, ok := ParseKey(d.pendingCore); ok {
		if k0, ok := ParseKey(d.core); ok && k1.Compare(k0) > 0 {
			d.core = d.pendingCore
			d.pkgs["opnsense"] = d.core
		}
	}
	if firmware.CompareVersions(d.pendingUpdate, d.updatePkg) > 0 {
		d.updatePkg = d.pendingUpdate
		d.pkgs["opnsense-update"] = d.updatePkg
	}
	for name, ver := range d.pendingPkgs {
		if firmware.CompareVersions(ver, d.pkgs[name]) > 0 {
			d.pkgs[name] = ver
		}
	}
	if withSets && firmware.CompareVersions(d.pendingSets, d.sets) > 0 {
		d.sets = d.pendingSets
	}
	if d.onRun != nil {
		d.onRun(d)
	}
}

func (d *simDevice) Progress(context.Context) (*opnapi.FirmwareProgressStatus, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.foreignLeft > 0 {
		status := "running"
		if !d.foreignHoldsTheLock() {
			status = "done"
		}
		return &opnapi.FirmwareProgressStatus{Status: status, Log: d.progressText}, nil
	}
	if d.updating && d.progressGap > 0 {
		d.progressGap--
		return &opnapi.FirmwareProgressStatus{Status: "error", Log: ""}, nil
	}
	if d.updating && d.hop.run != nil {
		return d.hopProgress(), nil
	}
	if d.updating && d.progressDown > 0 {
		d.progressDown--
		return nil, errSim
	}
	if !d.updating {
		if d.hop.posts > 0 {
			d.record("progress")
		}
		d.hook("progress-idle")
		// What OPNsense's API makes of the log: the end markers decide the status.
		status := "running"
		switch {
		case strings.Contains(d.progressText, "***DONE***"):
			status = "done"
		case strings.Contains(d.progressText, "***REBOOT***"):
			status = "reboot"
		}
		return &opnapi.FirmwareProgressStatus{Status: status, Log: d.progressText}, nil
	}
	if d.updateReads > 0 || d.updateNeverEnds {
		if d.updateReads > 0 {
			d.updateReads--
		}
		if d.updateEarlyDone && d.updateReads == 0 && !strings.Contains(d.progressText, "***DONE***") {
			d.progressText += "Fetching packages\n***DONE***\n"
			return &opnapi.FirmwareProgressStatus{Status: "done", Log: d.progressText}, nil
		}
		return &opnapi.FirmwareProgressStatus{Status: "running", Log: d.progressText}, nil
	}
	// The run ends.
	if d.updateEarlyDone {
		d.progressText = strings.Replace(d.progressText, "Fetching packages\n***DONE***\n", "", 1)
	}
	d.updating = false
	d.checked = nil
	if !d.updateFails {
		d.applyPending(!d.powerCut)
	}
	if d.updateFails {
		d.progressText += "Partial update failure detected\n***DONE***\n"
		return &opnapi.FirmwareProgressStatus{Status: "done", Log: d.progressText}, nil
	}
	if d.updateOutcome == "reboot" {
		d.boot += 300
		d.progressText += "***REBOOT***\n"
		return &opnapi.FirmwareProgressStatus{Status: "reboot", Log: d.progressText}, nil
	}
	d.progressText += "***DONE***\n"
	return &opnapi.FirmwareProgressStatus{Status: "done", Log: d.progressText}, nil
}

func (d *simDevice) ApplyPackagesOnly(context.Context) (ExecResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.record("exec opnsense-update -pt opnsense")
	d.ran = true
	const lockTail = "Updating OPNsense repository catalogue...\npkg: Cannot get an exclusive lock on a database, it is locked by another process"
	if d.execLockRefusal {
		return ExecResult{ExitCode: 1, Tail: lockTail}, nil
	}
	cat, ok := d.folderOf()
	if !ok {
		return ExecResult{ExitCode: 1, Tail: "Unable to update repository OPNsense"}, nil
	}
	if d.execFailsAfterInstalling {
		d.pendingCore, d.pendingUpdate, d.pendingSets, d.pendingPkgs = cat.core, cat.update, StripHotfix(cat.update), cat.pkgs
		d.applyPending(false)
		d.checked = nil
		return ExecResult{ExitCode: 1, Tail: lockTail}, nil
	}
	if d.execKilled {
		// The package that was upgraded is the agent's own, and its post-install hook
		// restarted the agent: the command was killed with it while pkg went on.
		d.pendingCore, d.pendingUpdate, d.pendingSets, d.pendingPkgs = cat.core, cat.update, StripHotfix(cat.update), cat.pkgs
		d.applyPending(false)
		d.checked = nil
		return ExecResult{ExitCode: -1}, errSim
	}
	if d.updateFails {
		return ExecResult{ExitCode: 3, Tail: "pkg: upgrade failed\nsecond line"}, nil
	}
	d.pendingCore, d.pendingUpdate, d.pendingSets, d.pendingPkgs = cat.core, cat.update, StripHotfix(cat.update), cat.pkgs
	d.applyPending(false)
	d.checked = nil
	return ExecResult{Tail: "done"}, nil
}

func (d *simDevice) Probes() firmware.Probes {
	return firmware.Probes{
		Running: func(ctx context.Context) (firmware.RunState, error) { return d.Running(ctx) },
		Locked:  func(context.Context) (bool, error) { return false, nil },
		Release: func(context.Context) (string, error) {
			d.mu.Lock()
			defer d.mu.Unlock()
			if d.installedErr != nil {
				return "", d.installedErr
			}
			return d.core, nil
		},
		BootTime: func() (int64, error) {
			d.mu.Lock()
			defer d.mu.Unlock()
			return d.boot, nil
		},
		Installed: func(context.Context) (map[string]string, error) {
			d.mu.Lock()
			defer d.mu.Unlock()
			out := make(map[string]string, len(d.pkgs))
			for k, v := range d.pkgs {
				out[k] = v
			}
			return out, nil
		},
		Updating: func(context.Context) (bool, error) {
			d.mu.Lock()
			defer d.mu.Unlock()
			return d.pkgToolsBusy, nil
		},
		Sets: func(context.Context) (string, string, error) {
			d.mu.Lock()
			defer d.mu.Unlock()
			return d.sets, d.sets, nil
		},
		Evidence: func(context.Context, time.Time) (string, error) {
			d.mu.Lock()
			defer d.mu.Unlock()
			if d.updateFails && strings.Contains(d.progressText, "Partial update failure detected") {
				return firmware.PartialFailureMarker, nil
			}
			if strings.Contains(d.progressText, firmware.UpgradeAbortedMarker) {
				return firmware.UpgradeAbortedMarker, nil
			}
			return "", nil
		},
	}
}

func (d *simDevice) BootTime() (int64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.boot, nil
}

var errSim = errors.New("simulated failure")
