package track

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// The series upgrade's side of the simulated box. It models what the proof of the
// 26.1 to 26.7 hop measured on a real 26.1.11_10 device and nothing more: the offer
// (three sets, sizes as strings on the wire), the target ABI's tree, a request that
// stage 0 turns into markers and a reboot (the new ABI, the new core, base, kernel
// and pkgs at the series, the pin left naming the old series on the new ABI: a 404),
// the aborts that leave an unchanged box (a failed stage 0, a full disk), the HA
// signals, the free space and the boot environments.

// simHop is the part of simDevice a series upgrade reads and changes.
type simHop struct {
	// sets overrides the offer's three sets (nil: the measured ones).
	sets []opnapi.FirmwareUpgradeSet
	// reinstallAgent lists the agent's own package as a same-version reinstall in
	// every check: its record says the old ABI after the hop.
	reinstallAgent bool

	// The target series' tree, and the ABI the box is on after the landing (a test
	// of a hop that keeps its ABI sets the source's).
	treeMissing, treeUnreachable bool
	landABI                      string

	// staleCheck makes every check describe this release instead of the installed one.
	staleCheck string

	// What the box answers.
	ha            bool
	haErr         error
	audit         RepoAudit
	auditErr      error
	agentRepo     AgentRepo
	agentRepoErr  error
	snapshots     bool
	snapshotsErr  error
	beAddErr      error
	beFindErr     error
	bes           []BootEnvironment
	disk          Disk
	diskErr       error
	workDirBytes  int64 // what a leftover work directory holds, until it is cleared
	workDirLeft   bool
	clearStaleErr error
	clearCacheErr error
	refreshErr    error

	// The state the stages leave. pkgsAbsent says the box has no packages marker
	// (`opnsense-update -vp` prints an empty line): an image or a box installed from
	// one never ran stage P, which writes it, and only when its pkg upgrade succeeded.
	base, kernel, pkgs string
	pkgsAbsent         bool
	markers            Markers
	setsDirBusy        bool
	running, userland  string
	updateLog          LogFile
	upgradeLog         LogFile
	stageErr           error

	// The request. stage0 is how stage 0 ends: "reboot" (the markers, the reboot and
	// the landing), "abort" (the script's own abort path), "diskfull" (the fetch or
	// the extraction ran out of disk), "vanish" (the request is accepted and nothing
	// starts).
	upgradeAnswer        string
	upgradeErr           error
	upgradeErrAfterStart bool
	stage0               string
	diskText             string
	runReads             int
	earlyDone            bool
	landCore             string
	posts                int
	run                  *simHopRun

	hooks map[string]func(*simDevice)
}

type simHopRun struct {
	reads int
}

// newSimHop is a healthy box: ZFS with room for the upgrade and a boot environment,
// the NetDefense tree under the new ABI, no HA, no third party.
func newSimHop() simHop {
	return simHop{
		snapshots:     true,
		agentRepo:     AgentRepo{Nested: true, Tree: true},
		disk:          Disk{CacheFree: 40 << 30, RootFree: 40 << 30, ZFS: true, Pool: "zroot", PoolFree: 40 << 30, BootDataset: "zroot/ROOT/default", BootCost: 1339559936},
		running:       "14.3-RELEASE-p16",
		userland:      "14.3-RELEASE-p16",
		landABI:       "FreeBSD:15:amd64",
		upgradeAnswer: "ok",
		stage0:        "reboot",
		diskText:      "Disc quota exceeded",
		runReads:      2,
		landCore:      "26.7.1_1",
	}
}

// offer is the sets the check lists for the series on offer.
func (h simHop) offer(series string) []opnapi.FirmwareUpgradeSet {
	if h.sets != nil {
		return h.sets
	}
	return offerSets(series)
}

// treeProbe answers a probe of a series' own tree on an ABI.
func (h simHop) treeProbe(abi, series string) ProbeResult {
	switch {
	case h.treeUnreachable:
		return ProbeUnreachable
	case h.treeMissing:
		return ProbeMissing
	case abi == h.landABI && series == "26.7":
		return ProbeFound
	}
	return ProbeMissing
}

// hook runs a test's mutation when the engine reaches a method, with the lock held.
func (d *simDevice) hook(name string) {
	if f := d.hop.hooks[name]; f != nil {
		f(d)
	}
}

// onCall registers fn to run, with the box locked, when the engine calls the
// named method: the way a test changes the box between two steps.
func (d *simDevice) onCall(name string, fn func(*simDevice)) {
	d.do(func(d *simDevice) {
		if d.hop.hooks == nil {
			d.hop.hooks = map[string]func(*simDevice){}
		}
		d.hop.hooks[name] = fn
	})
}

func (d *simDevice) HAMember(context.Context) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.record("ha-member")
	d.hook("ha-member")
	return d.hop.ha, d.hop.haErr
}

func (d *simDevice) RepoAudit(context.Context) (RepoAudit, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.record("repo-audit")
	d.hook("repo-audit")
	return d.hop.audit, d.hop.auditErr
}

func (d *simDevice) DiskFree(context.Context) (Disk, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.record("disk-free")
	d.hook("disk-free")
	if d.hop.diskErr != nil {
		return Disk{}, d.hop.diskErr
	}
	disk := d.hop.disk
	if d.hop.workDirLeft {
		disk.CacheFree -= d.hop.workDirBytes
	}
	return disk, nil
}

func (d *simDevice) ClearStaleWork(context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.record("clear-stale")
	d.hook("clear-stale")
	return d.clearCache(d.hop.clearStaleErr)
}

func (d *simDevice) ClearUpgradeCache(context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.record("clear-cache")
	d.hook("clear-cache")
	return d.clearCache(d.hop.clearCacheErr)
}

// clearCache is `opnsense-update -es`: it empties the whole directory, the markers
// and the logs included.
func (d *simDevice) clearCache(fail error) error {
	if fail != nil {
		return fail
	}
	d.hop.markers = Markers{}
	d.hop.workDirLeft = false
	d.hop.setsDirBusy = false
	d.hop.updateLog, d.hop.upgradeLog = LogFile{}, LogFile{}
	return nil
}

func (d *simDevice) RefreshCatalog(context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.record("refresh-catalog")
	return d.hop.refreshErr
}

func (d *simDevice) AgentRepoProbe(_ context.Context, abi string) (AgentRepo, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.record("agent-repo %s", abi)
	d.hook("agent-repo")
	return d.hop.agentRepo, d.hop.agentRepoErr
}

func (d *simDevice) SnapshotSupported(context.Context) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.record("snapshot-supported")
	return d.hop.snapshots, d.hop.snapshotsErr
}

func (d *simDevice) CreateBootEnvironment(_ context.Context, name, note string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.record("be-create %s", name)
	d.hook("be-create")
	if d.hop.beAddErr != nil {
		return d.hop.beAddErr
	}
	for _, be := range d.hop.bes {
		if be.Name == name {
			return ErrBootEnvironmentExists
		}
	}
	d.hop.bes = append(d.hop.bes, BootEnvironment{UUID: "uuid-" + name, Name: name, Active: "-"})
	return nil
}

func (d *simDevice) FindBootEnvironment(_ context.Context, name string) (BootEnvironment, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.record("be-find %s", name)
	if d.hop.beFindErr != nil {
		return BootEnvironment{}, false, d.hop.beFindErr
	}
	for _, be := range d.hop.bes {
		if be.Name == name {
			return be, true, nil
		}
	}
	return BootEnvironment{}, false, nil
}

// stageVersion is a set's version: the series upgrade's own when a test set one,
// else the single release the minor simulation keeps for base and kernel.
func (d *simDevice) stageVersion(set string) string {
	if set != "" {
		return set
	}
	return d.sets
}

func (d *simDevice) StageState(context.Context) (StageState, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.record("stage-state")
	d.hook("stage-state")
	if d.hop.stageErr != nil {
		return StageState{}, d.hop.stageErr
	}
	pkgs := d.stageVersion(d.hop.pkgs)
	if d.hop.pkgsAbsent {
		pkgs = ""
	}
	return StageState{
		Core: d.core, Base: d.stageVersion(d.hop.base), Kernel: d.stageVersion(d.hop.kernel), Pkgs: pkgs,
		Markers: d.hop.markers, SetsPendingEmpty: !d.hop.setsDirBusy,
		RunningKernel: d.hop.running, Userland: d.hop.userland,
		UpdateLog: d.hop.updateLog, UpgradeLog: d.hop.upgradeLog,
	}, nil
}

func (d *simDevice) TriggerUpgrade(ctx context.Context) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.record("upgrade")
	d.hop.posts++
	d.hook("upgrade")
	if d.cancelOnUpdate != nil {
		d.cancelOnUpdate()
	}
	if err := ctx.Err(); err != nil {
		return "", err // the request never left
	}
	if d.foreignOnUpdate > 0 && d.hop.upgradeAnswer == "ok" && !d.updateDropped {
		// Another firmware job holds OPNsense's lock: the launcher drops the request
		// and the API still answers ok.
		d.foreignOnUpdate--
		d.foreignLeft = d.foreignLife
		d.progressText = "***GOT REQUEST TO CHECK FOR UPDATES***\nCurrently running OPNsense at now\nFetching changelog information, please wait... "
		return "ok", nil
	}
	if d.hop.upgradeErr != nil && !d.hop.upgradeErrAfterStart {
		return "", d.hop.upgradeErr
	}
	if d.hop.upgradeAnswer != "ok" {
		return d.hop.upgradeAnswer, nil
	}
	if d.updateDropped || d.hop.stage0 == "vanish" {
		return "ok", nil
	}
	if d.majorOffered == "" {
		// Below the series' final build there is no offer, and core 26.1.9's upgrade.sh
		// does not see that opnsense-update refused ("No known packages set to fetch was
		// specified.") and reboots the box all the same, changing nothing. The agent
		// must never get here.
		d.progressText = "***GOT REQUEST TO UPGRADE***\nNo known packages set to fetch was specified.\n***REBOOT***\n"
		d.boot += 300
		d.ran = true
		return "ok", nil
	}
	d.updating = true
	d.progressText = "***GOT REQUEST TO UPGRADE***\nCurrently running OPNsense at now\n"
	d.hop.run = &simHopRun{reads: d.hop.runReads}
	if d.hop.upgradeErr != nil {
		return "", d.hop.upgradeErr // accepted and started; the answer was lost
	}
	return "ok", nil
}

// hopProgress is what the upgrade script's log says as stage 0 goes on and ends.
// OPNsense reads the status from the log's text: ***DONE*** anywhere makes it "done",
// before it looks for ***REBOOT***.
func (d *simDevice) hopProgress() *opnapi.FirmwareProgressStatus {
	d.hook("progress")
	status := func() string {
		switch {
		case strings.Contains(d.progressText, "***DONE***"):
			return "done"
		case strings.Contains(d.progressText, "***REBOOT***"):
			return "reboot"
		}
		return "running"
	}
	if d.hop.run.reads > 0 {
		d.hop.run.reads--
		if d.hop.earlyDone && d.hop.run.reads == 0 && !strings.Contains(d.progressText, "***DONE***") {
			d.progressText += "Fetching packages-26.7-amd64.tar\n***DONE***\n"
		}
		return &opnapi.FirmwareProgressStatus{Status: status(), Log: d.progressText}
	}
	d.updating = false
	d.checked = nil
	d.hop.run = nil
	if d.hop.earlyDone {
		d.progressText = strings.Replace(d.progressText, "Fetching packages-26.7-amd64.tar\n***DONE***\n", "", 1)
	}
	now := time.Now()
	switch d.hop.stage0 {
	case "abort":
		d.progressText += "The upgrade was aborted due to an error.\n***DONE***\n"
		d.hop.markers = Markers{}
		d.hop.updateLog = LogFile{Exists: true, ModTime: now, Text: d.progressText}
	case "diskfull":
		d.progressText += "tar: Error exit delayed from previous errors.\n" + d.diskTextLine() + "\n***DONE***\n"
		d.hop.workDirLeft, d.hop.workDirBytes = true, 1244208<<10
		d.hop.updateLog = LogFile{Exists: true, ModTime: now} // empty: its rewrite was lost
	default: // "reboot"
		d.hop.markers = Markers{Base: true, Pkgs: true} // the kernel marker is gone: stage 0 installed the kernel
		d.progressText += "***REBOOT***\n"
		d.land()
	}
	return &opnapi.FirmwareProgressStatus{Status: status(), Log: d.progressText}
}

func (d *simDevice) diskTextLine() string { return d.hop.diskText }

// land is the box after the three reboots: the new core, base, kernel and
// packages, on the new ABI, with the pin left as the agent wrote it, which names the
// old series on the new ABI and so resolves to nothing.
func (d *simDevice) land() {
	d.ran = true
	d.boot += 300
	d.abi = d.hop.landABI
	d.series = "26.7"
	d.core = d.hop.landCore
	d.updatePkg, d.sets = "26.7", "26.7"
	d.hop.base, d.hop.kernel, d.hop.pkgs = "26.7", "26.7", "26.7"
	d.hop.pkgsAbsent = false // stage P writes the marker when its pkg upgrade succeeds
	d.pkgs["opnsense"], d.pkgs["opnsense-update"] = d.core, "26.7"
	// The packages stage installs the whole catalog of the release it lands on.
	if cat, ok := d.folders[StripHotfix(d.core)]; ok {
		for name, version := range cat.pkgs {
			d.pkgs[name] = version
		}
	}
	d.hop.markers, d.hop.setsDirBusy, d.hop.workDirLeft = Markers{}, false, false
	d.hop.running, d.hop.userland = "15.1-RELEASE-p1", "15.1-RELEASE-p1"
	d.hop.updateLog = LogFile{Exists: true, ModTime: time.Now(), Text: "\n"}
	d.majorOffered = ""
	d.checked = nil
}

// --- the rig of a series upgrade -------------------------------------------------------

var (
	// approveFinal is what a track holding the final build approves for 26.1.
	approveFinal = map[string]string{"26.1": "26.1.11"}
	// approveFinalHotfix names the final build's own hotfix revision as the target:
	// the pin's directory is then not the target's, and no minor check is made.
	approveFinalHotfix = map[string]string{"26.1": "26.1.11_10"}
)

// finalBuild26 makes the box a community 26.1.11_10 on FreeBSD:14, the final build of
// its series: the series upgrade is on offer (with the sets the proof measured), the
// 26.1.11 directory holds what is installed, and the 26.7.1 directory of the new ABI
// holds what the hop lands on.
func finalBuild26(d *simDevice) {
	d.series = "26.1"
	d.core, d.updatePkg, d.sets = "26.1.11_10", "26.1.11", "26.1.11"
	d.pkgs = map[string]string{"curl": "8.20.0", "pkg": "2.3.1_1", "opnsense": "26.1.11_10", "opnsense-update": "26.1.11"}
	d.abi = "FreeBSD:14:amd64"
	d.folders = map[string]simCatalog{
		"26.1.11": {core: "26.1.11_10", update: "26.1.11", pkgs: map[string]string{"curl": "8.20.0", "pkg": "2.3.1_1"}, abi: "FreeBSD:14:amd64"},
		"26.7.1":  {core: "26.7.1_1", update: "26.7", pkgs: map[string]string{"curl": "8.22.0", "pkg": "2.3.1_1"}, abi: "FreeBSD:15:amd64"},
	}
	d.latest = d.folders["26.1.11"]
	d.majorOffered = "26.7"
	d.hop.base, d.hop.kernel, d.hop.pkgs = "26.1.11", "26.1.11", "26.1.6_2" // the pkgs marker of an image can sit below the core
}

// hopPayload is the advance a track window sends a device at the final build.
func hopPayload(approved map[string]string) Payload {
	p := advancePayload(TrackFast, true, approved)
	p.Major = "26.7"
	return p
}

// hopRig is a rig whose box is a 26.1.11_10 enrolled in the fast track, with the
// calls of the enrollment forgotten.
func hopRig(t *testing.T, tweak ...func(*simDevice)) *rig {
	t.Helper()
	r := enrolledRig(t, append([]func(*simDevice){finalBuild26}, tweak...)...)
	r.dev.do(func(d *simDevice) { d.record("--") })
	return r
}

// wantHop asserts the answer rule on a result: kind major, the series as its
// target_version and the notes.
func wantHop(t *testing.T, res *Result, notes ...string) {
	t.Helper()
	if res.Kind != KindMajor || res.TargetVersion != "26.7" {
		t.Fatalf("kind %q target %q: the answer of a series upgrade carries kind major and the series", res.Kind, res.TargetVersion)
	}
	if !equal(res.Notes, notes) {
		t.Fatalf("notes %v, want %v", res.Notes, notes)
	}
}

// wantOrdinary asserts an answer given before the step chose the series upgrade: no
// kind and no notes, even though the payload carried a major.
func wantOrdinary(t *testing.T, res *Result) {
	t.Helper()
	if res.Kind != "" || len(res.Notes) != 0 {
		t.Fatalf("kind %q notes %v: an answer before the decision is the ordinary step's", res.Kind, res.Notes)
	}
}

// posts is how many times the box was asked to start the upgrade.
func (d *simDevice) posts() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.hop.posts
}

// reboots runs the task until the box reboots, as it does for the update: the
// agent is stopped with the box, the row stays IN_PROGRESS, and the job the task
// left is what the agent that comes back settles it by.
func hopRebootedJob(t *testing.T, r *rig, p Payload) Job {
	t.Helper()
	initialBoot := r.dev.boot
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	go func() {
		for {
			r.dev.mu.Lock()
			rebooted := r.dev.boot != initialBoot
			r.dev.mu.Unlock()
			if rebooted {
				cancel()
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	if out := r.runCtx(ctx, p); !out.Aborted {
		t.Fatalf("the reboot should leave the task alone, got %+v", out)
	}
	return r.jobs[len(r.jobs)-1]
}

var errSimDisk = errors.New("simulated disk failure")

func indexOfPrefix(calls []string, prefix string) int {
	for i, c := range calls {
		if strings.HasPrefix(c, prefix) {
			return i
		}
	}
	return -1
}
