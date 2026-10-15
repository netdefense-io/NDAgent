package track

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestEnroll_PinsAtTheInstalledReleaseAndChecksAfterTheChange(t *testing.T) {
	r := newRig(t)
	out := r.run(enrollPayload(TrackFast))

	res := wantResult(t, out, OutcomeSuccess, ReasonEnrolled)
	wantVersions(t, res, "26.7.3_11", "26.7.3_11", "", "26.7.3_11")
	if res.Drift || res.ReinstallEntries != 0 {
		t.Errorf("drift=%v reinstalls=%d", res.Drift, res.ReinstallEntries)
	}
	// The release's directory takes hotfix revisions in place, so the pin names 26.7.3.
	if got := r.dev.Flavour(); got != "26.7/MINT/26.7.3/latest" {
		t.Fatalf("flavour %q", got)
	}
	st := r.state()
	if !st.Pinned || st.PinnedFlavour != "26.7/MINT/26.7.3/latest" || st.PinnedVersion != "26.7.3_11" ||
		st.OriginalFlavour != "" || st.Track != TrackFast || st.Pending != nil {
		t.Fatalf("record %+v", st)
	}

	// The mirror was asked before the write, and a forced check followed it.
	calls := r.dev.Calls()
	probe, set, check := indexOf(calls, "probe "), indexOf(calls, "set "), indexOf(calls, "check")
	if probe < 0 || set < 0 || check < 0 || !(probe < set && set < check) {
		t.Fatalf("calls %v: want probe, then set, then check", calls)
	}
	if len(r.jobs) == 0 || r.jobs[0].Phase != PhaseStarted || r.jobs[len(r.jobs)-1].Phase != PhaseMoved {
		t.Errorf("the job was not recorded before and after the move: %+v", r.jobs)
	}
}

func indexOf(calls []string, prefix string) int {
	for i, c := range calls {
		if strings.HasPrefix(c, prefix) {
			return i
		}
	}
	return -1
}

func TestEnroll_PinsTheGADirectory(t *testing.T) {
	r := newRig(t, func(d *simDevice) {
		d.core, d.updatePkg, d.sets = "26.7", "26.7", "26.7"
		d.pkgs["opnsense"] = "26.7"
		d.latest = d.folders["26.7"]
	})
	res := wantResult(t, r.run(enrollPayload(TrackStable)), OutcomeSuccess, ReasonEnrolled)
	wantVersions(t, res, "26.7", "26.7", "", "26.7")
	if got := r.dev.Flavour(); got != "26.7/MINT/26.7/latest" {
		t.Fatalf("flavour %q", got)
	}
}

// After a series' final release its hotfixes get directories of their own, and the
// pin is at the hotfix directory the installed release is.
func TestEnroll_PinsAHotfixDirectoryAfterAFinalRelease(t *testing.T) {
	r := newRig(t, func(d *simDevice) {
		d.series = "24.7"
		d.core, d.updatePkg, d.sets = "24.7.12_3", "24.7.12", "24.7.12"
		d.pkgs["opnsense"] = "24.7.12_3"
		d.folders = map[string]simCatalog{
			"24.7.12":   {core: "24.7.12", update: "24.7.12"},
			"24.7.12_3": {core: "24.7.12_3", update: "24.7.12"},
		}
		d.latest = d.folders["24.7.12_3"]
	})
	res := wantResult(t, r.run(enrollPayload(TrackRegular)), OutcomeSuccess, ReasonEnrolled)
	wantVersions(t, res, "24.7.12_3", "24.7.12_3", "", "24.7.12_3")
	if got := r.dev.Flavour(); got != "24.7/MINT/24.7.12_3/latest" {
		t.Fatalf("flavour %q", got)
	}
}

func TestEnroll_AnEnrollAgainIsANoopWithoutWrites(t *testing.T) {
	r := newRig(t)
	wantResult(t, r.run(enrollPayload(TrackFast)), OutcomeSuccess, ReasonEnrolled)
	writes := len(r.dev.writes())

	out := r.run(enrollPayload(TrackRegular)) // the control plane asked again, for another track
	res := wantResult(t, out, OutcomeNoop, ReasonEnrolled)
	wantVersions(t, res, "26.7.3_11", "26.7.3_11", "", "26.7.3_11")
	if got := len(r.dev.writes()); got != writes {
		t.Errorf("the device was written %d more times", got-writes)
	}
	if st := r.state(); st.Track != TrackRegular {
		t.Errorf("the track is %q", st.Track)
	}
}

// Every hold leaves the device as it found it, and says why with the closed reason.
func TestEnroll_HoldsInsteadOfPinning(t *testing.T) {
	cases := map[string]struct {
		tweak  func(*simDevice)
		reason string
		writes int // writes the device saw: a hold before the pin writes nothing
	}{
		"a subscription":              {func(d *simDevice) { d.subscription = true }, ReasonHeldUnsupportedEdition, 0},
		"a release type of its own":   {func(d *simDevice) { d.typ = "business" }, ReasonHeldUnsupportedEdition, 0},
		"a flavour of the operator's": {func(d *simDevice) { d.flavour = "25.7/MINT/25.7.11/latest" }, ReasonHeldCustomFlavour, 0},
		"a release folder the mirror lacks": {func(d *simDevice) {
			delete(d.folders, "26.7.3")
			d.latest = d.folders["26.7.5"]
		}, ReasonHeldReleaseFolderMissing, 0},
		"a mirror that cannot be asked":   {func(d *simDevice) { d.unreachable = true }, ReasonHeldCheckFailed, 0},
		"a folder that answers a failure": {func(d *simDevice) { d.probeErr = map[string]bool{"26.7.3": true} }, ReasonHeldCheckFailed, 0},
		"an aux repository without the aux folder": {func(d *simDevice) {
			d.aux = true
			d.auxFolders = map[string]bool{}
		}, ReasonHeldReleaseFolderMissing, 0},
		"a backend that stays busy":                    {func(d *simDevice) { d.alwaysBusy = true }, ReasonHeldFirmwareBusy, 0},
		"settings that cannot be read":                 {func(d *simDevice) { d.settingsErr = errSim }, ReasonHeldCheckFailed, 0},
		"an installed release that cannot be read":     {func(d *simDevice) { d.installedErr = errSim }, ReasonHeldCheckFailed, 0},
		"an installed release that is no release name": {func(d *simDevice) { d.core = "27.1.a" }, ReasonHeldCheckFailed, 0},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, tc.tweak)
			before := r.dev.Flavour()
			out := r.run(enrollPayload(TrackFast))
			res := wantResult(t, out, OutcomeHeld, tc.reason)
			if res.PinnedVersion != "" {
				t.Errorf("a hold during enroll leaves the device unpinned; the result names a pin %q", res.PinnedVersion)
			}
			if got := len(r.dev.writes()); got != tc.writes {
				t.Errorf("the device was written %d times: %v", got, r.dev.writes())
			}
			if r.dev.Flavour() != before {
				t.Errorf("flavour %q, was %q", r.dev.Flavour(), before)
			}
			if st := r.state(); st != nil {
				t.Errorf("a record was left behind: %+v", st)
			}
		})
	}
}

// The plan under the pin decides: when it shows what the pin was meant to prevent,
// the flavour goes back, a check follows, and the device is held.
func TestEnroll_APlanThatShowsMoreThanAHotfixIsRolledBack(t *testing.T) {
	cases := map[string]struct {
		tweak  func(*simDevice)
		reason string
	}{
		"a downgrade":   {func(d *simDevice) { d.extraDowngrade = true }, ReasonHeldDowngradeRisk},
		"a new package": {func(d *simDevice) { d.extraNew = true }, ReasonHeldUnexpectedPlan},
		"pending sets": {func(d *simDevice) {
			d.sets = "26.7.2" // base and kernel behind the packages: a mixed state
		}, ReasonHeldRebootPending},
		"a release beyond the installed one": {func(d *simDevice) {
			d.folders["26.7.3"] = simCatalog{core: "26.7.4_1", update: "26.7.4"}
		}, ReasonHeldUnexpectedPlan},
		"a check that cannot use the mirror": {func(d *simDevice) { d.checkFailsAs = "repository" }, ReasonHeldCheckFailed},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, tc.tweak)
			out := r.run(enrollPayload(TrackFast))
			wantResult(t, out, OutcomeHeld, tc.reason)

			// It was pinned for the check and put back by compare-and-swap.
			if got := r.dev.writes(); !equal(got, []string{"26.7/MINT/26.7.3/latest", ""}) {
				t.Fatalf("writes %v, want the pin and then the original", got)
			}
			if r.dev.Flavour() != "" {
				t.Errorf("flavour %q, want the default", r.dev.Flavour())
			}
			// A forced check follows the restore as it followed the pin.
			calls := r.dev.Calls()
			lastSet := -1
			for i, c := range calls {
				if strings.HasPrefix(c, "set ") {
					lastSet = i
				}
			}
			if indexOf(calls[lastSet:], "check") < 0 {
				t.Errorf("no check after the restore: %v", calls)
			}
			if st := r.state(); st != nil {
				t.Errorf("a record was left behind: %+v", st)
			}
		})
	}
}

// A same-release hotfix revision in the pinned directory is allowed: a device a few
// revisions behind sees it in the plan, and is enrolled all the same.
func TestEnroll_ToleratesAHotfixOfTheInstalledRelease(t *testing.T) {
	r := newRig(t, func(d *simDevice) {
		d.core = "26.7.3_8"
		d.pkgs["opnsense"] = "26.7.3_8"
		d.pkgs["curl"] = "8.20.0" // an ordinary package the hotfix upgrades
	})
	res := wantResult(t, r.run(enrollPayload(TrackFast)), OutcomeSuccess, ReasonEnrolled)
	wantVersions(t, res, "26.7.3_8", "26.7.3_8", "", "26.7.3_8")
}

// The same-version reinstall of a factory-installed core record is noise.
func TestEnroll_ASameVersionReinstallIsReportedNotHeldOn(t *testing.T) {
	r := newRig(t, func(d *simDevice) { d.reinstallCore = true })
	res := wantResult(t, r.run(enrollPayload(TrackFast)), OutcomeSuccess, ReasonEnrolled)
	if res.ReinstallEntries != 1 {
		t.Errorf("reinstall_entries = %d", res.ReinstallEntries)
	}
	for _, c := range r.dev.Calls() {
		if strings.HasPrefix(c, "update") || strings.HasPrefix(c, "exec") {
			t.Errorf("the agent acted on a reinstall entry: %v", r.dev.Calls())
		}
	}
	if got := r.dev.writes(); len(got) != 1 {
		t.Errorf("writes %v: the reinstall entry must not roll the pin back", got)
	}
}

// Packages the agent does not hold (a repository of its own) upgrade whatever the
// pin says; they are not a reason to hold.
func TestEnroll_IgnoresUpgradesFromRepositoriesThePinDoesNotHold(t *testing.T) {
	r := newRig(t, func(d *simDevice) { d.foreignUpgrade = true })
	wantResult(t, r.run(enrollPayload(TrackFast)), OutcomeSuccess, ReasonEnrolled)
}

func TestEnroll_AWriteThatErrorsButTookEffectIsJudgedByTheReadBack(t *testing.T) {
	r := newRig(t, func(d *simDevice) { d.setErr, d.setAppliedButErr = errSim, true })
	// The first write errors yet is applied; the restore also errors (it is the
	// same fake) yet is applied, so the rollback ends clean.
	out := r.run(enrollPayload(TrackFast))
	if out.Result == nil {
		t.Fatalf("want a result, got %+v", out)
	}
}

func TestEnroll_AFailedWriteIsRolledBackAndHeld(t *testing.T) {
	r := newRig(t, func(d *simDevice) { d.setErr = errSim })
	out := r.run(enrollPayload(TrackFast))
	wantResult(t, out, OutcomeHeld, ReasonHeldCheckFailed)
	if r.dev.Flavour() != "" {
		t.Errorf("flavour %q", r.dev.Flavour())
	}
}

func TestEnroll_APinOverAGoneRecordIsFlaggedAsDrift(t *testing.T) {
	r := newRig(t)
	wantResult(t, r.run(enrollPayload(TrackFast)), OutcomeSuccess, ReasonEnrolled)
	r.dev.do(func(d *simDevice) { d.flavour = "" }) // reset in the GUI

	res := wantResult(t, r.run(enrollPayload(TrackFast)), OutcomeSuccess, ReasonEnrolled)
	if !res.Drift {
		t.Error("the pin the record held was gone: the enroll must say so")
	}
}

// The context ending aborts the task, which the row reconciler then decides; the
// rollback of what the enrollment changed runs on a context of its own.
func TestEnroll_ACancelledTaskIsAbortedAndTheRollbackRunsToTheEnd(t *testing.T) {
	r := newRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	// The check never answers, so the cancel lands inside its wait.
	r.dev.do(func(d *simDevice) { d.onSet, d.dropChecks = cancel, 100 })
	out := r.runCtx(ctx, enrollPayload(TrackFast))
	if !out.Aborted {
		t.Fatalf("want an aborted task, got %+v", out)
	}
	if r.dev.Flavour() != "" {
		t.Errorf("a cancelled enrollment left the pin in place: %q", r.dev.Flavour())
	}
	if st := r.state(); st != nil && (st.Pinned || st.Pending != nil) {
		t.Errorf("a cancelled enrollment left a record: %+v", st)
	}
}

// --- unenroll ---------------------------------------------------------------------

func enrolled(t *testing.T, r *rig) {
	t.Helper()
	wantResult(t, r.run(enrollPayload(TrackFast)), OutcomeSuccess, ReasonEnrolled)
	r.jobs, r.dev.calls = nil, nil
}

func TestUnenroll_RestoresTheOriginalSettingAndForgets(t *testing.T) {
	r := newRig(t)
	enrolled(t, r)

	out := r.run(unenrollPayload(TrackFast))
	res := wantResult(t, out, OutcomeSuccess, ReasonUnenrolled)
	wantVersions(t, res, "26.7.3_11", "26.7.3_11", "", "")
	if r.dev.Flavour() != "" {
		t.Fatalf("flavour %q, want the default", r.dev.Flavour())
	}
	if st := r.state(); st != nil {
		t.Errorf("the record survives: %+v", st)
	}
	// A check follows the restore.
	if calls := r.dev.Calls(); indexOf(calls, "check") < indexOf(calls, "set ") {
		t.Errorf("calls %v", calls)
	}
}

func TestUnenroll_NothingToUndoIsANoop(t *testing.T) {
	r := newRig(t)
	res := wantResult(t, r.run(unenrollPayload(TrackFast)), OutcomeNoop, ReasonUnenrolled)
	wantVersions(t, res, "26.7.3_11", "26.7.3_11", "", "")
	if len(r.dev.writes()) != 0 {
		t.Errorf("writes %v", r.dev.writes())
	}
}

func TestUnenroll_AFlavourChangedByHandIsLeftAloneAndReportedAsDrift(t *testing.T) {
	r := newRig(t)
	enrolled(t, r)
	r.dev.do(func(d *simDevice) { d.flavour = "26.7/MINT/26.7.1/latest" })

	res := wantResult(t, r.run(unenrollPayload(TrackFast)), OutcomeNoop, ReasonPinDrift)
	if !res.Drift {
		t.Error("drift not reported")
	}
	if r.dev.Flavour() != "26.7/MINT/26.7.1/latest" {
		t.Errorf("the operator's flavour was overwritten: %q", r.dev.Flavour())
	}
	if len(r.dev.writes()) != 0 {
		t.Errorf("writes %v", r.dev.writes())
	}
	if st := r.state(); st != nil {
		t.Errorf("the agent still thinks it holds a pin: %+v", st)
	}
}

func TestUnenroll_AlreadyRestoredIsANoop(t *testing.T) {
	r := newRig(t)
	enrolled(t, r)
	r.dev.do(func(d *simDevice) { d.flavour = "" })
	wantResult(t, r.run(unenrollPayload(TrackFast)), OutcomeNoop, ReasonUnenrolled)
	if len(r.dev.writes()) != 0 {
		t.Errorf("writes %v", r.dev.writes())
	}
}

// An unenroll that could not do what it was asked fails, so the control plane
// asks again; it is not a hold, which leaves a row waiting for a window.
func TestUnenroll_ARestoreThatFailsIsFailedAndLeavesThePin(t *testing.T) {
	r := newRig(t)
	enrolled(t, r)
	r.dev.do(func(d *simDevice) { d.setErr = errSim })

	out := r.run(unenrollPayload(TrackFast))
	if out.Failure == "" {
		t.Fatalf("want a failure, got %+v", out)
	}
	if !out.Detail.Empty() {
		t.Errorf("an unenroll names no release it was moving to: %+v", out.Detail)
	}
	if r.dev.Flavour() != "26.7/MINT/26.7.3/latest" {
		t.Errorf("flavour %q: the pin must stay when the restore failed", r.dev.Flavour())
	}
	if st := r.state(); st == nil || !st.Pinned {
		t.Errorf("the record must keep the pin: %+v", st)
	}
}

func TestUnenroll_UnreadableDeviceFailsRatherThanHolds(t *testing.T) {
	r := newRig(t)
	enrolled(t, r)
	r.dev.do(func(d *simDevice) { d.settingsErr = errSim })
	out := r.run(unenrollPayload(TrackFast))
	if out.Failure == "" {
		t.Fatalf("want a failure, got %+v", out)
	}
}

// A flavour of exactly the shape the agent writes, and no record that it wrote
// it, is not "unenrolled": the answer closes the row on the control plane, and the
// device is still pinned. It may be an operator's own pin, so it is left, and said.
func TestUnenroll_APinShapedFlavourWithNoRecordIsReportedNotUnenrolled(t *testing.T) {
	r := newRig(t)
	r.dev.do(func(d *simDevice) { d.flavour = "26.7/MINT/26.7.3/latest" })

	res := wantResult(t, r.run(unenrollPayload(TrackFast)), OutcomeNoop, ReasonPinDrift)
	if !res.Drift {
		t.Error("drift not reported")
	}
	if r.dev.Flavour() != "26.7/MINT/26.7.3/latest" || len(r.dev.writes()) != 0 {
		t.Errorf("flavour %q, writes %v: a pin the agent has no record of is not its to restore", r.dev.Flavour(), r.dev.writes())
	}
}

func TestUnenroll_ATombstoneAndAPinShapedFlavourIsReportedAsWell(t *testing.T) {
	r := newRig(t)
	r.dev.do(func(d *simDevice) { d.flavour = "26.7/MINT/26.7.3/latest" })
	if err := r.store.Save(&State{Released: &Released{Reason: "dead_man", At: time.Now().Unix()}}); err != nil {
		t.Fatal(err)
	}
	wantResult(t, r.run(unenrollPayload(TrackFast)), OutcomeNoop, ReasonPinDrift)
	if r.state() != nil {
		t.Errorf("the tombstone survived: %+v", r.state())
	}
}

func TestUnenroll_AnythingElseWithNoRecordIsUnenrolled(t *testing.T) {
	for _, flavour := range []string{"", "26.7/latest", "not a release path"} {
		r := newRig(t)
		r.dev.do(func(d *simDevice) { d.flavour = flavour })
		res := wantResult(t, r.run(unenrollPayload(TrackFast)), OutcomeNoop, ReasonUnenrolled)
		if res.Drift {
			t.Errorf("flavour %q: drift reported", flavour)
		}
	}
}

// A record that cannot be removed fails the task: left behind it says the agent
// holds a pin, and the next round would put one back on a device the control plane
// has just released. The control plane asks again.
func TestUnenroll_ARecordThatCannotBeRemovedFailsTheTaskAndNoRoundPinsAgain(t *testing.T) {
	r := newRig(t)
	enrolled(t, r)
	r.store.remove = func(string) error { return errSim }

	out := r.run(unenrollPayload(TrackFast))
	if out.Failure == "" || !strings.Contains(out.Failure, "record") {
		t.Fatalf("want a failure about the record, got %+v", out)
	}
	if r.dev.Flavour() != "" {
		t.Fatalf("flavour %q: the setting is back", r.dev.Flavour())
	}

	r.dev.calls = nil
	r.eng.Tick(context.Background())
	if len(r.dev.writes()) != 0 {
		t.Fatalf("writes %v: a round pinned a device that was just unenrolled", r.dev.writes())
	}

	r.store.remove = os.Remove // the disk is back
	wantResult(t, r.run(unenrollPayload(TrackFast)), OutcomeNoop, ReasonUnenrolled)
	if r.state() != nil {
		t.Errorf("record %+v", r.state())
	}
}
