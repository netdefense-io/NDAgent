package track

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

var approve575 = map[string]string{"26.7": "26.7.5"}

// enrolledRig is a rig whose device was enrolled in the fast track at its
// installed release, with the calls of the enrollment forgotten.
func enrolledRig(t *testing.T, tweak ...func(*simDevice)) *rig {
	t.Helper()
	r := newRig(t, tweak...)
	enrolled(t, r)
	return r
}

// onlyHotfixes makes the update OPNsense runs end without a reboot, the way an
// update does that changes no base or kernel.
func onlyHotfixes(d *simDevice) { d.updateOutcome = "done" }

func TestAdvance_UpdatesToAHotfixRevisionInTheTargetsOwnDirectory(t *testing.T) {
	// Installed on 26.7.3_8, whose directory now holds 26.7.3_11: the key says the
	// device is at the target 26.7.3, and a forced check shows it is not.
	r := enrolledRig(t, onlyHotfixes, func(d *simDevice) {
		d.core = "26.7.3_8"
		d.pkgs["opnsense"] = "26.7.3_8"
		d.pkgs["curl"] = "8.20.0"
	})
	out := r.run(advancePayload(TrackFast, true, map[string]string{"26.7": "26.7.3"}))

	res := wantResult(t, out, OutcomeSuccess, ReasonApplied)
	wantVersions(t, res, "26.7.3_8", "26.7.3_11", "26.7.3", "26.7.3_11")
	if r.dev.Flavour() != "26.7/MINT/26.7.3/latest" {
		t.Errorf("flavour %q", r.dev.Flavour())
	}
	if st := r.state(); !st.Pinned || st.PinnedVersion != "26.7.3_11" || st.Pending != nil {
		t.Errorf("record %+v", st)
	}
	// The pin did not move: it already sat in the target's directory.
	if len(r.dev.writes()) != 0 {
		t.Errorf("writes %v", r.dev.writes())
	}
}

func TestAdvance_AtTheTargetWithNothingNewerIsANoop(t *testing.T) {
	r := enrolledRig(t)
	out := r.run(advancePayload(TrackFast, true, map[string]string{"26.7": "26.7.3"}))
	res := wantResult(t, out, OutcomeNoop, ReasonAtOrAboveTarget)
	wantVersions(t, res, "26.7.3_11", "26.7.3_11", "26.7.3", "26.7.3_11")
	if len(r.dev.writes()) != 0 || r.dev.count("update") != 0 {
		t.Errorf("calls %v", r.dev.Calls())
	}
	// The forced check ran at the pin to see whether the directory offers more.
	if r.dev.count("check") != 1 {
		t.Errorf("checks: %d", r.dev.count("check"))
	}
}

func TestAdvance_AboveTheTargetInAnotherDirectoryIsANoopWithoutAsking(t *testing.T) {
	r := newRig(t, func(d *simDevice) {
		d.core, d.updatePkg, d.sets = "26.7.5", "26.7.4_1", "26.7.4"
		d.pkgs["opnsense"] = "26.7.5"
		d.pkgs["curl"], d.pkgs["pkg"] = "8.22.0", "2.8.4_1"
	})
	enrolled(t, r)
	out := r.run(advancePayload(TrackFast, true, map[string]string{"26.7": "26.7.3"}))
	res := wantResult(t, out, OutcomeNoop, ReasonAtOrAboveTarget)
	wantVersions(t, res, "26.7.5", "26.7.5", "26.7.3", "26.7.5")
	if r.dev.count("check") != 0 || len(r.dev.writes()) != 0 {
		t.Errorf("calls %v: a device above the target needs no check and no move", r.dev.Calls())
	}
}

func TestAdvance_NoEntryForTheSeriesIsSeriesNotApproved(t *testing.T) {
	r := enrolledRig(t)
	out := r.run(advancePayload(TrackFast, true, map[string]string{"25.7": "25.7.11"}))
	res := wantResult(t, out, OutcomeNoop, ReasonSeriesNotApproved)
	wantVersions(t, res, "26.7.3_11", "26.7.3_11", "", "26.7.3_11")
	if r.dev.count("check") != 0 || len(r.dev.writes()) != 0 {
		t.Errorf("calls %v", r.dev.Calls())
	}
}

// reboot=true with a base and kernel to install: OPNsense reboots the box and the
// agent with it. The handler is cut short, the row is left, and the reconciler of
// the agent that comes back decides the outcome from the device.
func TestAdvance_AnUpdateThatRebootsIsSettledAfterTheReboot(t *testing.T) {
	r := enrolledRig(t)
	initialBoot := r.dev.boot

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { // the reboot: the agent is stopped
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
	out := r.runCtx(ctx, advancePayload(TrackFast, true, approve575))
	if !out.Aborted {
		t.Fatalf("a task cut short by the reboot must be left alone, got %+v", out)
	}

	// What was recorded before the request is what decides the row later.
	last := r.jobs[len(r.jobs)-1]
	if last.Phase != PhaseTriggered || last.Upgrade == nil || last.Upgrade.TriggeredAt == 0 || !last.Upgrade.RebootSeen ||
		last.From != "26.7.3_11" || last.Target != "26.7.5" || last.PrevFlavour != "26.7/MINT/26.7.3/latest" ||
		last.NewFlavour != "26.7/MINT/26.7.5/latest" {
		t.Fatalf("job %+v", last)
	}
	if st := r.state(); st.Pending == nil || !st.Pending.Triggered {
		t.Fatalf("record %+v", st)
	}

	// The agent that comes back: a new engine, the same device and record.
	back := r.newEngine()
	got, done := back.Resolve(context.Background(), last, Row{TaskID: "101", StartedAt: time.Now()})
	if !done {
		t.Fatal("the update had ended and the row was not resolved")
	}
	r.checkOutcome(advancePayload(TrackFast, true, approve575), got)
	res := wantResult(t, got, OutcomeSuccess, ReasonApplied)
	wantVersions(t, res, "26.7.3_11", "26.7.5", "26.7.5", "26.7.5")
	if r.dev.Flavour() != "26.7/MINT/26.7.5/latest" {
		t.Errorf("flavour %q", r.dev.Flavour())
	}
	if st := r.state(); !st.Pinned || st.PinnedFlavour != "26.7/MINT/26.7.5/latest" || st.PinnedVersion != "26.7.5" || st.Pending != nil {
		t.Errorf("record %+v", st)
	}
}

func TestAdvance_APackagesOnlyRunLeavesBaseAndKernelPending(t *testing.T) {
	r := enrolledRig(t)
	out := r.run(advancePayload(TrackFast, false, approve575))
	res := wantResult(t, out, OutcomeSuccess, ReasonApplied)
	wantVersions(t, res, "26.7.3_11", "26.7.5", "26.7.5", "26.7.5")
	if r.dev.count("update") != 0 || r.dev.count("exec") != 1 {
		t.Errorf("calls %v: reboot=false takes the exec path", r.dev.Calls())
	}
	if r.dev.sets != "26.7.3" {
		t.Errorf("base and kernel were installed (%s): a run without a reboot defers them", r.dev.sets)
	}
}

// Every end before the update is requested puts the pin back where it was.
func TestAdvance_APlanThatDoesNotLandOnTheTargetIsHeldWithThePinWhereItWas(t *testing.T) {
	cases := map[string]struct {
		tweak   func(*simDevice)
		reason  string
		outcome string
	}{
		"a downgrade": {func(d *simDevice) { d.extraDowngrade = true }, ReasonHeldDowngradeRisk, OutcomeHeld},
		"a release beyond the target": {func(d *simDevice) {
			d.folders["26.7.5"] = simCatalog{core: "26.7.6", update: "26.7.6"}
		}, ReasonHeldUnexpectedPlan, OutcomeHeld},
		"base and kernel at different releases": {func(d *simDevice) { d.kernelSkew = "26.7.9" }, ReasonHeldUnexpectedPlan, OutcomeHeld},
		"a check that cannot use the mirror":    {func(d *simDevice) { d.checkFailsAs = "repository" }, ReasonHeldCheckFailed, OutcomeHeld},
		"a mirror that offers less than the target": {func(d *simDevice) {
			d.folders["26.7.5"] = simCatalog{core: "26.7.4_1", update: "26.7.4"}
		}, ReasonTargetNotYetOffered, OutcomeNoop},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := enrolledRig(t)
			r.dev.do(tc.tweak)
			out := r.run(advancePayload(TrackFast, true, approve575))
			res := wantResult(t, out, tc.outcome, tc.reason)
			wantVersions(t, res, "26.7.3_11", "26.7.3_11", "26.7.5", "26.7.3_11")

			if got := r.dev.writes(); !equal(got, []string{"26.7/MINT/26.7.5/latest", "26.7/MINT/26.7.3/latest"}) {
				t.Errorf("writes %v: the pin should move to the target and come back", got)
			}
			if r.dev.Flavour() != "26.7/MINT/26.7.3/latest" {
				t.Errorf("flavour %q", r.dev.Flavour())
			}
			if r.dev.count("update") != 0 {
				t.Error("an update was requested")
			}
			if st := r.state(); !st.Pinned || st.PinnedFlavour != "26.7/MINT/26.7.3/latest" || st.Pending != nil || st.PinnedVersion != "26.7.3_11" {
				t.Errorf("record %+v", st)
			}
			// The restore is followed by a forced check, like the move.
			calls := r.dev.Calls()
			lastSet := -1
			for i, c := range calls {
				if strings.HasPrefix(c, "set ") {
					lastSet = i
				}
			}
			if indexOf(calls[lastSet:], "check") < 0 {
				t.Errorf("no check after the pin was put back: %v", calls)
			}
		})
	}
}

func TestAdvance_AFolderTheMirrorLacksIsNotYetOffered(t *testing.T) {
	r := enrolledRig(t, func(d *simDevice) { delete(d.folders, "26.7.5") })
	out := r.run(advancePayload(TrackFast, true, approve575))
	res := wantResult(t, out, OutcomeNoop, ReasonTargetNotYetOffered)
	wantVersions(t, res, "26.7.3_11", "26.7.3_11", "26.7.5", "26.7.3_11")
	if len(r.dev.writes()) != 0 || r.dev.count("check") != 0 {
		t.Errorf("calls %v: the pin must not be written to a folder the mirror lacks", r.dev.Calls())
	}
}

func TestAdvance_AMirrorThatCannotBeAskedIsAHold(t *testing.T) {
	r := enrolledRig(t)
	r.dev.do(func(d *simDevice) { d.probeErr = map[string]bool{"26.7.5": true} })
	wantResult(t, r.run(advancePayload(TrackFast, true, approve575)), OutcomeHeld, ReasonHeldCheckFailed)
	if len(r.dev.writes()) != 0 {
		t.Errorf("writes %v", r.dev.writes())
	}
}

func TestAdvance_AnUpdateOpnsenseDoesNotStartIsHeldAsBusyAndThePinComesBack(t *testing.T) {
	r := enrolledRig(t, func(d *simDevice) { d.updateDropped = true })
	out := r.run(advancePayload(TrackFast, true, approve575))
	wantResult(t, out, OutcomeHeld, ReasonHeldFirmwareBusy)
	if r.dev.count("update") != 2 {
		t.Errorf("the request is made twice: %v", r.dev.Calls())
	}
	if r.dev.Flavour() != "26.7/MINT/26.7.3/latest" {
		t.Errorf("flavour %q", r.dev.Flavour())
	}
	if st := r.state(); st.Pending != nil || !st.Pinned {
		t.Errorf("record %+v", st)
	}
}

func TestAdvance_AnUpdateRefusedByOpnsenseIsHeldAndThePinComesBack(t *testing.T) {
	r := enrolledRig(t, func(d *simDevice) { d.updateAnswer = "failure" })
	wantResult(t, r.run(advancePayload(TrackFast, true, approve575)), OutcomeHeld, ReasonHeldCheckFailed)
	if r.dev.Flavour() != "26.7/MINT/26.7.3/latest" {
		t.Errorf("flavour %q", r.dev.Flavour())
	}
}

func TestAdvance_AnUpdateThatFailsIsFailedWithTheTargetNamed(t *testing.T) {
	r := enrolledRig(t, func(d *simDevice) {
		d.updateFails = true
		d.updateOutcome = "done"
	})
	out := r.run(advancePayload(TrackFast, true, approve575))
	if out.Failure == "" {
		t.Fatalf("want a failure, got %+v", out)
	}
	// The control plane counts the failure against the release it was moving to.
	if out.Detail.Target != "26.7.5" || out.Detail.PinnedVersion != "26.7.3_11" {
		t.Errorf("detail %+v", out.Detail)
	}
	// Nothing was installed, so the pin is back where it was, not left ahead of the
	// installed release for the GUI to finish the job outside the window.
	if r.dev.Flavour() != "26.7/MINT/26.7.3/latest" {
		t.Errorf("flavour %q", r.dev.Flavour())
	}
	if st := r.state(); st.Pending != nil || st.PinnedFlavour != "26.7/MINT/26.7.3/latest" {
		t.Errorf("record %+v", st)
	}
}

func TestAdvance_APackagesOnlyRunThatExitsNonZeroIsFailed(t *testing.T) {
	r := enrolledRig(t, func(d *simDevice) { d.updateFails = true })
	out := r.run(advancePayload(TrackFast, false, approve575))
	if !strings.Contains(out.Failure, "exited with code 3") || out.Detail.Target != "26.7.5" {
		t.Fatalf("outcome %+v", out)
	}
	if r.dev.Flavour() != "26.7/MINT/26.7.3/latest" {
		t.Errorf("flavour %q", r.dev.Flavour())
	}
}

func TestAdvance_ABusyBackendHoldsBeforeAnythingIsWritten(t *testing.T) {
	r := enrolledRig(t)
	r.dev.do(func(d *simDevice) { d.alwaysBusy = true })
	wantResult(t, r.run(advancePayload(TrackFast, true, approve575)), OutcomeHeld, ReasonHeldFirmwareBusy)
	if len(r.dev.writes()) != 0 {
		t.Errorf("writes %v", r.dev.writes())
	}
}

func TestAdvance_ADroppedCheckRequestIsAskedForAgain(t *testing.T) {
	r := enrolledRig(t, onlyHotfixes, func(d *simDevice) {
		d.core = "26.7.3_8"
		d.pkgs["opnsense"] = "26.7.3_8"
	})
	r.dev.do(func(d *simDevice) { d.dropChecks = 1 })
	out := r.run(advancePayload(TrackFast, true, map[string]string{"26.7": "26.7.3"}))
	wantResult(t, out, OutcomeSuccess, ReasonApplied)
	if r.dev.count("check") != 2 {
		t.Errorf("checks: %d", r.dev.count("check"))
	}
}

// Test mode refuses an update and a reboot. The advance is a hold, which costs one
// window: a FAILED would block a release for the whole organization.
func TestAdvance_ATestModeAdvanceIsHeldAndTheDeviceUntouched(t *testing.T) {
	for name, tc := range map[string]struct {
		reboot  bool
		drifted bool
	}{
		"a window that reboots":      {reboot: true},
		"a packages-only window":     {reboot: false},
		"a pin changed from outside": {reboot: true, drifted: true},
	} {
		t.Run(name, func(t *testing.T) {
			r := enrolledRig(t)
			if tc.drifted {
				r.dev.do(func(d *simDevice) { d.flavour = "" })
			}
			flavour, record := r.dev.Flavour(), recordWithoutContact(r.state())

			out := r.runInTestMode(context.Background(), advancePayload(TrackFast, tc.reboot, approve575))

			res := wantResult(t, out, OutcomeHeld, ReasonHeldTestMode)
			wantVersions(t, res, "26.7.3_11", "26.7.3_11", "26.7.5", "26.7.3_11")
			if res.Drift {
				t.Error("a device in test mode reconciles nothing, so it reports no drift")
			}
			if calls := r.dev.Calls(); len(calls) != 0 {
				t.Errorf("calls %v: a device in test mode is asked for no probe, check, write or update", calls)
			}
			if after := r.state(); r.dev.Flavour() != flavour || after == nil || !reflect.DeepEqual(recordWithoutContact(after), record) {
				t.Errorf("the pin moved: flavour %q (was %q), record %+v (was %+v)", r.dev.Flavour(), flavour, after, &record)
			}
		})
	}
}

// recordWithoutContact is the record less the time of the last contact, which a
// signed task refreshes on any pinned device.
func recordWithoutContact(st *State) State {
	c := *st
	c.LastContact = 0
	return c
}

// The verdict is the agent's own, so a device it cannot read does not change it,
// and the result then names no release it did not read.
func TestAdvance_ATestModeAdvanceOnADeviceThatCannotBeReadIsStillHeldForTestMode(t *testing.T) {
	r := enrolledRig(t)
	r.dev.do(func(d *simDevice) { d.settingsErr = errSim })
	out := r.runInTestMode(context.Background(), advancePayload(TrackFast, true, approve575))
	res := wantResult(t, out, OutcomeHeld, ReasonHeldTestMode)
	wantVersions(t, res, "", "", "", "")
}

func TestAdvance_ATestModeAdvanceCutShortIsLeftAlone(t *testing.T) {
	r := enrolledRig(t)
	r.dev.do(func(d *simDevice) { d.settingsErr = errSim })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out := r.runInTestMode(ctx, advancePayload(TrackFast, true, approve575))
	if !out.Aborted || out.Result != nil || out.Failure != "" {
		t.Fatalf("outcome %+v: a task cut short is not answered", out)
	}
}

func TestTestMode_EnrollAndUnenrollStillRun(t *testing.T) {
	r := newRig(t)
	wantResult(t, r.runInTestMode(context.Background(), enrollPayload(TrackFast)), OutcomeSuccess, ReasonEnrolled)
	if st := r.state(); st == nil || !st.Pinned || r.dev.Flavour() != st.PinnedFlavour {
		t.Fatalf("record %+v, flavour %q: an enroll never updates or reboots, so it pins", r.state(), r.dev.Flavour())
	}
	wantResult(t, r.runInTestMode(context.Background(), unenrollPayload(TrackFast)), OutcomeSuccess, ReasonUnenrolled)
	if st := r.state(); st != nil || r.dev.Flavour() != "" {
		t.Errorf("record %+v, flavour %q: the original setting is back", st, r.dev.Flavour())
	}
}

func TestAdvance_ADeviceThatGainedASubscriptionIsHeldAndTheSettingUntouched(t *testing.T) {
	r := enrolledRig(t)
	r.dev.do(func(d *simDevice) { d.subscription = true })
	wantResult(t, r.run(advancePayload(TrackFast, true, approve575)), OutcomeHeld, ReasonHeldUnsupportedEdition)
	if len(r.dev.writes()) != 0 {
		t.Errorf("writes %v", r.dev.writes())
	}
}

// --- the pinned folder -----------------------------------------------------------

func TestAdvance_APinnedFolderThatVanishesHoldsOnceThenReleases(t *testing.T) {
	r := enrolledRig(t)
	clock := r.onClock()
	r.dev.do(func(d *simDevice) { delete(d.folders, "26.7.3") })

	res := wantResult(t, r.run(advancePayload(TrackFast, true, approve575)), OutcomeHeld, ReasonHeldReleaseFolderMissing)
	wantVersions(t, res, "26.7.3_11", "26.7.3_11", "26.7.5", "26.7.3_11")
	if st := r.state(); st.FolderMisses != 1 || !st.Pinned {
		t.Fatalf("record %+v", st)
	}
	if len(r.dev.writes()) != 0 {
		t.Errorf("a first miss writes nothing: %v", r.dev.writes())
	}

	// An answer of the mirror a few minutes after the first is the same observation:
	// it holds again and counts for nothing.
	clock.Advance(folderMissSpacing - time.Minute)
	wantResult(t, r.run(advancePayload(TrackFast, true, approve575)), OutcomeHeld, ReasonHeldReleaseFolderMissing)
	if st := r.state(); st.FolderMisses != 1 || !st.Pinned || r.dev.Flavour() == "" {
		t.Fatalf("a miss too close to the first released the device: record %+v, flavour %q", st, r.dev.Flavour())
	}

	// The second miss in a row, from another answer of the mirror, releases the
	// device: the original setting is back and the control plane is told, with the
	// one reason that goes with it.
	clock.Advance(2 * time.Minute)
	out := r.run(advancePayload(TrackFast, true, approve575))
	res = wantResult(t, out, OutcomeReleased, ReasonReleaseFolderUnavailable)
	if res.PinnedVersion != "" {
		t.Errorf("a released device names no pin: %q", res.PinnedVersion)
	}
	wantVersions(t, res, "26.7.3_11", "26.7.3_11", "26.7.5", "")
	if r.dev.Flavour() != "" {
		t.Errorf("flavour %q, want the original", r.dev.Flavour())
	}
	if st := r.state(); st != nil {
		t.Errorf("record survives a release: %+v", st)
	}
}

func TestAdvance_AFolderThatComesBackResetsTheCount(t *testing.T) {
	r := enrolledRig(t)
	r.dev.do(func(d *simDevice) { delete(d.folders, "26.7.3") })
	wantResult(t, r.run(advancePayload(TrackFast, true, approve575)), OutcomeHeld, ReasonHeldReleaseFolderMissing)

	r.dev.do(func(d *simDevice) {
		d.folders["26.7.3"] = simCatalog{core: "26.7.3_11", update: "26.7.3", pkgs: map[string]string{"curl": "8.21.0", "pkg": "2.3.1_1"}}
	})
	wantResult(t, r.run(advancePayload(TrackFast, true, map[string]string{"26.7": "26.7.3"})), OutcomeNoop, ReasonAtOrAboveTarget)
	if st := r.state(); st.FolderMisses != 0 || st.FolderMissAt != 0 {
		t.Errorf("miss count %d at %d", st.FolderMisses, st.FolderMissAt)
	}

	r.dev.do(func(d *simDevice) { delete(d.folders, "26.7.3") })
	r.eng.forgetProbes()
	wantResult(t, r.run(advancePayload(TrackFast, true, approve575)), OutcomeHeld, ReasonHeldReleaseFolderMissing) // a first miss again, not a release
}

// A 404 is not remembered: two misses are two answers of the mirror, never one
// answer served twice.
func TestAdvance_AMissingFolderIsAskedAboutEveryTime(t *testing.T) {
	r := enrolledRig(t)
	clock := r.onClock()
	r.dev.do(func(d *simDevice) { delete(d.folders, "26.7.3") })
	for i := 0; i < 2; i++ {
		wantResult(t, r.run(advancePayload(TrackFast, true, approve575)), OutcomeHeld, ReasonHeldReleaseFolderMissing)
		clock.Advance(time.Minute) // far less than the probe cache lives
	}
	pinned := 0
	for _, c := range r.dev.Calls() {
		if strings.HasPrefix(c, "probe") && strings.Contains(c, "/MINT/26.7.3/") {
			pinned++
		}
	}
	if pinned != 2 {
		t.Errorf("the mirror was asked about the pinned folder %d times in two tasks: %v", pinned, r.dev.Calls())
	}
}

// A release the record cannot follow is not reported: the control plane would
// drop the device while the agent's record still says it holds a pin.
func TestAdvance_AReleaseWhoseRecordCannotBeClearedIsNotReported(t *testing.T) {
	r := enrolledRig(t)
	clock := r.onClock()
	r.dev.do(func(d *simDevice) { delete(d.folders, "26.7.3") })
	wantResult(t, r.run(advancePayload(TrackFast, true, approve575)), OutcomeHeld, ReasonHeldReleaseFolderMissing)

	clock.Advance(folderMissSpacing + time.Minute)
	r.store.remove = func(string) error { return errSim }
	wantResult(t, r.run(advancePayload(TrackFast, true, approve575)), OutcomeHeld, ReasonHeldReleaseFolderMissing)
	if st := r.state(); st == nil || !st.Pinned {
		t.Fatalf("record %+v: the record still says the agent holds a pin, and the answer said so too", st)
	}

	// When the record can be cleared the release goes through.
	r.store.remove = os.Remove
	clock.Advance(folderMissSpacing + time.Minute)
	wantResult(t, r.run(advancePayload(TrackFast, true, approve575)), OutcomeReleased, ReasonReleaseFolderUnavailable)
	if r.state() != nil {
		t.Errorf("record %+v", r.state())
	}
}

func TestAdvance_AReleaseThatCannotRestoreTheSettingStaysPinned(t *testing.T) {
	r := enrolledRig(t)
	clock := r.onClock()
	r.dev.do(func(d *simDevice) { delete(d.folders, "26.7.3") })
	r.run(advancePayload(TrackFast, true, approve575))
	r.dev.do(func(d *simDevice) { d.setErr = errSim })
	clock.Advance(folderMissSpacing + time.Minute)
	wantResult(t, r.run(advancePayload(TrackFast, true, approve575)), OutcomeHeld, ReasonHeldReleaseFolderMissing)
	if r.dev.count("set") == 0 {
		t.Fatal("the release was not even attempted")
	}
	if r.dev.Flavour() != "26.7/MINT/26.7.3/latest" {
		t.Errorf("flavour %q: a device is not reported released while it is still pinned", r.dev.Flavour())
	}
	if st := r.state(); st == nil || !st.Pinned {
		t.Errorf("record %+v", st)
	}
}

// --- drift -----------------------------------------------------------------------

func TestAdvance_AResetFlavourIsPutBackAtTheInstalledReleaseAndFlagged(t *testing.T) {
	r := enrolledRig(t)
	r.dev.do(func(d *simDevice) { d.flavour = "" }) // "(default)" in the GUI

	out := r.run(advancePayload(TrackFast, true, map[string]string{"26.7": "26.7.3"}))
	res := wantResult(t, out, OutcomeNoop, ReasonPinDrift)
	if !res.Drift {
		t.Error("drift not flagged")
	}
	wantVersions(t, res, "26.7.3_11", "26.7.3_11", "26.7.3", "26.7.3_11")
	if r.dev.Flavour() != "26.7/MINT/26.7.3/latest" {
		t.Errorf("flavour %q", r.dev.Flavour())
	}
}

func TestAdvance_ADriftIsFlaggedOnAnAppliedUpdateToo(t *testing.T) {
	r := enrolledRig(t, onlyHotfixes, func(d *simDevice) {
		d.core = "26.7.3_8"
		d.pkgs["opnsense"] = "26.7.3_8"
		d.pkgs["curl"] = "8.20.0"
	})
	r.dev.do(func(d *simDevice) { d.flavour = "" })
	res := wantResult(t, r.run(advancePayload(TrackFast, true, map[string]string{"26.7": "26.7.3"})), OutcomeSuccess, ReasonApplied)
	if !res.Drift {
		t.Error("drift not flagged")
	}
}

func TestAdvance_AnInstalledReleaseBeyondThePinMovesThePinUpNeverDown(t *testing.T) {
	r := enrolledRig(t)
	// Updated outside NetDefense, with the flavour reset and restored by hand.
	r.dev.do(func(d *simDevice) {
		d.core, d.updatePkg, d.sets = "26.7.5", "26.7.4_1", "26.7.4"
		d.pkgs["opnsense"], d.pkgs["curl"], d.pkgs["pkg"] = "26.7.5", "8.22.0", "2.8.4_1"
	})
	out := r.run(advancePayload(TrackFast, true, map[string]string{"26.7": "26.7.3"}))
	res := wantResult(t, out, OutcomeNoop, ReasonPinDrift)
	wantVersions(t, res, "26.7.5", "26.7.5", "26.7.3", "26.7.5")
	if r.dev.Flavour() != "26.7/MINT/26.7.5/latest" {
		t.Errorf("flavour %q: the pin must follow the installed release up", r.dev.Flavour())
	}
	for _, w := range r.dev.writes() {
		if w == "" || w == "26.7/MINT/26.7.3/latest" {
			t.Errorf("a pin below the installed release was written: %v", r.dev.writes())
		}
	}
}

func TestAdvance_APinLeftAheadOfTheInstalledReleaseIsPulledBackWithoutADrift(t *testing.T) {
	r := enrolledRig(t)
	// An update that was requested and never happened left the setting at the target.
	r.dev.do(func(d *simDevice) { d.flavour = "26.7/MINT/26.7.5/latest" })
	_, _ = r.store.Update(func(s *State) { s.PinnedFlavour = "26.7/MINT/26.7.5/latest" })

	out := r.run(advancePayload(TrackFast, true, map[string]string{"26.7": "26.7.3"}))
	res := wantResult(t, out, OutcomeNoop, ReasonAtOrAboveTarget)
	if res.Drift {
		t.Error("a pin the agent left behind is not an outside change")
	}
	if r.dev.Flavour() != "26.7/MINT/26.7.3/latest" {
		t.Errorf("flavour %q", r.dev.Flavour())
	}
}

// afterAGUIMajor is a box a major upgrade was run on from the GUI: the release and
// the mirror's folders are the new series', and the firmware setting still holds
// the old series' pin, so the repository file OPNsense generates from it still
// names the old series.
func afterAGUIMajor(d *simDevice) {
	d.series = "27.1"
	d.core, d.updatePkg, d.sets = "27.1", "27.1", "27.1"
	d.pkgs["opnsense"] = "27.1"
	d.folders = map[string]simCatalog{"27.1": {core: "27.1", update: "27.1", pkgs: map[string]string{"curl": "8.21.0", "pkg": "2.8.4_1"}}}
	d.latest = d.folders["27.1"]
}

func TestAdvance_ASeriesChangedOutsideNetDefenseIsRePinnedOnTheNewSeries(t *testing.T) {
	r := enrolledRig(t)
	r.dev.do(afterAGUIMajor)
	if base, _ := r.dev.RepoBase(context.Background()); base.Series != "26.7" {
		t.Fatalf("the repository file names series %q: it should still be the pin's", base.Series)
	}
	out := r.run(advancePayload(TrackFast, true, approve575)) // no target for 27.1
	res := wantResult(t, out, OutcomeNoop, ReasonSeriesNotApproved)
	if !res.Drift {
		t.Error("drift not flagged")
	}
	if r.dev.Flavour() != "27.1/MINT/27.1/latest" {
		t.Errorf("flavour %q", r.dev.Flavour())
	}
}

func TestAdvance_APinThatCannotBeWrittenAgainBecauseItsFolderIsGoneCountsAsAMiss(t *testing.T) {
	r := enrolledRig(t)
	clock := r.onClock()
	r.dev.do(func(d *simDevice) {
		d.flavour = ""
		delete(d.folders, "26.7.3")
	})
	wantResult(t, r.run(advancePayload(TrackFast, true, approve575)), OutcomeHeld, ReasonHeldReleaseFolderMissing)
	if st := r.state(); st.FolderMisses != 1 {
		t.Errorf("record %+v", st)
	}
	clock.Advance(folderMissSpacing + time.Minute)
	wantResult(t, r.run(advancePayload(TrackFast, true, approve575)), OutcomeReleased, ReasonReleaseFolderUnavailable)
}

// --- an advance for a device the agent holds no pin on ---------------------------

func TestAdvance_AnAdvanceForAnUnpinnedDevicePinsItFirstAndFlagsIt(t *testing.T) {
	// Never enrolled: the record is gone. The directory holds a hotfix revision the
	// device lacks, so the advance has an update to make once the device is pinned.
	r := newRig(t, onlyHotfixes, func(d *simDevice) {
		d.core = "26.7.3_8"
		d.pkgs["opnsense"] = "26.7.3_8"
	})
	target := map[string]string{"26.7": "26.7.3"}
	out := r.run(advancePayload(TrackFast, true, target))
	res := wantResult(t, out, OutcomeSuccess, ReasonApplied)
	if !res.Drift {
		t.Error("an advance that had to pin the device first says so")
	}
	wantVersions(t, res, "26.7.3_8", "26.7.3_11", "26.7.3", "26.7.3_11")
	if got := r.dev.writes(); !equal(got, []string{"26.7/MINT/26.7.3/latest"}) {
		t.Errorf("writes %v", got)
	}
}

func TestAdvance_AnAdvanceForADeviceThatCannotBePinnedHolds(t *testing.T) {
	r := newRig(t, func(d *simDevice) { d.flavour = "25.7/MINT/25.7.11/latest" })
	wantResult(t, r.run(advancePayload(TrackFast, true, approve575)), OutcomeHeld, ReasonHeldCustomFlavour)
	if len(r.dev.writes()) != 0 {
		t.Errorf("writes %v", r.dev.writes())
	}
}

// OPNsense answers {"status":"error","log":""} while it restarts its own services
// in the first minute of a core update and again right after a boot, and its API
// does not answer at all while it reboots. None of that is the end of the run, and
// none is a failure: the run ends when OPNsense says so or its time is up.
func TestAdvance_AGapInOpnsensesProgressIsNotAFailure(t *testing.T) {
	r := enrolledRig(t, onlyHotfixes, func(d *simDevice) {
		d.core = "26.7.3_8"
		d.pkgs["opnsense"] = "26.7.3_8"
		d.progressGap = 3
		d.progressDown = 3
	})
	out := r.run(advancePayload(TrackFast, true, map[string]string{"26.7": "26.7.3"}))
	res := wantResult(t, out, OutcomeSuccess, ReasonApplied)
	wantVersions(t, res, "26.7.3_8", "26.7.3_11", "26.7.3", "26.7.3_11")
}

func TestAdvance_APackagesOnlyAdvanceWithOnlyTheSetsPendingIsANoop(t *testing.T) {
	r := enrolledRig(t)
	wantResult(t, r.run(advancePayload(TrackFast, false, approve575)), OutcomeSuccess, ReasonApplied)
	r.jobs, r.dev.calls = nil, nil

	out := r.run(advancePayload(TrackFast, false, approve575))
	wantResult(t, out, OutcomeNoop, ReasonAtOrAboveTarget)
	if r.dev.count("exec") != 0 || r.dev.count("update") != 0 {
		t.Errorf("calls %v: there is nothing a run without a reboot can install", r.dev.Calls())
	}
	if r.dev.sets != "26.7.3" {
		t.Errorf("sets %s: base and kernel wait for a window that reboots", r.dev.sets)
	}
	if got := r.dev.Flavour(); got != "26.7/MINT/26.7.5/latest" {
		t.Errorf("flavour %q: the pin stays at the installed release", got)
	}
}

func TestAdvance_ARebootingAdvanceFinishesWhatAPackagesOnlyRunDeferred(t *testing.T) {
	r := enrolledRig(t)
	wantResult(t, r.run(advancePayload(TrackFast, false, approve575)), OutcomeSuccess, ReasonApplied)
	r.jobs, r.dev.calls = nil, nil

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	initialBoot := r.dev.boot
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
	if out := r.runCtx(ctx, advancePayload(TrackFast, true, approve575)); !out.Aborted {
		t.Fatalf("a task cut short by the reboot must be left alone, got %+v", out)
	}
	if r.dev.count("update") != 1 {
		t.Errorf("calls %v: the window that reboots must request the update", r.dev.Calls())
	}

	back := r.newEngine()
	got, done := back.Resolve(context.Background(), r.jobs[len(r.jobs)-1], Row{TaskID: "101", StartedAt: time.Now()})
	if !done {
		t.Fatal("the update had ended and the row was not resolved")
	}
	res := wantResult(t, got, OutcomeSuccess, ReasonApplied)
	wantVersions(t, res, "26.7.5", "26.7.5", "26.7.5", "26.7.5")
	if want := StripHotfix(r.dev.updatePkg); r.dev.sets != want {
		t.Errorf("sets %s, want %s: the rebooting window installs base and kernel", r.dev.sets, want)
	}
}

// An unenroll that was left half done is finished by the reconcile, which forgets
// the record: the advance that found it has nothing to advance from.
func TestAdvance_AnUnenrollFinishedByTheReconcileLeavesNothingToAdvanceFrom(t *testing.T) {
	logs := captureLogs(t)
	r := enrolledRig(t)
	if _, err := r.store.Update(func(s *State) {
		s.Pending = &Pending{Op: ActionUnenroll, TaskID: "100", FromFlavour: s.PinnedFlavour, ToFlavour: "", StartedAt: time.Now().Unix()}
	}); err != nil {
		t.Fatal(err)
	}
	r.dev.do(func(d *simDevice) { d.setFailures = 1 }) // the first attempt to finish it fails, the second works

	out := r.run(advancePayload(TrackFast, true, approve575))

	wantResult(t, out, OutcomeHeld, ReasonHeldCheckFailed)
	if n := panics(logs); n != 0 {
		t.Fatalf("the engine panicked %d times", n)
	}
	if r.dev.Flavour() != "" || r.state() != nil {
		t.Errorf("flavour %q, record %+v: the unenroll should have been finished", r.dev.Flavour(), r.state())
	}
}

func TestEnroll_AnUnenrollFinishedByTheReconcileIsNotAnEnrollmentThatHolds(t *testing.T) {
	logs := captureLogs(t)
	r := enrolledRig(t)
	if _, err := r.store.Update(func(s *State) {
		s.Pending = &Pending{Op: ActionUnenroll, TaskID: "100", FromFlavour: s.PinnedFlavour, ToFlavour: "", StartedAt: time.Now().Unix()}
	}); err != nil {
		t.Fatal(err)
	}
	r.dev.do(func(d *simDevice) { d.setFailures = 1 })

	// The enroll finds a pin in force with an unenroll pending: it must not answer
	// "enrolled" for a device whose pin the reconcile just took off.
	out := r.run(enrollPayload(TrackFast))
	if res := out.Result; res != nil && res.Reason == ReasonEnrolled && res.Outcome == OutcomeNoop && r.dev.Flavour() == "" {
		t.Fatalf("answered %s for a device with no pin", out.Message)
	}
	if n := panics(logs); n != 0 {
		t.Fatalf("the engine panicked %d times", n)
	}
}

// A panic that reaches the top of a goroutine ends the agent, which daemon(8)
// starts again only after its restart delay. Whatever the engine hits, the task
// is answered and the rounds go on.
func TestEngine_APanicIsContainedAndAnswered(t *testing.T) {
	logs := captureLogs(t)
	r := enrolledRig(t)
	r.dev.do(func(d *simDevice) { d.panicSettings = true })

	out := r.run(advancePayload(TrackFast, true, approve575))
	wantResult(t, out, OutcomeHeld, ReasonHeldCheckFailed)
	if out := r.eng.Execute(context.Background(), Input{TaskID: "102", Payload: unenrollPayload(TrackFast)}); out.Failure == "" {
		t.Errorf("an unenroll that hit a bug is failed, so the control plane asks again: %+v", out)
	}
	r.eng.Tick(context.Background())
	if got, done := r.eng.Resolve(context.Background(), Job{Action: ActionUnenroll, Track: TrackFast, Phase: PhaseMoved,
		StartedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix()}, startedRow()); done {
		t.Errorf("a row the engine panicked on was resolved: %+v", got)
	}
	if n := panics(logs); n != 4 {
		t.Errorf("contained %d panics, want 4", n)
	}

	// And the engine works again once the bug is gone: the lock was released.
	r.dev.do(func(d *simDevice) { d.panicSettings = false })
	wantResult(t, r.run(advancePayload(TrackFast, true, map[string]string{"26.7": "26.7.3"})), OutcomeNoop, ReasonAtOrAboveTarget)
}

// --- the update request and the pin ----------------------------------------------

// A request that errors may have been heard all the same: a timeout or a reset
// after OPNsense accepted it. The update then runs on, and the pin must not be
// moved under it.
// atTheLastBase is a box whose base and kernel are already at what 26.7.5 ships,
// so that the update to 26.7.5 is the core package and the others, with no reboot.
func atTheLastBase(d *simDevice) {
	d.core, d.updatePkg, d.sets = "26.7.4_1", "26.7.4", "26.7.4"
	d.pkgs["opnsense"], d.pkgs["opnsense-update"] = "26.7.4_1", "26.7.4"
}

func TestAdvance_AnUpdateWhoseRequestErroredButStartedIsWatchedToItsEnd(t *testing.T) {
	r := enrolledRig(t, onlyHotfixes, atTheLastBase, func(d *simDevice) {
		d.updateErr, d.updateErrAfterStart = errSim, true
	})
	out := r.run(advancePayload(TrackFast, true, approve575))
	res := wantResult(t, out, OutcomeSuccess, ReasonApplied)
	wantVersions(t, res, "26.7.4_1", "26.7.5", "26.7.5", "26.7.5")
	if got := r.dev.writes(); !equal(got, []string{"26.7/MINT/26.7.5/latest"}) {
		t.Errorf("writes %v: the pin was moved under a running update", got)
	}
	if r.dev.count("update") != 1 {
		t.Errorf("the request was made %d times", r.dev.count("update"))
	}
}

// And one that errored and started nothing is a hold with the pin back.
func TestAdvance_AnUpdateWhoseRequestErroredAndStartedNothingIsHeldWithThePinBack(t *testing.T) {
	r := enrolledRig(t, func(d *simDevice) { d.updateErr = errSim })
	wantResult(t, r.run(advancePayload(TrackFast, true, approve575)), OutcomeHeld, ReasonHeldCheckFailed)
	if r.dev.Flavour() != "26.7/MINT/26.7.3/latest" {
		t.Errorf("flavour %q", r.dev.Flavour())
	}
	if st := r.state(); st.Pending != nil || !st.Pinned {
		t.Errorf("record %+v", st)
	}
}

// The connection dropping as the request is made must not cut the request in half:
// it is a local call that takes moments, and the update has to be the one the row
// says was requested.
func TestAdvance_ADroppedConnectionDoesNotCutTheRequestInHalf(t *testing.T) {
	r := enrolledRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.dev.do(func(d *simDevice) { d.cancelOnUpdate = cancel })

	out := r.runCtx(ctx, advancePayload(TrackFast, true, approve575))
	if !out.Aborted {
		t.Fatalf("a task whose connection dropped is left alone, got %+v", out)
	}
	if r.dev.count("update") != 1 {
		t.Fatalf("calls %v", r.dev.Calls())
	}
	r.dev.mu.Lock()
	updating := r.dev.updating
	r.dev.mu.Unlock()
	if !updating {
		t.Fatal("the request was cut off before OPNsense heard it, while the row says the update was requested")
	}
	if last := r.jobs[len(r.jobs)-1]; last.Phase != PhaseTriggered {
		t.Errorf("job %+v", last)
	}
	if r.dev.Flavour() != "26.7/MINT/26.7.5/latest" {
		t.Errorf("flavour %q: the pin is the running update's", r.dev.Flavour())
	}
}

// A cancelled task never starts an update.
func TestAdvance_ACancelledTaskDoesNotRequestAnUpdate(t *testing.T) {
	r := enrolledRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	r.dev.do(func(d *simDevice) { d.onSet = cancel }) // the connection drops once the pin is at the target
	out := r.runCtx(ctx, advancePayload(TrackFast, true, approve575))
	if !out.Aborted {
		t.Fatalf("got %+v", out)
	}
	if r.dev.count("update") != 0 {
		t.Errorf("an update was requested for a cancelled task: %v", r.dev.Calls())
	}
}

// runPastItsDeadline runs the task on simulated time with the eight minutes an
// advance needs (a task with less is held at once, as late dispatch) and lets the
// update go on until the task's time, and its grace, run out under it.
func (r *rig) runPastItsDeadline(p Payload) *Outcome {
	r.t.Helper()
	// The production waits, on a clock a wait moves: the watch crosses the task's
	// time in a few hundred polls and nothing sleeps.
	clock := r.simulateTime(WithTiming(DefaultTiming()))
	return r.runUntil(p, clock.Now().Add(advanceWork+time.Minute))
}

// The task's time runs out while OPNsense is still at the update: the pin is not
// moved under it, whatever the answer to the control plane is.
func TestAdvance_AnUpdateStillRunningAtTheDeadlineKeepsTheRepositoriesWhereTheyAre(t *testing.T) {
	r := enrolledRig(t, func(d *simDevice) { d.updateNeverEnds = true })
	out := r.runPastItsDeadline(advancePayload(TrackFast, true, approve575))
	r.checkOutcome(advancePayload(TrackFast, true, approve575), out)
	if out.Failure == "" || out.Detail.Target != "26.7.5" {
		t.Fatalf("want a failure that names the release, got %+v", out)
	}
	if got := r.dev.writes(); !equal(got, []string{"26.7/MINT/26.7.5/latest"}) {
		t.Fatalf("writes %v: the pin was pulled back under a running update", got)
	}
	if st := r.state(); st.Pending != nil || st.PinnedFlavour != "26.7/MINT/26.7.3/latest" {
		t.Fatalf("record %+v: the round that follows decides, from the installed release", st)
	}

	// The round leaves it alone while the box is busy...
	r.eng.Tick(context.Background())
	if len(r.dev.writes()) != 1 {
		t.Fatalf("writes %v: the round wrote under a running update", r.dev.writes())
	}
	// ...and puts the pin where the installed release says once it is idle: the
	// update never applied, so it comes back.
	r.dev.do(func(d *simDevice) { d.updating, d.updateNeverEnds = false, false })
	r.eng.Tick(context.Background())
	if r.dev.Flavour() != "26.7/MINT/26.7.3/latest" {
		t.Fatalf("flavour %q", r.dev.Flavour())
	}
}

func TestAdvance_AnUpdateThatFinishedWhileTheTaskWasFailedLeavesThePinWithTheInstalledRelease(t *testing.T) {
	r := enrolledRig(t, func(d *simDevice) { d.updateNeverEnds = true })
	out := r.runPastItsDeadline(advancePayload(TrackFast, true, approve575))
	if out.Failure == "" {
		t.Fatalf("got %+v", out)
	}
	r.dev.do(func(d *simDevice) { // OPNsense finishes after all
		d.updating, d.updateNeverEnds = false, false
		d.applyPending(true)
	})
	r.eng.Tick(context.Background())
	if r.dev.Flavour() != "26.7/MINT/26.7.5/latest" {
		t.Fatalf("flavour %q: the pin was moved back under a release that is installed", r.dev.Flavour())
	}
	if st := r.state(); st.PinnedVersion != "26.7.5" || st.Pending != nil {
		t.Errorf("record %+v", st)
	}
}

// --- the sets -------------------------------------------------------------------

// The core package is replaced first and base and kernel minutes later. A box that
// lost power in between restarts with the new core over the old sets: the version
// file calls it done, and the device would become evidence for the next track.
func TestAdvance_ABoxThatRestartedBeforeBaseAndKernelWereInstalledIsFailed(t *testing.T) {
	r := enrolledRig(t, func(d *simDevice) { d.powerCut = true })
	job := rebootedJob(t, r)

	back := r.newEngine()
	out, done := back.Resolve(context.Background(), job, startedRow())
	if !done || out.Failure == "" {
		t.Fatalf("want a failure, got done=%v %+v", done, out)
	}
	r.checkOutcome(advancePayload(TrackFast, true, approve575), out)
	if !strings.Contains(out.Failure, "base") || out.Detail.Target != "26.7.5" {
		t.Errorf("outcome %+v", out)
	}
	if r.dev.Core() != "26.7.5" || r.dev.sets != "26.7.3" {
		t.Fatalf("the box is not in the state under test: core %s, sets %s", r.dev.Core(), r.dev.sets)
	}
	// The pin follows the core package that is installed, never below it.
	if r.dev.Flavour() != "26.7/MINT/26.7.5/latest" {
		t.Errorf("flavour %q", r.dev.Flavour())
	}

	// The next window finishes it, and then the device is evidence.
	r.dev.do(func(d *simDevice) { d.powerCut = false })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	initialBoot := r.dev.boot
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
	if out := r.runCtx(ctx, advancePayload(TrackFast, true, approve575)); !out.Aborted {
		t.Fatalf("got %+v", out)
	}
	got, done := r.newEngine().Resolve(context.Background(), r.jobs[len(r.jobs)-1], startedRow())
	if !done {
		t.Fatal("not resolved")
	}
	wantResult(t, got, OutcomeSuccess, ReasonApplied)
	if r.dev.sets != "26.7.4" {
		t.Errorf("sets %s", r.dev.sets)
	}
}

// A run that does not reboot defers base and kernel by design, and a source that
// cannot be read is no reason to fail a run that otherwise ended well.
func TestAdvance_TheSetsAreOnlyHeldToTheirPlanWhenTheRunReboots(t *testing.T) {
	r := enrolledRig(t)
	wantResult(t, r.run(advancePayload(TrackFast, false, approve575)), OutcomeSuccess, ReasonApplied)
	if r.dev.sets != "26.7.3" {
		t.Fatalf("sets %s", r.dev.sets)
	}
}
