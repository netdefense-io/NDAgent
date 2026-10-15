package track

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/firmware"
)

// startedRow is the row of a task the engine ran as far as the job says.
func startedRow() Row { return Row{TaskID: "101", StartedAt: time.Now()} }

// The agent that comes back after the update's reboot decides the row from the
// device. These are the other ends of that decision.

func rebootedJob(t *testing.T, r *rig) Job {
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
	if out := r.runCtx(ctx, advancePayload(TrackFast, true, approve575)); !out.Aborted {
		t.Fatalf("the reboot should leave the task alone, got %+v", out)
	}
	return r.jobs[len(r.jobs)-1]
}

func TestResolve_AnUpdateStillRunningAfterTheAgentCameBackWaits(t *testing.T) {
	r := enrolledRig(t)
	job := rebootedJob(t, r)
	r.dev.do(func(d *simDevice) { d.updating = true }) // the box is still installing

	back := r.newEngine()
	if out, done := back.Resolve(context.Background(), job, startedRow()); done {
		t.Fatalf("resolved while OPNsense was busy: %+v", out)
	}
}

func TestResolve_AnUpdateThatFailedIsFailedAndThePinPulledBack(t *testing.T) {
	r := enrolledRig(t)
	job := rebootedJob(t, r)
	// The update failed before changing anything that stays: the device is as it was.
	r.dev.do(func(d *simDevice) {
		d.core, d.updatePkg, d.sets = "26.7.3_11", "26.7.3", "26.7.3"
		d.pkgs["opnsense"] = "26.7.3_11"
		d.boot = job.Upgrade.BootTime
		d.progressText = "Partial update failure detected\n***DONE***\n"
		d.updateFails = true
	})
	back := r.newEngine()
	out, done := back.Resolve(context.Background(), job, startedRow())
	if !done || out.Failure == "" {
		t.Fatalf("want a failure, got done=%v %+v", done, out)
	}
	r.checkOutcome(advancePayload(TrackFast, true, approve575), out)
	if out.Detail.Target != "26.7.5" || out.Detail.PinnedVersion != "26.7.3_11" {
		t.Errorf("detail %+v", out.Detail)
	}
	if r.dev.Flavour() != "26.7/MINT/26.7.3/latest" {
		t.Errorf("flavour %q: the pin must not stay ahead of the installed release", r.dev.Flavour())
	}
	if st := r.state(); st.Pending != nil || st.PinnedFlavour != "26.7/MINT/26.7.3/latest" {
		t.Errorf("record %+v", st)
	}
}

func TestResolve_AnEnrollmentThatDiedAfterTheWriteIsRolledBackAndHeld(t *testing.T) {
	r := newRig(t)
	pin := "26.7/MINT/26.7.3/latest"
	r.dev.do(func(d *simDevice) { d.flavour = pin })
	_ = r.store.Save(&State{Pending: &Pending{Op: ActionEnroll, TaskID: "101", ToFlavour: pin, StartedAt: time.Now().Unix()}})
	job := Job{Action: ActionEnroll, Track: TrackFast, Reboot: true, Phase: PhaseMoved, From: "26.7.3_11",
		StartedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(5 * time.Minute).Unix()}

	out, done := r.eng.Resolve(context.Background(), job, startedRow())
	if !done {
		t.Fatal("not resolved")
	}
	r.checkOutcome(enrollPayload(TrackFast), out)
	res := wantResult(t, out, OutcomeHeld, ReasonHeldCheckFailed)
	wantVersions(t, res, "26.7.3_11", "26.7.3_11", "", "")
	if r.dev.Flavour() != "" || r.state() != nil {
		t.Errorf("flavour %q, record %+v", r.dev.Flavour(), r.state())
	}
}

// An enrollment that had completed and only lost its answer is answered as what
// it was: the device is pinned.
func TestResolve_AnEnrollmentThatHadCompletedIsAnsweredAsEnrolled(t *testing.T) {
	r := newRig(t)
	wantResult(t, r.run(enrollPayload(TrackFast)), OutcomeSuccess, ReasonEnrolled)
	job := r.jobs[len(r.jobs)-1] // the record the task left: phase moved

	out, done := r.eng.Resolve(context.Background(), job, startedRow())
	if !done {
		t.Fatal("not resolved")
	}
	res := wantResult(t, out, OutcomeNoop, ReasonEnrolled)
	wantVersions(t, res, "26.7.3_11", "26.7.3_11", "", "26.7.3_11")
	if r.dev.Flavour() != "26.7/MINT/26.7.3/latest" {
		t.Errorf("flavour %q: a completed enrollment must keep its pin", r.dev.Flavour())
	}
}

func TestResolve_AnUnenrollThatDiedIsFinishedAndAnsweredAsSuch(t *testing.T) {
	r := enrolledRig(t)
	if _, err := r.store.Update(func(s *State) {
		s.Pending = &Pending{Op: ActionUnenroll, TaskID: "101", FromFlavour: s.PinnedFlavour, ToFlavour: "", StartedAt: time.Now().Unix()}
	}); err != nil {
		t.Fatal(err)
	}
	job := Job{Action: ActionUnenroll, Track: TrackFast, Reboot: true, Phase: PhaseMoved, From: "26.7.3_11",
		StartedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(5 * time.Minute).Unix()}
	out, done := r.eng.Resolve(context.Background(), job, startedRow())
	if !done {
		t.Fatal("not resolved")
	}
	wantResult(t, out, OutcomeSuccess, ReasonUnenrolled)
	if r.dev.Flavour() != "" || r.state() != nil {
		t.Errorf("flavour %q, record %+v", r.dev.Flavour(), r.state())
	}
}

func TestResolve_AnAdvanceThatDiedBeforeTheRequestIsHeldWithThePinBack(t *testing.T) {
	r := enrolledRig(t)
	prev, next := "26.7/MINT/26.7.3/latest", "26.7/MINT/26.7.5/latest"
	r.dev.do(func(d *simDevice) { d.flavour = next })
	_, _ = r.store.Update(func(s *State) {
		s.Pending = &Pending{Op: ActionAdvance, TaskID: "101", FromFlavour: prev, ToFlavour: next, StartedAt: time.Now().Unix()}
	})
	job := Job{Action: ActionAdvance, Track: TrackFast, Approved: approve575, Reboot: true, Phase: PhaseMoved,
		From: "26.7.3_11", Target: "26.7.5", PrevFlavour: prev, NewFlavour: next,
		StartedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(20 * time.Minute).Unix()}
	out, done := r.eng.Resolve(context.Background(), job, startedRow())
	if !done {
		t.Fatal("not resolved")
	}
	r.checkOutcome(advancePayload(TrackFast, true, approve575), out)
	res := wantResult(t, out, OutcomeHeld, ReasonHeldCheckFailed)
	wantVersions(t, res, "26.7.3_11", "26.7.3_11", "26.7.5", "26.7.3_11")
	if r.dev.Flavour() != prev {
		t.Errorf("flavour %q", r.dev.Flavour())
	}
}

// A row nothing can be read for is kept until its time is up, and then failed:
// an unenroll must not be told apart from a success on a guess.
func TestResolve_AnUnreadableDeviceKeepsTheRowUntilItsTimeIsUp(t *testing.T) {
	r := enrolledRig(t)
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	r.eng = r.newEngine(WithClock(func() time.Time { return now }))
	r.dev.do(func(d *simDevice) { d.settingsErr = errSim })
	job := Job{Action: ActionUnenroll, Track: TrackFast, Reboot: true, Phase: PhaseMoved,
		StartedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix()}

	if out, done := r.eng.Resolve(context.Background(), job, Row{TaskID: "101", StartedAt: now}); done {
		t.Fatalf("resolved on a guess: %+v", out)
	}
	now = now.Add(11 * time.Minute) // past the expiry and its grace
	out, done := r.eng.Resolve(context.Background(), job, Row{TaskID: "101", StartedAt: now})
	if !done || out.Failure == "" {
		t.Fatalf("want a failure, got done=%v %+v", done, out)
	}
}

func TestResolve_SkipsWhileATaskRunsOrTheSlotIsHeld(t *testing.T) {
	r := enrolledRig(t)
	job := Job{Action: ActionUnenroll, Track: TrackFast, Phase: PhaseStarted,
		StartedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(5 * time.Minute).Unix()}
	r.eng.mu.Lock()
	if _, done := r.eng.Resolve(context.Background(), job, startedRow()); done {
		t.Error("resolved while a task held the engine")
	}
	r.eng.mu.Unlock()
}

// An advance that never asked OPNsense for anything is held when its time is up,
// not failed: a failed advance counts against the release it was moving to for
// the whole organization, and this one never touched the device.
func TestResolve_AnAdvanceThatNeverReachedTheDeviceIsHeldWhenItsTimeIsUp(t *testing.T) {
	for _, phase := range []string{PhaseStarted, PhaseMoved} {
		t.Run(phase, func(t *testing.T) {
			r := enrolledRig(t)
			now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
			r.eng = r.newEngine(WithClock(func() time.Time { return now }))
			r.dev.do(func(d *simDevice) { d.settingsErr = errSim })
			job := Job{Action: ActionAdvance, Track: TrackFast, Approved: approve575, Reboot: true, Phase: phase,
				From: "26.7.3_11", Target: "26.7.5", StartedAt: now.Unix(), ExpiresAt: now.Add(20 * time.Minute).Unix()}

			if out, done := r.eng.Resolve(context.Background(), job, Row{TaskID: "101", StartedAt: now}); done {
				t.Fatalf("resolved on a guess: %+v", out)
			}
			now = now.Add(26 * time.Minute) // past the expiry and its grace
			out, done := r.eng.Resolve(context.Background(), job, Row{TaskID: "101", StartedAt: now})
			if !done {
				t.Fatal("not resolved when its time was up")
			}
			r.checkOutcome(advancePayload(TrackFast, true, approve575), out)
			wantResult(t, out, OutcomeHeld, ReasonHeldCheckFailed)
			if !out.Detail.Empty() {
				t.Errorf("a hold names no failure: %+v", out.Detail)
			}
		})
	}
}

// An enroll is asked again at once when it fails, so it still fails.
func TestResolve_AnEnrollThatCouldNotBeSettledIsFailedWhenItsTimeIsUp(t *testing.T) {
	r := newRig(t)
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	r.eng = r.newEngine(WithClock(func() time.Time { return now }))
	r.dev.do(func(d *simDevice) { d.settingsErr = errSim })
	job := Job{Action: ActionEnroll, Track: TrackFast, Reboot: true, Phase: PhaseMoved,
		StartedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix()}
	now = now.Add(11 * time.Minute)
	out, done := r.eng.Resolve(context.Background(), job, Row{TaskID: "101", StartedAt: now})
	if !done || out.Failure == "" {
		t.Fatalf("want a failure, got done=%v %+v", done, out)
	}
}

// A record nothing can read must not keep a row for ever: the reconciler holds
// every other firmware job out while a row waits.
func TestResolve_AnUnreadableRecordDoesNotKeepARowForEver(t *testing.T) {
	for name, job := range map[string]Job{
		"an unenroll": {Action: ActionUnenroll, Track: TrackFast, Reboot: true, Phase: PhaseMoved},
		"an advance":  {Action: ActionAdvance, Track: TrackFast, Approved: approve575, Reboot: true, Phase: PhaseMoved, From: "26.7.3_11", Target: "26.7.5"},
	} {
		t.Run(name, func(t *testing.T) {
			r := enrolledRig(t)
			now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
			r.eng = r.newEngine(WithClock(func() time.Time { return now }))
			if err := os.WriteFile(r.store.Path(), []byte("{this is not the record"), 0o600); err != nil {
				t.Fatal(err)
			}
			job.StartedAt, job.ExpiresAt = now.Unix(), now.Add(20*time.Minute).Unix()

			if out, done := r.eng.Resolve(context.Background(), job, Row{TaskID: "101", StartedAt: now}); done {
				t.Fatalf("resolved on a record it cannot read: %+v", out)
			}
			now = now.Add(26 * time.Minute)
			out, done := r.eng.Resolve(context.Background(), job, Row{TaskID: "101", StartedAt: now})
			if !done {
				t.Fatal("a row whose record cannot be read was kept past its time")
			}
			if job.Action == ActionUnenroll && out.Failure == "" {
				t.Errorf("an unenroll that could not be settled is failed: %+v", out)
			}
			if job.Action == ActionAdvance && out.Result == nil {
				t.Errorf("an advance that requested no update is held: %+v", out)
			}
		})
	}
}

// --- a request that was recorded and never made ------------------------------------

// requestedJob is the record of an advance whose update was marked requested, on a
// box that has not restarted since: the pin is at the target and the progress log
// is whatever the test leaves in it.
func requestedJob(t *testing.T, r *rig) Job {
	t.Helper()
	prev, next := "26.7/MINT/26.7.3/latest", "26.7/MINT/26.7.5/latest"
	now := time.Now()
	r.dev.do(func(d *simDevice) { d.flavour = next })
	if _, err := r.store.Update(func(s *State) {
		s.Pending = &Pending{Op: ActionAdvance, TaskID: "101", FromFlavour: prev, ToFlavour: next, Triggered: true, StartedAt: now.Unix()}
	}); err != nil {
		t.Fatal(err)
	}
	meta := firmware.Meta{
		Mode: "minor", Reboot: true, FromVersion: "26.7.3_11", BootTime: r.dev.boot,
		StartedAt: now.Unix(), ExpiresAt: now.Add(20 * time.Minute).Unix(), TriggeredAt: now.Unix(),
		Packages: []firmware.Package{{Name: "opnsense", Version: "26.7.5"}, {Name: "base", Version: "26.7.4"}, {Name: "kernel", Version: "26.7.4"}},
	}
	return Job{
		Action: ActionAdvance, Track: TrackFast, Approved: approve575, Reboot: true, Phase: PhaseTriggered,
		From: "26.7.3_11", Target: "26.7.5", PrevFlavour: prev, NewFlavour: next,
		StartedAt: now.Unix(), ExpiresAt: now.Add(20 * time.Minute).Unix(), Upgrade: &meta,
	}
}

// The record of the request is written before the request, so that an update that
// ran is never taken for one that did not. When the agent stops in between, the
// device tells them apart: nothing was requested, so the answer is a hold and the
// pin comes back at once, not a FAILED that names the release after 25 minutes.
func TestResolve_AnUpdateThatWasRecordedAndNeverRequestedIsHeldAndThePinComesBack(t *testing.T) {
	r := enrolledRig(t)
	job := requestedJob(t, r)

	out, done := r.newEngine().Resolve(context.Background(), job, startedRow())
	if !done {
		t.Fatal("a request that never reached OPNsense was left waiting for the task's time to run out")
	}
	r.checkOutcome(advancePayload(TrackFast, true, approve575), out)
	res := wantResult(t, out, OutcomeHeld, ReasonHeldCheckFailed)
	wantVersions(t, res, "26.7.3_11", "26.7.3_11", "26.7.5", "26.7.3_11")
	if r.dev.Flavour() != job.PrevFlavour {
		t.Errorf("flavour %q: the pin should be back where it was", r.dev.Flavour())
	}
	if st := r.state(); st.Pending != nil || st.PinnedFlavour != job.PrevFlavour {
		t.Errorf("record %+v", st)
	}
}

func TestResolve_ARequestOPNsenseMayHaveRunIsJudgedTheUsualWay(t *testing.T) {
	for name, tc := range map[string]struct {
		tweak func(*simDevice)
		done  bool
	}{
		// An update request is in the log: this run's, or an earlier one's.
		"the log holds an update request": {func(d *simDevice) { d.progressText = "***GOT REQUEST TO UPDATE***\nCurrently running OPNsense\n" }, false},
		// OPNsense is at something.
		"a job is running": {func(d *simDevice) { d.updating = true }, false},
		// The box restarted: the log is gone with /tmp, and the release did not move.
		"the box restarted": {func(d *simDevice) { d.boot += 600 }, true},
	} {
		t.Run(name, func(t *testing.T) {
			r := enrolledRig(t)
			job := requestedJob(t, r)
			r.dev.do(tc.tweak)

			out, done := r.newEngine().Resolve(context.Background(), job, startedRow())
			if done != tc.done {
				t.Fatalf("done=%v, want %v: %+v", done, tc.done, out)
			}
			if done && out.Result != nil {
				t.Errorf("a run OPNsense may have made was taken for one it never got: %+v", out)
			}
			if r.dev.Flavour() != job.NewFlavour && !done {
				t.Errorf("flavour %q: the pin was moved while the run may be going", r.dev.Flavour())
			}
		})
	}
}

// A run without the launcher (reboot=false) leaves no request in any log, so
// silence proves nothing.
func TestResolve_APackagesOnlyRunIsNeverTakenForOneThatWasNotRequested(t *testing.T) {
	r := enrolledRig(t)
	job := requestedJob(t, r)
	job.Reboot = false
	job.Upgrade.Reboot = false
	out, done := r.newEngine().Resolve(context.Background(), job, startedRow())
	if done && out.Result != nil && out.Result.Outcome == OutcomeHeld {
		t.Fatalf("held on the strength of a log a packages-only run never writes: %+v", out)
	}
}
