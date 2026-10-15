package track

import (
	"context"
	"os"
	"testing"
	"time"
)

// OPNsense's web GUI and configd come up after the agent does, so a task can
// arrive before the firmware API answers; and after the update's reboot the same
// API can still be settling when the engine records the result. Neither is a
// verdict on the device: the first must not be a hold (an advance costs a window)
// or a failure (an unenroll), and the second must never turn an update the device
// reported complete into a FAILED that names the release.
//
// The rigs here run on simulated time (rig.simulateTime): a wait moves a clock
// instead of sleeping, so how many polls a wait makes is the same on every
// machine, and nothing is decided by how long the test happens to take.

const waitingForTheAPI = "Waiting for OPNsense's firmware API..."

func (d *simDevice) reads() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.settingsReads
}

func (d *simDevice) releaseReads() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.installedReads
}

// waitingMessages is how often the task told the control plane it was waiting.
func (r *rig) waitingMessages() int {
	n := 0
	for _, m := range r.msgs {
		if m == waitingForTheAPI {
			n++
		}
	}
	return n
}

// --- before the task: the API is not up yet -----------------------------------------

func TestEnroll_AnAPIThatIsNotUpYetIsWaitedFor(t *testing.T) {
	r := newRig(t)
	r.simulateTime()
	r.dev.do(func(d *simDevice) { d.settingsFailures = 3 })
	res := wantResult(t, r.run(enrollPayload(TrackFast)), OutcomeSuccess, ReasonEnrolled)
	wantVersions(t, res, "26.7.3_11", "26.7.3_11", "", "26.7.3_11")
	if r.dev.Flavour() != pinAt573 {
		t.Errorf("flavour %q", r.dev.Flavour())
	}
	if n := r.waitingMessages(); n != 1 || r.msgs[0] != waitingForTheAPI {
		t.Errorf("progress messages %v: the control plane should be told once, first, that the task is waiting", r.msgs)
	}
}

func TestAdvance_AnAPIThatIsNotUpYetIsWaitedFor(t *testing.T) {
	r := enrolledRig(t)
	r.simulateTime()
	r.dev.do(func(d *simDevice) { d.settingsFailures = 3 })
	wantResult(t, r.run(advancePayload(TrackFast, true, approve573)), OutcomeNoop, ReasonAtOrAboveTarget)
}

func TestUnenroll_AnAPIThatIsNotUpYetIsWaitedFor(t *testing.T) {
	r := enrolledRig(t)
	r.simulateTime()
	r.dev.do(func(d *simDevice) { d.settingsFailures = 3 })
	wantResult(t, r.run(unenrollPayload(TrackFast)), OutcomeSuccess, ReasonUnenrolled)
	if r.dev.Flavour() != "" || r.state() != nil {
		t.Errorf("flavour %q, record %+v", r.dev.Flavour(), r.state())
	}
}

// The version file is read after the settings, and is waited for just the same.
func TestInstalledReleaseThatIsNotReadableYetIsWaitedForToo(t *testing.T) {
	r := newRig(t)
	r.simulateTime()
	r.dev.do(func(d *simDevice) { d.settingsFailures, d.installedFailures = 3, 3 })
	wantResult(t, r.run(enrollPayload(TrackFast)), OutcomeSuccess, ReasonEnrolled)
}

// The wait is bounded, and what is still unreadable at its end is met as it always
// was: a hold for an enroll and an advance, a failure for an unenroll.
func TestAnAPIThatNeverComesUpIsMetAsEverAfterTheWait(t *testing.T) {
	timing := fastTiming()
	// The wait is a read, then a poll and a read for as long as it lasts; the task
	// makes the read of its own that fails it.
	wantReads := 1 + int(timing.APIWait/timing.Poll) + 1

	for name, tc := range map[string]struct {
		payload Payload
		held    bool
	}{
		"an enroll":   {enrollPayload(TrackFast), true},
		"an advance":  {advancePayload(TrackFast, true, approve573), true},
		"an unenroll": {unenrollPayload(TrackFast), false},
	} {
		t.Run(name, func(t *testing.T) {
			r := enrolledRig(t)
			clock := r.simulateTime()
			r.dev.do(func(d *simDevice) { d.settingsErr = errSim })

			before, start := r.dev.reads(), clock.Now()
			out := r.run(tc.payload)
			if tc.held {
				wantResult(t, out, OutcomeHeld, ReasonHeldCheckFailed)
			} else if out.Failure == "" {
				t.Errorf("want a failure, got %+v", out)
			}
			if n := r.dev.reads() - before; n != wantReads {
				t.Errorf("the settings were read %d times, want %d: the whole of the wait, and not for ever", n, wantReads)
			}
			if waited := clock.Now().Sub(start); waited != timing.APIWait {
				t.Errorf("the task waited %v, want APIWait (%v)", waited, timing.APIWait)
			}
		})
	}
}

// The wait never goes into the time the task needs for its work: a task that is
// short of it reads once and holds, as it did.
func TestTheWaitForTheAPIStaysInsideTheTasksTime(t *testing.T) {
	for name, tc := range map[string]struct {
		payload Payload
		left    time.Duration
	}{
		"an enroll with less than a minute left": {enrollPayload(TrackFast), 30 * time.Second},
		// Exactly the time an advance needs: the signed expiry holds its work (a task
		// with less is held at once, see TestAdvance_LateDispatch...), so no wait is
		// left over for the API.
		"an advance with just the eight minutes it needs": {advancePayload(TrackFast, true, approve573), advanceWork},
	} {
		t.Run(name, func(t *testing.T) {
			r := enrolledRig(t)
			clock := r.simulateTime()
			r.dev.do(func(d *simDevice) { d.settingsFailures = 3 })
			before := r.dev.reads()
			out := r.runUntil(tc.payload, clock.Now().Add(tc.left))
			wantResult(t, out, OutcomeHeld, ReasonHeldCheckFailed)
			if n := r.dev.reads() - before; n != 1 {
				t.Errorf("the settings were read %d times, want 1", n)
			}
		})
	}

	// And with the time there, the same failures are waited out.
	t.Run("an advance with the time it needs", func(t *testing.T) {
		r := enrolledRig(t)
		clock := r.simulateTime()
		r.dev.do(func(d *simDevice) { d.settingsFailures = 3 })
		out := r.runUntil(advancePayload(TrackFast, true, approve573), clock.Now().Add(advanceWork+time.Minute))
		wantResult(t, out, OutcomeNoop, ReasonAtOrAboveTarget)
	})
}

// A task that is cut short while it waits is left alone, and the wait ends with it.
// Only the cut can end this wait.
func TestAnAPIWaitCutShortLeavesTheTaskAlone(t *testing.T) {
	for name, failures := range map[string]int{
		"an API that stays down":                      1_000_000,
		"an API that answers from the very next read": 2,
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			clock := &fakeClock{t: time.Now()}
			ctx, cut := context.WithCancel(context.Background())
			defer cut()
			timing := fastTiming()
			timing.APIWait = time.Hour
			sleeps := 0
			r.eng = r.newEngine(WithClock(clock.Now), WithTiming(timing), WithSleep(func(ctx context.Context, d time.Duration) error {
				if sleeps++; sleeps == 2 {
					cut()
				}
				return clock.Sleep(ctx, d)
			}))
			r.dev.do(func(d *simDevice) { d.settingsFailures = failures })

			out := r.eng.Execute(ctx, Input{TaskID: "101", Payload: enrollPayload(TrackFast), Started: clock.Now()})
			if !out.Aborted {
				t.Fatalf("got %+v", out)
			}
			if n := r.dev.reads(); n != 2 {
				t.Errorf("the settings were read %d times, want 2: the wait ended with the cut", n)
			}
			if calls := r.dev.Calls(); len(calls) != 0 {
				t.Errorf("a task whose context ended touched the device: %v", calls)
			}
		})
	}
}

// Test mode answers an advance without reading the device, so an advance waits for
// nothing there. An enroll and an unenroll run in test mode, and wait like any
// other task.
func TestAdvance_ATestModeAdvanceDoesNotWaitForTheAPI(t *testing.T) {
	r := enrolledRig(t)
	clock := r.simulateTime()
	r.dev.do(func(d *simDevice) { d.settingsErr = errSim })
	before, start := r.dev.reads(), clock.Now()
	wantResult(t, r.runInTestMode(context.Background(), advancePayload(TrackFast, true, approve575)), OutcomeHeld, ReasonHeldTestMode)
	if n := r.dev.reads() - before; n != 1 {
		t.Errorf("the settings were read %d times, want 1", n)
	}
	if waited := clock.Now().Sub(start); waited != 0 {
		t.Errorf("the task waited %v", waited)
	}
}

func TestEnrollAndUnenrollInTestModeWaitForTheAPIAsAnyTaskDoes(t *testing.T) {
	r := newRig(t)
	r.simulateTime()
	r.dev.do(func(d *simDevice) { d.settingsFailures = 3 })
	wantResult(t, r.runInTestMode(context.Background(), enrollPayload(TrackFast)), OutcomeSuccess, ReasonEnrolled)

	r.dev.do(func(d *simDevice) { d.settingsFailures = 3 })
	wantResult(t, r.runInTestMode(context.Background(), unenrollPayload(TrackFast)), OutcomeSuccess, ReasonUnenrolled)
}

// --- the wait itself ----------------------------------------------------------------

// A wait is counted in polls as well as by the clock. A clock that never moves
// (a test holds it still, or the wall clock was stepped back) cannot make it last
// for ever; a clock that jumps cannot make it last longer than its time.
func TestRetryFor_IsBoundedByItsPollsAndByTheClock(t *testing.T) {
	timing := Timing{Poll: time.Second}
	failing := func(reads *int, stop context.CancelFunc) func() error {
		return func() error {
			if *reads++; *reads > 1000 {
				stop() // a wait with no bound at all is cut here, and fails the count below
			}
			return errSim
		}
	}

	t.Run("a clock that never moves", func(t *testing.T) {
		r := newRig(t)
		eng := r.newEngine(WithClock(func() time.Time { return time.Unix(1_800_000_000, 0) }), WithTiming(timing),
			WithSleep(func(ctx context.Context, _ time.Duration) error { return ctx.Err() }))
		ctx, stop := context.WithCancel(context.Background())
		defer stop()
		reads := 0
		if err := eng.retryFor(ctx, 10*time.Second, failing(&reads, stop), nil); err != errSim {
			t.Errorf("error %v", err)
		}
		if reads != 11 {
			t.Errorf("%d reads, want 11: the first and one for each second of the wait", reads)
		}
	})

	t.Run("a clock that jumps", func(t *testing.T) {
		r := newRig(t)
		clock := &fakeClock{t: time.Unix(1_800_000_000, 0)}
		eng := r.newEngine(WithClock(clock.Now), WithTiming(timing),
			WithSleep(func(ctx context.Context, _ time.Duration) error { clock.Advance(5 * time.Second); return ctx.Err() }))
		ctx, stop := context.WithCancel(context.Background())
		defer stop()
		reads := 0
		_ = eng.retryFor(ctx, 10*time.Second, failing(&reads, stop), nil)
		if reads != 3 {
			t.Errorf("%d reads, want 3: the clock ran out of the 10 seconds after two waits of 5", reads)
		}
	})

	t.Run("no wait is one read", func(t *testing.T) {
		r := newRig(t)
		eng := r.newEngine(WithTiming(timing))
		reads := 0
		_ = eng.retryFor(context.Background(), 0, failing(&reads, func() {}), nil)
		if reads != 1 {
			t.Errorf("%d reads, want 1", reads)
		}
	})

	t.Run("no poll interval is one read", func(t *testing.T) {
		r := newRig(t)
		eng := r.newEngine(WithTiming(Timing{}))
		reads := 0
		_ = eng.retryFor(context.Background(), time.Minute, failing(&reads, func() {}), nil)
		if reads != 1 {
			t.Errorf("%d reads, want 1: a wait with no interval to count in is not a wait", reads)
		}
	})

	t.Run("a wait that is cut short ends at once", func(t *testing.T) {
		r := newRig(t)
		eng := r.newEngine(WithTiming(timing), WithSleep(func(ctx context.Context, _ time.Duration) error { return ctx.Err() }))
		ctx, stop := context.WithCancel(context.Background())
		defer stop()
		reads := 0
		_ = eng.retryFor(ctx, time.Minute, func() error {
			if reads++; reads == 3 {
				stop()
			}
			return errSim
		}, nil)
		if reads != 3 {
			t.Errorf("%d reads, want 3: the wait ended with the context", reads)
		}
	})

	t.Run("the first error is told once and a read that works ends it", func(t *testing.T) {
		r := newRig(t)
		clock := &fakeClock{t: time.Now()}
		eng := r.newEngine(WithClock(clock.Now), WithSleep(clock.Sleep), WithTiming(timing))
		reads, told := 0, 0
		err := eng.retryFor(context.Background(), time.Minute, func() error {
			if reads++; reads < 4 {
				return errSim
			}
			return nil
		}, func(error) { told++ })
		if err != nil || reads != 4 || told != 1 {
			t.Errorf("err %v after %d reads, told %d times; want nil after 4, told once", err, reads, told)
		}
	})
}

// The documented wait for an API that is not up yet.
func TestDefaultTimingWaitsTwoMinutesForTheAPI(t *testing.T) {
	if got := DefaultTiming().APIWait; got != 2*time.Minute {
		t.Errorf("APIWait = %v, want 2m0s", got)
	}
	if enrollWork != time.Minute || advanceWork != 8*time.Minute {
		t.Errorf("a task needs %v (enroll) and %v (advance) once the API answers, want 1m0s and 8m0s", enrollWork, advanceWork)
	}
}

// --- after the update: the API is settling -------------------------------------------

func TestAdvance_AnAPIStillSettlingAfterTheUpdateDoesNotFailIt(t *testing.T) {
	r := enrolledRig(t, aHotfixWindow, func(d *simDevice) { d.settingsFailuresAfterRun = 3 })
	r.simulateTime()
	out := r.run(advancePayload(TrackFast, true, approve573))

	res := wantResult(t, out, OutcomeSuccess, ReasonApplied)
	wantVersions(t, res, "26.7.3_8", "26.7.3_11", "26.7.3", "26.7.3_11")
	if res.Drift {
		t.Error("a setting that could not be read for a moment is no drift")
	}
	if got := r.dev.writes(); len(got) != 0 {
		t.Errorf("writes %v", got)
	}
	if st := r.state(); !st.Pinned || st.PinnedFlavour != pinAt573 || st.PinnedVersion != "26.7.3_11" || st.Pending != nil {
		t.Errorf("record %+v", st)
	}
}

// A setting that cannot be read for a moment is read again, not skipped: the pin
// it shows is still checked, and put right when something moved it.
func TestAdvance_AnAPIStillSettlingAfterTheUpdateStillChecksThePin(t *testing.T) {
	r := enrolledRig(t, aHotfixWindow, func(d *simDevice) {
		d.settingsFailuresAfterRun = 3
		d.onRun = func(d *simDevice) { d.flavour = "" } // reset in the GUI while the update ran
	})
	r.simulateTime()
	out := r.run(advancePayload(TrackFast, true, approve573))

	res := wantResult(t, out, OutcomeSuccess, ReasonApplied)
	wantVersions(t, res, "26.7.3_8", "26.7.3_11", "26.7.3", "26.7.3_11")
	if !res.Drift {
		t.Error("the pin was reset meanwhile and the result should say so")
	}
	if r.dev.Flavour() != pinAt573 {
		t.Errorf("flavour %q: the pin should be written again at the installed release", r.dev.Flavour())
	}
}

// The release is read again too: a version file that cannot be read for a moment
// after the reboot is not a reason to leave the answer to the next sweep.
func TestAdvance_AReleaseThatCannotBeReadForAMomentAfterTheUpdateIsReadAgain(t *testing.T) {
	r := enrolledRig(t, aHotfixWindow, func(d *simDevice) { d.installedFailuresAfterRun = 3 })
	r.simulateTime()
	out := r.run(advancePayload(TrackFast, true, approve573))

	res := wantResult(t, out, OutcomeSuccess, ReasonApplied)
	wantVersions(t, res, "26.7.3_8", "26.7.3_11", "26.7.3", "26.7.3_11")
	if st := r.state(); !st.Pinned || st.PinnedVersion != "26.7.3_11" || st.Pending != nil {
		t.Errorf("record %+v", st)
	}
}

// ... and so is the agent's own record.
func TestAdvance_ARecordThatCannotBeReadForAMomentAfterTheUpdateIsReadAgain(t *testing.T) {
	r := enrolledRig(t, aHotfixWindow)
	clock := &fakeClock{t: time.Now()}
	var saved []byte
	broken, sleepsSince := false, 0
	r.eng = r.newEngine(WithClock(clock.Now), WithSleep(func(ctx context.Context, d time.Duration) error {
		if broken {
			if sleepsSince++; sleepsSince == 2 { // it reads again on the third try
				_ = os.WriteFile(r.store.Path(), saved, 0o600)
			}
		}
		return clock.Sleep(ctx, d)
	}))
	r.clock = clock
	r.dev.do(func(d *simDevice) {
		d.onRun = func(*simDevice) { // the run ends: the record turns unreadable
			saved, _ = os.ReadFile(r.store.Path())
			_ = os.WriteFile(r.store.Path(), []byte("{this is not the record"), 0o600)
			broken = true
		}
	})

	out := r.run(advancePayload(TrackFast, true, approve573))
	res := wantResult(t, out, OutcomeSuccess, ReasonApplied)
	wantVersions(t, res, "26.7.3_8", "26.7.3_11", "26.7.3", "26.7.3_11")
	if sleepsSince < 2 {
		t.Fatalf("the record was never broken for long enough: %d waits after the run", sleepsSince)
	}
	if st := r.state(); st == nil || !st.Pinned || st.PinnedVersion != "26.7.3_11" || st.Pending != nil {
		t.Errorf("record %+v", st)
	}
}

// An update the device reported complete and verified is answered as applied
// whatever the settings do: they only show whether the pin held, and the periodic
// round checks that against the record.
func TestAdvance_SettingsThatStayUnreadableAfterTheUpdateStillAnswerApplied(t *testing.T) {
	r := enrolledRig(t, aHotfixWindow, func(d *simDevice) { d.settingsFailuresAfterRun = 1000 })
	r.simulateTime()
	out := r.run(advancePayload(TrackFast, true, approve573))

	res := wantResult(t, out, OutcomeSuccess, ReasonApplied)
	wantVersions(t, res, "26.7.3_8", "26.7.3_11", "26.7.3", "26.7.3_11")
	st := r.state()
	if !st.Pinned || st.PinnedFlavour != pinAt573 || st.PinnedVersion != "26.7.3_11" || st.Pending != nil {
		t.Fatalf("record %+v: it should hold the pin the update was run under, at the installed release, with nothing pending", st)
	}

	// The API comes back and the round finds the pin as the record says.
	r.dev.do(func(d *simDevice) { d.settingsFailuresAfterRun = 0 })
	r.eng.Tick(context.Background())
	if got := r.dev.writes(); len(got) != 0 {
		t.Errorf("writes %v: the pin held and nothing needed writing", got)
	}
	if st := r.state(); !st.Pinned || st.DriftPending {
		t.Errorf("record %+v", st)
	}
}

// ... and when the pin did not hold, the round puts it right and says so.
func TestAdvance_APinThatMovedWhileTheSettingsWereUnreadableIsRepairedByTheRound(t *testing.T) {
	r := enrolledRig(t, aHotfixWindow, func(d *simDevice) { d.settingsFailuresAfterRun = 1000 })
	r.simulateTime()
	wantResult(t, r.run(advancePayload(TrackFast, true, approve573)), OutcomeSuccess, ReasonApplied)

	r.dev.do(func(d *simDevice) { d.settingsFailuresAfterRun, d.flavour = 0, "" }) // reset in the GUI meanwhile
	r.eng.Tick(context.Background())
	if r.dev.Flavour() != pinAt573 {
		t.Errorf("flavour %q: the round should have put the pin back", r.dev.Flavour())
	}
	if st := r.state(); !st.DriftPending {
		t.Errorf("record %+v: the drift should be reported by the next result", st)
	}
}

// The release and the agent's own record are what the answer cannot do without.
// Until they can be read the task is left for the row's next evaluation, which
// asks again, and ends the row with its time like any that cannot be settled.
func TestAdvance_AnInstalledReleaseThatCannotBeReadAfterTheUpdateLeavesTheTaskUnsettled(t *testing.T) {
	r := enrolledRig(t, aHotfixWindow, func(d *simDevice) { d.installedErrAfterRun = true })
	r.simulateTime()
	out := r.run(advancePayload(TrackFast, true, approve573))
	if !out.Aborted {
		t.Fatalf("want the task left alone, got %+v", out)
	}
	job := r.jobs[len(r.jobs)-1]
	if job.Phase != PhaseTriggered || job.Upgrade == nil || !job.Upgrade.Triggered() {
		t.Fatalf("job %+v", job)
	}
	if st := r.state(); st.Pending == nil || !st.Pending.Triggered {
		t.Fatalf("record %+v: the update is still to be settled", st)
	}

	if got, done := r.newEngine().Resolve(context.Background(), job, startedRow()); done {
		t.Fatalf("resolved on a release it cannot read: %+v", got)
	}

	// Past its time the row ends, as every row that cannot be settled does.
	late := r.newEngine(WithClock(func() time.Time { return time.Now().Add(26 * time.Minute) }))
	got, done := late.Resolve(context.Background(), job, startedRow())
	if !done || got.Failure == "" {
		t.Fatalf("want the row ended with its time, got done=%v %+v", done, got)
	}

	// And once the release can be read the next evaluation answers it.
	r.dev.do(func(d *simDevice) { d.installedErrAfterRun = false })
	got, done = r.newEngine().Resolve(context.Background(), job, startedRow())
	if !done {
		t.Fatal("not resolved")
	}
	res := wantResult(t, got, OutcomeSuccess, ReasonApplied)
	wantVersions(t, res, "26.7.3_8", "26.7.3_11", "26.7.3", "26.7.3_11")
}

// The agent's record is as much a part of the answer as the release: a record
// that cannot be read leaves the task unsettled, not failed.
func TestAdvance_ARecordThatCannotBeReadAfterTheUpdateLeavesTheTaskUnsettled(t *testing.T) {
	r := enrolledRig(t, aHotfixWindow)
	r.simulateTime()
	record, err := os.ReadFile(r.store.Path())
	if err != nil {
		t.Fatal(err)
	}
	r.dev.do(func(d *simDevice) {
		d.onRun = func(*simDevice) { _ = os.WriteFile(r.store.Path(), []byte("{this is not the record"), 0o600) }
	})

	if out := r.run(advancePayload(TrackFast, true, approve573)); !out.Aborted {
		t.Fatalf("want the task left alone, got %+v", out)
	}
	job := r.jobs[len(r.jobs)-1]
	if got, done := r.newEngine().Resolve(context.Background(), job, startedRow()); done {
		t.Fatalf("resolved on a record it cannot read: %+v", got)
	}

	// The record is back (what the run last saved, as it was before the break).
	if err := os.WriteFile(r.store.Path(), record, 0o600); err != nil {
		t.Fatal(err)
	}
	got, done := r.newEngine().Resolve(context.Background(), job, startedRow())
	if !done {
		t.Fatal("not resolved")
	}
	wantResult(t, got, OutcomeSuccess, ReasonApplied)
}

// The reconciler asks once per sweep: the sweep comes round again every 15
// seconds, and waiting inside a sweep that runs in the connect would hold it up.
func TestResolve_AReleaseThatCannotBeReadIsAskedOncePerSweep(t *testing.T) {
	r := enrolledRig(t)
	job := rebootedJob(t, r)
	r.dev.do(func(d *simDevice) { d.installedErrAfterRun = true })

	before := r.dev.releaseReads()
	if got, done := r.newEngine().Resolve(context.Background(), job, startedRow()); done {
		t.Fatalf("resolved on a release it cannot read: %+v", got)
	}
	if n := r.dev.releaseReads() - before; n != 1 {
		t.Errorf("the release was read %d times in one sweep, want 1", n)
	}
}

func TestResolve_AnAPIStillSettlingAfterTheRebootDoesNotFailTheUpdate(t *testing.T) {
	r := enrolledRig(t)
	job := rebootedJob(t, r)
	r.dev.do(func(d *simDevice) { d.settingsFailuresAfterRun = 1 })

	got, done := r.newEngine().Resolve(context.Background(), job, startedRow())
	if !done {
		t.Fatal("not resolved")
	}
	res := wantResult(t, got, OutcomeSuccess, ReasonApplied)
	wantVersions(t, res, "26.7.3_11", "26.7.5", "26.7.5", "26.7.5")
	if st := r.state(); !st.Pinned || st.PinnedFlavour != pinAt575 || st.PinnedVersion != "26.7.5" || st.Pending != nil {
		t.Errorf("record %+v", st)
	}
}
