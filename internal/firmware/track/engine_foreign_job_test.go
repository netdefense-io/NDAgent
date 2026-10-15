package track

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/firmware"
	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// A firmware job that is not the engine's (a check from the GUI, OPNsense's cron
// job, a shell) can take OPNsense's lock between the engine's last look at the
// backend and its update request. The launcher drops the request and the API
// still answers ok, and the foreign job's ***DONE*** is not the update's. A FAILED
// that names the release blocks it for the whole organization, so none of this may
// end as one: the update runs after the foreign job, or the step holds with the
// pin back.
//
// The engine's own waits here move a clock instead of sleeping
// (rig.simulateTime), so a wait is bounded by the polls it makes and the deadlines
// it keeps, and not by how fast the machine is. The few real-time waits left in
// this file only guard against a hang.

const (
	foreignCheckMarker = "***GOT REQUEST TO CHECK FOR UPDATES***"
	previousRunLog     = updateRequestMarker + "\nCurrently running OPNsense at then\n***DONE***\n"
)

// aHotfixWindow is a window whose update changes no base or kernel: the device
// runs 26.7.3_8 and the pin already sits in 26.7.3's directory, which holds _11.
func aHotfixWindow(d *simDevice) {
	d.updateOutcome = "done"
	d.core = "26.7.3_8"
	d.pkgs["opnsense"] = "26.7.3_8"
	d.pkgs["curl"] = "8.20.0"
}

var approve573 = map[string]string{"26.7": "26.7.3"}

const (
	pinAt573 = "26.7/MINT/26.7.3/latest"
	pinAt575 = "26.7/MINT/26.7.5/latest"
)

// runBounded runs a task that must end by itself: a run that waits on a foreign
// job's end marker which never comes ends with the context instead of hanging
// the suite.
func (r *rig) runBounded(p Payload) *Outcome {
	r.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return r.runCtx(ctx, p)
}

// runUntil runs a task whose signed expiry is expires, and has to end by itself:
// an update that starts when it should not ends in a reboot that only the agent's
// stopping answers, and that would hang the suite.
func (r *rig) runUntil(p Payload, expires time.Time) *Outcome {
	r.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out := r.eng.Execute(ctx, Input{
		TaskID: "101", Payload: p, Started: r.now(), Expires: expires,
		Save:     func(j Job) { r.jobs = append(r.jobs, j) },
		Progress: func(m string) { r.msgs = append(r.msgs, m) },
	})
	r.checkOutcome(p, out)
	return out
}

// engineOver is an engine over another device (a scripted backend around the
// simulator) on the rig's simulated time.
func (r *rig) engineOver(dev Device, opts ...Option) *Engine {
	if r.clock == nil {
		r.simulateTime()
	}
	base := []Option{
		WithTiming(fastTiming()), WithJitter(func(time.Duration) time.Duration { return 0 }),
		WithUptime(func() time.Duration { return time.Hour }), WithBootTime(r.dev.BootTime),
		WithClock(r.clock.Now), WithSleep(r.clock.Sleep),
	}
	return New(dev, r.store, nil, append(base, opts...)...)
}

func aForeignJobAtTheUpdate(times, life int) func(*simDevice) {
	return func(d *simDevice) { d.foreignOnUpdate, d.foreignLife = times, life }
}

// foreverBusy is a foreign job that never lets go of the lock.
const foreverBusy = 1_000_000

// pinIsLeftAhead asserts what a hold under a running firmware job leaves: the pin
// still at the target's directory, the move recorded as pending (not requested),
// and the record's pin where it was.
func pinIsLeftAhead(t *testing.T, r *rig, behind, ahead string) {
	t.Helper()
	if r.dev.Flavour() != ahead {
		t.Errorf("flavour %q: the pin must not be written under a running firmware job", r.dev.Flavour())
	}
	st := r.state()
	if !st.Pinned || st.PinnedFlavour != behind || st.Pending == nil || st.Pending.Triggered ||
		st.Pending.FromFlavour != behind || st.Pending.ToFlavour != ahead {
		t.Errorf("record %+v (pending %+v): the move should stay recorded for the round", st, st.Pending)
	}
	if last := r.jobs[len(r.jobs)-1]; last.Phase != PhaseMoved || last.Upgrade == nil || last.Upgrade.Triggered() {
		t.Errorf("job %+v: nothing was requested, so the row must not say it was", last)
	}
}

// theRoundPutsThePinBack is the periodic round once the box is idle: it writes the
// pin back at the installed release, and does not call that a drift.
func theRoundPutsThePinBack(t *testing.T, r *rig, behind string) {
	t.Helper()
	r.eng.Tick(context.Background())
	if r.dev.Flavour() != behind {
		t.Errorf("flavour %q: the round should have put the pin back to %q", r.dev.Flavour(), behind)
	}
	if st := r.state(); !st.Pinned || st.Pending != nil || st.PinnedFlavour != behind || st.DriftPending {
		t.Errorf("record %+v", st)
	}
}

func TestAdvance_AForeignJobHoldingTheLockAtTheRequestDelaysTheUpdateAndFailsNothing(t *testing.T) {
	t.Run("an update with no reboot", func(t *testing.T) {
		r := enrolledRig(t, aHotfixWindow, aForeignJobAtTheUpdate(1, 4))
		r.simulateTime()
		out := r.runBounded(advancePayload(TrackFast, true, approve573))

		res := wantResult(t, out, OutcomeSuccess, ReasonApplied)
		wantVersions(t, res, "26.7.3_8", "26.7.3_11", "26.7.3", "26.7.3_11")
		if n := r.dev.count("update"); n != 2 {
			t.Errorf("the update was requested %d times, want 2: the first was dropped by the foreign job", n)
		}
		if r.dev.Flavour() != pinAt573 {
			t.Errorf("flavour %q", r.dev.Flavour())
		}
		if st := r.state(); !st.Pinned || st.PinnedVersion != "26.7.3_11" || st.Pending != nil {
			t.Errorf("record %+v", st)
		}
	})

	t.Run("an update that reboots", func(t *testing.T) {
		r := enrolledRig(t, aForeignJobAtTheUpdate(1, 4))
		r.simulateTime()
		job := rebootedJob(t, r) // fails the test if the task ended in anything but the reboot
		if n := r.dev.count("update"); n != 2 {
			t.Errorf("the update was requested %d times, want 2", n)
		}

		got, done := r.newEngine().Resolve(context.Background(), job, startedRow())
		if !done {
			t.Fatal("the update had ended and the row was not resolved")
		}
		res := wantResult(t, got, OutcomeSuccess, ReasonApplied)
		wantVersions(t, res, "26.7.3_11", "26.7.5", "26.7.5", "26.7.5")
	})
}

// The window ends false while the foreign job runs, and the second request is
// made once it is over. One that is dropped again is a hold, never a failure.
func TestAdvance_ARequestDroppedTwiceByForeignJobsIsHeldAsBusyWithThePinBack(t *testing.T) {
	r := enrolledRig(t, aHotfixWindow, aForeignJobAtTheUpdate(2, 4))
	r.simulateTime()
	out := r.runBounded(advancePayload(TrackFast, true, approve573))

	res := wantResult(t, out, OutcomeHeld, ReasonHeldFirmwareBusy)
	wantVersions(t, res, "26.7.3_8", "26.7.3_8", "26.7.3", "26.7.3_8")
	if n := r.dev.count("update"); n != 2 {
		t.Errorf("the update was requested %d times, want 2", n)
	}
	if r.dev.Core() != "26.7.3_8" {
		t.Errorf("the release moved to %s", r.dev.Core())
	}
	if r.dev.Flavour() != pinAt573 {
		t.Errorf("flavour %q: the pin should be back where it was", r.dev.Flavour())
	}
	if st := r.state(); !st.Pinned || st.Pending != nil || st.PinnedFlavour != pinAt573 {
		t.Errorf("record %+v", st)
	}
	if last := r.jobs[len(r.jobs)-1]; last.Phase != PhaseMoved || last.Upgrade == nil || last.Upgrade.Triggered() {
		t.Errorf("job %+v: nothing was requested, so the row must not say it was", last)
	}
}

// The second request waits for the backend like the first, and a foreign job that
// outlasts that wait is the same hold.
func TestAdvance_AForeignJobThatOutlastsTheWaitForTheBackendIsHeldAsBusy(t *testing.T) {
	r := enrolledRig(t, aHotfixWindow, aForeignJobAtTheUpdate(1, foreverBusy))
	r.simulateTime()
	out := r.runBounded(advancePayload(TrackFast, true, approve573))

	wantResult(t, out, OutcomeHeld, ReasonHeldFirmwareBusy)
	if n := r.dev.count("update"); n != 1 {
		t.Errorf("the update was requested %d times, want 1: the backend never freed up for the second", n)
	}
	if r.dev.Flavour() != pinAt573 {
		t.Errorf("flavour %q", r.dev.Flavour())
	}
	// The pin never moved, so there is nothing to put back under the foreign job and
	// nothing to leave to the round: the move is forgotten.
	if st := r.state(); !st.Pinned || st.Pending != nil || st.PinnedFlavour != pinAt573 {
		t.Errorf("record %+v", st)
	}
}

// A request dropped with nothing else at work is held as ever: the backend reads
// ready and the log is the previous run's.
func TestAdvance_ADroppedRequestWithTheBackendReadyIsStillHeldAsBusy(t *testing.T) {
	r := enrolledRig(t, aHotfixWindow, func(d *simDevice) {
		d.updateDropped = true
		d.progressText = previousRunLog
	})
	r.simulateTime()
	wantResult(t, r.run(advancePayload(TrackFast, true, approve573)), OutcomeHeld, ReasonHeldFirmwareBusy)
	if n := r.dev.count("update"); n != 2 {
		t.Errorf("the update was requested %d times, want 2", n)
	}
	if r.dev.Flavour() != pinAt573 {
		t.Errorf("flavour %q", r.dev.Flavour())
	}
}

// --- the task's time -------------------------------------------------------------------

// The wait for the backend ends when the backend is ready, at ReadyWait, or at the
// limit it is given if that comes first; a limit never makes it longer.
func TestWaitReadyUntil_EndsWhenTheBackendIsReadyOrAtTheEarlierOfReadyWaitAndTheLimit(t *testing.T) {
	readyWait := fastTiming().ReadyWait
	poll := fastTiming().Poll

	for name, tc := range map[string]struct {
		busyReads  int // the backend reads busy this many times
		alwaysBusy bool
		limit      time.Duration // from now; 0: none
		wantErr    bool
		wantTook   time.Duration // the most the wait may take; at least wantTook-poll when it fails
	}{
		"busy for a while, no limit":            {busyReads: 3, wantTook: 3 * poll},
		"ready at once with a limit long gone":  {limit: -time.Hour, wantTook: 0},
		"busy for a while within the limit":     {busyReads: 3, limit: time.Minute, wantTook: 3 * poll},
		"never ready, no limit":                 {alwaysBusy: true, wantErr: true, wantTook: readyWait + poll},
		"never ready, a limit before ReadyWait": {alwaysBusy: true, limit: readyWait / 4, wantErr: true, wantTook: readyWait/4 + poll},
		"never ready, a limit after ReadyWait":  {alwaysBusy: true, limit: time.Hour, wantErr: true, wantTook: readyWait + poll},
		"never ready, a limit long gone":        {alwaysBusy: true, limit: -time.Hour, wantErr: true, wantTook: 0},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			clock := r.simulateTime()
			r.dev.do(func(d *simDevice) { d.busyReads, d.alwaysBusy = tc.busyReads, tc.alwaysBusy })
			var limit time.Time
			if tc.limit != 0 {
				limit = clock.Now().Add(tc.limit)
			}
			start := clock.Now()

			err := r.eng.waitReadyUntil(context.Background(), limit)

			if (err != nil) != tc.wantErr {
				t.Fatalf("error %v, want an error: %v", err, tc.wantErr)
			}
			took := clock.Now().Sub(start)
			if took > tc.wantTook || (tc.wantErr && tc.wantTook > 0 && took < tc.wantTook-poll) {
				t.Errorf("the wait took %v, want %v", took, tc.wantTook)
			}
		})
	}
}

// A foreign job that keeps the lock must not take the time the update needs: the
// signed expiry is what NDBroker's stuck-task timeout turns into a failure of the
// release, so a task that waits behind another job answers while it still can.
func TestAdvance_AForeignJobHoldingTheLockThroughTheTasksTimeIsHeldInsideIt(t *testing.T) {
	production := WithTiming(DefaultTiming())

	t.Run("the wait for the backend stops where the update's time begins", func(t *testing.T) {
		r := enrolledRig(t, aForeignJobAtTheUpdate(1, foreverBusy))
		clock := r.simulateTime(production)
		start := clock.Now()
		expires := start.Add(advanceWork + time.Minute) // a minute of waiting is all it can spare

		out := r.runUntil(advancePayload(TrackFast, true, approve575), expires)

		res := wantResult(t, out, OutcomeHeld, ReasonHeldFirmwareBusy)
		wantVersions(t, res, "26.7.3_11", "26.7.3_11", "26.7.5", "26.7.3_11")
		if n := r.dev.count("update"); n != 1 {
			t.Errorf("the update was requested %d times, want 1: no time was left to ask again", n)
		}
		if took := clock.Now().Sub(start); took >= DefaultTiming().ReadyWait {
			t.Errorf("the task took %v: the wait went past the minute it could spare, into ReadyWait (%v)", took, DefaultTiming().ReadyWait)
		}
		if !clock.Now().Before(expires) {
			t.Errorf("answered at %v, past the signed expiry %v", clock.Now(), expires)
		}

		// The foreign job is still at work, so the pin is not written under it: the
		// round puts it back once the box is idle.
		pinIsLeftAhead(t, r, pinAt573, pinAt575)
		r.dev.do(func(d *simDevice) { d.foreignLeft = 0 })
		theRoundPutsThePinBack(t, r, pinAt573)
	})

	t.Run("with all its time the wait is the backend's own", func(t *testing.T) {
		r := enrolledRig(t, aForeignJobAtTheUpdate(1, foreverBusy))
		clock := r.simulateTime(production)
		start := clock.Now()
		expires := start.Add(AdvanceTTL)

		wantResult(t, r.runUntil(advancePayload(TrackFast, true, approve575), expires), OutcomeHeld, ReasonHeldFirmwareBusy)
		if took := clock.Now().Sub(start); took < DefaultTiming().ReadyWait || !clock.Now().Before(expires) {
			t.Errorf("the task took %v, want the whole of ReadyWait (%v) and an answer before %v", took, DefaultTiming().ReadyWait, AdvanceTTL)
		}
		if n := r.dev.count("update"); n != 1 {
			t.Errorf("the update was requested %d times, want 1", n)
		}
	})

	// The same bound holds for the first request, whose wait is for a job that was
	// already at work, and for a window that runs without the launcher.
	for name, payload := range map[string]Payload{
		"the first request":       advancePayload(TrackFast, true, approve575),
		"a window with no reboot": advancePayload(TrackFast, false, approve575),
	} {
		t.Run("a backend that is busy before "+name+" is waited for inside the time", func(t *testing.T) {
			r := enrolledRig(t)
			clock := r.simulateTime(production)
			r.dev.do(func(d *simDevice) { d.busyAfterNextCheck = true }) // after the check, somebody else takes the lock
			start := clock.Now()
			expires := start.Add(advanceWork + time.Minute)

			out := r.runUntil(payload, expires)

			res := wantResult(t, out, OutcomeHeld, ReasonHeldFirmwareBusy)
			wantVersions(t, res, "26.7.3_11", "26.7.3_11", "26.7.5", "26.7.3_11")
			if n := r.dev.count("update") + r.dev.count("exec"); n != 0 {
				t.Errorf("an update was asked for %d times: %v", n, r.dev.Calls())
			}
			if took := clock.Now().Sub(start); took >= DefaultTiming().ReadyWait || !clock.Now().Before(expires) {
				t.Errorf("the task took %v (expiry in %v): the wait for the backend went past the time the update needs", took, expires.Sub(start))
			}
			pinIsLeftAhead(t, r, pinAt573, pinAt575)
		})
	}

	// The backend is free again, but too late to leave the update its time.
	t.Run("a backend that is free when no time is left is not asked again", func(t *testing.T) {
		r := enrolledRig(t, aForeignJobAtTheUpdate(1, 4))
		clock := r.simulateTime(production)
		expires := clock.Now().Add(advanceWork + time.Second) // by the time of the request the second is long gone

		res := wantResult(t, r.runUntil(advancePayload(TrackFast, true, approve575), expires), OutcomeHeld, ReasonHeldFirmwareBusy)
		wantVersions(t, res, "26.7.3_11", "26.7.3_11", "26.7.5", "26.7.3_11")
		if n := r.dev.count("update"); n != 1 {
			t.Errorf("the update was requested %d times, want 1", n)
		}
		if r.dev.Flavour() != pinAt573 {
			t.Errorf("flavour %q: the foreign job was over, so the pin should be back", r.dev.Flavour())
		}
		if st := r.state(); !st.Pinned || st.Pending != nil || st.PinnedFlavour != pinAt573 {
			t.Errorf("record %+v", st)
		}
	})
}

// --- how a start is told --------------------------------------------------------

// scriptedBackend answers the progress log and the backend state from a script,
// so a test can put OPNsense in states the simulator's sequence never reaches.
// Both repeat their last answer.
type scriptedBackend struct {
	*simDevice

	mu       sync.Mutex
	progress []progressAnswer
	running  []firmware.RunState
	nProg    int
	nRun     int

	// runningAfterDone replaces running from the moment a progress answer of
	// status done has been served: what the backend does once the job whose end
	// that was has let go of the lock.
	runningAfterDone []firmware.RunState
	doneServed       bool
	nAfter           int

	// armed says the script applies: until then the simulator answers. The update
	// request arms it, after running onArm.
	armed bool
	onArm func(*simDevice)
}

type progressAnswer struct {
	status, log string
	err         error
}

func (s *scriptedBackend) Progress(ctx context.Context) (*opnapi.FirmwareProgressStatus, error) {
	s.mu.Lock()
	if !s.armed {
		s.mu.Unlock()
		return s.simDevice.Progress(ctx)
	}
	i := s.nProg
	if i >= len(s.progress) {
		i = len(s.progress) - 1
	}
	s.nProg++
	a := s.progress[i]
	if a.err == nil && a.status == "done" {
		s.doneServed = true
	}
	s.mu.Unlock()
	if a.err != nil {
		return nil, a.err
	}
	return &opnapi.FirmwareProgressStatus{Status: a.status, Log: a.log}, nil
}

func (s *scriptedBackend) Running(ctx context.Context) (firmware.RunState, error) {
	s.mu.Lock()
	if !s.armed || len(s.running) == 0 {
		s.mu.Unlock()
		return s.simDevice.Running(ctx)
	}
	if s.doneServed && len(s.runningAfterDone) > 0 {
		i := s.nAfter
		if i >= len(s.runningAfterDone) {
			i = len(s.runningAfterDone) - 1
		}
		s.nAfter++
		state := s.runningAfterDone[i]
		s.mu.Unlock()
		return state, nil
	}
	i := s.nRun
	if i >= len(s.running) {
		i = len(s.running) - 1
	}
	s.nRun++
	state := s.running[i]
	s.mu.Unlock()
	return state, nil
}

func (s *scriptedBackend) TriggerUpdate(ctx context.Context) (string, error) {
	answer, err := s.simDevice.TriggerUpdate(ctx)
	s.mu.Lock()
	s.armed = true
	arm := s.onArm
	s.mu.Unlock()
	if arm != nil {
		s.simDevice.do(arm)
	}
	return answer, err
}

func (s *scriptedBackend) Probes() firmware.Probes {
	p := s.simDevice.Probes()
	p.Running = s.Running
	return p
}

// scriptedEngine is an engine over a script, armed at once, for the checks that
// call one step of the update directly.
func scriptedEngine(t *testing.T, progress []progressAnswer, running ...firmware.RunState) *Engine {
	t.Helper()
	r := newRig(t)
	dev := &scriptedBackend{simDevice: r.dev, progress: progress, running: running, armed: true}
	return r.engineOver(dev)
}

func TestRunStarted_ASuccessfulStartIsToldFromAForeignJobsRun(t *testing.T) {
	ours := updateRequestMarker + "\nCurrently running OPNsense at now\n"
	foreign := foreignCheckMarker + "\nCurrently running OPNsense at now\nFetching changelog\n"
	gap := progressAnswer{status: "error"}
	busy, ready := firmware.RunBusy, firmware.RunReady

	for name, tc := range map[string]struct {
		baseline string
		progress []progressAnswer
		running  []firmware.RunState
		want     startEvidence
	}{
		"the log changed and carries the marker": {
			"previous", []progressAnswer{{status: "running", log: ours}}, []firmware.RunState{busy}, startedByMarker},
		"the marker arrives after another job's log": {
			"previous", []progressAnswer{{status: "running", log: foreign}, {status: "running", log: foreign}, {status: "running", log: ours}},
			[]firmware.RunState{busy}, startedByMarker},

		// The bug: whoever holds the lock turns the backend busy, and the request is gone.
		"another job's log with the backend busy": {
			"previous", []progressAnswer{{status: "running", log: foreign}}, []firmware.RunState{busy}, notStarted},
		"another job's log that the baseline already was": {
			foreign, []progressAnswer{{status: "running", log: foreign}}, []firmware.RunState{busy}, notStarted},
		"the previous run's log, with the marker, with the backend busy": {
			previousRunLog, []progressAnswer{{status: "done", log: previousRunLog}}, []firmware.RunState{busy}, notStarted},
		"a foreign job that has ended": {
			"previous", []progressAnswer{{status: "done", log: foreign + "***DONE***\n"}}, []firmware.RunState{ready}, notStarted},

		// The API goes away as OPNsense replaces its core package: busy is then all there is.
		"a log that cannot be read with the backend busy": {
			"previous", []progressAnswer{{err: errSim}}, []firmware.RunState{busy}, startedUnread},
		"an empty log with the backend busy": {
			"previous", []progressAnswer{gap}, []firmware.RunState{busy}, startedUnread},
		"an empty log on a box that had no log": {
			"", []progressAnswer{gap}, []firmware.RunState{busy}, startedUnread},
		"a log that cannot be read with the backend ready": {
			"previous", []progressAnswer{{err: errSim}}, []firmware.RunState{ready}, notStarted},
		"an empty log with the backend ready": {
			"previous", []progressAnswer{gap}, []firmware.RunState{ready}, notStarted},
	} {
		t.Run(name, func(t *testing.T) {
			eng := scriptedEngine(t, tc.progress, tc.running...)
			if got := eng.runStarted(context.Background(), tc.baseline, updateRequestMarker); got != tc.want {
				t.Fatalf("runStarted = %d, want %d", got, tc.want)
			}
		})
	}
}

// --- an end marker that is not the update's -----------------------------------------

func TestWatchUpdate_AnEndMarkerThatIsNotTheUpdatesIsAnotherJobs(t *testing.T) {
	ours := updateRequestMarker + "\nCurrently running OPNsense at now\n"
	foreign := foreignCheckMarker + "\nCurrently running OPNsense at now\n"

	for name, tc := range map[string]struct {
		baseline string
		ours     bool
		progress []progressAnswer
		want     string
	}{
		"another job's log that ended": {
			"previous", false, []progressAnswer{{status: "running", log: foreign}, {status: "done", log: foreign + "***DONE***\n"}}, endedElsewhere},
		"the previous run's log, which ended": {
			previousRunLog, false, []progressAnswer{{err: errSim}, {status: "done", log: previousRunLog}}, endedElsewhere},
		"the update's own log, shown late": {
			"previous", false, []progressAnswer{{status: "running", log: ours}, {status: "done", log: ours + "***DONE***\n"}}, "done"},
		"a run already seen to be the update's, whose log another job has replaced": {
			"previous", true, []progressAnswer{{status: "done", log: foreign + "***DONE***\n"}}, "done"},
	} {
		t.Run(name, func(t *testing.T) {
			eng := scriptedEngine(t, tc.progress)
			meta := firmware.Meta{Mode: "minor", Reboot: true, ExpiresAt: time.Now().Add(time.Hour).Unix(), StartedAt: time.Now().Unix()}
			got := eng.watchUpdate(context.Background(), &op{in: Input{TaskID: "101"}}, &meta, tc.baseline, tc.ours, updateRequestMarker)
			if got != tc.want {
				t.Fatalf("watchUpdate = %q, want %q", got, tc.want)
			}
		})
	}
}

// Only an end marker of done is judged by whose log it is. A reboot announced is
// a box that is going down, whoever's job it ends: the handler stays, holding the
// slot, until the agent is stopped, and the row is decided from the device after.
func TestWatchUpdate_ARebootIsAwaitedWhoseLogItIs(t *testing.T) {
	foreign := foreignCheckMarker + "\nCurrently running OPNsense at now\n***REBOOT***\n"
	eng := scriptedEngine(t, []progressAnswer{{err: errSim}, {status: "reboot", log: foreign}})
	meta := firmware.Meta{Mode: "minor", Reboot: true, ExpiresAt: time.Now().Add(time.Hour).Unix(), StartedAt: time.Now().Unix()}

	rebootSaved := make(chan struct{}, 1)
	o := &op{in: Input{TaskID: "101", Save: func(j Job) {
		if j.Upgrade != nil && j.Upgrade.RebootSeen {
			select {
			case rebootSaved <- struct{}{}:
			default:
			}
		}
	}}}
	ctx, stopped := context.WithCancel(context.Background()) // the reboot stops the agent
	defer stopped()
	ended := make(chan string, 1)
	go func() { ended <- eng.watchUpdate(ctx, o, &meta, "previous", false, updateRequestMarker) }()

	select {
	case <-rebootSaved:
	case got := <-ended:
		t.Fatalf("watchUpdate ended with %q without recording the reboot: an announced reboot is not another job's end", got)
	case <-time.After(10 * time.Second):
		t.Fatal("the reboot was never recorded")
	}
	if !meta.RebootSeen {
		t.Error("the reboot is not in the run's record")
	}
	stopped()
	if got := <-ended; got != "" {
		t.Errorf("watchUpdate = %q after the agent was stopped, want no sentinel: the device decides", got)
	}
}

// A request believed started because the log could not be read, which was a
// foreign job's after all: its ***DONE*** must not be judged as the update's (no
// reboot, packages missing), which would be a FAILED naming the release for a
// window that never ran.
func TestAdvance_ARunBelievedStartedThatWasAnotherJobsEndsAsAHoldWithThePinBack(t *testing.T) {
	foreign := foreignCheckMarker + "\nCurrently running OPNsense at now\nFetching changelog information... done\n***DONE***\n"
	r := enrolledRig(t, aHotfixWindow, func(d *simDevice) { d.updateDropped = true })
	dev := &scriptedBackend{
		simDevice: r.dev,
		progress:  []progressAnswer{{err: errSim}, {err: errSim}, {status: "done", log: foreign}, {status: "done", log: foreign}},
		running:   []firmware.RunState{firmware.RunBusy, firmware.RunBusy, firmware.RunBusy, firmware.RunReady},
	}
	r.eng = r.engineOver(dev)

	out := r.eng.Execute(context.Background(), Input{TaskID: "101", Payload: advancePayload(TrackFast, true, approve573), Started: r.now()})
	r.checkOutcome(advancePayload(TrackFast, true, approve573), out)

	res := wantResult(t, out, OutcomeHeld, ReasonHeldFirmwareBusy)
	wantVersions(t, res, "26.7.3_8", "26.7.3_8", "26.7.3", "26.7.3_8")
	if n := r.dev.count("update"); n != 1 {
		t.Errorf("the update was requested %d times, want 1", n)
	}
	if r.dev.Flavour() != pinAt573 {
		t.Errorf("flavour %q: the pin should be back where it was", r.dev.Flavour())
	}
	if st := r.state(); !st.Pinned || st.Pending != nil || st.PinnedFlavour != pinAt573 {
		t.Errorf("record %+v", st)
	}
}

// When the release has moved the foreign job's end says nothing either way, and
// the pin must not go back below what is installed: the device decides, as for
// any run.
func TestAdvance_ARunBelievedStartedWhoseReleaseMovedIsJudgedByTheDevice(t *testing.T) {
	foreign := foreignCheckMarker + "\nCurrently running OPNsense at now\n***DONE***\n"
	r := enrolledRig(t, aHotfixWindow, func(d *simDevice) { d.updateDropped = true })
	dev := &scriptedBackend{
		simDevice: r.dev,
		progress:  []progressAnswer{{err: errSim}, {status: "done", log: foreign}},
		running:   []firmware.RunState{firmware.RunBusy, firmware.RunBusy, firmware.RunReady},
		// Somebody installed the release the pin holds (a GUI update, say) meanwhile.
		onArm: func(d *simDevice) {
			cat, _ := d.folderOf()
			d.pendingCore, d.pendingUpdate, d.pendingSets, d.pendingPkgs = cat.core, cat.update, StripHotfix(cat.update), cat.pkgs
			d.applyPending(false)
		},
	}
	r.eng = r.engineOver(dev)

	out := r.eng.Execute(context.Background(), Input{TaskID: "101", Payload: advancePayload(TrackFast, true, approve573), Started: r.now()})
	r.checkOutcome(advancePayload(TrackFast, true, approve573), out)

	res := wantResult(t, out, OutcomeSuccess, ReasonApplied)
	wantVersions(t, res, "26.7.3_8", "26.7.3_11", "26.7.3", "26.7.3_11")
	if r.dev.Flavour() != pinAt573 {
		t.Errorf("flavour %q", r.dev.Flavour())
	}
}

// A start that the log itself showed stays the update's whatever the log says
// later: the launcher holds OPNsense's lock for the whole run, and a log that
// another job has replaced by the time it is read is not a reason to take the end
// for somebody else's. The update started and applied nothing: that is a failure
// of the update, and the device says so.
func TestAdvance_ARunWhoseStartTheLogShowedIsTheUpdatesWhateverTheLogSaysLater(t *testing.T) {
	ours := updateRequestMarker + "\nCurrently running OPNsense at now\n"
	foreign := foreignCheckMarker + "\nCurrently running OPNsense at now\n***DONE***\n"
	r := enrolledRig(t, func(d *simDevice) { d.updateDropped = true })
	dev := &scriptedBackend{
		simDevice: r.dev,
		progress:  []progressAnswer{{status: "running", log: ours}, {status: "done", log: foreign}},
		running:   []firmware.RunState{firmware.RunBusy, firmware.RunBusy, firmware.RunReady},
	}
	r.eng = r.engineOver(dev)

	out := r.eng.Execute(context.Background(), Input{TaskID: "101", Payload: advancePayload(TrackFast, true, approve575), Started: r.now()})
	r.checkOutcome(advancePayload(TrackFast, true, approve575), out)

	if out.Failure == "" || out.Detail.Target != "26.7.5" {
		t.Fatalf("want the update's failure naming its target, got %+v", out)
	}
	if n := r.dev.count("update"); n != 1 {
		t.Errorf("the update was requested %d times, want 1", n)
	}
}

// --- the end of a run that was believed to be the update's ------------------------------

// The job whose end was seen is another's, and the backend is not free yet (a
// third job took the lock): the pin is written back once it is, not under it.
func TestAdvance_AnotherJobsEndWaitsForTheBackendBeforeThePinGoesBack(t *testing.T) {
	foreign := foreignCheckMarker + "\nCurrently running OPNsense at now\n***DONE***\n"
	r := enrolledRig(t, func(d *simDevice) { d.updateDropped = true })
	dev := &scriptedBackend{
		simDevice:        r.dev,
		progress:         []progressAnswer{{err: errSim}, {err: errSim}, {status: "done", log: foreign}},
		running:          []firmware.RunState{firmware.RunBusy},
		runningAfterDone: []firmware.RunState{firmware.RunBusy, firmware.RunBusy, firmware.RunBusy, firmware.RunReady},
	}
	r.eng = r.engineOver(dev)

	out := r.eng.Execute(context.Background(), Input{TaskID: "101", Payload: advancePayload(TrackFast, true, approve575), Started: r.now()})
	r.checkOutcome(advancePayload(TrackFast, true, approve575), out)

	res := wantResult(t, out, OutcomeHeld, ReasonHeldFirmwareBusy)
	wantVersions(t, res, "26.7.3_11", "26.7.3_11", "26.7.5", "26.7.3_11")
	if r.dev.Flavour() != pinAt573 {
		t.Errorf("flavour %q: the pin is written back once the backend is free", r.dev.Flavour())
	}
	if st := r.state(); !st.Pinned || st.Pending != nil || st.PinnedFlavour != pinAt573 {
		t.Errorf("record %+v", st)
	}
}

// ... and that wait is the task's time too: a backend that stays busy past the
// moment the update's time begins ends it there, with the pin left to the round.
func TestAdvance_AnotherJobsEndDoesNotWaitForTheBackendPastTheTasksTime(t *testing.T) {
	foreign := foreignCheckMarker + "\nCurrently running OPNsense at now\n***DONE***\n"
	r := enrolledRig(t, func(d *simDevice) { d.updateDropped = true })
	clock := r.simulateTime()
	dev := &scriptedBackend{
		simDevice:        r.dev,
		progress:         []progressAnswer{{err: errSim}, {err: errSim}, {status: "done", log: foreign}},
		running:          []firmware.RunState{firmware.RunBusy},
		runningAfterDone: []firmware.RunState{firmware.RunBusy},
	}
	r.eng = r.engineOver(dev, WithTiming(DefaultTiming()))
	start := clock.Now()
	expires := start.Add(advanceWork + time.Minute)

	out := r.runUntil(advancePayload(TrackFast, true, approve575), expires)

	wantResult(t, out, OutcomeHeld, ReasonHeldFirmwareBusy)
	if took := clock.Now().Sub(start); took >= DefaultTiming().ReadyWait || !clock.Now().Before(expires) {
		t.Errorf("the task took %v (expiry in %v): the wait for the backend went past the time the update needs", took, expires.Sub(start))
	}
	pinIsLeftAhead(t, r, pinAt573, pinAt575)
}

// --- a request that errors ----------------------------------------------------------

// The call can fail while a foreign job holds the lock: the launcher dropped the
// request, nothing started, and the busy backend is not the update. A FAILED that
// names the release is not an answer for that.
func TestAdvance_AnUpdateRequestThatErrorsWhileAForeignJobHoldsTheLockIsHeldNotFailed(t *testing.T) {
	t.Run("the foreign job ends before the window does", func(t *testing.T) {
		r := enrolledRig(t, aForeignJobAtTheUpdate(1, 4), func(d *simDevice) { d.updateErr = errSim })
		r.simulateTime()
		out := r.runBounded(advancePayload(TrackFast, true, approve575))

		res := wantResult(t, out, OutcomeHeld, ReasonHeldCheckFailed)
		wantVersions(t, res, "26.7.3_11", "26.7.3_11", "26.7.5", "26.7.3_11")
		if n := r.dev.count("update"); n != 1 {
			t.Errorf("the update was requested %d times, want 1", n)
		}
		if r.dev.Flavour() != pinAt573 {
			t.Errorf("flavour %q: the pin should be back where it was", r.dev.Flavour())
		}
		if st := r.state(); !st.Pinned || st.Pending != nil || st.PinnedFlavour != pinAt573 {
			t.Errorf("record %+v", st)
		}
	})

	t.Run("the foreign job is still at work", func(t *testing.T) {
		r := enrolledRig(t, aForeignJobAtTheUpdate(1, foreverBusy), func(d *simDevice) { d.updateErr = errSim })
		r.simulateTime()
		out := r.runBounded(advancePayload(TrackFast, true, approve575))

		wantResult(t, out, OutcomeHeld, ReasonHeldCheckFailed)
		pinIsLeftAhead(t, r, pinAt573, pinAt575)
		r.dev.do(func(d *simDevice) { d.foreignLeft = 0 })
		theRoundPutsThePinBack(t, r, pinAt573)
	})
}

// --- a run without the launcher ---------------------------------------------------------

// opnsense-update, run by the agent, takes no firmware lock, so a foreign job at
// work refuses it through pkg's own lock. That exit is not a failure of the
// update: nothing was installed, and the cause is not the release.
func TestAdvance_APackagesOnlyRunTurnedAwayForALockIsHeldAsBusyWithThePinBack(t *testing.T) {
	r := enrolledRig(t, func(d *simDevice) { d.execLockRefusal = true })
	out := r.run(advancePayload(TrackFast, false, approve575))

	res := wantResult(t, out, OutcomeHeld, ReasonHeldFirmwareBusy)
	wantVersions(t, res, "26.7.3_11", "26.7.3_11", "26.7.5", "26.7.3_11")
	if r.dev.count("exec") != 1 {
		t.Errorf("calls %v", r.dev.Calls())
	}
	if r.dev.Flavour() != pinAt573 {
		t.Errorf("flavour %q: the pin should be back where it was", r.dev.Flavour())
	}
	if st := r.state(); !st.Pinned || st.Pending != nil || st.PinnedFlavour != pinAt573 {
		t.Errorf("record %+v", st)
	}
	if last := r.jobs[len(r.jobs)-1]; last.Phase != PhaseMoved || last.Upgrade == nil || last.Upgrade.Triggered() {
		t.Errorf("job %+v: nothing was installed, so the row must not say it was requested", last)
	}
}

// The refusal means another job is at work, or may be (a failure with a firmware
// tool running, a backend that cannot be read counts as busy): the write that puts
// the pin back moves the repositories under it, so it is left to the periodic round
// and the pin sits ahead of the installed release until then, never below it.
func TestAdvance_APackagesOnlyHoldUnderARunningJobLeavesThePinToTheRound(t *testing.T) {
	for name, tc := range map[string]struct {
		tweak func(*simDevice)
		over  func(*simDevice)
	}{
		"a package tool runs and the exit says nothing of a lock": {
			func(d *simDevice) { d.updateFails, d.pkgToolsBusy = true, true },
			func(d *simDevice) { d.pkgToolsBusy = false },
		},
		"pkg's lock was taken and a firmware job runs": {
			func(d *simDevice) { d.execLockRefusal, d.busyAfterRun = true, true },
			func(d *simDevice) { d.busyAfterRun = false },
		},
		"pkg's lock was taken and the backend cannot be read": {
			func(d *simDevice) { d.execLockRefusal, d.runningErrAfterRun = true, true },
			func(d *simDevice) { d.runningErrAfterRun = false },
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := enrolledRig(t, tc.tweak)
			out := r.run(advancePayload(TrackFast, false, approve575))

			res := wantResult(t, out, OutcomeHeld, ReasonHeldFirmwareBusy)
			wantVersions(t, res, "26.7.3_11", "26.7.3_11", "26.7.5", "26.7.3_11")
			if r.dev.Core() != "26.7.3_11" {
				t.Errorf("the release moved to %s", r.dev.Core())
			}
			pinIsLeftAhead(t, r, pinAt573, pinAt575)

			r.dev.do(tc.over) // the job is over, the box can be read again
			theRoundPutsThePinBack(t, r, pinAt573)
		})
	}
}

// What was installed, or a failure with nobody else at work, is a failure.
func TestAdvance_APackagesOnlyRunThatFailedForRealStaysFailed(t *testing.T) {
	t.Run("with nobody else at work", func(t *testing.T) {
		r := enrolledRig(t, func(d *simDevice) { d.updateFails = true })
		out := r.run(advancePayload(TrackFast, false, approve575))
		if !strings.Contains(out.Failure, "exited with code 3") || out.Detail.Target != "26.7.5" {
			t.Fatalf("outcome %+v", out)
		}
	})
	t.Run("after it installed the release, whatever pkg said at the end", func(t *testing.T) {
		r := enrolledRig(t, func(d *simDevice) { d.execFailsAfterInstalling = true })
		out := r.run(advancePayload(TrackFast, false, approve575))
		if out.Failure == "" || out.Detail.Target != "26.7.5" {
			t.Fatalf("want a failure naming the release, got %+v", out)
		}
		if r.dev.Core() != "26.7.5" {
			t.Fatalf("the box is not in the state under test: core %s", r.dev.Core())
		}
	})
	t.Run("when the release cannot be read to tell", func(t *testing.T) {
		r := enrolledRig(t, func(d *simDevice) { d.execLockRefusal, d.installedErrAfterRun = true, true })
		out := r.run(advancePayload(TrackFast, false, approve575))
		if out.Failure == "" {
			t.Fatalf("want the failure of an exit that cannot be shown harmless, got %+v", out)
		}
	})
}

func TestLockRefusalReadsPkgsOwnWords(t *testing.T) {
	for output, want := range map[string]bool{
		"pkg: Cannot get an exclusive lock on a database, it is locked by another process": true,
		"pkg: Cannot get a read lock on a database, it is locked by another process\n":     true,
		"pkg: sqlite error -- database is locked":                                          true,
		"PKG: CANNOT GET AN ADVISORY LOCK, IT IS LOCKED BY ANOTHER PROCESS":                true,
		"pkg: Unable to update repository OPNsense":                                        false,
		"pkg: upgrade failed\nsecond line":                                                 false,
		"":                                                                                 false,
	} {
		if got := lockRefusal(output); got != want {
			t.Errorf("lockRefusal(%q) = %v, want %v", output, got, want)
		}
	}
}
