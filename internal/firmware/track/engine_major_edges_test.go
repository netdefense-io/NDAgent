package track

import (
	"context"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/firmware"
)

// The edit sites of the series upgrade in the engine that serves every advance:
// the late-dispatch hold, the answer of a step that did not choose the hop, the
// record a job keeps across the reboots, the lifetimes and the waits that follow the
// payload.

// A1: the signed expiry has to hold the step's work, or the answer is
// held_late_dispatch before anything is read or changed.
func TestAdvance_ALateDispatchIsHeldBeforeAnythingIsReadOrChanged(t *testing.T) {
	type tc struct {
		name  string
		major bool
		left  time.Duration
		held  bool
	}
	for _, c := range []tc{
		{"a minor step with 7 minutes left", false, 7 * time.Minute, true},
		{"a minor step with 9 minutes left", false, 9 * time.Minute, false},
		{"a step that carries a major with 59 minutes left", true, 59 * time.Minute, true},
		{"a step that carries a major with 61 minutes left", true, 61 * time.Minute, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			var r *rig
			var p Payload
			if c.major {
				r = hopRig(t)
				r.dev.do(func(d *simDevice) { d.majorOffered = "" })
				p = hopPayload(approveFinalHotfix)
			} else {
				r = enrolledRig(t)
				p = advancePayload(TrackFast, true, map[string]string{"26.7": "26.7.3"})
			}
			mark := len(r.dev.Calls())
			out := r.runUntil(p, time.Now().Add(c.left))
			if c.held {
				// The hold is the ordinary step's even for a payload that carries a major:
				// the step has not chosen the hop.
				wantOrdinary(t, wantResult(t, out, OutcomeHeld, ReasonHeldLateDispatch))
				if calls := r.dev.Calls()[mark:]; len(calls) != 0 {
					t.Errorf("calls %v: the hold comes before anything is read or changed", calls)
				}
				return
			}
			if out.Result == nil || out.Result.Reason == ReasonHeldLateDispatch {
				t.Fatalf("held for a late dispatch with %v left: %+v", c.left, out)
			}
			if len(r.dev.Calls()) == mark {
				t.Error("the step read nothing")
			}
		})
	}
}

// A3: a device that is already on the series a step asks for (an answer that was
// lost, a major done outside NetDefense) continues as an ordinary minor step toward
// approved[major]. It chose no hop, so its answers carry no kind and no notes.
func TestAdvance_AStepForTheSeriesTheDeviceIsAlreadyOnIsAnOrdinaryMinorStep(t *testing.T) {
	major := func(approved map[string]string) Payload {
		p := advancePayload(TrackFast, true, approved)
		p.Major = "26.7"
		return p
	}

	t.Run("at the target", func(t *testing.T) {
		r := enrolledRig(t)
		res := wantResult(t, r.run(major(map[string]string{"26.7": "26.7.3"})), OutcomeNoop, ReasonAtOrAboveTarget)
		wantOrdinary(t, res)
		wantVersions(t, res, "26.7.3_11", "26.7.3_11", "26.7.3", "26.7.3_11")
		if r.dev.posts() != 0 {
			t.Error("a hop was requested for a device that is on the series")
		}
	})

	t.Run("behind the target by a hotfix", func(t *testing.T) {
		r := enrolledRig(t, onlyHotfixes, func(d *simDevice) {
			d.core = "26.7.3_8"
			d.pkgs["opnsense"] = "26.7.3_8"
			d.pkgs["curl"] = "8.20.0"
		})
		res := wantResult(t, r.run(major(map[string]string{"26.7": "26.7.3"})), OutcomeSuccess, ReasonApplied)
		wantOrdinary(t, res)
		wantVersions(t, res, "26.7.3_8", "26.7.3_11", "26.7.3", "26.7.3_11")
	})
}

// A3: no row of the hop table starts at the installed series: an ordinary hold.
func TestAdvance_AMajorTheHopTableHasNoRowForIsHeldAsTheOrdinaryStep(t *testing.T) {
	saved := hops
	defer func() { hops = saved }()
	r := hopRig(t)
	hops = nil // the agent's table has no pair for 26.1
	wantOrdinary(t, wantResult(t, r.run(hopPayload(approveFinalHotfix)), OutcomeHeld, ReasonHeldUnexpectedPlan))
	if r.dev.posts() != 0 {
		t.Error("a hop was requested without a row")
	}
}

// A step that carried `major` but took the minor path (a hotfix landed in the pinned
// directory after the window) fails on the approved minor, with no kind: the
// control plane records it as the MINOR row it is, and the minor rules judge it.
func TestAdvance_AFailureOnTheMinorPathOfAStepThatCarriesMajorKeepsTheApprovedMinor(t *testing.T) {
	r := hopRig(t, onlyHotfixes, func(d *simDevice) {
		d.core = "26.1.11_8"
		d.pkgs["opnsense"] = "26.1.11_8"
	})
	r.dev.do(func(d *simDevice) { d.updateFails = true })

	out := r.run(hopPayload(map[string]string{"26.1": "26.1.11"}))

	if out.Failure == "" {
		t.Fatalf("want a failure, got %+v", out)
	}
	if out.Detail.Target != "26.1.11" || out.Detail.Kind != "" || len(out.Detail.Notes) != 0 {
		t.Errorf("detail %+v: the failure of the minor path names the approved minor and no hop", out.Detail)
	}
	if r.dev.posts() != 0 {
		t.Error("a hop was requested")
	}
}

// opFromJob restores what the dispatch said, so that an answer built after the
// reboots echoes it: the series the payload carried, and for a hop that was
// requested the kind, the series as its target and the notes its attempt found.
func TestOpFromJob_RestoresTheDispatchAndTheHopsKindAndNotes(t *testing.T) {
	r := newRig(t)
	row := Row{TaskID: "101", StartedAt: time.Now()}
	hop := Job{
		Action: ActionAdvance, Track: TrackFast, Approved: map[string]string{"26.1": "26.1.11_10"}, Reboot: true,
		Phase: PhaseTriggered, Major: "26.7", Target: "26.1.11_10", From: "26.1.11_10",
		StartedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(2 * time.Hour).Unix(),
		Notes: []string{NoteBootEnvironmentMade, NoteThirdPartyPackage},
	}
	major := firmware.NewMeta("major", true, "26.1.11_10", nil, 0, time.Now(), time.Now().Add(2*time.Hour))
	hop.Upgrade = &major

	o := r.eng.opFromJob(hop, row)
	if o.in.Payload.Major != "26.7" || o.in.Payload.Action != ActionAdvance || !o.in.Payload.Reboot {
		t.Errorf("payload %+v", o.in.Payload)
	}
	if o.kind != KindMajor || o.target != "26.7" || !equal(o.notes, hop.Notes) {
		t.Errorf("kind %q target %q notes %v: a hop that was requested answers as the hop", o.kind, o.target, o.notes)
	}

	// A step that carried `major` and took the minor path, and one that held before it
	// recorded the run, answer as the ordinary step.
	minor := hop
	minorMeta := firmware.NewMeta("minor", true, "26.1.11_10", nil, 0, time.Now(), time.Now().Add(20*time.Minute))
	minor.Upgrade = &minorMeta
	untriggered := hop
	untriggered.Phase, untriggered.Upgrade = PhaseStarted, nil
	for name, job := range map[string]Job{"the minor path": minor, "a hold before the record": untriggered} {
		o := r.eng.opFromJob(job, row)
		if o.in.Payload.Major != "26.7" {
			t.Errorf("%s: the payload's major is restored for the validator: %+v", name, o.in.Payload)
		}
		if o.kind != "" || len(o.notes) != 0 || o.target != "26.1.11_10" {
			t.Errorf("%s: kind %q target %q notes %v", name, o.kind, o.target, o.notes)
		}
	}
}

// DefaultExpiry and NewJob follow the payload, not the action: an advance that
// carries `major` has the series upgrade's lifetime, and the job copies the series
// so that whoever settles the row after a restart can restore the dispatch.
func TestLifetimesAndTheJobFollowThePayload(t *testing.T) {
	if MajorAdvanceTTL != 120*time.Minute || majorWork != 60*time.Minute || advanceWork != 8*time.Minute {
		t.Errorf("series upgrade %v, its work %v, a minor's work %v", MajorAdvanceTTL, majorWork, advanceWork)
	}
	t0 := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	for name, tc := range map[string]struct {
		p    Payload
		want time.Duration
		work time.Duration
	}{
		"a minor advance":         {Payload{Action: ActionAdvance}, AdvanceTTL, advanceWork},
		"an advance with a major": {Payload{Action: ActionAdvance, Major: "26.7"}, MajorAdvanceTTL, majorWork},
		"an enroll":               {Payload{Action: ActionEnroll}, EnrollTTL, enrollWork},
		"an unenroll":             {Payload{Action: ActionUnenroll}, EnrollTTL, enrollWork},
	} {
		if got := DefaultExpiry(tc.p, t0); !got.Equal(t0.Add(tc.want)) {
			t.Errorf("%s: expires %v, want %v", name, got.Sub(t0), tc.want)
		}
		o := &op{in: Input{Payload: tc.p, Expires: t0}}
		if o.work() != tc.work || !o.updateLimit().Equal(t0.Add(-tc.work)) {
			t.Errorf("%s: work %v, limit %v before the expiry", name, o.work(), t0.Sub(o.updateLimit()))
		}
	}
	job := NewJob(Payload{Action: ActionAdvance, Track: TrackFast, Reboot: true, Major: "26.7"}, t0, t0.Add(MajorAdvanceTTL))
	if job.Major != "26.7" || job.Phase != PhaseStarted {
		t.Errorf("job %+v", job)
	}
	if NewJob(Payload{Action: ActionAdvance}, t0, t0).Major != "" {
		t.Error("a step without a major left one in its job")
	}
}

// The wait for the firmware API never goes into the time the step needs for its work,
// which for a step that carries `major` is the series upgrade's.
func TestAwaitAPI_FollowsTheWorkOfTheStep(t *testing.T) {
	reads := func(r *rig, p Payload, left time.Duration) int {
		clock := r.simulateTime()
		r.dev.do(func(d *simDevice) { d.settingsFailures = 1 << 20 })
		var before int
		r.dev.do(func(d *simDevice) { before = d.settingsReads })
		r.runUntil(p, clock.Now().Add(left))
		var after int
		r.dev.do(func(d *simDevice) { after = d.settingsReads })
		return after - before
	}
	slack := 5 * time.Millisecond // what is left of the expiry beyond the work, against an API wait of 25 ms

	t.Run("a step that carries a major", func(t *testing.T) {
		p := hopPayload(approveFinalHotfix)
		tight := reads(hopRig(t), p, majorWork+slack)
		roomy := reads(hopRig(t), p, majorWork+20*time.Minute)
		if tight >= 15 || roomy < 20 {
			t.Errorf("%d reads with %v to spare, %d with 20 minutes: the wait follows what the step needs", tight, slack, roomy)
		}
	})
	t.Run("a minor step", func(t *testing.T) {
		p := advancePayload(TrackFast, true, map[string]string{"26.7": "26.7.3"})
		tight := reads(enrolledRig(t), p, advanceWork+slack)
		roomy := reads(enrolledRig(t), p, advanceWork+20*time.Minute)
		if tight >= 15 || roomy < 20 {
			t.Errorf("%d reads with %v to spare, %d with 20 minutes", tight, slack, roomy)
		}
	})
}

// The line that proves a run started follows the run's mode: a series upgrade's
// launcher prints ***GOT REQUEST TO UPGRADE***, an update's ***GOT REQUEST TO UPDATE***.
func TestRequestMarkerFollowsTheModeOfTheRun(t *testing.T) {
	for mode, want := range map[string]string{
		"major": "***GOT REQUEST TO UPGRADE***",
		"minor": "***GOT REQUEST TO UPDATE***",
		"":      "***GOT REQUEST TO UPDATE***",
	} {
		if got := requestMarker(mode); got != want {
			t.Errorf("mode %q: marker %q, want %q", mode, got, want)
		}
	}
}

// otherJobEnded reads the installed release with the bounded retry finishApplied has:
// an API that is settling at that very moment must not make the device decide a run
// that never started.
func TestAdvance_AReleaseThatCannotBeReadWhenAnotherJobsEndIsSeenIsReadAgain(t *testing.T) {
	foreign := foreignCheckMarker + "\nCurrently running OPNsense at now\nFetching changelog information... done\n***DONE***\n"
	r := enrolledRig(t, aHotfixWindow, func(d *simDevice) { d.updateDropped = true })
	dev := &scriptedBackend{
		simDevice: r.dev,
		progress:  []progressAnswer{{err: errSim}, {err: errSim}, {status: "done", log: foreign}, {status: "done", log: foreign}},
		running:   []firmware.RunState{firmware.RunBusy, firmware.RunBusy, firmware.RunBusy, firmware.RunReady},
		onArm:     func(d *simDevice) { d.installedFailures = 2 },
	}
	r.eng = r.engineOver(dev)

	out := r.eng.Execute(context.Background(), Input{TaskID: "101", Payload: advancePayload(TrackFast, true, approve573), Started: r.now()})
	r.checkOutcome(advancePayload(TrackFast, true, approve573), out)

	wantResult(t, out, OutcomeHeld, ReasonHeldFirmwareBusy)
	if r.dev.Flavour() != pinAt573 {
		t.Errorf("flavour %q: the pin should be back where it was", r.dev.Flavour())
	}
}

// An offered major no longer holds an enroll: the pin at the installed release is
// right for a device at the final build, and the offer is information.
func TestEnroll_AnOfferedMajorIsNoReasonToHold(t *testing.T) {
	r := newRig(t, finalBuild26)
	res := wantResult(t, r.run(enrollPayload(TrackFast)), OutcomeSuccess, ReasonEnrolled)
	if res.Drift || res.ReinstallEntries != 0 || res.Kind != "" {
		t.Errorf("result %+v: the offer is neither a drift nor a reinstall, and an enroll carries no kind", res)
	}
	if got := r.dev.Flavour(); got != "26.1/MINT/26.1.11/latest" {
		t.Errorf("flavour %q", got)
	}
}

// The series upgrade's figures, pinned literally: a test that took them from the
// constants would follow any change of them.
func TestMajorFigures(t *testing.T) {
	if hopBackoffStreak != 2 || hopBackoff != 7*24*time.Hour {
		t.Errorf("back-off after %d aborts for %v: two attempts in a row, seven days (provisional)", hopBackoffStreak, hopBackoff)
	}
	if needFloor != 3.25*(1<<30) || needMargin != 512<<20 || rootNeed != 1<<30 {
		t.Errorf("floor %d, margin %d, root %d: 3.25 GiB, 512 MiB and 1 GiB", needFloor, needMargin, rootNeed)
	}
	if bootEnvironmentTries != 20 {
		t.Errorf("names tried for the boot environment: %d", bootEnvironmentTries)
	}
}
