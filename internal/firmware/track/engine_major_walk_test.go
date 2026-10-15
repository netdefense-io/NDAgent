package track

import (
	"context"
	"testing"
	"time"
)

// The walk: every end of the step sequence from A0 to A4.13, holds included, each
// answer held to the contract (rig.checkOutcome validates every result with
// ValidateResult against the dispatch, major included, and every failure detail with
// ValidateFailureDetail) and to the answer rule: an answer given before the step
// chose the series upgrade is the ordinary step's, with no kind and no notes; from
// there on every answer carries kind major, the series as its target_version and the
// notes found so far.

type walkCase struct {
	name string
	// setup builds the box (applied to the simulator before the enrollment), tweak
	// changes it after (a change that would have failed the enrollment).
	setup   func(*simDevice)
	tweak   func(*simDevice)
	payload Payload
	// run overrides how the task is run (test mode, a short expiry, a clock).
	run func(r *rig, p Payload) *Outcome

	outcome string
	reason  string
	hop     bool // the answer carries kind major
	notes   []string
	posts   int // requests for the upgrade made

	// check is for what is particular to the case.
	check func(t *testing.T, r *rig, res *Result)
}

func walkRun(r *rig, p Payload) *Outcome { return r.run(p) }

func TestMajor_EveryEndOfTheStepSequenceAnswersByTheAnswerRule(t *testing.T) {
	cases := []walkCase{
		// --- before the step has chosen the series upgrade: the ordinary step's answer ---
		{name: "A0 test mode", payload: hopPayload(approveFinalHotfix), outcome: OutcomeHeld, reason: ReasonHeldTestMode,
			run: func(r *rig, p Payload) *Outcome { return r.runInTestMode(context.Background(), p) }},
		{name: "A1 a signed expiry closer than the upgrade needs", payload: hopPayload(approveFinalHotfix),
			outcome: OutcomeHeld, reason: ReasonHeldLateDispatch,
			run: func(r *rig, p Payload) *Outcome { return r.runUntil(p, time.Now().Add(30*time.Minute)) },
			check: func(t *testing.T, r *rig, res *Result) {
				if n := len(r.dev.Calls()); n != 0 {
					t.Errorf("late dispatch answers before reading or changing anything: %v", r.dev.Calls())
				}
			}},
		{name: "A2 no entry for the installed series", payload: hopPayload(map[string]string{"25.7": "25.7.11"}),
			outcome: OutcomeNoop, reason: ReasonSeriesNotApproved},
		{name: "A3 the device is already on the series", setup: func(d *simDevice) {
			finalBuild26(d)
			d.series, d.core, d.updatePkg, d.sets = "26.7", "26.7.1_1", "26.7", "26.7"
			d.pkgs["opnsense"], d.abi = "26.7.1_1", "FreeBSD:15:amd64"
			d.folders = map[string]simCatalog{"26.7.1": {core: "26.7.1_1", update: "26.7", pkgs: map[string]string{"curl": "8.20.0", "pkg": "2.3.1_1"}, abi: "FreeBSD:15:amd64"}}
			d.latest, d.majorOffered = d.folders["26.7.1"], ""
		}, payload: hopPayload(map[string]string{"26.7": "26.7.1"}), outcome: OutcomeNoop, reason: ReasonAtOrAboveTarget},
		{name: "A3 no row of the hop table starts at the installed series", setup: func(d *simDevice) {
			finalBuild26(d)
			d.series, d.core, d.updatePkg, d.sets = "25.7", "25.7.11", "25.7.11", "25.7.11"
			d.pkgs["opnsense"], d.pkgs["opnsense-update"] = "25.7.11", "25.7.11"
			d.folders = map[string]simCatalog{"25.7.11": {core: "25.7.11", update: "25.7.11", pkgs: map[string]string{"curl": "8.20.0", "pkg": "2.3.1_1"}, abi: "FreeBSD:14:amd64"}}
			d.latest, d.majorOffered = d.folders["25.7.11"], ""
		}, payload: hopPayload(map[string]string{"25.7": "25.7.11"}), outcome: OutcomeHeld, reason: ReasonHeldUnexpectedPlan},

		{name: "A3 a payload with a major and reboot false (the parser refuses it, so does the engine)",
			payload: func() Payload { p := hopPayload(approveFinalHotfix); p.Reboot = false; return p }(),
			outcome: OutcomeHeld, reason: ReasonHeldUnexpectedPlan},

		// --- from the decision on: the hop's answer ---------------------------------------
		{name: "A4.0 the back-off after two aborts", payload: hopPayload(approveFinalHotfix), outcome: OutcomeHeld, reason: ReasonHeldUpgradeAborted, hop: true,
			tweak: func(d *simDevice) {},
			check: func(t *testing.T, r *rig, res *Result) {
				if calls := r.dev.Calls(); indexOfPrefix(calls, "repo-audit") >= 0 || indexOfPrefix(calls, "ha-member") >= 0 || indexOfPrefix(calls, "check") >= 0 {
					t.Errorf("the back-off answers without reading or changing anything: %v", calls)
				}
			}},
		{name: "A4.1 the box is not where the hop starts", payload: hopPayload(approveFinalHotfix), outcome: OutcomeHeld, reason: ReasonHeldUnexpectedPlan, hop: true,
			setup: func(d *simDevice) { finalBuild26(d); c := d.folders["26.1.11"]; c.abi = ""; d.folders["26.1.11"] = c },
			tweak: func(d *simDevice) { d.abi = "FreeBSD:13:amd64" }},
		{name: "A4.1 the target tree is not on the mirror", payload: hopPayload(approveFinalHotfix), outcome: OutcomeNoop, reason: ReasonTargetNotYetOffered, hop: true,
			tweak: func(d *simDevice) { d.hop.treeMissing = true }},
		{name: "A4.1 the mirror cannot be asked", payload: hopPayload(approveFinalHotfix), outcome: OutcomeHeld, reason: ReasonHeldCheckFailed, hop: true,
			tweak: func(d *simDevice) { d.hop.treeUnreachable = true }},
		{name: "A4.2 a member of an HA pair", payload: hopPayload(approveFinalHotfix), outcome: OutcomeHeld, reason: ReasonHeldHAMember, hop: true,
			tweak: func(d *simDevice) { d.hop.ha = true }},
		{name: "A4.2 the HA signals cannot be read", payload: hopPayload(approveFinalHotfix), outcome: OutcomeHeld, reason: ReasonHeldCheckFailed, hop: true,
			tweak: func(d *simDevice) { d.hop.haErr = errSim }},
		{name: "A4.4 the NetDefense repository is not laid out per ABI", payload: hopPayload(approveFinalHotfix), outcome: OutcomeHeld, reason: ReasonHeldAgentABIUnavailable, hop: true,
			tweak: func(d *simDevice) { d.hop.agentRepo = AgentRepo{Why: "flat url"} }},
		{name: "A4.4 the NetDefense repository has no tree for the new ABI", payload: hopPayload(approveFinalHotfix), outcome: OutcomeHeld, reason: ReasonHeldAgentABIUnavailable, hop: true,
			tweak: func(d *simDevice) { d.hop.agentRepo = AgentRepo{Nested: true, Why: "no tree"} }},
		{name: "A4.4 the probe fails", payload: hopPayload(approveFinalHotfix), outcome: OutcomeHeld, reason: ReasonHeldCheckFailed, hop: true,
			tweak: func(d *simDevice) { d.hop.agentRepoErr = errSim }},
		{name: "A4.5 the backend stays busy", payload: hopPayload(approveFinalHotfix), outcome: OutcomeHeld, reason: ReasonHeldFirmwareBusy, hop: true,
			tweak: func(d *simDevice) { d.alwaysBusy = true }},
		{name: "A4.5 an upgrade marker is left", payload: hopPayload(approveFinalHotfix), outcome: OutcomeHeld, reason: ReasonHeldRebootPending, hop: true,
			tweak: func(d *simDevice) { d.hop.markers = Markers{Pkgs: true} }},
		{name: "A4.5 the state of the box cannot be read", payload: hopPayload(approveFinalHotfix), outcome: OutcomeHeld, reason: ReasonHeldCheckFailed, hop: true,
			tweak: func(d *simDevice) { d.hop.stageErr = errSim }},
		{name: "A4.6 the check cannot use the mirror", payload: hopPayload(approveFinalHotfix), outcome: OutcomeHeld, reason: ReasonHeldCheckFailed, hop: true,
			tweak: func(d *simDevice) { d.checkFailsAs = "repository" }},
		{name: "A4.7 no offer", payload: hopPayload(approveFinalHotfix), outcome: OutcomeNoop, reason: ReasonTargetNotYetOffered, hop: true,
			tweak: func(d *simDevice) { d.majorOffered = "" }},
		{name: "A4.7 another series on offer", payload: hopPayload(approveFinalHotfix), outcome: OutcomeHeld, reason: ReasonHeldUnexpectedPlan, hop: true,
			tweak: func(d *simDevice) { d.majorOffered = "27.1" }},
		{name: "A4.7 the sets are not the three", payload: hopPayload(approveFinalHotfix), outcome: OutcomeHeld, reason: ReasonHeldUnexpectedPlan, hop: true,
			tweak: func(d *simDevice) { d.hop.sets = offerSets("26.7")[:2] }},
		{name: "A4.7 a downgrade in the plan", payload: hopPayload(approveFinalHotfix), outcome: OutcomeHeld, reason: ReasonHeldDowngradeRisk, hop: true,
			tweak: func(d *simDevice) { d.extraDowngrade = true }},
		{name: "A4.8 not enough free space", payload: hopPayload(approveFinalHotfix), outcome: OutcomeHeld, reason: ReasonHeldInsufficientSpace, hop: true,
			notes: []string{NoteThirdPartyRepository, NoteThirdPartyPackage},
			tweak: func(d *simDevice) {
				d.hop.disk.CacheFree = 3 << 30 // below 3.25 GiB
				d.hop.audit = RepoAudit{Repositories: []string{"Foreign"}, Packages: []string{"foo"}}
			}},
		{name: "A4.8 not enough free space on /", payload: hopPayload(approveFinalHotfix), outcome: OutcomeHeld, reason: ReasonHeldInsufficientSpace, hop: true,
			tweak: func(d *simDevice) { d.hop.disk.SplitRoot, d.hop.disk.RootFree = true, 512<<20 }},
		{name: "A4.8 the free space cannot be read", payload: hopPayload(approveFinalHotfix), outcome: OutcomeHeld, reason: ReasonHeldCheckFailed, hop: true,
			tweak: func(d *simDevice) { d.hop.diskErr = errSimDisk }},
		{name: "A4.12 the request errors and nothing started", payload: hopPayload(approveFinalHotfix), outcome: OutcomeHeld, reason: ReasonHeldCheckFailed, hop: true,
			notes: []string{NoteBootEnvironmentMade}, posts: 1,
			tweak: func(d *simDevice) { d.hop.upgradeErr = errSim }},
		{name: "A4.12 OPNsense does not accept the request", payload: hopPayload(approveFinalHotfix), outcome: OutcomeHeld, reason: ReasonHeldCheckFailed, hop: true,
			notes: []string{NoteBootEnvironmentMade}, posts: 1,
			tweak: func(d *simDevice) { d.hop.upgradeAnswer = "failed" }},
		{name: "A4.12 a foreign job drops the request twice", payload: hopPayload(approveFinalHotfix), outcome: OutcomeHeld, reason: ReasonHeldFirmwareBusy, hop: true,
			notes: []string{NoteBootEnvironmentMade}, posts: 1,
			tweak: aForeignJobAtTheUpdate(2, foreverBusy)},
		{name: "A4.13 stage 0 aborts and the box does not restart", payload: hopPayload(approveFinalHotfix), outcome: OutcomeHeld, reason: ReasonHeldUpgradeAborted, hop: true,
			notes: []string{NoteBootEnvironmentMade}, posts: 1,
			tweak: func(d *simDevice) { d.hop.stage0 = "abort" },
			check: func(t *testing.T, r *rig, res *Result) {
				if st := r.state(); st.HopAborts == nil || st.HopAborts.Streak != 1 || st.HopAborts.Series != "26.7" || st.Pending != nil {
					t.Errorf("record %+v (aborts %+v)", st, st.HopAborts)
				}
				if r.dev.count("clear-cache") != 1 {
					t.Errorf("the cache was not emptied once: %v", r.dev.Calls())
				}
			}},
		{name: "A4.13 stage 0 runs out of disk", payload: hopPayload(approveFinalHotfix), outcome: OutcomeHeld, reason: ReasonHeldInsufficientSpace, hop: true,
			notes: []string{NoteBootEnvironmentMade}, posts: 1,
			tweak: func(d *simDevice) { d.hop.stage0 = "diskfull" },
			check: func(t *testing.T, r *rig, res *Result) {
				if st := r.state(); st.HopAborts != nil {
					t.Errorf("a full disk adds nothing to the back-off: %+v", st.HopAborts)
				}
			}},
		{name: "A4.13 the cache cannot be emptied after an abort", payload: hopPayload(approveFinalHotfix), outcome: "", hop: true,
			notes: []string{NoteBootEnvironmentMade}, posts: 1,
			tweak: func(d *simDevice) { d.hop.stage0 = "abort"; d.hop.clearCacheErr = errSim }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var setup []func(*simDevice)
			if tc.setup != nil {
				setup = append(setup, tc.setup)
			} else {
				setup = append(setup, finalBuild26)
			}
			r := newRig(t, setup...)
			wantResult(t, r.run(enrollPayload(TrackFast)), OutcomeSuccess, ReasonEnrolled)
			r.jobs, r.dev.calls = nil, nil
			if tc.name == "A4.0 the back-off after two aborts" {
				if _, err := r.store.Update(func(s *State) {
					s.HopAborts = &HopAborts{Series: "26.7", At: time.Now().Add(-time.Hour).Unix(), Streak: 2}
				}); err != nil {
					t.Fatal(err)
				}
			}
			if tc.tweak != nil {
				r.dev.do(tc.tweak)
			}
			run := tc.run
			if run == nil {
				run = walkRun
			}
			out := run(r, tc.payload)

			if tc.outcome == "" { // a failure
				if out.Failure == "" {
					t.Fatalf("want a failure, got %+v", out)
				}
				if out.Detail.Kind != KindMajor || out.Detail.Target != "26.7" || !equal(out.Detail.Notes, tc.notes) {
					t.Errorf("failure detail %+v: a failed hop names the series with kind major and carries its notes", out.Detail)
				}
				if r.dev.posts() != tc.posts {
					t.Errorf("%d requests, want %d", r.dev.posts(), tc.posts)
				}
				return
			}
			res := wantResult(t, out, tc.outcome, tc.reason)
			if tc.hop {
				wantHop(t, res, tc.notes...)
			} else {
				wantOrdinary(t, res)
			}
			if r.dev.posts() != tc.posts {
				t.Errorf("%d requests for the upgrade, want %d: %v", r.dev.posts(), tc.posts, r.dev.Calls())
			}
			if got := r.dev.writes(); len(got) != 0 {
				t.Errorf("writes %v: the hop writes the pin once, after it landed", got)
			}
			if tc.posts == 0 {
				if st := r.state(); st.Pending != nil {
					t.Errorf("pending %+v: nothing was requested", st.Pending)
				}
			}
			if tc.check != nil {
				tc.check(t, r, res)
			}
		})
	}
}

// A4.9: the waits before it (the backend, the forced check) can have used the time
// the series upgrade needs. The signed expiry held majorWork on arrival (A1) and holds
// less now: nothing is made, not even the boot environment, and the answer is the
// hop's.
func TestMajor_TimeAgainAfterTheWaitsIsHeldAsLateDispatchBeforeAnythingIsMade(t *testing.T) {
	r := hopRig(t)
	clock := r.simulateTime(WithTiming(DefaultTiming()))
	r.dev.do(func(d *simDevice) { d.busyReads = 2 })

	out := r.runUntil(hopPayload(approveFinalHotfix), clock.Now().Add(majorWork+10*time.Second))

	res := wantResult(t, out, OutcomeHeld, ReasonHeldLateDispatch)
	wantHop(t, res)
	if r.dev.posts() != 0 || r.dev.count("be-create") != 0 {
		t.Errorf("calls %v: nothing is made once the time is short", r.dev.Calls())
	}
	if r.dev.count("disk-free") == 0 {
		t.Error("the hold came before the space was looked at: this is A1's, not A4.9's")
	}
	if st := r.state(); st.Pending != nil {
		t.Errorf("pending %+v", st.Pending)
	}
}

// A4.12: a request another firmware job's lock made OPNsense drop is asked again once,
// and only if the task still has the series upgrade's time once the backend is free.
// A task whose time went to waiting behind the other job holds, with the record
// unmarked: a step that runs past its expiry is counted against the series.
func TestMajor_ADroppedRequestWithNoTimeLeftToAskAgainIsHeldAsBusyAndUnmarked(t *testing.T) {
	r := hopRig(t)
	// The first request gets a long window to show that it started, which the foreign
	// job's lock keeps it from doing: by the time it is over, the task has less than the
	// series upgrade's time left.
	timing := DefaultTiming()
	timing.StartWindow = 5 * time.Minute
	clock := r.simulateTime(WithTiming(timing))
	r.dev.do(aForeignJobAtTheUpdateFor(1, 5))

	out := r.runUntil(hopPayload(approveFinalHotfix), clock.Now().Add(majorWork+2*time.Minute))

	res := wantResult(t, out, OutcomeHeld, ReasonHeldFirmwareBusy)
	wantHop(t, res, NoteBootEnvironmentMade)
	if r.dev.posts() != 1 {
		t.Errorf("%d requests: the second would run past the expiry", r.dev.posts())
	}
	if st := r.state(); st.Pending != nil || st.PinnedFlavour != "26.1/MINT/26.1.11/latest" {
		t.Errorf("record %+v: the move is forgotten and the pin where it was", st)
	}
	if last := r.jobs[len(r.jobs)-1]; last.Phase == PhaseTriggered || (last.Upgrade != nil && last.Upgrade.TriggeredAt != 0) {
		t.Errorf("job %+v: the record of the request is unmarked", last)
	}
	if got := r.dev.writes(); len(got) != 0 {
		t.Errorf("writes %v", got)
	}
}

// aForeignJobAtTheUpdateFor makes the next n update requests find a foreign firmware
// job holding OPNsense's lock for life reads of the backend.
func aForeignJobAtTheUpdateFor(n, life int) func(*simDevice) {
	return func(d *simDevice) { d.foreignOnUpdate, d.foreignLife = n, life }
}

// A4.12: a request another firmware job's lock made OPNsense drop is asked again once
// the lock is free, and the second request starts the upgrade. Between the two the
// state of the box is read again.
func TestMajor_ADroppedRequestIsAskedAgainOnABoxThatIsAsItWasAndTheSecondRunsTheUpgrade(t *testing.T) {
	r := hopRig(t)
	r.dev.do(aForeignJobAtTheUpdateFor(1, 3))
	p := hopPayload(approveFinalHotfix)

	job := hopRebootedJob(t, r, p)

	if r.dev.posts() != 2 {
		t.Fatalf("%d requests, want the dropped one and the one that ran", r.dev.posts())
	}
	if n := r.dev.count("stage-state"); n != 3 {
		t.Errorf("the state of the box was read %d times: at the markers, at the record, and before the second request", n)
	}
	if job.Phase != PhaseTriggered || job.Upgrade == nil || !job.Upgrade.RebootSeen {
		t.Fatalf("job %+v: the second request should have run the upgrade to its reboot", job)
	}
	out, done := r.agentBack(job)
	if !done {
		t.Fatal("not resolved")
	}
	r.checkOutcome(p, out)
	wantHop(t, wantResult(t, out, OutcomeSuccess, ReasonApplied), NoteBootEnvironmentMade)
}

// The same retry on a box the other job changed is not made: an upgrade marker it left
// would be resumed by any reboot, a release it installed is not the one the step
// was made for, and a state that cannot be read is no state. The record of the
// request is unmarked and the answer is the hop's hold.
func TestMajor_ADroppedRequestIsNotAskedAgainOnABoxAnotherJobChanged(t *testing.T) {
	for name, tc := range map[string]struct {
		change func(*simDevice)
		reason string
	}{
		"an upgrade marker was left": {func(d *simDevice) { d.hop.markers = Markers{Pkgs: true} }, ReasonHeldRebootPending},
		"the installed release changed": {func(d *simDevice) {
			d.core = "26.1.11_11"
			d.pkgs["opnsense"] = "26.1.11_11"
		}, ReasonHeldUnexpectedPlan},
		"the state of the box cannot be read": {func(d *simDevice) { d.hop.stageErr = errSim }, ReasonHeldCheckFailed},
	} {
		t.Run(name, func(t *testing.T) {
			r := hopRig(t)
			r.dev.do(aForeignJobAtTheUpdateFor(1, 3))
			first := true
			r.dev.onCall("upgrade", func(d *simDevice) {
				if first { // the other job does its work while the first request is dropped
					first = false
					tc.change(d)
				}
			})
			p := hopPayload(approveFinalHotfix)

			res := wantResult(t, r.run(p), OutcomeHeld, tc.reason)
			wantHop(t, res, NoteBootEnvironmentMade)

			if r.dev.posts() != 1 {
				t.Errorf("%d requests: the second one must not be made", r.dev.posts())
			}
			if st := r.state(); st.Pending != nil {
				t.Errorf("pending %+v: the record of the request is unmarked", st.Pending)
			}
			if last := r.jobs[len(r.jobs)-1]; last.Phase == PhaseTriggered || (last.Upgrade != nil && last.Upgrade.TriggeredAt != 0) {
				t.Errorf("job %+v", last)
			}
			if got := r.dev.writes(); len(got) != 0 {
				t.Errorf("writes %v", got)
			}
		})
	}
}
