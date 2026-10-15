package track

import (
	"context"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/firmware"
)

// The crash cases: what the agent that comes back decides from the box and the
// record the task left. The simulator's box keeps running, or stops, or restarts as
// each case says; the agent is stopped where the case stops it.

// hopCutAt runs a step until the engine reaches the named method of the simulated
// box and stops the agent there, as a reboot or a power cut does. It returns the job
// the task left on its row.
func hopCutAt(t *testing.T, r *rig, p Payload, at string) Job {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	fired := false
	r.dev.onCall(at, func(*simDevice) {
		if !fired {
			fired = true
			cancel()
		}
	})
	out := r.runCtx(ctx, p)
	if !out.Aborted {
		t.Fatalf("the cut at %s should leave the task alone, got %+v", at, out)
	}
	return r.jobs[len(r.jobs)-1]
}

// agentBack is the agent that comes back, asked about the row.
func (r *rig) agentBack(job Job) (*Outcome, bool) {
	return r.newEngine().Resolve(context.Background(), job, startedRow())
}

// orderOf is the index of the first call with the prefix after from, or -1.
func orderOf(calls []string, prefix string, from int) int {
	for i := from; i < len(calls); i++ {
		if len(calls[i]) >= len(prefix) && calls[i][:len(prefix)] == prefix {
			return i
		}
	}
	return -1
}

// --- the agent stopped before the request was made ------------------------------------

// Before A4.11 has recorded the run the job is `started`: the row is held as the
// ordinary step, with no kind and no notes. A boot environment made by A4.10 before the
// stop is then on the box and in the agent's log only, and the next attempt finds its
// name taken.
func TestMajorCrash_AnAgentStoppedBeforeTheRunWasRecordedHoldsAsTheOrdinaryStep(t *testing.T) {
	for name, at := range map[string]string{
		"in the check of the space":                 "disk-free",
		"right after the boot environment was made": "be-create",
	} {
		t.Run(name, func(t *testing.T) {
			r := hopRig(t)
			p := hopPayload(approveFinalHotfix)
			job := hopCutAt(t, r, p, at)
			if job.Phase != PhaseStarted || job.Upgrade != nil || job.Major != "26.7" || len(job.Notes) != 0 {
				t.Fatalf("job %+v: nothing of the hop path is recorded as run", job)
			}
			out, done := r.agentBack(job)
			if !done {
				t.Fatal("not resolved")
			}
			r.checkOutcome(p, out)
			wantOrdinary(t, wantResult(t, out, OutcomeHeld, ReasonHeldCheckFailed))
			if r.dev.posts() != 0 {
				t.Errorf("%d requests", r.dev.posts())
			}
			if got := r.dev.writes(); len(got) != 0 {
				t.Errorf("writes %v", got)
			}
			if st := r.state(); st.Pending != nil {
				t.Errorf("pending %+v", st.Pending)
			}
		})
	}
}

func TestMajorCrash_ABootEnvironmentMadeBeforeAStopMakesTheNextAttemptTakeTheNextName(t *testing.T) {
	r := hopRig(t)
	p := hopPayload(approveFinalHotfix)
	job := hopCutAt(t, r, p, "be-create")
	if _, done := r.agentBack(job); !done {
		t.Fatal("not resolved")
	}
	r.dev.do(func(d *simDevice) {
		if len(d.hop.bes) != 1 || d.hop.bes[0].Name != "ndagent-pre-26.7" {
			t.Fatalf("environments %+v", d.hop.bes)
		}
		d.hop.stage0 = "abort"
	})
	r.hopWants(t, ReasonHeldUpgradeAborted, NoteBootEnvironmentMade)
	r.dev.do(func(d *simDevice) {
		if len(d.hop.bes) != 2 || d.hop.bes[1].Name != "ndagent-pre-26.7-2" {
			t.Errorf("environments %+v: the agent never removes one, and the next takes the next name", d.hop.bes)
		}
	})
}

// After A4.11 the job is triggered and the hop is the row's: the hold is the hop's,
// with its kind and its notes. The request never reached OPNsense: the box has not
// restarted, nothing runs, and its progress log holds no request of an upgrade.
func TestMajorCrash_AnAgentStoppedBeforeTheRequestReachedOPNsenseHoldsAsTheHop(t *testing.T) {
	r := hopRig(t)
	p := hopPayload(approveFinalHotfix)
	job := hopCutAt(t, r, p, "progress-idle")
	if job.Phase != PhaseTriggered || job.Upgrade == nil || job.Upgrade.Mode != "major" {
		t.Fatalf("job %+v", job)
	}
	if st := r.state(); st.Pending == nil || !st.Pending.Triggered {
		t.Fatalf("pending %+v", st.Pending)
	}
	r.dev.do(func(d *simDevice) {
		if d.updating || d.hop.run != nil {
			t.Fatal("the request reached OPNsense")
		}
	})

	out, done := r.agentBack(job)
	if !done {
		t.Fatal("not resolved")
	}
	r.checkOutcome(p, out)
	wantHop(t, wantResult(t, out, OutcomeHeld, ReasonHeldCheckFailed), NoteBootEnvironmentMade)
	if st := r.state(); st.Pending != nil || st.PinnedFlavour != "26.1/MINT/26.1.11/latest" {
		t.Errorf("record %+v: the move is unmarked and the pin is where it was", st)
	}
	if got := r.dev.writes(); len(got) != 0 {
		t.Errorf("writes %v: the hop wrote nothing, so there is nothing to put back", got)
	}
	if r.dev.count("clear-cache") != 0 {
		t.Error("a request that never ran leaves nothing to clean")
	}
}

// --- the agent stopped while stage 0 runs and the box is up ------------------------------

// OPNsense's job is detached and goes on without the agent. The agent that comes back
// waits while the backend is busy, and settles the row from the box when it is over.
func TestMajorCrash_AnAgentStoppedDuringStage0WaitsAndSettlesFromTheBox(t *testing.T) {
	r := hopRig(t)
	p := hopPayload(approveFinalHotfix)
	job := hopCutAt(t, r, p, "progress")
	r.dev.do(func(d *simDevice) {
		if !d.updating {
			t.Fatal("stage 0 should be running")
		}
	})

	back := r.newEngine()
	if out, done := back.Resolve(context.Background(), job, startedRow()); done {
		t.Fatalf("resolved while OPNsense was busy: %+v", out)
	}
	if r.dev.count("clear-cache") != 0 || len(r.dev.writes()) != 0 {
		t.Errorf("calls %v: nothing is touched while the box works", r.dev.Calls())
	}

	// The box goes on by itself: the kernel, then three reboots.
	r.dev.do(func(d *simDevice) {
		d.updating, d.hop.run = false, nil
		d.hop.markers = Markers{Base: true, Pkgs: true}
		d.land()
	})
	out, done := back.Resolve(context.Background(), job, startedRow())
	if !done {
		t.Fatal("not resolved")
	}
	r.checkOutcome(p, out)
	res := wantResult(t, out, OutcomeSuccess, ReasonApplied)
	wantHop(t, res, NoteBootEnvironmentMade)
	wantVersions(t, res, "26.1.11_10", "26.7.1_1", "26.7", "26.7.1_1")
}

// --- the box restarted without completing stage 0 -------------------------------------

func TestMajorCrash_APowerCutBeforeTheUpgradeLandedIsHeldAsAbortedAfterTheLogsWereRead(t *testing.T) {
	later := time.Now().Add(time.Hour)
	earlier := time.Now().Add(-24 * time.Hour)
	for name, leftover := range map[string]func(*simDevice){
		"before the markers exist: a partial download, the boot's empty /tmp": func(d *simDevice) {
			d.hop.workDirLeft, d.hop.workDirBytes = true, 336068608
		},
		"a moment after the extraction: the markers lost with the last transaction group": func(d *simDevice) {
			d.hop.setsDirBusy, d.hop.workDirLeft, d.hop.workDirBytes = true, true, 1244208<<10
			d.hop.updateLog = LogFile{Exists: true, ModTime: earlier, Text: "the previous update"}
		},
		"the refused stage P: pkg refuses the new ABI over the old base": func(d *simDevice) {
			d.hop.setsDirBusy = true
			d.hop.upgradeLog = LogFile{Exists: true, ModTime: later, Text: "pkg: wrong architecture: FreeBSD:15:amd64 instead of FreeBSD:14:amd64"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := hopRig(t)
			p := hopPayload(approveFinalHotfix)
			job := hopCutAt(t, r, p, "progress")
			r.dev.do(func(d *simDevice) {
				d.updating, d.hop.run = false, nil
				d.boot += 300       // the box restarted
				d.progressText = "" // and its /tmp was cleared
				leftover(d)
			})
			mark := len(r.dev.Calls())

			out, done := r.agentBack(job)
			if !done {
				t.Fatal("not resolved")
			}
			r.checkOutcome(p, out)
			wantHop(t, wantResult(t, out, OutcomeHeld, ReasonHeldUpgradeAborted), NoteBootEnvironmentMade)

			if ha := r.state().HopAborts; ha == nil || ha.Streak != 1 {
				t.Errorf("aborts %+v", ha)
			}
			if st := r.state(); st.Pending != nil {
				t.Errorf("pending %+v", st.Pending)
			}
			calls := r.dev.Calls()[mark:]
			clean := orderOf(calls, "clear-cache", 0)
			read := orderOf(calls, "stage-state", 0)
			if clean < 0 || read < 0 || read > clean {
				t.Errorf("calls %v: every log is read before the cache is emptied", calls)
			}
			r.dev.do(func(d *simDevice) {
				if d.hop.workDirLeft || d.hop.setsDirBusy || d.hop.markers.Any() {
					t.Errorf("the cache was left as it was: %+v", d.hop)
				}
			})
		})
	}
}

// The logs are read before the cleanup, because opnsense-update -es empties the whole
// directory: a disk-full text that only the .update.log keeps (the progress log in
// /tmp went with the reboot) would otherwise be lost, and the attempt counted as an
// abort and backed off.
func TestMajorCrash_TheDiskFullTextOnlyTheUpdateLogKeepsStillMakesItAFullDisk(t *testing.T) {
	r := hopRig(t)
	p := hopPayload(approveFinalHotfix)
	job := hopCutAt(t, r, p, "progress")
	r.dev.do(func(d *simDevice) {
		d.updating, d.hop.run = false, nil
		d.boot += 300
		d.progressText = ""
		d.hop.workDirLeft, d.hop.workDirBytes = true, 1244208<<10
		d.hop.updateLog = LogFile{Exists: true, ModTime: time.Now().Add(time.Minute), Text: "tar: Error exit delayed from previous errors.\nNo space left on device"}
	})
	out, done := r.agentBack(job)
	if !done {
		t.Fatal("not resolved")
	}
	wantHop(t, wantResult(t, out, OutcomeHeld, ReasonHeldInsufficientSpace), NoteBootEnvironmentMade)
	if ha := r.state().HopAborts; ha != nil {
		t.Errorf("aborts %+v: a full disk is no abort", ha)
	}
	r.dev.do(func(d *simDevice) {
		if d.hop.workDirLeft {
			t.Error("the work directory was not cleared")
		}
	})
}

// A cleanup that cannot be made is a FAILED: a marker left in the cache would make
// the next reboot of any kind run stage P over the old base.
func TestMajorCrash_AnAbortWhoseCacheCannotBeEmptiedIsFailed(t *testing.T) {
	r := hopRig(t)
	p := hopPayload(approveFinalHotfix)
	job := hopCutAt(t, r, p, "progress")
	r.dev.do(func(d *simDevice) {
		d.updating, d.hop.run = false, nil
		d.boot += 300
		d.progressText = ""
		d.hop.clearCacheErr = errSim
	})
	out, done := r.agentBack(job)
	if !done || out.Failure == "" {
		t.Fatalf("want a failure, got done=%v %+v", done, out)
	}
	r.checkOutcome(p, out)
	if out.Detail.Kind != KindMajor || out.Detail.Target != "26.7" || !equal(out.Detail.Notes, []string{NoteBootEnvironmentMade}) {
		t.Errorf("detail %+v", out.Detail)
	}
}

// --- the landing ---------------------------------------------------------------------------

// A landed hop is a success whatever the number of boots: three, or four after a
// reset at the start of stage B.
func TestMajorCrash_ALandedHopWithFourBootsIsASuccess(t *testing.T) {
	r := hopRig(t)
	p := hopPayload(approveFinalHotfix)
	job := hopRebootedJob(t, r, p)
	r.dev.do(func(d *simDevice) { d.boot += 300 })

	out, done := r.agentBack(job)
	if !done {
		t.Fatal("not resolved")
	}
	r.checkOutcome(p, out)
	wantHop(t, wantResult(t, out, OutcomeSuccess, ReasonApplied), NoteBootEnvironmentMade)
}

// The API can be down for a while after the last reboot: a release that cannot be
// read leaves the row for the reconciler instead of failing it. Settings that stay
// unreadable do not: the answer is the landing's, and the round puts the pin right.
func TestMajorCrash_AnAPIThatIsNotUpAfterTheLastRebootLeavesTheRowUnsettled(t *testing.T) {
	r := hopRig(t)
	p := hopPayload(approveFinalHotfix)
	job := hopRebootedJob(t, r, p)
	r.dev.do(func(d *simDevice) { d.installedErrAfterRun = true })

	back := r.newEngine()
	if out, done := back.Resolve(context.Background(), job, startedRow()); done {
		t.Fatalf("settled with the API down: %+v", out)
	}
	if st := r.state(); st.Pending == nil || !st.Pending.Triggered {
		t.Fatalf("pending %+v: the row is still the hop's", st.Pending)
	}

	r.dev.do(func(d *simDevice) { d.installedErrAfterRun = false })
	out, done := back.Resolve(context.Background(), job, startedRow())
	if !done {
		t.Fatal("not resolved")
	}
	wantHop(t, wantResult(t, out, OutcomeSuccess, ReasonApplied), NoteBootEnvironmentMade)
}

func TestMajorCrash_SettingsThatStayUnreadableStillAnswerAppliedAndTheRoundRePins(t *testing.T) {
	r := hopRig(t)
	if _, err := r.store.Update(func(s *State) {
		s.HopAborts = &HopAborts{Series: "26.7", At: time.Now().Add(-time.Hour).Unix(), Streak: 1}
	}); err != nil {
		t.Fatal(err)
	}
	p := hopPayload(approveFinalHotfix)
	job := hopRebootedJob(t, r, p)
	r.dev.do(func(d *simDevice) { d.settingsFailuresAfterRun = 1 << 20 })

	out, done := r.agentBack(job)
	if !done {
		t.Fatal("not resolved")
	}
	r.checkOutcome(p, out)
	res := wantResult(t, out, OutcomeSuccess, ReasonApplied)
	wantHop(t, res, NoteBootEnvironmentMade)
	if res.PinnedVersion != "" {
		t.Errorf("pinned_version %q: the answer claims no pin the agent could not write", res.PinnedVersion)
	}
	if st := r.state(); st.Pending != nil || st.HopAborts != nil {
		t.Errorf("pending %+v aborts %+v: a hop that landed ends the streak whether or not the pin could be written", st.Pending, st.HopAborts)
	}

	r.dev.do(func(d *simDevice) { d.settingsFailuresAfterRun = 0 })
	r.eng.Tick(context.Background())
	if got := r.dev.Flavour(); got != "26.7/MINT/26.7.1/latest" {
		t.Errorf("flavour %q: the round puts the pin on the new series", got)
	}
}

// A stage that ended short is a FAILED that names the series, and leaves the system
// as it is: it is neither re-pinned nor counted as having reached the series until
// someone completes the upgrade.
func TestMajorCrash_AMixedSystemIsFailedAndLeftAloneUntilItIsWhole(t *testing.T) {
	r := hopRig(t)
	p := hopPayload(approveFinalHotfix)
	job := hopRebootedJob(t, r, p)
	// Stage P did not finish: the core is at the series, the packages marker is short
	// of it and still there.
	r.dev.do(func(d *simDevice) { d.hop.pkgs = "26.1.6_2"; d.hop.markers = Markers{Pkgs: true} })

	out, done := r.agentBack(job)
	if !done || out.Failure == "" {
		t.Fatalf("want a failure, got done=%v %+v", done, out)
	}
	r.checkOutcome(p, out)
	if out.Detail.Kind != KindMajor || out.Detail.Target != "26.7" || !equal(out.Detail.Notes, []string{NoteBootEnvironmentMade}) {
		t.Errorf("detail %+v: a failed hop names the series, not the final minor", out.Detail)
	}
	st := r.state()
	if st.Landing == nil || st.Landing.Series != "26.7" || st.Pending != nil {
		t.Fatalf("record %+v: the failure leaves the landing note", st)
	}
	const oldPin = "26.1/MINT/26.1.11/latest"

	// The periodic round does not re-pin it.
	if got := r.eng.Reconcile(context.Background()); got != TickSettled {
		t.Errorf("round %v", got)
	}
	if got := r.dev.Flavour(); got != oldPin || len(r.dev.writes()) != 0 {
		t.Fatalf("flavour %q, writes %v: a mixed system is not re-pinned", got, r.dev.writes())
	}

	// The next window answers a hold, which is no evidence and clears no failure.
	next := advancePayload(TrackFast, true, map[string]string{"26.7": "26.7.1"})
	wantOrdinary(t, wantResult(t, r.run(next), OutcomeHeld, ReasonHeldUnexpectedPlan))
	if got := r.dev.Flavour(); got != oldPin {
		t.Fatalf("flavour %q", got)
	}

	// Someone completes the upgrade: the note is cleared and the pin follows the series.
	r.dev.do(func(d *simDevice) { d.hop.pkgs = "26.7"; d.hop.markers = Markers{} })
	if got := r.eng.Reconcile(context.Background()); got != TickSettled {
		t.Errorf("round %v", got)
	}
	st = r.state()
	if st.Landing != nil || st.PinnedFlavour != "26.7/MINT/26.7.1/latest" || !st.DriftPending {
		t.Errorf("record %+v: an upgrade completed outside the task is a drift on the new series", st)
	}
}

func TestMajorCrash_ALandingNoteOfAnotherSeriesIsClearedAndHoldsNothing(t *testing.T) {
	r := hopRig(t)
	if _, err := r.store.Update(func(s *State) { s.Landing = &Landing{Series: "25.7", At: time.Now().Unix()} }); err != nil {
		t.Fatal(err)
	}
	r.eng.Tick(context.Background())
	if st := r.state(); st.Landing != nil {
		t.Errorf("landing %+v: the installed series is not the note's", st.Landing)
	}
}

// An enroll starts the device over with the control plane: the note a landing that
// ended short left is forgotten with it, whether the pin is written anew (after an
// unenroll) or is in force (an enroll the control plane sent again, or for a device
// it moved to another track). The note stands for a mixed system, so the test makes
// one for real, and shows that the next window is held by it before the enroll.
func TestMajorCrash_TheEnrollClearsALandingNote(t *testing.T) {
	mixedSystem := func(t *testing.T) *rig {
		t.Helper()
		r := hopRig(t)
		p := hopPayload(approveFinalHotfix)
		job := hopRebootedJob(t, r, p)
		r.dev.do(func(d *simDevice) { d.hop.pkgs = "26.1.6_2"; d.hop.markers = Markers{Pkgs: true} })
		if out, done := r.agentBack(job); !done || out.Failure == "" {
			t.Fatalf("want a failure, got done=%v %+v", done, out)
		}
		if st := r.state(); st.Landing == nil || st.Landing.Series != "26.7" {
			t.Fatalf("record %+v: no landing note", st)
		}
		next := advancePayload(TrackFast, true, map[string]string{"26.7": "26.7.1"})
		wantOrdinary(t, wantResult(t, r.run(next), OutcomeHeld, ReasonHeldUnexpectedPlan))
		return r
	}

	t.Run("the pin is in force", func(t *testing.T) {
		r := mixedSystem(t)
		if st := r.state(); !st.Pinned || st.PinnedFlavour != r.dev.Flavour() {
			t.Fatalf("record %+v, flavour %q: the pin of the old series is still in force", st, r.dev.Flavour())
		}
		wantResult(t, r.run(enrollPayload(TrackFast)), OutcomeNoop, ReasonEnrolled)
		if st := r.state(); st.Landing != nil {
			t.Errorf("landing %+v", st.Landing)
		}
	})

	// The pin on the new series is what clears the note too (a re-pin on another series
	// forgets it): the enroll must forget it whether or not it could write that pin.
	t.Run("the pin is in force and cannot be written", func(t *testing.T) {
		r := mixedSystem(t)
		r.dev.do(func(d *simDevice) { delete(d.folders, "26.7.1") }) // the new series' directory is not on the mirror
		if out := r.run(enrollPayload(TrackFast)); out.Result == nil {
			t.Fatalf("got %+v", out)
		}
		if st := r.state(); st.Landing != nil {
			t.Errorf("landing %+v", st.Landing)
		}
	})

	t.Run("the pin is written anew after an unenroll", func(t *testing.T) {
		r := mixedSystem(t)
		wantResult(t, r.run(unenrollPayload(TrackFast)), OutcomeSuccess, ReasonUnenrolled)
		wantResult(t, r.run(enrollPayload(TrackFast)), OutcomeSuccess, ReasonEnrolled)
		if st := r.state(); st.Landing != nil {
			t.Errorf("landing %+v", st.Landing)
		}
	})
}

// --- Evaluate does not decide an aborted stage 0 --------------------------------------

// firmware.Evaluate fails a run whose log carries "The upgrade was aborted due to an
// error.", or waits for a release that did not change; neither is what an aborted
// stage 0 is. The answer is the hold whatever Evaluate would have said.
func TestMajorCrash_AStage0AbortIsAHoldWhateverEvaluateWouldHaveSaid(t *testing.T) {
	evaluate := func(job Job, d *simDevice, sentinel string) firmware.Verdict {
		meta := *job.Upgrade
		return firmware.Evaluate(context.Background(), firmware.Input{
			Meta: &meta, RowStartedAt: time.Now(), Sentinel: sentinel, Now: time.Now(), ProcessUptime: time.Hour,
		}, d.Probes())
	}

	t.Run("the box did not restart: the handler's process survived", func(t *testing.T) {
		r := hopRig(t, stage0Aborts)
		r.hopWants(t, ReasonHeldUpgradeAborted, NoteBootEnvironmentMade)
		job := r.jobs[len(r.jobs)-1]
		if v := evaluate(job, r.dev, "done"); v.Action != firmware.Fail {
			t.Fatalf("Evaluate says %+v: the control of this test is that it would have failed the run", v)
		}
	})

	t.Run("the box restarted: the agent that comes back", func(t *testing.T) {
		r := hopRig(t)
		p := hopPayload(approveFinalHotfix)
		job := hopCutAt(t, r, p, "progress")
		r.dev.do(func(d *simDevice) {
			d.updating, d.hop.run = false, nil
			d.boot += 300
			d.progressText = "Fetching packages-26.7-amd64.tar\nThe upgrade was aborted due to an error.\n***DONE***\n"
			d.hop.updateLog = LogFile{Exists: true, ModTime: time.Now().Add(time.Minute), Text: d.progressText}
		})
		if v := evaluate(job, r.dev, ""); v.Action != firmware.Fail {
			t.Fatalf("Evaluate says %+v: the control of this test is that it would have failed the run", v)
		}
		out, done := r.agentBack(job)
		if !done {
			t.Fatal("not resolved")
		}
		wantHop(t, wantResult(t, out, OutcomeHeld, ReasonHeldUpgradeAborted), NoteBootEnvironmentMade)
	})
}

// An operator's Update click on the dead pin writes "Partial update failure detected"
// into the .update.log of a landed box: a hop that landed is a success whatever the
// log says, or whether there is one.
func TestMajorCrash_ALandedHopIsASuccessWhateverTheUpdateLogSays(t *testing.T) {
	for name, log := range map[string]LogFile{
		"a failure text written after the landing": {Exists: true, ModTime: time.Now().Add(time.Minute), Text: "Partial update failure detected\n***DONE***\n"},
		"no .update.log at all (Part 9's landing)": {},
	} {
		t.Run(name, func(t *testing.T) {
			r := hopRig(t)
			p := hopPayload(approveFinalHotfix)
			job := hopRebootedJob(t, r, p)
			r.dev.do(func(d *simDevice) {
				d.hop.updateLog = log
				d.progressText = "Partial update failure detected\n***DONE***\n"
			})
			out, done := r.agentBack(job)
			if !done {
				t.Fatal("not resolved")
			}
			wantHop(t, wantResult(t, out, OutcomeSuccess, ReasonApplied), NoteBootEnvironmentMade)
		})
	}
}

// --- a panic -------------------------------------------------------------------------------

func TestMajorCrash_APanicAfterTheRequestAnswersNothingAndOneBeforeItStillHolds(t *testing.T) {
	logs := captureLogs(t)

	t.Run("before the request: the ordinary hold, no kind and no notes", func(t *testing.T) {
		r := hopRig(t)
		r.dev.onCall("disk-free", func(*simDevice) { panic("simulated bug") })
		p := hopPayload(approveFinalHotfix)
		wantOrdinary(t, wantResult(t, r.run(p), OutcomeHeld, ReasonHeldCheckFailed))
		if r.dev.posts() != 0 {
			t.Error("the request was made")
		}
	})

	t.Run("after the request: nothing is answered, the row stays for Resolve", func(t *testing.T) {
		before := panics(logs)
		r := hopRig(t)
		r.dev.onCall("progress", func(*simDevice) { panic("simulated bug") })
		p := hopPayload(approveFinalHotfix)
		out := r.run(p)
		if !out.Aborted {
			t.Fatalf("a hold would be a COMPLETED row while the upgrade runs on: %+v", out)
		}
		if panics(logs) != before+1 {
			t.Errorf("%d panics contained", panics(logs)-before)
		}
		job := r.jobs[len(r.jobs)-1]
		if job.Phase != PhaseTriggered {
			t.Fatalf("job %+v", job)
		}
		r.dev.onCall("progress", nil)
		r.dev.do(func(d *simDevice) { d.updating, d.hop.run = false, nil; d.land() })
		out, done := r.agentBack(job)
		if !done {
			t.Fatal("not resolved")
		}
		wantHop(t, wantResult(t, out, OutcomeSuccess, ReasonApplied), NoteBootEnvironmentMade)
	})
}

// --- the interval guard -----------------------------------------------------------------------

// The guard that repairs an interrupted operation leaves a triggered series upgrade
// alone for twice its row's lifetime: the minor's value would let the round after
// boot 3 repair a record whose row is still unresolved.
func TestMajorCrash_TheIntervalGuardLeavesATriggeredHopAloneForTwiceItsRowsLifetime(t *testing.T) {
	for name, tc := range map[string]struct {
		major   string
		age     time.Duration
		cleared bool
	}{
		"a hop inside twice its lifetime":                    {"26.7", 2*MajorAdvanceTTL - time.Hour, false},
		"a hop past twice its lifetime":                      {"26.7", 2*MajorAdvanceTTL + time.Hour, true},
		"a hop older than a minor's guard is still resolved": {"26.7", 3 * AdvanceTTL, false},
		"a minor past twice its lifetime":                    {"", 2*AdvanceTTL + time.Minute, true},
		"a minor inside twice its lifetime":                  {"", AdvanceTTL, false},
	} {
		t.Run(name, func(t *testing.T) {
			r := hopRig(t)
			if _, err := r.store.Update(func(s *State) {
				s.Pending = &Pending{Op: ActionAdvance, TaskID: "101", FromFlavour: s.PinnedFlavour, ToFlavour: s.PinnedFlavour,
					Triggered: true, Major: tc.major, StartedAt: time.Now().Add(-tc.age).Unix()}
			}); err != nil {
				t.Fatal(err)
			}
			r.eng.Tick(context.Background())
			if cleared := r.state().Pending == nil; cleared != tc.cleared {
				t.Errorf("pending cleared: %v, want %v", cleared, tc.cleared)
			}
		})
	}
}

// The progress log of an earlier minor update holds ***GOT REQUEST TO UPDATE***, which
// is not the request of a series upgrade: a hop whose request never reached OPNsense is
// told by the line of its own mode.
func TestMajorCrash_AnEarlierUpdatesLogIsNotThisUpgradesRequest(t *testing.T) {
	r := hopRig(t)
	p := hopPayload(approveFinalHotfix)
	job := hopCutAt(t, r, p, "progress-idle")
	r.dev.do(func(d *simDevice) {
		d.progressText = "***GOT REQUEST TO UPDATE***\nCurrently running OPNsense at now\n***DONE***\n"
	})

	out, done := r.agentBack(job)
	if !done {
		t.Fatal("not resolved")
	}
	r.checkOutcome(p, out)
	wantHop(t, wantResult(t, out, OutcomeHeld, ReasonHeldCheckFailed), NoteBootEnvironmentMade)
	if r.dev.count("clear-cache") != 0 {
		t.Error("a request that never ran leaves nothing to clean")
	}
}

// The installed release is read again with the state of the box right before the
// record: a core that changed while the step waited (a hotfix installed from the GUI)
// is not the release the check was made for.
func TestOfferIsReReadRightBeforeThePost_TheInstalledReleaseChanged(t *testing.T) {
	r := hopRig(t)
	reads := 0
	r.dev.onCall("stage-state", func(d *simDevice) {
		if reads++; reads == 2 { // the first read is A4.5's, the second is the record's
			d.core = "26.1.11_11"
			d.pkgs["opnsense"] = "26.1.11_11"
		}
	})
	res := wantResult(t, r.runUntil(hopPayload(approveFinalHotfix), time.Now().Add(MajorAdvanceTTL)), OutcomeHeld, ReasonHeldUnexpectedPlan)
	wantHop(t, res, NoteBootEnvironmentMade)
	if r.dev.posts() != 0 {
		t.Error("the request was made for a release that was not the one checked")
	}
	if st := r.state(); st.Pending != nil {
		t.Errorf("pending %+v", st.Pending)
	}
}

// A row the agent that comes back cannot settle waits for its time, and ends FAILED
// only then, naming the series: the upgrade was requested, so nothing says it did not
// start, and a hold would be a COMPLETED row for an upgrade nobody could account for.
func TestMajorCrash_ARowThatCannotBeConfirmedIsFailedOnlyPastItsDeadline(t *testing.T) {
	for name, cannot := range map[string]func(*simDevice){
		"the state of the box cannot be read": func(d *simDevice) { d.hop.stageErr = errSim },
		"OPNsense never frees its lock":       func(d *simDevice) { d.alwaysBusy = true },
	} {
		t.Run(name, func(t *testing.T) {
			r := hopRig(t)
			p := hopPayload(approveFinalHotfix)
			job := hopCutAt(t, r, p, "progress")
			r.dev.do(cannot)

			if out, done := r.agentBack(job); done {
				t.Fatalf("settled inside its time: %+v", out)
			}

			late := job
			upgrade := *job.Upgrade
			late.ExpiresAt = time.Now().Add(-time.Hour).Unix()
			upgrade.ExpiresAt = late.ExpiresAt
			late.Upgrade = &upgrade
			out, done := r.agentBack(late)
			if !done || out.Failure == "" {
				t.Fatalf("want a failure past the deadline, got done=%v %+v", done, out)
			}
			r.checkOutcome(p, out)
			if out.Detail.Kind != KindMajor || out.Detail.Target != "26.7" || !equal(out.Detail.Notes, []string{NoteBootEnvironmentMade}) {
				t.Errorf("detail %+v", out.Detail)
			}
			if st := r.state(); st.Pending != nil || st.Landing != nil {
				t.Errorf("record %+v: not confirmed is no mixed system", st)
			}
		})
	}
}
