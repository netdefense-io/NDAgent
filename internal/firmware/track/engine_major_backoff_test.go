package track

import (
	"context"
	"strings"
	"testing"
	"time"
)

// A series upgrade whose stage 0 aborts leaves the box as it was, so the next window
// would repeat the 1.1 GiB download and extraction. After two such attempts in a row
// the agent answers held_upgrade_aborted for seven days without reading or changing
// anything (A4.0).

func stage0Aborts(d *simDevice) { d.hop.stage0 = "abort" }

// hopWants runs the step of a window and asserts the hold it ends with.
func (r *rig) hopWants(t *testing.T, reason string, notes ...string) {
	t.Helper()
	res := wantResult(t, r.run(hopPayload(approveFinalHotfix)), OutcomeHeld, reason)
	wantHop(t, res, notes...)
}

func (r *rig) streak() int {
	if ha := r.state().HopAborts; ha != nil {
		return ha.Streak
	}
	return 0
}

// touchesTheBox lists the calls that read or change the box beyond the ordinary
// step's own: the series upgrade's checks and everything after them.
var touchesTheBox = []string{"upgrade", "check", "disk-free", "ha-member", "repo-audit", "agent-repo",
	"be-create", "be-find", "clear-cache", "clear-stale", "stage-state", "snapshot-supported", "set "}

func TestMajor_TwoAbortedAttemptsBackTheThirdOffWithoutTouchingTheBox(t *testing.T) {
	r := hopRig(t, stage0Aborts)
	r.simulateTime()

	r.hopWants(t, ReasonHeldUpgradeAborted, NoteBootEnvironmentMade)
	if st := r.state(); r.streak() != 1 || st.HopAborts.Series != "26.7" || st.Pending != nil || st.Landing != nil {
		t.Fatalf("record %+v, aborts %+v: the first abort counts one", st, st.HopAborts)
	}
	if n := r.dev.count("clear-cache"); n != 1 {
		t.Fatalf("%d cleanups: the cache is emptied once, after the logs were read", n)
	}

	r.hopWants(t, ReasonHeldUpgradeAborted, NoteBootEnvironmentMade)
	if r.streak() != 2 {
		t.Fatalf("streak %d, want 2", r.streak())
	}
	aborted := r.state().HopAborts.At
	r.dev.do(func(d *simDevice) {
		if len(d.hop.bes) != 2 || d.hop.bes[0].Name != "ndagent-pre-26.7" || d.hop.bes[1].Name != "ndagent-pre-26.7-2" {
			t.Errorf("boot environments %+v: a second attempt leaves a second copy under the next name", d.hop.bes)
		}
	})

	mark := len(r.dev.Calls())
	r.hopWants(t, ReasonHeldUpgradeAborted)
	for _, c := range r.dev.Calls()[mark:] {
		for _, prefix := range touchesTheBox {
			if strings.HasPrefix(c, prefix) {
				t.Errorf("call %q: the back-off answers without reading or changing anything", c)
			}
		}
	}
	if r.dev.posts() != 2 {
		t.Errorf("%d requests: the third attempt must not be made", r.dev.posts())
	}
	if ha := r.state().HopAborts; ha.Streak != 2 || ha.At != aborted {
		t.Errorf("aborts %+v: an answer of the back-off is no attempt, and must not push its end away", ha)
	}
}

func TestMajor_TheBackOffEndsAfterSevenDays(t *testing.T) {
	r := hopRig(t, stage0Aborts)
	clock := r.simulateTime()
	r.hopWants(t, ReasonHeldUpgradeAborted, NoteBootEnvironmentMade)
	r.hopWants(t, ReasonHeldUpgradeAborted, NoteBootEnvironmentMade)

	clock.Advance(hopBackoff - time.Hour)
	r.hopWants(t, ReasonHeldUpgradeAborted)
	if r.dev.posts() != 2 {
		t.Fatalf("%d requests: still inside the seven days", r.dev.posts())
	}

	clock.Advance(2 * time.Hour)
	r.hopWants(t, ReasonHeldUpgradeAborted, NoteBootEnvironmentMade)
	if r.dev.posts() != 3 {
		t.Fatalf("%d requests: after the seven days the next window tries again", r.dev.posts())
	}
	if r.streak() != 3 {
		t.Errorf("streak %d: the new abort counts", r.streak())
	}

	r.hopWants(t, ReasonHeldUpgradeAborted)
	if r.dev.posts() != 3 {
		t.Errorf("%d requests: the abort starts the seven days again", r.dev.posts())
	}
}

// A stage 0 that ran out of disk is not a persistent cause the agent can name: it is
// held_insufficient_space, adds nothing to the streak and leaves it as it was.
func TestMajor_ADiskFullAbortAddsNothingToTheStreak(t *testing.T) {
	r := hopRig(t, stage0Aborts)
	r.simulateTime()
	r.hopWants(t, ReasonHeldUpgradeAborted, NoteBootEnvironmentMade)
	first := r.state().HopAborts.At

	r.dev.do(func(d *simDevice) { d.hop.stage0 = "diskfull" })
	r.hopWants(t, ReasonHeldInsufficientSpace, NoteBootEnvironmentMade)
	if ha := r.state().HopAborts; ha == nil || ha.Streak != 1 || ha.At != first {
		t.Fatalf("aborts %+v: a full disk leaves the streak as it was", ha)
	}
	r.dev.do(func(d *simDevice) {
		if d.hop.workDirLeft {
			t.Error("the numbered work directory of the full disk was not cleared")
		}
		d.hop.stage0 = "abort"
	})

	r.hopWants(t, ReasonHeldUpgradeAborted, NoteBootEnvironmentMade)
	if r.streak() != 2 {
		t.Fatalf("streak %d, want 2: the disk-full attempt in between did not count", r.streak())
	}
	r.hopWants(t, ReasonHeldUpgradeAborted)
	if r.dev.posts() != 3 {
		t.Errorf("%d requests, want 3", r.dev.posts())
	}
}

func TestMajor_AStreakOfAnotherSeriesBacksNothingOff(t *testing.T) {
	r := hopRig(t, stage0Aborts)
	clock := r.simulateTime()
	if _, err := r.store.Update(func(s *State) {
		s.HopAborts = &HopAborts{Series: "25.7", At: clock.Now().Unix(), Streak: 5}
	}); err != nil {
		t.Fatal(err)
	}
	r.hopWants(t, ReasonHeldUpgradeAborted, NoteBootEnvironmentMade)
	if r.dev.posts() != 1 {
		t.Errorf("%d requests: the streak was another series'", r.dev.posts())
	}
	if ha := r.state().HopAborts; ha.Series != "26.7" || ha.Streak != 1 {
		t.Errorf("aborts %+v: the record starts over for the series asked for", ha)
	}
}

// The streak resets when a hop lands, when the installed series changes and at
// enroll. The enroll is the operator's way out: moving the device to Unmanaged and
// back runs an unenroll and an enroll.
func TestMajor_TheStreakIsClearedByTheOperatorsUnenrollAndEnroll(t *testing.T) {
	r := hopRig(t, stage0Aborts)
	r.simulateTime()
	r.hopWants(t, ReasonHeldUpgradeAborted, NoteBootEnvironmentMade)
	r.hopWants(t, ReasonHeldUpgradeAborted, NoteBootEnvironmentMade)

	wantResult(t, r.run(unenrollPayload(TrackFast)), OutcomeSuccess, ReasonUnenrolled)
	wantResult(t, r.run(enrollPayload(TrackFast)), OutcomeSuccess, ReasonEnrolled)
	if ha := r.state().HopAborts; ha != nil {
		t.Fatalf("aborts %+v: the enroll starts the record over", ha)
	}

	r.hopWants(t, ReasonHeldUpgradeAborted, NoteBootEnvironmentMade)
	if r.dev.posts() != 3 {
		t.Errorf("%d requests: the removed cause is tried at once", r.dev.posts())
	}
}

// An enroll for a pin that is in force is the control plane starting over as well: the
// device is not moved to Unmanaged and back, and the count of its aborted attempts is
// forgotten all the same.
func TestMajor_AnEnrollForAPinInForceEndsTheBackOff(t *testing.T) {
	r := hopRig(t, stage0Aborts)
	r.simulateTime()
	r.hopWants(t, ReasonHeldUpgradeAborted, NoteBootEnvironmentMade)
	r.hopWants(t, ReasonHeldUpgradeAborted, NoteBootEnvironmentMade)
	r.hopWants(t, ReasonHeldUpgradeAborted)
	if r.dev.posts() != 2 || r.streak() != 2 {
		t.Fatalf("%d requests, streak %d: the third attempt should have been backed off", r.dev.posts(), r.streak())
	}

	wantResult(t, r.run(enrollPayload(TrackFast)), OutcomeNoop, ReasonEnrolled)
	if ha := r.state().HopAborts; ha != nil {
		t.Fatalf("aborts %+v: the enroll starts the record over", ha)
	}

	r.hopWants(t, ReasonHeldUpgradeAborted, NoteBootEnvironmentMade)
	if r.dev.posts() != 3 {
		t.Errorf("%d requests: the removed cause is tried at once", r.dev.posts())
	}
}

func TestMajor_TheStreakIsClearedByALandedHop(t *testing.T) {
	r := hopRig(t)
	if _, err := r.store.Update(func(s *State) {
		s.HopAborts = &HopAborts{Series: "26.7", At: time.Now().Add(-time.Hour).Unix(), Streak: 1}
	}); err != nil {
		t.Fatal(err)
	}
	p := hopPayload(approveFinalHotfix)
	job := hopRebootedJob(t, r, p)
	if out, done := r.newEngine().Resolve(context.Background(), job, startedRow()); !done {
		t.Fatalf("not resolved: %+v", out)
	}
	if st := r.state(); st.HopAborts != nil || st.Landing != nil {
		t.Errorf("record %+v", st)
	}
}

func TestMajor_TheStreakIsClearedWhenTheInstalledSeriesChanges(t *testing.T) {
	r := hopRig(t)
	if _, err := r.store.Update(func(s *State) {
		s.HopAborts = &HopAborts{Series: "26.7", At: time.Now().Add(-time.Hour).Unix(), Streak: 1}
	}); err != nil {
		t.Fatal(err)
	}
	r.dev.do(func(d *simDevice) { d.land() }) // somebody completed the upgrade outside NetDefense

	r.eng.Tick(context.Background())

	if got := r.dev.Flavour(); got != "26.7/MINT/26.7.1/latest" {
		t.Fatalf("flavour %q", got)
	}
	if st := r.state(); st.HopAborts != nil {
		t.Errorf("aborts %+v: they belong to the series the device left", st.HopAborts)
	}
}
