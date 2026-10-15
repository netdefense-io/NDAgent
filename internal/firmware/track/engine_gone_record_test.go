package track

import (
	"context"
	"os"
	"testing"
	"time"
)

// A record that is not there after the request is an answer, not a read that
// failed: nothing the engine can read will bring it back, which only a file deleted
// by hand comes to. The device proves the landing, so the answer is a success and
// not a FAILED that would count against the release for the whole organization
// (the gone-record rule), and what is written depends on the live flavour, compared with the
// pin the job names:
//
//   - empty: a success with drift and no pin, and no record; the next advance pins
//     first;
//   - equal to the job's pin: the agent's own pin, proved by the job: the record is
//     rebuilt, the ordinary finish runs, success with drift and the pin in force;
//   - anything else: a success with drift and no pin, the flavour untouched (it may
//     be an operator's); the next advance holds held_custom_flavour, visibly.
func TestFinish_AGoneRecordIsAnsweredByTheLiveFlavour(t *testing.T) {
	const custom = "custom/mirror/path"
	for name, tc := range map[string]struct {
		live        string // the flavour when the run ends; "" is left to the case
		keepPin     bool   // the setting still holds the pin the task relied on
		wantPinned  bool   // the answer carries a pin
		wantRecord  bool   // the record exists afterwards
		wantFlavour string
		next        string // what the next advance answers: outcome/reason
	}{
		"the setting is empty":             {live: "", wantPinned: false, wantRecord: false, wantFlavour: "", next: "noop/pin_drift"},
		"the setting is the job's own pin": {keepPin: true, wantPinned: true, wantRecord: true, wantFlavour: pinAt573, next: "noop/at_or_above_target"},
		"the setting is somebody else's":   {live: custom, wantPinned: false, wantRecord: false, wantFlavour: custom, next: "held/held_custom_flavour"},
	} {
		t.Run(name, func(t *testing.T) {
			r := enrolledRig(t, aHotfixWindow)
			r.simulateTime()
			r.dev.do(func(d *simDevice) {
				d.onRun = func(d *simDevice) {
					_ = os.Remove(r.store.Path())
					if !tc.keepPin {
						d.flavour = tc.live
					}
				}
			})

			out := r.run(advancePayload(TrackFast, true, approve573))
			res := wantResult(t, out, OutcomeSuccess, ReasonApplied)
			if !res.Drift {
				t.Error("the answer does not say drift: the pin is not one the agent can vouch for")
			}
			if (res.PinnedVersion != "") != tc.wantPinned {
				t.Errorf("pinned_version %q, want one: %v", res.PinnedVersion, tc.wantPinned)
			}
			if tc.wantPinned {
				wantVersions(t, res, "26.7.3_8", "26.7.3_11", "26.7.3", "26.7.3_11")
			} else if res.FromVersion != "26.7.3_8" || res.ToVersion != "26.7.3_11" || res.TargetVersion != "26.7.3" {
				t.Errorf("versions %+v", res)
			}
			st := r.state()
			if (st != nil) != tc.wantRecord {
				t.Fatalf("record %+v, want one: %v", st, tc.wantRecord)
			}
			if st != nil && (!st.Pinned || st.PinnedFlavour != pinAt573 || st.PinnedVersion != "26.7.3_11" || st.OriginalFlavour != "" ||
				st.Track != TrackFast || st.Pending != nil) {
				t.Errorf("the rebuilt record is %+v", st)
			}
			if r.dev.Flavour() != tc.wantFlavour {
				t.Errorf("flavour %q, want %q", r.dev.Flavour(), tc.wantFlavour)
			}

			// And what the next window finds.
			r.dev.do(func(d *simDevice) { d.onRun = nil })
			next := r.run(advancePayload(TrackFast, true, approve573))
			if next.Result == nil {
				t.Fatalf("the next advance: %+v", next)
			}
			if got := next.Result.Outcome + "/" + next.Result.Reason; got != tc.next {
				t.Errorf("the next advance answered %s, want %s", got, tc.next)
			}
		})
	}
}

// A setting that cannot be read leaves the row unsettled, as a record that cannot
// be read does: the three-way rule needs the live flavour.
func TestFinish_AGoneRecordWithUnreadableSettingsIsLeftUnsettled(t *testing.T) {
	r := enrolledRig(t, aHotfixWindow)
	r.simulateTime()
	r.dev.do(func(d *simDevice) {
		d.onRun = func(d *simDevice) {
			_ = os.Remove(r.store.Path())
			d.settingsFailuresAfterRun = 1 << 20
		}
	})
	out := r.run(advancePayload(TrackFast, true, approve573))
	if !out.Aborted {
		t.Fatalf("got %+v: an answer on a flavour that was not read", out)
	}
	_ = context.Background()
}

// The same rule for a series upgrade: the device proves the landing, the job names
// the pin the task relied on (the pin in force, which the hop wrote nothing to: after
// the landing it is the dead pin of the old series), and the live flavour is compared
// with it.
func TestFinish_AGoneRecordAfterAHopIsAnsweredByTheLiveFlavour(t *testing.T) {
	const (
		custom   = "custom/mirror/path"
		newPin   = "26.7/MINT/26.7.1/latest"
		approved = "26.7.1"
	)
	for name, tc := range map[string]struct {
		live        string
		keepPin     bool
		wantPinned  bool
		wantRecord  bool
		wantFlavour string
		next        string
	}{
		"the setting is empty":                             {live: "", wantPinned: false, wantRecord: false, wantFlavour: "", next: "noop/pin_drift"},
		"the setting is the job's own pin, a dead one":     {keepPin: true, wantPinned: true, wantRecord: true, wantFlavour: newPin, next: "noop/at_or_above_target"},
		"the setting is somebody else's":                   {live: custom, wantPinned: false, wantRecord: false, wantFlavour: custom, next: "held/held_custom_flavour"},
		"the setting is the old series' pin of a stranger": {live: "26.1/MINT/26.1.9/latest", wantPinned: false, wantRecord: false, wantFlavour: "26.1/MINT/26.1.9/latest", next: "held/held_custom_flavour"},
	} {
		t.Run(name, func(t *testing.T) {
			r := hopRig(t)
			p := hopPayload(approveFinalHotfix)
			job := hopRebootedJob(t, r, p)
			if err := os.Remove(r.store.Path()); err != nil {
				t.Fatal(err)
			}
			if !tc.keepPin {
				r.dev.do(func(d *simDevice) { d.flavour = tc.live })
			}

			out, done := r.agentBack(job)
			if !done {
				t.Fatal("not resolved")
			}
			r.checkOutcome(p, out)
			res := wantResult(t, out, OutcomeSuccess, ReasonApplied)
			wantHop(t, res, NoteBootEnvironmentMade)
			if !res.Drift {
				t.Error("the answer does not say drift: the pin is not one the agent can vouch for")
			}
			if (res.PinnedVersion != "") != tc.wantPinned {
				t.Errorf("pinned_version %q, want one: %v", res.PinnedVersion, tc.wantPinned)
			}
			if res.FromVersion != "26.1.11_10" || res.ToVersion != "26.7.1_1" || res.TargetVersion != "26.7" {
				t.Errorf("versions %+v", res)
			}
			st := r.state()
			if (st != nil) != tc.wantRecord {
				t.Fatalf("record %+v, want one: %v", st, tc.wantRecord)
			}
			if st != nil && (!st.Pinned || st.PinnedFlavour != newPin || st.PinnedVersion != "26.7.1_1" || st.OriginalFlavour != "" ||
				st.Track != TrackFast || st.Pending != nil || st.HopAborts != nil || st.Landing != nil) {
				t.Errorf("the rebuilt record is %+v", st)
			}
			if r.dev.Flavour() != tc.wantFlavour {
				t.Errorf("flavour %q, want %q", r.dev.Flavour(), tc.wantFlavour)
			}

			// And what the next window finds.
			next := r.runUntil(advancePayload(TrackFast, true, map[string]string{"26.7": approved}), time.Now().Add(20*time.Minute))
			if next.Result == nil {
				t.Fatalf("the next advance: %+v", next)
			}
			if got := next.Result.Outcome + "/" + next.Result.Reason; got != tc.next {
				t.Errorf("the next advance answered %s, want %s", got, tc.next)
			}
		})
	}
}
