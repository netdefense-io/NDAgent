package track

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// hotfixRig is a device enrolled at 26.7.3 whose folder holds a newer curl: an
// in-place hotfix, package-only, with no core entry in the plan.
func hotfixRig(t *testing.T) *rig {
	t.Helper()
	return enrolledRig(t, onlyHotfixes, func(d *simDevice) { d.pkgs["curl"] = "8.20.0" })
}

func wantRevision(t *testing.T, res *Result, want string) {
	t.Helper()
	if res.Revision != want {
		t.Fatalf("revision %q, want %q", res.Revision, want)
	}
}

func TestRevision_TheApprovedRevisionIsAppliedAndReported(t *testing.T) {
	r := hotfixRig(t)
	fp := r.dev.fingerprint()
	out := r.run(advanceWith(approve573, map[string]string{"26.7": fp}))
	res := wantResult(t, out, OutcomeSuccess, ReasonApplied)
	wantRevision(t, res, fp)
	if r.dev.pkgs["curl"] != "8.21.0" {
		t.Errorf("curl %s: the hotfix was not applied", r.dev.pkgs["curl"])
	}
	if !strings.Contains(out.Message, `"revision":"`+fp+`"`) {
		t.Errorf("message %s", out.Message)
	}
	// The read after the check, the read before the request and the read after the update.
	if n := r.dev.count("catalog"); n != 3 {
		t.Errorf("catalog reads: %d", n)
	}
}

func TestRevision_AFolderRewrittenSinceTheApprovalIsHeldAndNothingIsApplied(t *testing.T) {
	r := hotfixRig(t)
	approved := r.dev.fingerprint()
	r.dev.rewrite("-r2")
	seen := r.dev.fingerprint()
	out := r.run(advanceWith(approve573, map[string]string{"26.7": approved}))
	res := wantResult(t, out, OutcomeHeld, ReasonHeldRevisionMismatch)
	wantRevision(t, res, seen)
	if r.dev.count("update") != 0 || r.dev.pkgs["curl"] != "8.20.0" {
		t.Errorf("calls %v, curl %s", r.dev.Calls(), r.dev.pkgs["curl"])
	}
	if st := r.state(); !st.Pinned || st.Pending != nil || st.PinnedFlavour != "26.7/MINT/26.7.3/latest" {
		t.Errorf("record %+v", st)
	}
}

func TestRevision_AMismatchOnAMovePutsThePinBack(t *testing.T) {
	r := enrolledRig(t)
	out := r.run(advanceWith(approve575, map[string]string{"26.7": strings.Repeat("0", 64)}))
	res := wantResult(t, out, OutcomeHeld, ReasonHeldRevisionMismatch)
	if res.Revision == "" || res.Revision == strings.Repeat("0", 64) {
		t.Errorf("revision %q", res.Revision)
	}
	if r.dev.Flavour() != "26.7/MINT/26.7.3/latest" || r.dev.count("update") != 0 {
		t.Errorf("flavour %q calls %v", r.dev.Flavour(), r.dev.Calls())
	}
	if w := r.dev.writes(); len(w) != 2 || w[0] != "26.7/MINT/26.7.5/latest" || w[1] != "26.7/MINT/26.7.3/latest" {
		t.Errorf("writes %v", w)
	}
}

func TestRevision_AFolderRewrittenBetweenTheCheckAndTheRequestIsNotApplied(t *testing.T) {
	r := hotfixRig(t)
	fp := r.dev.fingerprint()
	r.dev.onCatalogRead = func(d *simDevice, n int) {
		if n == 2 {
			d.rewrite("-r2")
		}
	}
	out := r.run(advanceWith(approve573, map[string]string{"26.7": fp}))
	res := wantResult(t, out, OutcomeHeld, ReasonHeldRevisionMismatch)
	if res.Revision == fp || res.Revision == "" {
		t.Errorf("revision %q", res.Revision)
	}
	if r.dev.count("update") != 0 || r.dev.pkgs["curl"] != "8.20.0" {
		t.Errorf("calls %v", r.dev.Calls())
	}
	if st := r.state(); st.Pending != nil || st.Pinned != true {
		t.Errorf("record %+v", st)
	}
}

func TestRevision_AFolderRewrittenDuringTheUpdateIsAppliedAndReportedAsWhatItWas(t *testing.T) {
	r := hotfixRig(t)
	fp := r.dev.fingerprint()
	r.dev.onCatalogRead = func(d *simDevice, n int) {
		if n == 3 {
			d.rewrite("-r2")
		}
	}
	out := r.run(advanceWith(approve573, map[string]string{"26.7": fp}))
	res := wantResult(t, out, OutcomeSuccess, ReasonApplied)
	if res.Revision == fp || res.Revision == "" {
		t.Errorf("a success from another revision must not name the approved one: %q", res.Revision)
	}
}

func TestRevision_ACatalogThatCannotBeReadIsACheckFailure(t *testing.T) {
	r := hotfixRig(t)
	fp := r.dev.fingerprint()
	r.dev.catalogErr = errors.New("database is locked")
	out := r.run(advanceWith(approve573, map[string]string{"26.7": fp}))
	res := wantResult(t, out, OutcomeHeld, ReasonHeldCheckFailed)
	wantRevision(t, res, "")
	if r.dev.count("update") != 0 {
		t.Errorf("calls %v", r.dev.Calls())
	}
}

func TestRevision_APlanThatTheCatalogDoesNotHoldIsACheckFailure(t *testing.T) {
	r := hotfixRig(t)
	fp := r.dev.fingerprint()
	r.dev.onCatalogRead = func(d *simDevice, n int) {
		c := d.folders["26.7.3"]
		pkgs := map[string]string{}
		for k, v := range c.pkgs {
			pkgs[k] = v
		}
		pkgs["curl"] = "8.30.0"
		c.pkgs = pkgs
		d.folders["26.7.3"] = c
	}
	out := r.run(advanceWith(approve573, map[string]string{"26.7": fp}))
	wantResult(t, out, OutcomeHeld, ReasonHeldCheckFailed)
	if r.dev.count("update") != 0 {
		t.Errorf("calls %v", r.dev.Calls())
	}
}

func TestRevision_AnAdvanceAtTheRevisionWithNothingPendingIsANoopThatNamesIt(t *testing.T) {
	r := enrolledRig(t)
	fp := r.dev.fingerprint()
	out := r.run(advanceWith(approve573, map[string]string{"26.7": fp}))
	res := wantResult(t, out, OutcomeNoop, ReasonAtOrAboveTarget)
	wantRevision(t, res, fp)
	if r.dev.count("update") != 0 {
		t.Errorf("calls %v", r.dev.Calls())
	}
}

func TestRevision_ANoopThatIsNotAboutTheContentNamesNoRevision(t *testing.T) {
	r := enrolledRig(t)
	fp := r.dev.fingerprint()
	out := r.run(advanceWith(map[string]string{"26.7": "26.7.9"}, map[string]string{"26.7": fp}))
	res := wantResult(t, out, OutcomeNoop, ReasonTargetNotYetOffered)
	wantRevision(t, res, "")
}

func TestRevision_ADispatchWithoutRevisionsReadsNothingAndReportsNothing(t *testing.T) {
	r := hotfixRig(t)
	out := r.run(advancePayload(TrackFast, true, approve573))
	res := wantResult(t, out, OutcomeSuccess, ReasonApplied)
	wantRevision(t, res, "")
	if n := r.dev.count("catalog"); n != 0 {
		t.Errorf("catalog reads: %d", n)
	}
	if strings.Contains(out.Message, "revision") {
		t.Errorf("message %s", out.Message)
	}
}

func TestRevision_APackagesOnlyRunIsVerifiedToo(t *testing.T) {
	r := hotfixRig(t)
	fp := r.dev.fingerprint()
	p := advanceWith(approve573, map[string]string{"26.7": fp})
	p.Reboot = false
	res := wantResult(t, r.run(p), OutcomeSuccess, ReasonApplied)
	wantRevision(t, res, fp)
	if r.dev.count("exec") != 1 {
		t.Errorf("calls %v", r.dev.Calls())
	}
}

func TestRevision_TheAnswerAfterARestartStillNamesTheRevision(t *testing.T) {
	r := hotfixRig(t)
	fp := r.dev.fingerprint()
	p := advanceWith(approve573, map[string]string{"26.7": fp})
	initialBoot := r.dev.boot
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.dev.updateOutcome = "reboot"
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
	if out := r.runCtx(ctx, p); !out.Aborted {
		t.Fatalf("a task cut short by the reboot must be left alone, got %+v", out)
	}
	last := r.jobs[len(r.jobs)-1]
	if last.Revisions["26.7"] != fp {
		t.Fatalf("job %+v", last)
	}
	got, done := r.newEngine().Resolve(context.Background(), last, Row{TaskID: "101", StartedAt: time.Now()})
	if !done {
		t.Fatal("the row was not resolved")
	}
	r.checkOutcome(p, got)
	res := wantResult(t, got, OutcomeSuccess, ReasonApplied)
	wantRevision(t, res, fp)
}

func TestRevision_AFolderRewrittenWhileWaitingForTheLockIsNotApplied(t *testing.T) {
	for name, reboot := range map[string]bool{"rest update": true, "packages only": false} {
		t.Run(name, func(t *testing.T) {
			r := hotfixRig(t)
			fp := r.dev.fingerprint()
			r.dev.onCatalogRead = func(d *simDevice, n int) {
				switch n {
				case 1: // the read after the check: another job takes the lock
					d.mu.Lock()
					d.busyReads = 4
					d.mu.Unlock()
				case 2: // the read before the request: the wait has ended, and the lock's holder refetched
					d.mu.Lock()
					left := d.busyReads
					d.mu.Unlock()
					if left != 0 {
						t.Errorf("the second read came with the lock still held (%d reads left)", left)
					}
					d.rewrite("-r2")
				}
			}
			p := advanceWith(approve573, map[string]string{"26.7": fp})
			p.Reboot = reboot
			res := wantResult(t, r.run(p), OutcomeHeld, ReasonHeldRevisionMismatch)
			if res.Revision == fp || r.dev.count("update") != 0 || r.dev.count("exec") != 0 || r.dev.pkgs["curl"] != "8.20.0" {
				t.Errorf("revision %q calls %v", res.Revision, r.dev.Calls())
			}
		})
	}
}

func TestRevision_AFolderRewrittenBeforeTheSecondRequestIsNotApplied(t *testing.T) {
	r := hotfixRig(t)
	fp := r.dev.fingerprint()
	r.dev.foreignOnUpdate, r.dev.foreignLife = 1, 2
	r.dev.onCatalogRead = func(d *simDevice, n int) {
		if n == 3 { // gate, first request, then the request asked again
			d.rewrite("-r2")
		}
	}
	res := wantResult(t, r.run(advanceWith(approve573, map[string]string{"26.7": fp})), OutcomeHeld, ReasonHeldRevisionMismatch)
	if res.Revision == fp || r.dev.count("update") != 1 || r.dev.pkgs["curl"] != "8.20.0" {
		t.Errorf("revision %q calls %v", res.Revision, r.dev.Calls())
	}
	if st := r.state(); st.Pending != nil || st.PinnedFlavour != "26.7/MINT/26.7.3/latest" {
		t.Errorf("record %+v", st)
	}
}
