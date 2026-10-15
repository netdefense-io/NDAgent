package track

import (
	"context"
	"testing"
	"time"
)

// The agent's own package record says FreeBSD:14 after a hop, until something
// reinstalls it. The update job's package step is an unscoped upgrade, so the first
// advance whose update takes the NetDefense repository reinstalls the agent, and the
// package's post-install hook restarts it inside the job. There is no self-reinstall
// step. The requirement is that the advance's answer is its real outcome (applied,
// with the release reached and the pin following), never a hold and never a FAILED,
// however the agent restarted: the row is settled by Resolve, the path any firmware
// update that carries an agent upgrade already takes.

// landedRig is a box that hopped and was settled, whose next window brings 26.7.2 and
// whose plan lists the agent's own package as a same-version reinstall.
func landedRig(t *testing.T) *rig {
	t.Helper()
	r := hopRig(t)
	p := hopPayload(approveFinalHotfix)
	job := hopRebootedJob(t, r, p)
	if out, done := r.agentBack(job); !done || out.Result == nil {
		t.Fatalf("the hop was not settled: %+v", out)
	}
	r.dev.do(func(d *simDevice) {
		d.hop.reinstallAgent = true
		d.folders["26.7.2"] = simCatalog{
			core: "26.7.2_1", update: "26.7", pkgs: map[string]string{"curl": "8.23.0", "pkg": "2.3.1_1"}, abi: "FreeBSD:15:amd64",
		}
		d.record("--")
	})
	return r
}

var approve726 = map[string]string{"26.7": "26.7.2"}

func TestFirstAdvanceAfterAHop_ARebootingUpdateIsSettledAfterTheAgentRestarted(t *testing.T) {
	r := landedRig(t)
	p := advancePayload(TrackFast, true, approve726)

	initialBoot := r.dev.boot
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	go func() { // the agent is stopped by its own upgrade, and again by the reboot
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
		t.Fatalf("the restart should leave the task alone, got %+v", out)
	}
	job := r.jobs[len(r.jobs)-1]
	if job.Phase != PhaseTriggered || job.Upgrade == nil || job.Upgrade.Mode != "minor" {
		t.Fatalf("job %+v", job)
	}
	if job.Reinstalls != 1 {
		t.Errorf("reinstall entries %d: the agent's record of the old ABI is counted and never held on", job.Reinstalls)
	}

	out, done := r.agentBack(job)
	if !done {
		t.Fatal("not resolved")
	}
	r.checkOutcome(p, out)
	res := wantResult(t, out, OutcomeSuccess, ReasonApplied)
	wantOrdinary(t, res)
	wantVersions(t, res, "26.7.1_1", "26.7.2_1", "26.7.2", "26.7.2_1")
	if got := r.dev.Flavour(); got != "26.7/MINT/26.7.2/latest" {
		t.Errorf("flavour %q", got)
	}
	if st := r.state(); !st.Pinned || st.PinnedVersion != "26.7.2_1" || st.Pending != nil {
		t.Errorf("record %+v", st)
	}
}

func TestFirstAdvanceAfterAHop_AnUpdateWithoutARebootIsSettledAfterTheAgentRestarted(t *testing.T) {
	r := landedRig(t)
	p := advancePayload(TrackFast, false, approve726)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	r.dev.do(func(d *simDevice) {
		d.execKilled = true
		// The command is killed with the agent while pkg goes on.
		d.onRun = func(*simDevice) { cancel() }
	})
	if out := r.runCtx(ctx, p); !out.Aborted {
		t.Fatalf("the restart should leave the task alone, got %+v", out)
	}
	job := r.jobs[len(r.jobs)-1]
	if job.Phase != PhaseTriggered || job.Upgrade == nil || job.Upgrade.Reboot {
		t.Fatalf("job %+v", job)
	}

	out, done := r.agentBack(job)
	if !done {
		t.Fatal("not resolved")
	}
	r.checkOutcome(p, out)
	res := wantResult(t, out, OutcomeSuccess, ReasonApplied)
	wantOrdinary(t, res)
	wantVersions(t, res, "26.7.1_1", "26.7.2_1", "26.7.2", "26.7.2_1")
	if st := r.state(); !st.Pinned || st.PinnedVersion != "26.7.2_1" || st.Pending != nil {
		t.Errorf("record %+v", st)
	}
}
