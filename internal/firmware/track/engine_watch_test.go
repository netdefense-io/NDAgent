package track

import (
	"context"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/firmware"
)

// The end of the watch: OPNsense reads the status "done" as soon as
// ***DONE*** occurs anywhere in the log, before it looks for ***REBOOT***, and a
// transient early marker was read in the log of an update that ran clean to its
// reboot. Taken for the end of the run it makes Evaluate fail it as one that finished
// without the reboot it needed. The watch counts `done` only when the log's last
// non-empty line is the marker and /running reads ready.

func TestWatch_ATransientEarlyDoneWhileTheBackendIsBusyEndsNothingAndFailsNothing(t *testing.T) {
	r := enrolledRig(t, func(d *simDevice) { d.updateEarlyDone = true })
	job := rebootedJob(t, r) // the run goes on to its reboot, which stops the agent

	if job.Phase != PhaseTriggered || job.Upgrade == nil || !job.Upgrade.RebootSeen {
		t.Fatalf("job %+v: the watch ended on the early marker", job)
	}
	out, done := r.agentBack(job)
	if !done {
		t.Fatal("not resolved")
	}
	wantResult(t, out, OutcomeSuccess, ReasonApplied)
}

// The marker as the log's last line is not the end either while the lock is held: the
// watch polls until /running reads ready.
func TestWatch_ADoneThatEndsTheLogWhileTheBackendIsBusyKeepsPolling(t *testing.T) {
	r := enrolledRig(t, onlyHotfixes, aHotfixWindow)
	r.dev.do(func(d *simDevice) {
		d.onRun = func(d *simDevice) { d.busyReads = 4 } // the lock is still held when the log ends
	})
	out := r.run(advancePayload(TrackFast, true, approve573))

	wantResult(t, out, OutcomeSuccess, ReasonApplied)
	r.dev.do(func(d *simDevice) {
		if d.busyReads != 0 {
			t.Errorf("%d busy reads left: the watch ended before the backend was ready", d.busyReads)
		}
	})
}

// And with the backend ready the marker ends the watch at once.
func TestWatch_ADoneThatEndsTheLogWithTheBackendReadyEndsTheWatch(t *testing.T) {
	r := enrolledRig(t, onlyHotfixes, aHotfixWindow)
	out := r.run(advancePayload(TrackFast, true, approve573))
	wantResult(t, out, OutcomeSuccess, ReasonApplied)
}

// The same rule for a series upgrade: a marker that ends the log while the lock is
// still held is not the end of stage 0, and the hop that goes on to its reboots is
// settled by the box.
func TestWatch_ADoneThatEndsTheLogOfAHopWhileTheBackendIsBusyKeepsPolling(t *testing.T) {
	r := hopRig(t, func(d *simDevice) { d.hop.earlyDone = true })
	p := hopPayload(approveFinalHotfix)
	job := hopRebootedJob(t, r, p)

	if job.Phase != PhaseTriggered || job.Upgrade == nil || !job.Upgrade.RebootSeen {
		t.Fatalf("job %+v: the watch ended on the early marker", job)
	}
	out, done := r.agentBack(job)
	if !done {
		t.Fatal("not resolved")
	}
	wantHop(t, wantResult(t, out, OutcomeSuccess, ReasonApplied), NoteBootEnvironmentMade)
}

// The status is "done" as soon as ***DONE*** occurs anywhere in the log. A log that
// carries the marker and goes on from it is not at its end, whatever the backend
// reads: here it reads ready throughout, so only the log says the job goes on.
func TestWatchUpdate_ADoneThatTheLogGoesOnFromIsNotTheEnd(t *testing.T) {
	ours := updateRequestMarker + "\nCurrently running OPNsense at now\n"
	early := ours + "Fetching packages\n***DONE***\nInstalling packages\n"
	eng := scriptedEngine(t, []progressAnswer{
		{status: "running", log: ours},
		{status: "done", log: early},
		{status: "reboot", log: early + "***REBOOT***\n"},
	}, firmware.RunReady)
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
		t.Fatalf("the watch ended with %q at a marker the log went on from", got)
	case <-time.After(5 * time.Second):
		t.Fatal("the watch did not get to the reboot")
	}
	stopped()
	if got := <-ended; got != "" {
		t.Errorf("watchUpdate = %q: an announced reboot ends with the agent stopped", got)
	}
}
