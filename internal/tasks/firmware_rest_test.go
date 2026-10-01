package tasks

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/firmware"
	"github.com/netdefense-io/ndagent/internal/opnapi"
	"github.com/netdefense-io/ndagent/internal/taskstore"
)

// restClient scripts OPNsense's firmware API for a REST-driven run. running and
// progress are given the number of times the corresponding endpoint has been
// read and how many update requests have been made, and answer for that moment.
type restClient struct {
	*stubFirmwareClient

	mu       sync.Mutex
	events   []string
	posts    int
	runs     int
	progs    int
	running  func(reads, posts int) (*opnapi.FirmwareRunning, error)
	progress func(reads, posts int) (*opnapi.FirmwareProgressStatus, error)
	// onReboot runs when the progress log announces the reboot: the box goes down
	// a moment later and takes the agent with it.
	onReboot func()
}

func newRESTClient(st *opnapi.FirmwareUpgradeStatus) *restClient {
	return &restClient{
		stubFirmwareClient: &stubFirmwareClient{
			statusResp: st, release: st.ProductVersion,
			updateResp: &opnapi.FirmwareUpdateResponse{Status: "ok"}, upgradeResp: &opnapi.FirmwareUpgradeResponse{Status: "ok"},
		},
		running: func(int, int) (*opnapi.FirmwareRunning, error) { return &opnapi.FirmwareRunning{Status: "ready"}, nil },
		progress: func(int, int) (*opnapi.FirmwareProgressStatus, error) {
			return &opnapi.FirmwareProgressStatus{Status: "running"}, nil
		},
	}
}

func (c *restClient) note(event string) {
	c.mu.Lock()
	c.events = append(c.events, event)
	c.mu.Unlock()
}

func (c *restClient) GetFirmwareRunning(context.Context) (*opnapi.FirmwareRunning, error) {
	c.mu.Lock()
	c.runs++
	reads, posts := c.runs, c.posts
	c.mu.Unlock()
	r, err := c.running(reads, posts)
	if r != nil {
		c.note("running:" + r.Status)
	} else {
		c.note("running:error")
	}
	return r, err
}

func (c *restClient) GetFirmwareUpgradeProgress(context.Context) (*opnapi.FirmwareProgressStatus, error) {
	c.mu.Lock()
	c.progs++
	reads, posts := c.progs, c.posts
	c.mu.Unlock()
	p, err := c.progress(reads, posts)
	if p != nil && p.Status == "reboot" && c.onReboot != nil {
		c.onReboot()
	}
	return p, err
}

func (c *restClient) TriggerFirmwareUpdate(ctx context.Context) (*opnapi.FirmwareUpdateResponse, error) {
	c.mu.Lock()
	c.posts++
	c.mu.Unlock()
	c.note("post")
	return c.stubFirmwareClient.TriggerFirmwareUpdate(ctx)
}

func (c *restClient) TriggerFirmwareUpgrade(ctx context.Context) (*opnapi.FirmwareUpgradeResponse, error) {
	c.mu.Lock()
	c.posts++
	c.mu.Unlock()
	c.note("post")
	return c.stubFirmwareClient.TriggerFirmwareUpgrade(ctx)
}

func (c *restClient) postCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.posts
}

func (c *restClient) eventLog() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.events...)
}

// startsOnceAsked answers as a healthy OPNsense: after the n-th request the
// progress log carries the marker, then the given end marker.
func startsOnceAsked(n int, end string) func(int, int) (*opnapi.FirmwareProgressStatus, error) {
	return func(_, posts int) (*opnapi.FirmwareProgressStatus, error) {
		if posts < n {
			return &opnapi.FirmwareProgressStatus{Status: "done", Log: "the previous run\n***DONE***"}, nil
		}
		return &opnapi.FirmwareProgressStatus{Status: end, Log: updateRequestMarker + "\nrunning..."}, nil
	}
}

// deviceProbes is a device for the evaluation a run asks for at its end.
type deviceProbes struct {
	state     firmware.RunState
	release   string
	boot      int64
	installed map[string]string
	evidence  string
	states    []firmware.RunState // consumed one per Running read, the last one repeated
	reads     int
}

func (d *deviceProbes) probes() firmware.Probes {
	return firmware.Probes{
		Running: func(context.Context) (firmware.RunState, error) {
			if len(d.states) > 0 {
				i := d.reads
				if i >= len(d.states) {
					i = len(d.states) - 1
				}
				d.reads++
				return d.states[i], nil
			}
			return d.state, nil
		},
		Release:   func(context.Context) (string, error) { return d.release, nil },
		BootTime:  func() (int64, error) { return d.boot, nil },
		Installed: func(context.Context) (map[string]string, error) { return d.installed, nil },
		Updating:  func(context.Context) (bool, error) { return false, nil },
		Evidence:  func(context.Context, time.Time) (string, error) { return d.evidence, nil },
	}
}

// idleAfterAnUpdate is the box after a clean packages-only update: idle, the
// release unchanged, every planned package installed.
func idleAfterAnUpdate() *deviceProbes {
	return &deviceProbes{
		state: firmware.RunReady, release: "26.7.3_8", boot: 1_780_000_000,
		installed: map[string]string{"opnsense": "26.7.4_1", "os-netdefense": "1.19.5", "py311-newdep": "1.0"},
	}
}

// packagesOnlyStatus is a plan that does not include base or kernel.
func packagesOnlyStatus() *opnapi.FirmwareUpgradeStatus {
	st := planStatus()
	st.NeedsReboot = false
	st.UpgradePackages = []opnapi.FirmwarePackageEntry{
		{Name: "os-netdefense", CurrentVersion: "1.19.4", NewVersionAlt: "1.19.5"},
	}
	st.NewPackages = []opnapi.FirmwarePackageEntry{{Name: "py311-newdep", NewVersion: "1.0"}}
	return st
}

func (f *firmwareFixture) runMinor(ctx context.Context, id string, c *restClient, st *opnapi.FirmwareUpgradeStatus) error {
	f.t.Helper()
	f.begin(id)
	// A run that never settles must end the test with a failed assertion, not a
	// hang: the handler returns, leaving the row IN_PROGRESS, when this ends.
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	c.stopAgentOnReboot(cancel)
	return handleMinorWithReboot(ctx, nil, rebootCmd(id, "minor", metaTestNow.Add(15*time.Minute).Unix()), c,
		&firmwareUpgradePayload{Mode: "minor", Reboot: true}, st)
}

// stopAgentOnReboot makes the box take the agent down a moment after it announces
// the reboot: a handler that has seen ***REBOOT*** stays until then.
func (c *restClient) stopAgentOnReboot(stop context.CancelFunc) {
	c.onReboot = func() { time.AfterFunc(5*time.Millisecond, stop) }
}

func (f *firmwareFixture) withProbes(d *deviceProbes) {
	f.t.Helper()
	restore := SetFirmwareProbesForTest(func(firmwareOPNAPIClient) firmware.Probes { return d.probes() })
	f.t.Cleanup(restore)
}

// ── before the trigger ──────────────────────────────────────────────────────

// launcher.sh takes its lock with flock -n and drops a request that finds it
// held, so the run waits for the backend, also when check_first was false.
func TestRESTRun_WaitsForTheBackendToBeFreeBeforeTriggering(t *testing.T) {
	f := newFirmwareFixture(t)
	c := newRESTClient(planStatus())
	c.running = func(reads, _ int) (*opnapi.FirmwareRunning, error) {
		switch {
		case reads <= 3:
			return &opnapi.FirmwareRunning{Status: "busy"}, nil
		case reads == 4:
			return nil, errors.New("connection refused") // an API gap is not "ready" either
		default:
			return &opnapi.FirmwareRunning{Status: "ready"}, nil
		}
	}
	c.progress = startsOnceAsked(1, "reboot")

	if err := f.runMinor(context.Background(), "51", c, planStatus()); err != nil {
		t.Fatalf("run: %v", err)
	}

	events := c.eventLog()
	post := indexOf(events, "post")
	if post < 1 {
		t.Fatalf("the update was requested without first reading the backend, or never: %v", events)
	}
	if got := events[post-1]; got != "running:ready" {
		t.Fatalf("the read right before the request was %q, want running:ready: %v", got, events)
	}
	if busy := countOf(events[:post], "running:busy"); busy != 3 {
		t.Fatalf("saw %d busy reads before the request, want 3: %v", busy, events)
	}
}

func TestRESTRun_ABackendThatNeverFreesUpIsNotTriggered(t *testing.T) {
	f := newFirmwareFixture(t)
	c := newRESTClient(planStatus())
	c.running = func(int, int) (*opnapi.FirmwareRunning, error) { return &opnapi.FirmwareRunning{Status: "busy"}, nil }

	if err := f.runMinor(context.Background(), "52", c, planStatus()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if c.postCount() != 0 {
		t.Fatalf("requested an update %d times of a busy backend", c.postCount())
	}
	if len(f.terminals) != 1 || f.terminals[0].success ||
		!strings.Contains(f.terminals[0].message, "did not become free") {
		t.Fatalf("terminal responses = %+v, want one FAILED saying the backend did not become free", f.terminals)
	}
	// The run was recorded before the wait, and never triggered: an agent that
	// stopped now would leave a row that says so.
	if m, found := f.meta("52"); !found || m.Triggered() {
		t.Fatalf("meta = %+v (found %v), want the run recorded and not triggered", m, found)
	}
}

func TestRESTRun_CancelledWhileWaitingForTheBackendDoesNotTrigger(t *testing.T) {
	f := newFirmwareFixture(t)
	c := newRESTClient(planStatus())
	c.running = func(int, int) (*opnapi.FirmwareRunning, error) { return &opnapi.FirmwareRunning{Status: "busy"}, nil }

	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(10 * time.Millisecond); cancel() }()
	err := f.runMinor(ctx, "53", c, planStatus())

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("run returned %v; the dispatcher needs the cancellation to record it", err)
	}
	if c.postCount() != 0 || len(f.terminals) != 0 {
		t.Fatalf("posts=%d terminals=%+v, want neither", c.postCount(), f.terminals)
	}
}

// ── after the trigger ───────────────────────────────────────────────────────

func TestRESTRun_ARequestOPNsenseDroppedIsAskedAgainOnce(t *testing.T) {
	f := newFirmwareFixture(t)
	c := newRESTClient(planStatus())
	c.progress = startsOnceAsked(2, "reboot") // the first request is dropped, the second starts

	if err := f.runMinor(context.Background(), "54", c, planStatus()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if c.postCount() != 2 {
		t.Fatalf("requested %d times, want 2", c.postCount())
	}
	if len(f.terminals) != 0 {
		t.Fatalf("terminal responses = %+v; the run started and rebooted, nothing to say yet", f.terminals)
	}
}

func TestRESTRun_ARequestDroppedTwiceFailsAndSaysWhy(t *testing.T) {
	f := newFirmwareFixture(t)
	c := newRESTClient(planStatus())
	c.progress = startsOnceAsked(99, "reboot")

	if err := f.runMinor(context.Background(), "55", c, planStatus()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if c.postCount() != 2 {
		t.Fatalf("requested %d times, want 2", c.postCount())
	}
	if len(f.terminals) != 1 || f.terminals[0].success ||
		!strings.Contains(f.terminals[0].message, "did not start it") ||
		!strings.Contains(f.terminals[0].message, "Nothing was applied") {
		t.Fatalf("terminal responses = %+v", f.terminals)
	}
}

// The log the previous run left is still there when a request is dropped; it
// carries the marker too, and it did not change.
func TestRESTRun_AStaleLogIsNotProofThatTheRunStarted(t *testing.T) {
	f := newFirmwareFixture(t)
	c := newRESTClient(planStatus())
	c.progress = func(int, int) (*opnapi.FirmwareProgressStatus, error) {
		return &opnapi.FirmwareProgressStatus{Status: "done", Log: updateRequestMarker + "\n...\n***DONE***"}, nil
	}

	if err := f.runMinor(context.Background(), "56", c, planStatus()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if c.postCount() != 2 {
		t.Fatalf("requested %d times, want 2: the stale log must not count as a start", c.postCount())
	}
	if len(f.terminals) != 1 || f.terminals[0].success || !strings.Contains(f.terminals[0].message, "did not start it") {
		t.Fatalf("terminal responses = %+v, want the not-started failure", f.terminals)
	}
}

// The backend turning busy right after the request also shows the run started.
func TestRESTRun_ABusyBackendAfterTheRequestShowsTheRunStarted(t *testing.T) {
	f := newFirmwareFixture(t)
	c := newRESTClient(planStatus())
	c.running = func(_, posts int) (*opnapi.FirmwareRunning, error) {
		if posts == 0 {
			return &opnapi.FirmwareRunning{Status: "ready"}, nil
		}
		return &opnapi.FirmwareRunning{Status: "busy"}, nil
	}
	c.progress = func(_, posts int) (*opnapi.FirmwareProgressStatus, error) {
		if posts == 0 {
			return &opnapi.FirmwareProgressStatus{Status: "done", Log: "old"}, nil
		}
		return &opnapi.FirmwareProgressStatus{Status: "reboot", Log: "old"}, nil // ends the watch
	}

	if err := f.runMinor(context.Background(), "57", c, planStatus()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if c.postCount() != 1 || len(f.terminals) != 0 {
		t.Fatalf("posts=%d terminals=%+v, want one request and no terminal", c.postCount(), f.terminals)
	}
}

// ── watching ────────────────────────────────────────────────────────────────

// The box is going down: nothing is reported, and the announcement is recorded
// because it is what tells the reconciler a reboot was needed.
func TestRESTRun_TheRebootAnnouncementLeavesTheRowForTheReconciler(t *testing.T) {
	f := newFirmwareFixture(t)
	c := newRESTClient(packagesOnlyStatus())
	c.progress = startsOnceAsked(1, "reboot")

	if err := f.runMinor(context.Background(), "58", c, packagesOnlyStatus()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(f.terminals) != 0 {
		t.Fatalf("terminal responses = %+v, want none", f.terminals)
	}
	m, found := f.meta("58")
	if !found || !m.RebootSeen || !m.RebootExpected() {
		t.Fatalf("meta = %+v (found %v), want the announced reboot recorded", m, found)
	}
	if rec, _, _ := f.store.Get("58"); rec.Status != taskstore.StatusInProgress {
		t.Fatalf("row is %s, want IN_PROGRESS", rec.Status)
	}
}

// OPNsense restarts configd and its web GUI while it replaces the core package,
// and answers "error" for an empty log. A run must outlive that: the first failed
// poll must not end the watch, and "error" must not fail the task.
func TestRESTRun_AGapInTheAPIDoesNotEndTheRun(t *testing.T) {
	f := newFirmwareFixture(t)
	f.withProbes(idleAfterAnUpdate())
	c := newRESTClient(packagesOnlyStatus())
	c.progress = func(reads, posts int) (*opnapi.FirmwareProgressStatus, error) {
		switch {
		case posts == 0:
			return &opnapi.FirmwareProgressStatus{Status: "done", Log: "previous"}, nil
		case reads < 3: // the start verification reads the log before it is up
			return &opnapi.FirmwareProgressStatus{Status: "running", Log: updateRequestMarker}, nil
		case reads < 40:
			return nil, errors.New("connection refused") // well past ten seconds of polls
		case reads < 45:
			return &opnapi.FirmwareProgressStatus{Status: "error"}, nil
		default:
			return &opnapi.FirmwareProgressStatus{Status: "done", Log: updateRequestMarker + "\n***DONE***"}, nil
		}
	}

	if err := f.runMinor(context.Background(), "59", c, packagesOnlyStatus()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(f.terminals) != 1 || !f.terminals[0].success {
		t.Fatalf("terminal responses = %+v, want one COMPLETED once OPNsense said done", f.terminals)
	}
}

func TestRESTRun_ALostConnectionLeavesTheRowIN_PROGRESS(t *testing.T) {
	f := newFirmwareFixture(t)
	c := newRESTClient(planStatus())
	ctx, cancel := context.WithCancel(context.Background())
	c.progress = func(_, posts int) (*opnapi.FirmwareProgressStatus, error) {
		if posts == 0 {
			return &opnapi.FirmwareProgressStatus{Status: "done", Log: "previous"}, nil
		}
		go cancel() // the connection drops once the run is under way
		return &opnapi.FirmwareProgressStatus{Status: "running", Log: updateRequestMarker}, nil
	}

	if err := f.runMinor(ctx, "60", c, planStatus()); err != nil {
		t.Fatalf("run returned %v; leaving the row must not be reported as an error", err)
	}
	if len(f.terminals) != 0 {
		t.Fatalf("terminal responses = %+v, want none", f.terminals)
	}
	if _, found := f.meta("60"); !found {
		t.Fatal("the run's metadata must be on the row for the reconciler")
	}
	if rec, _, _ := f.store.Get("60"); rec.Status != taskstore.StatusInProgress {
		t.Fatalf("row is %s, want IN_PROGRESS", rec.Status)
	}
}

// ── the end marker is not the verdict ───────────────────────────────────────

func TestRESTRun_DoneIsEvaluatedNotTrusted(t *testing.T) {
	done := func(c *restClient) { c.progress = startsOnceAsked(1, "done") }

	t.Run("a clean packages-only run completes with the sentinel and the result shape", func(t *testing.T) {
		f := newFirmwareFixture(t)
		f.withProbes(idleAfterAnUpdate())
		c := newRESTClient(packagesOnlyStatus())
		done(c)

		if err := f.runMinor(context.Background(), "61", c, packagesOnlyStatus()); err != nil {
			t.Fatalf("run: %v", err)
		}
		if len(f.terminals) != 1 || !f.terminals[0].success {
			t.Fatalf("terminal responses = %+v", f.terminals)
		}
		var got map[string]interface{}
		if err := json.Unmarshal([]byte(f.terminals[0].message), &got); err != nil {
			t.Fatalf("not JSON: %v\n%s", err, f.terminals[0].message)
		}
		for k, want := range map[string]interface{}{
			"resolved_mode": "minor", "from_version": "26.7.3_8", "to_version": "26.7.3_8",
			"applied": true, "reboot_performed": false, "reboots_expected": float64(1),
			"status_sentinel": "done", "packages_applied": float64(2),
		} {
			if got[k] != want {
				t.Errorf("%s = %v, want %v", k, got[k], want)
			}
		}
		if _, present := got["reconciled"]; present {
			t.Error("an in-session result is not reconciled")
		}
	})

	t.Run("done after a partial failure is a failure", func(t *testing.T) {
		f := newFirmwareFixture(t)
		d := idleAfterAnUpdate()
		d.evidence = "Partial update failure detected"
		f.withProbes(d)
		c := newRESTClient(packagesOnlyStatus())
		done(c)

		if err := f.runMinor(context.Background(), "62", c, packagesOnlyStatus()); err != nil {
			t.Fatalf("run: %v", err)
		}
		if len(f.terminals) != 1 || f.terminals[0].success ||
			!strings.Contains(f.terminals[0].message, "Partial update failure detected") {
			t.Fatalf("terminal responses = %+v, want one FAILED naming the partial failure", f.terminals)
		}
		if strings.HasPrefix(f.terminals[0].message, "{") {
			t.Fatalf("a failure must be plain text: %q", f.terminals[0].message)
		}
	})

	t.Run("done with planned packages missing fails and names them", func(t *testing.T) {
		f := newFirmwareFixture(t)
		d := idleAfterAnUpdate()
		delete(d.installed, "os-netdefense")
		f.withProbes(d)
		c := newRESTClient(packagesOnlyStatus())
		done(c)

		if err := f.runMinor(context.Background(), "63", c, packagesOnlyStatus()); err != nil {
			t.Fatalf("run: %v", err)
		}
		if len(f.terminals) != 1 || f.terminals[0].success || !strings.Contains(f.terminals[0].message, "os-netdefense") {
			t.Fatalf("terminal responses = %+v", f.terminals)
		}
	})

	t.Run("done without the reboot the plan needed fails", func(t *testing.T) {
		f := newFirmwareFixture(t)
		f.withProbes(idleAfterAnUpdate()) // boot time unchanged
		c := newRESTClient(planStatus())  // the plan includes base and kernel
		done(c)

		if err := f.runMinor(context.Background(), "64", c, planStatus()); err != nil {
			t.Fatalf("run: %v", err)
		}
		if len(f.terminals) != 1 || f.terminals[0].success ||
			!strings.Contains(f.terminals[0].message, "without the reboot it needed") {
			t.Fatalf("terminal responses = %+v", f.terminals)
		}
	})
}

// The backend can still read busy for a moment after the end marker (the lock is
// released as the script exits); the evaluation waits and then answers once.
func TestRESTRun_TheEvaluationWaitsForWhatItCannotReadYet(t *testing.T) {
	f := newFirmwareFixture(t)
	d := idleAfterAnUpdate()
	d.states = []firmware.RunState{firmware.RunBusy, firmware.RunBusy, firmware.RunReady}
	f.withProbes(d)
	c := newRESTClient(packagesOnlyStatus())
	c.progress = startsOnceAsked(1, "done")

	if err := f.runMinor(context.Background(), "65", c, packagesOnlyStatus()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(f.terminals) != 1 || !f.terminals[0].success {
		t.Fatalf("terminal responses = %+v, want exactly one COMPLETED", f.terminals)
	}
}

// With no end marker by the deadline the run does not hang on: it asks the
// device, and a backend that is still busy is a failure with a reason.
func TestRESTRun_TheDeadlineWithoutAMarkerAsksTheDevice(t *testing.T) {
	f := newFirmwareFixture(t)
	restoreDeadline := SetFirmwareDeadlineForTest(func(time.Time) time.Time { return time.Now().Add(40 * time.Millisecond) })
	defer restoreDeadline()
	restoreNow := SetFirmwareNowForTest(func() time.Time { return time.Now().Add(24 * time.Hour) })
	defer restoreNow()
	defer SetFirmwareUptimeForTest(func() time.Duration { return 10 * time.Hour })()
	d := idleAfterAnUpdate()
	d.state = firmware.RunBusy
	f.withProbes(d)
	c := newRESTClient(planStatus())
	c.progress = func(_, posts int) (*opnapi.FirmwareProgressStatus, error) {
		if posts == 0 {
			return &opnapi.FirmwareProgressStatus{Status: "done", Log: "previous"}, nil
		}
		return &opnapi.FirmwareProgressStatus{Status: "running", Log: updateRequestMarker}, nil // never ends
	}

	if err := f.runMinor(context.Background(), "66", c, planStatus()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(f.terminals) != 1 || f.terminals[0].success ||
		!strings.Contains(f.terminals[0].message, "could not be confirmed") {
		t.Fatalf("terminal responses = %+v", f.terminals)
	}
}

// After ***REBOOT*** the handler keeps its place until the agent is stopped. If
// the box never goes down, the run's deadline ends the wait and the device is
// asked, which finds a reboot that did not happen.
func TestRESTRun_ARebootThatNeverHappensIsSettledFromTheDeviceAtTheDeadline(t *testing.T) {
	f := newFirmwareFixture(t)
	restoreDeadline := SetFirmwareDeadlineForTest(func(time.Time) time.Time { return time.Now().Add(60 * time.Millisecond) })
	defer restoreDeadline()
	restoreNow := SetFirmwareNowForTest(func() time.Time { return time.Now().Add(48 * time.Hour) })
	defer restoreNow()
	defer SetFirmwareUptimeForTest(func() time.Duration { return 10 * time.Hour })()
	d := idleAfterAnUpdate() // idle, and the boot time never moved
	f.withProbes(d)
	c := newRESTClient(planStatus()) // the plan includes base and kernel
	c.progress = startsOnceAsked(1, "reboot")
	f.begin("71")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	if err := handleMinorWithReboot(ctx, nil, rebootCmd("71", "minor", metaTestNow.Add(15*time.Minute).Unix()), c,
		&firmwareUpgradePayload{Mode: "minor", Reboot: true}, planStatus()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if time.Since(start) < 50*time.Millisecond {
		t.Fatalf("the handler returned after %v: it must hold its place until the box takes the agent down or the deadline passes", time.Since(start))
	}
	if len(f.terminals) != 1 || f.terminals[0].success ||
		!strings.Contains(f.terminals[0].message, "has not restarted") {
		t.Fatalf("terminal responses = %+v, want one FAILED saying the box has not restarted", f.terminals)
	}
}

// The bound needs the process to have been up for the grace, and the evaluation
// repeats until it can answer: the uptime has to be read again on every round. A
// process that was two minutes old when the run's watch ended is not two minutes
// old for the rest of the wait.
func TestRESTRun_TheBoundSeesTheProcessGrowUp(t *testing.T) {
	f := newFirmwareFixture(t)
	restoreDeadline := SetFirmwareDeadlineForTest(func(time.Time) time.Time { return time.Now().Add(40 * time.Millisecond) })
	defer restoreDeadline()
	restoreNow := SetFirmwareNowForTest(func() time.Time { return time.Now().Add(48 * time.Hour) })
	defer restoreNow()
	var reads int
	defer SetFirmwareUptimeForTest(func() time.Duration {
		reads++
		if reads == 1 {
			return 2 * time.Minute // young when the run was started, well inside the grace
		}
		return time.Hour
	})()
	d := idleAfterAnUpdate()
	d.state = firmware.RunBusy // it never frees up
	f.withProbes(d)
	c := newRESTClient(planStatus())
	c.progress = func(_, posts int) (*opnapi.FirmwareProgressStatus, error) {
		if posts == 0 {
			return &opnapi.FirmwareProgressStatus{Status: "done", Log: "previous"}, nil
		}
		return &opnapi.FirmwareProgressStatus{Status: "running", Log: updateRequestMarker}, nil // never ends
	}

	if err := f.runMinor(context.Background(), "70", c, planStatus()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(f.terminals) != 1 || f.terminals[0].success ||
		!strings.Contains(f.terminals[0].message, "could not be confirmed") {
		t.Fatalf("terminal responses = %+v, want the run failed once the process had been up for the grace", f.terminals)
	}
}

// ── a series upgrade goes through the same run ──────────────────────────────

func TestRESTRun_MajorTriggersTheUpgradeEndpointAndRecordsTheSeriesRun(t *testing.T) {
	f := newFirmwareFixture(t)
	st := planStatus()
	st.UpgradeMajorVersion = "26.9"
	c := newRESTClient(st)
	upgrades := 0
	c.stubFirmwareClient.onUpgrade = func() { upgrades++ }
	c.progress = func(_, posts int) (*opnapi.FirmwareProgressStatus, error) {
		if posts == 0 {
			return &opnapi.FirmwareProgressStatus{Status: "done", Log: "previous"}, nil
		}
		return &opnapi.FirmwareProgressStatus{Status: "reboot", Log: upgradeRequestMarker}, nil
	}
	f.begin("67")
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	c.stopAgentOnReboot(stop)

	if err := handleMajorWithReboot(ctx, nil, rebootCmd("67", "major", 0), c,
		&firmwareUpgradePayload{Mode: "major", Reboot: true}, st); err != nil {
		t.Fatalf("run: %v", err)
	}
	if upgrades != 1 {
		t.Fatalf("POST /upgrade made %d times, want 1", upgrades)
	}
	m, _ := f.meta("67")
	if m.Mode != "major" || !m.RebootExpected() || m.ExpectedReboots() != 2 {
		t.Fatalf("meta = %+v", m)
	}
	if len(f.progress) != 1 || !strings.Contains(f.progress[0], "major upgrade from series 26.7 to 26.9") {
		t.Fatalf("IN_PROGRESS messages = %v", f.progress)
	}
}

func indexOf(list []string, want string) int {
	for i, s := range list {
		if s == want {
			return i
		}
	}
	return -1
}

func countOf(list []string, want string) int {
	n := 0
	for _, s := range list {
		if s == want {
			n++
		}
	}
	return n
}

// progressReads answers the progress endpoint from a script, repeating the last
// answer.
type progressReads struct {
	*stubFirmwareClient
	answers []func() (*opnapi.FirmwareProgressStatus, error)
	n       int
}

func (p *progressReads) GetFirmwareUpgradeProgress(context.Context) (*opnapi.FirmwareProgressStatus, error) {
	i := p.n
	if i >= len(p.answers) {
		i = len(p.answers) - 1
	}
	p.n++
	return p.answers[i]()
}

func progressStatus(status string) func() (*opnapi.FirmwareProgressStatus, error) {
	return func() (*opnapi.FirmwareProgressStatus, error) {
		return &opnapi.FirmwareProgressStatus{Status: status}, nil
	}
}

func progressError() func() (*opnapi.FirmwareProgressStatus, error) {
	return func() (*opnapi.FirmwareProgressStatus, error) { return nil, errors.New("connection refused") }
}

// A failed poll is a gap, not the end of the run. On 1.19.4 the first one made
// the watch return and the handler give up.
func TestPollUpgradeStatus_SurvivesGapsAndKeepsWatching(t *testing.T) {
	restore := SetUpgradeStatusPollIntervalForTest(time.Millisecond)
	defer restore()

	answers := []func() (*opnapi.FirmwareProgressStatus, error){progressStatus("running"), progressError()}
	for i := 0; i < 30; i++ { // far more than the ten seconds the core package's restart takes
		answers = append(answers, progressError())
	}
	answers = append(answers, progressStatus("running"), progressStatus("done"))

	client := &progressReads{stubFirmwareClient: &stubFirmwareClient{}, answers: answers}
	if got := pollUpgradeStatus(context.Background(), client, noopLogger{}); got != "done" {
		t.Fatalf("sentinel = %q after a long gap, want done", got)
	}
}

// OPNsense answers "error" when its progress log is empty, and nothing else ever
// means an error: it is retried, not reported.
func TestPollUpgradeStatus_ErrorStatusIsRetriedNotTerminal(t *testing.T) {
	restore := SetUpgradeStatusPollIntervalForTest(time.Millisecond)
	defer restore()

	client := &progressReads{stubFirmwareClient: &stubFirmwareClient{}, answers: []func() (*opnapi.FirmwareProgressStatus, error){
		progressStatus("error"), progressStatus("error"), progressStatus("running"), progressStatus("reboot"),
	}}
	if got := pollUpgradeStatus(context.Background(), client, noopLogger{}); got != "reboot" {
		t.Fatalf("sentinel = %q, want reboot", got)
	}
}

func TestPollUpgradeStatus_ReturnsAtTheContextWhateverItSaw(t *testing.T) {
	restore := SetUpgradeStatusPollIntervalForTest(time.Millisecond)
	defer restore()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	client := &progressReads{stubFirmwareClient: &stubFirmwareClient{}, answers: []func() (*opnapi.FirmwareProgressStatus, error){progressError()}}
	if got := pollUpgradeStatus(ctx, client, noopLogger{}); got != "" {
		t.Fatalf("sentinel = %q, want empty when the context ends", got)
	}
}

// Cancelling opnsense-update kills the script and leaves pkg running. The task
// is neither failed nor finished; it stays with the plan recorded.
func TestHandleMinorNoReboot_ACancelledExecLeavesTheRowIN_PROGRESS(t *testing.T) {
	f := newFirmwareFixture(t)
	f.begin("68")

	ctx, cancel := context.WithCancel(context.Background())
	restoreExec := SetFirmwareExecFuncForTest(func(context.Context, ...string) ([]byte, []byte, int) {
		cancel() // the connection dropped (or the agent is stopping) mid-run
		return nil, []byte("signal: killed"), -1
	})
	defer restoreExec()

	st := planStatus()
	client := &stubFirmwareClient{statusResp: st, release: "26.7.3_8"}
	if err := handleMinorNoReboot(ctx, nil, minorNoRebootCmd("68"), client,
		&firmwareUpgradePayload{Mode: "minor", Reboot: false}, st); err != nil {
		t.Fatalf("handleMinorNoReboot: %v", err)
	}
	if len(f.terminals) != 0 {
		t.Fatalf("terminal responses = %+v, want none: pkg may still be running", f.terminals)
	}
	if _, found := f.meta("68"); !found {
		t.Fatal("the plan must be on the row for the reconciler")
	}
	if rec, _, _ := f.store.Get("68"); rec.Status != taskstore.StatusInProgress {
		t.Fatalf("row is %s, want IN_PROGRESS", rec.Status)
	}
}

// An exec that failed on its own, with the context alive, is still a failure.
func TestHandleMinorNoReboot_AFailedExecWithALiveContextStillFails(t *testing.T) {
	f := newFirmwareFixture(t)
	f.begin("69")
	restoreExec := SetFirmwareExecFuncForTest(func(context.Context, ...string) ([]byte, []byte, int) {
		return nil, []byte("pkg: repository unavailable"), 1
	})
	defer restoreExec()

	st := planStatus()
	client := &stubFirmwareClient{statusResp: st, release: "26.7.3_8"}
	if err := handleMinorNoReboot(context.Background(), nil, minorNoRebootCmd("69"), client,
		&firmwareUpgradePayload{Mode: "minor", Reboot: false}, st); err != nil {
		t.Fatalf("handleMinorNoReboot: %v", err)
	}
	if len(f.terminals) != 1 || f.terminals[0].success {
		t.Fatalf("terminal responses = %+v, want one FAILED", f.terminals)
	}
}
