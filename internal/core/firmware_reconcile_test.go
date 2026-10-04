package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/firmware"
	"github.com/netdefense-io/ndagent/internal/pkgmgr"
	"github.com/netdefense-io/ndagent/internal/taskstore"
)

// fakeDevice stands in for the OPNsense box: what /running says and which
// release is installed. It counts how often each is read.
type fakeDevice struct {
	mu           sync.Mutex
	state        firmware.RunState
	runErr       error
	release      string
	releaseErr   error
	boot         int64
	installed    map[string]string
	installErr   error
	updating     bool
	runningReads int
	releaseReads int
}

func (d *fakeDevice) set(f func(*fakeDevice)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	f(d)
}

func (d *fakeDevice) probes() firmware.Probes {
	return firmware.Probes{
		Running: func(context.Context) (firmware.RunState, error) {
			d.mu.Lock()
			defer d.mu.Unlock()
			d.runningReads++
			return d.state, d.runErr
		},
		Release: func(context.Context) (string, error) {
			d.mu.Lock()
			defer d.mu.Unlock()
			d.releaseReads++
			return d.release, d.releaseErr
		},
		BootTime: func() (int64, error) {
			d.mu.Lock()
			defer d.mu.Unlock()
			return d.boot, nil
		},
		Installed: func(context.Context) (map[string]string, error) {
			d.mu.Lock()
			defer d.mu.Unlock()
			return d.installed, d.installErr
		},
		Updating: func(context.Context) (bool, error) {
			d.mu.Lock()
			defer d.mu.Unlock()
			return d.updating, nil
		},
	}
}

type resolveCall struct{ id, status, message string }

type reconcilerFixture struct {
	t     *testing.T
	store *taskstore.Store
	dev   *fakeDevice
	rec   *firmwareReconciler

	mu    sync.Mutex
	calls []resolveCall
	logs  []string
	live  map[string]bool
}

func (f *reconcilerFixture) resolved() []resolveCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]resolveCall(nil), f.calls...)
}

func (f *reconcilerFixture) logged() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.logs...)
}

func (f *reconcilerFixture) setLive(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.live[id] = true
}

// newReconcilerFixture wires a reconciler to an in-memory store, a fake device
// and a resolver that does what WebSocketClient.CompleteInProgressTask does to
// the store, without the socket.
func newReconcilerFixture(t *testing.T) *reconcilerFixture {
	t.Helper()
	store, err := taskstore.OpenInMemory()
	if err != nil {
		t.Fatalf("OpenInMemory: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	f := &reconcilerFixture{
		t:     t,
		store: store,
		dev:   &fakeDevice{state: firmware.RunReady, release: "26.7.4_1"},
		live:  map[string]bool{},
	}
	f.rec = newFirmwareReconciler(
		store,
		f.dev.probes(),
		func(id string) bool {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.live[id]
		},
		func(id, status, message string) (bool, error) {
			f.mu.Lock()
			f.calls = append(f.calls, resolveCall{id, status, message})
			f.mu.Unlock()
			return store.CompleteIfInProgress(id, status, message, nil)
		},
		func(format string, args ...interface{}) {
			f.mu.Lock()
			f.logs = append(f.logs, fmt.Sprintf(format, args...))
			f.mu.Unlock()
		},
	)
	return f
}

func (f *reconcilerFixture) begin(id, taskType string) {
	f.t.Helper()
	if err := f.store.Begin(id, taskType, taskstore.LifecycleRestartCompletes); err != nil {
		f.t.Fatalf("Begin %s: %v", id, err)
	}
}

func (f *reconcilerFixture) statusOf(id string) string {
	f.t.Helper()
	rec, found, err := f.store.Get(id)
	if err != nil || !found {
		f.t.Fatalf("Get %s: found=%v err=%v", id, found, err)
	}
	return rec.Status
}

// The box is busy running the update and the agent comes back: while /running is
// busy nothing may be resolved, however the row looks.
func TestSweep_BusyKeepsTheRowInProgress(t *testing.T) {
	f := newReconcilerFixture(t)
	f.begin("1", "FIRMWARE_UPGRADE")
	f.dev.set(func(d *fakeDevice) { d.state = firmware.RunBusy })

	f.rec.Sweep(context.Background())

	if got := f.resolved(); len(got) != 0 {
		t.Fatalf("resolved %+v while OPNsense was busy", got)
	}
	if s := f.statusOf("1"); s != taskstore.StatusInProgress {
		t.Fatalf("row is %s, want IN_PROGRESS", s)
	}
}

// An API that does not answer, or answers with nothing, is unknown, never ready.
func TestSweep_UnreadableBackendKeepsTheRowInProgress(t *testing.T) {
	for name, set := range map[string]func(*fakeDevice){
		"api error":    func(d *fakeDevice) { d.runErr = errors.New("connection refused") },
		"empty status": func(d *fakeDevice) { d.state = firmware.RunUnknown },
	} {
		t.Run(name, func(t *testing.T) {
			f := newReconcilerFixture(t)
			f.begin("1", "FIRMWARE_UPGRADE")
			f.dev.set(set)

			f.rec.Sweep(context.Background())

			if got := f.resolved(); len(got) != 0 {
				t.Fatalf("resolved %+v with an unreadable backend", got)
			}
			if s := f.statusOf("1"); s != taskstore.StatusInProgress {
				t.Fatalf("row is %s, want IN_PROGRESS", s)
			}
		})
	}
}

// Once the backend is idle a row with nothing recorded about its run completes
// the way it always did, with the release the device came back with.
func TestSweep_ReadyResolvesTheRowWithTheInstalledRelease(t *testing.T) {
	f := newReconcilerFixture(t)
	f.begin("1", "FIRMWARE_UPGRADE")

	f.rec.Sweep(context.Background())

	want := []resolveCall{{"1", taskstore.StatusCompleted, "Firmware upgrade completed; device returned with product_version 26.7.4_1"}}
	if got := f.resolved(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("resolved %+v, want %+v", got, want)
	}
	if s := f.statusOf("1"); s != taskstore.StatusCompleted {
		t.Fatalf("row is %s, want COMPLETED", s)
	}
}

func TestSweep_ReadyWithAnUnreadableReleaseStillResolves(t *testing.T) {
	f := newReconcilerFixture(t)
	f.begin("1", "FIRMWARE_UPGRADE")
	f.dev.set(func(d *fakeDevice) { d.releaseErr = errors.New("no version file") })

	f.rec.Sweep(context.Background())

	want := []resolveCall{{"1", taskstore.StatusCompleted, "Device returned after restart"}}
	if got := f.resolved(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("resolved %+v, want %+v", got, want)
	}
}

// A row that can never be resolved is not left IN_PROGRESS forever: past its
// deadline it is failed and says why.
func TestSweep_BusyPastTheDeadlineFails(t *testing.T) {
	f := newReconcilerFixture(t)
	f.begin("1", "FIRMWARE_UPGRADE")
	f.dev.set(func(d *fakeDevice) { d.state = firmware.RunBusy })

	rec, _, _ := f.store.Get("1")
	// The agent has been up for longer than the grace, and the row is older than
	// the longest task lifetime plus the grace.
	f.rec.uptime = func() time.Duration { return time.Hour }
	f.rec.now = func() time.Time { return rec.StartedAt.Add(firmware.MajorTTL + firmware.Grace + time.Second) }

	f.rec.Sweep(context.Background())

	got := f.resolved()
	if len(got) != 1 || got[0].status != taskstore.StatusFailed ||
		!strings.Contains(got[0].message, "still running a firmware job") {
		t.Fatalf("resolved %+v, want one FAILED that says OPNsense was still running a job", got)
	}
	if strings.HasPrefix(got[0].message, "{") {
		t.Fatalf("a failure must be plain text, got %q", got[0].message)
	}
}

// After a reboot the agent process is young. The first sweeps of that process
// must get a real chance to read the outcome: a row is failed only once the
// process itself has been up for the grace.
func TestSweep_DeadlineWaitsForTheProcessToHaveBeenUp(t *testing.T) {
	f := newReconcilerFixture(t)
	f.begin("1", "FIRMWARE_UPGRADE")
	f.dev.set(func(d *fakeDevice) { d.state = firmware.RunUnknown; d.runErr = errors.New("api not up yet") })

	rec, _, _ := f.store.Get("1")
	long := rec.StartedAt.Add(3 * time.Hour) // far past the row's own deadline
	f.rec.now = func() time.Time { return long }

	f.rec.uptime = func() time.Duration { return time.Minute }
	f.rec.Sweep(context.Background())
	if got := f.resolved(); len(got) != 0 {
		t.Fatalf("failed a row %s after the agent started, inside the grace: %+v", time.Minute, got)
	}

	f.rec.uptime = func() time.Duration { return firmware.Grace + time.Second }
	f.rec.Sweep(context.Background())
	got := f.resolved()
	if len(got) != 1 || got[0].status != taskstore.StatusFailed {
		t.Fatalf("resolved %+v, want the row failed once the process had been up for the grace", got)
	}
}

// A row whose handler is alive is the handler's: the reconciler must not even
// read the device for it.
func TestSweep_LiveRowIsNotTouched(t *testing.T) {
	f := newReconcilerFixture(t)
	f.begin("1", "FIRMWARE_UPGRADE")
	f.setLive("1")

	f.rec.Sweep(context.Background())

	if got := f.resolved(); len(got) != 0 {
		t.Fatalf("resolved %+v for a live row", got)
	}
	if f.dev.runningReads != 0 {
		t.Fatalf("read /running %d times for a live row", f.dev.runningReads)
	}
	if s := f.statusOf("1"); s != taskstore.StatusInProgress {
		t.Fatalf("row is %s, want IN_PROGRESS", s)
	}
}

func TestSweep_OnlyFirmwareRowsAreConsidered(t *testing.T) {
	f := newReconcilerFixture(t)
	f.begin("1", "SYNC")
	f.begin("2", "REBOOT")

	f.rec.Sweep(context.Background())

	if got := f.resolved(); len(got) != 0 {
		t.Fatalf("resolved %+v with no firmware row", got)
	}
	if f.dev.runningReads != 0 {
		t.Fatalf("read the device %d times with nothing to decide", f.dev.runningReads)
	}
}

// The Sunday daily and weekly rows are about the same update on the same box.
func TestSweep_SeveralRowsReadTheDeviceOnce(t *testing.T) {
	f := newReconcilerFixture(t)
	for _, id := range []string{"1", "2", "3"} {
		f.begin(id, "FIRMWARE_UPGRADE")
	}

	f.rec.Sweep(context.Background())

	if got := f.resolved(); len(got) != 3 {
		t.Fatalf("resolved %d rows, want 3", len(got))
	}
	if f.dev.runningReads != 1 || f.dev.releaseReads != 1 {
		t.Fatalf("read /running %d and the release %d times, want once each", f.dev.runningReads, f.dev.releaseReads)
	}
}

func TestSweep_ResolvesOnlyTheRowsTheDeviceHasAnAnswerFor(t *testing.T) {
	f := newReconcilerFixture(t)
	f.begin("1", "FIRMWARE_UPGRADE")
	f.begin("2", "FIRMWARE_UPGRADE")
	f.setLive("2")

	f.rec.Sweep(context.Background())

	got := f.resolved()
	if len(got) != 1 || got[0].id != "1" {
		t.Fatalf("resolved %+v, want only row 1", got)
	}
	if s := f.statusOf("2"); s != taskstore.StatusInProgress {
		t.Fatalf("live row is %s, want IN_PROGRESS", s)
	}
}

// Losing the compare-and-set means somebody else already decided; the
// reconciler says so and does nothing more.
func TestSweep_ARowResolvedElsewhereIsLeftAlone(t *testing.T) {
	f := newReconcilerFixture(t)
	f.begin("1", "FIRMWARE_UPGRADE")
	f.rec.resolve = func(id, status, message string) (bool, error) { return false, nil }

	f.rec.Sweep(context.Background())

	logs := strings.Join(f.logged(), "\n")
	if !strings.Contains(logs, "already resolved") {
		t.Fatalf("expected a log line about the row being already resolved, got:\n%s", logs)
	}
}

func TestSweep_ADeliveryFailureIsReportedNotRetriedAsAnotherOutcome(t *testing.T) {
	f := newReconcilerFixture(t)
	f.begin("1", "FIRMWARE_UPGRADE")
	f.rec.resolve = func(id, status, message string) (bool, error) {
		return true, errors.New("websocket not connected")
	}

	f.rec.Sweep(context.Background())
	f.rec.Sweep(context.Background())

	logs := strings.Join(f.logged(), "\n")
	if !strings.Contains(logs, "replayed on the next connect") {
		t.Fatalf("expected the log to say the outcome will be replayed, got:\n%s", logs)
	}
}

// A row that waits twenty minutes must not fill the log with a line per sweep.
func TestSweep_LogsAWaitWhenItStartsAndWhenItChanges(t *testing.T) {
	f := newReconcilerFixture(t)
	f.begin("1", "FIRMWARE_UPGRADE")
	f.dev.set(func(d *fakeDevice) { d.state = firmware.RunBusy })

	for i := 0; i < 5; i++ {
		f.rec.Sweep(context.Background())
	}
	if n := len(f.logged()); n != 1 {
		t.Fatalf("%d log lines for five identical waits, want 1: %v", n, f.logged())
	}

	f.dev.set(func(d *fakeDevice) { d.state = firmware.RunUnknown; d.runErr = errors.New("api down") })
	f.rec.Sweep(context.Background())
	if n := len(f.logged()); n != 2 {
		t.Fatalf("%d log lines after the reason changed, want 2: %v", n, f.logged())
	}
}

// The loop belongs to the phase: it sweeps until its context ends and not after.
func TestRun_SweepsUntilTheContextEnds(t *testing.T) {
	f := newReconcilerFixture(t)
	f.begin("1", "FIRMWARE_UPGRADE")
	f.dev.set(func(d *fakeDevice) { d.state = firmware.RunBusy })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.rec.Run(ctx, 5*time.Millisecond)
	}()

	reads := func() int {
		f.dev.mu.Lock()
		defer f.dev.mu.Unlock()
		return f.dev.runningReads
	}
	deadline := time.Now().Add(2 * time.Second)
	for reads() < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("only %d sweeps ran", reads())
		}
		time.Sleep(time.Millisecond)
	}

	// The device becomes ready while the loop runs: the next sweep resolves it.
	f.dev.set(func(d *fakeDevice) { d.state = firmware.RunReady })
	deadline = time.Now().Add(2 * time.Second)
	for len(f.resolved()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the loop never resolved the row once the device was ready")
		}
		time.Sleep(time.Millisecond)
	}

	cancel()
	<-done
	after := reads()
	time.Sleep(50 * time.Millisecond)
	if reads() != after {
		t.Fatal("the loop kept sweeping after its context ended")
	}
	if got := f.resolved(); len(got) != 1 {
		t.Fatalf("resolved %d times, want once", len(got))
	}
}

// The connect hook and the ticker can fire together; overlapping sweeps must not
// both decide the same row.
func TestSweep_OverlappingSweepsResolveARowOnce(t *testing.T) {
	f := newReconcilerFixture(t)
	f.begin("1", "FIRMWARE_UPGRADE")

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f.rec.Sweep(context.Background())
		}()
	}
	wg.Wait()

	if got := f.resolved(); len(got) != 1 {
		t.Fatalf("resolved %d times, want once: %+v", len(got), got)
	}
}

// ── rows the handler recorded its run for ───────────────────────────────────

const (
	testBoot = int64(1_780_000_000)
	fromRel  = "26.7.3_8"
	toRel    = "26.7.4_1"
)

// beginRecorded starts a row whose run was recorded and triggered, as the handler
// does right before it asks OPNsense to start; beginNotTriggered starts one that
// was only taken up.
func (f *reconcilerFixture) beginRecorded(id string, m firmware.Meta) {
	f.t.Helper()
	f.begin(id, "FIRMWARE_UPGRADE")
	rec, _, _ := f.store.Get(id)
	if m.StartedAt == 0 {
		m.StartedAt = rec.StartedAt.Unix()
	}
	if m.ExpiresAt == 0 {
		m.ExpiresAt = rec.StartedAt.Add(firmware.TTL(m.Mode)).Unix()
	}
	if m.TriggeredAt == 0 {
		m.TriggeredAt = m.StartedAt
	}
	if err := f.store.SetTaskMeta(id, m); err != nil {
		f.t.Fatalf("SetTaskMeta: %v", err)
	}
}

func (f *reconcilerFixture) beginNotTriggered(id string, m firmware.Meta) {
	f.t.Helper()
	f.begin(id, "FIRMWARE_UPGRADE")
	rec, _, _ := f.store.Get(id)
	m.StartedAt, m.ExpiresAt, m.TriggeredAt = rec.StartedAt.Unix(), rec.StartedAt.Add(firmware.TTL(m.Mode)).Unix(), 0
	if err := f.store.SetTaskMeta(id, m); err != nil {
		f.t.Fatalf("SetTaskMeta: %v", err)
	}
}

func weeklyRun() firmware.Meta {
	return firmware.Meta{
		Mode: "minor", Reboot: true, FromVersion: fromRel, BootTime: testBoot,
		Packages: []firmware.Package{
			{Name: "opnsense", Version: toRel}, {Name: "os-netdefense", Version: "1.19.5"},
			{Name: "base", Version: "26.7.4"}, {Name: "kernel", Version: "26.7.4"},
		},
	}
}

// The update replaced the core package (the release already reads as the new
// one) but OPNsense is still busy installing the base system and kernel. The row
// must wait, and complete only after the reboot.
func TestSweep_ARecordedRunCompletesOnlyOnceTheBoxHasRebootedAndIsIdle(t *testing.T) {
	f := newReconcilerFixture(t)
	f.beginRecorded("1", weeklyRun())
	f.dev.set(func(d *fakeDevice) {
		d.state, d.release, d.boot = firmware.RunBusy, toRel, testBoot // busy, release advanced, no reboot yet
		d.installed = map[string]string{"opnsense": toRel, "os-netdefense": "1.19.5"}
	})

	f.rec.Sweep(context.Background())
	if got := f.resolved(); len(got) != 0 {
		t.Fatalf("resolved %+v while OPNsense was busy with the release already advanced", got)
	}

	// The box came back: idle, rebooted an hour later.
	f.dev.set(func(d *fakeDevice) { d.state, d.boot = firmware.RunReady, testBoot+3600 })
	f.rec.Sweep(context.Background())

	got := f.resolved()
	if len(got) != 1 || got[0].status != taskstore.StatusCompleted {
		t.Fatalf("resolved %+v, want one COMPLETED", got)
	}
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(got[0].message), &result); err != nil {
		t.Fatalf("the message is not JSON: %v\n%s", err, got[0].message)
	}
	for k, want := range map[string]interface{}{
		"resolved_mode": "minor", "from_version": fromRel, "to_version": toRel,
		"applied": true, "reboot_performed": true, "reconciled": true,
	} {
		if result[k] != want {
			t.Errorf("%s = %v, want %v", k, result[k], want)
		}
	}
}

// A packages-only update, and the agent's own upgrade, keep the release.
func TestSweep_APackagesOnlyRunCompletesWhenEveryPlannedPackageIsInstalled(t *testing.T) {
	f := newReconcilerFixture(t)
	run := firmware.Meta{
		Mode: "minor", Reboot: false, FromVersion: toRel, BootTime: testBoot,
		Packages: []firmware.Package{{Name: "os-netdefense", Version: "1.19.5"}, {Name: "curl", Version: "8.9.1_1"}},
	}
	f.beginRecorded("1", run)
	f.dev.set(func(d *fakeDevice) {
		d.release, d.boot = toRel, testBoot
		d.installed = map[string]string{"os-netdefense": "1.19.5", "curl": "8.9.1_1"}
	})

	f.rec.Sweep(context.Background())

	got := f.resolved()
	if len(got) != 1 || got[0].status != taskstore.StatusCompleted || !strings.Contains(got[0].message, `"to_version":"26.7.4_1"`) {
		t.Fatalf("resolved %+v, want a COMPLETED that keeps the release", got)
	}
}

// The killed exec child leaves pkg running: an incomplete plan is not yet a
// failed one.
func TestSweep_AnIncompletePlanWaitsWhilePackageToolsRunAndFailsWhenTheyStop(t *testing.T) {
	f := newReconcilerFixture(t)
	f.beginRecorded("1", firmware.Meta{
		Mode: "minor", Reboot: false, FromVersion: toRel, BootTime: testBoot,
		Packages: []firmware.Package{{Name: "os-netdefense", Version: "1.19.5"}, {Name: "curl", Version: "8.9.1_1"}},
	})
	f.dev.set(func(d *fakeDevice) {
		d.release, d.boot, d.updating = toRel, testBoot, true
		d.installed = map[string]string{"os-netdefense": "1.19.5", "curl": "8.9.0"}
	})

	f.rec.Sweep(context.Background())
	if got := f.resolved(); len(got) != 0 {
		t.Fatalf("resolved %+v while pkg was still running", got)
	}

	f.dev.set(func(d *fakeDevice) { d.updating = false })
	f.rec.Sweep(context.Background())
	got := f.resolved()
	if len(got) != 1 || got[0].status != taskstore.StatusFailed || !strings.Contains(got[0].message, "curl") {
		t.Fatalf("resolved %+v, want one FAILED naming curl", got)
	}
	if strings.HasPrefix(got[0].message, "{") {
		t.Fatalf("a failure must be plain text: %q", got[0].message)
	}
}

// The run's own recorded expiry, not the longest task lifetime, bounds its wait.
func TestSweep_ARecordedRunIsBoundedByItsOwnExpiry(t *testing.T) {
	f := newReconcilerFixture(t)
	f.beginRecorded("1", weeklyRun())
	f.dev.set(func(d *fakeDevice) { d.state = firmware.RunBusy })

	rec, _, _ := f.store.Get("1")
	f.rec.uptime = func() time.Duration { return time.Hour }

	f.rec.now = func() time.Time { return rec.StartedAt.Add(firmware.MinorTTL) }
	f.rec.Sweep(context.Background())
	if got := f.resolved(); len(got) != 0 {
		t.Fatalf("failed a run at its expiry, inside the grace: %+v", got)
	}

	f.rec.now = func() time.Time { return rec.StartedAt.Add(firmware.MinorTTL + firmware.Grace + time.Second) }
	f.rec.Sweep(context.Background())
	got := f.resolved()
	if len(got) != 1 || got[0].status != taskstore.StatusFailed {
		t.Fatalf("resolved %+v, want the run failed once its expiry and the grace passed", got)
	}
}

// Metadata that is not a firmware run's is not a run: the row is decided as one
// with none.
func TestSweep_UnrelatedMetadataIsTreatedAsNone(t *testing.T) {
	f := newReconcilerFixture(t)
	f.begin("1", "FIRMWARE_UPGRADE")
	if err := f.store.SetTaskMeta("1", map[string]string{"package_name": "os-netdefense"}); err != nil {
		t.Fatalf("SetTaskMeta: %v", err)
	}

	f.rec.Sweep(context.Background())

	got := f.resolved()
	if len(got) != 1 || got[0].status != taskstore.StatusCompleted ||
		!strings.HasPrefix(got[0].message, "Firmware upgrade completed; device returned") {
		t.Fatalf("resolved %+v, want the as-before completion", got)
	}
}

// ── rows that never started ─────────────────────────────────────────────────

// A task that was taken up and then waited for its turn (behind the other of the
// Sunday pair, or for OPNsense to be free) is a row too, when the agent stops
// under it. Nothing was triggered, so nothing was applied, and the row must not
// be mistaken for one an older agent wrote, which is completed as soon as the box
// is idle: the weekly update would be reported done though it never ran.
func TestSweep_ATaskThatNeverTriggeredAnythingIsFailedAndSaysSo(t *testing.T) {
	f := newReconcilerFixture(t)
	f.beginNotTriggered("1", weeklyRun()) // idle box, the release already the new one
	f.dev.set(func(d *fakeDevice) { d.release, d.boot = toRel, testBoot+3600 })

	f.rec.Sweep(context.Background())

	got := f.resolved()
	if len(got) != 1 || got[0].status != taskstore.StatusFailed ||
		!strings.Contains(got[0].message, "was not started") ||
		!strings.Contains(got[0].message, "Nothing was applied by this task") {
		t.Fatalf("resolved %+v, want one FAILED saying the task was not started", got)
	}
	if strings.HasPrefix(got[0].message, "{") {
		t.Fatalf("a failure must be plain text: %q", got[0].message)
	}
	if f.dev.runningReads != 0 || f.dev.releaseReads != 0 {
		t.Fatalf("read the device (/running %d, release %d times) to decide a task that never touched it",
			f.dev.runningReads, f.dev.releaseReads)
	}
}

// Whatever the device is doing says nothing about a task that did nothing to it.
func TestSweep_ATaskThatNeverTriggeredAnythingIsFailedWhileOPNsenseIsBusyToo(t *testing.T) {
	f := newReconcilerFixture(t)
	f.beginNotTriggered("1", weeklyRun())
	f.dev.set(func(d *fakeDevice) { d.state = firmware.RunBusy })

	f.rec.Sweep(context.Background())

	if got := f.resolved(); len(got) != 1 || got[0].status != taskstore.StatusFailed {
		t.Fatalf("resolved %+v, want the task failed at once", got)
	}
}

// The other row of the mixed pair is still judged by the device: its exec child
// died with the agent and its package tools are still installing.
func TestSweep_TheMixedPairAfterAnAgentRestartResolvesEachRowOnItsOwn(t *testing.T) {
	f := newReconcilerFixture(t)
	f.beginRecorded("1", firmware.Meta{ // the reboot=false run whose exec child was killed
		Mode: "minor", Reboot: false, FromVersion: fromRel, BootTime: testBoot,
		Packages: []firmware.Package{{Name: "opnsense", Version: toRel}, {Name: "os-netdefense", Version: "1.19.5"}},
	})
	f.beginNotTriggered("2", weeklyRun()) // the weekly task that was waiting behind it
	f.dev.set(func(d *fakeDevice) {
		d.release, d.boot, d.updating = toRel, testBoot, true // the core package is in, pkg is still busy
		d.installed = map[string]string{"opnsense": toRel}
	})

	f.rec.Sweep(context.Background())
	got := f.resolved()
	if len(got) != 1 || got[0].id != "2" || got[0].status != taskstore.StatusFailed {
		t.Fatalf("resolved %+v while pkg was still installing, want only the waiting task, failed", got)
	}
	if s := f.statusOf("1"); s != taskstore.StatusInProgress {
		t.Fatalf("the killed run is %s while pkg is still installing, want IN_PROGRESS", s)
	}

	f.dev.set(func(d *fakeDevice) {
		d.updating = false
		d.installed = map[string]string{"opnsense": toRel, "os-netdefense": "1.19.5"}
	})
	f.rec.Sweep(context.Background())
	if s := f.statusOf("1"); s != taskstore.StatusCompleted {
		t.Fatalf("the killed run is %s once pkg finished with every package in, want COMPLETED", s)
	}
}

// The release moves in the first minute of a package run; the packages after it
// are still to come, and only the package tools show that.
func TestSweep_ANoRebootRunIsNotCompletedByTheReleaseAloneWhilePkgInstalls(t *testing.T) {
	f := newReconcilerFixture(t)
	f.beginRecorded("1", firmware.Meta{
		Mode: "minor", Reboot: false, FromVersion: fromRel, BootTime: testBoot,
		Packages: []firmware.Package{{Name: "opnsense", Version: toRel}, {Name: "os-netdefense", Version: "1.19.5"}},
	})
	f.dev.set(func(d *fakeDevice) {
		d.release, d.boot, d.updating = toRel, testBoot, true
		d.installed = map[string]string{"opnsense": toRel}
	})

	f.rec.Sweep(context.Background())

	if got := f.resolved(); len(got) != 0 {
		t.Fatalf("resolved %+v with the release advanced and pkg still running", got)
	}
}

// A row an older agent wrote may have been a reboot=false run: its exec child
// died with the agent and pkg went on.
func TestSweep_ARowWithNoRecordWaitsWhilePackageToolsRun(t *testing.T) {
	f := newReconcilerFixture(t)
	f.begin("1", "FIRMWARE_UPGRADE")
	f.dev.set(func(d *fakeDevice) { d.updating = true })

	f.rec.Sweep(context.Background())
	if got := f.resolved(); len(got) != 0 {
		t.Fatalf("resolved %+v while package tools were running", got)
	}

	f.dev.set(func(d *fakeDevice) { d.updating = false })
	f.rec.Sweep(context.Background())
	if got := f.resolved(); len(got) != 1 || got[0].status != taskstore.StatusCompleted {
		t.Fatalf("resolved %+v, want the row completed once the tools stopped", got)
	}
}

// ── the guard the rest of the agent consults ────────────────────────────────

// While a row waits on the device the agent must not start firmware checks of its
// own: they would take the lock the update needs and truncate its progress log.
func TestSweep_KeepsFirmwareChecksOffWhileRowsWait(t *testing.T) {
	t.Cleanup(func() { firmware.Watch(0) })
	f := newReconcilerFixture(t)
	f.begin("1", "FIRMWARE_UPGRADE")
	f.dev.set(func(d *fakeDevice) { d.state = firmware.RunBusy })

	f.rec.Sweep(context.Background())
	if !firmware.Busy() {
		t.Fatal("firmware.Busy is false while a row waits on a busy device")
	}

	f.dev.set(func(d *fakeDevice) { d.state = firmware.RunReady })
	f.rec.Sweep(context.Background())
	if firmware.Busy() {
		t.Fatal("firmware.Busy is still true after the sweep resolved the row")
	}
}

// A row whose handler is alive is covered by the handler's own hold, and a store
// with no firmware rows holds nothing.
func TestSweep_DoesNotWatchALiveRowOrAnEmptyStore(t *testing.T) {
	t.Cleanup(func() { firmware.Watch(0) })
	f := newReconcilerFixture(t)

	f.rec.Sweep(context.Background())
	if firmware.Busy() {
		t.Fatal("firmware.Busy with no firmware rows")
	}

	f.begin("1", "FIRMWARE_UPGRADE")
	f.setLive("1")
	f.rec.Sweep(context.Background())
	if firmware.Busy() {
		t.Fatal("the reconciler watched a row whose handler is alive")
	}
}

// What the loop waited on is not something a dead loop can answer for.
func TestRun_StopsWatchingWhenItEnds(t *testing.T) {
	t.Cleanup(func() { firmware.Watch(0) })
	f := newReconcilerFixture(t)
	f.begin("1", "FIRMWARE_UPGRADE")
	f.dev.set(func(d *fakeDevice) { d.state = firmware.RunBusy })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.rec.Run(ctx, 5*time.Millisecond)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for !firmware.Busy() {
		if time.Now().After(deadline) {
			t.Fatal("the loop never marked the box busy")
		}
		time.Sleep(time.Millisecond)
	}

	cancel()
	<-done
	if firmware.Busy() {
		t.Fatal("firmware.Busy is still true after the loop ended")
	}
}

// ── the sweep on the connect path must not stall the connect ────────────────

// SoftwarePolicy installs hold the process-wide package lock for up to ten
// minutes. A sweep that needs the package database while one runs waits for the
// lock under its own context: the connect-time hook has fifteen seconds, and an
// authenticated connection sits idle (no heartbeats, no commands) until it returns.
func TestSweep_APackageOperationInFlightDoesNotStallTheSweep(t *testing.T) {
	f := newReconcilerFixture(t)
	f.beginRecorded("1", firmware.Meta{
		Mode: "minor", Reboot: false, FromVersion: toRel, BootTime: testBoot,
		Packages: []firmware.Package{{Name: "os-netdefense", Version: "1.19.5"}},
	})
	f.dev.set(func(d *fakeDevice) { d.release, d.boot = toRel, testBoot })
	f.rec.probes.Installed = pkgmgr.InstalledVersions // the production probe

	release := make(chan struct{})
	entered := make(chan struct{})
	prev := pkgmgr.SetInstallFunc(func(context.Context, string) pkgmgr.MutateOutcome {
		close(entered)
		<-release
		return pkgmgr.MutateOutcome{}
	})
	t.Cleanup(func() { pkgmgr.SetInstallFunc(prev) })
	installed := make(chan struct{})
	go func() { defer close(installed); pkgmgr.Install(context.Background(), "some-package") }()
	<-entered
	t.Cleanup(func() { close(release); <-installed })

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); f.rec.Sweep(ctx) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the sweep is still waiting for the package lock long after its context ended")
	}
	if got := f.resolved(); len(got) != 0 {
		t.Fatalf("resolved %+v without being able to read the package database", got)
	}
}

// The connect hook and the ticker share the sweep. A hook that finds a sweep
// already under way has nothing to add: that sweep, or the next tick, decides.
func TestSweep_ASweepUnderWayIsNotQueuedBehind(t *testing.T) {
	f := newReconcilerFixture(t)
	f.begin("1", "FIRMWARE_UPGRADE")

	inside := make(chan struct{})
	unblock := make(chan struct{})
	var open sync.Once
	letGo := func() { open.Do(func() { close(unblock) }) }
	t.Cleanup(letGo)
	f.rec.probes.Release = func(context.Context) (string, error) {
		close(inside)
		<-unblock
		return toRel, nil
	}
	first := make(chan struct{})
	go func() { defer close(first); f.rec.Sweep(context.Background()) }()
	<-inside

	second := make(chan struct{})
	go func() { defer close(second); f.rec.Sweep(context.Background()) }()
	select {
	case <-second:
	case <-time.After(time.Second):
		t.Fatal("a second sweep waited for the first instead of leaving it to finish")
	}
	letGo()
	<-first
	if got := f.resolved(); len(got) != 1 {
		t.Fatalf("resolved %+v, want the first sweep's single resolution", got)
	}
}

// A sweep whose context ran out part-way still leaves the guard counting what is
// left, not what it started with: a task waiting for the reconciler's rows would
// otherwise wait for rows that no longer need anyone.
func TestSweep_ASweepCutShortStillCountsWhatIsLeft(t *testing.T) {
	t.Cleanup(func() { firmware.Watch(0) })
	f := newReconcilerFixture(t)
	f.begin("1", "FIRMWARE_UPGRADE")
	f.begin("2", "FIRMWARE_UPGRADE")

	// Resolving the first row ends the sweep's context, and settles the second one
	// behind the sweep's back before it is looked at.
	ctx, cancel := context.WithCancel(context.Background())
	f.rec.resolve = func(id, status, message string) (bool, error) {
		cancel()
		_, _ = f.store.CompleteIfInProgress("2", taskstore.StatusFailed, "settled elsewhere", nil)
		return f.store.CompleteIfInProgress(id, status, message, nil)
	}
	f.rec.Sweep(ctx)

	if f.statusOf("1") != taskstore.StatusCompleted || f.statusOf("2") != taskstore.StatusFailed {
		t.Fatalf("rows are %s and %s", f.statusOf("1"), f.statusOf("2"))
	}
	if firmware.Busy() {
		t.Fatal("the guard still counts rows the sweep began with, although none is left")
	}
}

// A read that never finishes must not hold the ticker's sweep forever, or every
// later sweep would be skipped behind it and no row would ever be decided.
func TestRun_ASweepThatCannotFinishIsCutOffAndTheNextOneRuns(t *testing.T) {
	f := newReconcilerFixture(t)
	f.begin("1", "FIRMWARE_UPGRADE")
	f.rec.sweepTimeout = 30 * time.Millisecond

	var reads int
	var mu sync.Mutex
	f.rec.probes.Release = func(ctx context.Context) (string, error) {
		mu.Lock()
		reads++
		n := reads
		mu.Unlock()
		if n == 1 {
			<-ctx.Done() // the first read hangs until the sweep's own deadline
			return "", ctx.Err()
		}
		return toRel, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); f.rec.Run(ctx, 5*time.Millisecond) }()
	defer func() { cancel(); <-done }()

	deadline := time.Now().Add(3 * time.Second)
	for len(f.resolved()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the loop never got past the sweep that could not finish")
		}
		time.Sleep(time.Millisecond)
	}
	if got := f.resolved(); got[0].status != taskstore.StatusCompleted {
		t.Fatalf("resolved %+v, want the row completed by the sweep that followed", got)
	}
}

func drainOutcomes() int {
	n := 0
	for {
		select {
		case <-firmware.Outcomes():
			n++
		default:
			return n
		}
	}
}

// A row the reconciler resolves whose run asked OPNsense to apply something, or
// that has no record of its run (an older agent wrote it), asks the
// heavy-telemetry collector to check for updates again. A row whose task never
// triggered anything, and a row someone else resolved, do not.
func TestSweep_AResolvedRunThatTriggeredAsksForAFirmwareCheck(t *testing.T) {
	cases := []struct {
		name  string
		setup func(f *reconcilerFixture)
		want  int
	}{
		{"a run that was triggered", func(f *reconcilerFixture) {
			f.beginRecorded("1", weeklyRun())
			f.dev.set(func(d *fakeDevice) { // back from the reboot, idle, on the new release
				d.state, d.release, d.boot = firmware.RunReady, toRel, testBoot+3600
				d.installed = map[string]string{"opnsense": toRel, "os-netdefense": "1.19.5"}
			})
		}, 1},
		{"a row with no record of its run", func(f *reconcilerFixture) { f.begin("1", "FIRMWARE_UPGRADE") }, 1},
		{"a task that never triggered anything", func(f *reconcilerFixture) { f.beginNotTriggered("1", weeklyRun()) }, 0},
		{"a row resolved elsewhere", func(f *reconcilerFixture) {
			f.begin("1", "FIRMWARE_UPGRADE")
			f.rec.resolve = func(id, status, message string) (bool, error) { return false, nil }
		}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newReconcilerFixture(t)
			tc.setup(f)
			drainOutcomes()

			f.rec.Sweep(context.Background())
			if len(f.resolved()) == 0 && tc.want > 0 {
				t.Fatalf("the row was not resolved: %v", f.logged())
			}
			if n := drainOutcomes(); n != tc.want {
				t.Fatalf("%d firmware checks asked for, want %d", n, tc.want)
			}
		})
	}
}
