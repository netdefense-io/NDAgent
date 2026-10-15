package core

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/config"
	"github.com/netdefense-io/ndagent/internal/firmware"
	"github.com/netdefense-io/ndagent/internal/firmware/track"
	"github.com/netdefense-io/ndagent/internal/network"
	"github.com/netdefense-io/ndagent/internal/opnapi"
	"github.com/netdefense-io/ndagent/internal/signing"
	"github.com/netdefense-io/ndagent/internal/state"
	"github.com/netdefense-io/ndagent/internal/tasks"
	"github.com/netdefense-io/ndagent/internal/taskstore"
	"github.com/netdefense-io/ndagent/internal/testbroker"
)

// pinnedDevice is a box whose pin was moved ahead for an update that then failed:
// the firmware flavour is at the target, the installed release did not move, and
// OPNsense's log says the update failed part-way. The methods of a series upgrade
// are the embedded interface's, which is nil: these tests never ask for one.
type pinnedDevice struct {
	track.Device
	mu        sync.Mutex
	flavour   string
	installed string
	reads     int
	checks    int
	failed    bool
}

func (d *pinnedDevice) Settings(context.Context) (opnapi.FirmwareSettings, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.reads++
	return opnapi.FirmwareSettings{Flavour: d.flavour}, nil
}
func (d *pinnedDevice) SetFlavour(_ context.Context, f string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.flavour = f
	return nil
}
func (d *pinnedDevice) Installed(context.Context) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.installed, nil
}
func (d *pinnedDevice) RepoBase(context.Context) (track.RepoBase, error) {
	return track.RepoBase{Base: "https://pkg.example.test", ABI: "FreeBSD:15:amd64", Series: "26.7", Path: "26.7/latest"}, nil
}
func (d *pinnedDevice) RepoPath(context.Context) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.flavour == "" {
		return "26.7/latest", nil
	}
	return d.flavour, nil
}
func (d *pinnedDevice) Probe(context.Context, string) track.ProbeResult { return track.ProbeFound }
func (d *pinnedDevice) Running(context.Context) (firmware.RunState, error) {
	return firmware.RunReady, nil
}
func (d *pinnedDevice) TriggerCheck(context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.checks++
	return nil
}
func (d *pinnedDevice) Status(context.Context) (*opnapi.FirmwareUpgradeStatus, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return &opnapi.FirmwareUpgradeStatus{
		Status: "none", Connection: "ok", Repository: "ok", ProductVersion: d.installed, InstalledVersion: d.installed,
		LastCheck: fmt.Sprintf("check %d", d.checks),
	}, nil
}
func (d *pinnedDevice) TriggerUpdate(context.Context) (string, error) { return "ok", nil }
func (d *pinnedDevice) Progress(context.Context) (*opnapi.FirmwareProgressStatus, error) {
	return &opnapi.FirmwareProgressStatus{Status: "done"}, nil
}
func (d *pinnedDevice) ApplyPackagesOnly(context.Context) (track.ExecResult, error) {
	return track.ExecResult{}, nil
}
func (d *pinnedDevice) Probes() firmware.Probes {
	return firmware.Probes{
		Running:  func(context.Context) (firmware.RunState, error) { return firmware.RunReady, nil },
		Locked:   func(context.Context) (bool, error) { return false, nil },
		Release:  func(context.Context) (string, error) { return d.Installed(context.Background()) },
		BootTime: func() (int64, error) { return 1_780_000_000, nil },
		Installed: func(context.Context) (map[string]string, error) {
			return map[string]string{"opnsense": d.installed}, nil
		},
		Updating: func(context.Context) (bool, error) { return false, nil },
		Evidence: func(context.Context, time.Time) (string, error) {
			d.mu.Lock()
			defer d.mu.Unlock()
			if d.failed {
				return firmware.PartialFailureMarker, nil
			}
			return "", nil
		},
	}
}

const (
	trackPrev = "26.7/MINT/26.7.3/latest"
	trackNext = "26.7/MINT/26.7.5/latest"
)

var trackApproved = map[string]string{"26.7": "26.7.5"}

// triggeredAdvance is the record of an advance whose update was requested and
// whose handler is gone: the row, its job, and the agent's record of the move.
func triggeredAdvance(t *testing.T, store *taskstore.Store, st *track.StateStore, taskID string) track.Job {
	t.Helper()
	now := time.Now()
	meta := firmware.NewMeta("minor", true, "26.7.3_11", &opnapi.FirmwareUpgradeStatus{
		UpgradePackages: []opnapi.FirmwarePackageEntry{
			{Name: "opnsense", Repository: "OPNsense", CurrentVersion: "26.7.3_11", NewVersionAlt: "26.7.5"},
			{Name: "base", Repository: "OPNsense", CurrentVersion: "26.7.3", NewVersionAlt: "26.7.4"},
			{Name: "kernel", Repository: "OPNsense", CurrentVersion: "26.7.3", NewVersionAlt: "26.7.4"},
		},
	}, 1_780_000_000, now, now.Add(20*time.Minute))
	meta.TriggeredAt = now.Unix()
	job := track.Job{
		Action: "advance", Track: "fast", Approved: trackApproved, Reboot: true, Phase: track.PhaseTriggered,
		From: "26.7.3_11", Target: "26.7.5", PrevFlavour: trackPrev, NewFlavour: trackNext,
		StartedAt: now.Unix(), ExpiresAt: now.Add(20 * time.Minute).Unix(), Upgrade: &meta,
	}
	if err := store.Begin(taskID, network.TaskTypeFirmwareTrack, taskstore.LifecycleSynchronous); err != nil {
		t.Fatal(err)
	}
	if err := store.SetTaskMeta(taskID, job); err != nil {
		t.Fatal(err)
	}
	if err := st.Save(&track.State{
		Pinned: true, Track: "fast", PinnedFlavour: trackPrev, PinnedVersion: "26.7.3_11",
		Pending: &track.Pending{Op: "advance", TaskID: taskID, FromFlavour: trackPrev, ToFlavour: trackNext, Triggered: true, StartedAt: now.Unix()},
	}); err != nil {
		t.Fatal(err)
	}
	return job
}

func newTrackEngine(t *testing.T, dev track.Device) (*track.Engine, *track.StateStore) {
	t.Helper()
	// The guard is process-wide state the other tests of this package leave
	// counts in; these tests need the slot.
	firmware.ResetGuardForTest()
	t.Cleanup(firmware.ResetGuardForTest)
	st := track.NewStateStore(filepath.Join(t.TempDir(), "firmware-track.json"))
	return track.New(dev, st, nil,
		track.WithTiming(track.Timing{Poll: time.Millisecond, ReadyWait: 50 * time.Millisecond, CheckTimeout: 500 * time.Millisecond,
			CheckIdleDrop: 20 * time.Millisecond, StartWindow: 20 * time.Millisecond, StartPoll: time.Millisecond, Settle: time.Millisecond}),
		track.WithJitter(func(time.Duration) time.Duration { return 0 }),
		track.WithUptime(func() time.Duration { return time.Hour })), st
}

// startTrackPhase is a WebSocket phase as runWebSocketPhase runs it for the
// FIRMWARE_TRACK rows: a real client over a real connection, a real task store,
// and the row reconciler wired by the function the phase calls.
func startTrackPhase(t *testing.T, b *testbroker.Broker, store *taskstore.Store, engine *track.Engine, interval time.Duration) *network.WebSocketClient {
	t.Helper()
	_, priv, err := signing.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	stateStore, err := state.New(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		ServerURIWS:   b.URL(),
		DeviceUUID:    "3a1e88a3-0000-4000-8000-0000000000aa",
		Token:         "00000000-0000-4000-8000-000000000000",
		DevicePrivKey: base64.StdEncoding.EncodeToString(signing.SeedFromPrivateKey(priv)),
	}
	ws := network.NewWebSocketClient(cfg, stateStore, store, tasks.LifecycleFor, b.NDMKeys())
	ctx, cancel := context.WithCancel(context.Background())
	startTrackRowReconciler(ctx, ws, store, engine, func(string, ...interface{}) {}, interval)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = ws.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
		firmware.WatchTracks(0)
	})
	return ws
}

// The connection drops under an update the box then fails; the agent that comes
// back decides the row from the device: failed, with the release it was moving to
// in the signed response, the pin pulled back, and one answer on the wire.
func TestTrackPhase_AFailedUpdateIsAnsweredOnceWithTheReleaseItWasMovingTo(t *testing.T) {
	b := testbroker.New(t)
	store := openStore(t)
	dev := &pinnedDevice{flavour: trackNext, installed: "26.7.3_11", failed: true}
	engine, st := newTrackEngine(t, dev)
	triggeredAdvance(t, store, st, "401")

	startTrackPhase(t, b, store, engine, time.Hour)
	b.WaitFor("the answer for 401", 5*time.Second, func() bool { return len(b.TaskResponses()) >= 1 })

	got := b.TaskResponses()
	if len(got) != 1 || got[0].TaskID != 401 || got[0].Status != "FAILED" {
		t.Fatalf("task responses = %+v, want one FAILED for 401", got)
	}
	var detail map[string]string
	if err := json.Unmarshal(got[0].Inner[track.FailureKey], &detail); err != nil {
		t.Fatalf("the signed response carries no failure detail: %v (%v)", err, got[0].Inner)
	}
	if detail["target"] != "26.7.5" || detail["pinned_version"] != "26.7.3_11" {
		t.Errorf("detail %v", detail)
	}
	if dev.flavour != trackPrev {
		t.Errorf("flavour %q: the pin was left ahead of the installed release", dev.flavour)
	}
	// The broker counts the answer when it arrives; the agent marks the row delivered
	// when its send returns, which can be a moment later.
	b.WaitFor("the row to be marked delivered", 5*time.Second, func() bool {
		rec, _, _ := store.Get("401")
		return rec.Delivered
	})
	if rec, _, _ := store.Get("401"); rec.Status != taskstore.StatusFailed || !rec.Delivered {
		t.Errorf("row %+v", rec)
	}
	time.Sleep(100 * time.Millisecond)
	if got := b.TaskResponses(); len(got) != 1 {
		t.Errorf("task responses = %+v, want the answer sent once", got)
	}
}

// blockingDevice is a box whose settings cannot be read until the test lets it:
// what the connect would hang on if it waited for the sweep.
type blockingDevice struct {
	*pinnedDevice
	release chan struct{}
	entered chan struct{}
}

func (d *blockingDevice) Settings(ctx context.Context) (opnapi.FirmwareSettings, error) {
	select {
	case d.entered <- struct{}{}:
	default:
	}
	<-d.release
	return d.pinnedDevice.Settings(ctx)
}

// untriggeredAdvance is the record of an advance that wrote the pin to the target
// and died before it asked for the update: deciding its row means reading the
// device and putting the pin back.
func untriggeredAdvance(t *testing.T, store *taskstore.Store, st *track.StateStore, taskID string) {
	t.Helper()
	now := time.Now()
	job := track.Job{
		Action: "advance", Track: "fast", Approved: trackApproved, Reboot: true, Phase: track.PhaseMoved,
		From: "26.7.3_11", Target: "26.7.5", PrevFlavour: trackPrev, NewFlavour: trackNext,
		StartedAt: now.Unix(), ExpiresAt: now.Add(20 * time.Minute).Unix(),
	}
	if err := store.Begin(taskID, network.TaskTypeFirmwareTrack, taskstore.LifecycleSynchronous); err != nil {
		t.Fatal(err)
	}
	if err := store.SetTaskMeta(taskID, job); err != nil {
		t.Fatal(err)
	}
	if err := st.Save(&track.State{
		Pinned: true, Track: "fast", PinnedFlavour: trackPrev, PinnedVersion: "26.7.3_11",
		Pending: &track.Pending{Op: "advance", TaskID: taskID, FromFlavour: trackPrev, ToFlavour: trackNext, StartedAt: now.Unix()},
	}); err != nil {
		t.Fatal(err)
	}
}

// Deciding a row can write the pin back and check the mirror, which no bound of
// the connect's hook limits: the connect starts the sweep and goes on, or the
// heartbeat loop would wait for the work.
func TestTrackPhase_ASweepThatCannotFinishDoesNotHoldTheConnect(t *testing.T) {
	b := testbroker.New(t)
	store := openStore(t)
	dev := &blockingDevice{pinnedDevice: &pinnedDevice{flavour: trackNext, installed: "26.7.3_11"},
		release: make(chan struct{}), entered: make(chan struct{}, 1)}
	engine, st := newTrackEngine(t, dev)
	untriggeredAdvance(t, store, st, "403")

	startTrackPhase(t, b, store, engine, time.Hour)
	// Registered after the phase's own, so it runs first: a sweep that is let go can end.
	t.Cleanup(func() { close(dev.release) })
	b.WaitForHeartbeats(1, 5*time.Second) // the connect got past the hook with the sweep stuck
	select {
	case <-dev.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the sweep never started, so the test shows nothing")
	}
	if rec, _, _ := store.Get("403"); rec.Status != taskstore.StatusInProgress {
		t.Errorf("the row is %s while the sweep is stuck", rec.Status)
	}
}

func TestTrackPhase_AnUpdateStillRunningKeepsTheRowAndKeepsOtherFirmwareJobsOut(t *testing.T) {
	b := testbroker.New(t)
	store := openStore(t)
	dev := &pinnedDevice{flavour: trackNext, installed: "26.7.3_11"}
	engine, st := newTrackEngine(t, dev)
	triggeredAdvance(t, store, st, "402")
	// The release moved first (OPNsense replaces the core package in the first
	// minute), the box has not rebooted for the base and kernel: the update has not
	// ended, whatever the version file says.
	dev.installed = "26.7.5"

	startTrackPhase(t, b, store, engine, 10*time.Millisecond)
	b.WaitForHeartbeats(1, 5*time.Second)
	time.Sleep(100 * time.Millisecond)

	if rec, _, _ := store.Get("402"); rec.Status != taskstore.StatusInProgress {
		t.Fatalf("the row is %s while the box has not rebooted, want IN_PROGRESS", rec.Status)
	}
	if got := b.TaskResponses(); len(got) != 0 {
		t.Fatalf("task responses = %+v, want none", got)
	}
	if !firmware.Busy() {
		t.Error("a row waiting for the device must keep other firmware jobs out")
	}
	// Another firmware task has to wait for it.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := firmware.Acquire(ctx, nil); err == nil {
		t.Error("a firmware task started under a row that is waiting for the device")
	}
}

// A row with no record of what the task was cannot be answered with a valid
// result; it waits for its time and is failed then, naming no release.
func TestTrackRowReconciler_ARowWithoutARecordIsFailedOnlyWhenItsTimeIsUp(t *testing.T) {
	store := openStore(t)
	dev := &pinnedDevice{installed: "26.7.3_11"}
	engine, _ := newTrackEngine(t, dev)
	if err := store.Begin("501", network.TaskTypeFirmwareTrack, taskstore.LifecycleSynchronous); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var calls []resolveCall
	var datas []map[string]interface{}
	r := newTrackRowReconciler(store, engine, func(string) bool { return false },
		func(id, status, message string, data map[string]interface{}) (bool, error) {
			mu.Lock()
			defer mu.Unlock()
			calls = append(calls, resolveCall{id, status, message})
			datas = append(datas, data)
			return true, nil
		}, func(string, ...interface{}) {})

	r.Sweep(context.Background())
	mu.Lock()
	n := len(calls)
	mu.Unlock()
	if n != 0 {
		t.Fatalf("resolved at once: %+v", calls)
	}

	// An hour on: past what a minor step is given and inside what a series upgrade
	// is. There is no payload to say which this was, so the row waits for the longer
	// one: a lost series-upgrade step must never be failed here while the broker still
	// waits for it.
	r.now = func() time.Time { return time.Now().Add(time.Hour) }
	r.uptime = func() time.Duration { return time.Hour }
	r.Sweep(context.Background())
	mu.Lock()
	n = len(calls)
	mu.Unlock()
	if n != 0 {
		t.Fatalf("a row with no record was failed inside the series upgrade's time: %+v", calls)
	}

	// Time passes: the row was taken up long ago.
	r.now = func() time.Time { return time.Now().Add(track.MajorAdvanceTTL + firmware.Grace + time.Minute) }
	r.Sweep(context.Background())
	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 1 || calls[0].status != taskstore.StatusFailed || datas[0] != nil {
		t.Fatalf("calls %+v data %v", calls, datas)
	}
}

func TestTrackRowReconciler_ALiveHandlerKeepsItsRow(t *testing.T) {
	store := openStore(t)
	dev := &pinnedDevice{flavour: trackNext, installed: "26.7.3_11", failed: true}
	engine, st := newTrackEngine(t, dev)
	triggeredAdvance(t, store, st, "601")
	called := false
	r := newTrackRowReconciler(store, engine, func(string) bool { return true },
		func(string, string, string, map[string]interface{}) (bool, error) { called = true; return true, nil },
		func(string, ...interface{}) {})
	r.Sweep(context.Background())
	if called {
		t.Fatal("a row whose handler is alive was resolved")
	}
}

func TestTrackRowReconciler_NoRowsClearsTheWatch(t *testing.T) {
	store := openStore(t)
	engine, _ := newTrackEngine(t, &pinnedDevice{installed: "26.7.3_11"})
	firmware.WatchTracks(3)
	t.Cleanup(func() { firmware.WatchTracks(0) })
	r := newTrackRowReconciler(store, engine, func(string) bool { return false },
		func(string, string, string, map[string]interface{}) (bool, error) { return true, nil }, func(string, ...interface{}) {})
	r.Sweep(context.Background())
	if firmware.Busy() {
		t.Error("the watch survived a sweep with no rows")
	}
}

// --- the supervisor -----------------------------------------------------------------

func TestTrackSupervisor_RunsTheEngineOnItsTimerAndStops(t *testing.T) {
	dev := &pinnedDevice{flavour: trackPrev, installed: "26.7.3_11"}
	engine, st := newTrackEngine(t, dev)
	if err := st.Save(&track.State{Pinned: true, Track: "fast", PinnedFlavour: trackPrev, PinnedVersion: "26.7.3_11"}); err != nil {
		t.Fatal(err)
	}
	s := &trackSupervisor{engine: engine, contact: &track.Contact{}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.loop(ctx, 5*time.Millisecond, func(string, ...interface{}) {})
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		dev.mu.Lock()
		reads := dev.reads
		dev.mu.Unlock()
		if reads >= 3 {
			break // the engine looked at the pin on more than one round
		}
		if time.Now().After(deadline) {
			t.Fatalf("the engine ran %d rounds", reads)
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the loop did not stop")
	}
}

func TestTrackSupervisor_StartIsOnceAndStopWaits(t *testing.T) {
	dev := &pinnedDevice{installed: "26.7.3_11"}
	engine, _ := newTrackEngine(t, dev)
	s := &trackSupervisor{engine: engine, contact: &track.Contact{}}
	s.stop() // never started: nothing to wait for

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.start(ctx, func(string, ...interface{}) {})
	first := s.cancel
	s.start(ctx, func(string, ...interface{}) {})
	if s.cancel == nil || first == nil {
		t.Fatal("not started")
	}
	s.stop()
	select {
	case <-s.done:
	default:
		t.Fatal("stop returned before the loop ended")
	}
}

func TestNewTrackSupervisor_UsesTheRealDeviceAndTheDefaultRecord(t *testing.T) {
	s := newTrackSupervisor(&config.Config{OPNsenseAPIURL: "https://127.0.0.1/api", APIKey: "k", APISecret: "s"})
	if s.engine == nil || s.contact == nil {
		t.Fatalf("supervisor %+v", s)
	}
}

// --- the wiring ------------------------------------------------------------------------

// Nothing ties the lifecycle to the tracks at compile time, and a missed call is
// silent: without the observer the dead-man never sees a contact (and releases a
// device that is connected), without the reconciler FIRMWARE_TRACK rows stay
// IN_PROGRESS until NDManager gives up on them, and without the early start a
// disabled device never releases its pin.
func TestLifecycleWiresTheFirmwareTracks(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "lifecycle.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	calls := func(fn, callee string) bool {
		found := false
		for _, decl := range file.Decls {
			d, ok := decl.(*ast.FuncDecl)
			if !ok || d.Name.Name != fn {
				continue
			}
			ast.Inspect(d.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch f := call.Fun.(type) {
				case *ast.Ident:
					found = found || f.Name == callee
				case *ast.SelectorExpr:
					found = found || f.Sel.Name == callee
				}
				return true
			})
		}
		return found
	}
	for _, tc := range []struct{ fn, callee, why string }{
		{"Run", "startTracks", "the dead-man must run in the registration phase too"},
		{"runWebSocketPhase", "SetSessionObserver", "the dead-man runs on the contact the broker accepted"},
		{"runWebSocketPhase", "startTrackRowReconciler", "FIRMWARE_TRACK rows would never be resolved"},
		{"NewLifecycleManager", "SetFirmwareTrackEngine", "the handler would hold every task"},
	} {
		if !calls(tc.fn, tc.callee) {
			t.Errorf("%s does not call %s: %s", tc.fn, tc.callee, tc.why)
		}
	}

	decommission, err := parser.ParseFile(fset, "decommission.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	stops := false
	ast.Inspect(decommission, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "stopTracks" {
				stops = true
			}
		}
		return true
	})
	if !stops {
		t.Error("the decommission does not stop the tracks' loop: it would pin the device again behind the sequence that unpins it")
	}
}

// --- the whole path, over a real connection --------------------------------------------

// startTaskPhase is a WebSocket phase with the handlers registered and the
// engine installed, the way runWebSocketPhase leaves it: tasks are dispatched,
// signed, over the connection and answered with signed responses.
func startTaskPhase(t *testing.T, b *testbroker.Broker, engine *track.Engine, testMode bool) *taskstore.Store {
	t.Helper()
	store := openStore(t)
	_, priv, err := signing.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	stateStore, err := state.New(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		ServerURIWS:   b.URL(),
		DeviceUUID:    "3a1e88a3-0000-4000-8000-0000000000aa",
		Token:         "00000000-0000-4000-8000-000000000000",
		DevicePrivKey: base64.StdEncoding.EncodeToString(signing.SeedFromPrivateKey(priv)),
		TestMode:      testMode,
	}
	ws := network.NewWebSocketClient(cfg, stateStore, store, tasks.LifecycleFor, b.NDMKeys())
	tasks.RegisterHandlers(ws)
	tasks.SetFirmwareTrackEngine(engine)
	t.Cleanup(func() { tasks.SetFirmwareTrackEngine(nil) })

	ctx, cancel := context.WithCancel(context.Background())
	startTrackRowReconciler(ctx, ws, store, engine, func(string, ...interface{}) {}, time.Hour)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = ws.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
		firmware.WatchTracks(0)
	})
	b.WaitForHeartbeats(1, 5*time.Second)
	return store
}

func dispatchTrack(t *testing.T, b *testbroker.Broker, taskID int64, seq uint64, payload map[string]interface{}) {
	t.Helper()
	if err := b.Dispatch(testbroker.Dispatch{
		DeviceUUID: "3a1e88a3-0000-4000-8000-0000000000aa", TaskID: taskID, Seq: seq, TaskType: network.TaskTypeFirmwareTrack,
		Payload: payload, Exp: time.Now().Add(20 * time.Minute),
	}); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
}

func waitForResponses(t *testing.T, b *testbroker.Broker, n int) []testbroker.TaskResponse {
	t.Helper()
	b.WaitFor("task responses", 5*time.Second, func() bool {
		count := 0
		for _, r := range b.TaskResponses() {
			if r.Status != "IN_PROGRESS" {
				count++
			}
		}
		return count >= n
	})
	var out []testbroker.TaskResponse
	for _, r := range b.TaskResponses() {
		if r.Status != "IN_PROGRESS" {
			out = append(out, r)
		}
	}
	return out
}

func TestTrackTasks_ACompletedResultAHoldAndAFailureTravelSignedOverTheConnection(t *testing.T) {
	firmware.ResetGuardForTest()
	t.Cleanup(firmware.ResetGuardForTest)
	b := testbroker.New(t)
	dev := &pinnedDevice{installed: "26.7.3_11"}
	engine, _ := newTrackEngine(t, dev)
	startTaskPhase(t, b, engine, true)

	// An unenroll for a device the agent never pinned: COMPLETED, the result JSON.
	dispatchTrack(t, b, 701, 1, map[string]interface{}{"action": "unenroll", "track": "regular"})
	// An advance on a device in test mode: COMPLETED, held, the result JSON.
	dispatchTrack(t, b, 702, 2, map[string]interface{}{"action": "advance", "track": "regular", "approved": map[string]interface{}{"26.7": "26.7.5"}})
	// A payload that is not the contract: FAILED, and it names no release.
	dispatchTrack(t, b, 703, 3, map[string]interface{}{"action": "advance", "track": "regular"})

	got := map[int64]testbroker.TaskResponse{}
	for _, r := range waitForResponses(t, b, 3) {
		got[r.TaskID] = r
	}

	done := got[701]
	if done.Status != "COMPLETED" {
		t.Fatalf("701: %+v", done)
	}
	if f := track.ValidateResult(done.Message, &track.Expect{Action: "unenroll", Track: "regular", Approved: map[string]string{}}); f != nil {
		t.Fatalf("701 answered %s, which the contract refuses: %v", done.Message, f)
	}
	var result map[string]interface{}
	_ = json.Unmarshal([]byte(done.Message), &result)
	if result["outcome"] != "noop" || result["reason"] != "unenrolled" || result["from_version"] != "26.7.3_11" {
		t.Errorf("701 result %v", result)
	}
	if _, ok := done.Inner[track.FailureKey]; ok {
		t.Error("a completed result carries a failure detail")
	}

	held := got[702]
	if held.Status != "COMPLETED" {
		t.Fatalf("702: %+v: a refusal is a hold, never a FAILED the control plane would count against a release", held)
	}
	if f := track.ValidateResult(held.Message, &track.Expect{Action: "advance", Track: "regular", Approved: trackApproved}); f != nil {
		t.Fatalf("702 answered %s, which the contract refuses: %v", held.Message, f)
	}
	var heldResult map[string]interface{}
	_ = json.Unmarshal([]byte(held.Message), &heldResult)
	if heldResult["outcome"] != "held" || heldResult["reason"] != "held_test_mode" || heldResult["target_version"] != "26.7.5" {
		t.Errorf("702 result %v", heldResult)
	}
	if _, ok := held.Inner[track.FailureKey]; ok {
		t.Error("a hold carries a failure detail")
	}

	refused := got[703]
	if refused.Status != "FAILED" {
		t.Fatalf("703: %+v", refused)
	}
	if _, ok := refused.Inner[track.FailureKey]; ok {
		t.Error("a refused payload named a release: that would block it for the organization")
	}
}

// The agent holds nothing the task needs to survive: a row left behind by a
// handler that never answered is resolved by the phase's reconciler (the
// connection test above covers an update; this one an enrollment that died).
func TestTrackTasks_AnEnrollmentThatDiedIsHeldWhenTheAgentComesBack(t *testing.T) {
	firmware.ResetGuardForTest()
	t.Cleanup(firmware.ResetGuardForTest)
	b := testbroker.New(t)
	dev := &pinnedDevice{flavour: trackPrev, installed: "26.7.3_11"}
	engine, st := newTrackEngine(t, dev)
	_ = st.Save(&track.State{Pending: &track.Pending{Op: "enroll", TaskID: "801", ToFlavour: trackPrev, StartedAt: time.Now().Unix()}})

	store := openStore(t)
	if err := store.Begin("801", network.TaskTypeFirmwareTrack, taskstore.LifecycleSynchronous); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	_ = store.SetTaskMeta("801", track.Job{Action: "enroll", Track: "fast", Reboot: true, Phase: track.PhaseMoved, From: "26.7.3_11",
		StartedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix()})

	_, priv, _ := signing.GenerateKeypair()
	stateStore, _ := state.New(filepath.Join(t.TempDir(), "state.json"))
	cfg := &config.Config{ServerURIWS: b.URL(), DeviceUUID: "3a1e88a3-0000-4000-8000-0000000000aa",
		Token: "00000000-0000-4000-8000-000000000000", DevicePrivKey: base64.StdEncoding.EncodeToString(signing.SeedFromPrivateKey(priv))}
	ws := network.NewWebSocketClient(cfg, stateStore, store, tasks.LifecycleFor, b.NDMKeys())
	ctx, cancel := context.WithCancel(context.Background())
	startTrackRowReconciler(ctx, ws, store, engine, func(string, ...interface{}) {}, time.Hour)
	done := make(chan struct{})
	go func() { defer close(done); _ = ws.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done; firmware.WatchTracks(0) })
	b.WaitFor("the enrollment's answer", 5*time.Second, func() bool { return len(b.TaskResponses()) >= 1 })

	got := b.TaskResponses()
	if len(got) != 1 || got[0].TaskID != 801 || got[0].Status != "COMPLETED" {
		t.Fatalf("task responses = %+v", got)
	}
	if f := track.ValidateResult(got[0].Message, &track.Expect{Action: "enroll", Track: "fast", Approved: map[string]string{}}); f != nil {
		t.Fatalf("answered %s: %v", got[0].Message, f)
	}
	if dev.flavour != "" {
		t.Errorf("flavour %q: the enrollment that died left its pin", dev.flavour)
	}
}
