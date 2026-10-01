package core

import (
	"context"
	"encoding/base64"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/config"
	"github.com/netdefense-io/ndagent/internal/firmware"
	"github.com/netdefense-io/ndagent/internal/network"
	"github.com/netdefense-io/ndagent/internal/signing"
	"github.com/netdefense-io/ndagent/internal/state"
	"github.com/netdefense-io/ndagent/internal/tasks"
	"github.com/netdefense-io/ndagent/internal/taskstore"
	"github.com/netdefense-io/ndagent/internal/testbroker"
)

// startPhase is a WebSocket phase as runWebSocketPhase runs it for the
// reconciler: a real WebSocket client, a real task store, and the reconciler
// wired by the same function, startFirmwareReconciler, as the pre-drain hook and
// as the per-phase ticker. Only the OPNsense device is fake.
func startPhase(t *testing.T, b *testbroker.Broker, store *taskstore.Store, dev *fakeDevice) *network.WebSocketClient {
	t.Helper()
	return startPhaseEvery(t, b, store, dev, 10*time.Millisecond)
}

// startPhaseEvery is startPhase with the interval of the ticker chosen; an hour
// leaves only the connect hook to decide anything.
func startPhaseEvery(t *testing.T, b *testbroker.Broker, store *taskstore.Store, dev *fakeDevice, interval time.Duration) *network.WebSocketClient {
	t.Helper()

	_, priv, err := signing.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	stateStore, err := state.New(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	cfg := &config.Config{
		ServerURIWS:   b.URL(),
		DeviceUUID:    "3a1e88a3-0000-4000-8000-0000000000aa",
		Token:         "00000000-0000-4000-8000-000000000000",
		DevicePrivKey: base64.StdEncoding.EncodeToString(signing.SeedFromPrivateKey(priv)),
	}
	ws := network.NewWebSocketClient(cfg, stateStore, store, tasks.LifecycleFor, b.NDMKeys())

	ctx, cancel := context.WithCancel(context.Background())
	startFirmwareReconciler(ctx, ws, store, dev.probes(), func(string, ...interface{}) {}, interval)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = ws.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return ws
}

func openStore(t *testing.T) *taskstore.Store {
	t.Helper()
	store, err := taskstore.OpenInMemory()
	if err != nil {
		t.Fatalf("OpenInMemory: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// The whole path, over a real connection: an update that is still running when
// the agent connects must produce no answer, and the answer that follows the
// device becoming ready must be sent once.
func TestPhase_AnAnswerIsSentOnlyOnceTheUpdateHasEnded(t *testing.T) {
	b := testbroker.New(t)
	store := openStore(t)
	dev := &fakeDevice{state: firmware.RunBusy, release: "26.7.4_1"}

	_ = store.Begin("101", "FIRMWARE_UPGRADE", taskstore.LifecycleRestartCompletes)
	_ = store.Begin("102", "REBOOT", taskstore.LifecycleRestartCompletes)

	startPhase(t, b, store, dev)
	b.WaitForHeartbeats(1, 5*time.Second)

	// The REBOOT row is the drain's, as before; the firmware row is not.
	got := b.TaskResponses()
	if len(got) != 1 || got[0].TaskID != 102 {
		t.Fatalf("task responses while OPNsense was busy = %+v, want only 102", got)
	}
	time.Sleep(150 * time.Millisecond) // many sweeps
	if got := b.TaskResponses(); len(got) != 1 {
		t.Fatalf("task responses after several sweeps while busy = %+v, want still only 102", got)
	}
	if rec, _, _ := store.Get("101"); rec.Status != taskstore.StatusInProgress {
		t.Fatalf("firmware row is %s while OPNsense was busy, want IN_PROGRESS", rec.Status)
	}

	dev.set(func(d *fakeDevice) { d.state = firmware.RunReady })
	b.WaitFor("the firmware answer", 5*time.Second, func() bool { return len(b.TaskResponses()) >= 2 })
	time.Sleep(100 * time.Millisecond) // and no second one

	got = b.TaskResponses()
	if len(got) != 2 {
		t.Fatalf("task responses = %+v, want 102 and one for 101", got)
	}
	if r := got[1]; r.TaskID != 101 || r.Status != "COMPLETED" ||
		r.Message != "Firmware upgrade completed; device returned with product_version 26.7.4_1" {
		t.Fatalf("answer for the firmware task = %+v", r)
	}
	if rec, _, _ := store.Get("101"); rec.Status != taskstore.StatusCompleted || !rec.Delivered {
		t.Fatalf("firmware row is %s (delivered=%v), want COMPLETED and delivered", rec.Status, rec.Delivered)
	}
}

// When the device is already idle at connect, the hook resolves the row and the
// drain that follows must not send it again. The ticker is set an hour out, so
// only the hook can have decided.
func TestPhase_ARowResolvedAtConnectIsNotSentTwice(t *testing.T) {
	b := testbroker.New(t)
	store := openStore(t)
	dev := &fakeDevice{state: firmware.RunReady, release: "26.7.4_1"}
	_ = store.Begin("101", "FIRMWARE_UPGRADE", taskstore.LifecycleRestartCompletes)

	startPhaseEvery(t, b, store, dev, time.Hour)
	b.WaitForHeartbeats(1, 5*time.Second)
	time.Sleep(100 * time.Millisecond)

	got := b.TaskResponses()
	if len(got) != 1 || got[0].TaskID != 101 || got[0].Status != "COMPLETED" {
		t.Fatalf("task responses = %+v, want exactly one COMPLETED for 101", got)
	}
}

// A task that never got as far as triggering anything is answered on connect,
// whatever the box is doing, and the row of the run that did start is left to the
// device: the mixed pair after the agent was stopped by its own upgrade.
func TestPhase_ARowThatNeverTriggeredIsFailedOnConnectAndTheRunningOneWaits(t *testing.T) {
	b := testbroker.New(t)
	store := openStore(t)
	dev := &fakeDevice{state: firmware.RunReady, release: "26.7.4_1", boot: 1_780_000_000, updating: true,
		installed: map[string]string{"opnsense": "26.7.4_1"}}

	now := time.Now().Unix()
	_ = store.Begin("101", "FIRMWARE_UPGRADE", taskstore.LifecycleRestartCompletes)
	_ = store.SetTaskMeta("101", firmware.Meta{ // the reboot=false run: pkg is still installing
		Mode: "minor", Reboot: false, FromVersion: "26.7.3_8", BootTime: 1_780_000_000,
		StartedAt: now, TriggeredAt: now, ExpiresAt: now + 900,
		Packages: []firmware.Package{{Name: "opnsense", Version: "26.7.4_1"}, {Name: "os-netdefense", Version: "1.19.5"}},
	})
	_ = store.Begin("102", "FIRMWARE_UPGRADE", taskstore.LifecycleRestartCompletes)
	_ = store.SetTaskMeta("102", firmware.Meta{ // the weekly task that was still waiting for its turn
		Mode: "minor", Reboot: true, StartedAt: now, ExpiresAt: now + 900,
	})

	startPhase(t, b, store, dev)
	b.WaitForHeartbeats(1, 5*time.Second)
	b.WaitFor("the answer for the task that never started", 5*time.Second, func() bool { return len(b.TaskResponses()) >= 1 })
	time.Sleep(100 * time.Millisecond) // and nothing for the other one

	got := b.TaskResponses()
	if len(got) != 1 || got[0].TaskID != 102 || got[0].Status != "FAILED" ||
		!strings.Contains(got[0].Message, "was not started") {
		t.Fatalf("task responses = %+v, want one FAILED \"was not started\" for 102 and nothing for 101", got)
	}
	if rec, _, _ := store.Get("101"); rec.Status != taskstore.StatusInProgress {
		t.Fatalf("the run that is still installing is %s, want IN_PROGRESS", rec.Status)
	}
}

// Without API credentials the reconciler is given no API at all: the interface
// must not hold a nil client, whose methods would dereference it.
func TestFirmwareProbes_WithoutAnAPIClientReadsNothingFromTheBackend(t *testing.T) {
	probes := firmwareProbes(nil)
	state, err := probes.Running(context.Background())
	if err == nil || state != firmware.RunUnknown {
		t.Fatalf("Running = %v, %v; want an unreadable backend, not a panic and not ready", state, err)
	}
	if _, err := probes.Release(context.Background()); err != nil {
		t.Logf("Release without a client answered %v (local sources only)", err) // fine: the host has no OPNsense
	}
}

// runWebSocketPhase has to start the reconciler for its phase: nothing else
// ties the two together at compile time, and without it FIRMWARE_UPGRADE rows
// stay IN_PROGRESS until NDManager gives up on them. The tests above pin what
// startFirmwareReconciler does; this pins that the phase calls it, with the
// phase's context and the probes built for its API client.
func TestRunWebSocketPhaseStartsTheFirmwareReconciler(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "lifecycle.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing lifecycle.go: %v", err)
	}
	var phase *ast.FuncDecl
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "runWebSocketPhase" {
			phase = fn
		}
	}
	if phase == nil {
		t.Fatal("runWebSocketPhase not found in lifecycle.go")
	}

	var started *ast.CallExpr
	probesFrom := ""
	ast.Inspect(phase.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "startFirmwareReconciler" {
			started = call
		}
		return true
	})
	if started == nil {
		t.Fatal("runWebSocketPhase does not call startFirmwareReconciler: FIRMWARE_UPGRADE rows would never be resolved")
	}
	if len(started.Args) < 4 {
		t.Fatalf("startFirmwareReconciler called with %d arguments", len(started.Args))
	}
	if id, ok := started.Args[0].(*ast.Ident); !ok || id.Name != "phaseCtx" {
		t.Errorf("the reconciler must run under the phase's context (phaseCtx), got %s", exprString(started.Args[0]))
	}
	if call, ok := started.Args[3].(*ast.CallExpr); ok {
		if id, ok := call.Fun.(*ast.Ident); ok {
			probesFrom = id.Name
		}
	}
	if probesFrom != "firmwareProbes" {
		t.Errorf("the probes must come from firmwareProbes (which keeps a nil client out of the interface), got %s",
			exprString(started.Args[3]))
	}
}

func exprString(e ast.Expr) string {
	var b strings.Builder
	if err := printer.Fprint(&b, token.NewFileSet(), e); err != nil {
		return "?"
	}
	return b.String()
}

// A row whose handler is alive in this process belongs to it, whatever the device
// says: the phase's reconciler is given the dispatcher's own answer to "is this
// task live". The moment the handler is gone, the row is the reconciler's.
func TestPhase_ARowWhoseHandlerIsAliveIsLeftAloneUntilItIsGone(t *testing.T) {
	b := testbroker.New(t)
	store := openStore(t)
	dev := &fakeDevice{state: firmware.RunReady, release: "26.7.4_1"} // an answer is available for any row

	ws := startPhase(t, b, store, dev)
	started, release := make(chan struct{}), make(chan struct{})
	ws.GetDispatcher().RegisterHandler("FIRMWARE_UPGRADE", func(ctx context.Context, _ *network.WebSocketClient, _ network.Command) error {
		close(started)
		<-release
		return nil // ends without a terminal response: the row stays IN_PROGRESS
	})
	b.WaitForHeartbeats(1, 5*time.Second)
	if err := b.Dispatch(testbroker.Dispatch{
		DeviceUUID: "3a1e88a3-0000-4000-8000-0000000000aa", TaskID: 300, Seq: 1, TaskType: "FIRMWARE_UPGRADE",
		Payload: map[string]interface{}{"mode": "minor"}, Exp: time.Now().Add(15 * time.Minute),
	}); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	<-started

	time.Sleep(150 * time.Millisecond) // many sweeps
	if rec, _, _ := store.Get("300"); rec.Status != taskstore.StatusInProgress {
		t.Fatalf("the row of a running handler is %s, want IN_PROGRESS", rec.Status)
	}
	if got := b.TaskResponses(); len(got) != 0 {
		t.Fatalf("task responses = %+v while the handler was alive, want none", got)
	}

	close(release)
	b.WaitFor("the answer once the handler is gone", 5*time.Second, func() bool { return len(b.TaskResponses()) == 1 })
	if got := b.TaskResponses(); got[0].TaskID != 300 || got[0].Status != "COMPLETED" {
		t.Fatalf("task responses = %+v, want 300 COMPLETED", got)
	}
}
