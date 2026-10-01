package network

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/netdefense-io/ndagent/internal/config"
	"github.com/netdefense-io/ndagent/internal/signing"
	"github.com/netdefense-io/ndagent/internal/state"
	"github.com/netdefense-io/ndagent/internal/taskstore"
	"github.com/netdefense-io/ndagent/internal/testbroker"
)

// drainLifecycle is what the real tasks.LifecycleFor says about the types these
// tests use (the tasks package cannot be imported from here).
func drainLifecycle(taskType string) taskstore.Lifecycle {
	switch taskType {
	case TaskTypeFirmwareUpgrade, TaskTypeReboot:
		return taskstore.LifecycleRestartCompletes
	default:
		return taskstore.LifecycleSynchronous
	}
}

// newDrainClient builds a WebSocketClient that connects to b with an in-memory
// task store, and points the drain at an empty pending-results directory.
func newDrainClient(t *testing.T, b *testbroker.Broker) (*WebSocketClient, *taskstore.Store) {
	t.Helper()

	store, err := taskstore.OpenInMemory()
	if err != nil {
		t.Fatalf("OpenInMemory: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	_, priv, err := signing.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	stateStore, err := state.New(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}

	prev := drainPendingResultsDir
	drainPendingResultsDir = t.TempDir()
	t.Cleanup(func() { drainPendingResultsDir = prev })

	cfg := &config.Config{
		ServerURIWS:   b.URL(),
		DeviceUUID:    "3a1e88a3-0000-4000-8000-0000000000aa",
		Token:         "00000000-0000-4000-8000-000000000000",
		DevicePrivKey: base64.StdEncoding.EncodeToString(signing.SeedFromPrivateKey(priv)),
	}
	return NewWebSocketClient(cfg, stateStore, store, drainLifecycle, b.NDMKeys()), store
}

// connectOnce runs one connection in the background until it ends. wait blocks
// until it has.
func connectOnce(t *testing.T, w *WebSocketClient) (cancel func(), wait func()) {
	t.Helper()
	ctx, cancelCtx := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = w.connect(ctx)
	}()
	t.Cleanup(func() {
		cancelCtx()
		<-done
	})
	return cancelCtx, func() { <-done }
}

// statusOf describes where a task stands: its status, and for a terminal row
// whether it has been delivered.
func statusOf(t *testing.T, s *taskstore.Store, id string) string {
	t.Helper()
	rec, found, err := s.Get(id)
	if err != nil || !found {
		t.Fatalf("read row %s: found=%v err=%v", id, found, err)
	}
	switch {
	case rec.Status == taskstore.StatusInProgress:
		return rec.Status
	case rec.Delivered:
		return rec.Status + " (delivered)"
	default:
		return rec.Status + " (undelivered)"
	}
}

// A reconnect while the firmware update is still running. The reconciler's hook
// defers (it does nothing), and the drain that follows in the same connect must
// not close the row and tell the broker the task finished.
func TestConnect_FirmwareRowSurvivesTheDrainWhileTheHookDefers(t *testing.T) {
	b := testbroker.New(t)
	w, store := newDrainClient(t, b)

	_ = store.Begin("101", TaskTypeFirmwareUpgrade, taskstore.LifecycleRestartCompletes)
	_ = store.Begin("102", TaskTypeReboot, taskstore.LifecycleRestartCompletes)

	var hookCalls atomic.Int32
	w.SetPreDrainHook(func(ctx context.Context) { hookCalls.Add(1) })

	connectOnce(t, w)
	b.WaitForHeartbeats(1, 5*time.Second)

	got := b.TaskResponses()
	if len(got) != 1 || got[0].TaskID != 102 || got[0].Status != "COMPLETED" || got[0].Message != "Device returned after restart" {
		t.Fatalf("task responses = %+v, want only 102 COMPLETED \"Device returned after restart\"", got)
	}
	if s := statusOf(t, store, "101"); s != taskstore.StatusInProgress {
		t.Fatalf("firmware row is %q, want IN_PROGRESS", s)
	}
	if hookCalls.Load() != 1 {
		t.Fatalf("hook ran %d times, want 1", hookCalls.Load())
	}
}

// A reconnect runs the whole sequence again: still nothing for the firmware
// row, and nothing is delivered twice.
func TestConnect_ReconnectRunsTheHookAgainAndDoesNotResend(t *testing.T) {
	b := testbroker.New(t)
	w, store := newDrainClient(t, b)

	_ = store.Begin("101", TaskTypeFirmwareUpgrade, taskstore.LifecycleRestartCompletes)
	_ = store.Begin("102", TaskTypeReboot, taskstore.LifecycleRestartCompletes)

	var hookCalls atomic.Int32
	w.SetPreDrainHook(func(ctx context.Context) { hookCalls.Add(1) })

	_, wait := connectOnce(t, w)
	b.WaitForHeartbeats(1, 5*time.Second)
	b.Drop()
	wait()

	connectOnce(t, w)
	b.WaitForHeartbeats(2, 5*time.Second)

	if got := b.TaskResponses(); len(got) != 1 {
		t.Fatalf("task responses after the reconnect = %+v, want the single one from the first connect", got)
	}
	if s := statusOf(t, store, "101"); s != taskstore.StatusInProgress {
		t.Fatalf("firmware row is %q after the reconnect, want IN_PROGRESS", s)
	}
	if hookCalls.Load() != 2 {
		t.Fatalf("hook ran %d times over two connects, want 2", hookCalls.Load())
	}
}

// A task whose handler is running is not the drain's to close, and one whose
// handler is gone still is.
func TestConnect_DrainLeavesLiveRowsAndClosesDeadOnes(t *testing.T) {
	b := testbroker.New(t)
	w, store := newDrainClient(t, b)

	started := make(chan struct{})
	release := make(chan struct{})
	w.dispatcher.RegisterHandler(TaskTypePing, func(ctx context.Context, ws *WebSocketClient, cmd Command) error {
		close(started)
		<-release
		return nil
	})
	go w.dispatcher.dispatchCommand(context.Background(), w, Command{TaskID: "103", TaskType: TaskTypePing})
	<-started
	defer close(release)
	_ = store.Begin("104", TaskTypeSync, taskstore.LifecycleSynchronous)

	connectOnce(t, w)
	b.WaitForHeartbeats(1, 5*time.Second)

	got := b.TaskResponses()
	if len(got) != 1 || got[0].TaskID != 104 || got[0].Status != "FAILED" || got[0].Message != "agent restarted mid-task" {
		t.Fatalf("task responses = %+v, want only 104 FAILED \"agent restarted mid-task\"", got)
	}
	rows, err := store.InProgressByType(TaskTypePing)
	if err != nil || len(rows) != 1 || rows[0].TaskID != "103" {
		t.Fatalf("the live PING row must stay IN_PROGRESS: rows=%+v err=%v", rows, err)
	}
}

// The reconciler's hook resolves a row through the client; the drain that runs
// right after must not send it a second time.
func TestConnect_RowResolvedByTheHookIsSentOnce(t *testing.T) {
	b := testbroker.New(t)
	w, store := newDrainClient(t, b)

	_ = store.Begin("101", TaskTypeFirmwareUpgrade, taskstore.LifecycleRestartCompletes)
	w.SetPreDrainHook(func(ctx context.Context) {
		won, err := w.CompleteInProgressTask("101", TaskStatusCompleted, "reconciled")
		if !won || err != nil {
			t.Errorf("CompleteInProgressTask from the hook: won=%v err=%v", won, err)
		}
	})

	connectOnce(t, w)
	b.WaitForHeartbeats(1, 5*time.Second)

	got := b.TaskResponses()
	if len(got) != 1 || got[0].TaskID != 101 || got[0].Status != "COMPLETED" || got[0].Message != "reconciled" {
		t.Fatalf("task responses = %+v, want exactly one 101 COMPLETED \"reconciled\"", got)
	}
	if s := statusOf(t, store, "101"); s != "COMPLETED (delivered)" {
		t.Fatalf("row is %q, want COMPLETED (delivered)", s)
	}
}

func TestCompleteInProgressTask_ResolvesOnceAndSendsOnce(t *testing.T) {
	b := testbroker.New(t)
	w, store := newDrainClient(t, b)
	_ = store.Begin("101", TaskTypeFirmwareUpgrade, taskstore.LifecycleRestartCompletes)

	connectOnce(t, w)
	b.WaitForHeartbeats(1, 5*time.Second)

	won, err := w.CompleteInProgressTask("101", TaskStatusCompleted, "first")
	if !won || err != nil {
		t.Fatalf("first call: won=%v err=%v", won, err)
	}
	won, err = w.CompleteInProgressTask("101", TaskStatusFailed, "second")
	if won || err != nil {
		t.Fatalf("second call: won=%v err=%v, want false,nil", won, err)
	}

	b.WaitFor("the response", 5*time.Second, func() bool { return len(b.TaskResponses()) >= 1 })
	got := b.TaskResponses()
	if len(got) != 1 || got[0].Status != "COMPLETED" || got[0].Message != "first" {
		t.Fatalf("task responses = %+v, want exactly one 101 COMPLETED \"first\"", got)
	}
}

// The handler that owns a task records its outcome with SendTaskResponse; a
// reconciler that lost the race must neither overwrite it nor send anything.
func TestCompleteInProgressTask_DoesNotOverwriteTheHandlersOutcome(t *testing.T) {
	b := testbroker.New(t)
	w, store := newDrainClient(t, b)
	_ = store.Begin("105", TaskTypeFirmwareUpgrade, taskstore.LifecycleRestartCompletes)

	connectOnce(t, w)
	b.WaitForHeartbeats(1, 5*time.Second)

	if err := w.SendTaskResponse("105", TaskStatusCompleted, "handler outcome", nil); err != nil {
		t.Fatalf("SendTaskResponse: %v", err)
	}
	won, err := w.CompleteInProgressTask("105", TaskStatusFailed, "reconciler outcome")
	if won || err != nil {
		t.Fatalf("CompleteInProgressTask: won=%v err=%v, want false,nil", won, err)
	}

	b.WaitFor("the handler's response", 5*time.Second, func() bool { return len(b.TaskResponses()) >= 1 })
	time.Sleep(50 * time.Millisecond)
	got := b.TaskResponses()
	if len(got) != 1 || got[0].Message != "handler outcome" {
		t.Fatalf("task responses = %+v, want only the handler's", got)
	}
}

// CompleteInProgressTask has written the outcome itself (a compare-and-set), so
// the send it makes must not write the row again: whatever another writer put
// there in between would be replaced. The positive control shows the test can see
// a write.
func TestSendTaskResponse_WithoutRecordLeavesTheRowAlone(t *testing.T) {
	b := testbroker.New(t)
	w, store := newDrainClient(t, b)
	_ = store.Begin("108", TaskTypeFirmwareUpgrade, taskstore.LifecycleRestartCompletes)
	if err := store.Complete("108", taskstore.StatusFailed, "another writer's outcome", nil); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	// Not connected: the frame is not sent (errNotAuthenticated), which is after the
	// point where a record would have been written.
	if err := w.sendTaskResponse("108", TaskStatusCompleted, "the reconciler's", nil, false); !errors.Is(err, errNotAuthenticated) {
		t.Fatalf("sendTaskResponse: %v, want errNotAuthenticated", err)
	}
	if rec, _, _ := store.Get("108"); rec.Status != taskstore.StatusFailed || rec.Message != "another writer's outcome" {
		t.Fatalf("row = %s %q after a send that must not record, want the other writer's outcome untouched", rec.Status, rec.Message)
	}

	if err := w.sendTaskResponse("108", TaskStatusCompleted, "the handler's", nil, true); !errors.Is(err, errNotAuthenticated) {
		t.Fatalf("sendTaskResponse: %v, want errNotAuthenticated", err)
	}
	if rec, _, _ := store.Get("108"); rec.Status != taskstore.StatusCompleted || rec.Message != "the handler's" {
		t.Fatalf("row = %s %q after a send that records, want the handler's outcome", rec.Status, rec.Message)
	}
}

// With the socket down the outcome is still recorded, the caller is told it
// was not delivered, and the next connect replays it exactly once.
func TestCompleteInProgressTask_SocketDownIsReplayedOnTheNextConnect(t *testing.T) {
	b := testbroker.New(t)
	w, store := newDrainClient(t, b)
	_ = store.Begin("101", TaskTypeFirmwareUpgrade, taskstore.LifecycleRestartCompletes)

	won, err := w.CompleteInProgressTask("101", TaskStatusCompleted, "while offline")
	if !won || err == nil {
		t.Fatalf("offline call: won=%v err=%v, want true and a delivery error", won, err)
	}
	if s := statusOf(t, store, "101"); s != "COMPLETED (undelivered)" {
		t.Fatalf("row is %q, want COMPLETED (undelivered)", s)
	}

	_, wait := connectOnce(t, w)
	b.WaitForHeartbeats(1, 5*time.Second)
	b.Drop()
	wait()
	connectOnce(t, w)
	b.WaitForHeartbeats(2, 5*time.Second)

	got := b.TaskResponses()
	if len(got) != 1 || got[0].TaskID != 101 || got[0].Message != "while offline" {
		t.Fatalf("task responses over two connects = %+v, want the one replay", got)
	}
}

// The drain replays whatever is terminal and undelivered; CompleteInProgressTask
// makes a row terminal and sends it. Run together, each row must still be sent
// exactly once.
func TestCompleteInProgressTask_ConcurrentWithTheDrainSendsEachRowOnce(t *testing.T) {
	b := testbroker.New(t)
	w, store := newDrainClient(t, b)

	const rows = 40
	for i := 0; i < rows; i++ {
		_ = store.Begin(fmt.Sprintf("%d", 200+i), TaskTypeFirmwareUpgrade, taskstore.LifecycleRestartCompletes)
	}

	connectOnce(t, w)
	b.WaitForHeartbeats(1, 5*time.Second)

	var wg sync.WaitGroup
	for i := 0; i < rows; i++ {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			_, _ = w.CompleteInProgressTask(id, TaskStatusCompleted, "done")
		}(fmt.Sprintf("%d", 200+i))
	}
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w.reconcileAndDrain(context.Background())
		}()
	}
	wg.Wait()

	b.WaitFor("every row to be delivered", 10*time.Second, func() bool { return len(b.TaskResponses()) >= rows })
	time.Sleep(100 * time.Millisecond)
	seen := map[int64]int{}
	for _, r := range b.TaskResponses() {
		seen[r.TaskID]++
	}
	if len(seen) != rows {
		t.Fatalf("%d distinct tasks answered, want %d", len(seen), rows)
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("task %d answered %d times, want once", id, n)
		}
	}
}

// The broker reads the first frame of a connection as the authentication
// message, so a task response written before that exchange is finished is lost
// and, on the real broker, refused. The response is recorded and left for the
// drain that follows authentication.
func TestSendTaskResponse_IsRecordedButNotWrittenBeforeAuthentication(t *testing.T) {
	b := testbroker.New(t)
	w, store := newDrainClient(t, b)
	_ = store.Begin("101", TaskTypeFirmwareUpgrade, taskstore.LifecycleRestartCompletes)

	conn, _, err := websocket.DefaultDialer.Dial(b.URL(), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	w.mu.Lock()
	w.conn = conn // dialled, not authenticated
	w.mu.Unlock()

	if err := w.SendTaskResponse("101", TaskStatusCompleted, "too early", nil); !errors.Is(err, errNotAuthenticated) {
		t.Fatalf("SendTaskResponse before authentication returned %v, want errNotAuthenticated", err)
	}
	if s := statusOf(t, store, "101"); s != "COMPLETED (undelivered)" {
		t.Fatalf("row is %q, want COMPLETED (undelivered): the outcome must be recorded for the drain", s)
	}

	// Authenticate for real, then the same call writes the frame.
	if err := conn.WriteJSON(map[string]string{"type": "authentication"}); err != nil {
		t.Fatalf("write auth: %v", err)
	}
	if _, _, err := conn.ReadMessage(); err != nil {
		t.Fatalf("read auth reply: %v", err)
	}
	w.mu.Lock()
	w.authenticated = true
	w.mu.Unlock()

	if err := w.SendTaskResponse("101", TaskStatusCompleted, "on time", nil); err != nil {
		t.Fatalf("SendTaskResponse after authentication: %v", err)
	}
	b.WaitFor("the response", 5*time.Second, func() bool { return len(b.TaskResponses()) >= 1 })
	if got := b.TaskResponses(); len(got) != 1 || got[0].Message != "on time" {
		t.Fatalf("task responses = %+v, want the single one sent after authentication", got)
	}
}

// The dispatch envelope's signed expiry is NDManager's deadline for the task, and
// a handler whose work outlives it needs to know what it is.
func TestReceiveCommands_CarriesTheSignedExpiryToTheHandler(t *testing.T) {
	b := testbroker.New(t)
	w, _ := newDrainClient(t, b)

	got := make(chan Command, 1)
	w.dispatcher.RegisterHandler(TaskTypePing, func(ctx context.Context, ws *WebSocketClient, cmd Command) error {
		got <- cmd
		return nil
	})

	connectOnce(t, w)
	b.WaitForHeartbeats(1, 5*time.Second)

	exp := time.Now().Add(15 * time.Minute).Truncate(time.Second)
	if err := b.Dispatch(testbroker.Dispatch{
		DeviceUUID: w.cfg.DeviceUUID, TaskID: 77, Seq: 1, TaskType: TaskTypePing,
		Payload: map[string]interface{}{"host": "127.0.0.1"}, Exp: exp,
	}); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}

	select {
	case cmd := <-got:
		if cmd.TaskID != "77" || cmd.TaskType != TaskTypePing {
			t.Fatalf("command = %+v", cmd)
		}
		if cmd.ExpiresAt != exp.Unix() {
			t.Fatalf("ExpiresAt = %d, want the signed exp %d", cmd.ExpiresAt, exp.Unix())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the dispatched command never reached its handler")
	}
}
