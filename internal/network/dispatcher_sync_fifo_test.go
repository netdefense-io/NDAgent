package network

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/taskstore"
)

// newFIFOTestDispatcher builds a bare CommandDispatcher with a real
// syncQueue and handler map but no state store, task store or WebSocket —
// dispatchCommand never touches `ws` as long as the registered handler
// itself doesn't and returns a nil error, which is exactly the shape of
// the fake handlers below. This exercises the FIFO (ensureSyncWorker,
// trySyncEnqueue, dispatchCommand) in true isolation from envelope
// verification and the network.
func newFIFOTestDispatcher() *CommandDispatcher {
	return &CommandDispatcher{
		handlers:  make(map[string]TaskHandler),
		syncQueue: make(chan Command, syncQueueCapacity),
	}
}

// TestSyncFIFO_SecondStartsOnlyAfterFirstReturns is the FIFO's core
// contract: two SYNCs enqueued back to back,
// and the second's handler must not even START running until the first's
// handler has fully RETURNED — not merely "queued in order", but
// serialized execution.
func TestSyncFIFO_SecondStartsOnlyAfterFirstReturns(t *testing.T) {
	d := newFIFOTestDispatcher()

	var mu sync.Mutex
	var events []string
	firstStarted := make(chan struct{})
	release := make(chan struct{})

	d.RegisterHandler(TaskTypeSync, func(ctx context.Context, ws *WebSocketClient, cmd Command) error {
		mu.Lock()
		events = append(events, "start:"+cmd.TaskID)
		mu.Unlock()

		if cmd.TaskID == "1" {
			close(firstStarted)
			<-release // held open until the test says go
		}

		mu.Lock()
		events = append(events, "end:"+cmd.TaskID)
		mu.Unlock()
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	d.ensureSyncWorker(ctx, nil)

	if !d.trySyncEnqueue(Command{TaskID: "1", TaskType: TaskTypeSync}) {
		t.Fatal("enqueue of task 1 failed unexpectedly")
	}
	<-firstStarted

	if !d.trySyncEnqueue(Command{TaskID: "2", TaskType: TaskTypeSync}) {
		t.Fatal("enqueue of task 2 failed unexpectedly")
	}

	// Task 1 is still blocked on <-release. Task 2 must NOT have started —
	// this is the assertion that actually distinguishes a FIFO from a mere
	// "arrives in order" queue whose consumer still fans out into
	// goroutines.
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	snapshot := append([]string(nil), events...)
	mu.Unlock()
	if fmt.Sprint(snapshot) != fmt.Sprint([]string{"start:1"}) {
		t.Fatalf("events while task 1 is still running = %v, want exactly [start:1] (task 2 must wait for task 1 to return)", snapshot)
	}

	close(release)

	deadline := time.After(2 * time.Second)
	for {
		mu.Lock()
		n := len(events)
		snap := append([]string(nil), events...)
		mu.Unlock()
		if n == 4 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for task 2 to run; events = %v", snap)
		case <-time.After(5 * time.Millisecond):
		}
	}

	mu.Lock()
	final := append([]string(nil), events...)
	mu.Unlock()
	want := []string{"start:1", "end:1", "start:2", "end:2"}
	if fmt.Sprint(final) != fmt.Sprint(want) {
		t.Errorf("events = %v, want %v", final, want)
	}
}

// TestSyncFIFO_NonSyncTasksStillRunConcurrently guards against an
// over-broad fix: only SYNC goes through the FIFO. A non-SYNC task
// (dispatched the old way, via dispatchCommand's own goroutine) must not
// be blocked behind a slow SYNC sitting in the queue.
func TestSyncFIFO_NonSyncTasksStillRunConcurrently(t *testing.T) {
	d := newFIFOTestDispatcher()

	slowStarted := make(chan struct{})
	release := make(chan struct{})
	otherRan := make(chan struct{})

	d.RegisterHandler(TaskTypeSync, func(ctx context.Context, ws *WebSocketClient, cmd Command) error {
		close(slowStarted)
		<-release
		return nil
	})
	d.RegisterHandler(TaskTypePing, func(ctx context.Context, ws *WebSocketClient, cmd Command) error {
		close(otherRan)
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.ensureSyncWorker(ctx, nil)

	if !d.trySyncEnqueue(Command{TaskID: "1", TaskType: TaskTypeSync}) {
		t.Fatal("enqueue failed")
	}
	<-slowStarted

	// A PING dispatched the ordinary way (its own goroutine, as
	// dispatchCommand does for every non-SYNC type) must complete even
	// while the SYNC worker is still blocked.
	go d.dispatchCommand(ctx, nil, Command{TaskID: "2", TaskType: TaskTypePing})

	select {
	case <-otherRan:
	case <-time.After(2 * time.Second):
		t.Fatal("a non-SYNC task was blocked behind the in-flight SYNC")
	}

	close(release)
}

// TestTrySyncEnqueue_FullQueueReturnsFalse is the queue-full contract
// (SYNC_QUEUE_FULL): trySyncEnqueue must return false, without blocking,
// once syncQueueCapacity commands are already buffered and nothing is
// draining them.
func TestTrySyncEnqueue_FullQueueReturnsFalse(t *testing.T) {
	d := newFIFOTestDispatcher() // no worker started -- nothing drains the queue

	for i := 0; i < syncQueueCapacity; i++ {
		if !d.trySyncEnqueue(Command{TaskID: fmt.Sprintf("%d", i), TaskType: TaskTypeSync}) {
			t.Fatalf("enqueue %d unexpectedly failed before reaching capacity", i)
		}
	}

	if d.trySyncEnqueue(Command{TaskID: "overflow", TaskType: TaskTypeSync}) {
		t.Fatal("trySyncEnqueue succeeded past capacity, want false")
	}
}

// TestSyncFIFO_WorkerRestartsAfterConnectionContextCancelled is the
// reconnect regression test: the CommandDispatcher is NOT recreated on a
// WebSocket reconnect (see the syncWorkerCtx doc comment on
// CommandDispatcher) — only its per-connection loopCtx changes. A SYNC
// enqueued under a second, later ctx must still run once the first ctx has
// been cancelled; before the syncWorkerCtx fix, a plain sync.Once meant the
// worker never restarted and every later SYNC piled up in the queue
// forever.
func TestSyncFIFO_WorkerRestartsAfterConnectionContextCancelled(t *testing.T) {
	d := newFIFOTestDispatcher()

	var mu sync.Mutex
	var ran []string
	d.RegisterHandler(TaskTypeSync, func(ctx context.Context, ws *WebSocketClient, cmd Command) error {
		mu.Lock()
		ran = append(ran, cmd.TaskID)
		mu.Unlock()
		return nil
	})

	// Connection #1: worker starts under ctx1, runs SYNC "1", then the
	// connection ends (ctx1 is cancelled) — exactly what happens on an
	// ordinary WebSocket reconnect.
	ctx1, cancel1 := context.WithCancel(context.Background())
	d.ensureSyncWorker(ctx1, nil)
	if !d.trySyncEnqueue(Command{TaskID: "1", TaskType: TaskTypeSync}) {
		t.Fatal("enqueue of task 1 failed unexpectedly")
	}

	deadline := time.After(2 * time.Second)
	for {
		mu.Lock()
		n := len(ran)
		mu.Unlock()
		if n == 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for task 1 to run")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel1()
	// Give the ctx1 worker goroutine a moment to actually observe
	// ctx.Done() and return before starting the second connection — this
	// is not required for correctness (ensureSyncWorker only inspects
	// ctx.Err(), never whether the goroutine has physically exited) but
	// keeps the test's timeline unambiguous.
	time.Sleep(20 * time.Millisecond)

	// Connection #2: a fresh loopCtx, exactly as runCommunicationLoop
	// builds on every reconnect. ensureSyncWorker must start a NEW worker
	// here — ctx1 is done, so the old sync.Once-based implementation would
	// leave nothing draining the queue at all.
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	d.ensureSyncWorker(ctx2, nil)
	if !d.trySyncEnqueue(Command{TaskID: "2", TaskType: TaskTypeSync}) {
		t.Fatal("enqueue of task 2 failed unexpectedly")
	}

	deadline = time.After(2 * time.Second)
	for {
		mu.Lock()
		snap := append([]string(nil), ran...)
		mu.Unlock()
		if fmt.Sprint(snap) == fmt.Sprint([]string{"1", "2"}) {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("task 2 never ran after the connection's context was replaced; ran = %v", snap)
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// TestSyncFIFO_EnqueueRecordsTaskStateBeforeWorkerDequeues is the
// crash-recovery regression: a SYNC sitting in the queue behind another
// still-running SYNC must already have an IN_PROGRESS task_states row —
// not just once the worker eventually dequeues and dispatchCommand's own
// Begin call runs. Before this fix, a crash while a SYNC was still queued
// left the boot-time drain with no row at all for that task_id, so it
// could never send a terminal response for a task_id the broker was still
// waiting on.
func TestSyncFIFO_EnqueueRecordsTaskStateBeforeWorkerDequeues(t *testing.T) {
	store, err := taskstore.OpenInMemory()
	if err != nil {
		t.Fatalf("OpenInMemory: %v", err)
	}
	defer func() { _ = store.Close() }()

	d := &CommandDispatcher{
		handlers:     make(map[string]TaskHandler),
		syncQueue:    make(chan Command, syncQueueCapacity),
		taskStore:    store,
		lifecycleFor: func(string) taskstore.Lifecycle { return taskstore.LifecycleSynchronous },
	}

	release := make(chan struct{})
	d.RegisterHandler(TaskTypeSync, func(ctx context.Context, ws *WebSocketClient, cmd Command) error {
		if cmd.TaskID == "1" {
			<-release // hold task 1 open so task 2 stays queued, never dequeued
		}
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.ensureSyncWorker(ctx, nil)

	// beginTaskState is what ReceiveCommands calls before trySyncEnqueue —
	// exercised directly here since this test builds the dispatcher
	// without going through ReceiveCommands' envelope-verification path.
	d.beginTaskState(Command{TaskID: "1", TaskType: TaskTypeSync})
	if !d.trySyncEnqueue(Command{TaskID: "1", TaskType: TaskTypeSync}) {
		t.Fatal("enqueue of task 1 failed unexpectedly")
	}

	deadline := time.After(2 * time.Second)
	for {
		rows, err := store.InProgressByType(TaskTypeSync)
		if err != nil {
			t.Fatalf("InProgressByType: %v", err)
		}
		found := false
		for _, r := range rows {
			if r.TaskID == "1" {
				found = true
			}
		}
		if found {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for task 1's IN_PROGRESS row")
		case <-time.After(5 * time.Millisecond):
		}
	}

	// Task 2 is enqueued behind task 1 (still blocked on <-release) and
	// must ALREADY have an IN_PROGRESS row despite never having reached
	// the worker/dispatchCommand at all yet.
	d.beginTaskState(Command{TaskID: "2", TaskType: TaskTypeSync})
	if !d.trySyncEnqueue(Command{TaskID: "2", TaskType: TaskTypeSync}) {
		t.Fatal("enqueue of task 2 failed unexpectedly")
	}

	rows, err := store.InProgressByType(TaskTypeSync)
	if err != nil {
		t.Fatalf("InProgressByType: %v", err)
	}
	found := false
	for _, r := range rows {
		if r.TaskID == "2" {
			found = true
		}
	}
	if !found {
		t.Fatalf("task 2's IN_PROGRESS row is missing while it is still only queued (never dequeued); rows = %+v", rows)
	}

	close(release)
}

// TestEnsureSyncWorker_StartsOnlyOnce guards the single-live-worker
// invariant for one connection: calling
// ensureSyncWorker multiple times (as ReceiveCommands does, once per SYNC
// command received) must never start a second draining goroutine — two
// workers racing to dequeue would themselves reintroduce out-of-order
// execution.
func TestEnsureSyncWorker_StartsOnlyOnce(t *testing.T) {
	d := newFIFOTestDispatcher()

	var mu sync.Mutex
	var runningCount, maxConcurrent int

	d.RegisterHandler(TaskTypeSync, func(ctx context.Context, ws *WebSocketClient, cmd Command) error {
		mu.Lock()
		runningCount++
		if runningCount > maxConcurrent {
			maxConcurrent = runningCount
		}
		mu.Unlock()

		time.Sleep(20 * time.Millisecond)

		mu.Lock()
		runningCount--
		mu.Unlock()
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Call ensureSyncWorker many times, as the production call site does
	// on every SYNC command, before enqueueing a batch of SYNCs.
	for i := 0; i < 5; i++ {
		d.ensureSyncWorker(ctx, nil)
	}
	for i := 0; i < 10; i++ {
		if !d.trySyncEnqueue(Command{TaskID: fmt.Sprintf("%d", i), TaskType: TaskTypeSync}) {
			t.Fatalf("enqueue %d failed", i)
		}
	}

	// Give every task time to run through a single worker.
	time.Sleep(500 * time.Millisecond)

	mu.Lock()
	got := maxConcurrent
	mu.Unlock()
	if got != 1 {
		t.Errorf("max concurrent SYNC handlers = %d, want 1 (exactly one worker must ever be running)", got)
	}
}

// TestSyncFIFO_WorkerNeverDispatchesUnderAnAlreadyCancelledContext is the
// minor-finding regression for the race ensureSyncWorker's own doc
// comment describes: before the fix, the worker's loop selected over
// `<-workerCtx.Done()` and `<-d.syncQueue` in one two-case select. When a
// connection ends and a SYNC is (re-)enqueued right after — the exact
// shape of an ordinary reconnect racing a still-queued command — BOTH
// cases can be simultaneously ready on the very same loop iteration, and
// a bare select picks between ready cases pseudo-randomly, so the worker
// could still dequeue and dispatch under a context that is already dead,
// at the same moment ensureSyncWorker (reading that same Err() != nil)
// decides a replacement worker is needed — two workers draining
// d.syncQueue at once, which breaks the FIFO's whole ordering guarantee.
// The fix gives Done() priority via its own non-blocking pre-check. This
// races the same window on every one of many iterations rather than
// relying on hitting it once, since Go's select tie-break is
// intentionally unspecified and a single iteration could pass by chance
// even against the pre-fix code.
func TestSyncFIFO_WorkerNeverDispatchesUnderAnAlreadyCancelledContext(t *testing.T) {
	const iterations = 200

	for i := 0; i < iterations; i++ {
		d := newFIFOTestDispatcher()

		var dispatchedCancelled int32
		d.RegisterHandler(TaskTypeSync, func(ctx context.Context, ws *WebSocketClient, cmd Command) error {
			if ctx.Err() != nil {
				atomic.AddInt32(&dispatchedCancelled, 1)
			}
			return nil
		})

		ctx1, cancel1 := context.WithCancel(context.Background())
		d.ensureSyncWorker(ctx1, nil)

		// Cancel first, then enqueue immediately after — by the time the
		// worker's goroutine (started moments ago and possibly not even
		// scheduled yet) reaches its select, both workerCtx.Done() and
		// d.syncQueue are already ready together on the very first
		// iteration it runs.
		cancel1()
		if !d.trySyncEnqueue(Command{TaskID: fmt.Sprintf("%d", i), TaskType: TaskTypeSync}) {
			t.Fatalf("iteration %d: enqueue failed unexpectedly", i)
		}

		time.Sleep(2 * time.Millisecond)

		if atomic.LoadInt32(&dispatchedCancelled) != 0 {
			t.Fatalf("iteration %d: worker dispatched a SYNC under an already-cancelled context instead of exiting", i)
		}
	}
}
