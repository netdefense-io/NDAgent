package network

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// waitFor polls cond for up to two seconds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// A SYNC has an IN_PROGRESS row from the moment it is enqueued, but no handler
// until the worker dequeues it. It is this process's task the whole time.
func TestIsTaskLive_QueuedSyncIsLiveUntilItsHandlerReturns(t *testing.T) {
	d := newFIFOTestDispatcher()

	started := make(chan struct{})
	release := make(chan struct{})
	d.RegisterHandler(TaskTypeSync, func(ctx context.Context, ws *WebSocketClient, cmd Command) error {
		close(started)
		<-release
		return nil
	})

	if d.IsTaskLive("1") {
		t.Fatal("a task nobody has seen must not be live")
	}
	if !d.trySyncEnqueue(Command{TaskID: "1", TaskType: TaskTypeSync}) {
		t.Fatal("enqueue failed")
	}
	if !d.IsTaskLive("1") {
		t.Fatal("a queued SYNC with no worker yet must be live")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.ensureSyncWorker(ctx, nil)
	<-started
	if !d.IsTaskLive("1") {
		t.Fatal("a SYNC whose handler is running must be live")
	}

	close(release)
	waitFor(t, "the SYNC to stop being live", func() bool { return !d.IsTaskLive("1") })
}

func TestIsTaskLive_RunningHandlerOfAnyTypeIsLive(t *testing.T) {
	d := newFIFOTestDispatcher()

	started := make(chan struct{})
	release := make(chan struct{})
	d.RegisterHandler(TaskTypeFirmwareUpgrade, func(ctx context.Context, ws *WebSocketClient, cmd Command) error {
		close(started)
		<-release
		return nil
	})

	done := make(chan struct{})
	go func() {
		d.dispatchCommand(context.Background(), nil, Command{TaskID: "9", TaskType: TaskTypeFirmwareUpgrade})
		close(done)
	}()
	<-started
	if !d.IsTaskLive("9") {
		t.Fatal("a running handler must be live")
	}
	if d.IsTaskLive("10") {
		t.Fatal("another task id must not be live")
	}

	close(release)
	<-done
	if d.IsTaskLive("9") {
		t.Fatal("a finished handler must not be live")
	}
}

// A SYNC the queue refused is failed by the dispatcher itself; it must not
// linger as something a handler will get to.
func TestIsTaskLive_RefusedEnqueueIsNotLive(t *testing.T) {
	d := newFIFOTestDispatcher()

	for i := 0; i < syncQueueCapacity; i++ {
		if !d.trySyncEnqueue(Command{TaskID: fmt.Sprintf("q%d", i), TaskType: TaskTypeSync}) {
			t.Fatalf("enqueue %d failed before the queue was full", i)
		}
	}
	if d.trySyncEnqueue(Command{TaskID: "overflow", TaskType: TaskTypeSync}) {
		t.Fatal("enqueue past capacity succeeded")
	}
	if d.IsTaskLive("overflow") {
		t.Fatal("a refused SYNC must not be live")
	}
	if !d.IsTaskLive("q0") || !d.IsTaskLive(fmt.Sprintf("q%d", syncQueueCapacity-1)) {
		t.Fatal("the SYNCs that did fit must be live")
	}
}

// The order of IsTaskLive's two reads is what keeps a task that moves from the
// queued set to the active set from being seen in neither. A stress test almost
// never lands between two reads, so the move is made to happen between them.
func TestIsTaskLive_ReadsTheQueuedSetBeforeTheActiveSet(t *testing.T) {
	d := newFIFOTestDispatcher()
	d.queuedTasks.Store("7", struct{}{}) // queued, its handler not started

	livenessReadPause = func() { // the worker picks it up between the reads: active first, then off the queue
		d.activeTasks.Store("7", context.CancelFunc(func() {}))
		d.queuedTasks.Delete("7")
	}
	t.Cleanup(func() { livenessReadPause = nil })

	if !d.IsTaskLive("7") {
		t.Fatal("a task that moved from the queued set to the active set between the two reads was seen in neither")
	}
}

// A task moves from queued to active. If a reader could see it in neither, the
// connect-time drain would fail a SYNC that is about to run. Every id is
// checked from its enqueue until its handler has finished.
func TestIsTaskLive_NeverNeitherWhileASyncMovesFromQueuedToActive(t *testing.T) {
	d := newFIFOTestDispatcher()

	const total = 3000
	var mu sync.Mutex
	finished := make(map[string]bool, total)
	d.RegisterHandler(TaskTypeSync, func(ctx context.Context, ws *WebSocketClient, cmd Command) error {
		mu.Lock()
		finished[cmd.TaskID] = true
		mu.Unlock()
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.ensureSyncWorker(ctx, nil)

	var enqueued sync.Map
	stop := make(chan struct{})
	violation := make(chan string, 1)
	pollerDone := make(chan struct{})
	go func() {
		defer close(pollerDone)
		for {
			select {
			case <-stop:
				return
			default:
			}
			enqueued.Range(func(k, _ interface{}) bool {
				id := k.(string)
				// Liveness first, then "finished": a task that is no longer live
				// has finished, so this order cannot report a false violation.
				live := d.IsTaskLive(id)
				mu.Lock()
				fin := finished[id]
				mu.Unlock()
				if !live && !fin {
					select {
					case violation <- id:
					default:
					}
				}
				return true
			})
		}
	}()

	for i := 0; i < total; i++ {
		id := fmt.Sprintf("s%d", i)
		for !d.trySyncEnqueue(Command{TaskID: id, TaskType: TaskTypeSync}) {
			time.Sleep(time.Millisecond)
		}
		// Only ids whose enqueue has returned are checked: before that the task
		// is legitimately unknown.
		enqueued.Store(id, struct{}{})
	}
	waitFor(t, "every SYNC to finish", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(finished) == total
	})
	close(stop)
	<-pollerDone

	select {
	case id := <-violation:
		t.Fatalf("task %s was neither queued nor active before its handler finished", id)
	default:
	}
}

// The queue outlives a connection, its worker does not. A SYNC still queued
// when a connection begins must run without waiting for an unrelated SYNC.
func TestResumeQueuedSyncs_RestartsTheWorkerForALeftoverQueue(t *testing.T) {
	d := newFIFOTestDispatcher()

	ran := make(chan string, 1)
	d.RegisterHandler(TaskTypeSync, func(ctx context.Context, ws *WebSocketClient, cmd Command) error {
		ran <- cmd.TaskID
		return nil
	})
	if !d.trySyncEnqueue(Command{TaskID: "left-over", TaskType: TaskTypeSync}) {
		t.Fatal("enqueue failed")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// ReceiveCommands resumes first, then fails to read from a client that has no
	// connection, which is enough to observe the resume.
	if err := d.ReceiveCommands(ctx, &WebSocketClient{}); err == nil {
		t.Fatal("ReceiveCommands on an unconnected client returned nil")
	}

	select {
	case id := <-ran:
		if id != "left-over" {
			t.Fatalf("ran %q, want left-over", id)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the queued SYNC never ran")
	}
	waitFor(t, "the SYNC to stop being live", func() bool { return !d.IsTaskLive("left-over") })
}

func TestResumeQueuedSyncs_DoesNothingForAnEmptyQueue(t *testing.T) {
	d := newFIFOTestDispatcher()
	d.resumeQueuedSyncs(context.Background(), nil)

	d.syncWorkerMu.Lock()
	defer d.syncWorkerMu.Unlock()
	if d.syncWorkerCtx != nil {
		t.Fatal("a worker was started with nothing queued")
	}
}
