package firmware

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAcquire_SerializesRuns(t *testing.T) {
	t.Cleanup(func() { Watch(0) })

	releaseFirst, err := Acquire(context.Background(), nil)
	if err != nil {
		t.Fatalf("first Acquire: %v", err)
	}
	if !Busy() {
		t.Fatal("Busy is false while a run holds the slot")
	}

	var waited atomic.Int32
	got := make(chan func(), 1)
	go func() {
		release, err := Acquire(context.Background(), func() { waited.Add(1) })
		if err != nil {
			t.Errorf("second Acquire: %v", err)
		}
		got <- release
	}()

	select {
	case <-got:
		t.Fatal("the second run got the slot while the first held it")
	case <-time.After(50 * time.Millisecond):
	}
	if waited.Load() != 1 {
		t.Fatalf("onWait ran %d times, want once", waited.Load())
	}

	releaseFirst()
	select {
	case releaseSecond := <-got:
		if !Busy() {
			t.Fatal("Busy is false while the second run holds the slot")
		}
		releaseSecond()
	case <-time.After(2 * time.Second):
		t.Fatal("the second run never got the slot after the first released it")
	}
	if Busy() {
		t.Fatal("Busy is true with nothing running")
	}
}

func TestAcquire_FreeSlotDoesNotCallOnWait(t *testing.T) {
	called := false
	release, err := Acquire(context.Background(), func() { called = true })
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer release()
	if called {
		t.Fatal("onWait ran although the slot was free")
	}
}

// A task cancelled while it waits must not leave the slot taken.
func TestAcquire_CancelledWhileWaitingReturnsTheErrorAndKeepsTheSlotFree(t *testing.T) {
	release, _ := Acquire(context.Background(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := Acquire(ctx, nil)
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	if err := <-done; err != context.Canceled {
		t.Fatalf("Acquire returned %v, want context.Canceled", err)
	}

	release()
	if Busy() {
		t.Fatal("the cancelled waiter left the slot taken")
	}
	again, err := Acquire(context.Background(), nil)
	if err != nil {
		t.Fatalf("Acquire after the cancelled wait: %v", err)
	}
	again()
}

func TestRelease_IsIdempotent(t *testing.T) {
	first, _ := Acquire(context.Background(), nil)
	first()
	first() // a second call must not free a slot somebody else took

	second, _ := Acquire(context.Background(), nil)
	first()
	if !Busy() {
		t.Fatal("a stale release freed the slot the second run holds")
	}
	second()
}

func TestBusy_FollowsWhatTheReconcilerWatches(t *testing.T) {
	t.Cleanup(func() { Watch(0) })
	if Busy() {
		t.Fatal("Busy is true with nothing running")
	}
	Watch(2)
	if !Busy() {
		t.Fatal("Busy is false while the reconciler waits on rows")
	}
	Watch(0)
	if Busy() {
		t.Fatal("Busy is true after the reconciler stopped watching")
	}
}

// A run whose handler is gone (the connection dropped, or the previous process
// started it) still has OPNsense busy: a task that arrives meanwhile waits for
// the reconciler's rows too, or its check would be dropped by the launcher's lock
// and its status read would show what the run left, not what is pending.
func TestAcquire_WaitsWhileTheReconcilerWatchesARun(t *testing.T) {
	t.Cleanup(func() { Watch(0) })
	Watch(1)

	var waited atomic.Int32
	got := make(chan func(), 1)
	go func() {
		release, err := Acquire(context.Background(), func() { waited.Add(1) })
		if err != nil {
			t.Errorf("Acquire: %v", err)
		}
		got <- release
	}()

	select {
	case <-got:
		t.Fatal("a run got the slot while the reconciler was waiting on another")
	case <-time.After(50 * time.Millisecond):
	}
	if waited.Load() != 1 {
		t.Fatalf("onWait ran %d times, want once", waited.Load())
	}

	Watch(0)
	select {
	case release := <-got:
		release()
	case <-time.After(2 * time.Second):
		t.Fatal("the run never got the slot after the reconciler stopped waiting")
	}
}

// endedContext reports an error from the moment ended is set, and only wakes a
// select through Done when the test says so: it stands for a context that ends
// while the waiter is being woken by the slot being freed, whichever of the two
// the select happens to take.
type endedContext struct {
	context.Context
	ended atomic.Bool
}

func (c *endedContext) Err() error {
	if c.ended.Load() {
		return context.Canceled
	}
	return nil
}

// A handler that is cancelled while it waits (the agent is stopping) must not
// come away with the slot because the run ahead of it ended in the same moment.
func TestAcquire_NeverHandsTheSlotToAnEndedContext(t *testing.T) {
	holder, _ := Acquire(context.Background(), nil)
	ctx := &endedContext{Context: context.Background()}
	waiting := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		release, err := Acquire(ctx, func() { close(waiting) })
		if err == nil {
			release()
		}
		done <- err
	}()
	<-waiting
	time.Sleep(20 * time.Millisecond) // parked in the select

	ctx.ended.Store(true)
	holder() // frees the slot: the waiter wakes on that and sees its context has ended
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a run whose context had ended was given the slot")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the waiter never returned")
	}
	if Busy() {
		t.Fatal("the slot was left taken")
	}
}

func TestAcquire_ManyRunsNeverOverlap(t *testing.T) {
	var inside, maxInside atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := Acquire(context.Background(), nil)
			if err != nil {
				t.Errorf("Acquire: %v", err)
				return
			}
			n := inside.Add(1)
			for {
				m := maxInside.Load()
				if n <= m || maxInside.CompareAndSwap(m, n) {
					break
				}
			}
			time.Sleep(time.Millisecond)
			inside.Add(-1)
			release()
		}()
	}
	wg.Wait()
	if maxInside.Load() != 1 {
		t.Fatalf("%d runs held the slot at once, want 1", maxInside.Load())
	}
}
