package pkgmgr

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// pkg(8) keeps its own lock on the local package database, but it retries
// for only a few seconds (LOCK_WAIT=1, LOCK_RETRIES=5 on OPNsense 26.1) —
// far less than an install can take. The agent dispatches every command in
// its own goroutine, so two overlapping tasks (a SYNC_API racing a
// PLUGIN_INSTALL, both of which shell out to pkg) could collide and fail on
// a lock timeout rather than on anything the operator did wrong.
//
// These tests pin the in-process guarantees: one pkg invocation at a time,
// and every invocation bounded by a deadline so a hung pkg cannot hold a
// task open until the connection tears down.

func TestPkgCallsAreSerialized(t *testing.T) {
	var concurrent int32
	var maxSeen int32

	busy := func(ctx context.Context, name string) MutateOutcome {
		n := atomic.AddInt32(&concurrent, 1)
		for {
			old := atomic.LoadInt32(&maxSeen)
			if n <= old || atomic.CompareAndSwapInt32(&maxSeen, old, n) {
				break
			}
		}
		time.Sleep(15 * time.Millisecond)
		atomic.AddInt32(&concurrent, -1)
		return MutateOutcome{Action: ActionInstalled}
	}

	defer SetInstallFunc(SetInstallFunc(busy))

	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			Install(context.Background(), "somepkg")
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt32(&maxSeen); got != 1 {
		t.Fatalf("expected pkg calls to be serialized, saw %d concurrent", got)
	}
}

// A mutate and a read must not overlap either: `pkg info` reads the same
// local database `pkg install` is writing.
func TestMutateAndQueryDoNotOverlap(t *testing.T) {
	var concurrent int32
	var maxSeen int32

	enter := func() {
		n := atomic.AddInt32(&concurrent, 1)
		for {
			old := atomic.LoadInt32(&maxSeen)
			if n <= old || atomic.CompareAndSwapInt32(&maxSeen, old, n) {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
		atomic.AddInt32(&concurrent, -1)
	}

	defer SetInstallFunc(SetInstallFunc(func(ctx context.Context, name string) MutateOutcome {
		enter()
		return MutateOutcome{Action: ActionInstalled}
	}))
	defer SetIsInstalledFunc(SetIsInstalledFunc(func(ctx context.Context, name string) (bool, error) {
		enter()
		return true, nil
	}))

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); Install(context.Background(), "p") }()
		wg.Add(1)
		go func() { defer wg.Done(); IsInstalled(context.Background(), "p") }()
	}
	wg.Wait()

	if got := atomic.LoadInt32(&maxSeen); got != 1 {
		t.Fatalf("mutate and read overlapped: saw %d concurrent", got)
	}
}

func TestEveryCallCarriesADeadline(t *testing.T) {
	cases := []struct {
		name string
		want time.Duration
		call func(ctx context.Context) (deadline time.Time, ok bool)
	}{
		{
			name: "update",
			want: updateTimeout,
			call: func(ctx context.Context) (time.Time, bool) {
				var d time.Time
				var ok bool
				defer SetUpdateFunc(SetUpdateFunc(func(c context.Context) error {
					d, ok = c.Deadline()
					return nil
				}))
				_ = Update(ctx)
				return d, ok
			},
		},
		{
			name: "install",
			want: mutateTimeout,
			call: func(ctx context.Context) (time.Time, bool) {
				var d time.Time
				var ok bool
				defer SetInstallFunc(SetInstallFunc(func(c context.Context, n string) MutateOutcome {
					d, ok = c.Deadline()
					return MutateOutcome{Action: ActionInstalled}
				}))
				Install(ctx, "p")
				return d, ok
			},
		},
		{
			name: "delete",
			want: mutateTimeout,
			call: func(ctx context.Context) (time.Time, bool) {
				var d time.Time
				var ok bool
				defer SetRemoveFunc(SetRemoveFunc(func(c context.Context, n string) MutateOutcome {
					d, ok = c.Deadline()
					return MutateOutcome{Action: ActionRemoved}
				}))
				Delete(ctx, "p")
				return d, ok
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			deadline, ok := tc.call(context.Background())
			if !ok {
				t.Fatalf("%s ran with no deadline; a hung pkg would block until teardown", tc.name)
			}
			got := deadline.Sub(start)
			// Generous window: we care that the right ceiling was applied,
			// not about scheduler jitter.
			if got < tc.want-2*time.Second || got > tc.want+2*time.Second {
				t.Fatalf("%s deadline %v, want ~%v", tc.name, got, tc.want)
			}
		})
	}
}

// A caller that already imposed a tighter deadline must keep it — the
// ceiling is a backstop, not an override.
func TestCallerDeadlineIsNotExtended(t *testing.T) {
	var got time.Time
	var ok bool
	defer SetInstallFunc(SetInstallFunc(func(c context.Context, n string) MutateOutcome {
		got, ok = c.Deadline()
		return MutateOutcome{Action: ActionInstalled}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	Install(ctx, "p")

	if !ok {
		t.Fatal("expected a deadline")
	}
	if d := got.Sub(start); d > 5*time.Second {
		t.Fatalf("caller's 3s deadline was extended to %v", d)
	}
}

func TestTimeoutValuesMatchTheContract(t *testing.T) {
	if updateTimeout != 120*time.Second {
		t.Errorf("update timeout = %v, want 120s", updateTimeout)
	}
	if mutateTimeout != 600*time.Second {
		t.Errorf("mutate timeout = %v, want 600s", mutateTimeout)
	}
	if addURLTimeout != 900*time.Second {
		t.Errorf("pkg add URL timeout = %v, want 900s", addURLTimeout)
	}
}
