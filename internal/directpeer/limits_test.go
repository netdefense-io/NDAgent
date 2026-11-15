package directpeer

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// watch runs Watch and returns what it said and after how long.
func watch(t *testing.T, l Limits, ctx context.Context, connected <-chan struct{}, lastFrame func() time.Time) (string, time.Duration) {
	t.Helper()
	began := time.Now()
	result := make(chan string, 1)
	go func() { result <- l.Watch(ctx, began, connected, lastFrame) }()
	select {
	case limit := <-result:
		return limit, time.Since(began)
	case <-time.After(10 * time.Second):
		t.Fatal("Watch did not return")
		return "", 0
	}
}

func never() time.Time { return time.Time{} }

// notBefore checks that something timed did not happen early. How late it
// may be is left to the test's own deadline: a loaded machine is slow, and a
// limit that never fires fails there.
func notBefore(t *testing.T, what string, got, earliest time.Duration) {
	t.Helper()
	if got < earliest {
		t.Errorf("%s after %v, want not before %v", what, got.Round(time.Millisecond), earliest)
	}
}

func TestNoClientWithinThePairingWindowEndsTheSession(t *testing.T) {
	l := Limits{Pairing: 150 * time.Millisecond, Idle: time.Hour, Lifetime: time.Hour}
	limit, after := watch(t, l, context.Background(), make(chan struct{}), never)
	if limit != EndNoClient {
		t.Errorf("limit = %q, want %q", limit, EndNoClient)
	}
	notBefore(t, "pairing limit", after, 140*time.Millisecond)
}

// A client that connected is no longer held to the pairing window, and an
// idle session ends after the idle limit counted from the connection.
func TestAnIdleSessionEnds(t *testing.T) {
	l := Limits{Pairing: 5 * time.Second, Idle: 300 * time.Millisecond, Lifetime: time.Hour}
	connected := make(chan struct{})
	time.AfterFunc(50*time.Millisecond, func() { close(connected) })
	limit, after := watch(t, l, context.Background(), connected, never)
	if limit != EndIdleTimeout {
		t.Errorf("limit = %q, want %q", limit, EndIdleTimeout)
	}
	notBefore(t, "idle limit", after, 340*time.Millisecond)

	// A client that was there from the start, and a pairing window that
	// would have passed long before the idle limit: it no longer counts.
	l = Limits{Pairing: 50 * time.Millisecond, Idle: 400 * time.Millisecond, Lifetime: time.Hour}
	already := make(chan struct{})
	close(already)
	limit, after = watch(t, l, context.Background(), already, never)
	if limit != EndIdleTimeout {
		t.Errorf("limit = %q for a client that had connected, want %q", limit, EndIdleTimeout)
	}
	notBefore(t, "idle limit", after, 390*time.Millisecond)
}

// Frames in either direction keep a session from being idle; it ends one idle
// limit after the last one.
func TestFramesKeepASessionFromBeingIdle(t *testing.T) {
	// A frame every 50 ms for a second and a half, against an idle limit of
	// a second: wide apart, so a slow machine does not make the session idle
	// between two frames.
	l := Limits{Pairing: time.Hour, Idle: time.Second, Lifetime: time.Hour}
	connected := make(chan struct{})
	close(connected)

	began := time.Now()
	var last atomic.Pointer[time.Time]
	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case now := <-ticker.C:
				last.Store(&now)
				if time.Since(began) > 1500*time.Millisecond {
					close(stop)
					return
				}
			case <-stop:
				return
			}
		}
	}()
	lastFrame := func() time.Time {
		if at := last.Load(); at != nil {
			return *at
		}
		return time.Time{}
	}

	limit, after := watch(t, l, context.Background(), connected, lastFrame)
	if limit != EndIdleTimeout {
		t.Errorf("limit = %q, want %q", limit, EndIdleTimeout)
	}
	notBefore(t, "idle limit of a session busy for 1.5 s", after, 2400*time.Millisecond)
}

// The lifetime limit holds whatever the session does.
func TestABusySessionStillEndsAtItsLifetime(t *testing.T) {
	l := Limits{Pairing: time.Hour, Idle: time.Hour, Lifetime: 250 * time.Millisecond}
	connected := make(chan struct{})
	close(connected)
	limit, after := watch(t, l, context.Background(), connected, time.Now)
	if limit != EndMaxDuration {
		t.Errorf("limit = %q, want %q", limit, EndMaxDuration)
	}
	notBefore(t, "lifetime limit", after, 240*time.Millisecond)

	// And before any client: the lifetime is counted from listening.
	l = Limits{Pairing: time.Hour, Idle: time.Hour, Lifetime: 100 * time.Millisecond}
	if limit, _ := watch(t, l, context.Background(), make(chan struct{}), never); limit != EndMaxDuration {
		t.Errorf("limit = %q, want %q", limit, EndMaxDuration)
	}
}

func TestWatchEndsWithItsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	limit, after := watch(t, MaxLimits, ctx, make(chan struct{}), never)
	if limit != "" {
		t.Errorf("limit = %q for a session whose context ended, want none", limit)
	}
	notBefore(t, "return", after, 90*time.Millisecond)
}

// The control plane names a session's limits; the agent takes each where it
// is lower than its own and never where it is higher.
func TestLimitsForNeverExceedTheAgentsOwn(t *testing.T) {
	cases := []struct {
		pair, idle, max int
		want            Limits
	}{
		{300, 1800, 28800, Limits{5 * time.Minute, 30 * time.Minute, 8 * time.Hour}},
		{60, 600, 3600, Limits{time.Minute, 10 * time.Minute, time.Hour}},
		{301, 1801, 28801, Limits{5 * time.Minute, 30 * time.Minute, 8 * time.Hour}},
		{86400, 86400, 864000, Limits{5 * time.Minute, 30 * time.Minute, 8 * time.Hour}},
		{1, 1, 1, Limits{time.Second, time.Second, time.Second}},
		{299, 1800, 28800, Limits{299 * time.Second, 30 * time.Minute, 8 * time.Hour}},
		{1 << 40, 1 << 40, 1 << 40, Limits{5 * time.Minute, 30 * time.Minute, 8 * time.Hour}},
	}
	for _, tc := range cases {
		got, ok := LimitsFor(tc.pair, tc.idle, tc.max)
		if !ok || got != tc.want {
			t.Errorf("LimitsFor(%d, %d, %d) = %+v, %v; want %+v", tc.pair, tc.idle, tc.max, got, ok, tc.want)
		}
	}
	for _, bad := range [][3]int{{0, 1800, 28800}, {300, 0, 28800}, {300, 1800, 0}, {-1, 1800, 28800}, {300, -5, 28800}, {300, 1800, -28800}} {
		if got, ok := LimitsFor(bad[0], bad[1], bad[2]); ok {
			t.Errorf("LimitsFor(%v) = %+v: a limit that is not above zero is no limit", bad, got)
		}
	}
}

// The device carries as many sessions as the control plane allows it, and
// never more than the agent's own maximum of eight.
func TestSessionsAreCountedAgainstTheAllowedNumber(t *testing.T) {
	var sessions Sessions
	var releases []func()
	for i := 0; i < 4; i++ {
		release, ok := sessions.Acquire(4)
		if !ok {
			t.Fatalf("session %d of 4 allowed was refused", i+1)
		}
		releases = append(releases, release)
	}
	if _, ok := sessions.Acquire(4); ok {
		t.Fatal("a fifth session was let in with 4 allowed")
	}
	if sessions.Open() != 4 {
		t.Errorf("open = %d, want 4", sessions.Open())
	}

	releases[0]()
	releases[0]() // a second call gives nothing back
	if sessions.Open() != 3 {
		t.Errorf("open = %d after one session ended, want 3", sessions.Open())
	}
	release, ok := sessions.Acquire(4)
	if !ok {
		t.Fatal("no session was let in after one ended")
	}
	if _, ok := sessions.Acquire(4); ok {
		t.Fatal("ending one session twice let two in")
	}
	releases[0] = release

	// A control plane that allows more is held to eight.
	for i := 4; i < 8; i++ {
		release, ok := sessions.Acquire(1000)
		if !ok {
			t.Fatalf("session %d was refused with 1000 allowed", i+1)
		}
		releases = append(releases, release)
	}
	if _, ok := sessions.Acquire(1000); ok {
		t.Fatal("a ninth session was let in: the agent's own maximum is 8")
	}

	// One that allows fewer than are open lets nobody in, and ends nobody.
	if _, ok := sessions.Acquire(2); ok {
		t.Fatal("a session was let in with 2 allowed and 8 open")
	}
	for _, allowed := range []int{0, -1} {
		if _, ok := (&Sessions{}).Acquire(allowed); ok {
			t.Errorf("a session was let in with %d allowed", allowed)
		}
	}
	for _, r := range releases {
		r()
	}
	if sessions.Open() != 0 {
		t.Errorf("open = %d after all ended", sessions.Open())
	}
}

// The wait for the client and the session's lifetime are counted from the
// moment the companion listened, not from the moment the watch began.
func TestLimitsAreCountedFromListening(t *testing.T) {
	l := Limits{Pairing: 400 * time.Millisecond, Idle: time.Hour, Lifetime: time.Hour}
	listeningAt := time.Now().Add(-300 * time.Millisecond)
	began := time.Now()
	if why := l.Watch(context.Background(), listeningAt, make(chan struct{}), never); why != EndNoClient {
		t.Fatalf("why = %q, want %q", why, EndNoClient)
	}
	if waited := time.Since(began); waited < 50*time.Millisecond || waited > 350*time.Millisecond {
		t.Errorf("the pairing window of 400 ms, 300 ms of it gone, ended after %v", waited)
	}

	// A session whose lifetime is already over ends at once.
	l = Limits{Pairing: time.Hour, Idle: time.Hour, Lifetime: time.Second}
	began = time.Now()
	if why := l.Watch(context.Background(), time.Now().Add(-time.Minute), make(chan struct{}), never); why != EndMaxDuration {
		t.Fatalf("why = %q, want %q", why, EndMaxDuration)
	}
	if waited := time.Since(began); waited > 5*time.Second {
		t.Errorf("a lifetime that had passed was noticed after %v", waited)
	}
}
