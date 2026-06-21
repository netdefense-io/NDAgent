package pathfinder

import (
	"sync/atomic"
	"testing"

	"github.com/netdefense-io/ndagent/internal/logging"
)

// newLifetimeTestManager builds a StreamManager with a no-op sendFrameFunc so
// ACK/CLOSE frames don't need a real client connection.
func newLifetimeTestManager() *StreamManager {
	mgr := &StreamManager{
		streams: make(map[uint32]*Stream),
		log:     logging.Named("test"),
	}
	mgr.sendFrameFunc = func([]byte) error { return nil }
	return mgr
}

// openThenCloseStream drives one stream's full open→close lifecycle through the
// frame handlers, mimicking a single per-request webadmin stream.
func openThenCloseStream(mgr *StreamManager, id uint32, service string) {
	mgr.handleFrame(EncodeFrame(&Frame{Type: FrameTypeOpen, StreamID: id, Data: []byte(service)}))
	mgr.handleFrame(EncodeFrame(&Frame{Type: FrameTypeClose, StreamID: id}))
}

// TestSessionNotTornDownWhenStreamsReachZero is the core of the broad webadmin
// fix: when no all-streams-closed teardown is registered (the connect.go
// behavior — session lifetime is relay-tied, not stream-count-tied), opening
// and closing a webadmin stream so the count returns to zero must NOT trigger
// any session teardown. This is what lets the webadmin tunnel survive between
// per-request streams and after a terminal stream closes.
func TestSessionNotTornDownWhenStreamsReachZero(t *testing.T) {
	mgr := newLifetimeTestManager()
	// Intentionally do NOT call mgr.OnAllStreamsClosed — matching connect.go.

	// A no-op handler so handleOpen doesn't close the stream for "no handler".
	mgr.OnNewStream(func(*Stream) {})

	// Simulate several per-request webadmin streams; count returns to zero
	// after each one.
	for i := uint32(1); i <= 5; i++ {
		openThenCloseStream(mgr, i, ServiceWebadmin)
		if got := mgr.ActiveStreamCount(); got != 0 {
			t.Fatalf("after stream %d open/close, expected 0 active streams, got %d", i, got)
		}
	}

	// The session is still alive: nothing fired a teardown. (With onAllClosed
	// unset, handleClose's count==0 branch is a no-op — proven by the absence
	// of a panic and by the following positive control.)
}

// TestOnAllStreamsClosedStillFiresWhenRegistered is the positive control: the
// StreamManager mechanism itself is intact and fires exactly once when the last
// stream closes IF a callback is registered. connect.go simply chooses not to
// register one anymore, but the capability must keep working (and not fire
// before the first stream, nor more than once).
func TestOnAllStreamsClosedStillFiresWhenRegistered(t *testing.T) {
	mgr := newLifetimeTestManager()
	mgr.OnNewStream(func(*Stream) {})

	var fired int32
	mgr.OnAllStreamsClosed(func() { atomic.AddInt32(&fired, 1) })

	// No streams opened yet → must not fire.
	if n := atomic.LoadInt32(&fired); n != 0 {
		t.Fatalf("callback fired before any stream opened: %d", n)
	}

	openThenCloseStream(mgr, 1, ServiceWebadmin)

	if n := atomic.LoadInt32(&fired); n != 1 {
		t.Fatalf("expected all-streams-closed callback to fire exactly once, got %d", n)
	}
}

// TestTeardownDrivenByContextNotStreamCount documents the relay-tied lifetime:
// the connect session ends when its context is cancelled (relay/WS disconnect
// detected by ping/pong, or broker TTL / agent shutdown), independent of how
// many streams are open. Here we assert the proxy cleanup contract: CloseAll is
// safe to call when streams are still open (as it is after RunFrameLoop returns
// on relay end), tearing everything down regardless of stream count.
func TestTeardownDrivenByContextNotStreamCount(t *testing.T) {
	mgr := newLifetimeTestManager()
	mgr.OnNewStream(func(*Stream) {})

	// Open streams and leave them open (no close frame) — simulates an active
	// session with live streams when the relay drops.
	mgr.handleFrame(EncodeFrame(&Frame{Type: FrameTypeOpen, StreamID: 1, Data: []byte(ServiceWebadmin)}))
	mgr.handleFrame(EncodeFrame(&Frame{Type: FrameTypeOpen, StreamID: 2, Data: []byte(ServiceWebadmin)}))
	if got := mgr.ActiveStreamCount(); got != 2 {
		t.Fatalf("expected 2 active streams, got %d", got)
	}

	// Relay-end path: connectToPathfinder calls streamMgr.CloseAll() after
	// RunFrameLoop returns. It must close every remaining stream regardless of
	// count, so no stream dangles past the relay.
	mgr.CloseAll()
	if got := mgr.ActiveStreamCount(); got != 0 {
		t.Fatalf("after CloseAll on relay end, expected 0 active streams, got %d", got)
	}
}
