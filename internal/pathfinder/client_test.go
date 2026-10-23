package pathfinder

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// newTestPathfinderServer starts an httptest server that upgrades to a
// WebSocket, performs the register/registered handshake NewClient.Connect
// expects, then hands the raw server-side connection to onConnected so the
// test can drive whatever it needs afterward (a close frame, a text
// message, an abrupt disconnect, ...).
func newTestPathfinderServer(t *testing.T, onConnected func(conn *websocket.Conn)) *httptest.Server {
	t.Helper()

	upgrader := websocket.Upgrader{}
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		// Read the register message and reply "registered".
		var msg Message
		if err := conn.ReadJSON(&msg); err != nil {
			return
		}
		if msg.Type != MsgTypeRegister {
			return
		}
		registered := Message{
			Type:    MsgTypeRegistered,
			Payload: mustMarshal(t, RegisteredPayload{SessionKey: "s", Role: "agent", PeerOnline: false}),
		}
		if err := conn.WriteJSON(registered); err != nil {
			return
		}

		onConnected(conn)
	})

	return httptest.NewServer(mux)
}

func mustMarshal(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func wsURL(httpURL string) string {
	return "ws" + strings.TrimPrefix(httpURL, "http") + "/ws"
}

func newConnectedTestClient(t *testing.T, onConnected func(conn *websocket.Conn)) (*Client, func()) {
	t.Helper()

	srv := newTestPathfinderServer(t, onConnected)

	client := NewClient(wsURL(srv.URL), "session-key", "device-id", nil)
	if err := client.Connect(context.Background()); err != nil {
		srv.Close()
		t.Fatalf("Connect failed: %v", err)
	}

	return client, func() {
		client.Close()
		srv.Close()
	}
}

// ── Clean-close classification ──────────────────────────────────────────

func TestRunFrameLoop_CleanClose_NormalClosure(t *testing.T) {
	const reason = "TTL expired (client never connected)"

	client, cleanup := newConnectedTestClient(t, func(conn *websocket.Conn) {
		time.Sleep(20 * time.Millisecond)
		_ = conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, reason),
			time.Now().Add(time.Second))
	})
	defer cleanup()

	err := client.RunFrameLoop(context.Background())

	var cleanClose *ErrSessionEndedCleanly
	if !errors.As(err, &cleanClose) {
		t.Fatalf("RunFrameLoop returned %v (%T), want *ErrSessionEndedCleanly", err, err)
	}
	if cleanClose.Reason != reason {
		t.Errorf("Reason = %q, want %q", cleanClose.Reason, reason)
	}
}

func TestRunFrameLoop_CleanClose_GoingAway(t *testing.T) {
	const reason = "idle timeout (15m0s)"

	client, cleanup := newConnectedTestClient(t, func(conn *websocket.Conn) {
		time.Sleep(20 * time.Millisecond)
		_ = conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseGoingAway, reason),
			time.Now().Add(time.Second))
	})
	defer cleanup()

	err := client.RunFrameLoop(context.Background())

	var cleanClose *ErrSessionEndedCleanly
	if !errors.As(err, &cleanClose) {
		t.Fatalf("RunFrameLoop returned %v (%T), want *ErrSessionEndedCleanly", err, err)
	}
	if cleanClose.Reason != reason {
		t.Errorf("Reason = %q, want %q", cleanClose.Reason, reason)
	}
}

// TestRunFrameLoop_AbnormalClose_NotClassifiedAsClean pins the other half of
// the contract: an abrupt disconnect (no close frame at all — the 1005/1006
// case in practice) must NOT produce ErrSessionEndedCleanly. It surfaces as
// a plain error, same as before this change.
func TestRunFrameLoop_AbnormalClose_NotClassifiedAsClean(t *testing.T) {
	client, cleanup := newConnectedTestClient(t, func(conn *websocket.Conn) {
		time.Sleep(20 * time.Millisecond)
		// Close the underlying TCP connection without a WebSocket close
		// frame — this is what an abandoned/killed relay connection looks
		// like, and is what produces a 1005/1006 on the client side.
		_ = conn.NetConn().Close()
	})
	defer cleanup()

	err := client.RunFrameLoop(context.Background())

	if err == nil {
		t.Fatal("RunFrameLoop returned nil, want an error")
	}
	var cleanClose *ErrSessionEndedCleanly
	if errors.As(err, &cleanClose) {
		t.Fatalf("abrupt close misclassified as clean: %v", cleanClose)
	}
	if !strings.Contains(err.Error(), "read failed") {
		t.Errorf("error = %q, want it to still be wrapped as a read failure", err.Error())
	}
}

// ── ErrSessionEndedCleanly.Error() ──────────────────────────────────────

func TestErrSessionEndedCleanly_Error(t *testing.T) {
	withReason := &ErrSessionEndedCleanly{Reason: "TTL expired"}
	if got := withReason.Error(); got != "TTL expired" {
		t.Errorf("Error() = %q, want %q", got, "TTL expired")
	}

	empty := &ErrSessionEndedCleanly{}
	if got := empty.Error(); got == "" {
		t.Error("Error() must not be empty even with no reason text")
	}
}

// ── peer_offline handling ───────────────────────────────────────────────

// holdOpen keeps the relay side of a test connection open (and silent) until
// the test ends, so a frame loop that returns proves it ended the session on
// its own and was not ended by the relay.
func holdOpen(t *testing.T) <-chan struct{} {
	t.Helper()
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	return release
}

func sendPeerOffline(t *testing.T, conn *websocket.Conn, payload []byte) {
	t.Helper()
	_ = conn.WriteJSON(Message{Type: MsgTypePeerOffline, Payload: payload})
}

// runFrameLoopWithin runs RunFrameLoop and fails the test if it is still
// running after d.
func runFrameLoopWithin(t *testing.T, client *Client, d time.Duration) error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- client.RunFrameLoop(ctx) }()
	select {
	case err := <-done:
		return err
	case <-time.After(d):
		cancel()
		<-done
		t.Fatalf("RunFrameLoop was still running %v after the relay reported the client gone", d)
		return nil
	}
}

// TestRunFrameLoop_PeerOfflineEndsTheSession pins that the agent ends its
// side as soon as the relay reports the client gone, with the reason
// "client disconnected", instead of holding the session until the relay's
// TTL reaps it as "client never connected".
func TestRunFrameLoop_PeerOfflineEndsTheSession(t *testing.T) {
	release := holdOpen(t)
	client, cleanup := newConnectedTestClient(t, func(conn *websocket.Conn) {
		sendPeerOffline(t, conn, mustMarshal(t, PeerOfflinePayload{PeerID: "client-1234", Role: "client"}))
		<-release
	})
	defer cleanup()

	err := runFrameLoopWithin(t, client, 2*time.Second)

	var ended *ErrSessionEndedCleanly
	if !errors.As(err, &ended) {
		t.Fatalf("RunFrameLoop returned %v (%T), want *ErrSessionEndedCleanly", err, err)
	}
	if ended.Reason != "client disconnected" {
		t.Errorf("Reason = %q, want %q", ended.Reason, "client disconnected")
	}
}

// TestRunFrameLoop_PeerOfflineWithAnUnreadablePayloadStillEndsTheSession:
// the agent's only peer is the client, so the signal alone ends the session.
func TestRunFrameLoop_PeerOfflineWithAnUnreadablePayloadStillEndsTheSession(t *testing.T) {
	release := holdOpen(t)
	client, cleanup := newConnectedTestClient(t, func(conn *websocket.Conn) {
		sendPeerOffline(t, conn, []byte(`"not an object"`))
		<-release
	})
	defer cleanup()

	err := runFrameLoopWithin(t, client, 2*time.Second)

	var ended *ErrSessionEndedCleanly
	if !errors.As(err, &ended) || ended.Reason != "client disconnected" {
		t.Fatalf("RunFrameLoop returned %v, want a natural end with reason %q", err, "client disconnected")
	}
}

// ── WaitForPairing ──────────────────────────────────────────────────────

func TestWaitForPairing_PairedReturnsNil(t *testing.T) {
	release := holdOpen(t)
	client, cleanup := newConnectedTestClient(t, func(conn *websocket.Conn) {
		_ = conn.WriteJSON(Message{Type: MsgTypePaired})
		<-release
	})
	defer cleanup()

	if err := client.WaitForPairing(context.Background(), 2*time.Second); err != nil {
		t.Fatalf("WaitForPairing returned %v, want nil", err)
	}
}

// TestWaitForPairing_NoClientIsANaturalEnd: a session no client paired with
// ends as "client never connected", not as a read failure.
func TestWaitForPairing_NoClientIsANaturalEnd(t *testing.T) {
	release := holdOpen(t)
	client, cleanup := newConnectedTestClient(t, func(conn *websocket.Conn) {
		<-release
	})
	defer cleanup()

	err := client.WaitForPairing(context.Background(), 150*time.Millisecond)

	var ended *ErrSessionEndedCleanly
	if !errors.As(err, &ended) {
		t.Fatalf("WaitForPairing returned %v (%T), want *ErrSessionEndedCleanly", err, err)
	}
	if ended.Reason != "client never connected" {
		t.Errorf("Reason = %q, want %q", ended.Reason, "client never connected")
	}
}

// TestWaitForPairing_RelayCleanCloseIsANaturalEnd: the relay reaping the
// session at its TTL while the agent waits keeps the relay's reason.
func TestWaitForPairing_RelayCleanCloseIsANaturalEnd(t *testing.T) {
	const reason = "TTL expired (client never connected)"
	client, cleanup := newConnectedTestClient(t, func(conn *websocket.Conn) {
		_ = conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, reason),
			time.Now().Add(time.Second))
	})
	defer cleanup()

	err := client.WaitForPairing(context.Background(), 2*time.Second)

	var ended *ErrSessionEndedCleanly
	if !errors.As(err, &ended) {
		t.Fatalf("WaitForPairing returned %v (%T), want *ErrSessionEndedCleanly", err, err)
	}
	if ended.Reason != reason {
		t.Errorf("Reason = %q, want %q", ended.Reason, reason)
	}
}

func TestWaitForPairing_AbruptCloseIsAFailure(t *testing.T) {
	client, cleanup := newConnectedTestClient(t, func(conn *websocket.Conn) {
		_ = conn.NetConn().Close()
	})
	defer cleanup()

	err := client.WaitForPairing(context.Background(), 2*time.Second)

	var ended *ErrSessionEndedCleanly
	if err == nil || errors.As(err, &ended) {
		t.Fatalf("WaitForPairing returned %v, want a read failure", err)
	}
	if !strings.Contains(err.Error(), "read failed while waiting for pairing") {
		t.Errorf("error = %q, want it wrapped as a read failure", err.Error())
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "connection timed out" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// TestPairingReadEnd_TimeoutBeforeTheDeadlineIsAFailure: only the wait's own
// deadline means no client came. A connection the kernel gave up on reads as
// a timeout too, and before the deadline it stays a failure.
func TestPairingReadEnd_TimeoutBeforeTheDeadlineIsAFailure(t *testing.T) {
	var ended *ErrSessionEndedCleanly

	early := pairingReadEnd(timeoutError{}, time.Now().Add(time.Minute))
	if errors.As(early, &ended) {
		t.Errorf("a timeout before the deadline classified as %v, want a read failure", ended)
	}

	late := pairingReadEnd(timeoutError{}, time.Now().Add(-time.Millisecond))
	if !errors.As(late, &ended) || ended.Reason != "client never connected" {
		t.Errorf("a timeout at the deadline returned %v, want a natural end with reason %q", late, "client never connected")
	}

	if other := pairingReadEnd(errors.New("connection reset by peer"), time.Now().Add(-time.Millisecond)); errors.As(other, &ended) {
		t.Errorf("a reset after the deadline classified as %v, want a read failure", ended)
	}
}

// ── Close ───────────────────────────────────────────────────────────────

// TestCloseWhileAFrameIsBeingSent: the session ends without waiting for its
// streams, so Close must be safe beside a SendFrame (run with -race).
func TestCloseWhileAFrameIsBeingSent(t *testing.T) {
	release := holdOpen(t)
	client, cleanup := newConnectedTestClient(t, func(conn *websocket.Conn) {
		go func() {
			for {
				if _, _, err := conn.ReadMessage(); err != nil {
					return
				}
			}
		}()
		<-release
	})
	defer cleanup()

	stop := make(chan struct{})
	sent := make(chan struct{})
	go func() {
		defer close(sent)
		frame := make([]byte, 4096)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if err := client.SendFrame(frame); err != nil {
				return
			}
		}
	}()

	time.Sleep(20 * time.Millisecond)
	_ = client.Close()
	close(stop)
	<-sent
}
