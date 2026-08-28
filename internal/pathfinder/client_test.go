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

func TestRunFrameLoop_PeerOffline_RecordsFlag(t *testing.T) {
	client, cleanup := newConnectedTestClient(t, func(conn *websocket.Conn) {
		time.Sleep(20 * time.Millisecond)
		msg := Message{
			Type:    MsgTypePeerOffline,
			Payload: mustMarshal(t, PeerOfflinePayload{PeerID: "other-device", Role: "client"}),
		}
		_ = conn.WriteJSON(msg)
		// Keep the connection open so RunFrameLoop is still the one
		// blocking on ReadMessage when the test asserts the flag.
		time.Sleep(200 * time.Millisecond)
	})
	defer cleanup()

	if client.PeerOfflineRecently(time.Second) {
		t.Fatal("PeerOfflineRecently true before any peer_offline was received")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- client.RunFrameLoop(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for !client.PeerOfflineRecently(time.Second) {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for peer_offline to be recorded")
		}
		time.Sleep(5 * time.Millisecond)
	}

	cancel()
	<-done
}

func TestPeerOfflineRecently_Window(t *testing.T) {
	client := NewClient("ws://example.invalid/ws", "s", "d", nil)

	if client.PeerOfflineRecently(time.Minute) {
		t.Fatal("fresh client must report no recent peer_offline")
	}

	client.recordPeerOffline()

	if !client.PeerOfflineRecently(time.Minute) {
		t.Error("just-recorded peer_offline must be within a minute-wide window")
	}
	if client.PeerOfflineRecently(0) {
		t.Error("a zero-width window must not match even an instant-old timestamp")
	}
}
