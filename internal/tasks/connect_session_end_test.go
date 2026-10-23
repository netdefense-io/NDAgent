package tasks

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/netdefense-io/ndagent/internal/config"
	"github.com/netdefense-io/ndagent/internal/network"
	"github.com/netdefense-io/ndagent/internal/pathfinder"
)

// fakeRelay plays the relay's side of one agent connection: it answers the
// register, runs script, then keeps the connection open, without ever closing
// it itself, and reports the close code the agent sends.
type fakeRelay struct {
	url       string
	closeCode chan int
}

func newFakeRelay(t *testing.T, script func(conn *websocket.Conn)) *fakeRelay {
	t.Helper()
	relay := &fakeRelay{closeCode: make(chan int, 1)}
	testEnded := make(chan struct{})

	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		go func() {
			<-testEnded
			conn.Close()
		}()

		var msg pathfinder.Message
		if err := conn.ReadJSON(&msg); err != nil || msg.Type != pathfinder.MsgTypeRegister {
			return
		}
		payload, _ := json.Marshal(pathfinder.RegisteredPayload{SessionKey: "s", Role: "agent"})
		if err := conn.WriteJSON(pathfinder.Message{Type: pathfinder.MsgTypeRegistered, Payload: payload}); err != nil {
			return
		}
		if script != nil {
			script(conn)
		}
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				code := -1
				if closeErr, ok := err.(*websocket.CloseError); ok {
					code = closeErr.Code
				}
				relay.closeCode <- code
				return
			}
		}
	}))
	t.Cleanup(func() {
		close(testEnded)
		srv.Close()
	})
	relay.url = srv.URL
	return relay
}

func (r *fakeRelay) client() *network.WebSocketClient {
	return network.NewWebSocketClient(&config.Config{PathfinderHost: r.url, DeviceUUID: "device-1"}, nil, nil, nil, nil)
}

// connectWithin runs connectToPathfinder and fails the test if the session is
// still open after d.
func connectWithin(t *testing.T, ws *network.WebSocketClient, d time.Duration) error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- connectToPathfinder(ctx, ws, "session-key-0123456789", "root", false, config.RemoteAccessFull)
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(d):
		cancel()
		<-done
		t.Fatalf("the session was still open after %v", d)
		return nil
	}
}

// TestConnectToPathfinder_EndsWhenTheClientLeaves: once the relay reports the
// paired client gone, the agent closes its own relay connection and the task
// ends as a natural end with the reason "client disconnected", while the
// relay keeps the connection open (it would only reap it at the session TTL).
func TestConnectToPathfinder_EndsWhenTheClientLeaves(t *testing.T) {
	relay := newFakeRelay(t, func(conn *websocket.Conn) {
		_ = conn.WriteJSON(pathfinder.Message{Type: pathfinder.MsgTypePaired})
		offline, _ := json.Marshal(pathfinder.PeerOfflinePayload{PeerID: "client-1234", Role: "client"})
		_ = conn.WriteJSON(pathfinder.Message{Type: pathfinder.MsgTypePeerOffline, Payload: offline})
	})

	err := connectWithin(t, relay.client(), 3*time.Second)

	outcome := classifyPathfinderSessionEnd(nil, err)
	if !outcome.result.Success || !outcome.naturalEnd {
		t.Fatalf("outcome = %+v (err %v), want a natural end", outcome, err)
	}
	if want := "Relay session ended: client disconnected"; outcome.result.Message != want {
		t.Errorf("message = %q, want %q", outcome.result.Message, want)
	}

	select {
	case code := <-relay.closeCode:
		if code != websocket.CloseNormalClosure {
			t.Errorf("the agent left the relay with close code %d, want %d", code, websocket.CloseNormalClosure)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the agent did not close its relay connection")
	}
}

// TestConnectToPathfinder_NoClientWithinThePairingWait: a session no client
// paired with ends as "client never connected", a natural end, not FAILED.
func TestConnectToPathfinder_NoClientWithinThePairingWait(t *testing.T) {
	old := pairingTimeout
	pairingTimeout = 200 * time.Millisecond
	t.Cleanup(func() { pairingTimeout = old })

	relay := newFakeRelay(t, nil)

	err := connectWithin(t, relay.client(), 3*time.Second)

	outcome := classifyPathfinderSessionEnd(nil, err)
	if !outcome.result.Success || !outcome.naturalEnd {
		t.Fatalf("outcome = %+v (err %v), want a natural end", outcome, err)
	}
	if want := "Relay session ended: client never connected"; outcome.result.Message != want {
		t.Errorf("message = %q, want %q", outcome.result.Message, want)
	}
}
