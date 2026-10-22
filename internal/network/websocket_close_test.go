package network

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/netdefense-io/ndagent/internal/testbroker"
)

// The close frame of a graceful shutdown goes out while the heartbeat may still
// be writing on the same connection. gorilla/websocket allows one writer at a
// time, except for WriteControl and Close; run with -race.
func TestCloseCleanWhileAHeartbeatWrites(t *testing.T) {
	closeCode := make(chan int, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		c, err := (&websocket.Upgrader{}).Upgrade(rw, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				var ce *websocket.CloseError
				if errors.As(err, &ce) {
					closeCode <- ce.Code
				} else {
					closeCode <- -1
				}
				return
			}
		}
	}))
	defer srv.Close()

	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	w := &WebSocketClient{conn: conn}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = w.SendJSON(map[string]string{"type": "heartbeat"})
			}
		}
	}()

	time.Sleep(20 * time.Millisecond)
	closeClean(conn)
	close(stop)
	wg.Wait()

	select {
	case code := <-closeCode:
		if code != websocket.CloseNormalClosure {
			t.Errorf("the server read close code %d, want %d", code, websocket.CloseNormalClosure)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the server never saw the connection end")
	}
}

// A write stuck on a peer that stopped reading holds w.mu with no deadline. A
// graceful shutdown must not wait for it: the close frame gives up after
// closeFrameWait, and closing the connection ends the stuck write.
func TestShutdownIsNotHeldByAWriteStuckOnAPeerThatStoppedReading(t *testing.T) {
	prevWait := closeFrameWait
	closeFrameWait = 200 * time.Millisecond
	t.Cleanup(func() { closeFrameWait = prevWait })

	// A broker that authenticates the agent and then reads nothing more.
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		c, err := (&websocket.Upgrader{}).Upgrade(rw, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		if _, _, err := c.ReadMessage(); err != nil {
			return
		}
		if err := c.WriteJSON(map[string]string{"status": "authenticated"}); err != nil {
			return
		}
		<-release
	}))
	t.Cleanup(srv.Close)

	w, _ := newDrainClient(t, testbroker.New(t))
	w.cfg.ServerURIWS = "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	cancel, wait := connectOnce(t, w)
	// Registered after connectOnce so it runs before its cleanup: the peer then
	// closes, which ends a write a failing shutdown left stuck.
	t.Cleanup(func() { close(release) })

	deadline := time.Now().Add(5 * time.Second)
	for {
		w.mu.Lock()
		authenticated := w.authenticated
		w.mu.Unlock()
		if authenticated {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the agent did not authenticate")
		}
		time.Sleep(10 * time.Millisecond)
	}

	stuck := make(chan error, 1)
	go func() {
		stuck <- w.SendJSON(map[string]string{"type": "task_response", "pad": strings.Repeat("x", 32<<20)})
	}()
	select {
	case err := <-stuck:
		t.Fatalf("the write did not block (%v), so the test shows nothing", err)
	case <-time.After(300 * time.Millisecond):
	}

	start := time.Now()
	cancel()
	done := make(chan struct{})
	go func() {
		wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the shutdown waited for the stuck write")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("the shutdown took %v", elapsed)
	}
	select {
	case err := <-stuck:
		if err == nil {
			t.Error("the stuck write reported success")
		}
	case <-time.After(time.Second):
		t.Fatal("the stuck write never ended")
	}
}
