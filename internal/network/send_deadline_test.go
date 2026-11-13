package network

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/netdefense-io/ndagent/internal/config"
)

// SendJSON sends exactly what gorilla's WriteJSON would.
func TestSendJSON_SendsWhatWriteJSONWould(t *testing.T) {
	got := make(chan []byte, 1)
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(rw, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_, msg, _ := conn.ReadMessage()
		got <- msg
	}))
	t.Cleanup(server.Close)
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	w := NewWebSocketClient(&config.Config{}, nil, nil, nil, nil)
	w.conn = conn
	v := map[string]interface{}{"type": "heartbeat", "html": "<a&b>", "n": 1}
	if err := w.SendJSON(v); err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(v)
	if msg := <-got; string(msg) != string(want)+"\n" {
		t.Errorf("sent %q, want %q", msg, string(want)+"\n")
	}
}

// A peer that stops reading must not hold SendJSON, and the connection's lock,
// past the write's deadline; the connection is then unusable for writes.
func TestSendJSON_AWriteToAPeerThatDoesNotReadEndsAtTheDeadline(t *testing.T) {
	stop := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(rw, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		<-stop
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(stop) })

	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	prevFloor, prevRate := sendWriteFloor, sendWriteMinRate
	sendWriteFloor, sendWriteMinRate = 200*time.Millisecond, 1<<40
	t.Cleanup(func() { sendWriteFloor, sendWriteMinRate = prevFloor, prevRate })

	w := NewWebSocketClient(&config.Config{}, nil, nil, nil, nil)
	w.conn = conn
	done := make(chan error, 1)
	go func() { done <- w.SendJSON(map[string]string{"x": strings.Repeat("a", 32<<20)}) }()
	select {
	case err = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the write to a peer that never reads did not end at its deadline")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("err = %v, want a timeout", err)
	}
	if err := w.SendJSON(map[string]string{"x": "small"}); err == nil {
		t.Error("a write after the timed-out one must fail, so the heartbeat reconnects")
	}
}

func TestSendWriteTimeout_GivesAFullFrameTimeOnASlowLink(t *testing.T) {
	// 64 kbit/s is 8 KiB/s: a 1 MiB frame needs 128 s on the wire.
	if got := sendWriteTimeout(MaxTaskResponseFrame); got < 128*time.Second {
		t.Errorf("a full frame gets %s", got)
	}
	if got := sendWriteTimeout(200); got < sendWriteFloor || got > sendWriteFloor+time.Second {
		t.Errorf("a heartbeat gets %s, want about the floor %s", got, sendWriteFloor)
	}
}
