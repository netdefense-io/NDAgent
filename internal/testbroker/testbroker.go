// Package testbroker is a fake NDBroker WebSocket endpoint for tests. It
// accepts every connection, answers the authentication frame, records what the
// agent sends afterwards and can drop the connection. Only tests import it.
package testbroker

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/veraison/go-cose"

	"github.com/netdefense-io/ndagent/internal/signing"
)

// TaskResponse is a task_response frame with its signed envelope opened. The
// envelope's signature is not checked: tests care what the agent said, and the
// signing package has its own tests.
type TaskResponse struct {
	TaskID  int64
	Status  string
	Message string
}

// Broker is the fake endpoint. It also plays NDManager: it holds the key that
// signs dispatches, and NDMKeys is what the agent must be told to trust.
type Broker struct {
	t   testing.TB
	srv *httptest.Server

	ndmPub  ed25519.PublicKey
	ndmPriv ed25519.PrivateKey
	kid     []byte

	mu          sync.Mutex
	conn        *websocket.Conn
	connections int
	auths       []json.RawMessage
	heartbeats  []json.RawMessage
	responses   []TaskResponse
}

// New starts a broker that stops with the test.
func New(t testing.TB) *Broker {
	t.Helper()
	pub, priv, err := signing.GenerateKeypair()
	if err != nil {
		t.Fatalf("generate the NDManager key: %v", err)
	}
	b := &Broker{t: t, ndmPub: pub, ndmPriv: priv, kid: signing.KidFromPubkey(pub)}
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		b.serve(conn)
	}))
	t.Cleanup(func() {
		b.Drop()
		b.srv.Close()
	})
	return b
}

// URL is the ws:// address to give the agent.
func (b *Broker) URL() string {
	return "ws" + strings.TrimPrefix(b.srv.URL, "http") + "/ws"
}

func (b *Broker) serve(conn *websocket.Conn) {
	defer conn.Close()
	_, auth, err := conn.ReadMessage() // the authentication frame
	if err != nil {
		return
	}
	if err := conn.WriteJSON(map[string]string{"status": "authenticated"}); err != nil {
		return
	}
	b.mu.Lock()
	b.conn = conn
	b.connections++
	b.auths = append(b.auths, auth)
	b.mu.Unlock()

	for {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var frame struct {
			Type     string `json:"type"`
			TaskID   int64  `json:"task_id"`
			Envelope string `json:"envelope"`
		}
		if json.Unmarshal(raw, &frame) != nil {
			continue
		}
		b.mu.Lock()
		switch frame.Type {
		case "heartbeat":
			b.heartbeats = append(b.heartbeats, raw)
		case "task_response":
			b.responses = append(b.responses, b.open(frame.TaskID, frame.Envelope))
		}
		b.mu.Unlock()
	}
}

func (b *Broker) open(taskID int64, envelope string) TaskResponse {
	b.t.Helper()
	tr := TaskResponse{TaskID: taskID}
	raw, err := base64.StdEncoding.DecodeString(envelope)
	if err != nil {
		b.t.Errorf("task_response envelope is not base64: %v", err)
		return tr
	}
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(raw); err != nil {
		b.t.Errorf("task_response envelope is not COSE_Sign1: %v", err)
		return tr
	}
	var inner struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(msg.Payload, &inner); err != nil {
		b.t.Errorf("task_response payload is not JSON: %v", err)
		return tr
	}
	tr.Status, tr.Message = inner.Status, inner.Message
	return tr
}

// Drop closes the current connection, as a network failure would.
func (b *Broker) Drop() {
	b.mu.Lock()
	conn := b.conn
	b.conn = nil
	b.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
}

// Connections is how many connections have authenticated so far.
func (b *Broker) Connections() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.connections
}

// Heartbeats is how many heartbeat frames have arrived.
func (b *Broker) Heartbeats() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.heartbeats)
}

// AuthFrames returns the authentication frame of every connection, as sent,
// in arrival order.
func (b *Broker) AuthFrames() []json.RawMessage {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]json.RawMessage(nil), b.auths...)
}

// HeartbeatFrames returns every heartbeat frame received, as sent, in arrival
// order.
func (b *Broker) HeartbeatFrames() []json.RawMessage {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]json.RawMessage(nil), b.heartbeats...)
}

// TaskResponses returns every task_response received, in arrival order.
func (b *Broker) TaskResponses() []TaskResponse {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]TaskResponse(nil), b.responses...)
}

// WaitFor polls cond until it holds or the timeout passes.
func (b *Broker) WaitFor(what string, timeout time.Duration, cond func() bool) {
	b.t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			b.t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// WaitForHeartbeats waits until at least n heartbeats arrived. The agent sends
// its first heartbeat as soon as its command loop starts, which is after the
// connect-time drain has finished, so a heartbeat means the drain is over.
func (b *Broker) WaitForHeartbeats(n int, timeout time.Duration) {
	b.t.Helper()
	b.WaitFor("heartbeat(s)", timeout, func() bool { return b.Heartbeats() >= n })
}

// NDMKeys is the dispatch key table an agent needs to accept what Dispatch
// signs: hex(kid) to public key, as NewWebSocketClient takes it.
func (b *Broker) NDMKeys() map[string]ed25519.PublicKey {
	return map[string]ed25519.PublicKey{hex.EncodeToString(b.kid): b.ndmPub}
}

// Dispatch is one signed command for the agent.
type Dispatch struct {
	DeviceUUID string
	TaskID     int64
	// Seq is the per-device dispatch sequence; it must increase from one
	// dispatch to the next or the agent rejects the command as a replay.
	Seq      uint64
	TaskType string
	Payload  map[string]interface{}
	// Exp is the signed expiry, which for a real task is Tasks.expires_at.
	Exp time.Time
}

// Dispatch sends a command signed with the fake NDManager key over the current
// connection.
func (b *Broker) Dispatch(d Dispatch) error {
	payload, err := json.Marshal(d.Payload)
	if err != nil {
		return err
	}
	signer, err := cose.NewSigner(cose.AlgorithmEd25519, b.ndmPriv)
	if err != nil {
		return err
	}
	msg := cose.Sign1Message{
		Headers: cose.Headers{Protected: cose.ProtectedHeader{
			cose.HeaderLabelAlgorithm: cose.AlgorithmEd25519,
			cose.HeaderLabelKeyID:     b.kid,
			signing.HdrIss:            "ndmanager",
			signing.HdrIat:            time.Now().Unix(),
			signing.HdrTaskID:         d.TaskID,
			signing.HdrDeviceUUID:     d.DeviceUUID,
			signing.HdrVersion:        int64(signing.EnvelopeVersion),
			signing.HdrTaskType:       d.TaskType,
			signing.HdrExp:            d.Exp.Unix(),
			signing.HdrDispatchSeq:    int64(d.Seq),
		}},
		Payload: payload,
	}
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		return err
	}
	encoded, err := msg.MarshalCBOR()
	if err != nil {
		return err
	}

	b.mu.Lock()
	conn := b.conn
	b.mu.Unlock()
	if conn == nil {
		return errNoConnection
	}
	return conn.WriteJSON(map[string]interface{}{
		"type":      "task",
		"task_id":   d.TaskID,
		"task_type": d.TaskType,
		"envelope":  base64.StdEncoding.EncodeToString(encoded),
	})
}

var errNoConnection = &noConnectionError{}

type noConnectionError struct{}

func (*noConnectionError) Error() string { return "testbroker: no authenticated connection" }
