package network

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
	"go.uber.org/zap/zapcore"

	"github.com/netdefense-io/ndagent/internal/config"
	"github.com/netdefense-io/ndagent/internal/signing"
	"github.com/netdefense-io/ndagent/internal/status"
)

// authRoundTrip connects a client to a fake broker that records the auth
// frame and answers with reply. It returns the recorded frame, the status file
// the client wrote, and the authenticate error.
func authRoundTrip(t *testing.T, privB64 string, reply string) (map[string]any, map[string]any, error) {
	t.Helper()
	frames := make(chan map[string]any, 1)
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(rw, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		_, raw, err := c.ReadMessage()
		if err != nil {
			return
		}
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		frames <- m
		_ = c.WriteMessage(websocket.TextMessage, []byte(reply))
	}))
	defer srv.Close()

	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	statusPath := filepath.Join(t.TempDir(), "ndagent.status")
	cfg := &config.Config{
		Token:         "token-uuid",
		DeviceUUID:    "device-uuid",
		DevicePrivKey: privB64,
		ConfigXMLPath: filepath.Join(t.TempDir(), "absent.xml"),
	}
	w := NewWebSocketClient(cfg, nil, nil, nil, map[string]ed25519.PublicKey{})
	w.conn = conn
	w.statusWriter = status.NewWriter(statusPath, "1.0.0", "abc", "device-uuid")

	authErr := w.authenticate(context.Background())

	var sent map[string]any
	select {
	case sent = <-frames:
	default:
	}
	var snap map[string]any
	if raw, err := os.ReadFile(statusPath); err == nil {
		_ = json.Unmarshal(raw, &snap)
	}
	return sent, snap, authErr
}

func newKey(t *testing.T) (string, string) {
	t.Helper()
	pub, priv, err := signing.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(pub)
	return base64.StdEncoding.EncodeToString(priv.Seed()), hex.EncodeToString(sum[:16])
}

func TestAuthSendsDeviceKid(t *testing.T) {
	priv, wantKid := newKey(t)
	sent, snap, err := authRoundTrip(t, priv, `{"status":"authenticated"}`)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if sent["device_kid"] != wantKid || len(wantKid) != 32 {
		t.Fatalf("device_kid = %v, want %s", sent["device_kid"], wantKid)
	}
	if _, ok := snap["key_state"]; ok {
		t.Fatalf("key_state written without a mismatch: %v", snap)
	}
}

func TestAuthOmitsKidWithoutKey(t *testing.T) {
	sent, _, err := authRoundTrip(t, "", `{"status":"authenticated"}`)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if _, ok := sent["device_kid"]; ok {
		t.Fatalf("device_kid sent without a key: %v", sent)
	}
}

func TestAuthMismatchIsRecordedAndSessionContinues(t *testing.T) {
	priv, _ := newKey(t)
	const msg = "device key changed - rebind required: ndcli device rebind-token bt007"
	reply, _ := json.Marshal(map[string]string{"status": "authenticated", "key_state": "mismatch", "message": msg})
	_, snap, err := authRoundTrip(t, priv, string(reply))
	if err != nil {
		t.Fatalf("a mismatch must not fail auth: %v", err)
	}
	if snap["key_state"] != "mismatch" || snap["key_message"] != msg {
		t.Fatalf("status file = %v", snap)
	}
}

func TestAuthKeyStateOkAndOldBrokerLeaveNoState(t *testing.T) {
	priv, _ := newKey(t)
	for _, reply := range []string{
		`{"status":"authenticated","key_state":"ok"}`,
		`{"status":"authenticated"}`,
	} {
		_, snap, err := authRoundTrip(t, priv, reply)
		if err != nil {
			t.Fatalf("authenticate(%s): %v", reply, err)
		}
		if _, ok := snap["key_state"]; ok {
			t.Fatalf("reply %s left key_state in %v", reply, snap)
		}
	}
}

func TestStatusKeyStateClearsOnLaterOk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s")
	sw := status.NewWriter(path, "1", "c", "d")
	_ = sw.SetKeyState("mismatch", "m")
	_ = sw.SetKeyState("", "")
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "key_state") || strings.Contains(string(raw), "key_message") {
		t.Fatalf("not cleared: %s", raw)
	}
}

func TestAuthToleratesNonStringKeyFields(t *testing.T) {
	priv, _ := newKey(t)
	for _, reply := range []string{
		`{"status":"authenticated","key_state":{"x":1},"message":["a"]}`,
		`{"status":"authenticated","key_state":5,"message":7}`,
		`{"status":"authenticated","key_state":null,"message":null}`,
	} {
		_, snap, err := authRoundTrip(t, priv, reply)
		if err != nil {
			t.Fatalf("reply %s failed auth: %v", reply, err)
		}
		if _, ok := snap["key_state"]; ok {
			t.Fatalf("reply %s recorded a state: %v", reply, snap)
		}
	}
}

func TestRejectedAuthClearsStaleKeyState(t *testing.T) {
	priv, _ := newKey(t)
	path := filepath.Join(t.TempDir(), "s")
	sw := status.NewWriter(path, "1", "c", "d")
	_ = sw.SetKeyState("mismatch", "m")
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		c, err := (&websocket.Upgrader{}).Upgrade(rw, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		_, _, _ = c.ReadMessage()
		_ = c.WriteMessage(websocket.TextMessage, []byte(`{"status":"error","error":"nope"}`))
	}))
	defer srv.Close()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cfg := &config.Config{Token: "t", DeviceUUID: "d", DevicePrivKey: priv,
		ConfigXMLPath: filepath.Join(t.TempDir(), "absent.xml")}
	w := NewWebSocketClient(cfg, nil, nil, nil, map[string]ed25519.PublicKey{})
	w.conn = conn
	w.statusWriter = sw
	if err := w.authenticate(context.Background()); err == nil {
		t.Fatal("rejected auth returned nil")
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "key_state") {
		t.Fatalf("stale state survived: %s", raw)
	}
}

func TestMismatchLogsErrorWithoutKeyMaterial(t *testing.T) {
	logs := captureLogs(t)
	priv, _ := newKey(t)
	reply := `{"status":"authenticated","key_state":"mismatch","message":"device key changed - rebind required: ndcli device rebind-token bt007"}`
	if _, _, err := authRoundTrip(t, priv, reply); err != nil {
		t.Fatal(err)
	}
	errs := logs.FilterLevelExact(zapcore.ErrorLevel).All()
	if len(errs) != 1 || !strings.Contains(errs[0].Message, "does not match") {
		t.Fatalf("want one mismatch ERROR, got %v", errs)
	}
	seed, _ := base64.StdEncoding.DecodeString(priv)
	for _, e := range logs.All() {
		out := e.Message + " " + fmt.Sprint(e.ContextMap())
		if strings.Contains(out, priv) || strings.Contains(out, hex.EncodeToString(seed)) {
			t.Fatalf("private key material logged: %s", out)
		}
	}
}
