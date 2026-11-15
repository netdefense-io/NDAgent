package tasks

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/netdefense-io/ndagent/internal/config"
	"github.com/netdefense-io/ndagent/internal/directpeer"
	"github.com/netdefense-io/ndagent/internal/network"
	"github.com/netdefense-io/ndagent/internal/state"
	"github.com/netdefense-io/ndagent/internal/taskstore"
	"github.com/netdefense-io/ndagent/internal/testbroker"
)

const connectVectorFile = "../directpeer/testdata/contract/connect-direct-peer-v1.json"

// connectVector is the part of the shared vector the CONNECT handler is held
// to: the payloads as the control plane signs them.
type connectVector struct {
	DeviceKey struct {
		SeedB64 string `json:"ed25519_seed_b64"`
	} `json:"device_key"`
	SessionKeys struct {
		SeedHex string `json:"seed_hex"`
	} `json:"session_keys"`
	Payloads struct {
		Open           map[string]interface{} `json:"open"`
		Close          map[string]interface{} `json:"close"`
		Legacy         map[string]interface{} `json:"legacy"`
		LegacyFallback map[string]interface{} `json:"legacy_in_a_direct_peer_organization"`
	} `json:"payloads"`
}

func loadConnectVector(t *testing.T) connectVector {
	t.Helper()
	data, err := os.ReadFile(connectVectorFile)
	if err != nil {
		t.Fatal(err)
	}
	var v connectVector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Payloads.Open) != 10 || len(v.Payloads.Close) != 3 {
		t.Fatalf("the vector's payloads have %d and %d keys, want 10 and 3", len(v.Payloads.Open), len(v.Payloads.Close))
	}
	return v
}

// vectorOpen is a fresh copy of the vector's open payload, as the dispatcher
// hands it over: through JSON.
func vectorOpen(t *testing.T) map[string]interface{} {
	t.Helper()
	raw, err := json.Marshal(loadConnectVector(t).Payloads.Open)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestConnectPayloadKind(t *testing.T) {
	v := loadConnectVector(t)
	cases := []struct {
		name    string
		payload map[string]interface{}
		want    connectKind
	}{
		{"the vector's open", v.Payloads.Open, connectOpen},
		{"the vector's close", v.Payloads.Close, connectClose},
		{"the vector's websocket-relay task", v.Payloads.Legacy, connectRelay},
		{"the vector's websocket-relay task of a direct-peer organization", v.Payloads.LegacyFallback, connectRelay},
		{"no payload", nil, connectRelay},
		{"an empty payload", map[string]interface{}{}, connectRelay},
		{"the websocket relay named, with an action", map[string]interface{}{"transport": "relay-legacy", "action": "open"}, connectRelay},
		{"an action without a transport", map[string]interface{}{"action": "open", "pathfinder_session": "x"}, connectRelay},

		{"a null transport", map[string]interface{}{"transport": nil, "pathfinder_session": "x"}, connectUnknown},
		{"an unknown transport", map[string]interface{}{"transport": "quic", "pathfinder_session": "x"}, connectUnknown},
		{"an empty transport", map[string]interface{}{"transport": ""}, connectUnknown},
		{"a transport in another case", map[string]interface{}{"transport": "Direct-Peer", "action": "open"}, connectUnknown},
		{"a transport that is a number", map[string]interface{}{"transport": 1.0}, connectUnknown},
		{"a transport that is a list", map[string]interface{}{"transport": []interface{}{"direct-peer"}, "action": "open"}, connectUnknown},
		{"direct-peer without an action", map[string]interface{}{"transport": "direct-peer"}, connectUnknown},
		{"direct-peer with a null action", map[string]interface{}{"transport": "direct-peer", "action": nil}, connectUnknown},
		{"direct-peer with an unknown action", map[string]interface{}{"transport": "direct-peer", "action": "extend"}, connectUnknown},
		{"direct-peer with an action in another case", map[string]interface{}{"transport": "direct-peer", "action": "Open"}, connectUnknown},
	}
	for _, c := range cases {
		if got := connectPayloadKind(c.payload); got != c.want {
			t.Errorf("%s: kind %d, want %d", c.name, got, c.want)
		}
	}
}

func TestParseDirectPeerOpenReadsTheVector(t *testing.T) {
	got, ok := parseDirectPeerOpen(vectorOpen(t))
	if !ok {
		t.Fatal("the vector's open payload is refused")
	}
	want := directPeerOpen{
		connectID:   "eff97f3e3ad593d08e250b5a5e492449",
		protocol:    1,
		relay:       directpeer.Relay{ID: "eu", Host: "relay-eu.example.net", Port: 443, STUNPort: 3478},
		sealed:      got.sealed,
		admitServer: "00db23a1e87fd7c43931d68a2f78ff1b2fff8de909ac5edaaf52d8011562a079",
		admitClient: "cbd9804be55d87ff82584ed23a0bf513ca7ce4ac61eccfe2d85b66ef9cd5882d",
		pair:        300, idle: 1800, max: 28800, device: 4,
		readOnly: false,
	}
	if !reflect.DeepEqual(got, want) || !strings.HasPrefix(got.sealed, "3D535VEbdYH9NInF") {
		t.Fatalf("parsed %+v\nwant   %+v", got, want)
	}

	// A key this agent does not know is passed over.
	withMore := vectorOpen(t)
	withMore["region"] = "eu-west"
	withMore["relay"].(map[string]interface{})["label"] = "Europe"
	if _, ok := parseDirectPeerOpen(withMore); !ok {
		t.Fatal("an unknown key refused the payload")
	}
	ro := vectorOpen(t)
	ro["read_only"] = true
	if got, ok := parseDirectPeerOpen(ro); !ok || !got.readOnly {
		t.Fatalf("read_only true: %+v, %v", got, ok)
	}
}

// Nothing in an open payload is defaulted. read_only above all: a value that
// is not a boolean must never read as false, which is the full session.
func TestParseDirectPeerOpenDefaultsNothing(t *testing.T) {
	sub := func(m map[string]interface{}, key string) map[string]interface{} {
		return m[key].(map[string]interface{})
	}
	cases := map[string]func(m map[string]interface{}){
		"no read_only":              func(m map[string]interface{}) { delete(m, "read_only") },
		"read_only as text":         func(m map[string]interface{}) { m["read_only"] = "true" },
		"read_only as text false":   func(m map[string]interface{}) { m["read_only"] = "false" },
		"read_only as a number":     func(m map[string]interface{}) { m["read_only"] = 1.0 },
		"read_only null":            func(m map[string]interface{}) { m["read_only"] = nil },
		"no connect_id":             func(m map[string]interface{}) { delete(m, "connect_id") },
		"connect_id in upper case":  func(m map[string]interface{}) { m["connect_id"] = "EFF97F3E3AD593D08E250B5A5E492449" },
		"connect_id too short":      func(m map[string]interface{}) { m["connect_id"] = "eff97f3e" },
		"connect_id as a number":    func(m map[string]interface{}) { m["connect_id"] = 7.0 },
		"no protocol":               func(m map[string]interface{}) { delete(m, "protocol") },
		"protocol 0":                func(m map[string]interface{}) { m["protocol"] = 0.0 },
		"protocol 1.5":              func(m map[string]interface{}) { m["protocol"] = 1.5 },
		"protocol as text":          func(m map[string]interface{}) { m["protocol"] = "1" },
		"protocol beyond 65535":     func(m map[string]interface{}) { m["protocol"] = 65536.0 },
		"no relay":                  func(m map[string]interface{}) { delete(m, "relay") },
		"relay as text":             func(m map[string]interface{}) { m["relay"] = "eu" },
		"no relay id":               func(m map[string]interface{}) { delete(sub(m, "relay"), "id") },
		"relay id in upper case":    func(m map[string]interface{}) { sub(m, "relay")["id"] = "EU" },
		"relay id with a slash":     func(m map[string]interface{}) { sub(m, "relay")["id"] = "eu/../x" },
		"no relay hostname":         func(m map[string]interface{}) { delete(sub(m, "relay"), "hostname") },
		"relay hostname empty":      func(m map[string]interface{}) { sub(m, "relay")["hostname"] = "" },
		"relay hostname upper case": func(m map[string]interface{}) { sub(m, "relay")["hostname"] = "Relay-EU.example.net" },
		"relay hostname with port":  func(m map[string]interface{}) { sub(m, "relay")["hostname"] = "relay-eu.example.net:443" },
		"relay hostname with path":  func(m map[string]interface{}) { sub(m, "relay")["hostname"] = "relay-eu.example.net/x" },
		"relay hostname a URL":      func(m map[string]interface{}) { sub(m, "relay")["hostname"] = "https://relay-eu.example.net" },
		"relay hostname one label":  func(m map[string]interface{}) { sub(m, "relay")["hostname"] = "localhost" },
		"relay hostname with space": func(m map[string]interface{}) { sub(m, "relay")["hostname"] = "relay eu.example.net" },
		"relay hostname too long":   func(m map[string]interface{}) { sub(m, "relay")["hostname"] = strings.Repeat("a.", 127) + "net" },
		"no relay port":             func(m map[string]interface{}) { delete(sub(m, "relay"), "derp_port") },
		"relay port 0":              func(m map[string]interface{}) { sub(m, "relay")["derp_port"] = 0.0 },
		"relay port as text":        func(m map[string]interface{}) { sub(m, "relay")["derp_port"] = "443" },
		"relay port 443.5":          func(m map[string]interface{}) { sub(m, "relay")["derp_port"] = 443.5 },
		"relay port beyond 65535":   func(m map[string]interface{}) { sub(m, "relay")["derp_port"] = 65536.0 },
		"no STUN port":              func(m map[string]interface{}) { delete(sub(m, "relay"), "stun_port") },
		"STUN port negative":        func(m map[string]interface{}) { sub(m, "relay")["stun_port"] = -1.0 },
		"no sealed":                 func(m map[string]interface{}) { delete(m, "sealed") },
		"sealed empty":              func(m map[string]interface{}) { m["sealed"] = "" },
		"sealed as a list":          func(m map[string]interface{}) { m["sealed"] = []interface{}{"x"} },
		"no admit_keys":             func(m map[string]interface{}) { delete(m, "admit_keys") },
		"no server key":             func(m map[string]interface{}) { delete(sub(m, "admit_keys"), "server") },
		"server key in upper case": func(m map[string]interface{}) {
			sub(m, "admit_keys")["server"] = strings.ToUpper(sub(m, "admit_keys")["server"].(string))
		},
		"client key with a prefix": func(m map[string]interface{}) {
			sub(m, "admit_keys")["client"] = "nodekey:" + sub(m, "admit_keys")["client"].(string)
		},
		"client key too short":     func(m map[string]interface{}) { sub(m, "admit_keys")["client"] = "cbd9" },
		"no limits":                func(m map[string]interface{}) { delete(m, "limits") },
		"no max_seconds":           func(m map[string]interface{}) { delete(sub(m, "limits"), "max_seconds") },
		"max_seconds 0":            func(m map[string]interface{}) { sub(m, "limits")["max_seconds"] = 0.0 },
		"idle_seconds negative":    func(m map[string]interface{}) { sub(m, "limits")["idle_seconds"] = -1800.0 },
		"pair_seconds as text":     func(m map[string]interface{}) { sub(m, "limits")["pair_seconds"] = "300" },
		"pair_seconds a fraction":  func(m map[string]interface{}) { sub(m, "limits")["pair_seconds"] = 0.5 },
		"device_sessions 0":        func(m map[string]interface{}) { sub(m, "limits")["device_sessions"] = 0.0 },
		"no device_sessions":       func(m map[string]interface{}) { delete(sub(m, "limits"), "device_sessions") },
		"max_seconds beyond range": func(m map[string]interface{}) { sub(m, "limits")["max_seconds"] = 1e18 },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			m := vectorOpen(t)
			change(m)
			if got, ok := parseDirectPeerOpen(m); ok {
				t.Fatalf("accepted: %+v", got)
			}
		})
	}
}

// directPeerRig is an agent connected to a fake broker, with a task store,
// the vector's device identity and a manager of direct-peer sessions whose
// companion is not installed: everything up to starting one runs for real.
type directPeerRig struct {
	t      *testing.T
	broker *testbroker.Broker
	ws     *network.WebSocketClient
	store  *taskstore.Store
	device ed25519.PrivateKey
	uuid   string
	seq    uint64
}

const rigDeviceUUID = "3f2b8c1e-6a4d-4e0b-9c57-d1a2b3c4e5f6"

func newDirectPeerRig(t *testing.T, policy config.RemoteAccessPolicy, withManager bool) *directPeerRig {
	t.Helper()
	v := loadConnectVector(t)
	seed, err := base64.StdEncoding.DecodeString(v.DeviceKey.SeedB64)
	if err != nil {
		t.Fatal(err)
	}
	b := testbroker.New(t)
	store, err := taskstore.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	stateStore, err := state.New(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	ws := network.NewWebSocketClient(&config.Config{
		ServerURIWS:        b.URL(),
		DeviceUUID:         rigDeviceUUID,
		Token:              "00000000-0000-4000-8000-000000000000",
		DevicePrivKey:      v.DeviceKey.SeedB64,
		RemoteAccessPolicy: policy,
	}, stateStore, store, LifecycleFor, b.NDMKeys())
	RegisterHandlers(ws)

	prev := directPeerManager.Load()
	t.Cleanup(func() { directPeerManager.Store(prev) })
	directPeerManager.Store(nil)
	if withManager {
		ledger, err := directpeer.OpenLedger(filepath.Join(t.TempDir(), "sessions.json"), nil)
		if err != nil {
			t.Fatal(err)
		}
		starter := directpeer.NewStarter("0.0.0-test")
		starter.Path = filepath.Join(t.TempDir(), "ndagent-connect")
		m := directpeer.NewManager(starter, ledger, rigDeviceUUID)
		m.SetReporter(ws)
		t.Cleanup(func() { m.Shutdown(5 * time.Second) })
		SetDirectPeerManager(m)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = ws.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	b.WaitForHeartbeats(1, 5*time.Second)
	return &directPeerRig{t: t, broker: b, ws: ws, store: store, device: ed25519.NewKeyFromSeed(seed), uuid: rigDeviceUUID}
}

// dispatch sends a signed CONNECT and returns the one answer the agent gives
// that task after it.
func (r *directPeerRig) dispatch(taskID int64, exp time.Time, payload map[string]interface{}) (testbroker.TaskResponse, map[string]interface{}) {
	r.t.Helper()
	before := len(r.broker.TaskResponses())
	r.seq++
	if err := r.broker.Dispatch(testbroker.Dispatch{
		DeviceUUID: r.uuid, TaskID: taskID, Seq: r.seq, TaskType: network.TaskTypeConnect, Payload: payload, Exp: exp,
	}); err != nil {
		r.t.Fatal(err)
	}
	terminal := func() []testbroker.TaskResponse {
		var out []testbroker.TaskResponse
		for _, resp := range r.broker.TaskResponses()[before:] {
			if resp.TaskID == taskID && resp.Status != network.TaskStatusInProgress {
				out = append(out, resp)
			}
		}
		return out
	}
	r.broker.WaitFor("the task's answer", 10*time.Second, func() bool { return len(terminal()) >= 1 })
	time.Sleep(100 * time.Millisecond)
	got := terminal()
	if len(got) != 1 {
		r.t.Fatalf("%d answers, want 1: %+v", len(got), got)
	}
	var connect map[string]interface{}
	if raw, ok := got[0].Inner["connect"]; ok {
		if err := json.Unmarshal(raw, &connect); err != nil {
			r.t.Fatal(err)
		}
	}
	return got[0], connect
}

// sealedOpen is the vector's open payload sealed again for exp, which the
// vector's own expiry no longer is: a task that has expired is not dispatched.
func (r *directPeerRig) sealedOpen(exp time.Time, change func(plaintext map[string]interface{})) map[string]interface{} {
	r.t.Helper()
	v := loadConnectVector(r.t)
	payload := vectorOpen(r.t)
	seed, _ := hex.DecodeString(v.SessionKeys.SeedHex)
	clientKey, _ := hex.DecodeString(payload["admit_keys"].(map[string]interface{})["client"].(string))
	plaintext := map[string]interface{}{
		"v":           uint64(1),
		"seed":        seed,
		"connect_id":  payload["connect_id"],
		"device_uuid": r.uuid,
		"client_key":  clientKey,
		"relay":       map[string]interface{}{"hostname": "relay-eu.example.net", "derp_port": uint64(443), "stun_port": uint64(3478)},
		"exp":         uint64(exp.Unix()),
	}
	if change != nil {
		change(plaintext)
	}
	raw, err := cbor.Marshal(plaintext)
	if err != nil {
		r.t.Fatal(err)
	}
	digest := sha512.Sum512(r.device.Seed())
	private, err := ecdh.X25519().NewPrivateKey(digest[:32])
	if err != nil {
		r.t.Fatal(err)
	}
	public, err := hpke.DHKEM(ecdh.X25519()).NewPublicKey(private.PublicKey().Bytes())
	if err != nil {
		r.t.Fatal(err)
	}
	sealed, err := hpke.Seal(public, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), []byte("netdefense-connect-v1"), raw)
	if err != nil {
		r.t.Fatal(err)
	}
	payload["sealed"] = base64.StdEncoding.EncodeToString(sealed)
	return payload
}

const vectorID = "eff97f3e3ad593d08e250b5a5e492449"

// A task that names a transport or an action this agent does not know opens
// nothing and never takes the websocket relay's path: it would dial a relay
// nobody asked for.
func TestHandleConnectFailsClosedOnAnUnknownTransport(t *testing.T) {
	r := newDirectPeerRig(t, config.RemoteAccessFull, true)
	exp := time.Now().Add(time.Minute)
	cases := []struct {
		name    string
		payload map[string]interface{}
		connect bool
	}{
		{"a null transport on a websocket-relay task", map[string]interface{}{"transport": nil, "pathfinder_session": "550e8400-e29b-41d4-a716-446655440000", "read_only": false}, false},
		{"an unknown transport", map[string]interface{}{"transport": "quic", "pathfinder_session": "550e8400-e29b-41d4-a716-446655440000"}, false},
		{"an unknown action, with a session id", map[string]interface{}{"transport": "direct-peer", "action": "extend", "connect_id": vectorID}, true},
		{"an unknown action, with a session id that is not one", map[string]interface{}{"transport": "direct-peer", "action": "extend", "connect_id": "../x"}, false},
		{"a close without a session id", map[string]interface{}{"transport": "direct-peer", "action": "close"}, false},
	}
	for i, c := range cases {
		resp, connect := r.dispatch(int64(1000+i), exp, c.payload)
		if resp.Status != "FAILED" || resp.Message != "Remote session refused: the request is not one this agent can read" {
			t.Errorf("%s: %s %q", c.name, resp.Status, resp.Message)
		}
		if c.connect {
			want := map[string]interface{}{"event": "failed", "connect_id": vectorID, "reason": "unsupported_action"}
			if !reflect.DeepEqual(connect, want) {
				t.Errorf("%s: connect %v, want %v", c.name, connect, want)
			}
		} else if connect != nil {
			t.Errorf("%s: connect %v, want none", c.name, connect)
		}
		if strings.Contains(resp.Message, "relay") || strings.Contains(resp.Message, "pathfinder_session") {
			t.Errorf("%s: the answer is the websocket relay's: %q", c.name, resp.Message)
		}
	}
}

// The websocket relay's task is untouched, also with the two keys it gains
// in an organization set to direct-peer: under a policy that allows nothing
// it gets the refusal it always got, word for word.
func TestHandleConnectTheWebsocketRelayTaskIsUnchanged(t *testing.T) {
	v := loadConnectVector(t)
	r := newDirectPeerRig(t, config.RemoteAccessDisabled, true)
	want := "remote access refused by local policy remote_access_policy=disabled; " +
		"change it on the device under Services → NetDefense → Settings " +
		"(Remote Access Policy) — it cannot be changed remotely"
	for i, payload := range []map[string]interface{}{v.Payloads.Legacy, v.Payloads.LegacyFallback} {
		resp, connect := r.dispatch(int64(1100+i), time.Now().Add(time.Minute), payload)
		if resp.Status != "FAILED" || resp.Message != want || connect != nil {
			t.Errorf("payload %d: %s %q connect %v", i, resp.Status, resp.Message, connect)
		}
	}
}

func TestHandleConnectRefusesAnOpenUnderAPolicyThatAllowsNothing(t *testing.T) {
	r := newDirectPeerRig(t, config.RemoteAccessDisabled, true)
	exp := time.Now().Add(time.Minute)
	resp, connect := r.dispatch(1200, exp, r.sealedOpen(exp, nil))
	if resp.Status != "FAILED" || !strings.HasPrefix(resp.Message, "Remote session refused: remote access is disabled on this device") {
		t.Errorf("%s %q", resp.Status, resp.Message)
	}
	want := map[string]interface{}{"event": "failed", "connect_id": vectorID, "reason": "policy_disabled"}
	if !reflect.DeepEqual(connect, want) {
		t.Errorf("connect %v, want %v", connect, want)
	}

	// A close is not remote access: it is answered whatever the policy.
	closeResp, closeConnect := r.dispatch(1201, exp, loadConnectVector(t).Payloads.Close)
	if closeResp.Status != "COMPLETED" || closeResp.Message != "No such remote session" {
		t.Errorf("close: %s %q", closeResp.Status, closeResp.Message)
	}
	if !reflect.DeepEqual(closeConnect, map[string]interface{}{"event": "closed", "connect_id": vectorID, "found": false}) {
		t.Errorf("close connect %v", closeConnect)
	}
}

// An open that is signed and malformed opens nothing, and says so with the
// session's id.
func TestHandleConnectRefusesAnOpenItCannotRead(t *testing.T) {
	r := newDirectPeerRig(t, config.RemoteAccessFull, true)
	exp := time.Now().Add(time.Minute)
	payload := r.sealedOpen(exp, nil)
	payload["read_only"] = "false"
	resp, connect := r.dispatch(1300, exp, payload)
	if resp.Status != "FAILED" || resp.Message != "Remote session refused: the request is not one this agent can read" {
		t.Errorf("%s %q", resp.Status, resp.Message)
	}
	if !reflect.DeepEqual(connect, map[string]interface{}{"event": "failed", "connect_id": vectorID, "reason": "unsupported_action"}) {
		t.Errorf("connect %v", connect)
	}
}

// Everything up to starting the companion, on a device whose package has
// none: the task is answered with the remedy, and a session id is not used
// up by it.
func TestHandleConnectWithoutACompanionSaysToReinstall(t *testing.T) {
	r := newDirectPeerRig(t, config.RemoteAccessFull, true)
	exp := time.Now().Add(time.Minute)
	resp, connect := r.dispatch(1400, exp, r.sealedOpen(exp, nil))
	if resp.Status != "FAILED" || !strings.Contains(resp.Message, "reinstall the NetDefense package") {
		t.Errorf("%s %q", resp.Status, resp.Message)
	}
	if !reflect.DeepEqual(connect, map[string]interface{}{"event": "failed", "connect_id": vectorID, "reason": "companion_unavailable"}) {
		t.Errorf("connect %v", connect)
	}
	rec, found, err := r.store.Get("1400")
	if err != nil || !found || rec.Status != "FAILED" || !rec.Delivered {
		t.Errorf("the task's row: %+v found %v err %v", rec, found, err)
	}

	// The same task again gets the same answer again, and nothing more.
	again, againConnect := r.dispatch(1400, exp, r.sealedOpen(exp, nil))
	if again.Status != "FAILED" || !reflect.DeepEqual(againConnect, connect) {
		t.Errorf("delivered again: %s %v", again.Status, againConnect)
	}
}

func TestHandleConnectWithoutAManagerOpensNothing(t *testing.T) {
	r := newDirectPeerRig(t, config.RemoteAccessFull, false)
	exp := time.Now().Add(time.Minute)
	resp, connect := r.dispatch(1500, exp, r.sealedOpen(exp, nil))
	if resp.Status != "FAILED" || connect["reason"] != "internal" {
		t.Errorf("open: %s %v", resp.Status, connect)
	}
	closeResp, closeConnect := r.dispatch(1501, exp, loadConnectVector(t).Payloads.Close)
	if closeResp.Status != "COMPLETED" || closeConnect["found"] != false {
		t.Errorf("close: %s %v", closeResp.Status, closeConnect)
	}
}

// A close that arrives before its open: the open cannot start afterwards.
// (The companion is checked first, and this device has none, so the test
// reads the record the close left instead of a second refusal.)
func TestHandleConnectACloseIsRemembered(t *testing.T) {
	r := newDirectPeerRig(t, config.RemoteAccessFull, true)
	exp := time.Now().Add(8 * time.Hour)
	resp, connect := r.dispatch(1600, exp, loadConnectVector(t).Payloads.Close)
	if resp.Status != "COMPLETED" || resp.Message != "No such remote session" || connect["found"] != false {
		t.Fatalf("close: %s %q %v", resp.Status, resp.Message, connect)
	}
	rec, _, _ := r.store.Get("1600")
	if !rec.Delivered {
		t.Error("the close's answer is not marked delivered")
	}
}
