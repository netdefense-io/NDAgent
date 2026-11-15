package directpeer

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// recorder is a Reporter that keeps what it was given, as a task store does.
type recorder struct {
	mu      sync.Mutex
	results []reported
	resent  []string
	fail    error
}

type reported struct {
	taskID string
	result Result
}

func (r *recorder) ReportConnectResult(taskID string, result Result) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail != nil {
		return r.fail
	}
	r.results = append(r.results, reported{taskID, result})
	return nil
}

func (r *recorder) ResendConnectResult(taskID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, got := range r.results {
		if got.taskID == taskID {
			r.resent = append(r.resent, taskID)
			return true
		}
	}
	return false
}

func (r *recorder) all() []reported {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]reported(nil), r.results...)
}

// forget drops what was recorded, as the task store's retention does.
func (r *recorder) forget() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.results = nil
}

func (r *recorder) events(taskID string) []string {
	var out []string
	for _, got := range r.all() {
		if got.taskID == taskID {
			event, _ := got.result.Connect["event"].(string)
			if reason, ok := got.result.Connect["reason"].(string); ok {
				event += ":" + reason
			}
			out = append(out, event)
		}
	}
	return out
}

func (r *recorder) waitEvents(t *testing.T, taskID string, n int) []string {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		got := r.events(taskID)
		if len(got) >= n {
			// Anything more than n would be a second end: give it a moment.
			time.Sleep(100 * time.Millisecond)
			return r.events(taskID)
		}
		if time.Now().After(deadline) {
			t.Fatalf("task %s: results %v, waiting for %d", taskID, got, n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// pipeCarrier carries a session as the agent's frame connection does: it
// reads the companion's output to its end, and ends the session by closing
// the companion's input.
type pipeCarrier struct {
	sess     *Session
	fail     chan error
	activity func() time.Time
	closed   chan struct{}
	once     sync.Once
}

func newPipeCarrier(s *Session) *pipeCarrier {
	return &pipeCarrier{sess: s, fail: make(chan error, 1), closed: make(chan struct{})}
}

func (c *pipeCarrier) Run(ctx context.Context, connected <-chan struct{}) error {
	read := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, c.sess.FromPeer)
		close(read)
	}()
	select {
	case err := <-c.fail:
		c.Close()
		<-read
		return err
	case <-read:
		return nil
	}
}

func (c *pipeCarrier) LastActivity() time.Time {
	if c.activity != nil {
		return c.activity()
	}
	return time.Time{}
}

func (c *pipeCarrier) Close() {
	c.once.Do(func() {
		close(c.closed)
		_ = c.sess.ToPeer.Close()
	})
}

type managerFixture struct {
	t        *testing.T
	fake     *fake
	m        *Manager
	rec      *recorder
	ledger   string
	clock    *ledgerClock
	v        secretVector
	device   ed25519.PrivateKey
	mu       sync.Mutex
	carriers []*pipeCarrier
	secrets  []*Secret
}

func newManagerFixture(t *testing.T, scenario string) *managerFixture {
	t.Helper()
	v := loadSecretVector(t)
	fx := &managerFixture{
		t:      t,
		fake:   newFake(t, scenario),
		rec:    &recorder{},
		ledger: filepath.Join(t.TempDir(), "sessions.json"),
		clock:  newLedgerClock(),
		v:      v,
		device: vectorDeviceKey(t, v),
	}
	fx.fake.Starter.StopGrace = 2 * time.Second
	fx.fake.Starter.KillGrace = 2 * time.Second
	fx.m = fx.newManager()
	t.Cleanup(func() { fx.m.Shutdown(10 * time.Second) })
	return fx
}

// newManager is a manager on the fixture's record: the first, or the one of
// the next agent process.
func (fx *managerFixture) newManager() *Manager {
	fx.t.Helper()
	ledger, err := OpenLedger(fx.ledger, fx.clock.now)
	if err != nil {
		fx.t.Fatal(err)
	}
	m := NewManager(fx.fake.Starter, ledger, fx.v.Sealed.Plaintext.DeviceUUID)
	m.SetReporter(fx.rec)
	return m
}

// request is the vector's open task.
func (fx *managerFixture) request(taskID string) OpenRequest {
	p := fx.v.Sealed.Plaintext
	return OpenRequest{
		TaskID:         taskID,
		Exp:            int64(p.Exp),
		ConnectID:      p.ConnectID,
		Protocol:       1,
		Relay:          Relay{ID: "eu", Host: p.Relay.Hostname, Port: int(p.Relay.DERPPort), STUNPort: int(p.Relay.STUNPort)},
		Sealed:         fx.v.Sealed.SealedB64,
		AdmitServer:    fx.v.Payloads.Open.AdmitKeys.Server,
		AdmitClient:    fx.v.Payloads.Open.AdmitKeys.Client,
		PairSeconds:    300,
		IdleSeconds:    1800,
		MaxSeconds:     28800,
		DeviceSessions: 4,
		Unseal: func(sealed string) (*Secret, error) {
			secret, err := Unseal(fx.device, sealed)
			if err == nil {
				fx.mu.Lock()
				fx.secrets = append(fx.secrets, secret)
				fx.mu.Unlock()
			}
			return secret, err
		},
		Carry: func(s *Session) Carrier {
			c := newPipeCarrier(s)
			fx.mu.Lock()
			fx.carriers = append(fx.carriers, c)
			fx.mu.Unlock()
			return c
		},
	}
}

// another is a request for a second session: its own id, sealed here.
func (fx *managerFixture) another(taskID, connectID string) OpenRequest {
	m := goodPlaintext(fx.v)
	m["connect_id"] = connectID
	req := fx.request(taskID)
	req.ConnectID = connectID
	req.Sealed = sealFor(fx.t, fx.device, sealInfo, mustCBOR(fx.t, m))
	return req
}

func (fx *managerFixture) carrier(i int) *pipeCarrier {
	fx.mu.Lock()
	defer fx.mu.Unlock()
	if i >= len(fx.carriers) {
		fx.t.Fatalf("no carrier %d: %d sessions were carried", i, len(fx.carriers))
	}
	return fx.carriers[i]
}

func (fx *managerFixture) waitNoSessions() {
	fx.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for fx.m.Sessions() != 0 {
		if time.Now().After(deadline) {
			fx.t.Fatalf("%d sessions still counted", fx.m.Sessions())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (fx *managerFixture) orphansOnDisk() []Orphan {
	fx.t.Helper()
	ledger, err := OpenLedger(fx.ledger, fx.clock.now)
	if err != nil {
		fx.t.Fatal(err)
	}
	return ledger.Orphans()
}

const otherConnectID = "00112233445566778899aabbccddeeff"

// A whole session: the vector's task opens it, the companion is given the
// vector's keys, the close instruction ends it, and the task is answered
// twice.
func TestManagerOpensASessionAndReportsItsEnd(t *testing.T) {
	fx := newManagerFixture(t, "ok")
	fx.m.Open(context.Background(), fx.request("101"))

	if got := fx.rec.events("101"); len(got) != 1 || got[0] != "listening" {
		t.Fatalf("after Open: %v, want listening", got)
	}
	if fx.m.Sessions() != 1 {
		t.Fatalf("%d sessions counted, want 1", fx.m.Sessions())
	}

	// The companion got the keys the vector derives, and its relay.
	config, ok := fx.fake.seenValue(t, "config")
	if !ok {
		t.Fatal("the companion was given no configuration")
	}
	var cfg struct {
		Relay struct {
			ID       string `json:"id"`
			Host     string `json:"host"`
			Port     int    `json:"port"`
			STUNPort int    `json:"stun_port"`
		} `json:"relay"`
		NodeKey string `json:"node_key"`
		PeerKey string `json:"peer_key"`
		PSK     string `json:"psk"`
	}
	if err := json.Unmarshal([]byte(config), &cfg); err != nil {
		t.Fatal(err)
	}
	b64 := func(hexKey string) string {
		k := hex32(t, hexKey)
		return base64.StdEncoding.EncodeToString(k[:])
	}
	if cfg.NodeKey != b64(fx.v.SessionKeys.ServerPrivateHex) || cfg.PeerKey != b64(fx.v.SessionKeys.ClientPublicHex) || cfg.PSK != b64(fx.v.SessionKeys.PresharedKeyHex) {
		t.Errorf("the companion's keys are not the vector's: %+v", cfg)
	}
	if cfg.Relay.ID != "eu" || cfg.Relay.Host != "relay-eu.example.net" || cfg.Relay.Port != 443 || cfg.Relay.STUNPort != 3478 {
		t.Errorf("the companion's relay: %+v", cfg.Relay)
	}

	// The seed is gone once the keys are derived.
	fx.mu.Lock()
	secret := fx.secrets[0]
	fx.mu.Unlock()
	if secret.seed != ([32]byte{}) {
		t.Error("the seed was not wiped")
	}

	waitClosed(t, "the client's connection", fx.carrier(0).sess.Connected())
	time.Sleep(100 * time.Millisecond) // the path events follow

	fx.m.Close("102", fx.request("").ConnectID, fx.clock.at.Add(8*time.Hour).Unix())
	closed := fx.rec.all()[1]
	if closed.taskID != "102" || closed.result.Message != "Remote session closed" || closed.result.Connect["found"] != true {
		t.Fatalf("the close task's answer: %+v", closed)
	}

	got := fx.rec.waitEvents(t, "101", 2)
	if len(got) != 2 || got[1] != "session-end:closed" {
		t.Fatalf("the open task's answers: %v", got)
	}
	end := fx.rec.all()[2].result
	if end.Status != "COMPLETED" || end.Message != "Remote session ended: closed on request" ||
		end.Connect["path"] != "direct" || end.Connect["paired_after_seconds"] != 0 {
		t.Errorf("session-end: %+v", end)
	}
	if _, ok := CleanResult(end.Status, end.Connect); !ok {
		t.Errorf("the session-end is not one the contract accepts: %+v", end.Connect)
	}
	fx.waitNoSessions()
	if !fx.fake.gone(t) {
		t.Error("the companion is still running")
	}
	if left := fx.orphansOnDisk(); len(left) != 0 {
		t.Errorf("an ended and reported session is still open on disk: %+v", left)
	}
}

// Every refusal: its reason, no session, no companion left, and the place
// among the device's sessions given back.
func TestManagerRefusals(t *testing.T) {
	cases := []struct {
		name     string
		scenario string
		change   func(fx *managerFixture, req *OpenRequest)
		reason   string
	}{
		{"no companion", "ok", func(fx *managerFixture, req *OpenRequest) { fx.fake.Starter.Path = "/nonexistent/ndagent-connect" }, "companion_unavailable"},
		{"a companion of another build", "another-version", nil, "companion_unavailable"},
		{"another protocol asked for", "ok", func(fx *managerFixture, req *OpenRequest) { req.Protocol = 2 }, "protocol_mismatch"},
		{"no place left", "ok", func(fx *managerFixture, req *OpenRequest) { req.DeviceSessions = 0 }, "unsupported_action"},
		{"a limit of zero", "ok", func(fx *managerFixture, req *OpenRequest) { req.IdleSeconds = 0 }, "unsupported_action"},
		{"sealed data that does not open", "ok", func(fx *managerFixture, req *OpenRequest) { req.Sealed = fx.v.Sealed.MustNotOpen.TamperedB64 }, "unseal_failed"},
		{"sealed for another device", "ok", func(fx *managerFixture, req *OpenRequest) { fx.m.deviceUUID = "3f2b8c1e-6a4d-4e0b-9c57-d1a2b3c4e5f7" }, "binding_mismatch"},
		{"sealed for another session id", "ok", func(fx *managerFixture, req *OpenRequest) { req.ConnectID = otherConnectID }, "binding_mismatch"},
		{"sealed with another expiry", "ok", func(fx *managerFixture, req *OpenRequest) { req.Exp++ }, "binding_mismatch"},
		{"sealed for another relay", "ok", func(fx *managerFixture, req *OpenRequest) { req.Relay.Host = "relay-us.example.net" }, "binding_mismatch"},
		{"sealed for another relay port", "ok", func(fx *managerFixture, req *OpenRequest) { req.Relay.Port = 8443 }, "binding_mismatch"},
		{"another server key registered", "ok", func(fx *managerFixture, req *OpenRequest) { req.AdmitServer = req.AdmitClient }, "key_mismatch"},
		{"another client key registered", "ok", func(fx *managerFixture, req *OpenRequest) { req.AdmitClient = req.AdmitServer }, "key_mismatch"},
		{"the relay refuses the device", "relay-refused", nil, "relay_refused"},
		{"the relay cannot be reached", "relay-unreachable", nil, "relay_unreachable"},
		{"the companion does not come up", "start-failed", nil, "companion_failed"},
		{"the companion crashes", "crashes", nil, "companion_failed"},
		{"the companion refuses the session", "bad-config", nil, "internal"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fx := newManagerFixture(t, c.scenario)
			req := fx.request("201")
			if c.change != nil {
				c.change(fx, &req)
			}
			fx.m.Open(context.Background(), req)

			got := fx.rec.all()
			if len(got) != 1 {
				t.Fatalf("answers: %+v, want one refusal", got)
			}
			r := got[0].result
			if r.Status != "FAILED" || r.Connect["event"] != "failed" || r.Connect["reason"] != c.reason {
				t.Fatalf("answer %+v, want FAILED %s", r, c.reason)
			}
			if !strings.HasPrefix(r.Message, "Remote session refused: ") {
				t.Errorf("message %q", r.Message)
			}
			for _, leak := range []string{"203.0.113.5", "psk", fx.v.Sealed.Plaintext.DeviceUUID, "relay-us", "nonexistent"} {
				if strings.Contains(r.Message, leak) {
					t.Errorf("the message carries %q: %s", leak, r.Message)
				}
			}
			if fx.m.Sessions() != 0 {
				t.Errorf("%d sessions counted after a refusal", fx.m.Sessions())
			}
			fx.mu.Lock()
			carried, secrets := len(fx.carriers), fx.secrets
			fx.mu.Unlock()
			if carried != 0 {
				t.Error("a refused session was carried")
			}
			for _, s := range secrets {
				if s.seed != ([32]byte{}) {
					t.Error("the seed of a refused session was not wiped")
				}
			}
			if _, started := fx.fake.seenValue(t, "pid"); started {
				deadline := time.Now().Add(5 * time.Second)
				for !fx.fake.gone(t) {
					if time.Now().After(deadline) {
						t.Fatal("the companion of a refused session is still running")
					}
					time.Sleep(10 * time.Millisecond)
				}
			}
			// Nothing is on its way: a refusal is the task's only answer.
			time.Sleep(100 * time.Millisecond)
			if n := len(fx.rec.all()); n != 1 {
				t.Errorf("%d answers after a refusal", n)
			}
		})
	}
}

// A request wrong in several ways is refused for the first check it fails,
// in the contract's order.
func TestManagerChecksInTheContractsOrder(t *testing.T) {
	// Each step makes the request wrong in one more, earlier, way.
	steps := []struct {
		reason string
		change func(fx *managerFixture, req *OpenRequest)
	}{
		{"key_mismatch", func(fx *managerFixture, req *OpenRequest) { req.AdmitClient = req.AdmitServer }},
		{"replayed", func(fx *managerFixture, req *OpenRequest) {
			if err := fx.m.ledger.RememberClosed(req.ConnectID, 1<<40); err != nil {
				fx.t.Fatal(err)
			}
		}},
		{"binding_mismatch", func(fx *managerFixture, req *OpenRequest) { req.Exp++ }},
		{"unseal_failed", func(fx *managerFixture, req *OpenRequest) { req.Sealed = fx.v.Sealed.MustNotOpen.TamperedB64 }},
		{"too_many_sessions", func(fx *managerFixture, req *OpenRequest) {
			if _, ok := fx.m.sessions.Acquire(1); !ok {
				fx.t.Fatal("could not take the device's one place")
			}
			req.DeviceSessions = 1
		}},
		{"protocol_mismatch", func(fx *managerFixture, req *OpenRequest) { req.Protocol = 2 }},
		{"companion_unavailable", func(fx *managerFixture, req *OpenRequest) { fx.fake.Starter.Path = "/nonexistent/ndagent-connect" }},
	}
	for upTo := range steps {
		t.Run(steps[upTo].reason, func(t *testing.T) {
			fx := newManagerFixture(t, "ok")
			req := fx.request("301")
			for _, step := range steps[:upTo+1] {
				step.change(fx, &req)
			}
			fx.m.Open(context.Background(), req)
			got := fx.rec.all()
			if len(got) != 1 || got[0].result.Connect["reason"] != steps[upTo].reason {
				t.Fatalf("answers %+v, want %s", got, steps[upTo].reason)
			}
		})
	}
}

func TestManagerRefusesMoreSessionsThanTheDeviceMayCarry(t *testing.T) {
	fx := newManagerFixture(t, "waits-for-a-client")
	first := fx.request("401")
	first.DeviceSessions = 1
	fx.m.Open(context.Background(), first)
	if got := fx.rec.events("401"); len(got) != 1 || got[0] != "listening" {
		t.Fatalf("first: %v", got)
	}

	second := fx.another("402", otherConnectID)
	second.DeviceSessions = 1
	fx.m.Open(context.Background(), second)
	if got := fx.rec.events("402"); len(got) != 1 || got[0] != "failed:too_many_sessions" {
		t.Fatalf("second: %v", got)
	}

	// The control plane's number is held to the agent's own.
	if _, ok := fx.m.sessions.Acquire(1000); !ok {
		t.Fatal("a second place refused with 1000 allowed")
	}
	for i := 2; i < MaxDeviceSessions; i++ {
		if _, ok := fx.m.sessions.Acquire(1000); !ok {
			t.Fatalf("place %d refused", i+1)
		}
	}
	third := fx.another("403", "ffeeddccbbaa99887766554433221100")
	third.DeviceSessions = 1000
	fx.m.Open(context.Background(), third)
	if got := fx.rec.events("403"); len(got) != 1 || got[0] != "failed:too_many_sessions" {
		t.Fatalf("with the agent's maximum open: %v", got)
	}
}

// A session id is used once: another task that brings it is refused, also
// after the session is over, and by the next agent process.
func TestManagerRefusesAUsedSessionID(t *testing.T) {
	fx := newManagerFixture(t, "ok")
	fx.m.Open(context.Background(), fx.request("501"))
	fx.m.Open(context.Background(), fx.request("502"))
	if got := fx.rec.events("502"); len(got) != 1 || got[0] != "failed:replayed" {
		t.Fatalf("a second task with a running session's id: %v", got)
	}
	if got := fx.rec.events("501"); len(got) != 1 {
		t.Fatalf("the running session was disturbed: %v", got)
	}

	fx.m.Close("503", fx.request("").ConnectID, 1<<40)
	fx.rec.waitEvents(t, "501", 2)
	fx.waitNoSessions()
	fx.m.Open(context.Background(), fx.request("504"))
	if got := fx.rec.events("504"); len(got) != 1 || got[0] != "failed:replayed" {
		t.Fatalf("after the session ended: %v", got)
	}

	next := fx.newManager()
	defer next.Shutdown(5 * time.Second)
	next.Open(context.Background(), fx.request("505"))
	if got := fx.rec.events("505"); len(got) != 1 || got[0] != "failed:replayed" {
		t.Fatalf("in the next process: %v", got)
	}
}

// The same task delivered again is not a replay: nothing starts, nothing is
// refused, and the control plane gets the answer it missed.
func TestManagerAnswersATaskDeliveredAgainWithItsRecordedAnswer(t *testing.T) {
	fx := newManagerFixture(t, "ok")
	fx.m.Open(context.Background(), fx.request("601"))
	fx.m.Open(context.Background(), fx.request("601"))

	if got := fx.rec.events("601"); len(got) != 1 || got[0] != "listening" {
		t.Fatalf("answers after the second delivery: %v, want the one listening", got)
	}
	if len(fx.rec.resent) != 1 || fx.rec.resent[0] != "601" {
		t.Fatalf("resent: %v", fx.rec.resent)
	}
	if fx.m.Sessions() != 1 {
		t.Fatalf("%d sessions, want the one", fx.m.Sessions())
	}
	fx.mu.Lock()
	carried := len(fx.carriers)
	fx.mu.Unlock()
	if carried != 1 {
		t.Fatalf("%d sessions carried, want 1", carried)
	}

	// The record of the answer is gone (the task store keeps only so many):
	// a running session is said to be ready again, never refused.
	fx.rec.forget()
	fx.m.Open(context.Background(), fx.request("601"))
	if got := fx.rec.events("601"); len(got) != 1 || got[0] != "listening" {
		t.Fatalf("with the record gone: %v", got)
	}
	if fx.m.Sessions() != 1 {
		t.Fatalf("%d sessions", fx.m.Sessions())
	}

	// After the end: the end is what is on record and what is sent again.
	fx.m.Close("602", fx.request("").ConnectID, 1<<40)
	fx.rec.waitEvents(t, "601", 2)
	fx.waitNoSessions()
	before := len(fx.rec.all())
	fx.m.Open(context.Background(), fx.request("601"))
	if len(fx.rec.all()) != before || fx.rec.resent[len(fx.rec.resent)-1] != "601" {
		t.Fatalf("after the end: %v, resent %v", fx.rec.events("601"), fx.rec.resent)
	}

	// The end's record gone too: nothing starts and nothing is said.
	fx.rec.forget()
	fx.m.Open(context.Background(), fx.request("601"))
	if got := fx.rec.all(); len(got) != 0 {
		t.Fatalf("with no record and no session: %+v", got)
	}
	if fx.m.Sessions() != 0 {
		t.Fatal("a session started")
	}
}

// A task that was refused and is delivered again gets its refusal again:
// the checks do not run a second time.
func TestManagerARefusedTaskDeliveredAgainIsNotJudgedAgain(t *testing.T) {
	fx := newManagerFixture(t, "ok")
	req := fx.request("701")
	req.Sealed = fx.v.Sealed.MustNotOpen.TamperedB64
	fx.m.Open(context.Background(), req)
	fx.m.Open(context.Background(), fx.request("701"))
	if got := fx.rec.events("701"); len(got) != 1 || got[0] != "failed:unseal_failed" {
		t.Fatalf("answers: %v", got)
	}
	if fx.m.Sessions() != 0 {
		t.Fatal("the second delivery started a session")
	}
}

func TestManagerSessionEnds(t *testing.T) {
	cases := []struct {
		name     string
		scenario string
		act      func(fx *managerFixture)
		limits   func(req *OpenRequest)
		reason   string
		paired   bool
	}{
		{"the client closes", "client-leaves", nil, nil, "client_closed", true},
		{"the connection to the client breaks", "connection-lost", nil, nil, "client_timeout", true},
		{"the companion exits without a word", "dies-quietly", nil, nil, "companion_exited", false},
		{"the companion crashes", "dies-loudly", nil, nil, "companion_exited", false},
		{"the client goes silent", "ok", func(fx *managerFixture) { fx.carrier(0).fail <- ErrClientSilent }, nil, "client_timeout", true},
		{"the transport fails", "ok", func(fx *managerFixture) { fx.carrier(0).fail <- errors.New("write stalled") }, nil, "error", true},
		{"no client connects", "waits-for-a-client", nil, func(req *OpenRequest) { req.PairSeconds = 1 }, "no_client", false},
		{"the session reaches its longest life", "ok", nil, func(req *OpenRequest) { req.MaxSeconds = 1 }, "max_duration", true},
		{"the session is idle", "ok", nil, func(req *OpenRequest) { req.IdleSeconds = 1 }, "idle_timeout", true},
		{"the agent stops", "ok", func(fx *managerFixture) { go fx.m.Shutdown(10 * time.Second) }, nil, "agent_shutdown", true},
		{"a companion that ignores its stdin is closed", "stubborn", func(fx *managerFixture) { fx.m.Close("9", fx.request("").ConnectID, 1<<40) }, nil, "closed", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fx := newManagerFixture(t, c.scenario)
			req := fx.request("801")
			if c.limits != nil {
				c.limits(&req)
			}
			fx.m.Open(context.Background(), req)
			if got := fx.rec.events("801"); len(got) != 1 || got[0] != "listening" {
				t.Fatalf("after Open: %v", got)
			}
			if c.act != nil {
				if c.paired {
					waitClosed(t, "the client's connection", fx.carrier(0).sess.Connected())
				}
				c.act(fx)
			}
			got := fx.rec.waitEvents(t, "801", 2)
			if len(got) != 2 || got[1] != "session-end:"+c.reason {
				t.Fatalf("answers %v, want one session-end:%s", got, c.reason)
			}
			var end Result
			for _, r := range fx.rec.all() {
				if r.taskID == "801" && r.result.Connect["event"] == "session-end" {
					end = r.result
				}
			}
			if end.Status != "COMPLETED" {
				t.Errorf("a session's end is %s; it is never a failed task", end.Status)
			}
			_, paired := end.Connect["paired_after_seconds"]
			if paired != c.paired || (end.Connect["path"] == "none") == c.paired {
				t.Errorf("paired %v, path %v; want paired %v", paired, end.Connect["path"], c.paired)
			}
			if _, ok := CleanResult(end.Status, end.Connect); !ok {
				t.Errorf("not a result the contract accepts: %+v", end.Connect)
			}
			fx.waitNoSessions()
			if !fx.fake.gone(t) {
				t.Error("the companion is still running")
			}
			select {
			case <-fx.carrier(0).closed:
			default:
				t.Error("the session's streams were not closed")
			}
			if left := fx.orphansOnDisk(); len(left) != 0 {
				t.Errorf("still open on disk: %+v", left)
			}
		})
	}
}

// A session does not live on the context of the task that opened it: the
// control connection can drop and the session runs on.
func TestManagerASessionOutlivesItsTasksContext(t *testing.T) {
	fx := newManagerFixture(t, "ok")
	ctx, cancel := context.WithCancel(context.Background())
	fx.m.Open(ctx, fx.request("901"))
	cancel()
	time.Sleep(300 * time.Millisecond)
	if got := fx.rec.events("901"); len(got) != 1 || fx.m.Sessions() != 1 || fx.fake.gone(t) {
		t.Fatalf("after the task's context ended: answers %v, sessions %d, companion gone %v", got, fx.m.Sessions(), fx.fake.gone(t))
	}
}

// A start cut short by its context opens nothing and leaves nothing.
func TestManagerAStartCutShortOpensNothing(t *testing.T) {
	fx := newManagerFixture(t, "never-listens")
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(300 * time.Millisecond)
		cancel()
	}()
	fx.m.Open(ctx, fx.request("1001"))
	if got := fx.rec.events("1001"); len(got) != 1 || got[0] != "failed:internal" {
		t.Fatalf("answers: %v", got)
	}
	if fx.m.Sessions() != 0 || !fx.fake.gone(t) {
		t.Fatalf("sessions %d, companion gone %v", fx.m.Sessions(), fx.fake.gone(t))
	}
	// The id was accepted before the start: it stays used.
	fx.m.Open(context.Background(), fx.request("1002"))
	if got := fx.rec.events("1002"); len(got) != 1 || got[0] != "failed:replayed" {
		t.Fatalf("the id of a start that was cut short: %v", got)
	}
}

// A close for an id the device never saw: answered, and remembered, so the
// open that arrives later cannot start.
func TestManagerRemembersACloseForAnUnknownSession(t *testing.T) {
	fx := newManagerFixture(t, "ok")
	id := fx.request("").ConnectID
	fx.m.Close("1101", id, fx.clock.at.Add(8*time.Hour).Unix())
	got := fx.rec.all()
	if len(got) != 1 || got[0].result.Message != "No such remote session" || got[0].result.Connect["found"] != false || got[0].result.Status != "COMPLETED" {
		t.Fatalf("answer: %+v", got)
	}
	fx.m.Open(context.Background(), fx.request("1102"))
	if got := fx.rec.events("1102"); len(got) != 1 || got[0] != "failed:replayed" {
		t.Fatalf("an open after its close: %v", got)
	}
}

// A result that cannot be recorded when it is made waits, in order, for the
// next connection: the session's end is not lost with the control connection.
func TestManagerKeepsResultsUntilTheyCanBeRecorded(t *testing.T) {
	fx := newManagerFixture(t, "client-leaves")
	fx.m.SetReporter(nil)
	fx.m.Open(context.Background(), fx.request("1201"))
	fx.waitNoSessions()
	time.Sleep(100 * time.Millisecond)
	if got := fx.rec.all(); len(got) != 0 {
		t.Fatalf("recorded without a reporter: %+v", got)
	}
	// Not on record yet: the next process would still find the session.
	if left := fx.orphansOnDisk(); len(left) != 1 || left[0].EndReason != "client_closed" {
		t.Fatalf("on disk while the end waits: %+v", left)
	}

	fx.rec.fail = errors.New("the task store is not there")
	fx.m.SetReporter(fx.rec)
	if got := fx.rec.all(); len(got) != 0 {
		t.Fatalf("recorded by a reporter that failed: %+v", got)
	}
	fx.rec.fail = nil
	fx.m.SetReporter(fx.rec)
	if got := fx.rec.events("1201"); len(got) != 2 || got[0] != "listening" || got[1] != "session-end:client_closed" {
		t.Fatalf("after a reporter came: %v", got)
	}
	if left := fx.orphansOnDisk(); len(left) != 0 {
		t.Fatalf("on disk after the end was recorded: %+v", left)
	}
}

// The agent dies with a session open: the next process reports its end.
func TestManagerReportsTheSessionsOfAProcessThatDied(t *testing.T) {
	fx := newManagerFixture(t, "ok")
	fx.m.Open(context.Background(), fx.request("1301"))
	waitClosed(t, "the client's connection", fx.carrier(0).sess.Connected())
	deadline := time.Now().Add(5 * time.Second)
	for {
		left := fx.orphansOnDisk()
		if len(left) == 1 && !left[0].ConnectedAt.IsZero() && left[0].Path == PathDirect {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the open session on disk: %+v", left)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// The next process, started on the record the first left behind.
	rec := &recorder{}
	ledger, err := OpenLedger(fx.ledger, fx.clock.now)
	if err != nil {
		t.Fatal(err)
	}
	next := NewManager(fx.fake.Starter, ledger, fx.v.Sealed.Plaintext.DeviceUUID)
	defer next.Shutdown(time.Second)
	if got := rec.all(); len(got) != 0 {
		t.Fatal("reported before there was a reporter")
	}
	next.SetReporter(rec)
	got := rec.all()
	if len(got) != 1 || got[0].taskID != "1301" {
		t.Fatalf("the next process reported %+v", got)
	}
	end := got[0].result
	if end.Status != "COMPLETED" || end.Connect["event"] != "session-end" || end.Connect["reason"] != "error" ||
		end.Connect["path"] != "direct" || end.Connect["connect_id"] != fx.request("").ConnectID {
		t.Fatalf("the reported end: %+v", end)
	}
	if _, ok := CleanResult(end.Status, end.Connect); !ok {
		t.Fatalf("not a result the contract accepts: %+v", end.Connect)
	}

	// Once: a third process finds nothing.
	third, err := OpenLedger(fx.ledger, fx.clock.now)
	if err != nil {
		t.Fatal(err)
	}
	if left := third.Orphans(); len(left) != 0 {
		t.Fatalf("reported again by the process after: %+v", left)
	}
}

// A clean stop whose end could not be recorded: the next process reports
// what the first saw, not a guess.
func TestManagerReportsAnEndThePreviousProcessCouldNotRecord(t *testing.T) {
	fx := newManagerFixture(t, "ok")
	fx.m.Open(context.Background(), fx.request("1401"))
	waitClosed(t, "the client's connection", fx.carrier(0).sess.Connected())
	fx.m.SetReporter(nil)
	fx.m.Shutdown(10 * time.Second)

	rec := &recorder{}
	ledger, err := OpenLedger(fx.ledger, fx.clock.now)
	if err != nil {
		t.Fatal(err)
	}
	next := NewManager(fx.fake.Starter, ledger, fx.v.Sealed.Plaintext.DeviceUUID)
	next.SetReporter(rec)
	if got := rec.events("1401"); len(got) != 1 || got[0] != "session-end:agent_shutdown" {
		t.Fatalf("the next process reported %v", got)
	}
}

func TestManagerOpensNothingOnceItStops(t *testing.T) {
	fx := newManagerFixture(t, "ok")
	fx.m.Shutdown(time.Second)
	fx.m.Open(context.Background(), fx.request("1501"))
	if got := fx.rec.events("1501"); len(got) != 1 || got[0] != "failed:internal" {
		t.Fatalf("answers: %v", got)
	}
	if _, started := fx.fake.seenValue(t, "pid"); started {
		t.Fatal("a companion was started")
	}
}

// The device cannot tell whether an id was used: it refuses, and says it is
// its own trouble, not a replay.
func TestManagerRefusesWhileItsRecordIsBlind(t *testing.T) {
	fx := newManagerFixture(t, "ok")
	if err := os.WriteFile(fx.ledger, []byte("not a record"), 0o600); err != nil {
		t.Fatal(err)
	}
	ledger, err := OpenLedger(fx.ledger, func() time.Time { return time.Unix(int64(fx.v.Sealed.Plaintext.Exp)-60, 0) })
	if err == nil {
		t.Fatal("an unusable record was opened without a word")
	}
	m := NewManager(fx.fake.Starter, ledger, fx.v.Sealed.Plaintext.DeviceUUID)
	defer m.Shutdown(time.Second)
	m.SetReporter(fx.rec)
	m.Open(context.Background(), fx.request("1601"))
	if got := fx.rec.events("1601"); len(got) != 1 || got[0] != "failed:internal" {
		t.Fatalf("answers: %v", got)
	}
	if m.Sessions() != 0 {
		t.Fatal("a session started")
	}
}

// The same task delivered again while its session is still starting: the
// second delivery says nothing and starts nothing. Answered early it would
// say "ready" before the relay admitted the device; judged again it could be
// refused for the place the first delivery holds.
func TestManagerATaskDeliveredAgainWhileItStartsIsLeftToTheFirstDelivery(t *testing.T) {
	fx := newManagerFixture(t, "slow-start")
	req := fx.request("1701")
	req.DeviceSessions = 1

	first := make(chan struct{})
	go func() {
		defer close(first)
		fx.m.Open(context.Background(), req)
	}()
	// The first delivery is past the companion's hello and waits for it to
	// listen.
	deadline := time.Now().Add(5 * time.Second)
	for fx.m.Sessions() != 1 {
		if time.Now().After(deadline) {
			t.Fatal("the first delivery never took its place")
		}
		time.Sleep(5 * time.Millisecond)
	}

	returned := make(chan struct{})
	go func() {
		defer close(returned)
		fx.m.Open(context.Background(), req)
	}()
	select {
	case <-returned:
	case <-time.After(300 * time.Millisecond):
		t.Fatal("the second delivery did not return at once")
	}
	if got := fx.rec.all(); len(got) != 0 {
		t.Fatalf("answers while the first delivery is still starting: %+v", got)
	}

	waitClosed(t, "the first delivery", first)
	if got := fx.rec.events("1701"); len(got) != 1 || got[0] != "listening" {
		t.Fatalf("answers: %v, want the one listening", got)
	}
	fx.mu.Lock()
	carried := len(fx.carriers)
	fx.mu.Unlock()
	if carried != 1 || fx.m.Sessions() != 1 {
		t.Fatalf("%d sessions carried, %d counted; want 1 and 1", carried, fx.m.Sessions())
	}
	started := 0
	for _, line := range fx.fake.seen(t) {
		if strings.HasPrefix(line, "pid=") {
			started++
		}
	}
	if started != 1 {
		t.Fatalf("%d companions were started, want 1", started)
	}
}

// refusing is a Reporter that says a result is not one the contract accepts.
type refusing struct{ recorder }

func (r *refusing) ReportConnectResult(taskID string, result Result) error {
	if result.Connect["reason"] == FailInternal {
		return ErrNotAResult
	}
	return r.recorder.ReportConnectResult(taskID, result)
}

// A result that will never be recorded is dropped: kept, it would hold back
// every result behind it, of every session.
func TestManagerAResultThatCanNeverBeRecordedDoesNotHoldTheOthersBack(t *testing.T) {
	fx := newManagerFixture(t, "ok")
	rep := &refusing{}
	fx.m.SetReporter(nil)
	fx.m.Refuse("1801", otherConnectID, FailInternal)
	fx.m.Refuse("1802", otherConnectID, FailReplayed)
	fx.m.SetReporter(rep)
	if got := rep.all(); len(got) != 1 || got[0].taskID != "1802" {
		t.Fatalf("recorded %+v, want the one result behind the refused one", got)
	}
	fx.m.Refuse("1803", otherConnectID, FailKeyMismatch)
	if got := rep.all(); len(got) != 2 || got[1].taskID != "1803" {
		t.Fatalf("recorded %+v", got)
	}

	// One the manager can tell is not a result is never queued at all.
	fx.m.report("1804", Result{Status: "COMPLETED", Message: "x", Connect: map[string]interface{}{"event": "ready"}}, nil)
	fx.m.repMu.Lock()
	queued := len(fx.m.queue)
	fx.m.repMu.Unlock()
	if queued != 0 {
		t.Fatalf("%d results queued", queued)
	}
}

// With no connection for long, the results that wait are bounded, and the
// newest are the ones kept.
func TestManagerBoundsTheResultsThatWait(t *testing.T) {
	fx := newManagerFixture(t, "ok")
	fx.m.SetReporter(nil)
	for i := 0; i < maxQueuedResults+10; i++ {
		fx.m.Refuse(strconv.Itoa(5000+i), otherConnectID, FailReplayed)
	}
	fx.m.SetReporter(fx.rec)
	got := fx.rec.all()
	if len(got) != maxQueuedResults {
		t.Fatalf("%d results recorded, want %d", len(got), maxQueuedResults)
	}
	if got[0].taskID != "5010" || got[len(got)-1].taskID != strconv.Itoa(5000+maxQueuedResults+9) {
		t.Fatalf("kept %s to %s", got[0].taskID, got[len(got)-1].taskID)
	}
}

// A task that has its answer keeps it when it is delivered again and the
// caller would now turn it away (the device's policy changed, the agent is
// stopping): a refusal would end the relay admission of a running session.
func TestManagerARefusalNeverReplacesTheAnswerOfARunningSession(t *testing.T) {
	fx := newManagerFixture(t, "ok")
	fx.m.Open(context.Background(), fx.request("1901"))
	fx.m.Refuse("1901", fx.request("").ConnectID, FailPolicyDisabled)
	if got := fx.rec.events("1901"); len(got) != 1 || got[0] != "listening" {
		t.Fatalf("answers: %v, want the one listening", got)
	}
	if n := len(fx.rec.resent); n != 1 {
		t.Fatalf("%d answers sent again, want 1", n)
	}
	if fx.m.Sessions() != 1 || fx.fake.gone(t) {
		t.Fatal("the session was disturbed")
	}

	// The control: a task with no answer yet is refused.
	fx.m.Refuse("1902", otherConnectID, FailPolicyDisabled)
	if got := fx.rec.events("1902"); len(got) != 1 || got[0] != "failed:policy_disabled" {
		t.Fatalf("a first refusal: %v", got)
	}
}

// A close instruction that arrives while its session is still starting finds
// it: the session ends as soon as it is up, and is never left running.
func TestManagerACloseDuringTheStartEndsTheSession(t *testing.T) {
	fx := newManagerFixture(t, "slow-start")
	opened := make(chan struct{})
	go func() {
		defer close(opened)
		fx.m.Open(context.Background(), fx.request("2001"))
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, known := fx.m.ledger.Lookup(fx.request("").ConnectID); known {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the open never accepted its id")
		}
		time.Sleep(2 * time.Millisecond)
	}
	if got := fx.rec.all(); len(got) != 0 {
		t.Fatalf("the session was up before the close: %+v", got)
	}

	fx.m.Close("2002", fx.request("").ConnectID, 1<<40)
	closed := fx.rec.all()
	if len(closed) != 1 || closed[0].taskID != "2002" || closed[0].result.Connect["found"] != true {
		t.Fatalf("the close's answer: %+v", closed)
	}

	waitClosed(t, "the open", opened)
	got := fx.rec.waitEvents(t, "2001", 2)
	if len(got) != 2 || got[0] != "listening" || got[1] != "session-end:closed" {
		t.Fatalf("the open task's answers: %v", got)
	}
	fx.waitNoSessions()
	if !fx.fake.gone(t) {
		t.Fatal("the companion is still running")
	}
}
