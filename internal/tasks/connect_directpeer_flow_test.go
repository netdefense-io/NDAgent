package tasks

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/config"
	"github.com/netdefense-io/ndagent/internal/directpeer"
	"github.com/netdefense-io/ndagent/internal/pathfinder"
	"github.com/netdefense-io/ndagent/internal/testbroker"
)

// standInVersion is the version the stand-in companion says, and the rig's
// agent with it.
const standInVersion = "0.0.0-test"

// standIn is a companion played by a shell script: it says hello, takes the
// configuration, says it listens and that a client connected, plays the
// client's frames from a file, and keeps what the agent sends until its
// stdin closes. Everything on the agent's side of the pipes is the real
// thing: the handler, the manager, the frame connection and the streams.
type standIn struct {
	t   *testing.T
	dir string
}

const execStream = 7

func newStandIn(t *testing.T) *standIn {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("as root the companion runs as another user, which cannot write into the test's directory")
	}
	s := &standIn{t: t, dir: t.TempDir()}

	// What the client does once connected: opens the command stream and asks
	// for one command.
	request, _ := json.Marshal(map[string]interface{}{"id": "r1", "command": "printf carried"})
	frames := append(
		pathfinder.EncodeFrame(&pathfinder.Frame{Type: pathfinder.FrameTypeOpen, StreamID: execStream, Data: []byte("exec")}),
		pathfinder.EncodeFrame(&pathfinder.Frame{Type: pathfinder.FrameTypeData, StreamID: execStream, Data: request})...,
	)
	if err := os.WriteFile(filepath.Join(s.dir, "client-frames"), frames, 0o600); err != nil {
		t.Fatal(err)
	}

	// The agent starts a companion with an empty environment: the script
	// names its own PATH.
	script := fmt.Sprintf(`#!/bin/sh
PATH=/usr/bin:/bin
export PATH
dir='%s'
echo '{"event":"hello","version":"%s","commit":"test","protocol":1,"ipc":1}' >&2
len=$(dd bs=1 count=4 2>/dev/null | od -An -tu1 | awk 'NR==1 {print $1*16777216+$2*65536+$3*256+$4}')
dd bs=1 count="$len" of="$dir/config" 2>/dev/null
echo '{"event":"listening"}' >&2
echo '{"event":"connected"}' >&2
cat "$dir/client-frames"
cat > "$dir/agent-frames"
echo '{"event":"closed","reason":"stdin_closed"}' >&2
`, s.dir, standInVersion)
	if err := os.WriteFile(s.path(), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return s
}

func (s *standIn) path() string { return filepath.Join(s.dir, "ndagent-connect") }

// agentFrames is what the agent has sent the client so far.
func (s *standIn) agentFrames() []*pathfinder.Frame {
	data, _ := os.ReadFile(filepath.Join(s.dir, "agent-frames"))
	var out []*pathfinder.Frame
	for len(data) >= 9 {
		size := int(binary.BigEndian.Uint32(data[5:9]))
		if len(data) < 9+size {
			break
		}
		out = append(out, &pathfinder.Frame{Type: data[0], StreamID: binary.BigEndian.Uint32(data[1:5]), Data: data[9 : 9+size]})
		data = data[9+size:]
	}
	return out
}

// waitFrames waits until the agent has answered the client's stream one way
// or the other, and returns whether the command ran and what it printed.
func (s *standIn) waitCommand() (ran bool, output string) {
	s.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		var printed bytes.Buffer
		for _, f := range s.agentFrames() {
			if f.StreamID != execStream {
				continue
			}
			switch f.Type {
			case pathfinder.FrameTypeClose:
				return false, printed.String()
			case pathfinder.FrameTypeData:
				var msg struct {
					Type string `json:"type"`
					Data string `json:"data"`
				}
				if json.Unmarshal(f.Data, &msg) != nil {
					continue
				}
				if msg.Type == "stdout" {
					raw, _ := base64.StdEncoding.DecodeString(msg.Data)
					printed.Write(raw)
				}
				if msg.Type == "result" {
					return true, printed.String()
				}
			}
		}
		if time.Now().After(deadline) {
			s.t.Fatalf("the agent never answered the client's stream: %d frames", len(s.agentFrames()))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// newFlowRig is a rig whose manager starts the stand-in.
func newFlowRig(t *testing.T, policy config.RemoteAccessPolicy) (*directPeerRig, *standIn) {
	t.Helper()
	s := newStandIn(t)
	r := newDirectPeerRig(t, policy, false)
	ledger, err := directpeer.OpenLedger(filepath.Join(t.TempDir(), "sessions.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	starter := directpeer.NewStarter(standInVersion)
	starter.Path = s.path()
	m := directpeer.NewManager(starter, ledger, rigDeviceUUID)
	m.SetReporter(r.ws)
	t.Cleanup(func() { m.Shutdown(10 * time.Second) })
	SetDirectPeerManager(m)
	return r, s
}

// answers are the terminal answers the broker holds for a task, with their
// connect objects.
func (r *directPeerRig) answers(taskID int64) (out []testbroker.TaskResponse, connects []map[string]interface{}) {
	r.t.Helper()
	for _, resp := range r.broker.TaskResponses() {
		if resp.TaskID != taskID || resp.Status == "IN_PROGRESS" {
			continue
		}
		var connect map[string]interface{}
		if raw, ok := resp.Inner["connect"]; ok {
			_ = json.Unmarshal(raw, &connect)
		}
		out = append(out, resp)
		connects = append(connects, connect)
	}
	return out, connects
}

func (r *directPeerRig) waitAnswers(taskID int64, n int) ([]testbroker.TaskResponse, []map[string]interface{}) {
	r.t.Helper()
	r.broker.WaitFor(fmt.Sprintf("%d answers for task %d", n, taskID), 20*time.Second, func() bool {
		got, _ := r.answers(taskID)
		return len(got) >= n
	})
	time.Sleep(150 * time.Millisecond)
	got, connects := r.answers(taskID)
	if len(got) != n {
		r.t.Fatalf("task %d has %d answers, want %d: %+v", taskID, len(got), n, got)
	}
	return got, connects
}

// The whole of a session through the real handler: a signed open task, the
// device's own key opening the secret, the companion given the session's
// keys, the client's stream served, the close instruction, and the task
// answered twice.
func TestDirectPeerSessionThroughTheHandler(t *testing.T) {
	r, s := newFlowRig(t, config.RemoteAccessFull)
	exp := time.Now().Add(90 * time.Second)

	resp, connect := r.dispatch(2000, exp, r.sealedOpen(exp, nil))
	if resp.Status != "COMPLETED" || resp.Message != "Remote session ready" {
		t.Fatalf("open: %s %q", resp.Status, resp.Message)
	}
	if want := map[string]interface{}{"event": "listening", "connect_id": vectorID, "protocol": 1.0}; !reflect.DeepEqual(connect, want) {
		t.Fatalf("open connect %v, want %v", connect, want)
	}

	// The companion was given the keys the vector's seed derives.
	raw, err := os.ReadFile(filepath.Join(s.dir, "config"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Role  string `json:"role"`
		Relay struct {
			ID   string `json:"id"`
			Host string `json:"host"`
			Port int    `json:"port"`
		} `json:"relay"`
		NodeKey string `json:"node_key"`
		PeerKey string `json:"peer_key"`
		PSK     string `json:"psk"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("the companion's configuration %q: %v", raw, err)
	}
	b64 := func(hexKey string) string {
		k, _ := hex.DecodeString(hexKey)
		return base64.StdEncoding.EncodeToString(k)
	}
	if cfg.NodeKey != b64("e8973626e7c81881fb5bd6f7c76199bc8acaa49859ced2201803e43d7038c27c") ||
		cfg.PeerKey != b64("cbd9804be55d87ff82584ed23a0bf513ca7ce4ac61eccfe2d85b66ef9cd5882d") ||
		cfg.PSK != b64("4a34cb3e9478bf409d84c4dbfcc221bd41e6669961b543996982de1cd61b5d01") {
		t.Errorf("the companion's keys are not the vector's: %+v", cfg)
	}
	if cfg.Relay.ID != "eu" || cfg.Relay.Host != "relay-eu.example.net" || cfg.Relay.Port != 443 {
		t.Errorf("the companion's relay: %+v", cfg.Relay)
	}

	// The client's command stream is served.
	if ran, output := s.waitCommand(); !ran || output != "carried" {
		t.Fatalf("the client's command: ran %v, printed %q", ran, output)
	}

	// The close instruction ends it; the open task is answered a second time.
	closeResp, closeConnect := r.dispatch(2001, time.Now().Add(8*time.Hour), loadConnectVector(t).Payloads.Close)
	if closeResp.Status != "COMPLETED" || closeResp.Message != "Remote session closed" ||
		!reflect.DeepEqual(closeConnect, map[string]interface{}{"event": "closed", "connect_id": vectorID, "found": true}) {
		t.Fatalf("close: %s %q %v", closeResp.Status, closeResp.Message, closeConnect)
	}
	got, connects := r.waitAnswers(2000, 2)
	end := connects[1]
	if got[1].Status != "COMPLETED" || got[1].Message != "Remote session ended: closed on request" ||
		end["event"] != "session-end" || end["reason"] != "closed" || end["path"] != "relayed" || end["protocol"] != 1.0 {
		t.Fatalf("session-end: %s %q %v", got[1].Status, got[1].Message, end)
	}
	if _, paired := end["paired_after_seconds"]; !paired {
		t.Errorf("the client connected and the end does not say when: %v", end)
	}
	rec, found, err := r.store.Get("2000")
	if err != nil || !found || rec.Status != "COMPLETED" || !rec.Delivered || !strings.Contains(string(rec.ResultData), "session-end") {
		t.Errorf("the open task's row: %+v", rec)
	}

	// The session id is used: another task with it starts nothing.
	exp = time.Now().Add(90 * time.Second)
	replay, replayConnect := r.dispatch(2002, exp, r.sealedOpen(exp, nil))
	if replay.Status != "FAILED" || replayConnect["reason"] != "replayed" {
		t.Errorf("a second task with the id: %s %v", replay.Status, replayConnect)
	}
}

// A read-only session serves no command stream, whichever side made it
// read-only: the task, or the device's own policy over a task that asked for
// the full session.
func TestDirectPeerReadOnlySessionThroughTheHandler(t *testing.T) {
	for _, c := range []struct {
		name     string
		policy   config.RemoteAccessPolicy
		readOnly bool
		ran      bool
	}{
		{"the task asks for read-only", config.RemoteAccessFull, true, false},
		{"the device's policy allows read-only", config.RemoteAccessReadOnly, false, false},
		{"both", config.RemoteAccessReadOnly, true, false},
		{"neither: the control", config.RemoteAccessFull, false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			r, s := newFlowRig(t, c.policy)
			exp := time.Now().Add(90 * time.Second)
			payload := r.sealedOpen(exp, nil)
			payload["read_only"] = c.readOnly
			resp, _ := r.dispatch(2100, exp, payload)
			if resp.Status != "COMPLETED" {
				t.Fatalf("open: %s %q", resp.Status, resp.Message)
			}
			if ran, output := s.waitCommand(); ran != c.ran {
				t.Fatalf("the client's command ran: %v (printed %q), want %v", ran, output, c.ran)
			}
		})
	}
}

// The checks behind the companion, with the device's own key and the signed
// task's own expiry: the handler passes the real ones on.
func TestDirectPeerBindingsThroughTheHandler(t *testing.T) {
	cases := []struct {
		name   string
		change func(r *directPeerRig, exp time.Time, payload map[string]interface{}) map[string]interface{}
		reason string
	}{
		{"sealed with another expiry than the task's", func(r *directPeerRig, exp time.Time, _ map[string]interface{}) map[string]interface{} {
			return r.sealedOpen(exp, func(p map[string]interface{}) { p["exp"] = uint64(exp.Unix() + 1) })
		}, "binding_mismatch"},
		{"sealed for another device", func(r *directPeerRig, exp time.Time, _ map[string]interface{}) map[string]interface{} {
			return r.sealedOpen(exp, func(p map[string]interface{}) { p["device_uuid"] = "3f2b8c1e-6a4d-4e0b-9c57-d1a2b3c4e5f7" })
		}, "binding_mismatch"},
		{"sealed for another relay than the task's", func(r *directPeerRig, exp time.Time, payload map[string]interface{}) map[string]interface{} {
			payload["relay"].(map[string]interface{})["hostname"] = "relay-us.example.net"
			return payload
		}, "binding_mismatch"},
		{"the vector's own blob, sealed for an expiry that has passed", func(r *directPeerRig, exp time.Time, _ map[string]interface{}) map[string]interface{} {
			return vectorOpen(r.t)
		}, "binding_mismatch"},
		{"sealed data that is not this device's", func(r *directPeerRig, exp time.Time, payload map[string]interface{}) map[string]interface{} {
			sealed := []byte(payload["sealed"].(string))
			sealed[10] ^= 1
			payload["sealed"] = string(sealed)
			return payload
		}, "unseal_failed"},
		{"keys registered that are not the seed's", func(r *directPeerRig, exp time.Time, payload map[string]interface{}) map[string]interface{} {
			keys := payload["admit_keys"].(map[string]interface{})
			keys["server"] = keys["client"]
			return payload
		}, "key_mismatch"},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, s := newFlowRig(t, config.RemoteAccessFull)
			exp := time.Now().Add(90 * time.Second)
			resp, connect := r.dispatch(int64(2200+i), exp, c.change(r, exp, r.sealedOpen(exp, nil)))
			if resp.Status != "FAILED" || connect["reason"] != c.reason {
				t.Fatalf("%s %q %v, want FAILED %s", resp.Status, resp.Message, connect, c.reason)
			}
			if _, err := os.Stat(filepath.Join(s.dir, "config")); err == nil {
				t.Fatal("the companion of a refused session was given a configuration")
			}
		})
	}
}

// The local policy answers before the request is read: a device that allows
// no remote access says so, also for an open it could not read.
func TestDirectPeerPolicyComesBeforeTheRequestIsRead(t *testing.T) {
	r := newDirectPeerRig(t, config.RemoteAccessDisabled, true)
	exp := time.Now().Add(time.Minute)
	payload := r.sealedOpen(exp, nil)
	payload["read_only"] = "false"
	delete(payload, "limits")
	resp, connect := r.dispatch(2300, exp, payload)
	if resp.Status != "FAILED" || connect["reason"] != "policy_disabled" {
		t.Fatalf("%s %q %v", resp.Status, resp.Message, connect)
	}
}

func TestSessionServices(t *testing.T) {
	id := sessionIdentity{shell: "/bin/csh", webadminUser: "root", webadminReadOnly: "netdefense-readonly", webadminSessionDir: "/var/lib/php/sessions", webadminPort: 8443}
	cases := []struct {
		policy    config.RemoteAccessPolicy
		requested bool
		readOnly  bool
		user      string
	}{
		{config.RemoteAccessFull, false, false, "root"},
		{config.RemoteAccessFull, true, true, "netdefense-readonly"},
		{config.RemoteAccessReadOnly, false, true, "netdefense-readonly"},
		{config.RemoteAccessReadOnly, true, true, "netdefense-readonly"},
	}
	for _, c := range cases {
		got := sessionServices(c.policy, c.requested, id)
		want := streamServiceConfig{
			shell: "/bin/csh", webadminUser: c.user, webadminSessionDir: "/var/lib/php/sessions", webadminPort: 8443,
			readOnly: c.readOnly, policy: c.policy,
		}
		if got != want {
			t.Errorf("policy %s, requested %v: %+v, want %+v", c.policy, c.requested, got, want)
		}
	}
}
