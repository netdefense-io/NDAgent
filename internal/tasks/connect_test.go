package tasks

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/netdefense-io/ndagent/internal/config"
	"github.com/netdefense-io/ndagent/internal/network"
	"github.com/netdefense-io/ndagent/internal/pathfinder"
)

func TestBuildPathfinderWSURL(t *testing.T) {
	tests := []struct {
		name string
		host string
		want string
	}{
		{
			name: "https with path",
			host: "https://pathfinder.example.com",
			want: "wss://pathfinder.example.com/ws",
		},
		{
			name: "https with trailing slash",
			host: "https://pathfinder.example.com/",
			want: "wss://pathfinder.example.com/ws",
		},
		{
			name: "https already has /ws",
			host: "https://pathfinder.example.com/ws",
			want: "wss://pathfinder.example.com/ws",
		},
		{
			name: "http to ws",
			host: "http://localhost:8080",
			want: "ws://localhost:8080/ws",
		},
		{
			name: "wss already correct",
			host: "wss://relay.example.com/ws",
			want: "wss://relay.example.com/ws",
		},
		{
			name: "bare hostname",
			host: "pathfinder.example.com",
			want: "wss://pathfinder.example.com/ws",
		},
		{
			name: "hostname with port",
			host: "pathfinder.example.com:9443",
			want: "wss://pathfinder.example.com:9443/ws",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildPathfinderWSURL(tt.host)
			if got != tt.want {
				t.Errorf("buildPathfinderWSURL(%q) = %q, want %q", tt.host, got, tt.want)
			}
		})
	}
}

func TestPayloadBool(t *testing.T) {
	tests := []struct {
		name    string
		payload map[string]interface{}
		key     string
		want    bool
	}{
		{
			name:    "missing key defaults false",
			payload: map[string]interface{}{},
			key:     "read_only",
			want:    false,
		},
		{
			name:    "nil payload entry defaults false",
			payload: map[string]interface{}{"read_only": nil},
			key:     "read_only",
			want:    false,
		},
		{
			name:    "bool true",
			payload: map[string]interface{}{"read_only": true},
			key:     "read_only",
			want:    true,
		},
		{
			name:    "bool false",
			payload: map[string]interface{}{"read_only": false},
			key:     "read_only",
			want:    false,
		},
		{
			name:    "json number 1",
			payload: map[string]interface{}{"read_only": float64(1)},
			key:     "read_only",
			want:    true,
		},
		{
			name:    "json number 0",
			payload: map[string]interface{}{"read_only": float64(0)},
			key:     "read_only",
			want:    false,
		},
		{
			name:    "string true",
			payload: map[string]interface{}{"read_only": "true"},
			key:     "read_only",
			want:    true,
		},
		{
			name:    "string 1",
			payload: map[string]interface{}{"read_only": "1"},
			key:     "read_only",
			want:    true,
		},
		{
			name:    "string false",
			payload: map[string]interface{}{"read_only": "false"},
			key:     "read_only",
			want:    false,
		},
		{
			name:    "unexpected type defaults false",
			payload: map[string]interface{}{"read_only": []string{"x"}},
			key:     "read_only",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := payloadBool(tt.payload, tt.key); got != tt.want {
				t.Errorf("payloadBool(%v, %q) = %v, want %v", tt.payload, tt.key, got, tt.want)
			}
		})
	}
}

// ── Device-local remote-access ceiling ─────────────────────────────────────

// TestEffectiveReadOnlyClampsOneWay pins the clamp's direction. The control
// plane's read_only flag is a request, not an instruction: a "readonly"
// ceiling must force read-only on regardless of what was asked for, and no
// policy may ever turn read-only OFF for a caller that requested it.
//
// The second half is the subtle one. If a future edit made "full" mean
// "override the request to full access", a control plane that intended a
// read-only support session would silently get a root shell.
func TestEffectiveReadOnlyClampsOneWay(t *testing.T) {
	tests := []struct {
		name      string
		policy    config.RemoteAccessPolicy
		requested bool
		want      bool
	}{
		{"full honours a full request", config.RemoteAccessFull, false, false},
		{"full honours a read-only request", config.RemoteAccessFull, true, true},
		{"readonly clamps a full request", config.RemoteAccessReadOnly, false, true},
		{"readonly keeps a read-only request", config.RemoteAccessReadOnly, true, true},
		// Not reachable in production (HandleConnect refuses first), but the
		// clamp must not widen the session if it ever were.
		{"disabled never widens", config.RemoteAccessDisabled, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := effectiveReadOnly(tt.policy, tt.requested); got != tt.want {
				t.Errorf("effectiveReadOnly(%q, %v) = %v, want %v",
					tt.policy, tt.requested, got, tt.want)
			}
		})
	}
}

// TestHandleConnectRefusesWhenDisabled is the device-final assertion at the
// handler level: with the ceiling set to "disabled", a fully valid,
// signature-verified CONNECT carrying a real Pathfinder session must be
// refused — no relay dialed — and must produce a terminal FAILED task whose
// message names the policy and points at the device.
//
// The payload here is deliberately well-formed and requests FULL access
// (read_only absent), i.e. exactly what a compromised control plane or a
// stolen write-scoped credential would send.
func TestHandleConnectRefusesWhenDisabled(t *testing.T) {
	var (
		gotTaskID string
		gotResult TaskResult
		calls     int
	)
	restore := SetConnectSendResponseForTest(
		func(_ *network.WebSocketClient, taskID string, result TaskResult) error {
			calls++
			gotTaskID = taskID
			gotResult = result
			return nil
		})
	defer restore()

	ws := network.NewWebSocketClient(
		&config.Config{RemoteAccessPolicy: config.RemoteAccessDisabled},
		nil, nil, nil, nil,
	)

	cmd := network.Command{
		TaskID: "task-abc",
		Payload: map[string]interface{}{
			"pathfinder_session": "session-that-must-never-be-dialed",
		},
	}

	if err := HandleConnect(context.Background(), ws, cmd); err != nil {
		t.Fatalf("HandleConnect returned error: %v", err)
	}

	if calls != 1 {
		t.Fatalf("expected exactly one terminal response, got %d", calls)
	}
	if gotTaskID != "task-abc" {
		t.Errorf("terminal response carried task_id %q, want %q", gotTaskID, "task-abc")
	}
	if gotResult.Success {
		t.Error("a refused CONNECT must be a FAILED task, not a silent success")
	}
	for _, want := range []string{"remote_access_policy=disabled", "cannot be changed remotely"} {
		if !strings.Contains(gotResult.Message, want) {
			t.Errorf("refusal message %q should contain %q", gotResult.Message, want)
		}
	}
}

// TestHandleConnectAllowsWhenPolicyFull guards against the ceiling refusing
// traffic it should pass. With "full", HandleConnect must get past the policy
// gate — it will fail later trying to reach a bogus relay, which is fine; the
// assertion is that it did NOT stop at the refusal.
func TestHandleConnectAllowsWhenPolicyFull(t *testing.T) {
	var refused bool
	restore := SetConnectSendResponseForTest(
		func(_ *network.WebSocketClient, _ string, _ TaskResult) error {
			refused = true
			return nil
		})
	defer restore()

	ws := network.NewWebSocketClient(
		&config.Config{RemoteAccessPolicy: config.RemoteAccessFull},
		nil, nil, nil, nil,
	)

	// Cancelled context so the handler exits at the cancellation check,
	// immediately after the policy gate and before any network activity.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_ = HandleConnect(ctx, ws, network.Command{
		TaskID:  "task-xyz",
		Payload: map[string]interface{}{"pathfinder_session": "s"},
	})

	if refused {
		t.Error("policy=full must not take the remote-access refusal path")
	}
}

// ── Natural session-end classification ──────────────────────────────────
//
// NDPathFinder's cleaner-driven teardown (session TTL expiry, idle timeout)
// closes the WebSocket with a clean close frame (code 1000/1001) carrying a
// stable reason string — see API-CONTRACT.md's "Cleaner-driven WebSocket
// close frames" section. That must classify as a SUCCESS task, not FAILED;
// a genuine transport failure (1005/1006, network error) must still FAIL.

// TestClassifyPathfinderSessionEnd_CleanCloseReasons pins the SUCCESS path
// for every reason string in the NDPathFinder contract. The classification
// must key off the *pathfinder.ErrSessionEndedCleanly sentinel type (itself
// only ever constructed from close code 1000/1001), not off matching these
// exact strings, so a future relay reason not in this list still succeeds —
// this test exists to document what the strings look like in practice, not
// to gate the classification on them.
func TestClassifyPathfinderSessionEnd_CleanCloseReasons(t *testing.T) {
	reasons := []string{
		"TTL expired (client never connected)",
		"TTL expired (agent never connected)",
		"TTL expired",
		"idle timeout (15m0s)",
	}

	for _, reason := range reasons {
		t.Run(reason, func(t *testing.T) {
			err := &pathfinder.ErrSessionEndedCleanly{Reason: reason}

			outcome := classifyPathfinderSessionEnd(nil, err)

			if !outcome.result.Success {
				t.Fatalf("clean close %q classified as FAILED, want SUCCESS", reason)
			}
			if outcome.cancelled {
				t.Error("clean close must not be reported as cancelled")
			}
			if !outcome.naturalEnd {
				t.Error("clean close must set naturalEnd")
			}
			want := fmt.Sprintf("Pathfinder session ended: %s", reason)
			if outcome.result.Message != want {
				t.Errorf("message = %q, want %q", outcome.result.Message, want)
			}
		})
	}
}

// TestClassifyPathfinderSessionEnd_CleanCloseWrapped confirms the errors.As
// unwrapping catches a sentinel that arrives wrapped (e.g. via %w further up
// the call chain), not just a bare *ErrSessionEndedCleanly.
func TestClassifyPathfinderSessionEnd_CleanCloseWrapped(t *testing.T) {
	inner := &pathfinder.ErrSessionEndedCleanly{Reason: "idle timeout (15m0s)"}
	wrapped := fmt.Errorf("connect failed: %w", inner)

	outcome := classifyPathfinderSessionEnd(nil, wrapped)

	if !outcome.result.Success {
		t.Fatalf("wrapped clean close classified as FAILED, want SUCCESS")
	}
	if !outcome.naturalEnd {
		t.Error("wrapped clean close must set naturalEnd")
	}
}

// TestClassifyPathfinderSessionEnd_TransportFailure pins the FAILED path for
// genuine transport errors — abrupt close (1005/1006) and plain network
// errors both surface as a bare error from connectToPathfinder, never the
// ErrSessionEndedCleanly sentinel.
func TestClassifyPathfinderSessionEnd_TransportFailure(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"abrupt close 1006", errors.New("read failed: websocket: close 1006 (abnormal closure): unexpected EOF")},
		{"abrupt close 1005", errors.New("read failed: websocket: close 1005 (no status)")},
		{"network error", errors.New("read failed: read tcp 10.0.0.1:443: connection reset by peer")},
		{"dial failure", errors.New("connect failed: dial failed: dial tcp: lookup pathfinder.example.com: no such host")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outcome := classifyPathfinderSessionEnd(nil, tt.err)

			if outcome.result.Success {
				t.Fatalf("transport failure %q classified as SUCCESS, want FAILED", tt.err)
			}
			if outcome.naturalEnd {
				t.Error("transport failure must not set naturalEnd")
			}
			if outcome.cancelled {
				t.Error("transport failure must not be reported as cancelled")
			}
			want := fmt.Sprintf("Pathfinder session ended: %v", tt.err)
			if outcome.result.Message != want {
				t.Errorf("message = %q, want %q", outcome.result.Message, want)
			}
		})
	}
}

// TestClassifyPathfinderSessionEnd_Cancellation pins the pre-existing
// cancellation behavior: it must win over any classification of err (which
// connectToPathfinder returns as nil on cancellation anyway), and must
// remain a SUCCESS with the original "(cancelled)" message.
func TestClassifyPathfinderSessionEnd_Cancellation(t *testing.T) {
	outcome := classifyPathfinderSessionEnd(context.Canceled, nil)

	if !outcome.result.Success {
		t.Fatal("cancellation must classify as SUCCESS")
	}
	if !outcome.cancelled {
		t.Error("cancellation must set cancelled")
	}
	if outcome.naturalEnd {
		t.Error("cancellation must not also set naturalEnd")
	}
	want := "Pathfinder session ended (cancelled)"
	if outcome.result.Message != want {
		t.Errorf("message = %q, want %q", outcome.result.Message, want)
	}
}

// TestRemoteAccessRefusalMessageNamesPolicy pins the operator-facing contract:
// the message states which policy refused, and directs the remedy to the
// device. Pointing at a remote fix would be actively misleading — the setting
// exists precisely because it cannot be changed from the control plane.
func TestRemoteAccessRefusalMessageNamesPolicy(t *testing.T) {
	msg := remoteAccessRefusalMessage(config.RemoteAccessDisabled)
	for _, want := range []string{
		"remote_access_policy=disabled",
		"Services → NetDefense → Settings",
		"cannot be changed remotely",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal message %q should contain %q", msg, want)
		}
	}
}
