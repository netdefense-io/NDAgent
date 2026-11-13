package network

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/config"
	"github.com/netdefense-io/ndagent/internal/signing"
)

const statusTestUUID = "3a1e88a3-0000-4000-8000-0000000000aa"

// statusServer answers DeviceRegistrationCheck with a scripted sequence,
// repeating the last entry forever.
func statusServer(t *testing.T, replies []CheckRegistrationResponse, calls *int64) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt64(calls, 1)
		idx := int(n) - 1
		if idx >= len(replies) {
			idx = len(replies) - 1
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(replies[idx])
	}))
}

func testClient(t *testing.T, srv *httptest.Server) *RegistrationClient {
	t.Helper()
	cfg := &config.Config{
		DeviceUUID:     statusTestUUID,
		Token:          "00000000-0000-4000-8000-000000000000",
		ServerURICheck: srv.URL + "/check",
		ServerURIStart: srv.URL + "/start",
	}
	c := NewRegistrationClient(cfg)
	c.httpClient = srv.Client()
	return c
}

func TestWaitForRegistration_EnabledProceeds(t *testing.T) {
	var calls int64
	srv := statusServer(t, []CheckRegistrationResponse{{Status: StatusEnabled}}, &calls)
	defer srv.Close()

	if err := testClient(t, srv).WaitForRegistration(context.Background()); err != nil {
		t.Fatalf("WaitForRegistration: %v", err)
	}
}

// A disabled device must never exit the lifecycle: DISABLED is a reversible
// state, and an exit would only be restarted, after the supervisor's delay,
// into another rate-limited registration check.
func TestWaitForRegistration_DisabledWaitsAndNeverExits(t *testing.T) {
	var calls int64
	srv := statusServer(t, []CheckRegistrationResponse{{Status: StatusDisabled}}, &calls)
	defer srv.Close()

	c := testClient(t, srv)

	// Short-circuit the real 60s..5min waits; assert the growth instead.
	var waits []time.Duration
	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	origSleep := registrationSleep
	registrationSleep = func(ctx context.Context, d time.Duration) error {
		if d >= disabledInitialBackoff {
			waits = append(waits, d)
			if len(waits) == 4 {
				cancel()
			}
		}
		return ctx.Err()
	}
	t.Cleanup(func() { registrationSleep = origSleep })

	go func() { done <- c.WaitForRegistration(ctx) }()

	select {
	case err := <-done:
		if errors.Is(err, ErrDeviceDisabled) {
			t.Fatal("DISABLED returned ErrDeviceDisabled; it must wait, not exit")
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected the wait to end only on cancellation, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("WaitForRegistration did not react to cancellation")
	}

	if len(waits) < 3 {
		t.Fatalf("expected repeated disabled waits, got %v", waits)
	}
	if waits[0] != disabledInitialBackoff {
		t.Errorf("first wait = %v, want %v", waits[0], disabledInitialBackoff)
	}
	if waits[1] <= waits[0] {
		t.Errorf("backoff did not grow: %v", waits)
	}
	for _, w := range waits {
		if w > disabledMaxBackoff {
			t.Errorf("wait %v exceeds the %v cap", w, disabledMaxBackoff)
		}
	}
}

func TestWaitForRegistration_DeletedWithVerifiedTombstoneRequestsDecommission(t *testing.T) {
	var calls int64
	srv := statusServer(t, []CheckRegistrationResponse{{Status: StatusDeleted, Tombstone: "dGVzdA=="}}, &calls)
	defer srv.Close()

	c := testClient(t, srv)
	c.loadPinnedKeys = func(string) (map[string]ed25519.PublicKey, error) {
		return map[string]ed25519.PublicKey{"aa": make(ed25519.PublicKey, ed25519.PublicKeySize)}, nil
	}
	c.verifyTombstone = func(b64 string, _ signing.VerifyKeyByKid, own string) (*signing.Tombstone, error) {
		if own != statusTestUUID {
			t.Errorf("verifier got device_uuid %q", own)
		}
		return &signing.Tombstone{DeletedAt: "2026-09-18T23:40:12Z", Kid: "abcd"}, nil
	}

	err := c.WaitForRegistration(context.Background())
	var req *DecommissionRequiredError
	if !errors.As(err, &req) {
		t.Fatalf("expected DecommissionRequiredError, got %v", err)
	}
	if req.Tombstone.DeletedAt != "2026-09-18T23:40:12Z" {
		t.Errorf("tombstone not carried through: %+v", req.Tombstone)
	}
}

// Every way a tombstone can be unusable must stop the agent WITHOUT
// wiping the device. This is the fail-closed half of the contract.
func TestWaitForRegistration_DeletedWithoutUsableTombstoneStopsOnly(t *testing.T) {
	cases := []struct {
		name   string
		reply  CheckRegistrationResponse
		keys   func(string) (map[string]ed25519.PublicKey, error)
		verify func(string, signing.VerifyKeyByKid, string) (*signing.Tombstone, error)
	}{
		{
			name:  "no tombstone at all",
			reply: CheckRegistrationResponse{Status: StatusDeleted},
			keys: func(string) (map[string]ed25519.PublicKey, error) {
				t.Error("keys must not be loaded when there is no tombstone")
				return nil, nil
			},
		},
		{
			name:  "no pinned keys on disk",
			reply: CheckRegistrationResponse{Status: StatusDeleted, Tombstone: "dGVzdA=="},
			keys: func(string) (map[string]ed25519.PublicKey, error) {
				return nil, errors.New("no pinned NDM keys")
			},
		},
		{
			name:  "empty key table",
			reply: CheckRegistrationResponse{Status: StatusDeleted, Tombstone: "dGVzdA=="},
			keys: func(string) (map[string]ed25519.PublicKey, error) {
				return map[string]ed25519.PublicKey{}, nil
			},
		},
		{
			name:  "signature invalid",
			reply: CheckRegistrationResponse{Status: StatusDeleted, Tombstone: "dGVzdA=="},
			keys: func(string) (map[string]ed25519.PublicKey, error) {
				return map[string]ed25519.PublicKey{"aa": make(ed25519.PublicKey, ed25519.PublicKeySize)}, nil
			},
			verify: func(string, signing.VerifyKeyByKid, string) (*signing.Tombstone, error) {
				return nil, fmt.Errorf("cose verify: signature mismatch")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls int64
			srv := statusServer(t, []CheckRegistrationResponse{tc.reply}, &calls)
			defer srv.Close()

			c := testClient(t, srv)
			c.loadPinnedKeys = tc.keys
			if tc.verify != nil {
				c.verifyTombstone = tc.verify
			} else {
				c.verifyTombstone = func(string, signing.VerifyKeyByKid, string) (*signing.Tombstone, error) {
					t.Error("verifier must not be reached")
					return nil, nil
				}
			}

			err := c.WaitForRegistration(context.Background())
			var req *DecommissionRequiredError
			if errors.As(err, &req) {
				t.Fatal("an unverifiable tombstone must NOT authorize decommission")
			}
			if !errors.Is(err, ErrDeviceDeleted) {
				t.Fatalf("expected ErrDeviceDeleted, got %v", err)
			}
		})
	}
}

// The check endpoint is rate-limited per IP, and Phase 1 is now re-entered
// on every permanent WS refusal, so the floor has to live in the client.
func TestCheckRegistration_RespectsMinimumSpacing(t *testing.T) {
	var calls int64
	srv := statusServer(t, []CheckRegistrationResponse{{Status: StatusEnabled}}, &calls)
	defer srv.Close()

	c := testClient(t, srv)

	var slept time.Duration
	origSleep := registrationSleep
	registrationSleep = func(ctx context.Context, d time.Duration) error {
		slept += d
		return nil
	}
	t.Cleanup(func() { registrationSleep = origSleep })

	if _, err := c.CheckRegistration(context.Background()); err != nil {
		t.Fatalf("first check: %v", err)
	}
	if slept != 0 {
		t.Errorf("first check slept %v; it should go straight out", slept)
	}
	if _, err := c.CheckRegistration(context.Background()); err != nil {
		t.Fatalf("second check: %v", err)
	}
	if slept <= 0 || slept > checkRegistrationMinInterval {
		t.Fatalf("second check waited %v, want >0 and <= %v", slept, checkRegistrationMinInterval)
	}
}

// Every status the wait reads is handed to the hook, so the agent's status file
// can say what it waits for (#179).
func TestWaitForRegistration_TellsTheHookEveryStatus(t *testing.T) {
	var calls int64
	srv := statusServer(t, []CheckRegistrationResponse{{Status: StatusPending}, {Status: StatusDisabled}, {Status: StatusDisabled}, {Status: StatusEnabled}}, &calls)
	defer srv.Close()

	origSleep := registrationSleep
	registrationSleep = func(ctx context.Context, d time.Duration) error { return ctx.Err() }
	t.Cleanup(func() { registrationSleep = origSleep })

	c := testClient(t, srv)
	var seen []string
	c.SetWaitStatusHook(func(status string, err error) {
		if err != nil {
			status = "error"
		}
		seen = append(seen, status)
	})
	if err := c.WaitForRegistration(context.Background()); err != nil {
		t.Fatalf("WaitForRegistration: %v", err)
	}
	if got := strings.Join(seen, ","); got != "PENDING,DISABLED,DISABLED,ENABLED" {
		t.Errorf("hook saw %q, want every status in order", got)
	}
}

// A check that fails is handed to the hook as "", so the status file does not
// keep saying the device waits for an approval while the control plane cannot
// be reached.
func TestWaitForRegistration_TellsTheHookOfAFailedCheck(t *testing.T) {
	var calls int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt64(&calls, 1) == 1 {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(CheckRegistrationResponse{Status: StatusEnabled})
	}))
	defer srv.Close()

	origSleep := registrationSleep
	registrationSleep = func(ctx context.Context, d time.Duration) error { return ctx.Err() }
	t.Cleanup(func() { registrationSleep = origSleep })

	c := testClient(t, srv)
	var seen []string
	c.SetWaitStatusHook(func(status string, err error) {
		if err != nil {
			status = "error"
		}
		seen = append(seen, status)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := c.WaitForRegistration(ctx); err != nil {
		t.Fatalf("WaitForRegistration: %v", err)
	}
	if got := strings.Join(seen, ","); got != "error,ENABLED" {
		t.Errorf("hook saw %q, want the failed check's error and then ENABLED", got)
	}
}

// A start of the registration that fails is handed to the hook too, so a device
// whose start keeps failing does not read as a fresh "Connecting" for as long
// as the wait runs.
func TestWaitForRegistration_TellsTheHookOfAFailedStart(t *testing.T) {
	var checks int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/start") {
			http.Error(w, "refused", http.StatusBadRequest)
			return
		}
		reply := CheckRegistrationResponse{Status: StatusUnregistered}
		if atomic.AddInt64(&checks, 1) > 1 {
			reply.Status = StatusEnabled
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(reply)
	}))
	defer srv.Close()

	origSleep := registrationSleep
	registrationSleep = func(ctx context.Context, d time.Duration) error { return ctx.Err() }
	t.Cleanup(func() { registrationSleep = origSleep })

	c := testClient(t, srv)
	var seen []string
	c.SetWaitStatusHook(func(status string, err error) {
		if err != nil {
			status += "+error"
		}
		seen = append(seen, status)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := c.WaitForRegistration(ctx); err != nil {
		t.Fatalf("WaitForRegistration: %v", err)
	}
	if got := strings.Join(seen, ","); got != "UNREGISTERED,UNREGISTERED+error,ENABLED" {
		t.Errorf("hook saw %q, want the failed start reported", got)
	}
}
