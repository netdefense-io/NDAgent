package pathfinder

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// A relay at its cap of unregistered connections answers 503 with a
// Retry-After. Connect dials again for one of at most 30 s, twice at most, and
// not past its context's deadline; any other refusal fails at once.
func TestConnect_ARelayBusyAnswerIsRetriedWithinBounds(t *testing.T) {
	for _, tc := range []struct {
		name       string
		busy       int
		status     int
		retryAfter string
		deadline   time.Duration
		wantOK     bool
		wantDials  int32
		wantWaits  []time.Duration
	}{
		{"busy twice, then registered", 2, 503, "15", 0, true, 3, []time.Duration{15 * time.Second, 15 * time.Second}},
		{"busy three times", 3, 503, "15", 0, false, 3, []time.Duration{15 * time.Second, 15 * time.Second}},
		{"the longest wait taken", 1, 503, "30", 0, true, 2, []time.Duration{30 * time.Second}},
		{"a wait over 30 s", 1, 503, "31", 0, false, 1, nil},
		{"no Retry-After", 1, 503, "", 0, false, 1, nil},
		{"an HTTP-date Retry-After", 1, 503, "Wed, 21 Oct 2026 07:28:00 GMT", 0, false, 1, nil},
		{"another status", 1, 502, "15", 0, false, 1, nil},
		{"a wait past the deadline", 1, 503, "15", 5 * time.Second, false, 1, nil},
		{"a wait within the deadline", 1, 503, "15", time.Minute, true, 2, []time.Duration{15 * time.Second}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var waits []time.Duration
			prev := relayBusySleep
			relayBusySleep = func(ctx context.Context, d time.Duration) error {
				waits = append(waits, d)
				return nil
			}
			t.Cleanup(func() { relayBusySleep = prev })

			var dials atomic.Int32
			ok := newTestPathfinderServer(t, func(conn *websocket.Conn) {})
			t.Cleanup(ok.Close)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if int(dials.Add(1)) <= tc.busy {
					if tc.retryAfter != "" {
						w.Header().Set("Retry-After", tc.retryAfter)
					}
					w.WriteHeader(tc.status)
					return
				}
				ok.Config.Handler.ServeHTTP(w, r)
			}))
			t.Cleanup(srv.Close)

			ctx := context.Background()
			if tc.deadline > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tc.deadline)
				t.Cleanup(cancel)
			}
			client := NewClient(wsURL(srv.URL), "session-key", "device-id", nil)
			t.Cleanup(func() { client.Close() })
			err := client.Connect(ctx)
			if (err == nil) != tc.wantOK {
				t.Fatalf("Connect: %v, want ok %v", err, tc.wantOK)
			}
			if got := dials.Load(); got != tc.wantDials {
				t.Errorf("%d dials, want %d", got, tc.wantDials)
			}
			if !reflect.DeepEqual(waits, tc.wantWaits) {
				t.Errorf("waits %v, want %v", waits, tc.wantWaits)
			}
		})
	}
}

// A context that ends during the wait ends the dial with its error.
func TestConnect_ACancelledWaitStopsDialling(t *testing.T) {
	var dials atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dials.Add(1)
		w.Header().Set("Retry-After", "15")
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithCancel(context.Background())
	prev := relayBusySleep
	relayBusySleep = func(c context.Context, d time.Duration) error {
		cancel()
		return prev(c, d)
	}
	t.Cleanup(func() { relayBusySleep = prev })

	client := NewClient(wsURL(srv.URL), "session-key", "device-id", nil)
	t.Cleanup(func() { client.Close() })
	if err := client.Connect(ctx); err == nil {
		t.Fatal("Connect succeeded")
	}
	if got := dials.Load(); got != 1 {
		t.Errorf("%d dials, want 1", got)
	}
}

// A client closed during the wait does not dial again.
func TestConnect_AClientClosedDuringTheWaitDoesNotDialAgain(t *testing.T) {
	var dials atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dials.Add(1)
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	client := NewClient(wsURL(srv.URL), "session-key", "device-id", nil)
	prev := relayBusySleep
	relayBusySleep = func(context.Context, time.Duration) error {
		client.Close()
		return nil
	}
	t.Cleanup(func() { relayBusySleep = prev })

	if err := client.Connect(context.Background()); err == nil {
		t.Fatal("Connect succeeded")
	}
	if got := dials.Load(); got != 1 {
		t.Errorf("%d dials, want 1", got)
	}
}

// A refused upgrade names the relay's status and Retry-After in the error, in
// the form clients match (#185), instead of a bare "bad handshake".
func TestConnect_ARefusedUpgradeNamesTheRelaysAnswer(t *testing.T) {
	for _, tc := range []struct {
		status     int
		retryAfter string
		want       string
	}{
		{429, "15", "dial failed: the relay answered HTTP 429 (Retry-After: 15): websocket: bad handshake"},
		{403, "", "dial failed: the relay answered HTTP 403: websocket: bad handshake"},
		{503, "120", "dial failed: the relay answered HTTP 503 (Retry-After: 120): websocket: bad handshake"},
		{429, "Wed, 21 Oct 2026 07:28:00 GMT", "dial failed: the relay answered HTTP 429: websocket: bad handshake"},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if tc.retryAfter != "" {
				w.Header().Set("Retry-After", tc.retryAfter)
			}
			w.WriteHeader(tc.status)
		}))
		client := NewClient(wsURL(srv.URL), "session-key", "device-id", nil)
		err := client.Connect(context.Background())
		client.Close()
		srv.Close()
		if err == nil || err.Error() != tc.want {
			t.Errorf("HTTP %d: %v, want %q", tc.status, err, tc.want)
		}
	}
}

// A 101 whose handshake headers are wrong is no refusal: the dial error is
// gorilla's alone, with no "the relay answered HTTP 101".
func TestRelayAnswered_A101IsNotNamed(t *testing.T) {
	if got := relayAnswered(&http.Response{StatusCode: http.StatusSwitchingProtocols}); got != "" {
		t.Errorf("101: %q, want nothing", got)
	}
	if got := relayAnswered(nil); got != "" {
		t.Errorf("no response: %q", got)
	}
}
