package tasks

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// resetOPNsenseVersionWarnings clears the process-global warn state between
// tests. Lives here rather than in the production file so it does not ship.
// Resets the fields, not the struct: replacing the whole value while holding
// its mutex would leave the deferred Unlock releasing a different, unlocked
// mutex.
func resetOPNsenseVersionWarnings() {
	opnsenseVersionWarnings.mu.Lock()
	defer opnsenseVersionWarnings.mu.Unlock()
	opnsenseVersionWarnings.knownSupported = false
	opnsenseVersionWarnings.warnedUnsupported = false
	opnsenseVersionWarnings.warnedUnknown = false
}

// versionServer serves /core/firmware/info, counting reads so the
// "stop checking once supported" behaviour is observable.
type versionServer struct {
	mu      sync.Mutex
	calls   int
	version string
	fail    bool
}

func (v *versionServer) client(t *testing.T) *opnapi.Client {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/core/firmware/info", func(w http.ResponseWriter, r *http.Request) {
		v.mu.Lock()
		v.calls++
		fail, version := v.fail, v.version
		v.mu.Unlock()

		if fail {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"product_version": version})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return opnapi.NewClient(srv.URL, "key", "secret", true)
}

func (v *versionServer) callCount() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.calls
}

// TestWarnIfOPNsenseBelowFloor_SupportedStopsChecking pins that a supported
// device costs one API call for the life of the process, not one per sync.
// OPNsense versions only move forward, so the determination cannot go stale.
func TestWarnIfOPNsenseBelowFloor_SupportedStopsChecking(t *testing.T) {
	resetOPNsenseVersionWarnings()
	t.Cleanup(resetOPNsenseVersionWarnings)

	srv := &versionServer{version: "26.1.9"}
	client := srv.client(t)

	for i := 0; i < 5; i++ {
		warnIfOPNsenseBelowFloor(context.Background(), client)
	}

	if got := srv.callCount(); got != 1 {
		t.Errorf("firmware info read %d times, want 1 (a supported release must not be re-checked every sync)", got)
	}
}

// TestWarnIfOPNsenseBelowFloor_UnsupportedKeepsChecking pins the other side:
// below the floor the answer CAN change, because the device may be upgraded
// without restarting the agent, so the check repeats. The log line does not.
func TestWarnIfOPNsenseBelowFloor_UnsupportedKeepsChecking(t *testing.T) {
	resetOPNsenseVersionWarnings()
	t.Cleanup(resetOPNsenseVersionWarnings)

	srv := &versionServer{version: "25.7.9"}
	client := srv.client(t)

	warnIfOPNsenseBelowFloor(context.Background(), client)
	warnIfOPNsenseBelowFloor(context.Background(), client)

	if got := srv.callCount(); got != 2 {
		t.Errorf("firmware info read %d times, want 2 (an unsupported device may be upgraded in place)", got)
	}
	if !opnsenseVersionWarnings.warnedUnsupported {
		t.Error("expected the unsupported warning to have fired")
	}
	if opnsenseVersionWarnings.knownSupported {
		t.Error("25.7.9 must not be recorded as supported")
	}

	// Upgrade in place: the next check must clear the state without a restart.
	srv.mu.Lock()
	srv.version = "26.1.0"
	srv.mu.Unlock()

	warnIfOPNsenseBelowFloor(context.Background(), client)
	if !opnsenseVersionWarnings.knownSupported {
		t.Error("after an in-place upgrade to 26.1 the device must be recognised as supported")
	}
}

// TestWarnIfOPNsenseBelowFloor_UnknownIsItsOwnCategory pins that an
// unreadable version is tracked separately from a too-old one. The two are
// worded differently because unknown is expected to be common, and a message
// that reads like "your device is too old" when the truth is "we could not
// tell" trains people to ignore both.
func TestWarnIfOPNsenseBelowFloor_UnknownIsItsOwnCategory(t *testing.T) {
	resetOPNsenseVersionWarnings()
	t.Cleanup(resetOPNsenseVersionWarnings)

	srv := &versionServer{fail: true}
	client := srv.client(t)

	warnIfOPNsenseBelowFloor(context.Background(), client)
	warnIfOPNsenseBelowFloor(context.Background(), client)

	if !opnsenseVersionWarnings.warnedUnknown {
		t.Error("expected the unknown-version warning to have fired")
	}
	if opnsenseVersionWarnings.warnedUnsupported {
		t.Error("a failed read must NOT be reported as an unsupported version")
	}
	if opnsenseVersionWarnings.knownSupported {
		t.Error("a failed read must not be recorded as supported")
	}
	if got := srv.callCount(); got != 2 {
		t.Errorf("firmware info read %d times, want 2 (a transient failure must not permanently give up)", got)
	}

	// A later success must still be able to resolve the device.
	srv.mu.Lock()
	srv.fail = false
	srv.version = "26.1.9"
	srv.mu.Unlock()

	warnIfOPNsenseBelowFloor(context.Background(), client)
	if !opnsenseVersionWarnings.knownSupported {
		t.Error("a successful read after a failure must resolve the device as supported")
	}
}

// TestWarnIfOPNsenseBelowFloor_NeverBlocks is the operator's constraint: this
// is visibility, not a gate. It returns normally on every path, including a
// nil client and an already-cancelled context, so a sync is never stopped by
// it.
func TestWarnIfOPNsenseBelowFloor_NeverBlocks(t *testing.T) {
	resetOPNsenseVersionWarnings()
	t.Cleanup(resetOPNsenseVersionWarnings)

	warnIfOPNsenseBelowFloor(context.Background(), nil)

	srv := &versionServer{version: "25.7.9"}
	client := srv.client(t)

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	warnIfOPNsenseBelowFloor(cancelled, client)

	// Reaching here at all is the assertion: no panic, no error return, no
	// mechanism by which a caller could be blocked.
}

// TestUnsupportedVersionConsequenceIsActionable pins that the message names
// what the user should go and look for. "Unsupported version" alone tells
// nobody what broke; the whole point of warning instead of gating is that
// the log has to carry the consequence.
func TestUnsupportedVersionConsequenceIsActionable(t *testing.T) {
	for _, want := range []string{"VPN", "firewall rules", "[nd-vpn:"} {
		if !strings.Contains(unsupportedVersionConsequence, want) {
			t.Errorf("consequence text is missing %q; it must say what to look for, not just that the version is unsupported", want)
		}
	}
	if got := minimumSupportedRelease(); got != "26.1" {
		t.Errorf("minimumSupportedRelease() = %q, want 26.1", got)
	}
}
