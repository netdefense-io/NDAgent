package tasks

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
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

// useLocalReleaseSources keeps the release lookup off the real device: the
// version file is absent and opnsense-version fails, so the API is the only
// source left. A test that wants a local source passes its own.
func useLocalReleaseSources(t *testing.T, versionFile string, opnsenseVersion func(*exec.Cmd) ([]byte, error)) {
	t.Helper()
	if versionFile == "" {
		versionFile = filepath.Join(t.TempDir(), "absent")
	}
	t.Cleanup(opnapi.SetVersionFileForTest(versionFile))
	if opnsenseVersion == nil {
		opnsenseVersion = func(*exec.Cmd) ([]byte, error) { return nil, errors.New("opnsense-version is not available") }
	}
	t.Cleanup(opnapi.SetCommandOutputForTest(opnsenseVersion))
}

// versionServer serves the API's release source, /core/firmware/status,
// counting reads so the "stop checking" behaviour is observable. It fails the
// test on any /core/firmware/info request.
type versionServer struct {
	mu      sync.Mutex
	calls   int
	version string
	fail    bool
}

// client returns a client whose only release source is the server.
func (v *versionServer) client(t *testing.T) *opnapi.Client {
	t.Helper()
	useLocalReleaseSources(t, "", nil)
	return v.newClient(t)
}

func (v *versionServer) newClient(t *testing.T) *opnapi.Client {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/core/firmware/info", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the OPNsense release was read from /core/firmware/info")
		http.Error(w, "must not be called", http.StatusGone)
	})
	mux.HandleFunc("/core/firmware/status", func(w http.ResponseWriter, r *http.Request) {
		v.mu.Lock()
		v.calls++
		fail, version := v.fail, v.version
		v.mu.Unlock()

		if fail {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"product": map[string]string{"product_version": version},
		})
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

	srv := &versionServer{version: "26.1.11"}
	client := srv.client(t)

	for i := 0; i < 5; i++ {
		warnIfOPNsenseBelowFloor(context.Background(), client)
	}

	if got := srv.callCount(); got != 1 {
		t.Errorf("release read from the API %d times, want 1 (a supported release must not be re-checked every sync)", got)
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
		t.Errorf("release read from the API %d times, want 2 (an unsupported device may be upgraded in place)", got)
	}
	if !opnsenseVersionWarnings.warnedUnsupported {
		t.Error("expected the unsupported warning to have fired")
	}
	if opnsenseVersionWarnings.knownSupported {
		t.Error("25.7.9 must not be recorded as supported")
	}

	// Upgrade in place: the next check must clear the state without a restart.
	srv.mu.Lock()
	srv.version = "26.1.11"
	srv.mu.Unlock()

	warnIfOPNsenseBelowFloor(context.Background(), client)
	if !opnsenseVersionWarnings.knownSupported {
		t.Error("after an in-place upgrade to 26.1.11 the device must be recognised as supported")
	}
}

// TestWarnIfOPNsenseBelowFloor_UnknownIsItsOwnCategory pins that an
// unreadable version is tracked separately from a too-old one. The two are
// worded differently because a message that reads like "your device is too
// old" when the truth is "we could not tell" trains people to ignore both.
func TestWarnIfOPNsenseBelowFloor_UnknownIsItsOwnCategory(t *testing.T) {
	resetOPNsenseVersionWarnings()
	t.Cleanup(resetOPNsenseVersionWarnings)

	srv := &versionServer{fail: true}
	client := srv.client(t)

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
}

// TestWarnIfOPNsenseBelowFloor_UnknownIsAskedOnce pins that once every source
// has failed the lookup is not repeated on every sync: it would only repeat the
// failure, and the warning has already said so.
func TestWarnIfOPNsenseBelowFloor_UnknownIsAskedOnce(t *testing.T) {
	resetOPNsenseVersionWarnings()
	t.Cleanup(resetOPNsenseVersionWarnings)

	srv := &versionServer{fail: true}
	client := srv.client(t)

	for i := 0; i < 5; i++ {
		warnIfOPNsenseBelowFloor(context.Background(), client)
	}

	if got := srv.callCount(); got != 1 {
		t.Errorf("release read from the API %d times, want 1 (an unknown release must not be re-asked on every sync)", got)
	}
}

// TestWarnIfOPNsenseBelowFloor_CancelledContextIsNotUnknown pins that a sync
// cancelled mid-lookup says nothing about the device: it must not latch the
// unknown state, or one cancelled sync would silence the check for the life of
// the process.
func TestWarnIfOPNsenseBelowFloor_CancelledContextIsNotUnknown(t *testing.T) {
	resetOPNsenseVersionWarnings()
	t.Cleanup(resetOPNsenseVersionWarnings)

	srv := &versionServer{version: "26.1.11"}
	client := srv.client(t)

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	warnIfOPNsenseBelowFloor(cancelled, client)

	if opnsenseVersionWarnings.warnedUnknown {
		t.Fatal("a cancelled context must not be recorded as an unknown release")
	}

	warnIfOPNsenseBelowFloor(context.Background(), client)
	if !opnsenseVersionWarnings.knownSupported {
		t.Error("the next sync must still be able to resolve the device")
	}
}

// TestWarnIfOPNsenseBelowFloor_LocalReleaseNeedsNoAPI pins the common case on a
// real device: the release is read from the box itself, so the API is never
// asked, and once it is known to be supported nothing is read again.
func TestWarnIfOPNsenseBelowFloor_LocalReleaseNeedsNoAPI(t *testing.T) {
	resetOPNsenseVersionWarnings()
	t.Cleanup(resetOPNsenseVersionWarnings)

	versionFile := filepath.Join(t.TempDir(), "core")
	write := func(version string) {
		t.Helper()
		if err := os.WriteFile(versionFile, []byte(`{"product_series":"26.7","product_version":"`+version+`"}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("26.7.4_1")

	useLocalReleaseSources(t, versionFile, nil)
	srv := &versionServer{fail: true}
	client := srv.newClient(t)

	warnIfOPNsenseBelowFloor(context.Background(), client)
	if !opnsenseVersionWarnings.knownSupported {
		t.Fatal("26.7.4_1 read from the version file must be recognised as supported")
	}
	if got := srv.callCount(); got != 0 {
		t.Errorf("the API was asked %d times although the box answered", got)
	}

	write("25.7.9")
	warnIfOPNsenseBelowFloor(context.Background(), client)
	if opnsenseVersionWarnings.warnedUnsupported {
		t.Error("a supported release was read again")
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

// TestWarnIfOPNsenseBelowFloor_PatchLevelFloor: the floor is 26.1.11, so a 26.1
// release before it is unsupported though its series is fine, and a FreeBSD
// revision suffix never lowers a release.
func TestWarnIfOPNsenseBelowFloor_PatchLevelFloor(t *testing.T) {
	tests := []struct {
		version   string
		supported bool
	}{
		{"26.1.10", false},
		{"26.1.9", false},
		{"26.1", false},
		{"26.1.11", true},
		{"26.1.11_1", true},
		{"26.1.12", true},
		{"26.7.5", true},
		{"25.7.11_9", false},
	}
	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			resetOPNsenseVersionWarnings()
			t.Cleanup(resetOPNsenseVersionWarnings)

			srv := &versionServer{version: tt.version}
			client := srv.client(t)

			warnIfOPNsenseBelowFloor(context.Background(), client)

			if opnsenseVersionWarnings.knownSupported != tt.supported {
				t.Errorf("%s: recognised as supported = %v, want %v", tt.version, opnsenseVersionWarnings.knownSupported, tt.supported)
			}
			if opnsenseVersionWarnings.warnedUnsupported == tt.supported {
				t.Errorf("%s: unsupported warning fired = %v, want %v", tt.version, opnsenseVersionWarnings.warnedUnsupported, !tt.supported)
			}
			if opnsenseVersionWarnings.warnedUnknown {
				t.Errorf("%s: a readable release must never be reported as unknown", tt.version)
			}
		})
	}
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
	for _, want := range []string{"administrator rights", "26.1.11"} {
		if !strings.Contains(unsupportedPatchConsequence, want) {
			t.Errorf("the patch consequence is missing %q", want)
		}
	}
	if got := minimumSupportedRelease(); got != "26.1.11" {
		t.Errorf("minimumSupportedRelease() = %q, want 26.1.11", got)
	}
}

// TestUnsupportedConsequenceFollowsTheBand: each band of unsupported releases
// is told the consequence that applies to it, not the other's.
func TestUnsupportedConsequenceFollowsTheBand(t *testing.T) {
	parse := func(v string) opnapi.ProductRelease {
		r, err := opnapi.ParseProductRelease(v)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	for _, v := range []string{"25.7.11_9", "25.1", "24.7.12"} {
		if got := unsupportedConsequenceFor(parse(v)); got != unsupportedVersionConsequence {
			t.Errorf("%s: consequence = %q, want the stranded VPN rules", v, got)
		}
	}
	for _, v := range []string{"26.1.10", "26.1.0", "26.1"} {
		if got := unsupportedConsequenceFor(parse(v)); got != unsupportedPatchConsequence {
			t.Errorf("%s: consequence = %q, want the missing privilege fixes", v, got)
		}
	}
	if !strings.Contains(unknownReleaseConsequence, unsupportedVersionConsequence) || !strings.Contains(unknownReleaseConsequence, unsupportedPatchConsequence) {
		t.Error("an unreadable release must be told both possible consequences")
	}
}
