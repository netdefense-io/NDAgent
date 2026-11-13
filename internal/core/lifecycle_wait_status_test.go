package core

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/network"
	"github.com/netdefense-io/ndagent/internal/status"
)

func statusState(t *testing.T, path string) (string, time.Time) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var snap struct {
		State     string    `json:"state"`
		UpdatedAt time.Time `json:"updated_at"`
	}
	if err := json.Unmarshal(data, &snap); err != nil {
		t.Fatal(err)
	}
	return snap.State, snap.UpdatedAt
}

// The registration wait's statuses become the status file's states: waiting
// for approval, disabled, and connecting for anything else (#179).
func TestNoteRegistrationStatus_NamesTheWait(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ndagent.status")
	l := &LifecycleManager{status: status.NewWriter(path, "1.0.0", "abc", "221f3268-0000-4000-8000-000000000001")}
	// A failed check after a PENDING answer is disconnected, with its error,
	// not still waiting for an approval the control plane cannot be asked about.
	l.noteRegistrationStatus(network.StatusPending, nil)
	l.noteRegistrationStatus("", errors.New("dial tcp: no route to host"))
	if got, _ := statusState(t, path); got != "disconnected" {
		t.Errorf("a failed check after PENDING: state %q, want disconnected", got)
	}
	for registration, want := range map[string]string{
		network.StatusPending:      "pending",
		network.StatusDisabled:     "disabled",
		network.StatusEnabled:      "connecting",
		network.StatusUnregistered: "connecting",
	} {
		l.noteRegistrationStatus(registration, nil)
		if got, _ := statusState(t, path); got != want {
			t.Errorf("%s: state %q, want %q", registration, got, want)
		}
	}
}

// The status file stays fresh while the wait sleeps between checks, which a
// disabled device spaces up to five minutes apart; the plugin reads a file
// older than 120 s as stale.
func TestTouchStatusWhileWaiting_KeepsTheFileFresh(t *testing.T) {
	orig := statusTouchInterval
	statusTouchInterval = 20 * time.Millisecond
	t.Cleanup(func() { statusTouchInterval = orig })

	path := filepath.Join(t.TempDir(), "ndagent.status")
	l := &LifecycleManager{status: status.NewWriter(path, "1.0.0", "abc", "221f3268-0000-4000-8000-000000000001")}
	l.noteRegistrationStatus(network.StatusDisabled, nil)
	_, first := statusState(t, path)

	stop := l.touchStatusWhileWaiting()
	time.Sleep(100 * time.Millisecond)
	stop()
	state, touched := statusState(t, path)
	if state != "disabled" || !touched.After(first) {
		t.Errorf("after the wait: state %q, updated %v (first %v); want disabled, refreshed", state, touched, first)
	}

	time.Sleep(60 * time.Millisecond)
	if _, after := statusState(t, path); !after.Equal(touched) {
		t.Error("the file was still touched after stop")
	}
}

// A wait that stops checking is left to go stale: the touch keeps the file
// fresh only while the wait shows progress.
func TestTouchStatusWhileWaiting_AStuckWaitGoesStale(t *testing.T) {
	origInterval, origQuiet := statusTouchInterval, waitQuietLimit
	statusTouchInterval, waitQuietLimit = 10*time.Millisecond, 60*time.Millisecond
	t.Cleanup(func() { statusTouchInterval, waitQuietLimit = origInterval, origQuiet })

	path := filepath.Join(t.TempDir(), "ndagent.status")
	l := &LifecycleManager{status: status.NewWriter(path, "1.0.0", "abc", "221f3268-0000-4000-8000-000000000001")}
	stop := l.touchStatusWhileWaiting()
	l.noteRegistrationStatus(network.StatusPending, nil)
	time.Sleep(300 * time.Millisecond)
	stop()

	_, last := statusState(t, path)
	if since := time.Since(last); since < 150*time.Millisecond {
		t.Errorf("the file was touched %v ago, after the wait had been quiet past the limit", since)
	}
}
