// Package status writes a small JSON snapshot of the agent's runtime
// state (version + WebSocket connection status) to a well-known path so
// the OPNsense plugin GUI can render it on the NetDefense Settings page
// without having to talk to NDBroker itself.
//
// Single producer (the agent process), single file (/var/run/ndagent.status,
// mode 0644). Writes are atomic via tempfile+rename. File mtime is the
// freshness signal — readers should treat snapshots older than ~60s as
// stale (the heartbeat refreshes it every interval).
package status

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DefaultPath is the on-disk location written by the agent.
const DefaultPath = "/var/run/ndagent.status"

// State is the connection lifecycle state surfaced to the GUI.
type State string

const (
	StateConnecting   State = "connecting"
	StateConnected    State = "connected"
	StateDisconnected State = "disconnected"
)

// snapshot is the JSON shape written to disk.
type snapshot struct {
	Version    string    `json:"version"`
	GitCommit  string    `json:"git_commit"`
	DeviceUUID string    `json:"device_uuid"`
	State      State     `json:"state"`
	Server     string    `json:"server,omitempty"`
	Since      time.Time `json:"since"`
	UpdatedAt  time.Time `json:"updated_at"`
	LastError  string    `json:"last_error,omitempty"`
}

// Writer serializes status snapshots to a file. Safe for concurrent use.
type Writer struct {
	path string

	mu   sync.Mutex
	snap snapshot
}

// NewWriter constructs a Writer with static identity fields (version,
// commit, device UUID) baked in. State is initialized to "connecting".
func NewWriter(path, version, gitCommit, deviceUUID string) *Writer {
	now := time.Now().UTC()
	return &Writer{
		path: path,
		snap: snapshot{
			Version:    version,
			GitCommit:  gitCommit,
			DeviceUUID: deviceUUID,
			State:      StateConnecting,
			Since:      now,
			UpdatedAt:  now,
		},
	}
}

// MarkConnecting records that the agent is mid-connect/registration. Safe
// to call repeatedly during reconnect backoff — Since only advances on
// state changes.
func (w *Writer) MarkConnecting() error {
	return w.transition(StateConnecting, "", "")
}

// MarkConnected records a successful WebSocket auth, with the server URL.
func (w *Writer) MarkConnected(serverURL string) error {
	return w.transition(StateConnected, serverURL, "")
}

// MarkDisconnected records that the WebSocket session ended. Reason is
// optional human-readable context (network err, auth fail, etc.).
func (w *Writer) MarkDisconnected(reason string) error {
	return w.transition(StateDisconnected, "", reason)
}

// Touch refreshes UpdatedAt without changing state — used by the
// heartbeat loop so a stalled agent shows up as stale to the GUI even if
// it never crashed cleanly.
func (w *Writer) Touch() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.snap.UpdatedAt = time.Now().UTC()
	return w.persist()
}

func (w *Writer) transition(state State, server, reason string) error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now().UTC()
	if w.snap.State != state {
		w.snap.Since = now
	}
	w.snap.State = state
	w.snap.Server = server
	w.snap.LastError = reason
	w.snap.UpdatedAt = now
	return w.persist()
}

// persist writes the current snapshot atomically. Caller holds w.mu.
func (w *Writer) persist() error {
	data, err := json.MarshalIndent(w.snap, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(w.path)
	tmp, err := os.CreateTemp(dir, ".ndagent.status.*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Chmod(tmpPath, 0o644); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, w.path)
}
