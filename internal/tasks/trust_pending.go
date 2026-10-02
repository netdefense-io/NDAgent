package tasks

// Renewals whose reloads have not run yet. A renewal is written to the device
// first and its services are reloaded after; an agent that stops between the
// two would leave the services on the old certificate for good, since the next
// pass finds the object unchanged. So a renewal is recorded on disk as soon as
// it is known, and dropped once its reloads ran. A web GUI restart a renewal
// asked for is recorded until the restart has started, which is after the
// SYNC result is sent.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/netdefense-io/ndagent/internal/logging"
)

// trustPendingPath is where the pending renewals are kept: refids and names,
// nothing secret. Tests replace it.
var trustPendingPath = "/var/db/ndagent/trust-pending-reloads.json"

// trustPendingMu serializes the file between a SYNC and the web GUI restart.
var trustPendingMu sync.Mutex

// trustPending is the file's content.
type trustPending struct {
	CAs   []renewedTrust `json:"cas,omitempty"`
	Certs []renewedTrust `json:"certs,omitempty"`
	// WebGUI is a web GUI restart asked for and not started yet.
	WebGUI bool `json:"webgui,omitempty"`
}

func (p trustPending) empty() bool {
	return len(p.CAs) == 0 && len(p.Certs) == 0 && !p.WebGUI
}

// loadTrustPending reads the pending renewals; none when there is no file.
func loadTrustPending() (trustPending, error) {
	trustPendingMu.Lock()
	defer trustPendingMu.Unlock()
	return readTrustPending()
}

// saveTrustPending replaces the file, or removes it when nothing is pending.
func saveTrustPending(p trustPending) error {
	trustPendingMu.Lock()
	defer trustPendingMu.Unlock()
	return writeTrustPending(p)
}

// clearPendingWebGUIRestart records that the web GUI restart has started.
func clearPendingWebGUIRestart() {
	trustPendingMu.Lock()
	defer trustPendingMu.Unlock()
	p, err := readTrustPending()
	if err == nil && p.WebGUI {
		p.WebGUI = false
		err = writeTrustPending(p)
	}
	if err != nil {
		logging.Named("SYNC_API").Warnw("Trust: could not record that the web GUI restart started", "error", err)
	}
}

func readTrustPending() (trustPending, error) {
	var p trustPending
	data, err := os.ReadFile(trustPendingPath)
	if errors.Is(err, fs.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return p, err
	}
	if err := json.Unmarshal(data, &p); err != nil {
		return trustPending{}, fmt.Errorf("decode %s: %w", trustPendingPath, err)
	}
	return p, nil
}

func writeTrustPending(p trustPending) error {
	if p.empty() {
		err := os.Remove(trustPendingPath)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	dir := filepath.Dir(trustPendingPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".trust-pending.*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), trustPendingPath)
}
