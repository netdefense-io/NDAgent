package telemetry

// heavy_store.go — the heavy snapshot kept on disk between agent processes, so
// the first heartbeat after a restart, a boot or an upgrade of the agent
// carries the last known blocks instead of none.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// DefaultHeavyCachePath is where the snapshot is kept, next to the agent's
// other state. The decommission removes the directory, and with it the file.
const DefaultHeavyCachePath = "/var/db/ndagent/heavy.json"

// heavyCacheVersion is the file's format. A file of any other version is
// ignored.
const heavyCacheVersion = 1

// heavyCacheFile is the file's content: the snapshot as it goes on the wire,
// as_of and collected_at included.
type heavyCacheFile struct {
	V     int            `json:"v"`
	Heavy *HeavySnapshot `json:"heavy"`
}

// Restore loads the snapshot the previous process saved, for the heartbeats
// to carry until the first gather replaces it. Call it before Run. Every block
// keeps its own as_of, except one stamped more than clockAhead after the
// clock, which is stamped now in memory (restamp); the file is left as it is.
// The update reading is dropped when it describes another release than the
// installed one, or the installed one cannot be read, or when it is older
// than updatesMaxAge: only a check rewrites it, so after an update it
// describes the release that was replaced.
func (h *HeavyCollector) Restore() {
	if h.cachePath == "" {
		return
	}
	data, err := os.ReadFile(h.cachePath)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err != nil {
		h.log.Warnw("heavy-telemetry: cannot read the saved snapshot", "path", h.cachePath, "error", err)
		return
	}
	var file heavyCacheFile
	if err := json.Unmarshal(data, &file); err != nil || file.V != heavyCacheVersion || file.Heavy == nil {
		h.log.Warnw("heavy-telemetry: ignoring a saved snapshot this agent cannot use",
			"path", h.cachePath, "version", file.V, "error", err)
		return
	}

	now := h.now()
	snap := restamp(file.Heavy, now)
	restamped := snap != file.Heavy
	installed := h.installedVersion()
	updatesDropped := snap.Updates != nil &&
		(!describes(snap.Updates, installed) || !young(snap.Updates.AsOf, updatesMaxAge, now))
	if updatesDropped {
		snap.Updates = nil
	}
	if snap.Services == nil && snap.Updates == nil && snap.Certs == nil {
		h.log.Infow("heavy-telemetry: the saved snapshot holds nothing still usable", "path", h.cachePath)
		return
	}

	h.mu.Lock()
	h.cache = snap
	h.mu.Unlock()
	if snap.Updates != nil {
		h.reading = snap.Updates.FirmwareStatus
	}
	h.log.Infow("heavy-telemetry: restored the saved snapshot",
		"collected", now.Sub(time.Unix(int64(snap.CollectedAt), 0)).Round(time.Second).String()+" ago",
		"services", snap.Services != nil,
		"updates", snap.Updates != nil,
		"updates_dropped", updatesDropped,
		"certs", snap.Certs != nil,
		"restamped", restamped,
	)
}

// save writes the snapshot for the next process: plain telemetry (service
// names, certificate descriptions and expiries, update counts), mode 0600,
// replaced atomically, every block with the stamp it was collected with. The
// directory is not created: when it is gone the agent's state was removed,
// and nothing should be written back.
func (h *HeavyCollector) save(snap *HeavySnapshot) {
	if h.cachePath == "" {
		return
	}
	data, err := json.Marshal(heavyCacheFile{V: heavyCacheVersion, Heavy: asCollected(snap)})
	if err == nil {
		err = writeFileAtomic(h.cachePath, data)
	}
	if err != nil {
		h.log.Warnw("heavy-telemetry: cannot save the snapshot", "path", h.cachePath, "error", err)
	}
}

// RemoveCache deletes the saved snapshot. Call it once Run has returned.
func (h *HeavyCollector) RemoveCache() error {
	if h.cachePath == "" {
		return nil
	}
	if err := os.Remove(h.cachePath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}
