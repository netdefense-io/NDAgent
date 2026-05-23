package taskstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// DefaultPendingResultsDir is the drop-file directory written by helper
// scripts (today: ndagent-plugin-install.sh) and read by the boot-time
// drain. Sibling of /var/db/ndagent/tasks.db so a single chmod 0700 on
// /var/db/ndagent covers both.
const DefaultPendingResultsDir = "/var/db/ndagent/pending-results"

// DropFile is the wire shape that helper scripts write. Helpers don't
// know the agent's lifecycle types; they just record what pkg(8)
// returned. The reconciler maps exit_code → terminal status.
type DropFile struct {
	TaskID   string `json:"task_id"`
	ExitCode int    `json:"exit_code"`
	Message  string `json:"message,omitempty"`
}

// ReconcileDropFiles processes every JSON file in `dir`, applying each
// to the store as a terminal Complete and removing the file on success.
// Malformed files are moved to `dir/quarantine/` so a poisoned file
// doesn't loop on every boot. Returns the number of files successfully
// applied.
//
// Safe to call when `dir` doesn't exist (returns 0, nil). The drain
// step calls this BEFORE ResolveStuck so helper-resolved tasks whose
// drop file is present get their real outcome instead of the fallback.
func ReconcileDropFiles(dir string, store *Store) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("read pending-results dir %s: %w", dir, err)
	}

	applied := 0
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		path := filepath.Join(dir, e.Name())
		ok, err := applyDropFile(path, store)
		switch {
		case err != nil:
			// Don't fail the whole drain over one bad file; quarantine
			// and move on. The drain still wants to deliver other rows.
			_ = quarantine(dir, path)
		case ok:
			_ = os.Remove(path)
			applied++
		default:
			// well-formed but applying failed (unknown task_id, etc.) —
			// log via caller's logger and drop the file so it doesn't
			// loop. Use quarantine so operators can inspect.
			_ = quarantine(dir, path)
		}
	}
	return applied, nil
}

// applyDropFile parses one file and applies it to the store.
//
// Returns (true, nil) on full success, (false, err) on parse/IO error
// (caller quarantines), (false, nil) when the file is well-formed but
// the store couldn't apply it (e.g., task is already terminal — also
// quarantined so the operator can see it).
func applyDropFile(path string, store *Store) (bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	var df DropFile
	if err := json.Unmarshal(raw, &df); err != nil {
		return false, err
	}
	if df.TaskID == "" {
		return false, errors.New("drop file missing task_id")
	}

	status := StatusCompleted
	if df.ExitCode != 0 {
		status = StatusFailed
	}
	message := df.Message
	if message == "" {
		if df.ExitCode == 0 {
			message = "Helper completed successfully"
		} else {
			message = fmt.Sprintf("Helper exited with code %d", df.ExitCode)
		}
	}

	if err := store.Complete(df.TaskID, status, message, nil); err != nil {
		return false, nil
	}
	return true, nil
}

func quarantine(dir, path string) error {
	qDir := filepath.Join(dir, "quarantine")
	if err := os.MkdirAll(qDir, 0o700); err != nil {
		return err
	}
	return os.Rename(path, filepath.Join(qDir, filepath.Base(path)))
}
