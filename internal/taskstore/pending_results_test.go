package taskstore

import (
	"os"
	"path/filepath"
	"testing"
)

// writeDropFile writes a drop file the way ndagent-plugin-install.sh does: to a
// temporary name in the same directory that does not end in .json, then a
// rename, so a drain polling the directory never reads it half written (it
// quarantines a file it cannot parse).
func writeDropFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Errorf("mkdir: %v", err)
		return ""
	}
	tmp, err := os.CreateTemp(dir, "."+name+".")
	if err != nil {
		t.Errorf("create: %v", err)
		return ""
	}
	_, werr := tmp.WriteString(content)
	cerr := tmp.Close()
	p := filepath.Join(dir, name)
	if werr != nil || cerr != nil || os.Chmod(tmp.Name(), 0o600) != nil || os.Rename(tmp.Name(), p) != nil {
		t.Errorf("write %s: %v %v", name, werr, cerr)
	}
	return p
}

func TestReconcileDropFiles_AppliesSuccess(t *testing.T) {
	dir := t.TempDir()
	s := newTestStore(t)
	if err := s.Begin("plugin-1", "PLUGIN_INSTALL", LifecycleHelperResolves); err != nil {
		t.Fatalf("Begin: %v", err)
	}

	writeDropFile(t, dir, "plugin-1.json", `{"task_id":"plugin-1","exit_code":0,"message":"installed v1.5.2"}`)

	n, err := ReconcileDropFiles(dir, s)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 applied, got %d", n)
	}

	rows, _ := s.Undelivered()
	if len(rows) != 1 || rows[0].Status != StatusCompleted || rows[0].Message != "installed v1.5.2" {
		t.Fatalf("unexpected row: %+v", rows)
	}

	if _, err := os.Stat(filepath.Join(dir, "plugin-1.json")); !os.IsNotExist(err) {
		t.Fatalf("expected drop file to be deleted, stat err = %v", err)
	}
}

func TestReconcileDropFiles_FailureExitCode(t *testing.T) {
	dir := t.TempDir()
	s := newTestStore(t)
	_ = s.Begin("plugin-1", "PLUGIN_INSTALL", LifecycleHelperResolves)

	writeDropFile(t, dir, "plugin-1.json", `{"task_id":"plugin-1","exit_code":1,"message":"pkg install failed"}`)

	if _, err := ReconcileDropFiles(dir, s); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	rows, _ := s.Undelivered()
	if len(rows) != 1 || rows[0].Status != StatusFailed {
		t.Fatalf("expected FAILED row, got %+v", rows)
	}
}

func TestReconcileDropFiles_MalformedQuarantined(t *testing.T) {
	dir := t.TempDir()
	s := newTestStore(t)

	bad := writeDropFile(t, dir, "broken.json", `{not json`)

	n, err := ReconcileDropFiles(dir, s)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 applied, got %d", n)
	}
	// Original is gone, moved to quarantine/.
	if _, err := os.Stat(bad); !os.IsNotExist(err) {
		t.Fatalf("expected source removed, stat err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "quarantine", "broken.json")); err != nil {
		t.Fatalf("expected quarantined file, stat err = %v", err)
	}
}

func TestReconcileDropFiles_MissingDirIsNoop(t *testing.T) {
	s := newTestStore(t)
	n, err := ReconcileDropFiles(filepath.Join(t.TempDir(), "does-not-exist"), s)
	if err != nil {
		t.Fatalf("Reconcile on missing dir: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 applied, got %d", n)
	}
}

func TestReconcileDropFiles_IgnoresNonJSON(t *testing.T) {
	dir := t.TempDir()
	s := newTestStore(t)

	writeDropFile(t, dir, "notes.txt", "not a drop file")
	writeDropFile(t, dir, "good.json", `{"task_id":"a","exit_code":0}`)

	n, err := ReconcileDropFiles(dir, s)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 applied, got %d", n)
	}
	// The .txt file is left in place.
	if _, err := os.Stat(filepath.Join(dir, "notes.txt")); err != nil {
		t.Fatalf("expected .txt file untouched: %v", err)
	}
}

func TestReconcileDropFiles_MissingTaskID(t *testing.T) {
	dir := t.TempDir()
	s := newTestStore(t)

	writeDropFile(t, dir, "no-id.json", `{"exit_code":0}`)

	n, err := ReconcileDropFiles(dir, s)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 applied, got %d", n)
	}
	if _, err := os.Stat(filepath.Join(dir, "quarantine", "no-id.json")); err != nil {
		t.Fatalf("expected quarantined file: %v", err)
	}
}
