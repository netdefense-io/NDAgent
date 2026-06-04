package taskstore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type sentResponse struct {
	taskID  string
	status  string
	message string
}

type stubResponder struct {
	sent   []sentResponse
	failOn map[string]error
}

func (s *stubResponder) SendTaskResponse(taskID, status, message string, data map[string]interface{}) error {
	if err, ok := s.failOn[taskID]; ok {
		return err
	}
	s.sent = append(s.sent, sentResponse{taskID, status, message})
	return nil
}

// noopChecker is a PluginInstallChecker that always returns "" (not installed).
// Used in tests that don't need the pkg-check path.
var noopChecker PluginInstallChecker = func(_ context.Context, _, _ string) (string, error) {
	return "", nil
}

func TestDrain_ReconcilesDropFilesResolvesStuckAndReplays(t *testing.T) {
	// Speed up the race-wait so the test doesn't block for 5 seconds.
	origWait := pluginInstallDropWait
	origInterval := pluginInstallDropPollInterval
	pluginInstallDropWait = 20 * time.Millisecond
	pluginInstallDropPollInterval = 5 * time.Millisecond
	t.Cleanup(func() {
		pluginInstallDropWait = origWait
		pluginInstallDropPollInterval = origInterval
	})

	store := newTestStore(t)
	withClock(t, time.Unix(1_716_336_000, 0))

	// Row 1: a clean terminal row already in the registry (came from
	// SendTaskResponse on a previous boot, but wire send failed).
	_ = store.Begin("ping-1", "PING", LifecycleSynchronous)
	_ = store.Complete("ping-1", StatusCompleted, "pong", nil)

	// Row 2: a stuck IN_PROGRESS REBOOT — should resolve to COMPLETED.
	_ = store.Begin("reboot-1", "REBOOT", LifecycleRestartCompletes)

	// Row 3: a stuck PLUGIN_INSTALL whose drop file IS present —
	// should be reconciled before ResolveStuck runs.
	_ = store.Begin("plugin-good", "PLUGIN_INSTALL", LifecycleHelperResolves)
	dropDir := t.TempDir()
	writeDropFile(t, dropDir, "plugin-good.json", `{"task_id":"plugin-good","exit_code":0,"message":"pkg ok"}`)

	// Row 4: a stuck PLUGIN_INSTALL with NO drop file and noopChecker
	// (not installed) — should fall through to FAILED.
	_ = store.Begin("plugin-bad", "PLUGIN_INSTALL", LifecycleHelperResolves)

	resp := &stubResponder{}
	sent, err := DrainUndelivered(context.Background(), store, dropDir, resp, nil, noopChecker)
	if err != nil {
		t.Fatalf("DrainUndelivered: %v", err)
	}
	if sent != 4 {
		t.Fatalf("expected 4 sent, got %d", sent)
	}

	got := map[string]sentResponse{}
	for _, s := range resp.sent {
		got[s.taskID] = s
	}

	cases := []struct {
		id     string
		status string
		// msgContains: non-empty means we only check substring, not equality.
		msgContains string
		msgExact    string
	}{
		{id: "ping-1", status: StatusCompleted, msgExact: "pong"},
		{id: "reboot-1", status: StatusCompleted, msgExact: "Device returned after restart"},
		{id: "plugin-good", status: StatusCompleted, msgExact: "pkg ok"},
		// plugin-bad has no metadata → falls through to the no-meta path → FAILED with
		// the generic message (same as the old ResolveStuck behaviour).
		{id: "plugin-bad", status: StatusFailed, msgExact: "helper did not produce result file"},
	}
	for _, c := range cases {
		g, ok := got[c.id]
		if !ok {
			t.Errorf("missing send for %s", c.id)
			continue
		}
		if g.status != c.status {
			t.Errorf("%s: got status %q, want %q", c.id, g.status, c.status)
		}
		if c.msgExact != "" && g.message != c.msgExact {
			t.Errorf("%s: got message %q, want %q", c.id, g.message, c.msgExact)
		}
		if c.msgContains != "" && !strings.Contains(g.message, c.msgContains) {
			t.Errorf("%s: message %q does not contain %q", c.id, g.message, c.msgContains)
		}
	}

	// All rows are now delivered → Undelivered() returns empty.
	leftover, _ := store.Undelivered()
	if len(leftover) != 0 {
		t.Fatalf("expected 0 undelivered after drain, got %d", len(leftover))
	}
}

func TestDrain_PerSendFailureDoesNotAbort(t *testing.T) {
	store := newTestStore(t)
	withClock(t, time.Unix(1_716_336_000, 0))

	_ = store.Begin("a", "PING", LifecycleSynchronous)
	_ = store.Complete("a", StatusCompleted, "", nil)
	_ = store.Begin("b", "PING", LifecycleSynchronous)
	_ = store.Complete("b", StatusCompleted, "", nil)
	_ = store.Begin("c", "PING", LifecycleSynchronous)
	_ = store.Complete("c", StatusCompleted, "", nil)

	resp := &stubResponder{failOn: map[string]error{"b": errors.New("wire down")}}
	sent, err := DrainUndelivered(context.Background(), store, t.TempDir(), resp, nil, nil)
	if err == nil {
		t.Fatalf("expected non-nil error from failed send")
	}
	if sent != 2 {
		t.Fatalf("expected 2 successful sends, got %d", sent)
	}

	// a and c are delivered; b stays undelivered for the next boot.
	rows, _ := store.Undelivered()
	if len(rows) != 1 || rows[0].TaskID != "b" {
		t.Fatalf("expected b still undelivered, got %+v", rows)
	}
}

func TestDrain_EmptyStoreIsNoop(t *testing.T) {
	store := newTestStore(t)
	resp := &stubResponder{}
	sent, err := DrainUndelivered(context.Background(), store, t.TempDir(), resp, nil, nil)
	if err != nil {
		t.Fatalf("DrainUndelivered: %v", err)
	}
	if sent != 0 {
		t.Fatalf("expected 0 sent on empty store, got %d", sent)
	}
}

// TestDrain_PluginInstall_DropFileLate verifies case (a): the drop file
// arrives during the race-wait window → COMPLETED via the late reconcile.
func TestDrain_PluginInstall_DropFileLate(t *testing.T) {
	// Speed up the poll interval to keep the test fast.
	origInterval := pluginInstallDropPollInterval
	pluginInstallDropPollInterval = 10 * time.Millisecond
	t.Cleanup(func() { pluginInstallDropPollInterval = origInterval })

	store := newTestStore(t)
	withClock(t, time.Unix(1_716_336_000, 0))

	dropDir := t.TempDir()
	_ = store.Begin("plugin-late", "PLUGIN_INSTALL", LifecycleHelperResolves)

	// Write the drop file after a short delay (simulating the helper
	// finishing just after the agent restarted).
	go func() {
		time.Sleep(30 * time.Millisecond)
		writeDropFile(t, dropDir, "plugin-late.json",
			`{"task_id":"plugin-late","exit_code":0,"message":"installed v1.6.0"}`)
	}()

	resp := &stubResponder{}
	// checker returns not-installed so the pkg path would fail if reached;
	// the drop file should arrive before we need to fall through.
	checker := func(_ context.Context, _, _ string) (string, error) { return "", nil }
	sent, err := DrainUndelivered(context.Background(), store, dropDir, resp, nil, checker)
	if err != nil {
		t.Fatalf("DrainUndelivered: %v", err)
	}
	if sent != 1 {
		t.Fatalf("expected 1 sent, got %d", sent)
	}
	if resp.sent[0].status != StatusCompleted {
		t.Fatalf("expected COMPLETED, got %s (msg=%s)", resp.sent[0].status, resp.sent[0].message)
	}
	if resp.sent[0].message != "installed v1.6.0" {
		t.Fatalf("unexpected message: %s", resp.sent[0].message)
	}
}

// TestDrain_PluginInstall_NoDropFilePkgMatch verifies case (b): no drop file
// but pkg reports the target version is installed → COMPLETED.
func TestDrain_PluginInstall_NoDropFilePkgMatch(t *testing.T) {
	origWait := pluginInstallDropWait
	origInterval := pluginInstallDropPollInterval
	pluginInstallDropWait = 10 * time.Millisecond
	pluginInstallDropPollInterval = 5 * time.Millisecond
	t.Cleanup(func() {
		pluginInstallDropWait = origWait
		pluginInstallDropPollInterval = origInterval
	})

	store := newTestStore(t)
	withClock(t, time.Unix(1_716_336_000, 0))

	_ = store.Begin("pi-match", "PLUGIN_INSTALL", LifecycleHelperResolves)
	_ = store.SetTaskMeta("pi-match", PluginInstallMeta{
		PackageName:   "os-netdefense",
		TargetVersion: "1.6.0",
	})

	checker := func(_ context.Context, pkg, _ string) (string, error) {
		if pkg == "os-netdefense" {
			return "1.6.0", nil
		}
		return "", nil
	}

	resp := &stubResponder{}
	sent, err := DrainUndelivered(context.Background(), store, t.TempDir(), resp, nil, checker)
	if err != nil {
		t.Fatalf("DrainUndelivered: %v", err)
	}
	if sent != 1 {
		t.Fatalf("expected 1 sent, got %d", sent)
	}
	if resp.sent[0].status != StatusCompleted {
		t.Fatalf("expected COMPLETED, got %s (msg=%s)", resp.sent[0].status, resp.sent[0].message)
	}
	if !strings.Contains(resp.sent[0].message, "1.6.0") {
		t.Fatalf("expected version in message, got %s", resp.sent[0].message)
	}
}

// TestDrain_PluginInstall_NoDropFilePkgMismatch verifies case (c): no drop
// file and pkg reports a version that does not match the target → FAILED.
func TestDrain_PluginInstall_NoDropFilePkgMismatch(t *testing.T) {
	origWait := pluginInstallDropWait
	origInterval := pluginInstallDropPollInterval
	pluginInstallDropWait = 10 * time.Millisecond
	pluginInstallDropPollInterval = 5 * time.Millisecond
	t.Cleanup(func() {
		pluginInstallDropWait = origWait
		pluginInstallDropPollInterval = origInterval
	})

	store := newTestStore(t)
	withClock(t, time.Unix(1_716_336_000, 0))

	_ = store.Begin("pi-mismatch", "PLUGIN_INSTALL", LifecycleHelperResolves)
	_ = store.SetTaskMeta("pi-mismatch", PluginInstallMeta{
		PackageName:   "os-netdefense",
		TargetVersion: "1.6.0",
	})

	// Installed version is the OLD version — install failed to complete.
	checker := func(_ context.Context, _, _ string) (string, error) {
		return "1.5.9", nil
	}

	resp := &stubResponder{}
	sent, err := DrainUndelivered(context.Background(), store, t.TempDir(), resp, nil, checker)
	if err != nil {
		t.Fatalf("DrainUndelivered: %v", err)
	}
	if sent != 1 {
		t.Fatalf("expected 1 sent, got %d", sent)
	}
	if resp.sent[0].status != StatusFailed {
		t.Fatalf("expected FAILED, got %s (msg=%s)", resp.sent[0].status, resp.sent[0].message)
	}
}

// TestDrain_PluginInstall_OtherTypesUnaffected verifies case (d): other
// LifecycleHelperResolves task types are NOT processed by the PLUGIN_INSTALL
// race-check logic and still get the generic "helper did not produce result
// file" treatment from ResolveStuck.
func TestDrain_PluginInstall_OtherTypesUnaffected(t *testing.T) {
	origWait := pluginInstallDropWait
	pluginInstallDropWait = 10 * time.Millisecond
	t.Cleanup(func() { pluginInstallDropWait = origWait })

	store := newTestStore(t)
	withClock(t, time.Unix(1_716_336_000, 0))

	// A hypothetical future task type that also uses LifecycleHelperResolves
	// but is NOT PLUGIN_INSTALL — the drain must not apply pkg-check to it.
	_ = store.Begin("other-helper", "OTHER_HELPER_TASK", LifecycleHelperResolves)

	// Checker that would return a version (we want to confirm it is NOT called).
	checkerCalled := false
	checker := func(_ context.Context, _, _ string) (string, error) {
		checkerCalled = true
		return "1.0.0", nil
	}

	resp := &stubResponder{}
	sent, err := DrainUndelivered(context.Background(), store, t.TempDir(), resp, nil, checker)
	if err != nil {
		t.Fatalf("DrainUndelivered: %v", err)
	}
	if sent != 1 {
		t.Fatalf("expected 1 sent, got %d", sent)
	}
	if resp.sent[0].status != StatusFailed {
		t.Fatalf("expected FAILED for other helper type, got %s", resp.sent[0].status)
	}
	if resp.sent[0].message != "helper did not produce result file" {
		t.Fatalf("expected generic message for other type, got %q", resp.sent[0].message)
	}
	if checkerCalled {
		t.Fatal("pkg checker was called for a non-PLUGIN_INSTALL task type — violates scope constraint")
	}
}

