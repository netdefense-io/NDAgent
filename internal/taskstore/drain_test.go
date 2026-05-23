package taskstore

import (
	"context"
	"errors"
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

func TestDrain_ReconcilesDropFilesResolvesStuckAndReplays(t *testing.T) {
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

	// Row 4: a stuck PLUGIN_INSTALL with NO drop file — should fail
	// over to "helper did not produce result file".
	_ = store.Begin("plugin-bad", "PLUGIN_INSTALL", LifecycleHelperResolves)

	resp := &stubResponder{}
	sent, err := DrainUndelivered(context.Background(), store, dropDir, resp, nil)
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
		id, status, msg string
	}{
		{"ping-1", StatusCompleted, "pong"},
		{"reboot-1", StatusCompleted, "Device returned after restart"},
		{"plugin-good", StatusCompleted, "pkg ok"},
		{"plugin-bad", StatusFailed, "helper did not produce result file"},
	}
	for _, c := range cases {
		g, ok := got[c.id]
		if !ok {
			t.Errorf("missing send for %s", c.id)
			continue
		}
		if g.status != c.status || g.message != c.msg {
			t.Errorf("%s: got %+v, want status=%s msg=%s", c.id, g, c.status, c.msg)
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
	sent, err := DrainUndelivered(context.Background(), store, t.TempDir(), resp, nil)
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
	sent, err := DrainUndelivered(context.Background(), store, t.TempDir(), resp, nil)
	if err != nil {
		t.Fatalf("DrainUndelivered: %v", err)
	}
	if sent != 0 {
		t.Fatalf("expected 0 sent on empty store, got %d", sent)
	}
}

