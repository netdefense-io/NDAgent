package taskstore

import (
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := OpenInMemory()
	if err != nil {
		t.Fatalf("OpenInMemory: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// withClock overrides nowFn for a test. Restores on cleanup.
func withClock(t *testing.T, start time.Time) func(delta time.Duration) {
	t.Helper()
	orig := nowFn
	current := start
	nowFn = func() time.Time { return current }
	t.Cleanup(func() { nowFn = orig })
	return func(delta time.Duration) {
		current = current.Add(delta)
	}
}

func TestBeginCompleteMarkDelivered_RoundTrip(t *testing.T) {
	s := newTestStore(t)
	advance := withClock(t, time.Unix(1_700_000_000, 0))

	if err := s.Begin("task-1", "PING", LifecycleSynchronous); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	advance(time.Second)
	if err := s.Complete("task-1", StatusCompleted, "pong", nil); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	rows, err := s.Undelivered()
	if err != nil {
		t.Fatalf("Undelivered: %v", err)
	}
	if len(rows) != 1 || rows[0].TaskID != "task-1" || rows[0].Status != StatusCompleted {
		t.Fatalf("unexpected undelivered: %+v", rows)
	}

	advance(time.Second)
	if err := s.MarkDelivered("task-1"); err != nil {
		t.Fatalf("MarkDelivered: %v", err)
	}
	rows, err = s.Undelivered()
	if err != nil {
		t.Fatalf("Undelivered after deliver: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("expected 0 undelivered after MarkDelivered, got %d", len(rows))
	}
}

func TestBegin_IdempotentReBeginOnInProgress(t *testing.T) {
	s := newTestStore(t)
	withClock(t, time.Unix(1_700_000_000, 0))

	if err := s.Begin("task-1", "SYNC", LifecycleSynchronous); err != nil {
		t.Fatalf("Begin 1: %v", err)
	}
	if err := s.Begin("task-1", "SYNC", LifecycleSynchronous); err != nil {
		t.Fatalf("Begin 2 (idempotent): %v", err)
	}
}

func TestBegin_RejectsAlreadyTerminal(t *testing.T) {
	s := newTestStore(t)
	withClock(t, time.Unix(1_700_000_000, 0))

	if err := s.Begin("task-1", "SYNC", LifecycleSynchronous); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := s.Complete("task-1", StatusCompleted, "done", nil); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	err := s.Begin("task-1", "SYNC", LifecycleSynchronous)
	if !errors.Is(err, ErrAlreadyTerminal) {
		t.Fatalf("expected ErrAlreadyTerminal, got %v", err)
	}
}

func TestComplete_RejectsInProgressStatus(t *testing.T) {
	s := newTestStore(t)
	if err := s.Complete("task-1", StatusInProgress, "x", nil); err == nil {
		t.Fatalf("expected error for IN_PROGRESS status")
	}
}

func TestComplete_DefensiveInsertWithoutBegin(t *testing.T) {
	s := newTestStore(t)
	withClock(t, time.Unix(1_700_000_000, 0))

	if err := s.Complete("orphan", StatusCompleted, "from drop file", nil); err != nil {
		t.Fatalf("Complete without Begin: %v", err)
	}
	rows, _ := s.Undelivered()
	if len(rows) != 1 || rows[0].TaskID != "orphan" {
		t.Fatalf("expected orphan row, got %+v", rows)
	}
}

func TestUndelivered_OldestFirst(t *testing.T) {
	s := newTestStore(t)
	advance := withClock(t, time.Unix(1_700_000_000, 0))

	for i, id := range []string{"a", "b", "c"} {
		if err := s.Begin(id, "PING", LifecycleSynchronous); err != nil {
			t.Fatalf("Begin %s: %v", id, err)
		}
		if err := s.Complete(id, StatusCompleted, "", nil); err != nil {
			t.Fatalf("Complete %s: %v", id, err)
		}
		// Each task's started_at is i seconds apart.
		advance(time.Second)
		_ = i
	}
	rows, err := s.Undelivered()
	if err != nil {
		t.Fatalf("Undelivered: %v", err)
	}
	if len(rows) != 3 || rows[0].TaskID != "a" || rows[1].TaskID != "b" || rows[2].TaskID != "c" {
		t.Fatalf("expected a,b,c, got %+v", rows)
	}
}

func TestResolveStuck_PerCategoryOutcome(t *testing.T) {
	s := newTestStore(t)
	withClock(t, time.Unix(1_700_000_000, 0))

	if err := s.Begin("sync-stuck", "SYNC", LifecycleSynchronous); err != nil {
		t.Fatalf("Begin sync: %v", err)
	}
	if err := s.Begin("reboot-stuck", "REBOOT", LifecycleRestartCompletes); err != nil {
		t.Fatalf("Begin reboot: %v", err)
	}
	if err := s.Begin("plugin-stuck", "PLUGIN_INSTALL", LifecycleHelperResolves); err != nil {
		t.Fatalf("Begin plugin: %v", err)
	}

	n, err := s.ResolveStuck()
	if err != nil {
		t.Fatalf("ResolveStuck: %v", err)
	}
	if n != 3 {
		t.Fatalf("expected 3 rows resolved, got %d", n)
	}

	rows, err := s.Undelivered()
	if err != nil {
		t.Fatalf("Undelivered: %v", err)
	}
	got := map[string]struct {
		status, message string
	}{}
	for _, r := range rows {
		got[r.TaskID] = struct{ status, message string }{r.Status, r.Message}
	}

	want := map[string]struct {
		status, message string
	}{
		"sync-stuck":   {StatusFailed, "agent restarted mid-task"},
		"reboot-stuck": {StatusCompleted, "Device returned after restart"},
		"plugin-stuck": {StatusFailed, "helper did not produce result file"},
	}
	for id, w := range want {
		g, ok := got[id]
		if !ok {
			t.Errorf("missing resolved row %s", id)
			continue
		}
		if g.status != w.status || g.message != w.message {
			t.Errorf("%s: got %+v, want %+v", id, g, w)
		}
	}
}

func TestResolveStuck_PreservesAlreadyTerminal(t *testing.T) {
	s := newTestStore(t)
	withClock(t, time.Unix(1_700_000_000, 0))

	if err := s.Begin("done", "PING", LifecycleSynchronous); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := s.Complete("done", StatusCompleted, "pong", nil); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	n, err := s.ResolveStuck()
	if err != nil {
		t.Fatalf("ResolveStuck: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 resolved, got %d", n)
	}
	rows, _ := s.Undelivered()
	if len(rows) != 1 || rows[0].Status != StatusCompleted || rows[0].Message != "pong" {
		t.Fatalf("ResolveStuck mutated a terminal row: %+v", rows)
	}
}

func TestRetention_KeepsNewest100Delivered(t *testing.T) {
	s := newTestStore(t)
	advance := withClock(t, time.Unix(1_700_000_000, 0))

	// 105 delivered rows, started_at strictly increasing.
	for i := 0; i < 105; i++ {
		id := "delivered-" + strconv.Itoa(i)
		if err := s.Begin(id, "PING", LifecycleSynchronous); err != nil {
			t.Fatalf("Begin %s: %v", id, err)
		}
		if err := s.Complete(id, StatusCompleted, "", nil); err != nil {
			t.Fatalf("Complete %s: %v", id, err)
		}
		if err := s.MarkDelivered(id); err != nil {
			t.Fatalf("MarkDelivered %s: %v", id, err)
		}
		advance(time.Second)
	}

	got := mustCountRows(t, s, "SELECT COUNT(*) FROM task_states WHERE delivered_at IS NOT NULL")
	if got != MaxDeliveredRows {
		t.Fatalf("retention: expected %d delivered rows, got %d", MaxDeliveredRows, got)
	}

	// The 5 oldest should be gone; the newest MaxDeliveredRows should remain.
	for i := 0; i < 5; i++ {
		id := "delivered-" + strconv.Itoa(i)
		if mustCountRows(t, s, fmt.Sprintf("SELECT COUNT(*) FROM task_states WHERE task_id = '%s'", id)) != 0 {
			t.Errorf("expected %s to be pruned", id)
		}
	}
	for i := 5; i < 105; i++ {
		id := "delivered-" + strconv.Itoa(i)
		if mustCountRows(t, s, fmt.Sprintf("SELECT COUNT(*) FROM task_states WHERE task_id = '%s'", id)) != 1 {
			t.Errorf("expected %s to be retained", id)
		}
	}
}

func TestRetention_NeverDeletesUndelivered(t *testing.T) {
	s := newTestStore(t)
	advance := withClock(t, time.Unix(1_700_000_000, 0))

	// 200 undelivered rows (all in COMPLETED but never MarkDelivered).
	for i := 0; i < 200; i++ {
		id := "undeliv-" + strconv.Itoa(i)
		if err := s.Begin(id, "PING", LifecycleSynchronous); err != nil {
			t.Fatalf("Begin: %v", err)
		}
		if err := s.Complete(id, StatusCompleted, "", nil); err != nil {
			t.Fatalf("Complete: %v", err)
		}
		advance(time.Second)
	}

	// One delivered row to trigger retention.
	if err := s.Begin("delivered", "PING", LifecycleSynchronous); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := s.Complete("delivered", StatusCompleted, "", nil); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if err := s.MarkDelivered("delivered"); err != nil {
		t.Fatalf("MarkDelivered: %v", err)
	}

	undeliv := mustCountRows(t, s, "SELECT COUNT(*) FROM task_states WHERE delivered_at IS NULL")
	if undeliv != 200 {
		t.Fatalf("retention deleted undelivered rows: %d remain (want 200)", undeliv)
	}
}

func mustCountRows(t *testing.T, s *Store, query string) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(query).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}
