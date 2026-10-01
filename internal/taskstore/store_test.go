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

// rowState reads a row's status and message straight from the table.
func rowState(t *testing.T, s *Store, id string) (status, message string) {
	t.Helper()
	if err := s.db.QueryRow("SELECT status, message FROM task_states WHERE task_id = ?", id).Scan(&status, &message); err != nil {
		t.Fatalf("read row %s: %v", id, err)
	}
	return status, message
}

// FIRMWARE_UPGRADE's outcome is decided from the device's state, so the
// blanket rule must leave it alone while it still resolves every other type
// exactly as before.
func TestResolveStuck_DeferredTypeIsLeftInProgress(t *testing.T) {
	s := newTestStore(t)
	withClock(t, time.Unix(1_700_000_000, 0))

	for _, r := range []struct {
		id, typ string
		lc      Lifecycle
	}{
		{"fw", "FIRMWARE_UPGRADE", LifecycleRestartCompletes},
		{"reboot", "REBOOT", LifecycleRestartCompletes},
		{"sync", "SYNC", LifecycleSynchronous},
		{"plugin", "PLUGIN_INSTALL", LifecycleHelperResolves},
	} {
		if err := s.Begin(r.id, r.typ, r.lc); err != nil {
			t.Fatalf("Begin %s: %v", r.id, err)
		}
	}

	n, err := s.ResolveStuck(WithDeferredTypes("FIRMWARE_UPGRADE"))
	if err != nil {
		t.Fatalf("ResolveStuck: %v", err)
	}
	if n != 3 {
		t.Fatalf("resolved %d rows, want 3 (every row but the firmware one)", n)
	}

	want := map[string][2]string{
		"fw":     {StatusInProgress, ""},
		"reboot": {StatusCompleted, "Device returned after restart"},
		"sync":   {StatusFailed, "agent restarted mid-task"},
		"plugin": {StatusFailed, "helper did not produce result file"},
	}
	for id, w := range want {
		status, message := rowState(t, s, id)
		if status != w[0] || message != w[1] {
			t.Errorf("%s: got (%s, %q), want (%s, %q)", id, status, message, w[0], w[1])
		}
	}
}

// A row written by an agent that predates the option carries whatever
// lifecycle that agent chose; the deferral must not depend on it.
func TestResolveStuck_DeferredTypeIgnoresTheStoredLifecycle(t *testing.T) {
	s := newTestStore(t)
	withClock(t, time.Unix(1_700_000_000, 0))

	for id, lc := range map[string]Lifecycle{
		"fw-restart":     LifecycleRestartCompletes,
		"fw-synchronous": LifecycleSynchronous,
		"fw-helper":      LifecycleHelperResolves,
	} {
		if err := s.Begin(id, "FIRMWARE_UPGRADE", lc); err != nil {
			t.Fatalf("Begin %s: %v", id, err)
		}
	}

	n, err := s.ResolveStuck(WithDeferredTypes("FIRMWARE_UPGRADE"))
	if err != nil {
		t.Fatalf("ResolveStuck: %v", err)
	}
	if n != 0 {
		t.Fatalf("resolved %d firmware rows, want 0", n)
	}
	for _, id := range []string{"fw-restart", "fw-synchronous", "fw-helper"} {
		if status, _ := rowState(t, s, id); status != StatusInProgress {
			t.Errorf("%s: status %s, want IN_PROGRESS", id, status)
		}
	}
}

// A SYNC that is queued behind another already has an IN_PROGRESS row. A plain
// reconnect drain used to fail it as "agent restarted mid-task" although the
// process never restarted and the SYNC was still going to run.
func TestResolveStuck_LiveRowIsLeftAlone(t *testing.T) {
	s := newTestStore(t)
	withClock(t, time.Unix(1_700_000_000, 0))

	for _, id := range []string{"queued-sync", "orphan-sync"} {
		if err := s.Begin(id, "SYNC", LifecycleSynchronous); err != nil {
			t.Fatalf("Begin %s: %v", id, err)
		}
	}
	live := func(id string) bool { return id == "queued-sync" }

	n, err := s.ResolveStuck(WithLiveness(live))
	if err != nil {
		t.Fatalf("ResolveStuck: %v", err)
	}
	if n != 1 {
		t.Fatalf("resolved %d rows, want 1 (only the orphan)", n)
	}
	if status, _ := rowState(t, s, "queued-sync"); status != StatusInProgress {
		t.Errorf("queued-sync: status %s, want IN_PROGRESS", status)
	}
	if status, message := rowState(t, s, "orphan-sync"); status != StatusFailed || message != "agent restarted mid-task" {
		t.Errorf("orphan-sync: got (%s, %q), want the mid-task failure", status, message)
	}
}

// The scan and the write are separate statements: a handler that finishes in
// between must keep the outcome it recorded.
func TestResolveStuck_KeepsAnOutcomeRecordedAfterTheScan(t *testing.T) {
	s := newTestStore(t)
	withClock(t, time.Unix(1_700_000_000, 0))

	if err := s.Begin("racing", "SYNC", LifecycleSynchronous); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	finishesMeanwhile := func(id string) bool {
		if err := s.Complete(id, StatusCompleted, "handler result", nil); err != nil {
			t.Fatalf("Complete: %v", err)
		}
		return false
	}

	n, err := s.ResolveStuck(WithLiveness(finishesMeanwhile))
	if err != nil {
		t.Fatalf("ResolveStuck: %v", err)
	}
	if n != 0 {
		t.Fatalf("resolved %d rows, want 0", n)
	}
	if status, message := rowState(t, s, "racing"); status != StatusCompleted || message != "handler result" {
		t.Fatalf("handler outcome was overwritten: got (%s, %q)", status, message)
	}
}

func TestCompleteIfInProgress_WinsOnceAndNeverOverwrites(t *testing.T) {
	s := newTestStore(t)
	withClock(t, time.Unix(1_700_000_000, 0))

	if err := s.Begin("t", "FIRMWARE_UPGRADE", LifecycleRestartCompletes); err != nil {
		t.Fatalf("Begin: %v", err)
	}

	won, err := s.CompleteIfInProgress("t", StatusCompleted, "first", []byte(`{"a":1}`))
	if err != nil || !won {
		t.Fatalf("first call: won=%v err=%v, want true,nil", won, err)
	}
	won, err = s.CompleteIfInProgress("t", StatusFailed, "second", nil)
	if err != nil || won {
		t.Fatalf("second call: won=%v err=%v, want false,nil", won, err)
	}
	if status, message := rowState(t, s, "t"); status != StatusCompleted || message != "first" {
		t.Fatalf("row was overwritten: (%s, %q)", status, message)
	}

	rows, err := s.Undelivered()
	if err != nil || len(rows) != 1 || string(rows[0].ResultData) != `{"a":1}` {
		t.Fatalf("the winning write must be replayable with its data: rows=%+v err=%v", rows, err)
	}
}

func TestCompleteIfInProgress_UnknownRowAndBadStatus(t *testing.T) {
	s := newTestStore(t)

	won, err := s.CompleteIfInProgress("ghost", StatusCompleted, "x", nil)
	if err != nil || won {
		t.Fatalf("unknown row: won=%v err=%v, want false,nil (it must not create one)", won, err)
	}
	if n := mustCountRows(t, s, "SELECT COUNT(*) FROM task_states"); n != 0 {
		t.Fatalf("CompleteIfInProgress created %d row(s)", n)
	}
	if _, err := s.CompleteIfInProgress("ghost", StatusInProgress, "x", nil); err == nil {
		t.Fatal("IN_PROGRESS is not a terminal status and must be rejected")
	}
}

func TestGetTaskMeta_RoundTripAndAbsent(t *testing.T) {
	s := newTestStore(t)
	withClock(t, time.Unix(1_700_000_000, 0))

	type meta struct {
		Mode string `json:"mode"`
		N    int    `json:"n"`
	}
	if err := s.Begin("with", "FIRMWARE_UPGRADE", LifecycleRestartCompletes); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := s.Begin("without", "FIRMWARE_UPGRADE", LifecycleRestartCompletes); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := s.SetTaskMeta("with", meta{Mode: "minor", N: 7}); err != nil {
		t.Fatalf("SetTaskMeta: %v", err)
	}

	var got meta
	found, err := s.GetTaskMeta("with", &got)
	if err != nil || !found || got != (meta{Mode: "minor", N: 7}) {
		t.Fatalf("round trip: found=%v err=%v got=%+v", found, err, got)
	}

	for _, id := range []string{"without", "no-such-task"} {
		var m meta
		found, err := s.GetTaskMeta(id, &m)
		if err != nil || found {
			t.Errorf("%s: found=%v err=%v, want false,nil", id, found, err)
		}
	}
}

func TestGetTaskMeta_MalformedBlobCountsAsAbsent(t *testing.T) {
	s := newTestStore(t)
	withClock(t, time.Unix(1_700_000_000, 0))

	if err := s.Begin("t", "FIRMWARE_UPGRADE", LifecycleRestartCompletes); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if _, err := s.db.Exec("UPDATE task_states SET task_meta = ? WHERE task_id = ?", "{not json", "t"); err != nil {
		t.Fatalf("seed blob: %v", err)
	}

	var m struct{ Mode string }
	found, err := s.GetTaskMeta("t", &m)
	if err != nil || found {
		t.Fatalf("found=%v err=%v, want false,nil", found, err)
	}
}

func TestGet_ReportsTheRowWhereverItStands(t *testing.T) {
	s := newTestStore(t)
	withClock(t, time.Unix(1_700_000_000, 0))

	if _, found, err := s.Get("nope"); err != nil || found {
		t.Fatalf("Get of a missing task: found=%v err=%v, want false,nil", found, err)
	}

	_ = s.Begin("t", "FIRMWARE_UPGRADE", LifecycleRestartCompletes)
	rec, found, err := s.Get("t")
	if err != nil || !found || rec.Status != StatusInProgress || rec.Delivered || rec.TaskType != "FIRMWARE_UPGRADE" ||
		rec.Lifecycle != LifecycleRestartCompletes || !rec.StartedAt.Equal(time.Unix(1_700_000_000, 0)) {
		t.Fatalf("in progress: %+v found=%v err=%v", rec, found, err)
	}

	_ = s.Complete("t", StatusCompleted, "done", []byte(`{"a":1}`))
	rec, _, _ = s.Get("t")
	if rec.Status != StatusCompleted || rec.Message != "done" || string(rec.ResultData) != `{"a":1}` || rec.Delivered || rec.EndedAt.IsZero() {
		t.Fatalf("terminal: %+v", rec)
	}

	_ = s.MarkDelivered("t")
	if rec, _, _ = s.Get("t"); !rec.Delivered {
		t.Fatalf("delivered: %+v", rec)
	}
}
