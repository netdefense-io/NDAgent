package network

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/netdefense-io/ndagent/internal/signing"
	"github.com/netdefense-io/ndagent/internal/state"
)

// newTestDispatcher builds a bare CommandDispatcher wired to a fresh state
// store on disk at t.TempDir() — enough to exercise
// checkDispatchReplayBarrier without a real WebSocket connection.
func newTestDispatcher(t *testing.T) *CommandDispatcher {
	t.Helper()
	s, err := state.New(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	return &CommandDispatcher{state: s}
}

func envelopeWithDispatchSeq(taskID int64, seq uint64) *signing.DecodedEnvelope {
	return &signing.DecodedEnvelope{
		TaskID:         taskID,
		DispatchSeq:    seq,
		HasDispatchSeq: true,
	}
}

func envelopeWithoutDispatchSeq(taskID int64) *signing.DecodedEnvelope {
	return &signing.DecodedEnvelope{
		TaskID:         taskID,
		HasDispatchSeq: false,
	}
}

// TestDispatchSeqBarrier_StrictlyIncreasingAccepted_LEqRejected_GapsTolerated
// covers the core dispatch_seq barrier contract: strict `>`, gap-tolerant.
func TestDispatchSeqBarrier_StrictlyIncreasingAccepted_LEqRejected_GapsTolerated(t *testing.T) {
	d := newTestDispatcher(t)

	// First envelope with dispatch_seq=1 (first minted value) accepted.
	if err := d.checkDispatchReplayBarrier(envelopeWithDispatchSeq(100, 1)); err != nil {
		t.Fatalf("seq=1 should be accepted: %v", err)
	}

	// Strictly increasing: 2 accepted.
	if err := d.checkDispatchReplayBarrier(envelopeWithDispatchSeq(101, 2)); err != nil {
		t.Fatalf("seq=2 should be accepted: %v", err)
	}

	// Equal to last accepted (2) must be rejected as replay.
	if err := d.checkDispatchReplayBarrier(envelopeWithDispatchSeq(102, 2)); !errors.Is(err, errDispatchReplay) {
		t.Fatalf("seq=2 repeated should be rejected as replay, got: %v", err)
	}

	// Lower than last accepted (2) must be rejected as replay.
	if err := d.checkDispatchReplayBarrier(envelopeWithDispatchSeq(103, 1)); !errors.Is(err, errDispatchReplay) {
		t.Fatalf("seq=1 (stale) should be rejected as replay, got: %v", err)
	}

	// Gap-tolerant: jumping from 2 to 5 is accepted (dropped/skipped
	// numbers are fine — only non-increasing is rejected).
	if err := d.checkDispatchReplayBarrier(envelopeWithDispatchSeq(104, 5)); err != nil {
		t.Fatalf("seq=5 after seq=2 (gap) should be accepted: %v", err)
	}
	if got := d.state.LastDispatchSeq(); got != 5 {
		t.Errorf("LastDispatchSeq() = %d, want 5", got)
	}

	// Another gap: 5 -> 8.
	if err := d.checkDispatchReplayBarrier(envelopeWithDispatchSeq(105, 8)); err != nil {
		t.Fatalf("seq=8 after seq=5 (gap) should be accepted: %v", err)
	}
	if got := d.state.LastDispatchSeq(); got != 8 {
		t.Errorf("LastDispatchSeq() = %d, want 8", got)
	}
}

// TestDispatchSeqBarrier_XM12Repro is the XM-12 repro at the agent layer:
// seq 5 accepted -> seq 6 accepted -> a late seq 5 rejected, BUT a
// task_id-only envelope (no dispatch_seq) is still governed by the
// task_id barrier, independently.
func TestDispatchSeqBarrier_XM12Repro(t *testing.T) {
	d := newTestDispatcher(t)

	if err := d.checkDispatchReplayBarrier(envelopeWithDispatchSeq(1000, 5)); err != nil {
		t.Fatalf("seq=5 should be accepted: %v", err)
	}
	if err := d.checkDispatchReplayBarrier(envelopeWithDispatchSeq(1001, 6)); err != nil {
		t.Fatalf("seq=6 should be accepted: %v", err)
	}
	// Late/replayed seq=5 rejected.
	if err := d.checkDispatchReplayBarrier(envelopeWithDispatchSeq(999, 5)); !errors.Is(err, errDispatchReplay) {
		t.Fatalf("late seq=5 should be rejected as replay, got: %v", err)
	}

	// A task_id-only envelope (old-NDManager style, no dispatch_seq) is
	// governed by the independent task_id barrier, which hasn't been
	// touched by any of the above (all dispatch_seq envelopes). Starting
	// task_id barrier is 0, so task_id=1 is accepted.
	if err := d.checkDispatchReplayBarrier(envelopeWithoutDispatchSeq(1)); err != nil {
		t.Fatalf("task_id=1 (no dispatch_seq) should be accepted against untouched task_id barrier: %v", err)
	}
	// A repeat of that same task_id is now rejected via the task_id
	// barrier.
	if err := d.checkDispatchReplayBarrier(envelopeWithoutDispatchSeq(1)); !errors.Is(err, errDispatchReplay) {
		t.Fatalf("task_id=1 repeated should be rejected as replay via task_id barrier, got: %v", err)
	}
}

// TestDispatchSeqBarrier_AbsentFallsBackToTaskIDBarrier proves old-NDManager
// compatibility: when dispatch_seq is never present, behavior is exactly
// the pre-XM-12 task_id barrier (strict >, persisted, replay rejected).
func TestDispatchSeqBarrier_AbsentFallsBackToTaskIDBarrier(t *testing.T) {
	d := newTestDispatcher(t)

	if err := d.checkDispatchReplayBarrier(envelopeWithoutDispatchSeq(10)); err != nil {
		t.Fatalf("task_id=10 should be accepted: %v", err)
	}
	if got := d.state.LastExecutedTaskID(); got != 10 {
		t.Errorf("LastExecutedTaskID() = %d, want 10", got)
	}
	// dispatch_seq barrier must remain untouched (0) — no cross-talk.
	if got := d.state.LastDispatchSeq(); got != 0 {
		t.Errorf("LastDispatchSeq() = %d, want 0 (untouched by task_id-only envelopes)", got)
	}

	if err := d.checkDispatchReplayBarrier(envelopeWithoutDispatchSeq(10)); !errors.Is(err, errDispatchReplay) {
		t.Fatalf("task_id=10 repeated should be rejected as replay, got: %v", err)
	}
	if err := d.checkDispatchReplayBarrier(envelopeWithoutDispatchSeq(9)); !errors.Is(err, errDispatchReplay) {
		t.Fatalf("task_id=9 (lower) should be rejected as replay, got: %v", err)
	}
	if err := d.checkDispatchReplayBarrier(envelopeWithoutDispatchSeq(11)); err != nil {
		t.Fatalf("task_id=11 should be accepted: %v", err)
	}
}

// TestDispatchSeqBarrier_PersistsAcrossRestart simulates a restart by
// reloading a fresh state.Store from the same on-disk path and confirms
// both barriers hold their ground.
func TestDispatchSeqBarrier_PersistsAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	s, err := state.New(path)
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	d := &CommandDispatcher{state: s}

	if err := d.checkDispatchReplayBarrier(envelopeWithDispatchSeq(1, 3)); err != nil {
		t.Fatalf("seq=3 should be accepted: %v", err)
	}
	if err := d.checkDispatchReplayBarrier(envelopeWithoutDispatchSeq(50)); err != nil {
		t.Fatalf("task_id=50 (no dispatch_seq) should be accepted: %v", err)
	}

	// "Restart": reload state from disk into a new Store + Dispatcher.
	reloaded, err := state.New(path)
	if err != nil {
		t.Fatalf("reload state.New: %v", err)
	}
	d2 := &CommandDispatcher{state: reloaded}

	// Barrier still holds post-restart: replays rejected.
	if err := d2.checkDispatchReplayBarrier(envelopeWithDispatchSeq(2, 3)); !errors.Is(err, errDispatchReplay) {
		t.Fatalf("seq=3 replay after restart should be rejected, got: %v", err)
	}
	if err := d2.checkDispatchReplayBarrier(envelopeWithoutDispatchSeq(50)); !errors.Is(err, errDispatchReplay) {
		t.Fatalf("task_id=50 replay after restart should be rejected, got: %v", err)
	}

	// And forward progress still works post-restart.
	if err := d2.checkDispatchReplayBarrier(envelopeWithDispatchSeq(3, 4)); err != nil {
		t.Fatalf("seq=4 after restart should be accepted: %v", err)
	}
	if err := d2.checkDispatchReplayBarrier(envelopeWithoutDispatchSeq(51)); err != nil {
		t.Fatalf("task_id=51 after restart should be accepted: %v", err)
	}
}

// TestDispatchSeqBarrier_NoCrossContamination is the core XM-12 fix
// assertion: a dispatch_seq envelope whose task_id is LOWER than the
// already-persisted last_executed_task_id is still ACCEPTED, because the
// two barriers are independent and a present dispatch_seq always wins.
func TestDispatchSeqBarrier_NoCrossContamination(t *testing.T) {
	d := newTestDispatcher(t)

	// Advance the task_id barrier via an immediate task with a HIGH
	// task_id (as XM-12 describes: an immediate task fires after a
	// deferred/scheduled task was already minted with a lower id).
	if err := d.checkDispatchReplayBarrier(envelopeWithoutDispatchSeq(1001)); err != nil {
		t.Fatalf("task_id=1001 should be accepted: %v", err)
	}
	if got := d.state.LastExecutedTaskID(); got != 1001 {
		t.Fatalf("LastExecutedTaskID() = %d, want 1001", got)
	}

	// Now the deferred/scheduled task activates: task_id=1000 (LOWER
	// than last_executed_task_id=1001) but it carries a valid,
	// strictly-increasing dispatch_seq. Under the old global task_id
	// barrier this would have been silently dropped (1000 <= 1001) —
	// that's exactly XM-12. With dispatch_seq present, the task_id
	// barrier must be skipped entirely and this envelope accepted.
	if err := d.checkDispatchReplayBarrier(envelopeWithDispatchSeq(1000, 1)); err != nil {
		t.Fatalf("XM-12 case: task_id=1000 (< last_executed=1001) with dispatch_seq=1 should be ACCEPTED, got: %v", err)
	}
	if got := d.state.LastDispatchSeq(); got != 1 {
		t.Errorf("LastDispatchSeq() = %d, want 1", got)
	}
	// task_id barrier must be untouched by the dispatch_seq envelope —
	// still 1001, proving no cross-contamination in either direction.
	if got := d.state.LastExecutedTaskID(); got != 1001 {
		t.Errorf("LastExecutedTaskID() = %d, want 1001 (untouched by dispatch_seq envelope)", got)
	}
}
