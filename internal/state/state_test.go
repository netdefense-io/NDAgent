package state

import (
	"path/filepath"
	"testing"
)

func TestLastDispatchSeq_ZeroByDefault(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := s.LastDispatchSeq(); got != 0 {
		t.Errorf("LastDispatchSeq() on fresh store = %d, want 0", got)
	}
}

func TestSetLastDispatchSeq_AdvancesAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	s, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := s.SetLastDispatchSeq(5); err != nil {
		t.Fatalf("SetLastDispatchSeq(5): %v", err)
	}
	if got := s.LastDispatchSeq(); got != 5 {
		t.Errorf("LastDispatchSeq() = %d, want 5", got)
	}

	// Reload from disk (simulated restart) — value must survive.
	reloaded, err := New(path)
	if err != nil {
		t.Fatalf("reload New: %v", err)
	}
	if got := reloaded.LastDispatchSeq(); got != 5 {
		t.Errorf("reloaded LastDispatchSeq() = %d, want 5", got)
	}
}

func TestSetLastDispatchSeq_RefusesNonIncreasing(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.SetLastDispatchSeq(10); err != nil {
		t.Fatalf("SetLastDispatchSeq(10): %v", err)
	}
	if err := s.SetLastDispatchSeq(10); err == nil {
		t.Error("SetLastDispatchSeq(10) after 10 should refuse (equal), got nil error")
	}
	if err := s.SetLastDispatchSeq(9); err == nil {
		t.Error("SetLastDispatchSeq(9) after 10 should refuse (backwards), got nil error")
	}
	// Refused calls must not have mutated the persisted value.
	if got := s.LastDispatchSeq(); got != 10 {
		t.Errorf("LastDispatchSeq() after refused calls = %d, want 10 (unchanged)", got)
	}
}

func TestSetLastDispatchSeq_ToleratesGaps(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.SetLastDispatchSeq(5); err != nil {
		t.Fatalf("SetLastDispatchSeq(5): %v", err)
	}
	if err := s.SetLastDispatchSeq(8); err != nil {
		t.Fatalf("SetLastDispatchSeq(8) after 5 (gap) should be accepted: %v", err)
	}
	if got := s.LastDispatchSeq(); got != 8 {
		t.Errorf("LastDispatchSeq() = %d, want 8", got)
	}
}

// TestStateWipe_ZeroesLastDispatchSeq mirrors NextResponseSeq's
// reset-on-state-loss behavior: a missing state file is zero-state, no
// special reset logic needed for the new plain uint64 field.
func TestStateWipe_ZeroesLastDispatchSeq(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state")

	s, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.SetLastDispatchSeq(42); err != nil {
		t.Fatalf("SetLastDispatchSeq: %v", err)
	}
	if err := s.SetLastExecutedTaskID(100); err != nil {
		t.Fatalf("SetLastExecutedTaskID: %v", err)
	}

	// Simulate a wipe: point a fresh Store at a state file that doesn't
	// exist (as if /var/db/ndagent/state was deleted).
	wiped, err := New(filepath.Join(dir, "state-does-not-exist"))
	if err != nil {
		t.Fatalf("New (wiped): %v", err)
	}
	if got := wiped.LastDispatchSeq(); got != 0 {
		t.Errorf("wiped LastDispatchSeq() = %d, want 0", got)
	}
	if got := wiped.LastExecutedTaskID(); got != 0 {
		t.Errorf("wiped LastExecutedTaskID() = %d, want 0", got)
	}
}
