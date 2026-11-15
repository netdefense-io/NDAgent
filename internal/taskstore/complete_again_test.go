package taskstore

import "testing"

func undeliveredIDs(t *testing.T, s *Store) map[string]Record {
	t.Helper()
	rows, err := s.Undelivered()
	if err != nil {
		t.Fatalf("Undelivered: %v", err)
	}
	out := make(map[string]Record, len(rows))
	for _, r := range rows {
		out[r.TaskID] = r
	}
	return out
}

// A task with two results: the second must be replayed when its send failed,
// although the first was delivered.
func TestCompleteAgain_ASecondResultIsUndeliveredAgain(t *testing.T) {
	s, err := OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.Begin("7", "CONNECT", LifecycleSynchronous); err != nil {
		t.Fatal(err)
	}
	if err := s.Complete("7", StatusCompleted, "ready", []byte(`{"n":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkDelivered("7"); err != nil {
		t.Fatal(err)
	}
	if len(undeliveredIDs(t, s)) != 0 {
		t.Fatal("the first result is still undelivered")
	}

	// The control: Complete keeps the row delivered, so the second result
	// would never be replayed.
	if err := s.Complete("7", StatusCompleted, "ended", []byte(`{"n":2}`)); err != nil {
		t.Fatal(err)
	}
	if len(undeliveredIDs(t, s)) != 0 {
		t.Fatal("Complete marks a delivered row undelivered: CompleteAgain is no longer needed, and this test's premise is gone")
	}

	if err := s.CompleteAgain("7", "CONNECT", StatusCompleted, "ended", []byte(`{"n":2}`)); err != nil {
		t.Fatal(err)
	}
	row, ok := undeliveredIDs(t, s)["7"]
	if !ok {
		t.Fatal("the second result is not undelivered")
	}
	if row.Message != "ended" || string(row.ResultData) != `{"n":2}` || row.Status != StatusCompleted || row.TaskType != "CONNECT" {
		t.Fatalf("row = %+v", row)
	}

	if err := s.MarkDelivered("7"); err != nil {
		t.Fatal(err)
	}
	if len(undeliveredIDs(t, s)) != 0 {
		t.Fatal("the second result stays undelivered after MarkDelivered")
	}
}

// Retention may have dropped the first result during a session of hours.
func TestCompleteAgain_CreatesARowThatIsGone(t *testing.T) {
	s, err := OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.CompleteAgain("9", "CONNECT", StatusCompleted, "ended", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	row, ok := undeliveredIDs(t, s)["9"]
	if !ok || row.TaskType != "CONNECT" || row.Message != "ended" {
		t.Fatalf("row = %+v, found %v", row, ok)
	}
}

func TestCompleteAgain_RejectsANonTerminalStatus(t *testing.T) {
	s, err := OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.CompleteAgain("1", "CONNECT", StatusInProgress, "x", nil); err == nil {
		t.Fatal("accepted IN_PROGRESS")
	}
}
