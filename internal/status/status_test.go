package status

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func readSnapshot(t *testing.T, path string) snapshot {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var snap snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		t.Fatal(err)
	}
	return snap
}

// The registration waits have states of their own, so the plugin page can say
// what the agent waits for (NDAgent-go#179).
func TestWriter_TheRegistrationWaitsHaveTheirOwnStates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ndagent.status")
	w := NewWriter(path, "1.0.0", "abc", "221f3268-0000-4000-8000-000000000001")

	if err := w.MarkPending(); err != nil {
		t.Fatal(err)
	}
	pending := readSnapshot(t, path)
	if pending.State != "pending" {
		t.Errorf("state = %q, want pending", pending.State)
	}

	time.Sleep(10 * time.Millisecond)
	if err := w.MarkPending(); err != nil {
		t.Fatal(err)
	}
	if again := readSnapshot(t, path); !again.Since.Equal(pending.Since) || !again.UpdatedAt.After(pending.UpdatedAt) {
		t.Errorf("a repeated pending moved since (%v -> %v) or kept updated_at (%v -> %v)", pending.Since, again.Since, pending.UpdatedAt, again.UpdatedAt)
	}

	if err := w.MarkDisabled(); err != nil {
		t.Fatal(err)
	}
	if disabled := readSnapshot(t, path); disabled.State != "disabled" || !disabled.Since.After(pending.Since) {
		t.Errorf("disabled snapshot = %+v, want state disabled with a new since", disabled)
	}

	var nilWriter *Writer
	if err := nilWriter.MarkPending(); err != nil {
		t.Errorf("a nil writer returned %v", err)
	}
}

// The plugin page reads tls_error to say why every connection is refused; it
// stays through the state changes and is left out when there is none.
func TestWriter_TLSErrorSurvivesStateChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ndagent.status")
	w := NewWriter(path, "1.0.0", "abc", "221f3268-0000-4000-8000-000000000001")
	if err := w.SetTLSError("tls_mode custom_ca needs tls_ca_file"); err != nil {
		t.Fatal(err)
	}
	if err := w.MarkDisconnected("tls: failed to verify certificate"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if raw["tls_error"] != "tls_mode custom_ca needs tls_ca_file" {
		t.Errorf("tls_error = %v", raw["tls_error"])
	}

	if err := w.SetTLSError(""); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(path)
	raw = nil
	_ = json.Unmarshal(data, &raw)
	if _, ok := raw["tls_error"]; ok {
		t.Errorf("an empty tls_error is written: %s", data)
	}

	var nilWriter *Writer
	if err := nilWriter.SetTLSError("x"); err != nil {
		t.Errorf("a nil writer returned %v", err)
	}
}
