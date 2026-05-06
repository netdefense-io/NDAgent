// Package state persists durable agent state across restarts.
//
// Two counters are tracked:
//   - `last_executed_task_id`: replay barrier for inbound dispatch envelopes
//     (NDManager → agent). PAYLOAD-SIGNATURES-DESIGN.md §13.
//   - `next_response_seq`: device-monotonic counter included in the protected
//     header of every outbound response envelope. Replaces task_id as the
//     response replay token because IN_PROGRESS and final responses share
//     task_id. PAYLOAD-SIGNATURES-FINDINGS-FIXES.md §3 Finding 3a.
//
// The agent acquires a fresh seq under a mutex that also covers the WS write
// (see internal/network/websocket.go) so seq order matches wire order.
//
// State-loss recovery: if /var/db/ndagent/state is wiped, both counters
// reset to zero. The operator's bootstrap-token rebind flow on the broker
// side also resets Device.last_response_seq=0, so the two stay aligned and
// the first response after recovery is accepted with seq=1.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

// DefaultStatePath is where the agent persists state on FreeBSD/OPNsense.
const DefaultStatePath = "/var/db/ndagent/state"

type onDisk struct {
	LastExecutedTaskID  int64  `json:"last_executed_task_id"`
	NextResponseSeq     uint64 `json:"next_response_seq"`
	// LastRebindTokenHash is the SHA-256 hex of the most recent
	// `bootstrap_token=` value the agent used to rotate its keypair.
	// Stored so a restart that still has the same (now-consumed) token
	// in conf doesn't double-rotate. Empty when the agent has never
	// processed a rebind token. PAYLOAD-SIGNATURES-FINDINGS-FIXES.md §3
	// Finding 2 (UX follow-up).
	LastRebindTokenHash string `json:"last_rebind_token_hash,omitempty"`
}

// Store is a goroutine-safe view of the agent state file. Construct via
// New(); call Get / SetLastExecutedTaskID for reads/writes.
type Store struct {
	path string
	mu   sync.Mutex
	data onDisk
}

// New opens (or creates) a state store at `path`. Reads existing state
// from disk if present; treats a missing file as zero-state.
func New(path string) (*Store, error) {
	s := &Store{path: path}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) load() error {
	f, err := os.Open(s.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("open state file %s: %w", s.path, err)
	}
	defer f.Close()
	if err := json.NewDecoder(f).Decode(&s.data); err != nil {
		return fmt.Errorf("decode state file %s: %w", s.path, err)
	}
	return nil
}

// LastExecutedTaskID returns the last task_id we've executed under a
// verified envelope. Compare against an inbound envelope's protected-
// header task_id with strict `>` to enforce the replay barrier.
func (s *Store) LastExecutedTaskID() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.LastExecutedTaskID
}

// SetLastExecutedTaskID atomically updates the persisted last task_id.
//
// Persists ahead of dispatch (before the handler runs) to be conservative
// against duplicate execution if the agent crashes mid-handler — replay
// of the same task_id would be rejected because we already advanced the
// counter, and the operator would notice via the orphaned IN_PROGRESS
// task on the broker side.
func (s *Store) SetLastExecutedTaskID(taskID int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if taskID <= s.data.LastExecutedTaskID {
		// Refuse to go backwards (shouldn't happen — caller already gates)
		return fmt.Errorf("refusing to set last_executed_task_id %d <= current %d", taskID, s.data.LastExecutedTaskID)
	}
	s.data.LastExecutedTaskID = taskID
	return s.persist()
}

// AcquireNextResponseSeq atomically increments and persists the response
// sequence counter, then returns the new value. The caller MUST hold a
// mutex that also covers the COSE sign + WS write so seq order equals
// wire order — see internal/network/websocket.go.
//
// Persists ahead of send so a crash-mid-write never reuses a number; the
// broker's strict-> replay barrier will reject a hypothetical duplicate.
func (s *Store) AcquireNextResponseSeq() (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.data.NextResponseSeq + 1
	s.data.NextResponseSeq = next
	if err := s.persist(); err != nil {
		// Roll back the in-memory increment so the next call retries
		// the same seq rather than skipping it after a transient
		// disk error.
		s.data.NextResponseSeq = next - 1
		return 0, fmt.Errorf("persist next_response_seq: %w", err)
	}
	return next, nil
}

// CurrentResponseSeq returns the most recently issued response seq (or 0
// if none have been issued). Diagnostic only — not used for replay logic.
func (s *Store) CurrentResponseSeq() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.NextResponseSeq
}

// LastRebindTokenHash returns the SHA-256 hex of the rebind token whose
// keypair rotation this agent has already executed (or "" if none).
// Used to make rebind-token consumption idempotent across restarts —
// see RotateDevicePrivkey + the lifecycle's pre-registration check.
func (s *Store) LastRebindTokenHash() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.LastRebindTokenHash
}

// SetLastRebindTokenHash atomically updates the persisted hash. Pass
// hex-encoded SHA-256 of the raw token; empty string is allowed to
// reset.
func (s *Store) SetLastRebindTokenHash(hashHex string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.LastRebindTokenHash = hashHex
	return s.persist()
}

// persist atomically rewrites the state file. Caller holds s.mu.
func (s *Store) persist() error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".state.*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
	}()
	if err := json.NewEncoder(tmp).Encode(&s.data); err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), s.path); err != nil {
		return fmt.Errorf("rename state: %w", err)
	}
	return nil
}
