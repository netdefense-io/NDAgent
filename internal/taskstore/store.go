// Package taskstore persists per-task state across NDAgent restarts.
//
// Every dispatched task is recorded here with its lifecycle category at
// Begin time, gets its terminal status (COMPLETED / FAILED) written via
// Complete, and is marked delivered after the corresponding task_response
// successfully leaves the wire. Rows that are still IN_PROGRESS when the
// connect-time drain runs are resolved by ResolveStuck per their category —
// see the Lifecycle docs below — unless something still owns them: a handler
// alive in this process, or a task type with its own reconciler
// (FIRMWARE_UPGRADE, whose outcome only the device can tell).
//
// Storage is a single SQLite file at DefaultStorePath. The store is
// goroutine-safe via SQLite's own locking; callers don't need their own
// mutex. WAL journal mode lets the dispatcher and the connect-time drain
// touch the DB concurrently without writer starvation.
//
// Retention is enforced by MarkDelivered: each successful delivery prunes
// the table down to MaxDeliveredRows. Undelivered rows are never pruned
// — they are the whole reason the store exists.
package taskstore

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// DefaultStorePath is the on-disk location on FreeBSD/OPNsense. Sits in
// the same /var/db/ndagent/ directory as the existing state file and the
// NDM-keys cache (see internal/state and internal/network/ndmkeys).
const DefaultStorePath = "/var/db/ndagent/tasks.db"

// MaxDeliveredRows is the retention cap. After every MarkDelivered we
// keep only the newest MaxDeliveredRows rows whose delivered_at is set.
// Undelivered rows are exempt. Operators can inspect history via
// `sqlite3 /var/db/ndagent/tasks.db 'select * from task_states'`; if real
// usage shows operators want more, raise the constant.
const MaxDeliveredRows = 100

// Wire status strings — mirror NDDataModels.DB.TaskStatus values. Kept
// local rather than imported from internal/network so the store doesn't
// pull in WebSocket types.
const (
	StatusInProgress = "IN_PROGRESS"
	StatusCompleted  = "COMPLETED"
	StatusFailed     = "FAILED"
)

// Lifecycle declares how a task type relates to the agent process lifetime
// — and therefore what to do with rows still IN_PROGRESS when the drain runs.
//
// Set once by the dispatcher at Begin time (see internal/tasks/register.go
// for the task-type → lifecycle map). The drain step consults it after
// reconciling any helper drop files.
type Lifecycle int

const (
	// LifecycleSynchronous: the handler is expected to send a final
	// task_response from the same process. An IN_PROGRESS row whose handler
	// is no longer alive means the agent died mid-task → ResolveStuck marks
	// it FAILED with "agent restarted mid-task".
	LifecycleSynchronous Lifecycle = iota

	// LifecycleRestartCompletes: the act of restarting the agent (or the
	// device) is the task's success signal. RESTART and REBOOT use this.
	// An IN_PROGRESS row once the agent is back means the restart finished → ResolveStuck
	// marks it COMPLETED. There is no time-based heuristic; a 10-minute
	// device reboot resolves correctly whenever the agent comes back.
	LifecycleRestartCompletes

	// LifecycleHelperResolves: a detached helper script writes the
	// outcome to a JSON drop file under /var/db/ndagent/pending-results/.
	// ReconcileDropFiles applies any present drop files BEFORE
	// ResolveStuck runs, so by the time ResolveStuck sees an IN_PROGRESS
	// row with this lifecycle, the helper was killed before producing a
	// result → mark FAILED with "helper did not produce result file".
	// A slow helper (e.g. a 20-minute OS update) is fine: the drop file
	// just lands later, and the next connect's drain picks it up.
	LifecycleHelperResolves
)

func (l Lifecycle) String() string {
	switch l {
	case LifecycleRestartCompletes:
		return "restart_completes"
	case LifecycleHelperResolves:
		return "helper_resolves"
	default:
		return "synchronous"
	}
}

func parseLifecycle(s string) Lifecycle {
	switch s {
	case "restart_completes":
		return LifecycleRestartCompletes
	case "helper_resolves":
		return LifecycleHelperResolves
	default:
		return LifecycleSynchronous
	}
}

// ErrAlreadyTerminal is returned by Begin when a task_id already has a
// row in a terminal state. The broker should never redispatch a terminal
// task, but the store defends against it.
var ErrAlreadyTerminal = errors.New("taskstore: task is already terminal")

// Record is the projection returned by Undelivered. Carries everything
// the drain step needs to replay a task_response.
type Record struct {
	TaskID     string
	TaskType   string
	Lifecycle  Lifecycle
	Status     string
	Message    string
	ResultData []byte
	StartedAt  time.Time
	EndedAt    time.Time
	// Delivered is set only by Get: the rows the other queries return are
	// selected by it.
	Delivered bool
}

// Store is the SQLite-backed task-state registry. Construct with Open;
// always Close before exit.
type Store struct {
	db *sql.DB
}

// nowFn is the time source. Overridable in tests for deterministic
// timestamps. Production callers see time.Now().
var nowFn = time.Now

// Open opens or creates the store at `path`. The parent directory is
// created with 0700 if missing (matching the convention in
// internal/state/state.go); the DB file is chmod'd to 0600 on first
// create so secrets-shaped fields (none yet, but task payloads could
// grow into them) aren't world-readable.
func Open(path string) (*Store, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", dir, err)
	}
	// modernc.org/sqlite driver name is "sqlite". DSN options enable WAL
	// and reasonable durability. _txlock=immediate avoids upgrade
	// deadlocks when a write transaction starts as a read.
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", path, err)
	}
	// Single connection keeps WAL behavior predictable on a low-traffic
	// store; SQLite serializes writers anyway.
	db.SetMaxOpenConns(1)

	if err := initSchema(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	// Tighten file mode after the driver has created the file. Ignore
	// errors on systems where chmod is a no-op (the test in-memory DSN
	// doesn't create a file).
	_ = os.Chmod(path, 0o600)

	return &Store{db: db}, nil
}

// OpenInMemory returns a store backed by an anonymous in-memory SQLite.
// For tests only.
func OpenInMemory() (*Store, error) {
	db, err := sql.Open("sqlite", "file::memory:?cache=shared&_pragma=journal_mode(MEMORY)&_pragma=foreign_keys(ON)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := initSchema(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

const schemaVersion = 2

func initSchema(db *sql.DB) error {
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS task_states (
    task_id      TEXT PRIMARY KEY,
    task_type    TEXT NOT NULL,
    lifecycle    TEXT NOT NULL,
    status       TEXT NOT NULL,
    message      TEXT NOT NULL DEFAULT '',
    result_data  BLOB,
    started_at   INTEGER NOT NULL,
    ended_at     INTEGER,
    delivered_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_task_states_undelivered ON task_states(delivered_at, started_at);
`); err != nil {
		return fmt.Errorf("init schema: %w", err)
	}
	// v2 migration: add task_meta column (stores JSON metadata set at Begin
	// time, e.g. package_name + target_version for PLUGIN_INSTALL). SQLite
	// ADD COLUMN is safe on any existing DB — it's a no-op if the column
	// already exists (SQLite ≥ 3.37 supports IF NOT EXISTS on ADD COLUMN;
	// we catch the "duplicate column" error for older SQLite versions used
	// in the modernc driver).
	if _, err := db.Exec(`ALTER TABLE task_states ADD COLUMN task_meta TEXT`); err != nil {
		// "duplicate column name" means the migration already ran — not an error.
		if !isDuplicateColumnError(err) {
			return fmt.Errorf("migrate schema v2 (add task_meta): %w", err)
		}
	}
	if _, err := db.Exec(fmt.Sprintf("PRAGMA user_version = %d", schemaVersion)); err != nil {
		return fmt.Errorf("set user_version: %w", err)
	}
	return nil
}

// isDuplicateColumnError reports whether err is the SQLite "duplicate column
// name" error returned when ALTER TABLE ADD COLUMN is run a second time.
func isDuplicateColumnError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "duplicate column name") || strings.Contains(msg, "already exists")
}

// PluginInstallMeta is the metadata stored at Begin time for PLUGIN_INSTALL
// tasks. It is written by BeginWithMeta and read by the connect-time drain to
// perform a version-aware stuck-row resolution without requiring the original
// command payload.
type PluginInstallMeta struct {
	PackageName   string `json:"package_name"`
	TargetVersion string `json:"target_version"` // "" means "latest"
}

// Close releases the underlying DB handle. Safe to call on a nil receiver.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Begin records that the dispatcher has handed `taskID` to a handler.
// Idempotent for already-IN_PROGRESS rows (the broker may redispatch
// across a transient WS reconnect); returns ErrAlreadyTerminal if the
// task already has a terminal status (the broker should never reach
// this path — defensive only).
func (s *Store) Begin(taskID, taskType string, lifecycle Lifecycle) error {
	now := nowFn().Unix()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var existingStatus string
	err = tx.QueryRow("SELECT status FROM task_states WHERE task_id = ?", taskID).Scan(&existingStatus)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// fresh insert below
	case err != nil:
		return fmt.Errorf("query existing: %w", err)
	default:
		// Row exists.
		if existingStatus == StatusInProgress {
			return tx.Commit() // idempotent re-Begin
		}
		return ErrAlreadyTerminal
	}

	if _, err := tx.Exec(`
INSERT INTO task_states (task_id, task_type, lifecycle, status, started_at)
VALUES (?, ?, ?, ?, ?)
`, taskID, taskType, lifecycle.String(), StatusInProgress, now); err != nil {
		return fmt.Errorf("insert: %w", err)
	}
	return tx.Commit()
}

// SetTaskMeta stores a JSON-encoded metadata blob in the task_meta column for
// an existing task row. It is intended to be called by a handler immediately
// after the dispatcher has called Begin, before any long-running work begins.
// The row must exist and be IN_PROGRESS; a no-op for terminal rows so callers
// don't need to guard against task completion races.
//
// Only PLUGIN_INSTALL uses this today; future handler types may extend it.
func (s *Store) SetTaskMeta(taskID string, meta interface{}) error {
	raw, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("marshal task_meta: %w", err)
	}
	_, err = s.db.Exec(
		"UPDATE task_states SET task_meta = ? WHERE task_id = ? AND status = ?",
		string(raw), taskID, StatusInProgress,
	)
	return err
}

// GetPluginInstallMeta reads the PluginInstallMeta stored by SetTaskMeta for
// the given task. Returns nil (no error) if the row has no metadata or the
// task is not found — callers must treat nil as "metadata absent".
func (s *Store) GetPluginInstallMeta(taskID string) (*PluginInstallMeta, error) {
	var raw sql.NullString
	err := s.db.QueryRow("SELECT task_meta FROM task_states WHERE task_id = ?", taskID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) || !raw.Valid || raw.String == "" {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query task_meta for %s: %w", taskID, err)
	}
	var m PluginInstallMeta
	if err := json.Unmarshal([]byte(raw.String), &m); err != nil {
		return nil, nil // malformed meta — treat as absent
	}
	return &m, nil
}

// GetTaskMeta decodes the metadata SetTaskMeta stored for taskID into dst.
// found is false when the row does not exist, carries no metadata, or holds a
// blob that does not decode into dst: a caller cannot tell those apart and
// must treat all three as "metadata absent" (a row written by an agent that
// stored none).
func (s *Store) GetTaskMeta(taskID string, dst interface{}) (found bool, err error) {
	var raw sql.NullString
	err = s.db.QueryRow("SELECT task_meta FROM task_states WHERE task_id = ?", taskID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("query task_meta for %s: %w", taskID, err)
	}
	if !raw.Valid || raw.String == "" {
		return false, nil
	}
	if err := json.Unmarshal([]byte(raw.String), dst); err != nil {
		return false, nil
	}
	return true, nil
}

// Complete writes a terminal status for `taskID`. If the row doesn't
// exist (Begin was skipped or the store was wiped between dispatch and
// completion), the row is created so the drain step can still deliver
// the response on the next connect.
//
// Status must be StatusCompleted or StatusFailed. IN_PROGRESS is rejected
// — callers should use SendInProgressResponse for that, which doesn't
// touch the store.
func (s *Store) Complete(taskID, status, message string, data []byte) error {
	if status != StatusCompleted && status != StatusFailed {
		return fmt.Errorf("taskstore: Complete called with non-terminal status %q", status)
	}
	now := nowFn().Unix()
	// INSERT OR UPDATE so a Complete without a prior Begin (defensive
	// path — e.g., drop-file reconciliation for a row the registry never
	// saw) still lands. UPSERT pattern via ON CONFLICT.
	_, err := s.db.Exec(`
INSERT INTO task_states (task_id, task_type, lifecycle, status, message, result_data, started_at, ended_at)
VALUES (?, '', 'synchronous', ?, ?, ?, ?, ?)
ON CONFLICT(task_id) DO UPDATE SET
    status = excluded.status,
    message = excluded.message,
    result_data = excluded.result_data,
    ended_at = excluded.ended_at
`, taskID, status, message, data, now, now)
	if err != nil {
		return fmt.Errorf("complete: %w", err)
	}
	return nil
}

// CompleteIfInProgress is Complete for a caller that is not the task's owner:
// it writes the terminal status only while the row is still IN_PROGRESS and
// reports whether it did. Complete overwrites whatever is there, which is right
// for the handler that owns the task and wrong for anyone else, who could
// otherwise replace an outcome the owner recorded a moment earlier. A caller
// that gets false lost the race (or the row is gone) and must not send a
// response of its own.
func (s *Store) CompleteIfInProgress(taskID, status, message string, data []byte) (bool, error) {
	if status != StatusCompleted && status != StatusFailed {
		return false, fmt.Errorf("taskstore: CompleteIfInProgress called with non-terminal status %q", status)
	}
	res, err := s.db.Exec(`
UPDATE task_states
SET status = ?, message = ?, result_data = ?, ended_at = ?
WHERE task_id = ? AND status = ?
`, status, message, data, nowFn().Unix(), taskID, StatusInProgress)
	if err != nil {
		return false, fmt.Errorf("complete if in progress: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("complete if in progress: %w", err)
	}
	return n == 1, nil
}

// MarkDelivered stamps delivered_at and runs retention in the same
// transaction. Idempotent — re-marking an already-delivered row is a
// no-op as far as visible state goes (delivered_at gets overwritten with
// the same wall-clock kind of value).
func (s *Store) MarkDelivered(taskID string) error {
	now := nowFn().Unix()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.Exec("UPDATE task_states SET delivered_at = ? WHERE task_id = ?", now, taskID)
	if err != nil {
		return fmt.Errorf("mark delivered: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("taskstore: MarkDelivered: no row for task_id %s", taskID)
	}

	// Retention: keep only the newest MaxDeliveredRows delivered rows.
	// Subquery picks the rows to KEEP (by recency of started_at);
	// everything else with delivered_at IS NOT NULL gets dropped.
	if _, err := tx.Exec(`
DELETE FROM task_states
WHERE delivered_at IS NOT NULL
  AND task_id NOT IN (
    SELECT task_id FROM task_states
    WHERE delivered_at IS NOT NULL
    ORDER BY started_at DESC
    LIMIT ?
  )
`, MaxDeliveredRows); err != nil {
		return fmt.Errorf("retention: %w", err)
	}

	return tx.Commit()
}

// Undelivered returns terminal rows (COMPLETED or FAILED) whose
// delivered_at is still NULL, oldest-first by started_at. The drain
// step iterates these and replays each as a task_response.
func (s *Store) Undelivered() ([]Record, error) {
	rows, err := s.db.Query(`
SELECT task_id, task_type, lifecycle, status, message, result_data, started_at, ended_at
FROM task_states
WHERE delivered_at IS NULL
  AND status IN (?, ?)
ORDER BY started_at ASC
`, StatusCompleted, StatusFailed)
	if err != nil {
		return nil, fmt.Errorf("query undelivered: %w", err)
	}
	defer rows.Close()

	var out []Record
	for rows.Next() {
		var r Record
		var lifecycleStr string
		var endedAt sql.NullInt64
		var startedAt int64
		var data []byte
		if err := rows.Scan(&r.TaskID, &r.TaskType, &lifecycleStr, &r.Status, &r.Message, &data, &startedAt, &endedAt); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		r.Lifecycle = parseLifecycle(lifecycleStr)
		r.ResultData = data
		r.StartedAt = time.Unix(startedAt, 0)
		if endedAt.Valid {
			r.EndedAt = time.Unix(endedAt.Int64, 0)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Get returns the row for taskID, or found=false when there is none.
func (s *Store) Get(taskID string) (rec Record, found bool, err error) {
	var (
		lifecycleStr string
		data         []byte
		startedAt    int64
		endedAt      sql.NullInt64
		deliveredAt  sql.NullInt64
	)
	err = s.db.QueryRow(`
SELECT task_id, task_type, lifecycle, status, message, result_data, started_at, ended_at, delivered_at
FROM task_states
WHERE task_id = ?
`, taskID).Scan(&rec.TaskID, &rec.TaskType, &lifecycleStr, &rec.Status, &rec.Message, &data, &startedAt, &endedAt, &deliveredAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, false, nil
	}
	if err != nil {
		return Record{}, false, fmt.Errorf("get %s: %w", taskID, err)
	}
	rec.Lifecycle = parseLifecycle(lifecycleStr)
	rec.ResultData = data
	rec.StartedAt = time.Unix(startedAt, 0)
	if endedAt.Valid {
		rec.EndedAt = time.Unix(endedAt.Int64, 0)
	}
	rec.Delivered = deliveredAt.Valid
	return rec, true, nil
}

// InProgressByType returns all rows still IN_PROGRESS for the given task type.
// The FIRMWARE_UPGRADE reconciler uses it to find the tasks it has to decide
// from the device's state, and the PLUGIN_INSTALL drain uses it for its
// drop-file wait.
func (s *Store) InProgressByType(taskType string) ([]Record, error) {
	rows, err := s.db.Query(`
SELECT task_id, task_type, lifecycle, status, message, result_data, started_at, ended_at
FROM task_states
WHERE status = ? AND task_type = ?
ORDER BY started_at ASC
`, StatusInProgress, taskType)
	if err != nil {
		return nil, fmt.Errorf("query in-progress by type: %w", err)
	}
	defer rows.Close()

	var out []Record
	for rows.Next() {
		var r Record
		var lifecycleStr string
		var endedAt sql.NullInt64
		var startedAt int64
		var data []byte
		if err := rows.Scan(&r.TaskID, &r.TaskType, &lifecycleStr, &r.Status, &r.Message, &data, &startedAt, &endedAt); err != nil {
			return nil, fmt.Errorf("scan in-progress: %w", err)
		}
		r.Lifecycle = parseLifecycle(lifecycleStr)
		r.ResultData = data
		r.StartedAt = time.Unix(startedAt, 0)
		if endedAt.Valid {
			r.EndedAt = time.Unix(endedAt.Int64, 0)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ResolveOption narrows which IN_PROGRESS rows ResolveStuck may resolve.
type ResolveOption func(*resolveConfig)

type resolveConfig struct {
	deferredTypes map[string]struct{}
	isLive        func(taskID string) bool
}

// WithDeferredTypes leaves the rows of the given task types IN_PROGRESS: their
// outcome is decided by something that can read the device (FIRMWARE_UPGRADE's
// reconciler), not by the blanket lifecycle rule. The rule is keyed on the task
// type and not on the lifecycle stored in the row, so rows written by an agent
// that predates the option are covered too.
func WithDeferredTypes(types ...string) ResolveOption {
	return func(c *resolveConfig) {
		if c.deferredTypes == nil {
			c.deferredTypes = make(map[string]struct{}, len(types))
		}
		for _, t := range types {
			c.deferredTypes[t] = struct{}{}
		}
	}
}

// WithLiveness leaves alone every row whose handler is still running, or still
// queued, in this process. A row is only stuck once nothing here owns it any
// more; resolving one that is owned would report a running task as dead, and
// the owner's later terminal write would then overwrite that.
func WithLiveness(isLive func(taskID string) bool) ResolveOption {
	return func(c *resolveConfig) { c.isLive = isLive }
}

// ResolveStuck walks every row still IN_PROGRESS and applies the
// lifecycle-category rule. Returns the number of rows changed.
//
// Callers should run ReconcileDropFiles FIRST so helper-resolved tasks
// with a drop file already on disk get their real outcome instead of
// the "helper did not produce result file" fallback.
//
// It runs at every WebSocket connect, not only at boot, so a row whose handler
// is alive in this process must be left to that handler (WithLiveness) and a
// type whose outcome needs the device's state must be left to its reconciler
// (WithDeferredTypes). Each write is a compare-and-set: a row that turns
// terminal between the scan and the write keeps the outcome its handler gave it.
func (s *Store) ResolveStuck(opts ...ResolveOption) (int, error) {
	var cfg resolveConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	rows, err := s.db.Query("SELECT task_id, task_type, lifecycle FROM task_states WHERE status = ?", StatusInProgress)
	if err != nil {
		return 0, fmt.Errorf("query stuck: %w", err)
	}
	type stuck struct {
		taskID    string
		taskType  string
		lifecycle Lifecycle
	}
	var pending []stuck
	for rows.Next() {
		var s stuck
		var lc string
		if err := rows.Scan(&s.taskID, &s.taskType, &lc); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan stuck: %w", err)
		}
		s.lifecycle = parseLifecycle(lc)
		pending = append(pending, s)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	changed := 0
	for _, p := range pending {
		if _, deferred := cfg.deferredTypes[p.taskType]; deferred {
			continue
		}
		if cfg.isLive != nil && cfg.isLive(p.taskID) {
			continue
		}
		var status, message string
		switch p.lifecycle {
		case LifecycleRestartCompletes:
			status = StatusCompleted
			message = "Device returned after restart"
		case LifecycleHelperResolves:
			status = StatusFailed
			message = "helper did not produce result file"
		default: // LifecycleSynchronous
			status = StatusFailed
			message = "agent restarted mid-task"
		}
		won, err := s.CompleteIfInProgress(p.taskID, status, message, nil)
		if err != nil {
			return changed, err
		}
		if won {
			changed++
		}
	}
	return changed, nil
}
