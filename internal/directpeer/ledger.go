package directpeer

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// DefaultLedgerPath is where the device keeps its record of session ids,
// next to the agent's other state.
const DefaultLedgerPath = "/var/db/ndagent/connect-sessions.json"

const (
	ledgerVersion = 1

	// ledgerMaxEntries bounds the record. Every entry took a signed task, and
	// each is dropped at its expiry, so a device never comes near it.
	ledgerMaxEntries = 4096

	// ledgerKeepPast is how long an id is kept past its expiry, for a clock
	// that was stepped back.
	ledgerKeepPast = 5 * time.Minute

	// ledgerBlindFor is how far ahead the expiry of a task the device accepted
	// can lie: the longest life the control plane gives an open task. A device
	// that lost its record refuses every open that expires within it, since
	// any of those could carry an id the lost record held.
	ledgerBlindFor = 15 * time.Minute
)

// ErrLedgerBlind is Accept's answer while the device cannot tell whether an
// id was used: its record was unreadable, and the open could predate that.
var ErrLedgerBlind = errors.New("the record of earlier sessions was lost")

// ErrLedgerFull is Accept's answer when the record holds its maximum.
var ErrLedgerFull = errors.New("the record of sessions is full")

// Accepted is what the record says of a session id an open task brings.
type Accepted int

const (
	// AcceptedNew: the id was never seen and is now recorded, durably.
	AcceptedNew Accepted = iota
	// AcceptedSameTask: the same task brought the id before. It is the task
	// delivered again, not a replay: nothing starts and nothing is refused.
	AcceptedSameTask
	// AcceptedReplayed: another task brought the id, or a close named it.
	AcceptedReplayed
)

// ledgerEntry is one session id the device accepted or was told to close.
type ledgerEntry struct {
	ConnectID string `json:"connect_id"`
	// TaskID is the open task that brought the id; empty for an id only a
	// close instruction named.
	TaskID string `json:"task_id,omitempty"`
	// Until is when the id may be forgotten, in Unix seconds.
	Until int64 `json:"until"`

	// The session, from the moment it listens until its end is recorded.
	ListeningAt int64  `json:"listening_at,omitempty"`
	ConnectedAt int64  `json:"connected_at,omitempty"`
	Path        string `json:"path,omitempty"`
	Protocol    int    `json:"protocol,omitempty"`
	// How the session ended, from the moment that is known until the end is
	// on record with the task.
	EndReason string `json:"end_reason,omitempty"`
	EndedAt   int64  `json:"ended_at,omitempty"`
}

type ledgerFile struct {
	V int `json:"v"`
	// RefuseUntil: an open task that expires at or before it is refused.
	RefuseUntil int64         `json:"refuse_until,omitempty"`
	Entries     []ledgerEntry `json:"entries"`
}

// Orphan is a session the previous agent process left open: it listened and
// its end was never recorded, so that process died with it.
type Orphan struct {
	ConnectID   string
	TaskID      string
	Protocol    int
	ListeningAt time.Time
	// ConnectedAt is zero when no client had connected.
	ConnectedAt time.Time
	Path        string
	// LastSeen is the last moment the previous process is known to have been
	// alive with the session open.
	LastSeen time.Time
	// EndReason and EndedAt are set when the previous process saw the session
	// end and did not get to put that on record with the task.
	EndReason string
	EndedAt   time.Time
}

// Ledger is the device's record of session ids, kept on disk: an id is used
// once, across restarts of the agent, and a session that listened is known
// until its end has been recorded.
type Ledger struct {
	path string
	now  func() time.Time

	mu          sync.Mutex
	entries     map[string]*ledgerEntry
	refuseUntil int64
	orphans     []Orphan
}

// OpenLedger loads the record at path. A file that is not there is an empty
// record. One that cannot be read or is not a record this agent wrote is
// replaced by an empty one that refuses, for ledgerBlindFor, every open that
// could predate it; the error says so and the Ledger is usable.
func OpenLedger(path string, now func() time.Time) (*Ledger, error) {
	if now == nil {
		now = time.Now
	}
	l := &Ledger{path: path, now: now, entries: make(map[string]*ledgerEntry)}

	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return l, nil
	}
	var file ledgerFile
	if err == nil {
		if err = json.Unmarshal(data, &file); err == nil && file.V != ledgerVersion {
			err = fmt.Errorf("version %d", file.V)
		}
	}
	if err != nil {
		l.refuseUntil = now().Add(ledgerBlindFor).Unix()
		if saveErr := l.saveLocked(); saveErr != nil {
			return l, fmt.Errorf("the session record at %s is unusable (%v) and cannot be replaced: %w", path, err, saveErr)
		}
		return l, fmt.Errorf("the session record at %s was unusable and is started again: %v", path, err)
	}

	lastSeen := now()
	if info, statErr := os.Stat(path); statErr == nil && info.ModTime().Before(lastSeen) {
		lastSeen = info.ModTime()
	}
	l.refuseUntil = file.RefuseUntil
	for i := range file.Entries {
		e := file.Entries[i]
		if e.ConnectID == "" {
			continue
		}
		l.entries[e.ConnectID] = &e
		if e.ListeningAt != 0 {
			o := Orphan{
				ConnectID:   e.ConnectID,
				TaskID:      e.TaskID,
				Protocol:    e.Protocol,
				ListeningAt: time.Unix(e.ListeningAt, 0),
				Path:        e.Path,
				LastSeen:    lastSeen,
			}
			if e.ConnectedAt != 0 {
				o.ConnectedAt = time.Unix(e.ConnectedAt, 0)
			}
			if o.LastSeen.Before(o.ListeningAt) {
				o.LastSeen = o.ListeningAt
			}
			if e.EndReason != "" {
				o.EndReason, o.EndedAt = e.EndReason, time.Unix(e.EndedAt, 0)
			}
			l.orphans = append(l.orphans, o)
		}
	}
	sort.Slice(l.orphans, func(i, j int) bool { return l.orphans[i].ListeningAt.Before(l.orphans[j].ListeningAt) })
	return l, nil
}

// Orphans returns the sessions the previous process left open. Each stays in
// the record, and is returned by the next process too, until Ended is called
// for it.
func (l *Ledger) Orphans() []Orphan {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Orphan(nil), l.orphans...)
}

// Accept records that the open task taskID brings connectID, a session that
// expires at exp (Unix seconds), and says whether the id is new. A new id is
// on disk when Accept returns: an error means it could not be written, or
// cannot be judged, and nothing may start.
func (l *Ledger) Accept(connectID, taskID string, exp int64) (Accepted, error) {
	if connectID == "" || taskID == "" {
		return AcceptedReplayed, errors.New("no session id or task id")
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	if e, ok := l.entries[connectID]; ok {
		if e.TaskID == taskID {
			return AcceptedSameTask, nil
		}
		return AcceptedReplayed, nil
	}
	if exp <= l.refuseUntil {
		return AcceptedReplayed, ErrLedgerBlind
	}
	l.pruneLocked()
	if len(l.entries) >= ledgerMaxEntries {
		return AcceptedReplayed, ErrLedgerFull
	}
	l.entries[connectID] = &ledgerEntry{ConnectID: connectID, TaskID: taskID, Until: exp}
	if err := l.saveLocked(); err != nil {
		delete(l.entries, connectID)
		return AcceptedReplayed, err
	}
	return AcceptedNew, nil
}

// RememberClosed records that a close instruction named connectID, until the
// instruction's expiry: an open that arrives later with that id cannot start.
// An id the record already holds is kept at least that long.
func (l *Ledger) RememberClosed(connectID string, until int64) error {
	if connectID == "" {
		return errors.New("no session id")
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	e, ok := l.entries[connectID]
	if ok && e.Until >= until {
		return nil
	}
	var before int64
	if ok {
		before, e.Until = e.Until, until
	} else {
		l.pruneLocked()
		if len(l.entries) >= ledgerMaxEntries {
			return ErrLedgerFull
		}
		l.entries[connectID] = &ledgerEntry{ConnectID: connectID, Until: until}
	}
	if err := l.saveLocked(); err != nil {
		if ok {
			e.Until = before
		} else {
			delete(l.entries, connectID)
		}
		return err
	}
	return nil
}

// update changes the entry of connectID and writes the record.
func (l *Ledger) update(connectID string, change func(e *ledgerEntry)) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[connectID]
	if !ok {
		return fmt.Errorf("no record of session %s", connectID)
	}
	change(e)
	return l.saveLocked()
}

// Listening records that the session of connectID listens since at. From here
// until Ended, a process that starts and finds it knows the session died. It
// leaves what Connected and Path recorded: the client can connect in the
// instant before this is written.
func (l *Ledger) Listening(connectID string, protocol int, at time.Time) error {
	return l.update(connectID, func(e *ledgerEntry) {
		e.ListeningAt, e.Protocol = at.Unix(), protocol
	})
}

// Connected records the moment the client connected.
func (l *Ledger) Connected(connectID string, at time.Time) error {
	return l.update(connectID, func(e *ledgerEntry) { e.ConnectedAt = at.Unix() })
}

// Path records the path the session is on.
func (l *Ledger) Path(connectID, path string) error {
	return l.update(connectID, func(e *ledgerEntry) { e.Path = path })
}

// Ending records how and when the session of connectID ended, before that
// is put on record with the task: a process that stops in between leaves it
// for the next one to report.
func (l *Ledger) Ending(connectID, reason string, at time.Time) error {
	return l.update(connectID, func(e *ledgerEntry) { e.EndReason, e.EndedAt = reason, at.Unix() })
}

// Lookup returns the task that brought connectID, and whether the record
// holds the id at all. The task is "" for an id only a close named.
func (l *Ledger) Lookup(connectID string) (taskID string, known bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[connectID]
	if !ok {
		return "", false
	}
	return e.TaskID, true
}

// Ended records that the end of the session of connectID is on record
// elsewhere (the task's result). The id stays used until its expiry.
func (l *Ledger) Ended(connectID string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i, o := range l.orphans {
		if o.ConnectID == connectID {
			l.orphans = append(l.orphans[:i], l.orphans[i+1:]...)
			break
		}
	}
	e, ok := l.entries[connectID]
	if !ok || e.ListeningAt == 0 {
		return nil
	}
	e.ListeningAt, e.ConnectedAt, e.Path, e.Protocol, e.EndReason, e.EndedAt = 0, 0, "", 0, "", 0
	return l.saveLocked()
}

// Touch notes that the agent is alive with sessions open: the file's time is
// what a later process reads as the moment a session it finds open was last
// known to run.
func (l *Ledger) Touch() {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	_ = os.Chtimes(l.path, now, now)
}

// pruneLocked forgets the ids past their expiry that carry no session.
func (l *Ledger) pruneLocked() {
	limit := l.now().Add(-ledgerKeepPast).Unix()
	for id, e := range l.entries {
		if e.ListeningAt == 0 && e.Until < limit {
			delete(l.entries, id)
		}
	}
	if l.refuseUntil != 0 && l.refuseUntil < limit {
		l.refuseUntil = 0
	}
}

// saveLocked replaces the file, mode 0600, and returns once it is on disk.
// The directory is not created: when it is gone the agent's state was
// removed, and nothing is written back.
func (l *Ledger) saveLocked() error {
	l.pruneLocked()
	file := ledgerFile{V: ledgerVersion, RefuseUntil: l.refuseUntil, Entries: make([]ledgerEntry, 0, len(l.entries))}
	for _, e := range l.entries {
		file.Entries = append(file.Entries, *e)
	}
	sort.Slice(file.Entries, func(i, j int) bool { return file.Entries[i].ConnectID < file.Entries[j].ConnectID })
	data, err := json.Marshal(file)
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(filepath.Dir(l.path), "."+filepath.Base(l.path)+".*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), l.path); err != nil {
		return err
	}
	if dir, err := os.Open(filepath.Dir(l.path)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}
