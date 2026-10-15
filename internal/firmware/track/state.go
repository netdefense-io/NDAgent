package track

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// DefaultStatePath is where the agent keeps what it did to the device's firmware
// setting: next to the rest of its state, so a decommission that removes the
// directory removes it, and readable by the plugin's PHP helper, which restores
// the setting on a package removal or a decommission when the agent cannot.
const DefaultStatePath = "/var/db/ndagent/firmware-track.json"

// stateVersion is the file's format. A file of a newer one is not read: the
// agent cannot tell what it would be undoing.
const stateVersion = 1

// State is the agent's record of a pin it holds on this device, and the only
// thing that makes the pin the agent's: the compare-and-swap restore changes the
// firmware flavour only when it still equals what this record says was written.
//
// The field names are read by plugin/.../release_firmware_flavour.php
// (pinned, pinned_flavour, original_flavour, pending.to_flavour); the golden
// file testdata/state-pinned.json holds the shape both sides test against.
type State struct {
	V int `json:"v"`

	// Pinned says the agent holds a pin: the flavour it wrote is PinnedFlavour.
	// A record with Pinned false is a tombstone (Released) or the trace of an
	// operation that was interrupted before it pinned (Pending).
	Pinned bool `json:"pinned"`

	// Track is the device's track as the control plane last said.
	Track string `json:"track,omitempty"`

	// OriginalFlavour is the flavour the device had before the pin. A device with
	// a flavour of its own is never enrolled, so this is normally empty (the
	// default), and is kept as the string it was.
	OriginalFlavour string `json:"original_flavour"`

	// PinnedFlavour is the exact value the agent last wrote, and PinnedVersion
	// the release the pin holds the device at: the installed release when it was
	// written.
	PinnedFlavour string `json:"pinned_flavour,omitempty"`
	PinnedVersion string `json:"pinned_version,omitempty"`

	EnrolledAt int64 `json:"enrolled_at,omitempty"`

	// LastContact is the last authenticated contact from an ENABLED device, as
	// far as it was saved (unix seconds). The dead-man measures from it. It is not
	// moved across a silence of 30 days or more: see Engine.saveContact.
	LastContact int64 `json:"last_contact,omitempty"`

	// FolderMisses counts consecutive confirmed misses of the pinned release
	// folder on the device's mirror, counted by tasks only: the second one
	// releases the device. FolderMissAt is when the last one was counted (unix
	// seconds): a second answer too soon after the first is the same observation.
	FolderMisses int   `json:"folder_misses,omitempty"`
	FolderMissAt int64 `json:"folder_miss_at,omitempty"`

	// DriftPending is a drift the periodic reconcile found and repaired, still to
	// be reported by the next result.
	DriftPending bool `json:"drift_pending,omitempty"`

	// Pending is an operation that wrote the flavour and has not finished.
	Pending *Pending `json:"pending,omitempty"`

	// Released says the agent took its own pin off (the dead-man). It does not
	// pin again by itself.
	Released *Released `json:"released,omitempty"`

	// HopAborts counts the series upgrade's consecutive aborted attempts, for the
	// back-off (A4.0). Cleared when a hop lands, when the installed series changes
	// and at enroll.
	HopAborts *HopAborts `json:"hop_aborts,omitempty"`

	// Landing is the note a series upgrade leaves when it ended FAILED because the
	// system it left is mixed (the core at the new series, a set or a marker short
	// of it). While it stands a re-pin on that series runs majorLanded first and a
	// mixed system is neither re-pinned nor counted as having reached the series.
	// Cleared when majorLanded passes (someone completed the upgrade), at enroll and
	// when the installed series changes.
	Landing *Landing `json:"landing,omitempty"`
}

// HopAborts is the record of aborted attempts of a series upgrade: its stage 0
// ended without a reboot, or the box restarted before it completed, and nothing
// changed. After two in a row, and for a while after the last, the attempts are
// answered held_upgrade_aborted without touching the box. A disk-full abort is
// held_insufficient_space and adds nothing.
type HopAborts struct {
	Series string `json:"series"`
	At     int64  `json:"at"`
	Streak int    `json:"streak"`
}

// Landing is the note of a hop that ended FAILED on the landing test.
type Landing struct {
	Series string `json:"series"`
	At     int64  `json:"at"`
}

// Pending is written before an operation changes the flavour and cleared when
// the operation ends, so whoever finds it after a crash or a reboot knows which
// values were in play and what to put back.
type Pending struct {
	Op          string `json:"op"`
	TaskID      string `json:"task_id,omitempty"`
	FromFlavour string `json:"from_flavour"`
	ToFlavour   string `json:"to_flavour"`
	// Triggered says an update was requested: the pin is then ahead of the
	// installed release on purpose, and the row's reconciler owns the outcome.
	Triggered bool  `json:"triggered,omitempty"`
	StartedAt int64 `json:"started_at"`
	// Major is the series of a series upgrade that was requested ("" for a minor
	// update). The upgrade writes no flavour, so its pending move has FromFlavour
	// equal to ToFlavour, the pin in force; the field only tells it apart, and gives
	// it the longer time the interval guard leaves it alone for.
	Major string `json:"major,omitempty"`
}

// Released records that the agent unpinned the device on its own.
type Released struct {
	Reason string `json:"reason"`
	At     int64  `json:"at"`
}

// Owns reports whether flavour is a value this record says the agent wrote.
func (s *State) Owns(flavour string) bool {
	if s == nil || flavour == "" {
		return false
	}
	if s.Pinned && flavour == s.PinnedFlavour {
		return true
	}
	return s.Pending != nil && flavour == s.Pending.ToFlavour
}

// clearMisses forgets the folder misses: the folder answered.
func (s *State) clearMisses() { s.FolderMisses, s.FolderMissAt = 0, 0 }

// Empty reports whether the record says nothing worth keeping.
func (s *State) Empty() bool {
	return s == nil || (!s.Pinned && s.Pending == nil && s.Released == nil)
}

// ErrState is a state file the agent cannot read. It is never taken for "not
// enrolled": a device that may hold a pin is not touched on a guess.
var ErrState = errors.New("the firmware track state file cannot be read")

// StateStore keeps the State in a file, replaced atomically, mode 0600.
type StateStore struct {
	path string
	mu   sync.Mutex

	// write and remove are what touch the disk; tests replace them to fail.
	write  func(path string, data []byte) error
	remove func(path string) error
}

// NewStateStore returns the store of the file at path.
func NewStateStore(path string) *StateStore {
	return &StateStore{path: path, write: writeFileAtomic, remove: removeFile}
}

// Path is the file's location.
func (s *StateStore) Path() string { return s.path }

// Load reads the record: nil, nil when there is none.
func (s *StateStore) Load() (*State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.load()
}

func (s *StateStore) load() (*State, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrState, err)
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrState, err)
	}
	if st.V != stateVersion {
		return nil, fmt.Errorf("%w: format %d", ErrState, st.V)
	}
	return &st, nil
}

// Save writes the record, or removes the file when the record says nothing.
// It does not create the directory: when it is gone the agent's state was
// removed, and nothing should be written back.
func (s *StateStore) Save(st *State) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.save(st)
}

func (s *StateStore) save(st *State) error {
	if st.Empty() {
		if err := s.remove(s.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	st.V = stateVersion
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return s.write(s.path, append(data, '\n'))
}

// Update loads the record, lets fn change it and saves the result, under the
// store's lock. fn gets an empty record when there is none.
func (s *StateStore) Update(fn func(*State)) (*State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.load()
	if err != nil {
		return nil, err
	}
	if st == nil {
		st = &State{}
	}
	fn(st)
	if err := s.save(st); err != nil {
		return nil, err
	}
	return st, nil
}

// Remove deletes the record.
func (s *StateStore) Remove() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.remove(s.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// removeFile deletes the record and syncs the directory, for the same reason a
// write does: a removal that sits in the open transaction group comes back after a
// hard reset, and a record that says the agent holds a pin, on a device the
// control plane has just released, would have the next round pin it again.
func removeFile(path string) error {
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

// What touches the disk in writeFileAtomic, as variables so that a test can record
// the order: the file is synced, renamed over the record, and then the directory is
// synced.
var (
	syncFile   = func(f *os.File) error { return f.Sync() }
	renameFile = os.Rename
	syncDir    = func(dir string) error {
		d, err := os.Open(dir)
		if err != nil {
			return err
		}
		defer d.Close()
		err = d.Sync()
		if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) {
			// A filesystem that cannot sync a directory keeps its names as it writes
			// them; there is nothing more to ask of it.
			return nil
		}
		return err
	}
)

// writeFileAtomic replaces the file at path with data, atomically and durably: the
// data is written to a temp file next to it and synced, the temp file is renamed
// over the record, and the directory is synced. Syncing the file alone is not
// enough on ZFS: the rename sits in the open transaction group (up to 90 seconds,
// OPNsense's own vfs.zfs.txg.timeout) and a hard reset right after the request
// that follows brings the previous record back, so the directory is synced too.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := syncFile(tmp); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return err
	}
	if err := renameFile(tmp.Name(), path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	if err := syncDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("sync the directory: %w", err)
	}
	return nil
}
