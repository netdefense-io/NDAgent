package track

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// The record of a request is on disk before the request is made: on ZFS a
// rename sits in the open transaction group for up to 90 seconds, and a hard reset
// right after the request brings the previous record back. The file is synced, then
// renamed over the record, then the directory is synced; and for a series upgrade
// the job and the pending move are both durable before the POST.

type diskLog struct {
	mu    sync.Mutex
	steps []string
}

func (l *diskLog) add(step string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.steps = append(l.steps, step)
}

func (l *diskLog) list() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.steps...)
}

// recordTheDisk replaces what touches the disk in the record's writer with steps that
// log themselves, and puts it back at the end of the test.
func recordTheDisk(t *testing.T) *diskLog {
	t.Helper()
	l := &diskLog{}
	savedSync, savedRename, savedDir := syncFile, renameFile, syncDir
	t.Cleanup(func() { syncFile, renameFile, syncDir = savedSync, savedRename, savedDir })
	syncFile = func(f *os.File) error { l.add("sync-file"); return savedSync(f) }
	renameFile = func(from, to string) error { l.add("rename"); return savedRename(from, to) }
	syncDir = func(dir string) error { l.add("sync-dir"); return savedDir(dir) }
	return l
}

func TestStateStore_AWriteSyncsTheFileRenamesItAndSyncsTheDirectory(t *testing.T) {
	l := recordTheDisk(t)
	store := NewStateStore(filepath.Join(t.TempDir(), "firmware-track.json"))
	if err := store.Save(&State{Pinned: true, Track: TrackFast, PinnedFlavour: "26.7/MINT/26.7.3/latest", PinnedVersion: "26.7.3_11"}); err != nil {
		t.Fatal(err)
	}
	if got := l.list(); !equal(got, []string{"sync-file", "rename", "sync-dir"}) {
		t.Fatalf("steps %v: the directory is synced after the rename, or the rename can be lost with the open transaction group", got)
	}
	if st, err := store.Load(); err != nil || st == nil || !st.Pinned {
		t.Fatalf("the record reads back as %+v (%v)", st, err)
	}
}

func TestStateStore_ARemovalSyncsTheDirectoryToo(t *testing.T) {
	store := NewStateStore(filepath.Join(t.TempDir(), "firmware-track.json"))
	if err := store.Save(&State{Pinned: true, Track: TrackFast, PinnedFlavour: "26.7/MINT/26.7.3/latest", PinnedVersion: "26.7.3_11"}); err != nil {
		t.Fatal(err)
	}
	l := recordTheDisk(t)
	if err := store.Remove(); err != nil {
		t.Fatal(err)
	}
	if got := l.list(); !equal(got, []string{"sync-dir"}) {
		t.Fatalf("steps %v: a removal that sits in the open transaction group comes back after a reset", got)
	}
}

func TestStateStore_AFailedDirectorySyncIsAFailedWrite(t *testing.T) {
	store := NewStateStore(filepath.Join(t.TempDir(), "firmware-track.json"))
	saved := syncDir
	t.Cleanup(func() { syncDir = saved })
	syncDir = func(string) error { return errSim }
	if err := store.Save(&State{Pinned: true}); err == nil {
		t.Fatal("a record that may not be on disk was reported as written")
	}
}

// Both records of the request are on disk, in order, before the POST: the job
// (through Persist) and then the pending move (file, rename, directory), and what
// the file says at that moment is the triggered move of the series upgrade.
func TestDurability_TheJobAndThePendingMoveAreOnDiskBeforeThePost(t *testing.T) {
	r := hopRig(t)
	l := recordTheDisk(t)
	r.dev.onCall("upgrade", func(*simDevice) {
		l.add("POST")
		var onDisk State
		raw, err := os.ReadFile(r.store.Path())
		if err != nil || json.Unmarshal(raw, &onDisk) != nil {
			t.Errorf("the record cannot be read at the request: %v", err)
			return
		}
		if onDisk.Pending == nil || !onDisk.Pending.Triggered || onDisk.Pending.Major != "26.7" {
			t.Errorf("the record on disk at the request: %+v", onDisk.Pending)
		}
	})
	persisted := Job{}
	p := hopPayload(approveFinalHotfix)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	r.dev.onCall("progress", func(*simDevice) { cancel() }) // do not wait for the run
	out := r.eng.Execute(ctx, Input{
		TaskID: "101", Payload: p, Started: time.Now(),
		Save: func(j Job) { r.jobs = append(r.jobs, j) },
		Persist: func(j Job) error {
			l.add("persist-job")
			persisted = j
			return nil
		},
	})
	if !out.Aborted {
		t.Fatalf("got %+v", out)
	}
	if persisted.Phase != PhaseTriggered || persisted.Major != "26.7" || persisted.Upgrade == nil {
		t.Fatalf("the job persisted before the request: %+v", persisted)
	}

	steps := l.list()
	job := orderOf(steps, "persist-job", 0)
	file := orderOf(steps, "sync-file", job)
	rename := orderOf(steps, "rename", file)
	dir := orderOf(steps, "sync-dir", rename)
	post := orderOf(steps, "POST", dir)
	if job < 0 || file < 0 || rename < 0 || dir < 0 || post < 0 {
		t.Fatalf("steps %v: want the job, the file, the rename, the directory, then the POST", steps)
	}
}

// Nothing is requested on a record that may be lost: a job that cannot be made
// durable, or a pending move that cannot be written, is a hold before the request.
func TestDurability_NothingIsRequestedOnARecordThatMayBeLost(t *testing.T) {
	t.Run("the job cannot be made durable", func(t *testing.T) {
		r := hopRig(t)
		p := hopPayload(approveFinalHotfix)
		out := r.execute(Input{
			TaskID: "101", Payload: p, Started: time.Now(),
			Save:    func(j Job) { r.jobs = append(r.jobs, j) },
			Persist: func(Job) error { return errors.New("the task store is read-only") },
		})
		r.checkOutcome(p, out)
		wantHop(t, wantResult(t, out, OutcomeHeld, ReasonHeldCheckFailed), NoteBootEnvironmentMade)
		if r.dev.posts() != 0 {
			t.Error("the request was made on a record that may be lost")
		}
		for _, j := range r.jobs {
			if j.Phase == PhaseTriggered {
				t.Errorf("job %+v left triggered", j)
			}
		}
		if st := r.state(); st.Pending != nil {
			t.Errorf("pending %+v", st.Pending)
		}
	})

	t.Run("the pending move cannot be written", func(t *testing.T) {
		r := hopRig(t)
		persisted := false
		saved := syncDir
		t.Cleanup(func() { syncDir = saved })
		syncDir = func(dir string) error {
			if persisted {
				return errSim
			}
			return saved(dir)
		}
		p := hopPayload(approveFinalHotfix)
		out := r.execute(Input{
			TaskID: "101", Payload: p, Started: time.Now(),
			Save:    func(j Job) { r.jobs = append(r.jobs, j) },
			Persist: func(Job) error { persisted = true; return nil },
		})
		r.checkOutcome(p, out)
		wantHop(t, wantResult(t, out, OutcomeHeld, ReasonHeldCheckFailed), NoteBootEnvironmentMade)
		if r.dev.posts() != 0 {
			t.Error("the request was made on a record that may be lost")
		}
		if last := r.jobs[len(r.jobs)-1]; last.Phase == PhaseTriggered || last.Upgrade != nil {
			t.Errorf("the job was left as requested: %+v", last)
		}
	})
}
