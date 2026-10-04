package firmware

import (
	"context"
	"sync"
)

// OPNsense has one firmware job at a time: launcher.sh takes its lock with
// `flock -n`, and a request that finds it held is dropped without a word. A
// check and an update also share one progress log, and starting a check truncates
// it. The agent has three callers that would each do that to the others: two
// FIRMWARE_UPGRADE tasks (a daily and a weekly schedule dispatch in the same
// second every Sunday), the heavy-telemetry collector (a check every 6 hours
// and when something calls for one), and the reconciler that is waiting for an
// update the previous process started. This is their shared, in-process guard.
// It cannot see a job somebody else started (the web GUI, a shell): the
// pre-trigger wait and the start check in the handler, and the collector's own
// look at /running, cover that.

var (
	guardMu sync.Mutex
	// taken: a FIRMWARE_UPGRADE run holds the slot.
	taken bool
	// triggered: the run holding the slot asked OPNsense to apply an update or
	// upgrade.
	triggered bool
	// watching is how many rows the reconciler is waiting on.
	watching int
	// changed is closed, and replaced, whenever taken or watching changes, so
	// that a waiter can sleep until they do.
	changed = make(chan struct{})
)

// wake tells every waiter that the state changed. guardMu must be held.
func wake() {
	close(changed)
	changed = make(chan struct{})
}

// Acquire waits for the slot and returns the function that gives it back, which
// is safe to call more than once. It waits for two things: no other run holds the
// slot, and the reconciler is not waiting on a run nothing in this process owns
// any more (one whose handler was cancelled by a dropped connection, or that the
// previous process started): both leave OPNsense busy without a holder to wait
// for. onWait, if not nil, runs once when the caller has to wait, so the task can
// say so. It returns the context's error if the context ends first, and never
// hands out the slot to a context that has already ended.
func Acquire(ctx context.Context, onWait func()) (release func(), err error) {
	waited := false
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		guardMu.Lock()
		if !taken && watching == 0 {
			taken = true
			guardMu.Unlock()
			return releaser(), nil
		}
		changes := changed
		guardMu.Unlock()

		if !waited && onWait != nil {
			waited = true
			onWait()
		}
		select {
		case <-changes:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func releaser() func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			guardMu.Lock()
			applied := triggered
			taken, triggered = false, false
			wake()
			guardMu.Unlock()
			if applied {
				NoteOutcome()
			}
		})
	}
}

// NoteTriggered records that the run holding the slot asked OPNsense to apply
// an update or upgrade: giving the slot back then notes an outcome
// (NoteOutcome). Without a run holding the slot it does nothing.
func NoteTriggered() {
	guardMu.Lock()
	defer guardMu.Unlock()
	if taken {
		triggered = true
	}
}

// Watch records how many FIRMWARE_UPGRADE rows the reconciler is waiting on, for
// Busy and Acquire. It replaces the previous count; 0 clears it.
func Watch(rows int) {
	guardMu.Lock()
	defer guardMu.Unlock()
	if watching != rows {
		watching = rows
		wake()
	}
}

// Busy reports whether a firmware update is in progress as far as this process
// knows: a run holds the slot, or the reconciler is waiting for one to end.
// Anything that would start a firmware check must not while it is true, because
// the check would take the lock the update needs, or be dropped by it, and
// truncate the progress log the update is being judged by.
func Busy() bool {
	guardMu.Lock()
	defer guardMu.Unlock()
	return taken || watching > 0
}

// outcomes holds at most one pending "an update or upgrade ended": however many
// end, one check for updates afterwards is enough.
var outcomes = make(chan struct{}, 1)

// NoteOutcome records that a FIRMWARE_UPGRADE run that applied, or tried to
// apply, an update or upgrade reached its outcome. What is pending has changed,
// so the heavy-telemetry collector checks for updates again. A dry run, a run
// with nothing to apply and one that failed before asking OPNsense for anything
// change nothing, and note none. It never blocks.
func NoteOutcome() {
	select {
	case outcomes <- struct{}{}:
	default:
	}
}

// Outcomes delivers a value after one or more NoteOutcome calls.
func Outcomes() <-chan struct{} {
	return outcomes
}
