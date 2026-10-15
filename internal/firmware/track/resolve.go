package track

import (
	"context"
	"strings"
	"time"

	"github.com/netdefense-io/ndagent/internal/firmware"
)

// Row is a task row whose handler is gone, as the reconciler sees it.
type Row struct {
	TaskID    string
	StartedAt time.Time
}

// Resolve decides how a task ended whose handler is not running any more: the
// connection dropped under it, or the agent was stopped, by the reboot of the
// update itself or otherwise. The second result says whether the task can be
// resolved yet; false leaves it IN_PROGRESS and the reconciler asks again.
//
// What decides it is the device and the record the task left, never the agent
// coming back:
//
//   - a task that had not changed anything (or whose changes the repair undoes)
//     ends as a hold, because nothing was applied; an enroll that had in fact
//     completed (the record holds the pin and the setting equals it) ends as
//     that enrollment;
//   - a task whose update was requested ends when firmware.Evaluate says the run
//     is over: completed with the release read back, or failed.
//
// It never blocks behind a task that is running (TryLock) and takes the firmware
// slot without waiting, so a sweep inside the connect cannot stall it.
func (e *Engine) Resolve(ctx context.Context, job Job, row Row) (out *Outcome, done bool) {
	if !e.mu.TryLock() {
		return nil, false
	}
	defer e.mu.Unlock()
	defer func() {
		if r := recover(); r != nil {
			e.logPanic("row", r)
			out, done = nil, false
		}
	}()

	release, ok := firmware.TryAcquireResolver()
	if !ok {
		return nil, false
	}
	defer release()

	o := e.opFromJob(job, row)
	if job.Phase == PhaseTriggered && job.Upgrade != nil {
		return e.resolveTriggered(ctx, o, row)
	}
	return e.resolveUntriggered(ctx, o, row)
}

// opFromJob rebuilds the op of a task whose handler is gone from the record the
// task left, so that a result or a failure detail built after the reboots echoes
// what the dispatch said: the action, the track, the approved map and the `major`
// the payload carried. A series upgrade that was requested answers as the hop
// (the answer rule): kind major, the series as its target and the notes its
// attempt found, which the job carried across the reboots. Any other row, a step
// that carried `major` and ran the minor update included, answers as the ordinary
// step.
func (e *Engine) opFromJob(job Job, row Row) *op {
	o := &op{
		in: Input{
			TaskID:  row.TaskID,
			Payload: Payload{Action: job.Action, Track: job.Track, Approved: job.Approved, Reboot: job.Reboot, Major: job.Major},
			Started: time.Unix(job.StartedAt, 0),
			Expires: time.Unix(job.ExpiresAt, 0),
		},
		job:        job,
		from:       job.From,
		to:         job.From,
		target:     job.Target,
		drift:      job.Drift,
		reinstalls: job.Reinstalls,
		installed:  job.From,
	}
	if job.isHop() {
		o.kind, o.target = KindMajor, job.Major
		o.notes = append([]string(nil), job.Notes...)
	}
	return o
}

func (e *Engine) pastDeadline(job Job) bool {
	return e.now().After(firmware.Deadline(time.Unix(job.ExpiresAt, 0))) && e.uptime() > firmware.Grace
}

func (e *Engine) resolveTriggered(ctx context.Context, o *op, row Row) (*Outcome, bool) {
	meta := *o.job.Upgrade
	if e.neverRequested(ctx, meta) {
		e.log.Infow("The update was marked requested but OPNsense never ran it; putting the pin back", "task_id", row.TaskID)
		e.unmarkTriggered(o, &meta)
		e.undoMove(ctx, o, o.job.PrevFlavour, o.job.NewFlavour)
		if ctx.Err() != nil {
			return nil, false
		}
		if st, err := e.store.Load(); err == nil && st != nil && st.Pinned {
			o.pinned = st.PinnedVersion
		}
		// The job is triggered, so the hold is the series upgrade's when it was one:
		// the answer carries its kind and notes.
		return e.hold(o, ReasonHeldCheckFailed), true
	}
	if o.job.isHop() {
		return e.resolveHop(ctx, o, row, meta)
	}
	v := firmware.Evaluate(ctx, firmware.Input{
		Meta:          &meta,
		RowStartedAt:  row.StartedAt,
		Now:           e.now(),
		ProcessUptime: e.uptime(),
	}, e.dev.Probes())
	switch v.Action {
	case firmware.Complete:
		e.log.Infow("Firmware track update resolved: completed", "task_id", row.TaskID, "reason", v.Reason)
		o.drift = o.drift || e.driftOnRecord()
		out := e.finishApplied(ctx, o, 0)
		if out.Aborted {
			// What the answer needs cannot be read yet. The next sweep asks again, and the
			// row ends with its time like any that cannot be settled.
			return e.stillUnresolved(o)
		}
		return out, true
	case firmware.Fail:
		e.log.Infow("Firmware track update resolved: failed", "task_id", row.TaskID, "reason", v.Reason)
		return e.failApplied(ctx, o, v.Message), true
	}
	e.log.Debugw("Firmware track update has not ended yet", "task_id", row.TaskID, "reason", v.Reason, "detail", v.Message)
	return nil, false
}

// neverRequested reports whether an update the row says was requested never
// reached OPNsense: the agent stopped between recording the request and making it.
// The record is written first on purpose (an update that ran must never be taken
// for one that did not, with the pin moved back under it), so this is told from the
// device: the box has not restarted since, nothing runs, and the progress log holds
// no update request. A log that holds one may be an earlier run's, and then the
// run is judged the usual way; so is a run that does not go through the launcher
// (reboot=false), which leaves no such line.
func (e *Engine) neverRequested(ctx context.Context, meta firmware.Meta) bool {
	if !meta.Reboot || meta.RebootSeen || meta.BootTime == 0 {
		return false
	}
	boot, err := e.bootTime()
	if err != nil || time.Unix(boot, 0).After(time.Unix(meta.BootTime, 0).Add(firmware.BootMargin)) {
		return false
	}
	if !e.firmwareIdle(ctx) {
		return false
	}
	prog, err := e.dev.Progress(ctx)
	return err == nil && prog != nil && !strings.Contains(prog.Log, requestMarker(meta.Mode))
}

// driftOnRecord reports a drift the periodic reconcile found and repaired.
func (e *Engine) driftOnRecord() bool {
	st, err := e.store.Load()
	return err == nil && st != nil && st.DriftPending
}

func (e *Engine) resolveUntriggered(ctx context.Context, o *op, row Row) (*Outcome, bool) {
	st, err := e.store.Load()
	if err != nil {
		// A record nothing can read is no reason to keep the row for ever: the
		// reconciler holds every other firmware job out while a row waits.
		e.log.Warnw("Cannot read the firmware track record to settle a task", "task_id", row.TaskID, "error", err)
		return e.stillUnresolved(o)
	}
	if st != nil && st.Pending != nil && !st.Pending.Triggered {
		e.repairPending(ctx, st)
		if st, err = e.store.Load(); err != nil {
			return e.stillUnresolved(o)
		}
		if st != nil && st.Pending != nil {
			return e.stillUnresolved(o)
		}
	}
	settings, serr := e.dev.Settings(ctx)
	installed, ierr := e.dev.Installed(ctx)
	if serr != nil || ierr != nil {
		return e.stillUnresolved(o)
	}
	if _, ok := SeriesOf(installed); ok {
		o.installed, o.from, o.to = installed, installed, installed
	}
	intact := st != nil && st.Pinned && st.Pending == nil && settings.Flavour == st.PinnedFlavour
	if intact {
		o.pinned = st.PinnedVersion
	}

	switch o.job.Action {
	case ActionUnenroll:
		if st == nil || !st.Pinned {
			return e.result(o, OutcomeSuccess, ReasonUnenrolled), true
		}
		return e.stillUnresolved(o)
	case ActionEnroll:
		if intact {
			// The enrollment had completed; only its answer was lost.
			return e.result(o, OutcomeNoop, ReasonEnrolled), true
		}
	}
	// Nothing was applied by this task. The control plane asks again at the next window.
	if intact {
		o.pinned = st.PinnedVersion
	}
	return e.hold(o, ReasonHeldCheckFailed), true
}

// stillUnresolved keeps a task IN_PROGRESS until its time is up, and ends it
// then. An unenroll is failed, so that it is not taken for a success and the
// control plane asks again; so is an enroll, which is asked again at once. An
// advance that never asked OPNsense for anything is a hold: a FAILED advance
// counts against the release it was moving to, for the whole organization, and
// this one never touched the device.
func (e *Engine) stillUnresolved(o *op) (*Outcome, bool) {
	if !e.pastDeadline(o.job) {
		return nil, false
	}
	if o.job.Action == ActionAdvance && o.job.Phase != PhaseTriggered {
		e.log.Warnw("An advance that requested no update could not be settled before its time ran out; holding", "task_id", o.in.TaskID)
		return e.hold(o, ReasonHeldCheckFailed), true
	}
	return e.fail(o, "The firmware %s could not be settled before the task's time ran out", o.job.Action), true
}
