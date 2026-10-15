package track

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/netdefense-io/ndagent/internal/firmware"
	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// The progress-log lines OPNsense's launcher writes when it starts an update and
// when it starts a series upgrade (it prints ***GOT REQUEST TO ${REQUEST}***).
const (
	updateRequestMarker  = "***GOT REQUEST TO UPDATE***"
	upgradeRequestMarker = "***GOT REQUEST TO UPGRADE***"
)

// requestMarker is the line a run of the given mode (firmware.Meta.Mode) leaves in
// the progress log when it starts: the start of a run is proved by it, in a log
// that changed, and never by a file's modification time.
func requestMarker(mode string) string {
	if mode == "major" {
		return upgradeRequestMarker
	}
	return updateRequestMarker
}

// endedElsewhere is watchUpdate's answer for an end marker that belongs to
// another firmware job.
const endedElsewhere = "elsewhere"

// apply requests the update the verified plan describes and watches it to its
// end. The pin is at the target's directory, so the update OPNsense runs (the
// REST /update, or `opnsense-update -pt` for a run without a reboot) installs
// that directory's catalog and nothing else.
//
// The run is OPNsense's, not the agent's: a detached process tree that outlives
// the handler whenever the box reboots or a package in the run replaces the
// agent's own. So what is recorded before the request is what the reconciler
// needs to decide the outcome later (Job, with firmware.Meta inside), and a task
// that is cut short is left IN_PROGRESS rather than answered on a guess.
func (e *Engine) apply(ctx context.Context, o *op, status *opnapi.FirmwareUpgradeStatus, prev, next string) *Outcome {
	bootTime, err := e.bootTime()
	if err != nil {
		bootTime = 0
		e.log.Warnw("Cannot read the boot time; a reboot cannot be confirmed later", "error", describeErr(err))
	}
	meta := firmware.NewMeta("minor", o.in.Payload.Reboot, o.installed, status, bootTime, o.in.Started, o.in.Expires)
	o.job.Upgrade = &meta
	o.saveJob()

	if !o.in.Payload.Reboot {
		return e.applyPackagesOnly(ctx, o, &meta, prev, next)
	}
	return e.applyViaREST(ctx, o, &meta, prev, next)
}

// markTriggered records that the update is about to be requested, in the job and
// in the pending move, right before the request, and returns once both are on
// disk (the job through Input.Persist, the pending move through the record's own
// synced write). A record that cannot be written is an error: nothing is
// requested on a record that may be lost, and the caller holds.
func (e *Engine) markTriggered(o *op, meta *firmware.Meta) error {
	meta.TriggeredAt = e.now().Unix()
	o.job.Phase = PhaseTriggered
	if err := o.persistJob(); err != nil {
		e.log.Errorw("Cannot record that the update is about to be requested; not requesting it", "error", err)
		return err
	}
	if _, err := e.store.Update(func(s *State) {
		if s.Pending != nil {
			s.Pending.Triggered = true
		}
	}); err != nil {
		e.log.Errorw("Cannot record that the update is about to be requested; not requesting it", "error", err)
		return err
	}
	firmware.NoteTriggered()
	return nil
}

// unmarkTriggered undoes markTriggered for a request that did not start anything.
func (e *Engine) unmarkTriggered(o *op, meta *firmware.Meta) {
	meta.TriggeredAt = 0
	o.job.Phase = PhaseMoved
	if meta.Mode == "major" {
		// A series upgrade writes no flavour, so the job never reached "moved".
		o.job.Phase = PhaseStarted
	}
	o.saveJob()
	if _, err := e.store.Update(func(s *State) {
		if s.Pending != nil {
			s.Pending.Triggered = false
		}
	}); err != nil {
		e.log.Warnw("Cannot record that the update was not started", "error", err)
	}
}

// nothingStarted ends a task whose update request did not start anything: the
// pin goes back where it was and the task holds. It is not a failure: nothing
// was applied, and what is wrong is OPNsense's lock or API, not the release.
//
// The pin is not written under a running firmware job (firmwareIdle: anything
// unreadable counts as running), because the write replays the repository files
// the job is reading from, and the cause of the hold is usually such a job. The
// move then stays recorded as pending and the periodic round puts the pin back
// once the box is idle: until then it sits ahead of the installed release, never
// below it.
func (e *Engine) nothingStarted(ctx context.Context, o *op, meta *firmware.Meta, prev, next, reason string) *Outcome {
	e.unmarkTriggered(o, meta)
	if next != prev && !e.firmwareIdle(detached(ctx)) {
		e.log.Warnw("A firmware job is running; leaving the pin for the periodic round to put back",
			"task_id", o.in.TaskID, "pin", next, "back_to", prev)
	} else {
		e.undoMove(ctx, o, prev, next)
	}
	if ctx.Err() != nil {
		return aborted()
	}
	return e.hold(o, reason)
}

func (e *Engine) applyViaREST(ctx context.Context, o *op, meta *firmware.Meta, prev, next string) *Outcome {
	o.progress(fmt.Sprintf("Updating from %s to %s; OPNsense will reboot if it needs to...", o.installed, o.target))
	return e.requestRun(ctx, o, meta, prev, next, runSpec{marker: updateRequestMarker, trigger: e.dev.TriggerUpdate})
}

// runSpec is what differs between asking OPNsense for the minor update and for the
// series upgrade: the request, the line that proves it started, and whether the job
// and the pending move were recorded as triggered before this point.
type runSpec struct {
	marker  string
	trigger func(ctx context.Context) (string, error)
	// marked says the record of the request was written already: the series upgrade
	// records it in A4.11, with the four versions and the notes, right before this.
	marked bool
	// recheck, when set, is asked before every request after the first: the box may
	// not be what the step was made for any more, because another firmware job held
	// OPNsense's lock in between. It returns the reason to hold for, "" to go on.
	recheck func(ctx context.Context) string
}

// requestRun makes the request and watches the run to its end. The request is
// asked again once if OPNsense dropped it, and only if the task can still afford
// the run.
func (e *Engine) requestRun(ctx context.Context, o *op, meta *firmware.Meta, prev, next string, spec runSpec) *Outcome {
	var (
		baseline string
		start    startEvidence
	)
	// No wait for the backend goes into the time the update needs, and the second
	// request is only made if that time is still there once the backend is free.
	limit := o.updateLimit()
	for attempt := 1; ; attempt++ {
		if err := e.waitReadyUntil(ctx, limit); err != nil {
			if ctx.Err() != nil {
				return aborted()
			}
			return e.nothingStarted(ctx, o, meta, prev, next, ReasonHeldFirmwareBusy)
		}
		if attempt > 1 && !e.now().Before(limit) {
			return e.noTimeToAskAgain(ctx, o, meta, prev, next)
		}
		if attempt > 1 && spec.recheck != nil {
			if reason := spec.recheck(ctx); reason != "" {
				if ctx.Err() != nil {
					return aborted()
				}
				return e.nothingStarted(ctx, o, meta, prev, next, reason)
			}
		}
		baseline = e.progressLog(ctx)
		if ctx.Err() != nil {
			return aborted()
		}
		if attempt == 1 && !spec.marked {
			if err := e.markTriggered(o, meta); err != nil {
				return e.nothingStarted(ctx, o, meta, prev, next, ReasonHeldCheckFailed)
			}
		}
		// The request is made to the end whatever happens to the connection: it is a
		// local call that takes moments, and one cut off half way leaves the task not
		// knowing whether OPNsense heard it.
		answer, err := spec.trigger(detached(ctx))
		if err != nil {
			e.log.Warnw("Cannot request the firmware update", "error", describeErr(err))
			// The request may have been accepted and its answer lost (a timeout, a
			// reset): the update then runs on without the agent, and moving the
			// repositories under it is what must not happen. Look before undoing.
			if start = e.runStarted(ctx, baseline, spec.marker); start == notStarted {
				if ctx.Err() != nil {
					return aborted()
				}
				return e.nothingStarted(ctx, o, meta, prev, next, ReasonHeldCheckFailed)
			}
			e.log.Warnw("OPNsense started the update although the request reported an error; watching it")
			break
		}
		if answer != "ok" {
			e.log.Warnw("OPNsense did not accept the firmware update request", "answer", answer)
			return e.nothingStarted(ctx, o, meta, prev, next, ReasonHeldCheckFailed)
		}
		if start = e.runStarted(ctx, baseline, spec.marker); start != notStarted {
			break
		}
		if ctx.Err() != nil {
			return aborted()
		}
		if attempt == 2 {
			e.log.Warnw("OPNsense accepted the update request but did not start it; another firmware job probably held its lock")
			return e.nothingStarted(ctx, o, meta, prev, next, ReasonHeldFirmwareBusy)
		}
		e.log.Warnw("OPNsense accepted the update request but did not start it; asking once more")
	}

	sentinel := e.watchUpdate(ctx, o, meta, baseline, start == startedByMarker, spec.marker)
	if ctx.Err() != nil {
		e.log.Infow("The task's context ended while the update ran; leaving it IN_PROGRESS", "task_id", o.in.TaskID)
		return aborted()
	}
	if sentinel == endedElsewhere {
		return e.otherJobEnded(ctx, o, meta, prev, next)
	}
	return e.settle(ctx, o, meta, sentinel)
}

// noTimeToAskAgain ends a task whose first update request was dropped by another
// firmware job and which cannot afford to wait for the backend and ask again: its
// time went to waiting behind another firmware job, which is what
// held_firmware_busy says. Starting the update with less than it needs would risk
// a task that runs past its signed expiry, which the control plane counts as a
// failure of the release.
func (e *Engine) noTimeToAskAgain(ctx context.Context, o *op, meta *firmware.Meta, prev, next string) *Outcome {
	e.log.Warnw("OPNsense dropped the update request and the task has no time left to wait for the backend and ask again",
		"task_id", o.in.TaskID, "expires", o.in.Expires.UTC())
	return e.nothingStarted(ctx, o, meta, prev, next, ReasonHeldFirmwareBusy)
}

// otherJobEnded settles a run that was believed to be the requested update and
// turned out to be another firmware job's (a check from the GUI, the cron job or a
// shell that held OPNsense's lock when the request arrived): its end marker says
// nothing about the update, and judging the device by it would fail a window that
// never ran. When the release has not moved nothing was applied, so the task holds
// with the pin back. A release that has moved, or cannot be read, is the device's
// to tell, as for any run.
func (e *Engine) otherJobEnded(ctx context.Context, o *op, meta *firmware.Meta, prev, next string) *Outcome {
	e.log.Warnw("The firmware job that ended is not the update requested; another job held OPNsense's lock", "task_id", o.in.TaskID)
	if err := e.waitReadyUntil(ctx, o.updateLimit()); err != nil && ctx.Err() != nil {
		return aborted()
	}
	// The release is read as finishApplied reads it, repeated for a bounded time: an
	// API that is settling at this very moment must not make the device decide a run
	// that never started.
	cx := detached(ctx)
	var installed string
	err := e.retryFor(cx, e.timing.APIWait, func() (err error) {
		installed, err = e.dev.Installed(cx)
		return err
	}, nil)
	if err == nil && installed == o.installed {
		return e.nothingStarted(ctx, o, meta, prev, next, ReasonHeldFirmwareBusy)
	}
	return e.settle(ctx, o, meta, "")
}

func (e *Engine) applyPackagesOnly(ctx context.Context, o *op, meta *firmware.Meta, prev, next string) *Outcome {
	o.progress(fmt.Sprintf("Updating the packages from %s to %s without a reboot...", o.installed, o.target))
	if err := e.waitReadyUntil(ctx, o.updateLimit()); err != nil {
		if ctx.Err() != nil {
			return aborted()
		}
		return e.nothingStarted(ctx, o, meta, prev, next, ReasonHeldFirmwareBusy)
	}
	if err := e.markTriggered(o, meta); err != nil {
		return e.nothingStarted(ctx, o, meta, prev, next, ReasonHeldCheckFailed)
	}
	res, err := e.dev.ApplyPackagesOnly(ctx)
	if ctx.Err() != nil && (err != nil || res.ExitCode != 0) {
		// A cancelled context kills opnsense-update, and pkg, which it started, goes
		// on. That is neither a failed run nor a finished one.
		e.log.Infow("The task's context ended during opnsense-update; leaving it IN_PROGRESS", "task_id", o.in.TaskID)
		return aborted()
	}
	if err != nil {
		e.log.Warnw("Cannot run opnsense-update", "error", describeErr(err))
		return e.nothingStarted(ctx, o, meta, prev, next, ReasonHeldCheckFailed)
	}
	if res.ExitCode != 0 {
		if e.turnedAway(ctx, o, res) {
			e.log.Warnw("opnsense-update was turned away by another firmware job; nothing was installed",
				"task_id", o.in.TaskID, "exit_code", res.ExitCode)
			return e.nothingStarted(ctx, o, meta, prev, next, ReasonHeldFirmwareBusy)
		}
		return e.failApplied(ctx, o, fmt.Sprintf("opnsense-update exited with code %d: %s", res.ExitCode, firstLine(res.Tail)))
	}
	return e.settle(ctx, o, meta, "")
}

// turnedAway reports whether a failed opnsense-update was refused by another
// firmware job or package tool rather than failing on its own. pkg takes its
// database lock before it installs anything, so a refusal leaves the release
// where it was; it is told from a real failure by pkg saying the database is
// locked, or by a firmware job running now. A release that moved, or cannot be
// read, is a failure.
func (e *Engine) turnedAway(ctx context.Context, o *op, res ExecResult) bool {
	cx := detached(ctx)
	installed, err := e.dev.Installed(cx)
	if err != nil || installed != o.installed {
		return false
	}
	return lockRefusal(res.Tail) || !e.firmwareIdle(cx)
}

// lockRefusal reports whether pkg's output says another process held its
// database ("Cannot get an exclusive lock on a database, it is locked by another
// process").
func lockRefusal(output string) bool {
	output = strings.ToLower(output)
	return strings.Contains(output, "locked by another process") || strings.Contains(output, "database is locked")
}

// progressLog reads OPNsense's progress log, "" when it cannot.
func (e *Engine) progressLog(ctx context.Context) string {
	prog, err := e.dev.Progress(ctx)
	if err != nil || prog == nil {
		return ""
	}
	return prog.Log
}

// startEvidence is how OPNsense showed that the update just requested started.
type startEvidence int

const (
	// notStarted: no sign of it within the window.
	notStarted startEvidence = iota
	// startedByMarker: the progress log changed and carries the request marker.
	startedByMarker
	// startedUnread: the progress log could not be read, or was empty, while the
	// backend was busy. The API goes away while OPNsense replaces its core package,
	// so a request that did start can show nothing else; the run is believed until
	// its log says otherwise (see watchUpdate).
	startedUnread
)

// runStarted reports how OPNsense showed that the request just made started.
// Its launcher takes a lock with `flock -n` and drops a request that finds it held
// without saying so, while the API still answers "ok", so the answer proves
// nothing, and neither does a busy backend: whoever holds the lock (a check from
// the GUI or the cron job, an update from a shell) is not this request, and
// its end marker would be taken for the update's. A run shows it started when the
// progress log changed and carries the request marker (an unchanged log is the
// previous run's). Only while the log cannot be read or is empty does a busy
// backend stand in for the marker: a log that reads and lacks it belongs to
// another job.
func (e *Engine) runStarted(ctx context.Context, baseline, marker string) startEvidence {
	deadline := e.now().Add(e.timing.StartWindow)
	for {
		log := e.progressLog(ctx)
		switch {
		case log != baseline && strings.Contains(log, marker):
			return startedByMarker
		case log == "":
			if state, err := e.dev.Running(ctx); err == nil && state == firmware.RunBusy {
				return startedUnread
			}
		}
		if ctx.Err() != nil || e.now().After(deadline) {
			return notStarted
		}
		if err := e.sleep(ctx, e.timing.StartPoll); err != nil {
			return notStarted
		}
	}
}

// watchUpdate polls OPNsense's progress until its end marker appears or the
// run's deadline passes. It does not give up on anything else: the API goes away
// while OPNsense replaces its own core package (configd and the web GUI
// restart, in the first minute of every core update) and again for the reboot,
// and answers "error" when the progress log is empty, which is also what a
// freshly booted box answers. None of that is the end of the run.
//
// When OPNsense announces the reboot the box is going down and takes the agent
// with it; the handler stays, holding the firmware slot, until the agent is
// stopped or the deadline passes without the box going down.
//
// ours says the log has already shown the request marker (marker: the line of the
// run's mode). A run that was only believed started (the log could not be read when
// it was asked) is held to it: a log that reads, ends with ***DONE*** and carries no
// marker of the update, or is the log of the run before it, belongs to another job,
// and is reported as endedElsewhere instead of as the end of the update.
//
// `done` ends the watch only as the log's last non-empty line, and, for the run's
// own log, with the backend ready. OPNsense reads the status "done" as soon as
// ***DONE*** occurs anywhere in the log, before it looks for ***REBOOT***, and a
// transient early ***DONE*** was read in the log of an update that ran clean to its
// reboot: taken for the end it would make Evaluate fail the run as one that finished
// without the reboot it needed. Until the log ends with it and the lock is free the
// watch goes on. Another job's end is not judged by the lock: the lock is then held
// by whatever runs now, and otherJobEnded waits for it inside the task's time.
func (e *Engine) watchUpdate(ctx context.Context, o *op, meta *firmware.Meta, baseline string, ours bool, marker string) string {
	deadline := firmware.Deadline(meta.Expiry())
	pollCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	sentinel := ""
	failures := 0
poll:
	for {
		if err := e.sleep(pollCtx, e.timing.Poll); err != nil {
			break
		}
		if !e.now().Before(deadline) {
			// The engine's own clock says the time is up (the context's deadline is the
			// same moment on the wall clock; a test that moves the engine's clock
			// reaches it without waiting for the real one).
			break
		}
		prog, err := e.dev.Progress(pollCtx)
		if err != nil || prog == nil {
			if failures++; failures == 1 || failures%12 == 0 {
				e.log.Infow("Firmware progress not readable; still watching", "failures", failures, "error", describeErr(err))
			}
			continue
		}
		failures = 0
		ours = ours || (prog.Log != baseline && strings.Contains(prog.Log, marker))
		switch prog.Status {
		case "done", "reboot":
			if prog.Status == "done" {
				if lastLine(prog.Log) != "***DONE***" {
					continue // a transient early marker: the job goes on
				}
				if !ours {
					return endedElsewhere
				}
				if state, err := e.dev.Running(pollCtx); err != nil || state != firmware.RunReady {
					continue // the lock is still held: the run is not over
				}
			}
			sentinel = prog.Status
			break poll
		}
	}
	if sentinel == "reboot" {
		meta.RebootSeen = true
		o.job.Upgrade = meta
		o.saveJob()
		e.log.Infow("The system is rebooting; holding the firmware slot until the agent is stopped", "task_id", o.in.TaskID)
		<-pollCtx.Done()
		sentinel = ""
	}
	return sentinel
}

// lastLine is the last non-empty line of text, trimmed.
func lastLine(text string) string {
	lines := strings.Split(text, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if t := strings.TrimSpace(lines[i]); t != "" {
			return t
		}
	}
	return ""
}

// settle asks the device how the run ended, until it can say, and reports it.
// sentinel is "done" when OPNsense said so and "" when the deadline ran out first.
func (e *Engine) settle(ctx context.Context, o *op, meta *firmware.Meta, sentinel string) *Outcome {
	if o.kind == KindMajor {
		return e.settleHop(ctx, o, meta, sentinel)
	}
	probes := e.dev.Probes()
	for {
		v := firmware.Evaluate(ctx, firmware.Input{
			Meta:          meta,
			RowStartedAt:  time.Unix(meta.StartedAt, 0),
			Sentinel:      sentinel,
			Now:           e.now(),
			ProcessUptime: e.uptime(),
		}, probes)
		switch v.Action {
		case firmware.Complete:
			e.log.Infow("The firmware update ended: completed", "task_id", o.in.TaskID, "reason", v.Reason)
			return e.finishApplied(ctx, o, e.timing.APIWait)
		case firmware.Fail:
			e.log.Infow("The firmware update ended: failed", "task_id", o.in.TaskID, "reason", v.Reason)
			return e.failApplied(ctx, o, v.Message)
		}
		e.log.Infow("The firmware update has not ended yet", "task_id", o.in.TaskID, "reason", v.Reason, "detail", v.Message)
		if err := e.sleep(ctx, e.timing.Settle); err != nil {
			return aborted()
		}
	}
}

// finishApplied is the end of an update that completed: the installed release is
// read back from the version file, never inferred from the agent coming back,
// and has to have reached the target; the pin follows it.
//
// The device has already said the update completed, so a read that fails here
// (the firmware API can still be settling after the reboot) says nothing about
// the update, and is never turned into a FAILED that names the release. Each read
// is repeated for up to wait. The release and the agent's record are what the
// answer cannot do without: while either cannot be read the task is left
// unsettled (Aborted) for the next evaluation of its row. The firmware settings
// only show whether the pin held, so without them the update is answered as
// applied and the periodic round checks the pin against the record.
func (e *Engine) finishApplied(ctx context.Context, o *op, wait time.Duration) *Outcome {
	cx := detached(ctx)

	var installed string
	if err := e.retryFor(cx, wait, func() (err error) {
		installed, err = e.dev.Installed(cx)
		return err
	}, nil); err != nil {
		return e.unsettled(o, "the installed release", err)
	}
	o.installed, o.to = installed, installed
	if ok, comparable := AtOrAbove(installed, o.target); !comparable || !ok {
		return e.failApplied(cx, o, fmt.Sprintf("The firmware update ended with release %s installed, below the target %s", installed, o.target))
	}
	if why := e.setsStillOld(cx, o); why != "" {
		return e.failApplied(cx, o, "The firmware update ended with the release at the target but the base system and kernel not installed ("+
			why+"): the box restarted before it got to them. The next window finishes it.")
	}

	var st *State
	if err := e.retryFor(cx, wait, func() (err error) {
		st, err = e.store.Load()
		return err
	}, nil); err != nil {
		return e.unsettled(o, "the agent's record of the pin", err)
	}
	var settings opnapi.FirmwareSettings
	settingsErr := e.retryFor(cx, wait, func() (err error) {
		settings, err = e.dev.Settings(cx)
		return err
	}, nil)
	if st == nil {
		// The record is gone after the request (the state file was deleted by hand).
		// The device proves the landing, so the answer is a success; what is written
		// depends on the live flavour (the gone-record rule).
		if settingsErr != nil {
			return e.unsettled(o, "the firmware settings", settingsErr)
		}
		if st = e.finishWithoutRecord(cx, o, settings, o.job.NewFlavour); st == nil {
			return e.result(o, OutcomeSuccess, ReasonApplied)
		}
	}

	// The pin stays where it was moved to, now equal to the installed release. If
	// anything moved it meanwhile, or the installed release is beyond its
	// directory, it is written again at the installed release.
	pin := o.job.NewFlavour
	if pin == "" {
		pin = st.PinnedFlavour
	}
	if settingsErr != nil {
		e.log.Warnw("Cannot read the firmware settings after the update; the periodic round checks the pin",
			"task_id", o.in.TaskID, "error", describeErr(settingsErr))
		if _, err := e.store.Update(func(s *State) {
			if pin != "" {
				s.PinnedFlavour = pin
			}
			s.PinnedVersion = installed
			s.Pending = nil
			s.clearMisses()
		}); err != nil {
			e.log.Warnw("Cannot save the pin after the update", "error", err)
		}
	} else if _, pinDir, pinOK := ParseFlavour(settings.Flavour); settings.Flavour != pin || !pinOK || !DirCovers(pinDir, installed) {
		o.drift = true
		if err := e.repin(cx, st, settings, installed, o.in.TaskID, false, false, nil); err != nil {
			e.log.Warnw("Cannot put the pin at the installed release after the update", "error", describeErr(err))
			if _, uerr := e.store.Update(func(s *State) { s.DriftPending = true }); uerr != nil {
				e.log.Warnw("Cannot save the pending drift flag", "error", uerr)
			}
		}
	} else if _, err := e.store.Update(func(s *State) {
		s.PinnedFlavour, s.PinnedVersion = settings.Flavour, installed
		s.Pending = nil
		s.clearMisses()
	}); err != nil {
		e.log.Warnw("Cannot save the pin after the update", "error", err)
	}
	if st, err := e.store.Load(); err == nil && st != nil {
		o.pinned = st.PinnedVersion
	}
	if o.pinned == "" {
		o.pinned = installed
	}
	return e.result(o, OutcomeSuccess, ReasonApplied)
}

// finishWithoutRecord is the end of an update, minor or series upgrade, whose
// landing the device proved while the agent's own record of the pin is gone. A
// FAILED answer there would count against the release for the whole
// organization, and the update has in fact landed, so the answer is a success with
// drift true, and what is written depends on the live flavour, read with the same
// retries as the other reads and compared with the pin the job names (pin: the pin
// the task relied on, which the job recorded before the request):
//
//   - empty: the answer carries no pin and the record stays absent; the next advance
//     pins first, which the engine does for an empty flavour;
//   - equal to the job's pin: it is the agent's own pin, proved by the job. The record
//     is rebuilt (the pin the setting holds, the track of the job, no original
//     flavour, which every record has because an enroll refuses a non-empty one) and
//     the ordinary finish runs, which re-pins at the installed release, so a series
//     upgrade's dead pin does not outlive the answer. It returns that record;
//   - anything else: the flavour may be an operator's and is left alone; the answer
//     carries no pin, and the next advance holds held_custom_flavour, visibly.
//
// It returns nil when the answer is the success without a pin.
func (e *Engine) finishWithoutRecord(cx context.Context, o *op, settings opnapi.FirmwareSettings, pin string) *State {
	o.drift = true
	live := settings.Flavour
	if live == "" || pin == "" || live != pin {
		e.log.Warnw("The agent has no record of the pin after the update; answering applied with no pin",
			"task_id", o.in.TaskID, "flavour", live, "job_pin", pin)
		o.noPin = true
		return nil
	}
	e.log.Warnw("The agent has no record of the pin after the update, and the setting holds the pin the task relied on; rebuilding the record",
		"task_id", o.in.TaskID, "flavour", live)
	st, err := e.store.Update(func(s *State) {
		*s = State{Pinned: true, Track: o.job.Track, OriginalFlavour: "", PinnedFlavour: live, PinnedVersion: o.job.From}
	})
	if err != nil {
		e.log.Errorw("Cannot rebuild the firmware track record; answering applied with no pin", "error", err)
		o.noPin = true
		return nil
	}
	return st
}

// unsettled leaves an update that completed, and cannot be recorded yet, to the
// next evaluation of its row: answering it on a guess would be a FAILED that
// names the release, or a success that the device did not give.
func (e *Engine) unsettled(o *op, what string, err error) *Outcome {
	e.log.Warnw("The firmware update completed but "+what+" cannot be read; leaving the task to be settled later",
		"task_id", o.in.TaskID, "error", describeErr(err))
	return aborted()
}

// setsStillOld names the base system or kernel an update that reboots was to
// install and did not, "" when they are as planned or cannot be read. The core
// package is replaced first and the sets minutes later: a box that lost power in
// between restarts with the new core over the old base and kernel, which the
// version file alone calls done and which would count as promotion evidence. A
// run that does not reboot defers the sets by design, and a source that cannot be
// read is not a reason to fail a run that otherwise ended well.
func (e *Engine) setsStillOld(ctx context.Context, o *op) string {
	meta := o.job.Upgrade
	if meta == nil || !meta.RebootExpected() {
		return ""
	}
	read := e.dev.Probes().Sets
	if read == nil {
		return ""
	}
	base, kernel, err := read(ctx)
	if err != nil {
		e.log.Warnw("Cannot read the installed base system and kernel; going by the release alone", "error", describeErr(err))
		return ""
	}
	for _, p := range meta.Packages {
		// The sets carry no hotfix revision of their own: the plan's is the release.
		planned := StripHotfix(p.Version)
		switch {
		case p.Name == "base" && !firmware.AtLeast(base, planned):
			return fmt.Sprintf("base is %s, planned %s", base, planned)
		case p.Name == "kernel" && !firmware.AtLeast(kernel, planned):
			return fmt.Sprintf("kernel is %s, planned %s", kernel, planned)
		}
	}
	return ""
}

// failApplied is the end of an update that started and did not finish, or whose
// result cannot be trusted. The pin is pulled back to the installed release (it
// was moved ahead of it for the update, and a pin ahead of the installed release
// lets the GUI's Update finish the job outside the window), and the task fails,
// with the release it was moving to named for the control plane.
func (e *Engine) failApplied(ctx context.Context, o *op, message string) *Outcome {
	cx := detached(ctx)
	installed, ierr := e.dev.Installed(cx)
	if ierr == nil {
		o.installed, o.to = installed, installed
	}
	st, serr := e.store.Load()
	settings, perr := e.dev.Settings(cx)
	if ierr == nil && serr == nil && st != nil && perr == nil {
		if e.firmwareIdle(cx) {
			e.pullBack(cx, o, st, settings, installed)
		} else {
			// The task's time ran out while OPNsense is still at it (a slow link, a
			// package tool that outlived its parent). The pin is not moved under a
			// running update; the round that follows puts it where the installed
			// release says once the box is idle.
			e.log.Warnw("A firmware job is still running; leaving the pin where it is for the periodic round", "task_id", o.in.TaskID)
			if _, err := e.store.Update(func(s *State) { s.Pending = nil }); err != nil {
				e.log.Warnw("Cannot save the firmware track record", "error", err)
			}
		}
		if st, err := e.store.Load(); err == nil && st != nil && st.Pinned {
			o.pinned = st.PinnedVersion
		}
	}
	return e.fail(o, "%s", message)
}

// pullBack returns the pin to the installed release after an update that did
// not end well. When the installed release did not move, the pin goes back to
// where it was by compare-and-swap, without asking the mirror anything.
func (e *Engine) pullBack(ctx context.Context, o *op, st *State, settings opnapi.FirmwareSettings, installed string) {
	next, prev := o.job.NewFlavour, o.job.PrevFlavour
	if next != "" && prev != "" && installed == o.job.From && settings.Flavour == next {
		if next != prev {
			if err := e.restoreFlavour(ctx, func(f string) bool { return f == next }, prev, "update failed"); err != nil {
				e.log.Errorw("Cannot put the firmware pin back after a failed update; the periodic reconcile will retry", "error", describeErr(err))
				return
			}
			e.checkAfterChange(ctx, "the failed update")
		}
		if _, err := e.store.Update(func(s *State) { s.Pending = nil }); err != nil {
			e.log.Warnw("Cannot save the firmware track record", "error", err)
		}
		return
	}
	// The release moved (a partial update) or the setting changed: write the pin
	// again at the installed release.
	if err := e.repin(ctx, st, settings, installed, o.in.TaskID, false, false, nil); err != nil {
		e.log.Errorw("Cannot put the firmware pin at the installed release after a failed update; the periodic reconcile will retry",
			"error", describeErr(err))
	}
}

func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			return t
		}
	}
	return ""
}
