package track

import (
	"context"
	"errors"
)

// preflight waits for the firmware API (see awaitAPI) and then reads what every
// task needs.
func (e *Engine) preflight(ctx context.Context, o *op) *Outcome {
	e.awaitAPI(ctx, o)
	if ctx.Err() != nil {
		return aborted()
	}
	return e.readDevice(ctx, o)
}

// readDevice reads the record of the pin, the firmware settings and the installed
// release. It returns an outcome when the device cannot be read, and nil with the
// op filled in when it can.
//
// A device that cannot be read is held (enroll, advance), never failed: nothing
// has changed, and a wrong FAILED stops a release for the whole organization.
// An unenroll that cannot read the device has to fail instead, because it did
// not do what it was asked and the control plane has to ask again.
func (e *Engine) readDevice(ctx context.Context, o *op) *Outcome {
	st, err := e.store.Load()
	if err != nil {
		e.log.Errorw("Cannot read the firmware track record; touching nothing", "error", err)
		return e.unreadable(o, "the agent's firmware track record")
	}
	if st != nil && st.Pending != nil {
		// An operation of the agent's that did not end left the flavour as it was
		// writing it. That value is the agent's, not an operator's: put the device
		// back to a state the record describes before this task reads it.
		e.repairPending(ctx, st)
		if st, err = e.store.Load(); err != nil {
			return e.unreadable(o, "the agent's firmware track record")
		}
	}
	o.st = st
	if st != nil && st.Pinned {
		e.noteTask()
	}

	settings, err := e.dev.Settings(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return aborted()
		}
		e.log.Warnw("Cannot read the firmware settings", "error", describeErr(err))
		return e.unreadable(o, "the firmware settings")
	}
	o.settings = settings

	installed, err := e.dev.Installed(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return aborted()
		}
		e.log.Warnw("Cannot read the installed release", "error", describeErr(err))
		return e.unreadable(o, "the installed release")
	}
	series, ok := SeriesOf(installed)
	if !ok {
		e.log.Warnw("The installed release is not a release name the agent knows", "installed", installed)
		return e.unreadable(o, "the installed release")
	}
	o.installed, o.from, o.to = installed, installed, installed
	o.job.From = installed
	if target, ok := o.in.Payload.Approved[series]; ok {
		o.target = target
		o.job.Target = target
	}
	if st != nil && st.Pinned {
		o.pinned = st.PinnedVersion
	}
	return nil
}

func (e *Engine) unreadable(o *op, what string) *Outcome {
	if o.in.Payload.Action == ActionUnenroll {
		return e.fail(o, "Could not read %s; the firmware pin was not touched", what)
	}
	return e.hold(o, ReasonHeldCheckFailed)
}

// enroll pins the device at the release it has installed, so that from now on
// the GUI's Check and Update and OPNsense's own auto-update see nothing beyond
// it. It holds instead when pinning would overwrite an operator's choice or
// break the device's updates, and it leaves the device unpinned when it holds.
func (e *Engine) enroll(ctx context.Context, o *op) *Outcome {
	if out := e.preflight(ctx, o); out != nil {
		return out
	}
	o.progress("Checking the device before pinning it...")

	if st := o.st; st != nil && st.Pinned && o.settings.Flavour == st.PinnedFlavour {
		return e.enrollIntact(ctx, o)
	}
	if o.st != nil && o.st.Pinned {
		// The record says the agent holds a pin and the setting no longer holds it.
		o.drift = true
	}
	o.pinned = "" // whatever the record says, the device is not pinned until this task pins it
	if out := e.pinAtInstalled(ctx, o); out != nil {
		return out
	}
	return e.result(o, OutcomeSuccess, ReasonEnrolled)
}

// enrollIntact answers an enroll for a pin that is in force: the control plane
// asked again because it never heard (a result is retried until one arrives), or
// it moved the device to another track, which needs no task.
func (e *Engine) enrollIntact(ctx context.Context, o *op) *Outcome {
	// An enroll starts the device over with the control plane: what a series upgrade
	// left in the record, the count of its aborted attempts and the note of a landing
	// that ended short, is forgotten with it, as it is when the pin is written anew.
	updated, err := e.store.Update(func(st *State) {
		st.Track = o.in.Payload.Track
		st.HopAborts, st.Landing = nil, nil
	})
	if err != nil {
		e.log.Warnw("Cannot save the track", "error", err)
	} else {
		o.st = updated
	}
	if out := e.reconcileOp(ctx, o); out != nil {
		return out
	}
	return e.result(o, OutcomeNoop, ReasonEnrolled)
}

// guardDevice holds a device the pin must not touch: a subscription or a release
// type of its own, whose mirror and series differ from the community pin.
func (e *Engine) guardDevice(o *op) *Outcome {
	if why := settingsProblem(o.settings); why != "" {
		e.log.Infow("Not touching the firmware pin: "+why, "task_id", o.in.TaskID)
		return e.hold(o, ReasonHeldUnsupportedEdition)
	}
	return nil
}

// pinAtInstalled is the enroll procedure: every hold, then the pin at the
// release the device has installed, a forced check, and the verdict on the plan.
// On success the record holds the pin and o.pinned names its release; every
// other end restores the setting the device had.
func (e *Engine) pinAtInstalled(ctx context.Context, o *op) *Outcome {
	if out := e.guardDevice(o); out != nil {
		return out
	}
	if o.settings.Flavour != "" {
		// A flavour the agent did not write. It is the operator's, and a pin would
		// overwrite it.
		e.log.Infow("Not enrolling: the device has a firmware flavour of its own", "flavour", o.settings.Flavour)
		return e.hold(o, ReasonHeldCustomFlavour)
	}

	m, err := e.dev.RepoBase(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return aborted()
		}
		e.log.Warnw("Cannot tell which mirror the device uses", "error", describeErr(err))
		return e.hold(o, ReasonHeldCheckFailed)
	}
	series, _ := SeriesOf(o.installed)
	if m.Series != series {
		e.log.Warnw("The mirror's series is not the installed release's", "mirror", m.Series, "installed", o.installed)
		return e.hold(o, ReasonHeldUnexpectedPlan)
	}

	e.jitterOnce(ctx, o)
	dir, probe := e.pickDir(ctx, m, o.installed, o.settings.Aux)
	switch probe {
	case ProbeMissing:
		e.log.Infow("Not enrolling: the release folder is not on the device's mirror", "installed", o.installed)
		return e.hold(o, ReasonHeldReleaseFolderMissing)
	case ProbeUnreachable:
		if ctx.Err() != nil {
			return aborted()
		}
		e.log.Warnw("Not enrolling: the mirror could not be asked", "installed", o.installed)
		return e.hold(o, ReasonHeldCheckFailed)
	}
	pin := Flavour(series, dir)

	if err := e.waitReady(ctx); err != nil {
		if ctx.Err() != nil {
			return aborted()
		}
		return e.hold(o, ReasonHeldFirmwareBusy)
	}

	// The record goes first: whoever finds the device after a crash knows which
	// values were in play.
	if _, err := e.store.Update(func(st *State) {
		*st = State{
			Track: o.in.Payload.Track, OriginalFlavour: o.settings.Flavour,
			Pending: &Pending{Op: ActionEnroll, TaskID: o.in.TaskID, FromFlavour: o.settings.Flavour, ToFlavour: pin, StartedAt: e.now().Unix()},
		}
	}); err != nil {
		e.log.Errorw("Cannot save the firmware track record; not pinning", "error", err)
		return e.hold(o, ReasonHeldCheckFailed)
	}
	o.job.Phase, o.job.PrevFlavour, o.job.NewFlavour = PhaseMoved, o.settings.Flavour, pin
	o.saveJob()

	rollback := func(reason string) *Outcome {
		e.rollbackEnroll(ctx, o, pin)
		if ctx.Err() != nil {
			return aborted()
		}
		return e.hold(o, reason)
	}

	if err := e.writeFlavour(ctx, pin, "enroll"); err != nil {
		e.log.Warnw("Cannot write the firmware flavour", "error", describeErr(err))
		return rollback(ReasonHeldCheckFailed)
	}
	status, err := e.forcedCheck(ctx)
	if err != nil {
		e.log.Warnw("The firmware check after the pin failed", "error", describeErr(err))
		return rollback(ReasonHeldCheckFailed)
	}
	if err := usable(status); err != nil {
		e.log.Warnw("The firmware check after the pin is unusable", "error", describeErr(err))
		return rollback(ReasonHeldCheckFailed)
	}
	plan := NewPlan(status)
	o.reinstalls = plan.ReinstallEntries()
	if plan.Major != "" {
		// The final build of a series is offered the next one whatever it is pinned to:
		// the offer is a file of that build. It is no reason to refuse the pin, which is
		// right for a device at its series' final build; it is recorded as information.
		e.log.Infow("The device is offered a major upgrade; enrolling it at its installed release all the same",
			"installed", o.installed, "offered", plan.Major)
	}
	if h := plan.forEnroll(o.installed); h != nil {
		e.log.Infow("Not enrolling: "+h.Why, "reason", h.Reason)
		return rollback(h.Reason)
	}

	if _, err := e.store.Update(func(st *State) {
		st.Pinned = true
		st.Track = o.in.Payload.Track
		st.OriginalFlavour = o.settings.Flavour
		st.PinnedFlavour, st.PinnedVersion = pin, o.installed
		st.EnrolledAt = e.now().Unix()
		st.LastContact = e.now().Unix()
		st.clearMisses()
		st.DriftPending = false
		st.Pending, st.Released = nil, nil
	}); err != nil {
		e.log.Errorw("Cannot save the firmware track record after pinning", "error", err)
		return rollback(ReasonHeldCheckFailed)
	}
	o.pinned = o.installed
	return nil
}

// rollbackEnroll puts back the setting an enrollment changed and forgets the
// enrollment. The setting is restored by compare-and-swap, and a check follows,
// as after every change of the flavour. If the restore cannot be made the record
// keeps the pending operation for the periodic reconcile to finish.
func (e *Engine) rollbackEnroll(ctx context.Context, o *op, pin string) {
	cx := detached(ctx)
	err := e.restoreFlavour(cx, func(f string) bool { return f == pin }, o.settings.Flavour, "enroll rolled back")
	var foreign *foreignError
	switch {
	case err == nil || errors.As(err, &foreign):
		if foreign != nil {
			e.log.Warnw("The flavour changed under the enrollment; leaving it", "flavour", foreign.current)
		}
		if _, uerr := e.store.Update(func(st *State) { *st = State{} }); uerr != nil {
			e.log.Errorw("Cannot clear the firmware track record", "error", uerr)
		}
		if err == nil {
			if _, cerr := e.forcedCheck(cx); cerr != nil {
				e.log.Warnw("The firmware check after the rollback failed", "error", describeErr(cerr))
			}
		}
	default:
		e.log.Errorw("Cannot restore the firmware flavour after a failed enrollment; the periodic reconcile will retry", "error", describeErr(err))
	}
}

// unenroll puts the device's setting back and forgets the pin. The restore is a
// compare-and-swap: it writes only when the setting still holds what the agent
// wrote, and anything else is left as it is and reported as drift.
func (e *Engine) unenroll(ctx context.Context, o *op) *Outcome {
	if out := e.preflight(ctx, o); out != nil {
		return out
	}
	o.pinned = "" // an unenroll names no pin
	o.progress("Restoring the firmware setting...")

	st := o.st
	if st == nil || (!st.Pinned && st.Pending == nil) {
		// Nothing of the agent's to undo. A tombstone of a release the agent made
		// itself goes too.
		if st != nil {
			if out := e.forget(o); out != nil {
				return out
			}
		}
		if _, _, shaped := ParseFlavour(o.settings.Flavour); shaped {
			// A flavour of exactly the shape the agent writes, and no record that the
			// agent wrote it: it may be an operator's own pin, so it is left alone, and
			// the answer is not "unenrolled", which would close the row on a device
			// that is still pinned.
			e.log.Warnw("Unenroll: the firmware flavour has the shape of a pin and the agent has no record of writing it; leaving it", "flavour", o.settings.Flavour)
			o.drift = true
			return e.result(o, OutcomeNoop, ReasonPinDrift)
		}
		return e.result(o, OutcomeNoop, ReasonUnenrolled)
	}

	owned := st.Owns
	current := o.settings.Flavour
	original := st.OriginalFlavour

	if _, err := e.store.Update(func(s *State) {
		s.Pending = &Pending{Op: ActionUnenroll, TaskID: o.in.TaskID, FromFlavour: current, ToFlavour: original, StartedAt: e.now().Unix()}
	}); err != nil {
		return e.fail(o, "Cannot save the firmware track record; the firmware pin was not touched")
	}
	o.job.Phase, o.job.PrevFlavour, o.job.NewFlavour = PhaseMoved, current, original
	o.saveJob()

	switch {
	case current == original:
		// Already back (somebody reset it): nothing to write.
		if out := e.forget(o); out != nil {
			return out
		}
		return e.result(o, OutcomeNoop, ReasonUnenrolled)
	case owned(current):
		if err := e.restoreFlavour(detached(ctx), owned, original, "unenroll"); err != nil {
			if ctx.Err() != nil {
				return aborted()
			}
			e.log.Errorw("Cannot restore the firmware flavour", "error", describeErr(err))
			return e.fail(o, "Could not restore the firmware setting: %s", describeErr(err))
		}
		e.checkAfterChange(ctx, "unenroll")
		if out := e.forget(o); out != nil {
			return out
		}
		return e.result(o, OutcomeSuccess, ReasonUnenrolled)
	default:
		// The setting holds a value the agent did not write: it is left alone, the
		// pin is no longer the agent's, and the change is reported.
		e.log.Warnw("Unenroll: the firmware flavour was changed outside NetDefense; leaving it", "flavour", current)
		if out := e.forget(o); out != nil {
			return out
		}
		o.drift = true
		return e.result(o, OutcomeNoop, ReasonPinDrift)
	}
}

// forget removes the record once the setting is as it should be. A record that
// cannot be removed fails the task: left behind it says the agent holds a pin,
// and the next round would put one back on a device the control plane has just
// released. The control plane asks again.
func (e *Engine) forget(o *op) *Outcome {
	if err := e.store.Remove(); err != nil {
		e.log.Errorw("Cannot remove the firmware track record", "error", err)
		return e.fail(o, "Could not clear the agent's firmware track record: %s", describeErr(err))
	}
	return nil
}

// checkAfterChange makes the check that follows a change of the flavour when the
// result does not matter to the task (a restore): a failure is logged only.
func (e *Engine) checkAfterChange(ctx context.Context, why string) {
	if _, err := e.forcedCheck(detached(ctx)); err != nil {
		e.log.Warnw("The firmware check after "+why+" failed", "error", describeErr(err))
	}
}

// detached is a context that outlives the task's: a rollback or a restore that
// is cut short by a dropped connection leaves the device pinned, so it runs to
// the end. Every wait inside it is bounded by the engine's timing.
func detached(ctx context.Context) context.Context { return context.WithoutCancel(ctx) }
