package track

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// advance moves a pinned device to the release its track approved for the
// device's series, in a window. Reconcile first: a pin that was changed outside
// NetDefense is put back, and flagged, before anything else. Then the cases:
//
//	no entry for the series                    -> series_not_approved
//	installed at or above the target           -> at_or_above_target, unless the
//	  target's own directory (where the pin sits) offers a newer hotfix revision
//	the target's folder is not on the mirror   -> target_not_yet_offered
//	the plan lands on the target               -> pin at the target, update, read back
//	anything else                              -> a hold, with the pin where it was
//
// In test mode, which refuses an update and a reboot, the advance reads what its
// result names and is held (held_test_mode): no reconcile, no check, no move of the
// pin. A device that cannot be read does not change that verdict.
func (e *Engine) advance(ctx context.Context, o *op) *Outcome {
	if o.in.TestMode {
		// The verdict does not depend on the device, so nothing waits for its API.
		if out := e.readDevice(ctx, o); out != nil && out.Aborted {
			return out
		}
		e.log.Warnw("Holding the advance: test mode (test_mode=true) refuses an update and a reboot", "task_id", o.in.TaskID)
		return e.hold(o, ReasonHeldTestMode)
	}
	// A1: the signed expiry has to hold the step's work (8 minutes for a minor
	// advance, majorWork for a step that carries `major`), or the answer is
	// held_late_dispatch before anything is read or changed. A device that was
	// offline at the window can receive its step minutes before the expiry, and a
	// step that runs past it is failed by the broker and counted against the release;
	// for a series upgrade it also keeps the three-reboot job inside the window the
	// operator chose. It applies to every advance.
	if left := o.in.Expires.Sub(e.now()); left < o.work() {
		e.log.Warnw("Holding the advance: the signed expiry is closer than the step needs",
			"task_id", o.in.TaskID, "left", left.Round(time.Second).String(), "needs", o.work().String())
		return e.hold(o, ReasonHeldLateDispatch)
	}
	if out := e.preflight(ctx, o); out != nil {
		return out
	}
	o.progress("Checking the firmware pin...")

	if o.st == nil || !o.st.Pinned {
		// The control plane has this device in a track and the device holds no
		// pin: the record is gone, or the agent released itself (the dead-man) while
		// the control plane did not. The signed task says the device is managed, so
		// it is pinned first, by the same steps as an enrollment, and flagged.
		o.drift = true
		e.log.Warnw("An advance reached a device that holds no pin; pinning it first")
		if out := e.pinAtInstalled(ctx, o); out != nil {
			return out
		}
		if out := e.reread(ctx, o); out != nil {
			return out
		}
		o.pinned = o.st.PinnedVersion
		o.repinned = true
	} else {
		if out := e.guardDevice(o); out != nil {
			return out
		}
		if out := e.reconcileOp(ctx, o); out != nil {
			return out
		}
	}
	st := o.st
	if st == nil || !st.Pinned {
		// The reconcile removed the record: an unenroll that was left half done was
		// finished, and there is no pin to advance from. Asked again at the next window.
		e.log.Warnw("The firmware track record is gone after the reconcile; holding the advance")
		return e.hold(o, ReasonHeldCheckFailed)
	}
	if _, err := e.store.Update(func(s *State) { s.Track = o.in.Payload.Track }); err != nil {
		e.log.Warnw("Cannot save the track", "error", err)
	}

	if o.target == "" {
		return e.result(o, OutcomeNoop, ReasonSeriesNotApproved)
	}
	series, _ := SeriesOf(o.installed)
	_, pinDir, _ := ParseFlavour(st.PinnedFlavour)
	if pinDir == "" {
		// The record holds no pin the agent can read: nothing is probed on a guess.
		return e.hold(o, ReasonHeldCheckFailed)
	}

	m, err := e.dev.RepoBase(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return aborted()
		}
		e.log.Warnw("Cannot tell which mirror the device uses", "error", describeErr(err))
		return e.hold(o, ReasonHeldCheckFailed)
	}
	if m.Series != series {
		return e.hold(o, ReasonHeldUnexpectedPlan)
	}

	// The pinned folder is looked at before every advance: a mirror can drop it
	// (upstream pruning, a partial sync, a switch to a mirror that lacks it), and
	// then every check fails closed and no fix reaches the device. A pin written
	// by this very task was probed a moment ago.
	if !o.repinned {
		e.jitterOnce(ctx, o)
		switch e.probeDir(ctx, m, pinDir, o.settings.Aux) {
		case ProbeFound:
			if st.FolderMisses != 0 {
				_, _ = e.store.Update(func(s *State) { s.clearMisses() })
			}
		case ProbeMissing:
			return e.missFolder(ctx, o)
		default:
			if ctx.Err() != nil {
				return aborted()
			}
			return e.hold(o, ReasonHeldCheckFailed)
		}
	}

	ik, _ := ParseKey(o.installed)
	tk, _ := ParseKey(o.target)
	needsUpdate := ik.Compare(tk) < 0
	sameDir := pinDir == o.target

	if !needsUpdate && !sameDir {
		return e.atTarget(ctx, o)
	}
	if needsUpdate {
		// Is the target's folder on the mirror yet?
		e.jitterOnce(ctx, o)
		switch e.probeDir(ctx, m, o.target, o.settings.Aux) {
		case ProbeFound:
		case ProbeMissing:
			e.log.Infow("The target's folder is not on the device's mirror yet", "target", o.target)
			return e.result(o, OutcomeNoop, ReasonTargetNotYetOffered)
		default:
			if ctx.Err() != nil {
				return aborted()
			}
			return e.hold(o, ReasonHeldCheckFailed)
		}
	}
	return e.moveAndApply(ctx, o, series, needsUpdate)
}

// noopAtTarget is the answer for a device that needs nothing: at or above the
// target, with nothing newer on offer. A drift found on the way is the reason.
func (e *Engine) noopAtTarget(o *op) *Outcome {
	if o.drift {
		return e.result(o, OutcomeNoop, ReasonPinDrift)
	}
	return e.result(o, OutcomeNoop, ReasonAtOrAboveTarget)
}

// moveAndApply moves the pin to the target's directory (when the device is below
// it), makes the forced check, judges the plan, and applies it. Until the update
// is requested every end puts the pin back where it was.
func (e *Engine) moveAndApply(ctx context.Context, o *op, series string, needsUpdate bool) *Outcome {
	st := o.st
	prev := st.PinnedFlavour
	next := prev
	if needsUpdate {
		next = Flavour(series, o.target)
	}

	if err := e.waitReady(ctx); err != nil {
		if ctx.Err() != nil {
			return aborted()
		}
		return e.hold(o, ReasonHeldFirmwareBusy)
	}
	if _, err := e.store.Update(func(s *State) {
		s.Pending = &Pending{Op: ActionAdvance, TaskID: o.in.TaskID, FromFlavour: prev, ToFlavour: next, StartedAt: e.now().Unix()}
	}); err != nil {
		e.log.Errorw("Cannot save the firmware track record; not moving the pin", "error", err)
		return e.hold(o, ReasonHeldCheckFailed)
	}
	o.job.Phase, o.job.PrevFlavour, o.job.NewFlavour = PhaseMoved, prev, next
	o.saveJob()
	o.progress(fmt.Sprintf("Checking what %s offers...", o.target))

	// back is every end before the update is requested: the pin returns to where
	// it was, the record forgets the move, and the task answers as told.
	back := func(out func() *Outcome) *Outcome {
		e.undoMove(ctx, o, prev, next)
		if ctx.Err() != nil {
			return aborted()
		}
		return out()
	}
	holdBack := func(reason string) *Outcome { return back(func() *Outcome { return e.hold(o, reason) }) }

	if next != prev {
		if err := e.writeFlavour(ctx, next, "advance to "+o.target); err != nil {
			e.log.Warnw("Cannot write the firmware flavour", "error", describeErr(err))
			return holdBack(ReasonHeldCheckFailed)
		}
	}
	status, err := e.forcedCheck(ctx)
	if err != nil {
		e.log.Warnw("The firmware check at the target failed", "error", describeErr(err))
		if errors.Is(err, errBackendBusy) {
			return holdBack(ReasonHeldFirmwareBusy)
		}
		return holdBack(ReasonHeldCheckFailed)
	}
	if err := usable(status); err != nil {
		e.log.Warnw("The firmware check at the target is unusable", "error", describeErr(err))
		return holdBack(ReasonHeldCheckFailed)
	}
	if reason := e.verifyRevision(ctx, o, status); reason != "" {
		return holdBack(reason)
	}
	plan := NewPlan(status)
	o.reinstalls = plan.ReinstallEntries()

	kind, h, _ := plan.forAdvance(o.installed, o.target, needsUpdate)
	switch kind {
	case planHeld:
		e.log.Infow("Holding the advance: "+h.Why, "reason", h.Reason)
		return holdBack(h.Reason)
	case planBehindTarget:
		e.log.Infow("The mirror offers a release below the target", "target", o.target)
		return back(func() *Outcome { return e.result(o, OutcomeNoop, ReasonTargetNotYetOffered) })
	case planNothingNewer:
		return back(func() *Outcome { return e.atTarget(ctx, o) })
	}
	if !o.in.Payload.Reboot && !plan.PackagesPending() {
		// Only base and kernel are left, and they wait for a window that reboots.
		return back(func() *Outcome { return e.noopAtTarget(o) })
	}
	return e.apply(ctx, o, status, prev, next)
}

// undoMove puts the pin back where it was before the task moved it and forgets
// the move. The restore is a compare-and-swap against the value the task wrote;
// if it cannot be made the record keeps the pending move for the reconcile.
func (e *Engine) undoMove(ctx context.Context, o *op, prev, next string) {
	if next == prev {
		if _, err := e.store.Update(func(s *State) { s.Pending = nil }); err != nil {
			e.log.Errorw("Cannot save the firmware track record", "error", err)
		}
		return
	}
	cx := detached(ctx)
	err := e.restoreFlavour(cx, func(f string) bool { return f == next }, prev, "advance undone")
	var foreign *foreignError
	switch {
	case err == nil || errors.As(err, &foreign):
		if foreign != nil {
			e.log.Warnw("The flavour changed under the advance; leaving it", "flavour", foreign.current)
		}
		if _, uerr := e.store.Update(func(s *State) { s.Pending = nil }); uerr != nil {
			e.log.Errorw("Cannot save the firmware track record", "error", uerr)
		}
		if err == nil {
			e.checkAfterChange(cx, "the advance was undone")
		}
	default:
		e.log.Errorw("Cannot put the firmware pin back; the periodic reconcile will retry", "error", describeErr(err))
	}
}
