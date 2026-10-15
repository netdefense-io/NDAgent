package track

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/netdefense-io/ndagent/internal/firmware"
	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// pinKind is what a pin needs, judged from the record, the setting and the
// installed release alone.
type pinKind int

const (
	// pinFine: the setting is the agent's pin and holds the installed release.
	pinFine pinKind = iota
	// pinRepin: the pin has to be written again at the installed release.
	pinRepin
)

type pinAssessment struct {
	kind pinKind
	// drift says the pin was changed outside NetDefense, as opposed to being
	// left ahead of the installed release by an operation that did not finish.
	drift bool
	// force says the setting is right and has to be written anyway: the file the
	// setting is replayed into does not hold it.
	force bool
	why   string
}

// assessPin is the reconcile's decision, pure so that every case is a table row.
//
//   - The flavour is not the one the agent wrote (reset to the default in the GUI,
//     a mirror or type change, a restored configuration): put the pin back at the
//     installed release and flag the drift. It is a guardrail, not a lock.
//   - It is the one the agent wrote, but another series (a major upgrade done
//     outside NetDefense): pin the new series at the installed release.
//   - It is the agent's and the installed release is beyond its directory: a pin
//     never sits below the installed release, because GUI Reinstall would install
//     the older build from it, so it moves up to the installed release.
//   - It is the agent's and its directory is beyond the installed release, with no
//     operation of the agent's in flight: the leftover of an update that did not
//     happen; it comes back to the installed release, not as a drift.
//   - The setting is the agent's pin and the repository file OPNsense generated
//     from it does not say so (a command rewrote the file alone): the setting is
//     written again, which makes OPNsense replay it into the files.
//
// repoPath is what the repository file's url holds after the ABI, "" when it
// could not be read.
func assessPin(st *State, flavour, repoPath, installed string) pinAssessment {
	if flavour != st.PinnedFlavour {
		return pinAssessment{kind: pinRepin, drift: true, why: "the firmware flavour is not the one the agent wrote"}
	}
	if repoPath != "" && repoPath != flavour {
		return pinAssessment{kind: pinRepin, drift: true, force: true, why: "the generated repository file does not hold the pin"}
	}
	series, dir, ok := ParseFlavour(flavour)
	if !ok {
		return pinAssessment{kind: pinRepin, drift: true, why: "the recorded pin is not a release path"}
	}
	iSeries, ok := SeriesOf(installed)
	if !ok {
		return pinAssessment{kind: pinFine}
	}
	if series != iSeries {
		return pinAssessment{kind: pinRepin, drift: true, why: "the installed release is in another series than the pin"}
	}
	if DirCovers(dir, installed) {
		return pinAssessment{kind: pinFine}
	}
	dk, dok := ParseKey(dir)
	ik, iok := ParseKey(installed)
	if !dok || !iok {
		return pinAssessment{kind: pinFine}
	}
	if ik.Compare(dk) > 0 {
		return pinAssessment{kind: pinRepin, drift: true, why: "the installed release is beyond the pin"}
	}
	return pinAssessment{kind: pinRepin, why: "the pin is ahead of the installed release"}
}

var (
	errFolderMissing = errors.New("the release folder is not on the device's mirror")
	errUnreachable   = errors.New("the mirror could not be asked")
	errNotReadable   = errors.New("the device cannot be read")
	errEdition       = errors.New("the device has a subscription or a release type of its own")
)

// repin writes the pin again at the installed release: the directory is found on
// the device's own mirror, the flavour is written, and a check follows. The
// record is updated to the new pin; the caller has already decided that it is
// needed. A folder the mirror does not hold is errFolderMissing, never a guess.
//
// scoped is the series upgrade's re-pin: the refresh that follows the write is
// `pkg update -f -r OPNsense` through the exec path and its result is logged and
// never judged, in place of the REST forced check. That check updates every
// enabled repository and fails as a whole when one does (check.sh), so a
// third-party repository that is dead after the hop would make the first reading a
// failure for a reason that is not the pin's; and the box's catalog is unusable
// until the first `pkg update` ("wrong packagesite, need to re-create database").
// The cached result the GUI shows comes back with the next check, which the start
// order puts right after this write.
func (e *Engine) repin(ctx context.Context, st *State, settings opnapi.FirmwareSettings, installed, taskID string, force, scoped bool, beforeProbe func()) error {
	if settingsProblem(settings) != "" {
		return errEdition
	}
	series, ok := SeriesOf(installed)
	if !ok {
		return errNotReadable
	}
	m, err := e.dev.RepoBase(ctx)
	if err != nil {
		e.log.Warnw("Cannot tell which mirror the device uses", "error", describeErr(err))
		return errNotReadable
	}
	// Only the mirror and the ABI come from the repository file. Its path after the
	// ABI is the pin being replaced, series included: after a major upgrade made
	// outside NetDefense it still names the old series, which is the reason to
	// write the pin again, so the series is the installed release's.
	m.Series = series
	if beforeProbe != nil {
		beforeProbe()
	}
	dir, probe := e.pickDir(ctx, m, installed, settings.Aux)
	switch probe {
	case ProbeMissing:
		return errFolderMissing
	case ProbeUnreachable:
		return errUnreachable
	}
	pin := Flavour(series, dir)

	if pin != settings.Flavour || force {
		if err := e.waitReady(ctx); err != nil {
			return err
		}
		if _, err := e.store.Update(func(s *State) {
			s.Pending = &Pending{Op: "repin", TaskID: taskID, FromFlavour: settings.Flavour, ToFlavour: pin, StartedAt: e.now().Unix()}
		}); err != nil {
			return fmt.Errorf("save the firmware track record: %w", err)
		}
		if err := e.writeFlavour(ctx, pin, "reconcile: "+reconcileWhy(st, settings.Flavour, e.repoPath(ctx), installed)); err != nil {
			return err
		}
		if scoped {
			if err := e.dev.RefreshCatalog(detached(ctx)); err != nil {
				e.log.Warnw("The catalog refresh after the series upgrade's re-pin failed; the next check does it", "error", describeErr(err))
			}
		} else if _, err := e.forcedCheck(detached(ctx)); err != nil {
			// The pin is in place; the check that is owed after a change failed, and
			// the next one (the heavy-telemetry collector's, a window's) will do.
			e.log.Warnw("The firmware check after the re-pin failed", "error", describeErr(err))
		}
	}
	_, err = e.store.Update(func(s *State) {
		if oldSeries, _, ok := ParseFlavour(s.PinnedFlavour); !ok || oldSeries != series {
			// The installed series changed: the record of aborted attempts of an upgrade
			// to it, and the note of a landing that ended short, belong to the old one.
			s.HopAborts, s.Landing = nil, nil
		}
		s.PinnedFlavour, s.PinnedVersion = pin, installed
		s.Pending = nil
	})
	return err
}

func reconcileWhy(st *State, flavour, repoPath, installed string) string {
	return assessPin(st, flavour, repoPath, installed).why
}

// repoPath reads the path the generated repository file points at, "" when the
// file cannot be read (then the setting alone is judged).
func (e *Engine) repoPath(ctx context.Context) string {
	path, err := e.dev.RepoPath(ctx)
	if err != nil {
		e.log.Debugw("Cannot read the generated repository file", "error", describeErr(err))
		return ""
	}
	return path
}

// reconcileOp is the reconcile a task makes before it acts. It returns an outcome
// when the pin cannot be put right (the task holds), nil when it is right or was
// put right. A drift found is carried into the result.
func (e *Engine) reconcileOp(ctx context.Context, o *op) *Outcome {
	if st := o.st; st != nil && st.Pending != nil {
		e.repairPending(ctx, st)
		if out := e.reread(ctx, o); out != nil {
			return out
		}
	}
	st := o.st
	if st == nil || !st.Pinned {
		// Both callers hold a pinned record, so it went away while an operation that
		// did not end was being finished (an unenroll, which forgets the pin).
		return e.hold(o, ReasonHeldCheckFailed)
	}
	if st.Pending != nil {
		// An update that was requested and has not been settled: the device is
		// mid-run, with the pin ahead of the installed release on purpose, and the
		// row of that task decides how it ended. Nothing is touched meanwhile.
		e.log.Infow("An earlier update has not been settled; holding", "pending_task", st.Pending.TaskID)
		return e.hold(o, ReasonHeldFirmwareBusy)
	}
	if st.DriftPending {
		o.drift = true
		if _, err := e.store.Update(func(s *State) { s.DriftPending = false }); err != nil {
			e.log.Warnw("Cannot clear the pending drift flag", "error", err)
		}
	}
	if o.in.Payload.Action == ActionAdvance && e.landingHolds(ctx, st, o.installed) {
		// A series upgrade left the system mixed. It is neither re-pinned nor counted
		// as having reached the series: the answer is a hold, which is no evidence and
		// clears no failure, until someone completes the upgrade. An enroll is the
		// control plane starting over (enrollIntact forgets the note) and is not held.
		return e.hold(o, ReasonHeldUnexpectedPlan)
	}
	a := assessPin(st, o.settings.Flavour, e.repoPath(ctx), o.installed)
	if a.kind == pinFine {
		if st.PinnedVersion != o.installed {
			_, _ = e.store.Update(func(s *State) { s.PinnedVersion = o.installed })
			o.pinned = o.installed
		}
		return nil
	}
	e.log.Infow("The firmware pin needs to be written again: "+a.why, "task_id", o.in.TaskID, "drift", a.drift)
	o.drift = o.drift || a.drift
	if err := e.repin(ctx, st, o.settings, o.installed, o.in.TaskID, a.force, false, func() { e.jitterOnce(ctx, o) }); err != nil {
		return e.repinFailed(ctx, o, err)
	}
	if out := e.reread(ctx, o); out != nil {
		return out
	}
	if o.st == nil {
		return e.hold(o, ReasonHeldCheckFailed)
	}
	o.pinned = o.st.PinnedVersion
	o.repinned = true
	o.job.Phase = PhaseStarted
	o.saveJob()
	return nil
}

// reread refreshes what the task knows after the device or the record changed.
func (e *Engine) reread(ctx context.Context, o *op) *Outcome {
	st, err := e.store.Load()
	if err != nil {
		return e.unreadable(o, "the agent's firmware track record")
	}
	o.st = st
	settings, err := e.dev.Settings(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return aborted()
		}
		return e.unreadable(o, "the firmware settings")
	}
	o.settings = settings
	return nil
}

// repinFailed turns a pin that could not be written into the task's outcome: a
// hold, and for a folder the mirror does not hold a count towards a release.
func (e *Engine) repinFailed(ctx context.Context, o *op, err error) *Outcome {
	switch {
	case ctx.Err() != nil:
		return aborted()
	case errors.Is(err, errFolderMissing):
		return e.missFolder(ctx, o)
	case errors.Is(err, errEdition):
		return e.hold(o, ReasonHeldUnsupportedEdition)
	case errors.Is(err, errBackendBusy):
		return e.hold(o, ReasonHeldFirmwareBusy)
	default:
		e.log.Warnw("Cannot write the firmware pin again", "error", describeErr(err))
		return e.hold(o, ReasonHeldCheckFailed)
	}
}

// folderMissSpacing is the least time between the two misses of a release folder
// that release a device: two answers of the mirror a few seconds apart (a retry
// of the same window, a mirror in the middle of a sync) are one observation.
var folderMissSpacing = 10 * time.Minute

// missFolder counts a confirmed miss of the pinned release folder. The first
// holds, with the pin in place. The second in a row, from another answer of the
// mirror than the first, releases the device: the mirror has dropped what the
// pin points at, every check fails closed and no fix can reach the device, so
// the original setting goes back and the control plane is told, which drops the
// device to Unmanaged.
func (e *Engine) missFolder(ctx context.Context, o *op) *Outcome {
	st := o.st
	if st == nil {
		return e.hold(o, ReasonHeldReleaseFolderMissing)
	}
	now := e.now()
	if st.FolderMisses >= 1 && now.Sub(time.Unix(st.FolderMissAt, 0)) < folderMissSpacing {
		e.log.Warnw("The pinned release folder is still not on the device's mirror; the first miss is too recent to count as a second",
			"first_miss", time.Unix(st.FolderMissAt, 0).UTC())
		return e.hold(o, ReasonHeldReleaseFolderMissing)
	}
	misses := st.FolderMisses + 1
	if misses < 2 {
		if _, err := e.store.Update(func(s *State) { s.FolderMisses, s.FolderMissAt = misses, now.Unix() }); err != nil {
			e.log.Warnw("Cannot save the miss count", "error", err)
		}
		e.log.Warnw("The pinned release folder is not on the device's mirror (first miss); the pin stays")
		return e.hold(o, ReasonHeldReleaseFolderMissing)
	}
	e.log.Warnw("The pinned release folder is still not on the device's mirror (second miss); releasing the device")
	return e.releaseDevice(ctx, o)
}

// releaseDevice takes the agent's pin off and reports it as released. If the
// setting cannot be restored, or the record cannot be cleared, the device is not
// released: it stays pinned, which is the safe side, and the task holds. A record
// left saying the agent holds a pin would have the next round put one back on a
// device the control plane has just dropped.
func (e *Engine) releaseDevice(ctx context.Context, o *op) *Outcome {
	st := o.st
	err := e.restoreFlavour(detached(ctx), st.Owns, st.OriginalFlavour, "release: folder unavailable")
	var foreign *foreignError
	switch {
	case err == nil:
		e.checkAfterChange(ctx, "the release")
	case errors.As(err, &foreign):
		e.log.Warnw("The firmware flavour was changed outside NetDefense; leaving it", "flavour", foreign.current)
	default:
		e.log.Errorw("Cannot restore the firmware flavour; the device stays pinned", "error", describeErr(err))
		return e.hold(o, ReasonHeldReleaseFolderMissing)
	}
	if _, err := e.store.Update(func(s *State) { *s = State{} }); err != nil {
		e.log.Errorw("Cannot clear the firmware track record; not reporting the device released", "error", err)
		return e.hold(o, ReasonHeldReleaseFolderMissing)
	}
	o.pinned = ""
	return e.result(o, OutcomeReleased, ReasonReleaseFolderUnavailable)
}

// repairPending finishes or undoes an operation of the agent's that did not end:
// it wrote the flavour and the process stopped, or the connection dropped under
// it. The device is put back to a state the record describes, so that "outside a
// running track task a device in a track is pinned at its installed release"
// holds again.
func (e *Engine) repairPending(ctx context.Context, st *State) {
	p := st.Pending
	if p == nil {
		return
	}
	cx := detached(ctx)
	cur, err := e.dev.Settings(cx)
	if err != nil {
		e.log.Warnw("Cannot read the firmware settings to repair an interrupted operation", "op", p.Op, "error", describeErr(err))
		return
	}
	e.log.Warnw("Repairing a firmware track operation that did not end", "op", p.Op, "task_id", p.TaskID,
		"from", p.FromFlavour, "to", p.ToFlavour, "now", cur.Flavour)

	clear := func(mutate func(*State)) {
		if _, err := e.store.Update(func(s *State) {
			s.Pending = nil
			if mutate != nil {
				mutate(s)
			}
		}); err != nil {
			e.log.Errorw("Cannot save the firmware track record", "error", err)
		}
	}
	back := func(to string) bool {
		if cur.Flavour != p.ToFlavour {
			return true // not (or no longer) what the operation wrote: nothing of ours to undo
		}
		if !e.firmwareIdle(cx) {
			e.log.Infow("A firmware job is running; the interrupted operation is repaired later", "op", p.Op)
			return false
		}
		if err := e.writeFlavour(cx, to, "repair of "+p.Op); err != nil {
			e.log.Errorw("Cannot restore the firmware flavour; will retry", "error", describeErr(err))
			return false
		}
		e.checkAfterChange(cx, "the repair")
		return true
	}

	switch p.Op {
	case ActionEnroll:
		if back(p.FromFlavour) {
			clear(func(s *State) {
				if !s.Pinned {
					*s = State{}
				}
			})
		}
	case ActionAdvance:
		if p.Triggered {
			// The update was requested: the device, read by the row's reconciler,
			// decides how it ended. A record this old has no row to wait for. A series
			// upgrade's row lives MajorAdvanceTTL, and the interval guard leaves its
			// record alone for twice that: the minor value would let the round after
			// boot 3 repair a record whose row is still unresolved.
			ttl := AdvanceTTL
			if p.Major != "" {
				ttl = MajorAdvanceTTL
			}
			if e.now().Sub(time.Unix(p.StartedAt, 0)) > 2*ttl {
				clear(nil)
			}
			return
		}
		if p.ToFlavour != st.PinnedFlavour && back(p.FromFlavour) {
			clear(nil)
		} else if p.ToFlavour == st.PinnedFlavour {
			clear(nil)
		}
	case ActionUnenroll:
		if st.Owns(cur.Flavour) && cur.Flavour != p.ToFlavour {
			if !e.firmwareIdle(cx) {
				e.log.Infow("A firmware job is running; the interrupted unenroll is finished later")
				return
			}
			if err := e.writeFlavour(cx, p.ToFlavour, "repair of unenroll"); err != nil {
				e.log.Errorw("Cannot restore the firmware flavour; will retry", "error", describeErr(err))
				return
			}
			e.checkAfterChange(cx, "the repair")
		}
		if err := e.store.Remove(); err != nil {
			e.log.Errorw("Cannot remove the firmware track record of an unenroll; will retry", "error", err)
		}
	case "repin":
		clear(func(s *State) {
			if cur.Flavour == p.ToFlavour {
				s.PinnedFlavour = p.ToFlavour
			}
		})
	default:
		clear(nil)
	}
}

// Tick is the periodic work: the dead-man, then the reconcile of the pin. It
// runs at agent start and on a timer, whatever the connection is doing (a
// disabled device waits in the registration phase and still has to release its
// pin after 30 days). It skips the round when a task is running, another
// firmware job holds the slot, or OPNsense is busy.
func (e *Engine) Tick(ctx context.Context) { _ = e.Reconcile(ctx) }

// TickResult says how far a round of the periodic work got.
type TickResult int

const (
	// TickSkipped: the round did not decide anything. A task runs, another firmware
	// job holds the slot or OPNsense is busy, the API does not answer or the record
	// cannot be read, or an operation of the agent's is in flight (an update was
	// requested, and its row decides how it ended and where the pin goes).
	TickSkipped TickResult = iota
	// TickSettled: the round read what it needed and decided: the pin was right, or
	// was written again (or could not be, and is left to the back-off), or there is
	// no record or no pin to keep, or the dead-man has the decision, or a series
	// upgrade's mixed system is left as it is.
	TickSettled
)

// Reconcile is Tick that says how far it got. The start order uses it: the first
// firmware check of the process waits until a round has been able to read the
// device, because a check is a write when its catalog carries a newer pkg, and a
// pin that still names the old series must be put right first.
func (e *Engine) Reconcile(ctx context.Context) (result TickResult) {
	if !e.mu.TryLock() {
		return TickSkipped
	}
	defer e.mu.Unlock()
	defer func() {
		if r := recover(); r != nil {
			e.logPanic("round", r)
			result = TickSkipped
		}
	}()

	st, err := e.store.Load()
	if err != nil {
		e.log.Errorw("Cannot read the firmware track record", "error", err)
		return TickSkipped
	}
	if st == nil || (!st.Pinned && st.Pending == nil) {
		return TickSettled // no record, no pin: nothing to put right
	}
	now := e.now()
	st = e.saveContact(st, now)
	if st.Pinned && e.deadMan(ctx, st, now) != silenceNone {
		// A silence the dead-man counts as due is not a pin to keep in order: the
		// round writes nothing but the release, so it cannot put back a flavour the
		// operator reset, or one the package's removal restored, while the release
		// is being confirmed.
		return TickSettled
	}

	release, ok := firmware.TryAcquire()
	if !ok {
		return TickSkipped
	}
	defer release()

	if st.Pending != nil {
		e.repairPending(ctx, st)
		if st, err = e.store.Load(); err != nil || st == nil {
			return TickSkipped
		}
	}
	// An operation of the agent's that is still in flight (an update requested,
	// whose row decides the outcome) owns the setting.
	if !st.Pinned || st.Pending != nil {
		return TickSkipped
	}
	if now.Before(e.repinAfter) {
		return TickSettled
	}
	if !e.firmwareIdle(ctx) {
		// A check, an update started from the GUI, one that outlived its task: the
		// round looks again next time, and does not write under it.
		return TickSkipped
	}
	settings, err := e.dev.Settings(ctx)
	if err != nil {
		return TickSkipped
	}
	if why := settingsProblem(settings); why != "" {
		e.log.Warnw("The pinned device now has a subscription or a release type of its own; not touching the pin", "why", why)
		return TickSettled
	}
	installed, err := e.dev.Installed(ctx)
	if err != nil {
		return TickSkipped
	}
	if e.landingHolds(ctx, st, installed) {
		e.log.Warnw("A series upgrade left the system mixed; the pin is not touched until it is whole")
		return TickSettled
	}
	if st, err = e.store.Load(); err != nil || st == nil {
		return TickSkipped // the guard may have cleared its note
	}
	a := assessPin(st, settings.Flavour, e.repoPath(ctx), installed)
	switch a.kind {
	case pinFine:
		if st.PinnedVersion != installed {
			_, _ = e.store.Update(func(s *State) { s.PinnedVersion = installed })
		}
	case pinRepin:
		e.log.Warnw("The firmware pin needs to be written again: "+a.why, "drift", a.drift)
		if err := e.repin(ctx, st, settings, installed, "", a.force, false, nil); err != nil {
			e.log.Warnw("Cannot write the firmware pin again; trying later", "error", describeErr(err))
			e.repinAfter = now.Add(repinBackoff)
			return TickSettled
		}
		if a.drift {
			_, _ = e.store.Update(func(s *State) { s.DriftPending = true })
			e.noteDriftRepin(now)
		}
	}
	return TickSettled
}

// repinBackoff is how long the periodic reconcile leaves a pin it could not
// write again alone, so a mirror problem is not asked about every round.
var repinBackoff = 30 * time.Minute

// The back-off of a pin that keeps being changed from outside: a tool that saves
// the firmware form with the flavour empty, a configuration restored again and
// again. Every re-pin is two config revisions and a catalog refetch, so the wait
// doubles from driftBackoffBase to driftBackoffMax; a day without a re-pin ends
// the streak. A task's own reconcile is not held back by it.
var (
	driftBackoffBase = 10 * time.Minute
	driftBackoffMax  = 6 * time.Hour
	driftQuiet       = 24 * time.Hour
)

// noteDriftRepin counts a pin written again after an outside change, and sets
// how long the round leaves the pin alone after the second in a row.
func (e *Engine) noteDriftRepin(now time.Time) {
	if e.driftLast.IsZero() || now.Sub(e.driftLast) > driftQuiet {
		e.driftStreak = 0
	}
	e.driftStreak++
	e.driftLast = now
	if e.driftStreak < 2 {
		return
	}
	wait := driftBackoffBase
	for i := 2; i < e.driftStreak && wait < driftBackoffMax; i++ {
		wait *= 2
	}
	if wait > driftBackoffMax {
		wait = driftBackoffMax
	}
	e.repinAfter = now.Add(wait)
	e.log.Warnw("The firmware pin keeps being changed outside NetDefense; the periodic round leaves it alone for a while",
		"times", e.driftStreak, "wait", wait.String())
}

// saveContact keeps the record's last contact up to date: continuously while a
// connection is up, from the moment it ended otherwise. The file is rewritten
// only when the value moved by saveContactEvery, to spare the flash.
//
// It never moves the value across a silence the dead-man already counts as due. A
// device that comes back after 30 days, with its connection up, has not been in
// contact for 30 days, and the control plane dropped it from its track on its own
// clock; saving the new contact would erase the very silence the release is for
// and leave the pin on a device nothing manages. The value stays where it was
// (e.silent says so) until the release is made, or a task shows the control
// plane still holds the device (noteTask). A clock that was wrong when it was
// judged does no harm: nothing is written, and the next round judges again.
//
// The silence ends now for a connection that is up, and when it began for one that
// is over. A box whose clock was behind when the connection began (a dead RTC
// battery: it boots at the time the disk was last written) saves a contact that
// looks recent until the clock is set, and only then shows the month.
func (e *Engine) saveContact(st *State, now time.Time) *State {
	e.silent = false
	last, live := e.contact.Last()
	var seen int64
	switch {
	case live:
		seen = now.Unix()
	case !last.IsZero():
		seen = last.Unix()
	}
	if seen <= st.LastContact {
		return st
	}
	end := e.contact.Started()
	if live || end.After(now) {
		// The time a connection recorded when it began is not one to trust once the
		// clock has been stepped back since: the silence ended at some time before now.
		end = now
	}
	if base := contactBase(st); base != 0 && !end.IsZero() &&
		DeadManDue(time.Duration(end.Unix()-base)*time.Second) {
		if !e.silentLogged {
			e.log.Warnw("Dead-man: the device is back after 30 days or more without contact; the pin is not kept for it",
				"last_contact", time.Unix(base, 0).UTC(), "back", end.UTC())
			e.silentLogged = true
		}
		e.silent = true
		return st
	}
	e.silentLogged = false
	if live && time.Duration(seen-st.LastContact)*time.Second < saveContactEvery {
		return st
	}
	updated, err := e.store.Update(func(s *State) {
		if seen > s.LastContact {
			s.LastContact = seen
		}
	})
	if err != nil {
		e.log.Warnw("Cannot save the last contact", "error", err)
		return st
	}
	return updated
}

const saveContactEvery = 10 * time.Minute

// contactBase is the time the silence is measured from: the last contact the
// record holds, or the enrollment's for a record that never saved one.
func contactBase(st *State) int64 {
	if st.LastContact != 0 {
		return st.LastContact
	}
	return st.EnrolledAt
}

// noteTask records that the control plane just sent the device a signed task: it
// holds the device in a track, so whatever silence came before ends here, and a
// release that was being confirmed is called off.
func (e *Engine) noteTask() {
	e.armed, e.silent, e.silentLogged = false, false, false
	now := e.now().Unix()
	if _, err := e.store.Update(func(s *State) {
		if now > s.LastContact {
			s.LastContact = now
		}
	}); err != nil {
		e.log.Warnw("Cannot save the last contact", "error", err)
	}
}

// deadManConfirm is how long the silence must persist, as the agent sees it,
// before the pin is released: a clock that jumped forward at boot, before NTP
// set it, would otherwise read as a month of silence.
var deadManConfirm = 30 * time.Minute

// silence is where the dead-man stands after a round.
type silence int

const (
	// silenceNone: the device is in contact, or the silence is not long enough.
	silenceNone silence = iota
	// silenceDue: 30 days by the clocks. The release is being confirmed, or it was
	// tried and did not go through; either way the round does nothing else with
	// the pin.
	silenceDue
	// silenceReleased: the pin was taken off.
	silenceReleased
)

// deadMan releases the pin of a device nobody has heard from for 30 days. The
// control plane applies the same rule on its own clock and drops the device to
// Unmanaged, so neither side sends a message. The silence is measured from the
// last authenticated contact; a disabled device never has one.
//
// A connection that is up is not silence, unless the saved contact says the
// device came back after 30 days or more (e.silent): then the silence is
// measured from the saved contact, and goes through the same confirmation.
func (e *Engine) deadMan(ctx context.Context, st *State, now time.Time) silence {
	ref := contactBase(st)
	if !e.silent {
		if last, live := e.contact.Last(); live {
			ref = now.Unix()
		} else if !last.IsZero() && last.Unix() > ref {
			ref = last.Unix()
		}
	}
	if ref == 0 {
		// Nothing to measure from: start counting now.
		_, _ = e.store.Update(func(s *State) { s.LastContact = now.Unix() })
		return silenceNone
	}
	if !DeadManDue(now.Sub(time.Unix(ref, 0))) {
		e.armed = false
		return silenceNone
	}

	// Due as the clocks read. It must hold for deadManConfirm on the monotonic
	// clock, with the wall clock having moved as much, before it counts.
	if !e.armed {
		e.armed, e.armedAt, e.armedWall = true, e.mono(), now
		e.log.Warnw("Dead-man: no authenticated contact for 30 days by the clock; confirming", "last_contact", time.Unix(ref, 0).UTC())
		return silenceDue
	}
	elapsed := e.mono() - e.armedAt
	if elapsed < deadManConfirm {
		return silenceDue
	}
	if skew := wallElapsed(e.armedWall, now) - elapsed; skew > 2*time.Minute || skew < -2*time.Minute {
		e.log.Warnw("Dead-man: the clock stepped while confirming; starting over", "skew", skew)
		e.armedAt, e.armedWall = e.mono(), now
		return silenceDue
	}
	if e.selfRelease(ctx, st, now) {
		return silenceReleased
	}
	return silenceDue
}

// wallElapsed is the time between two readings of the wall clock. Not Sub: a
// reading that carries a monotonic clock value is subtracted on it.
func wallElapsed(from, to time.Time) time.Duration {
	return time.Duration(to.UnixNano() - from.UnixNano())
}

// releasedByHelper runs the PHP fallback and reports whether the agent's pin is
// off the device afterwards. A setting that is not the agent's any more counts as
// released: there is nothing of the agent's left to take off.
func (e *Engine) releasedByHelper(ctx context.Context, st *State) bool {
	if e.helperRelease == nil {
		return false
	}
	if err := e.helperRelease(detached(ctx)); err != nil {
		e.log.Errorw("Dead-man: the plugin helper could not take the pin off either; trying again", "error", describeErr(err))
		return false
	}
	cur, err := e.dev.Settings(detached(ctx))
	if err != nil {
		e.log.Warnw("Dead-man: cannot read the setting after the plugin helper ran; trying again", "error", describeErr(err))
		return false
	}
	if st.Owns(cur.Flavour) {
		e.log.Errorw("Dead-man: the plugin helper ran and the setting is still the agent's pin; trying again", "flavour", cur.Flavour)
		return false
	}
	e.checkAfterChange(ctx, "the dead-man release")
	return true
}

// selfRelease removes the agent's pin because of the dead-man. It leaves a
// tombstone: the agent does not pin again by itself, only a task from the
// control plane (which then still holds the device) asks it to.
func (e *Engine) selfRelease(ctx context.Context, st *State, now time.Time) bool {
	release, ok := firmware.TryAcquire()
	if !ok {
		return false
	}
	defer release()

	e.log.Warnw("Dead-man: releasing the firmware pin after 30 days without authenticated contact",
		"pinned_flavour", st.PinnedFlavour, "original_flavour", st.OriginalFlavour)
	err := e.restoreFlavour(detached(ctx), st.Owns, st.OriginalFlavour, "dead-man")
	var foreign *foreignError
	switch {
	case err == nil:
		e.checkAfterChange(ctx, "the dead-man release")
	case errors.As(err, &foreign):
		e.log.Warnw("The firmware flavour was changed outside NetDefense; leaving it", "flavour", foreign.current)
	default:
		// The REST API could not restore it (the API user is gone, the web server
		// is down). The release is the one thing that must not depend on it, so the
		// plugin's PHP is asked, and the setting is read back to see whether it took.
		e.log.Errorw("Dead-man: cannot restore the firmware flavour over the API", "error", describeErr(err))
		if !e.releasedByHelper(ctx, st) {
			return false
		}
	}
	if _, err := e.store.Update(func(s *State) {
		*s = State{Released: &Released{Reason: "dead_man", At: now.Unix()}, OriginalFlavour: s.OriginalFlavour}
	}); err != nil {
		// Without the tombstone the next round would find a record that says the agent
		// holds a pin the setting no longer has, and put one back. No record says the
		// same thing, so that is the fallback.
		e.log.Errorw("Cannot save the dead-man release; removing the record instead", "error", err)
		if rerr := e.store.Remove(); rerr != nil {
			e.log.Errorw("Cannot remove the firmware track record either", "error", rerr)
		}
	}
	e.armed, e.silent, e.silentLogged = false, false, false
	return true
}
