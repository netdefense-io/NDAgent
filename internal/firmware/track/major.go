package track

// major.go — a series upgrade inside a firmware track: an `advance` that carries
// `major` asks the device to move from its series to the next one the hop table
// names (26.1 to 26.7). The step is the ordinary advance until it finds nothing
// left to do on the minor path (A3); from there it is the hop's, and every answer
// carries kind major, the series as its target and the notes found so far.
//
// The hop is OPNsense's, not the agent's: `POST /api/core/firmware/upgrade` starts
// a detached job that downloads and verifies the sets, installs the kernel, and
// reboots three times (the base at the second boot, the packages at the third), with
// no web GUI, no SSH and no agent running between the first reboot and the end of
// the third. So what is recorded before the request is what decides the row later,
// and the outcome is read from the device, never from an exit code, a log or the
// agent coming back: the version files and the markers say whether it landed.
//
// The sequence, with its step numbers (A0 test mode and A1 late dispatch are in
// advance.go):
//
//	A3    the minor path would end at_or_above_target: choose the series upgrade
//	A4.0  the back-off after two aborted attempts
//	A4.1  the target tree is on the device's own mirror
//	A4.2  not a member of an HA pair
//	A4.3  the repositories and packages from outside (a warning, never a hold)
//	A4.4  the NetDefense repository has a tree for the new ABI
//	A4.5  the backend is idle and no upgrade marker is left
//	A4.6  a forced check at the current pin, nothing written
//	A4.7  the offer is the one expected (never judged from the status)
//	A4.8  free space and the boot-environment decision
//	A4.9  time again
//	A4.10 the boot environment
//	A4.11 re-read, record (durably), request
//	A4.12 the request
//	A4.13 watch, and classify an upgrade that did not land
//	A5    after boot 3: Resolve settles the row (resolve.go)

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/netdefense-io/ndagent/internal/firmware"
	"github.com/netdefense-io/ndagent/internal/opnapi"
)

const (
	// hopBackoffStreak and hopBackoff: after two consecutive aborted attempts the
	// agent answers held_upgrade_aborted for seven days without reading or changing
	// anything, so that a persistent cause (a missing pkg-static, a package manager
	// from the wrong repository) does not repeat the 1.1 GiB download and extraction
	// at every window. The seven days are provisional: the lab did not measure them.
	hopBackoffStreak = 2
	hopBackoff       = 7 * 24 * time.Hour

	// needFloor is the free space the upgrade needs on the filesystem that holds its
	// work, at least: 3.25 GiB, the smallest budget that completed the lab's hop
	// (2.75 GiB; 2.0 GiB failed in the extraction and 1.0 GiB in the fetch) plus
	// 512 MiB. needMargin is that margin in the formula. rootNeed is the free space
	// asked of / when it is not the cache's filesystem: unproven and conservative.
	needFloor  int64 = 3328 << 20
	needMargin int64 = 512 << 20
	rootNeed   int64 = 1 << 30

	// bootEnvironmentTries bounds the names tried for the boot environment:
	// ndagent-pre-26.7, then -2, -3 ... when the name is taken.
	bootEnvironmentTries = 20
)

// needBytes is the free space a series upgrade needs: the packages tar and its
// extraction both sit on disk at once, so twice the packages set, plus the base and
// the kernel, plus a margin, and never less than the floor. The sizes come from the
// offer. A sampled df peak never sizes it: ZFS lags its accounting by up to a
// transaction group, so the peak understates the transient by about the extracted
// size.
func needBytes(sets []opnapi.FirmwareUpgradeSet) int64 {
	var packages, rest int64
	for _, s := range sets {
		if s.Name == "packages" {
			packages = s.Size
		} else {
			rest += s.Size
		}
	}
	need := 2*packages + rest + needMargin
	if need < needFloor {
		need = needFloor
	}
	return need
}

// atTarget is the end of the minor path that finds nothing to update: the device
// is at or above the target and the target's directory offers nothing newer. A
// step without `major` answers the ordinary noop. A step with it chooses the series
// upgrade here (A3):
//
//   - the device is already on the series (an answer that was lost, a major done
//     outside): the ordinary noop toward approved[major], which readDevice took as
//     the target because the installed series is the major;
//   - the hop table has no row from the installed series to the major: an ordinary
//     held_unexpected_plan (the step has not chosen the hop, so it carries no kind);
//   - otherwise the step is the hop's.
func (e *Engine) atTarget(ctx context.Context, o *op) *Outcome {
	major := o.in.Payload.Major
	if major == "" {
		return e.noopAtTarget(o)
	}
	series, _ := SeriesOf(o.installed)
	if series == major {
		return e.noopAtTarget(o)
	}
	if _, ok := HopBetween(series, major); !ok {
		e.log.Warnw("The step asks for a series upgrade the hop table has no row for", "from", series, "major", major)
		return e.hold(o, ReasonHeldUnexpectedPlan)
	}
	if !o.in.Payload.Reboot {
		e.log.Warnw("A series upgrade needs the reboot; the payload says no", "major", major)
		return e.hold(o, ReasonHeldUnexpectedPlan)
	}
	o.asHop(major)
	return e.majorStep(ctx, o)
}

// majorStep is A4 of the step sequence. Every end from here on is an answer of the
// hop's: kind major, target_version the series, the notes found so far.
func (e *Engine) majorStep(ctx context.Context, o *op) *Outcome {
	major := o.in.Payload.Major
	series, _ := SeriesOf(o.installed)
	hop, _ := HopBetween(series, major)
	if o.st == nil || !o.st.Pinned {
		return e.hold(o, ReasonHeldCheckFailed)
	}
	pin := o.st.PinnedFlavour
	o.progress(fmt.Sprintf("Considering the upgrade from %s to %s...", series, major))

	// A4.0 back-off.
	if e.backedOff(o, major) {
		e.log.Warnw("Holding the series upgrade: two attempts in a row aborted and the last one is recent",
			"task_id", o.in.TaskID, "major", major, "streak", o.st.HopAborts.Streak,
			"last", time.Unix(o.st.HopAborts.At, 0).UTC())
		return e.hold(o, ReasonHeldUpgradeAborted)
	}

	// A4.1 the target tree.
	if out := e.majorTargetTree(ctx, o, hop); out != nil {
		return out
	}
	// A4.2 HA.
	if ha, err := e.dev.HAMember(ctx); err != nil {
		if ctx.Err() != nil {
			return aborted()
		}
		e.log.Warnw("Cannot tell whether the device is a member of an HA pair", "error", describeErr(err))
		return e.hold(o, ReasonHeldCheckFailed)
	} else if ha {
		e.log.Infow("Holding the series upgrade: the device is a member of an HA pair")
		return e.hold(o, ReasonHeldHAMember)
	}
	// A4.3 the audit: a warning, never a hold.
	e.auditThirdParty(ctx, o)
	if ctx.Err() != nil {
		return aborted()
	}
	// A4.4 the agent's own repository.
	if out := e.majorAgentRepo(ctx, o, hop); out != nil {
		return out
	}
	// A4.5 an idle backend, no marker.
	if err := e.waitReadyUntil(ctx, o.updateLimit()); err != nil {
		if ctx.Err() != nil {
			return aborted()
		}
		return e.hold(o, ReasonHeldFirmwareBusy)
	}
	stage, err := e.dev.StageState(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return aborted()
		}
		e.log.Warnw("Cannot read the state of a previous upgrade", "error", describeErr(err))
		return e.hold(o, ReasonHeldCheckFailed)
	}
	if stage.Markers.Any() {
		// Any reboot, the agent's or the operator's, would resume that upgrade by
		// itself: the kernel at the first boot, the base at the second, the packages
		// at the third.
		e.log.Warnw("Holding the series upgrade: an upgrade marker is left in the cache", "markers", fmt.Sprintf("%+v", stage.Markers))
		return e.hold(o, ReasonHeldRebootPending)
	}

	// A4.6 a forced check at the current pin. Nothing is written.
	o.progress("Checking what the mirror offers...")
	status, err := e.forcedCheck(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return aborted()
		}
		e.log.Warnw("The firmware check for the series upgrade failed", "error", describeErr(err))
		if errors.Is(err, errBackendBusy) {
			return e.hold(o, ReasonHeldFirmwareBusy)
		}
		return e.hold(o, ReasonHeldCheckFailed)
	}
	if err := usable(status); err != nil {
		e.log.Warnw("The firmware check for the series upgrade is unusable", "error", describeErr(err))
		return e.hold(o, ReasonHeldCheckFailed)
	}

	// A4.7 the offer, from upgrade_major_version and upgrade_sets, never the status.
	plan := NewPlan(status)
	o.reinstalls = plan.ReinstallEntries()
	if out := e.judgeOffer(o, plan); out != nil {
		return out
	}

	// A4.8 space, and the boot-environment decision.
	makeBE, out := e.majorSpace(ctx, o, plan)
	if out != nil {
		return out
	}
	// A4.9 time again: the waits above can have used it.
	if e.timeLeft(o) < majorWork {
		e.log.Warnw("Holding the series upgrade: too little time is left", "left", e.timeLeft(o).Round(time.Second).String())
		return e.hold(o, ReasonHeldLateDispatch)
	}
	// A4.10 the boot environment, when A4.8 decided for it.
	if makeBE {
		e.makeBootEnvironment(ctx, o, major)
		if ctx.Err() != nil {
			return aborted()
		}
	}

	// A4.11 re-read, then record, then request.
	meta, out := e.recordHop(ctx, o, status, pin)
	if out != nil {
		return out
	}
	o.progress(fmt.Sprintf("Upgrading from %s to %s; OPNsense will reboot three times and the device will be offline meanwhile...", o.installed, major))
	// A4.12 and A4.13: the request, the watch.
	return e.requestRun(ctx, o, meta, pin, pin, runSpec{
		marker: upgradeRequestMarker, trigger: e.dev.TriggerUpgrade, marked: true,
		recheck: func(ctx context.Context) string { return e.hopStillStands(ctx, o) },
	})
}

// hopStillStands is what the series upgrade asks of the box before it asks OPNsense
// a second time. The first request was dropped because another firmware job held the
// lock, and whatever that job was (an update from the GUI, an upgrade started from a
// shell) may have changed the box since the step looked at it: the installed release
// has to be the one the step was made for, and no stage may be waiting for a reboot.
// It returns the reason to hold for, "" when the box is as it was.
func (e *Engine) hopStillStands(ctx context.Context, o *op) string {
	stage, err := e.dev.StageState(ctx)
	switch {
	case err != nil:
		if ctx.Err() == nil {
			e.log.Warnw("Cannot read the state of the box before asking for the series upgrade again", "error", describeErr(err))
		}
		return ReasonHeldCheckFailed
	case stage.Markers.Any():
		e.log.Warnw("Another firmware job left an upgrade marker while the request was dropped; not asking again",
			"markers", fmt.Sprintf("%+v", stage.Markers))
		return ReasonHeldRebootPending
	case stage.Core != o.installed:
		e.log.Warnw("The installed release changed while the request was dropped; not asking again",
			"read_at_the_start", o.installed, "now", stage.Core)
		return ReasonHeldUnexpectedPlan
	}
	return ""
}

// timeLeft is what is left of the task's signed expiry.
func (e *Engine) timeLeft(o *op) time.Duration { return o.in.Expires.Sub(e.now()) }

// backedOff reports whether the last attempts aborted twice in a row, recently
// enough that this one is answered without touching the box.
func (e *Engine) backedOff(o *op, major string) bool {
	if o.st == nil || o.st.HopAborts == nil {
		return false
	}
	ha := o.st.HopAborts
	return ha.Series == major && ha.Streak >= hopBackoffStreak && e.now().Sub(time.Unix(ha.At, 0)) < hopBackoff
}

// majorTargetTree is A4.1: the box's own ABI must be the one the hop starts from,
// and the target series' tree must be on the device's own mirror under the ABI the
// row names. Nothing is derived from the number of the current ABI.
func (e *Engine) majorTargetTree(ctx context.Context, o *op, hop Hop) *Outcome {
	m, err := e.dev.RepoBase(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return aborted()
		}
		e.log.Warnw("Cannot tell which mirror the device uses", "error", describeErr(err))
		return e.hold(o, ReasonHeldCheckFailed)
	}
	if m.ABI != hop.SourceABI {
		e.log.Warnw("The device is not where the series hop starts", "abi", m.ABI, "hop_starts_at", hop.SourceABI)
		return e.hold(o, ReasonHeldUnexpectedPlan)
	}
	url := m.Base + "/" + hop.TargetABI + "/" + hop.Target + "/latest/meta.conf"
	switch r := e.probe(ctx, url); r {
	case ProbeFound:
		return nil
	case ProbeMissing:
		e.log.Infow("The target series' tree is not on the device's mirror yet", "major", hop.Target, "abi", hop.TargetABI)
		return e.result(o, OutcomeNoop, ReasonTargetNotYetOffered)
	default:
		if ctx.Err() != nil {
			return aborted()
		}
		e.log.Warnw("The mirror could not be asked for the target series", "major", hop.Target)
		return e.hold(o, ReasonHeldCheckFailed)
	}
}

// auditThirdParty is A4.3: it names, in the progress text and the log, the
// repositories and packages from outside OPNsense and NetDefense, and adds a token
// of the closed set to the notes for each kind found. The vendor warns that third
// party repositories "may interfere with your upgrade experience"; it is no reason
// to hold. The contract carries the two tokens and never a name.
func (e *Engine) auditThirdParty(ctx context.Context, o *op) {
	audit, err := e.dev.RepoAudit(ctx)
	if err != nil {
		if ctx.Err() == nil {
			e.log.Warnw("Cannot audit the repositories and packages; going on", "error", describeErr(err))
		}
		return
	}
	if len(audit.Repositories) > 0 {
		o.note(NoteThirdPartyRepository)
		e.log.Warnw("The device has a repository from outside OPNsense and NetDefense; the upgrade goes on",
			"repositories", audit.Repositories)
	}
	if len(audit.Packages) > 0 {
		o.note(NoteThirdPartyPackage)
		e.log.Warnw("The device has packages from outside OPNsense and NetDefense; the upgrade goes on",
			"packages", capNames(audit.Packages, 20))
	}
	if len(audit.Repositories) > 0 || len(audit.Packages) > 0 {
		o.progress(fmt.Sprintf("Found %d repositories and %d packages from outside OPNsense and NetDefense (%s); third-party repositories may interfere with the upgrade. Going on.",
			len(audit.Repositories), len(audit.Packages), strings.Join(capNames(append(append([]string(nil), audit.Repositories...), audit.Packages...), 8), ", ")))
	}
}

// capNames returns at most n names, with a count of the rest.
func capNames(names []string, n int) []string {
	if len(names) <= n {
		return names
	}
	out := append([]string(nil), names[:n]...)
	return append(out, fmt.Sprintf("and %d more", len(names)-n))
}

// majorAgentRepo is A4.4, the agent ABI guard. After the hop pkg expands ${ABI} to
// the new ABI in every repository file, and OPNsense's check fails as a whole when
// any enabled repository fails to update: a NetDefense repository that has no tree
// for the new ABI, or a flat url that keeps serving the old build, would break every
// update on the device until the file is fixed by hand. One reason covers the flat
// url, an unreachable host and a missing tree, because the device cannot tell them
// apart.
func (e *Engine) majorAgentRepo(ctx context.Context, o *op, hop Hop) *Outcome {
	repo, err := e.dev.AgentRepoProbe(ctx, hop.TargetABI)
	if err != nil {
		if ctx.Err() != nil {
			return aborted()
		}
		e.log.Warnw("Cannot probe the NetDefense repository", "error", describeErr(err))
		return e.hold(o, ReasonHeldCheckFailed)
	}
	if !repo.Nested || !repo.Tree {
		e.log.Warnw("Holding the series upgrade: the NetDefense repository would break the device's updates on the new ABI",
			"why", repo.Why, "abi", hop.TargetABI)
		return e.hold(o, ReasonHeldAgentABIUnavailable)
	}
	return nil
}

// judgeOffer is A4.7: the plan of the forced check against the series asked for.
// No offer is the sub-final device the control plane should not have sent (the offer
// is a file of the series' final build), and the answer is a noop with no request:
// on core 26.1.9 a `POST /upgrade` with no offer rebooted the box.
func (e *Engine) judgeOffer(o *op, plan Plan) *Outcome {
	kind, h := plan.forMajor(o.in.Payload.Major)
	switch kind {
	case majorNoOffer:
		e.log.Infow("The check offers no major upgrade; not asking for one. The device is below its series' final build, or the path is closed")
		return e.result(o, OutcomeNoop, ReasonTargetNotYetOffered)
	case majorHeld:
		e.log.Infow("Holding the series upgrade: "+h.Why, "reason", h.Reason)
		return e.hold(o, h.Reason)
	}
	return nil
}

// majorSpace is A4.8. It clears a stale work directory first (only when nothing
// runs, no marker is left and the agent has no operation in flight), reads the free
// space, holds when the cache's filesystem has less than the upgrade needs, and
// decides once whether to make a boot environment: when the device's setting is on,
// the snapshots API says it is supported and the pool has room for the upgrade and
// the environment both. The decision is never a hold and never a reason to delete
// anything: a pool in the band between the two thresholds skips the environment and
// says so.
func (e *Engine) majorSpace(ctx context.Context, o *op, plan Plan) (makeBE bool, out *Outcome) {
	o.progress("Checking the free space...")
	if e.firmwareIdle(ctx) && (o.st == nil || o.st.Pending == nil) {
		// An aborted stage 0 leaves its numbered work directory, a partial
		// .sets.pending and the old logs; a disk-full one leaves 1244208 KB of them.
		if err := e.dev.ClearStaleWork(ctx); err != nil {
			if ctx.Err() != nil {
				return false, aborted()
			}
			e.log.Warnw("Cannot clear the upgrade's work directory; measuring the space as it is", "error", describeErr(err))
		}
	}
	disk, err := e.dev.DiskFree(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return false, aborted()
		}
		e.log.Warnw("Cannot read the free space", "error", describeErr(err))
		return false, e.hold(o, ReasonHeldCheckFailed)
	}
	need := needBytes(plan.MajorSets)
	if disk.CacheFree < need {
		e.log.Warnw("Holding the series upgrade: not enough free space on the filesystem of the cache",
			"free", disk.CacheFree, "need", need)
		return false, e.hold(o, ReasonHeldInsufficientSpace)
	}
	if disk.SplitRoot && disk.RootFree < rootNeed {
		e.log.Warnw("Holding the series upgrade: not enough free space on /",
			"free", disk.RootFree, "need", rootNeed)
		return false, e.hold(o, ReasonHeldInsufficientSpace)
	}

	switch {
	case o.in.Payload.BootEnvironmentOff:
		o.note(NoteBootEnvironmentOff)
		return false, nil
	case !disk.ZFS || disk.BootDataset == "":
		o.note(NoteBootEnvironmentUnavailable)
		return false, nil
	}
	supported, err := e.dev.SnapshotSupported(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return false, aborted()
		}
		e.log.Warnw("Cannot tell whether boot environments are supported; making none", "error", describeErr(err))
		o.note(NoteBootEnvironmentUnavailable)
		return false, nil
	}
	if !supported {
		o.note(NoteBootEnvironmentUnavailable)
		return false, nil
	}
	if disk.PoolFree < need+disk.BootCost {
		// A snapshot taken on a marginal pool is what could push the box into the
		// ENOSPC of the kernel, base or package stage.
		e.log.Infow("Making no boot environment: the pool has room for the upgrade but not for the environment too",
			"pool_free", disk.PoolFree, "need", need, "boot_environment_cost", disk.BootCost)
		o.progress("Making no boot environment: the pool has no room for it beside the upgrade.")
		o.note(NoteBootEnvironmentSkippedNoRoom)
		return false, nil
	}
	return true, nil
}

// makeBootEnvironment is A4.10: a boot environment named ndagent-pre-<major>, then
// -2, -3 ... when the name is taken, made through the snapshots API and found by
// name in its listing (the answer to the add carries no uuid). Best effort: a
// refused or failed call is logged and adds boot_environment_unavailable, and the
// upgrade goes on. The agent never removes an environment, so one copy accumulates
// per upgrade. It is a recovery path from the console only: the boot back into it
// is unproven and takes the agent's state with it.
func (e *Engine) makeBootEnvironment(ctx context.Context, o *op, major string) {
	base := "ndagent-pre-" + major
	note := "NetDefense: before the upgrade to " + major
	o.progress("Making a boot environment before the upgrade...")
	for try := 1; try <= bootEnvironmentTries; try++ {
		name := base
		if try > 1 {
			name = fmt.Sprintf("%s-%d", base, try)
		}
		err := e.dev.CreateBootEnvironment(ctx, name, note)
		switch {
		case err == nil:
			made := &MadeBootEnvironment{Name: name}
			if be, found, ferr := e.dev.FindBootEnvironment(ctx, name); ferr != nil {
				e.log.Warnw("Made a boot environment but cannot find it in the listing", "name", name, "error", describeErr(ferr))
			} else if found {
				made.UUID = be.UUID
			}
			o.job.BootEnvironment = made
			o.note(NoteBootEnvironmentMade)
			e.log.Infow("Made a boot environment before the series upgrade; the agent never removes it", "name", made.Name, "uuid", made.UUID)
			return
		case errors.Is(err, ErrBootEnvironmentExists):
			continue
		case ctx.Err() != nil:
			return
		default:
			e.log.Warnw("Cannot make a boot environment; the upgrade goes on without one", "name", name, "error", describeErr(err))
			o.note(NoteBootEnvironmentUnavailable)
			return
		}
	}
	e.log.Warnw("Every name for the boot environment is taken; the upgrade goes on without one", "base", base)
	o.note(NoteBootEnvironmentUnavailable)
}

// recordHop is A4.11. The first act is a re-read of the status, with no new check:
// its last_check must be the forced check's, and the tests of A4.6 and the offer
// tests of A4.7 must still pass. Anything else is a noop or a hold and nothing is
// recorded. Then, in this order, and each write on disk before the next (the job
// through Input.Persist, the pending move through the record's synced write): the
// job (the phase triggered, the series, the four versions the abort classification
// compares, the notes, and the pin in force as both flavours: the hop writes
// nothing, and the job is the only record of the pin that survives a lost record)
// with the firmware.Meta of the run inside it, and the pending move. It returns the
// run's meta for the request.
func (e *Engine) recordHop(ctx context.Context, o *op, status *opnapi.FirmwareUpgradeStatus, pin string) (*firmware.Meta, *Outcome) {
	again, err := e.dev.Status(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return nil, aborted()
		}
		e.log.Warnw("Cannot read the firmware status again before the request", "error", describeErr(err))
		return nil, e.hold(o, ReasonHeldCheckFailed)
	}
	if usable(again) != nil || again.LastCheck != status.LastCheck {
		e.log.Warnw("The firmware status changed between the check and the request; not requesting",
			"check", status.LastCheck, "now", again.LastCheck)
		return nil, e.hold(o, ReasonHeldCheckFailed)
	}
	plan := NewPlan(again)
	if out := e.judgeOffer(o, plan); out != nil {
		return nil, out
	}

	stage, err := e.dev.StageState(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return nil, aborted()
		}
		e.log.Warnw("Cannot read the state of the box before the request", "error", describeErr(err))
		return nil, e.hold(o, ReasonHeldCheckFailed)
	}
	if stage.Markers.Any() {
		return nil, e.hold(o, ReasonHeldRebootPending)
	}
	if stage.Core != o.installed {
		e.log.Warnw("The installed release changed while the step waited; not requesting the series upgrade",
			"read_at_the_start", o.installed, "now", stage.Core)
		return nil, e.hold(o, ReasonHeldUnexpectedPlan)
	}
	bootTime, berr := e.bootTime()
	if berr != nil {
		bootTime = 0
		e.log.Warnw("Cannot read the boot time; a reboot cannot be confirmed later", "error", describeErr(berr))
	}
	meta := firmware.NewMeta("major", true, o.installed, again, bootTime, o.in.Started, o.in.Expires)
	meta.TriggeredAt = e.now().Unix()

	o.job.Phase, o.job.PrevFlavour, o.job.NewFlavour = PhaseTriggered, pin, pin
	o.job.Major = o.in.Payload.Major
	o.job.From, o.job.FromBase, o.job.FromKernel, o.job.FromPkgs = stage.Core, stage.Base, stage.Kernel, stage.Pkgs
	o.job.Upgrade = &meta
	if err := o.persistJob(); err != nil {
		e.log.Errorw("Cannot record the series upgrade before requesting it; not requesting it", "error", err)
		o.job.Phase, o.job.Upgrade = PhaseStarted, nil
		return nil, e.hold(o, ReasonHeldCheckFailed)
	}
	if _, err := e.store.Update(func(s *State) {
		s.Pending = &Pending{
			Op: ActionAdvance, TaskID: o.in.TaskID, FromFlavour: pin, ToFlavour: pin,
			Triggered: true, Major: o.in.Payload.Major, StartedAt: e.now().Unix(),
		}
	}); err != nil {
		e.log.Errorw("Cannot save the firmware track record before requesting the series upgrade; not requesting it", "error", err)
		o.job.Phase, o.job.Upgrade = PhaseStarted, nil
		o.saveJob()
		return nil, e.hold(o, ReasonHeldCheckFailed)
	}
	firmware.NoteTriggered()
	return &meta, nil
}

// --- the verdict on an upgrade that has been requested --------------------------------

// majorLanded reports whether the box is whole at the new series. It reads the
// version files and the markers and nothing else: no repository, no failure text,
// no log file's presence. The pkgs marker is written only when stage P's pkg
// upgrade succeeded, and stage P exits 0 whatever happened, so the exit code and
// the core version alone say nothing. The installed series is the major; base, kernel
// and pkgs are all at it; none of the three pending markers is left and .sets.pending
// is empty; and the running kernel and the userland agree (the base is whole).
//
// A core at the series with a marker short of it is a stage that did not finish:
// positive failure evidence.
func majorLanded(st StageState, major string) bool {
	if series, ok := SeriesOf(st.Core); !ok || series != major {
		return false
	}
	for _, v := range []string{st.Base, st.Kernel, st.Pkgs} {
		if series, ok := SeriesOf(v); !ok || series != major {
			return false
		}
	}
	return !st.Markers.Any() && st.SetsPendingEmpty &&
		st.RunningKernel != "" && st.RunningKernel == st.Userland
}

// landingHolds reports whether a landing note keeps the pin from being touched: a
// series upgrade ended FAILED because the system it left is mixed (the core at the
// new series, a set or a marker short of it), and that system is still mixed. Such
// a device would otherwise be re-pinned as drift at the next round, answer a noop
// that shows the new series, clear its own failure and count as evidence. The note
// is cleared when the installed series is no longer the note's or when majorLanded
// passes (someone completed the upgrade). The control plane cannot read markers, so
// this guard lives on the agent. A state that cannot be read keeps the note.
func (e *Engine) landingHolds(ctx context.Context, st *State, installed string) bool {
	if st == nil || st.Landing == nil {
		return false
	}
	clearNote := func(why string) {
		e.log.Infow("The landing note of a series upgrade is cleared: "+why, "series", st.Landing.Series)
		if _, err := e.store.Update(func(s *State) { s.Landing = nil }); err != nil {
			e.log.Warnw("Cannot clear the landing note", "error", err)
		}
	}
	if series, _ := SeriesOf(installed); series != st.Landing.Series {
		clearNote("the installed series is not the note's")
		return false
	}
	stage, err := e.dev.StageState(ctx)
	if err != nil {
		e.log.Warnw("Cannot read the state of the box to judge a landing note; keeping it", "error", describeErr(err))
		return true
	}
	if majorLanded(stage, st.Landing.Series) {
		clearNote("the upgrade was completed")
		return false
	}
	return true
}

type hopAction int

const (
	// hopWait: the device cannot say yet.
	hopWait hopAction = iota
	// hopLanded: the box is whole at the new series.
	hopLanded
	// hopHold: the upgrade did not happen or cannot be taken as done; nothing stays
	// changed that the next window cannot meet.
	hopHold
	// hopFail: a stage ended short, or nothing settled before the deadline.
	hopFail
)

// hopVerdict is the classification of a series upgrade that has been requested.
type hopVerdict struct {
	action hopAction
	// reason is the hold's reason; why is the text of a wait, a failure or the log.
	reason string
	why    string
	// abort says the hold counts in the back-off streak (held_upgrade_aborted);
	// clean says the cache is emptied once every log has been read; mixed says the
	// failure leaves the landing note.
	abort, clean, mixed bool
}

// hopEvidence is everything the classification reads, gathered before anything is
// cleaned up: the cleanup (`opnsense-update -es`) empties the whole directory, the
// logs included.
type hopEvidence struct {
	Job   Job
	Meta  firmware.Meta
	State StageState
	// Progress is the live progress log; BootMoved whether the boot time is later
	// than the one the run recorded by more than firmware.BootMargin, BootKnown
	// whether both could be read.
	Progress  string
	BootMoved bool
	BootKnown bool
}

// The two spellings of a full disk in OPNsense's logs: ENOSPC, the field's case, and
// EDQUOT, which a quota (the lab's) produces.
var diskFullTexts = []string{"No space left on device", "Disc quota exceeded"}

func diskFullIn(text string) bool {
	for _, t := range diskFullTexts {
		if strings.Contains(text, t) {
			return true
		}
	}
	return false
}

// classifyHop decides what a series upgrade that did not land was, from the four
// versions against what the job recorded at A4.11, the markers, the boot time and
// the text of the logs. No size is a test: a partial .sets.pending of 903614 KB
// and one of 129350 KB were both seen, and neither tells a failed upgrade from a
// running one. majorLanded has already been asked.
//
//	versions unchanged, a marker left, the boot time unchanged  held_reboot_pending, no cleanup
//	versions unchanged, no marker, the logs say the disk was full   held_insufficient_space, then cleanup
//	versions unchanged, no marker, anything else                    held_upgrade_aborted, then cleanup
//	versions changed, some at the new series, the box restarted      FAILED, with the landing note
//	anything else                                                     wait
//
// The log text comes from the live progress log, which survives a disk-full stage 0
// (the box keeps running) while .update.log can be empty, and from .update.log and
// .upgrade.log only when they were written after the request: an older one is an
// earlier run's.
func classifyHop(ev hopEvidence) hopVerdict {
	major := ev.Job.Major
	st := ev.State
	unchanged := st.Core == ev.Job.From && st.Base == ev.Job.FromBase &&
		st.Kernel == ev.Job.FromKernel && st.Pkgs == ev.Job.FromPkgs

	atSeries := func(v string) bool { s, ok := SeriesOf(v); return ok && s == major }
	anyAtSeries := atSeries(st.Core) || atSeries(st.Base) || atSeries(st.Kernel) || atSeries(st.Pkgs)
	moved := ev.BootMoved || !ev.BootKnown // the versions prove what an unreadable boot time cannot

	if !unchanged {
		if anyAtSeries && moved {
			return hopVerdict{
				action: hopFail, mixed: true,
				why: fmt.Sprintf("The series upgrade ended short of %s: the core is %s, base %s, kernel %s, packages %s, "+
					"and the stage that should have finished it did not. The device is left as it is.",
					major, st.Core, st.Base, st.Kernel, st.Pkgs),
			}
		}
		return hopVerdict{action: hopWait, why: "the installed versions changed but the upgrade did not land"}
	}

	if st.Markers.Any() {
		if ev.BootKnown && !ev.BootMoved {
			return hopVerdict{
				action: hopHold, reason: ReasonHeldRebootPending,
				why: "the upgrade is staged and waits for a reboot, which will resume it",
			}
		}
		return hopVerdict{action: hopWait, why: "an upgrade marker is left and the box restarted"}
	}

	text := ev.Progress
	for _, f := range []LogFile{ev.State.UpdateLog, ev.State.UpgradeLog} {
		if f.Exists && !f.ModTime.Before(time.Unix(ev.Meta.TriggeredAt, 0)) {
			text += "\n" + f.Text
		}
	}
	if diskFullIn(text) {
		return hopVerdict{
			action: hopHold, reason: ReasonHeldInsufficientSpace, clean: true,
			why: "the first stage of the upgrade ran out of disk",
		}
	}
	return hopVerdict{
		action: hopHold, reason: ReasonHeldUpgradeAborted, abort: true, clean: true,
		why: "the first stage of the upgrade aborted or the box restarted before it completed; nothing changed",
	}
}

// backendQuiet reports whether nothing runs on the firmware backend or in the
// package tools: the state in which an upgrade that has not landed has ended.
func (e *Engine) backendQuiet(ctx context.Context) bool {
	if state, err := e.dev.Running(ctx); err != nil || state != firmware.RunReady {
		return false
	}
	probes := e.dev.Probes()
	if probes.Locked != nil {
		if held, err := probes.Locked(ctx); err == nil && held {
			return false
		}
	}
	if probes.Updating != nil {
		if busy, err := probes.Updating(ctx); err != nil || busy {
			return false
		}
	}
	return true
}

// judgeHop reads the device and decides how a series upgrade that was requested
// stands. majorLanded decides first and alone: a hop that landed is a success
// whatever any log says, or whether any log exists. Only a hop that did not land is
// classified, and only once nothing runs. Everything is read before the caller
// cleans anything.
func (e *Engine) judgeHop(ctx context.Context, o *op, meta firmware.Meta) hopVerdict {
	pastBound := e.now().After(firmware.Deadline(meta.Expiry())) && e.uptime() > firmware.Grace
	wait := func(why string) hopVerdict {
		if !pastBound {
			return hopVerdict{action: hopWait, why: why}
		}
		return hopVerdict{
			action: hopFail,
			why:    "The series upgrade could not be confirmed before the task's time ran out: " + why,
		}
	}

	stage, err := e.dev.StageState(ctx)
	if err != nil {
		return wait("the state of the upgrade cannot be read (" + describeErr(err) + ")")
	}
	if majorLanded(stage, o.job.Major) {
		return hopVerdict{action: hopLanded}
	}
	if !e.backendQuiet(ctx) {
		return wait("OPNsense is still running a firmware job")
	}

	ev := hopEvidence{Job: o.job, Meta: meta, State: stage, Progress: e.progressLog(ctx)}
	if meta.BootTime > 0 {
		if boot, err := e.bootTime(); err == nil {
			ev.BootKnown = true
			ev.BootMoved = time.Unix(boot, 0).After(time.Unix(meta.BootTime, 0).Add(firmware.BootMargin))
		}
	}
	v := classifyHop(ev)
	if v.action == hopWait {
		return wait(v.why)
	}
	// What the classification leaves open is Evaluate's, but only to fail: it would
	// complete a core that moved while the rest did not, which is the false success
	// the landing test exists to refuse.
	return v
}

// settleHop is the handler's end of a series upgrade whose process survived: the
// stage 0 aborted, or the box did not reboot. It asks the device until it can say.
func (e *Engine) settleHop(ctx context.Context, o *op, meta *firmware.Meta, sentinel string) *Outcome {
	for {
		v := e.judgeHop(ctx, o, *meta)
		switch v.action {
		case hopLanded:
			e.log.Infow("The series upgrade ended: landed", "task_id", o.in.TaskID, "sentinel", sentinel)
			return e.finishMajor(ctx, o, e.timing.APIWait)
		case hopHold, hopFail:
			e.log.Infow("The series upgrade ended: "+v.why, "task_id", o.in.TaskID, "sentinel", sentinel)
			return e.endHop(ctx, o, v)
		}
		e.log.Infow("The series upgrade has not ended yet", "task_id", o.in.TaskID, "detail", v.why)
		if err := e.sleep(ctx, e.timing.Settle); err != nil {
			return aborted()
		}
	}
}

// resolveHop settles the row of a series upgrade after the agent came back: the
// reboots of the upgrade itself stop the process, and the reconciler of the agent
// that starts at boot 3 asks the device. Outcome false leaves the row IN_PROGRESS.
func (e *Engine) resolveHop(ctx context.Context, o *op, row Row, meta firmware.Meta) (*Outcome, bool) {
	v := e.judgeHop(ctx, o, meta)
	switch v.action {
	case hopLanded:
		e.log.Infow("Series upgrade resolved: landed", "task_id", row.TaskID)
		out := e.finishMajor(ctx, o, 0)
		if out.Aborted {
			// What the answer needs cannot be read yet. The next sweep asks again, and the
			// row ends with its time like any that cannot be settled.
			return e.stillUnresolved(o)
		}
		return out, true
	case hopHold, hopFail:
		e.log.Infow("Series upgrade resolved: "+v.why, "task_id", row.TaskID)
		out := e.endHop(ctx, o, v)
		if out.Aborted {
			return nil, false
		}
		return out, true
	}
	e.log.Debugw("Series upgrade has not ended yet", "task_id", row.TaskID, "detail", v.why)
	return e.stillUnresolved(o)
}

// endHop answers a series upgrade that did not land: a hold (the streak and the
// cleanup first, when the verdict says so) or a failure (with the landing note when
// the system is mixed). The cleanup comes after every log was read, and a cleanup
// that cannot be made is a FAILED: a leftover .pkgs.pending would make the next
// reboot of any kind run stage P over the old base.
func (e *Engine) endHop(ctx context.Context, o *op, v hopVerdict) *Outcome {
	cx := detached(ctx)
	switch {
	case v.mixed:
		e.noteLanding(o.job.Major)
	case v.abort:
		e.noteHopAbort(o.job.Major)
	}
	e.clearHopPending()
	if v.action == hopFail {
		if st, err := e.store.Load(); err == nil && st != nil && st.Pinned {
			o.pinned = st.PinnedVersion
		}
		return e.fail(o, "%s", v.why)
	}
	if v.clean {
		if err := e.dev.ClearUpgradeCache(cx); err != nil {
			if ctx.Err() != nil {
				return aborted()
			}
			e.log.Errorw("Cannot empty the upgrade's cache after the abort", "error", describeErr(err))
			return e.fail(o, "The series upgrade aborted and the agent could not empty its cache (%s); a marker left there would resume it at the next reboot", describeErr(err))
		}
	}
	if st, err := e.store.Load(); err == nil && st != nil && st.Pinned {
		o.pinned = st.PinnedVersion
	}
	return e.hold(o, v.reason)
}

// clearHopPending forgets the pending move of a series upgrade that is over.
func (e *Engine) clearHopPending() {
	if _, err := e.store.Update(func(s *State) {
		if s.Pending != nil && s.Pending.Major != "" {
			s.Pending = nil
		}
	}); err != nil {
		e.log.Warnw("Cannot clear the pending series upgrade from the firmware track record", "error", err)
	}
}

// noteHopAbort counts an aborted attempt for the back-off.
func (e *Engine) noteHopAbort(series string) {
	now := e.now().Unix()
	if _, err := e.store.Update(func(s *State) {
		if s.HopAborts == nil || s.HopAborts.Series != series {
			s.HopAborts = &HopAborts{Series: series}
		}
		s.HopAborts.Streak++
		s.HopAborts.At = now
	}); err != nil {
		e.log.Warnw("Cannot record the aborted series upgrade", "error", err)
	}
}

// noteLanding leaves the landing note of an upgrade that ended short.
func (e *Engine) noteLanding(series string) {
	now := e.now().Unix()
	if _, err := e.store.Update(func(s *State) { s.Landing = &Landing{Series: series, At: now} }); err != nil {
		e.log.Warnw("Cannot record the landing note", "error", err)
	}
}

// finishMajor is the end of a series upgrade that landed: the installed release is
// read back, the pin is written again on the new series, the record is updated, the
// pending move is cleared and the success is built. The order is the landing's:
// majorLanded (the caller), then the re-pin, then one catalog refresh. The finish
// makes no check before the re-pin and reads none, because the first check on the
// old pin of a cross-ABI hop reads "repository error" for a reason that is not the
// box's, and on a same-ABI landing the old pin still answers and a check would be a
// write. A landing reading is a forced check, never a `-U` read: until the first
// `pkg update` the local catalog is unusable.
//
// Like finishApplied, a read that fails here (the firmware API can still be settling
// after the last reboot) is no verdict: while the release or the agent's record
// cannot be read the task is left unsettled for the row's reconciler. With no record
// the gone-record rule applies.
func (e *Engine) finishMajor(ctx context.Context, o *op, wait time.Duration) *Outcome {
	cx := detached(ctx)

	var installed string
	if err := e.retryFor(cx, wait, func() (err error) {
		installed, err = e.dev.Installed(cx)
		return err
	}, nil); err != nil {
		return e.unsettled(o, "the installed release", err)
	}
	o.installed, o.to = installed, installed

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
		if settingsErr != nil {
			return e.unsettled(o, "the firmware settings", settingsErr)
		}
		// The job names the pin the task relied on: for a hop the pin in force, which
		// the hop wrote nothing to (PrevFlavour equals NewFlavour).
		if st = e.finishWithoutRecord(cx, o, settings, o.job.NewFlavour); st == nil {
			e.clearHopRecords()
			return e.result(o, OutcomeSuccess, ReasonApplied)
		}
	}

	repinned := false
	if settingsErr != nil {
		e.log.Warnw("Cannot read the firmware settings after the series upgrade; the periodic round puts the pin right",
			"task_id", o.in.TaskID, "error", describeErr(settingsErr))
	} else if err := e.repinAfterHop(cx, o, st, settings, installed); err != nil {
		e.log.Warnw("Cannot put the pin on the new series after the upgrade; the periodic round retries",
			"task_id", o.in.TaskID, "error", describeErr(err))
	} else {
		repinned = true
	}
	e.clearHopRecords()
	switch {
	case repinned:
		o.pinned = installed
	default:
		// The pin is still the old series' (fail-closed on a cross-ABI hop): the
		// answer does not claim one, and the control plane takes the release reached.
		o.pinned = ""
	}
	return e.result(o, OutcomeSuccess, ReasonApplied)
}

// repinAfterHop is the one write of the pin a series upgrade makes. What the setting
// should hold at this point is the pin the task relied on, which the hop wrote nothing
// to: after the landing it is the dead pin of the old series. Anything else means
// something changed the setting while the box was upgrading (an operator reset it, a
// tool saved the firmware form), and the answer says so, as the answer of a minor
// update does; the pin is written at the installed release all the same.
func (e *Engine) repinAfterHop(cx context.Context, o *op, st *State, settings opnapi.FirmwareSettings, installed string) error {
	pin := o.job.NewFlavour
	if pin == "" {
		pin = st.PinnedFlavour
	}
	if settings.Flavour != pin {
		o.drift = true
	}
	return e.repin(cx, st, settings, installed, o.in.TaskID, false, true, nil)
}

// clearHopRecords forgets what a landed upgrade makes obsolete: the pending move
// and the record of aborted attempts and of a short landing.
func (e *Engine) clearHopRecords() {
	if _, err := e.store.Update(func(s *State) {
		if s.Pending != nil && s.Pending.Major != "" {
			s.Pending = nil
		}
		s.HopAborts, s.Landing = nil, nil
	}); err != nil {
		e.log.Warnw("Cannot save the firmware track record after the series upgrade", "error", err)
	}
}
