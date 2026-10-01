package firmware

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Action is what to do with a row.
type Action int

const (
	// Wait: leave the row IN_PROGRESS and evaluate it again later.
	Wait Action = iota
	// Complete: the row is COMPLETED with Verdict.Message.
	Complete
	// Fail: the row is FAILED with Verdict.Message.
	Fail
)

// Verdict is Evaluate's answer.
type Verdict struct {
	Action Action
	// Reason is a short stable tag for logs and tests.
	Reason string
	// Message is the task message for Complete and Fail, and the detail worth
	// logging for Wait. A completed run's message is the result JSON NDCLI and
	// NDWeb render (a row with no metadata gets text, as it always did); a
	// failure's is plain text, because NDCLI shows a JSON message without
	// "applied" as a dry-run preview.
	Message string
	// Missing names the planned packages that were not at their planned version,
	// for a Fail because of them.
	Missing []string
}

// Input is the row being evaluated.
type Input struct {
	// Meta is what the handler recorded before triggering the update, nil for a
	// row written by an agent that recorded none.
	Meta *Meta
	// RowStartedAt is when the task row was created.
	RowStartedAt time.Time
	// ProcessUptime is how long this agent process has been running (Uptime).
	ProcessUptime time.Duration
	// Now is the current time.
	Now time.Time
	// Sentinel is the end marker the handler saw in OPNsense's progress log
	// ("done"), when it is evaluating its own run rather than the reconciler
	// resolving one whose handler is gone. "done" is OPNsense saying the update
	// script finished and is not going to reboot; it does not say the update
	// worked, because the script prints it after a partial failure too.
	Sentinel string
}

// BootMargin is how far the boot time must move to count as a reboot. The
// kernel's boot time shifts whenever the clock is stepped, and a box that is
// syncing its clock can step it by seconds without ever restarting.
const BootMargin = 2 * time.Minute

// missingShown is how many missing packages a failure names.
const missingShown = 8

// NotStartedMessage is what a row that never triggered anything is failed with.
const NotStartedMessage = "The firmware task was not started: the agent stopped or lost its connection before it " +
	"could run (it was waiting for another firmware task or for OPNsense to be free). Nothing was applied by this task."

// Evaluate decides how an update ended.
//
// A row whose run was recorded but never triggered (the handler was still waiting
// for its turn, or for OPNsense to be free, when the agent stopped) touched
// nothing: it is failed at once and says so. Every other decision is about a run
// that did start.
//
// It never resolves a row while the firmware backend is busy or cannot be read:
// OPNsense replaces the core package, and with it the version file, in the first
// minute of an update, minutes before the base and kernel install and the
// reboot, so neither "the agent is back" nor "the version changed" proves the
// update is over. A row that stays unresolvable is failed only once its deadline
// has passed.
//
// Once the backend is idle:
//   - proof the run failed part-way (OPNsense's failure text) fails it;
//   - a reboot the run needed, that did not happen, is not a completed run (the
//     update script reboots only if installing the base system and kernel
//     succeeded, and otherwise finishes quietly with them unapplied). The end
//     marker the handler saw settles it at once; without one it waits, because
//     the API can answer "ready" while OPNsense restarts its own services;
//   - an installed release different from the one the run started at completes
//     it, for a run that reboots (the reboot was checked above);
//   - a run that does not reboot (reboot=false: the agent's own child, packages
//     only) is complete only once no package tool is running and every planned
//     package is at its planned version or newer, whether or not the release has
//     moved: the core package is replaced first, minutes before the rest;
//   - an unchanged release is a packages-only run, whose planned packages must
//     then all be at their planned version (or newer): all there completes it,
//     any missing fails it and names them. A packages-only update, and the
//     agent's own upgrade, do not change the release, so "release unchanged"
//     alone is not a failure. A series upgrade, which always changes it, is
//     given until its deadline (it fails sooner only on the end marker or on
//     OPNsense's own abort text);
//   - anything that cannot be read (the release, the package database) waits.
//
// A row with no metadata (an older agent wrote it) completes once the backend is
// idle and no package tool runs, unless there is proof it failed.
func Evaluate(ctx context.Context, in Input, p Probes) Verdict {
	meta := in.Meta
	if meta != nil && !meta.Triggered() {
		return Verdict{Action: Fail, Reason: "not-started", Message: NotStartedMessage}
	}
	expires := in.RowStartedAt.Add(MajorTTL)
	since := in.RowStartedAt
	if meta != nil {
		expires = meta.Expiry()
		since = time.Unix(meta.TriggeredAt, 0)
	}
	pastBound := in.Now.After(Deadline(expires)) && in.ProcessUptime > Grace

	// The lock the busy state reads is held by the REST path's update script. A
	// reboot=false run is the agent's own child and never takes it, so for those
	// the package tools are the only sign the run is still going.
	viaLauncher := meta == nil || meta.Reboot
	if viaLauncher {
		state, err := runState(ctx, p)
		switch {
		case err != nil:
			return unresolved(pastBound, "unreachable",
				fmt.Sprintf("the OPNsense firmware API could not be read (%v)", err))
		case state != RunReady:
			return unresolved(pastBound, "busy", "OPNsense is still running a firmware job")
		}

		if p.Evidence != nil {
			if evidence, err := p.Evidence(ctx, since); err == nil && evidence != "" {
				return Verdict{
					Action: Fail,
					Reason: "partial-failure",
					Message: fmt.Sprintf("The firmware update did not complete: OPNsense reported %q, so the update may "+
						"not have been applied in full.", evidence),
				}
			}
		}
	}
	if meta == nil || !meta.Reboot {
		// pkg goes on after the process that started it is gone (the exec child of
		// a reboot=false run dies with the agent, which one of the run's own
		// packages can stop), and an older agent's row may have been such a run.
		if running, err := toolsBusy(ctx, p); err != nil || running {
			return unresolved(pastBound, "packages-updating", "package tools are still running")
		}
	}

	if meta == nil {
		return legacyCompletion(ctx, p)
	}
	return evaluateRecorded(ctx, in, p, *meta, pastBound)
}

// toolsBusy is whether pkg or opnsense-update runs; a probe that cannot answer,
// or is missing, is an error, and callers wait on an error.
func toolsBusy(ctx context.Context, p Probes) (bool, error) {
	if p.Updating == nil {
		return true, errNoProbe
	}
	return p.Updating(ctx)
}

// runState is what the API says, unless the lock it reports on is in fact held:
// the API is a PHP page that asks configd, and while OPNsense restarts either
// during an update the lock is the truer answer.
func runState(ctx context.Context, p Probes) (RunState, error) {
	if p.Running == nil {
		return RunUnknown, errNoAPI
	}
	state, err := p.Running(ctx)
	if err == nil && state == RunReady && p.Locked != nil {
		if held, lockErr := p.Locked(ctx); lockErr == nil && held {
			return RunBusy, nil
		}
	}
	return state, err
}

// legacyCompletion resolves a row nothing was recorded for, as the agent always
// did once the device is back: complete it, with the release if it can be read.
func legacyCompletion(ctx context.Context, p Probes) Verdict {
	if p.Release != nil {
		if version, err := p.Release(ctx); err == nil && version != "" {
			return Verdict{
				Action:  Complete,
				Reason:  "returned",
				Message: fmt.Sprintf("Firmware upgrade completed; device returned with product_version %s", version),
			}
		}
	}
	return Verdict{Action: Complete, Reason: "returned", Message: "Device returned after restart"}
}

func evaluateRecorded(ctx context.Context, in Input, p Probes, meta Meta, pastBound bool) Verdict {
	// Has the box restarted since the run was triggered?
	rebooted, bootKnown := false, false
	if p.BootTime != nil && meta.BootTime > 0 {
		if boot, err := p.BootTime(); err == nil {
			bootKnown = true
			rebooted = time.Unix(boot, 0).After(time.Unix(meta.BootTime, 0).Add(BootMargin))
		}
	}
	if meta.RebootExpected() && meta.BootTime > 0 {
		if !bootKnown {
			return unresolved(pastBound, "boot-time", "the boot time could not be read")
		}
		if !rebooted {
			const detail = "the device has not restarted since the update was triggered, so the base system " +
				"and kernel update was not applied"
			if in.Sentinel == "done" {
				return Verdict{
					Action:  Fail,
					Reason:  "no-reboot",
					Message: "The firmware update finished without the reboot it needed: " + detail + ".",
				}
			}
			return unresolved(pastBound, "no-reboot", detail)
		}
	}

	if p.Release == nil {
		return unresolved(pastBound, "release-unreadable", "the installed release could not be read")
	}
	version, err := p.Release(ctx)
	if err != nil || version == "" {
		return unresolved(pastBound, "release-unreadable",
			fmt.Sprintf("the installed release could not be read (%v)", err))
	}

	advanced := version != meta.FromVersion
	if advanced && meta.Reboot {
		return completed(in, meta, version, rebooted, "advanced")
	}

	if !advanced && meta.Mode == "major" {
		detail := fmt.Sprintf("the installed release has not changed (still %s)", version)
		if in.Sentinel == "done" {
			return Verdict{
				Action:  Fail,
				Reason:  "unchanged",
				Message: "The series upgrade finished without changing the installed release (still " + version + ").",
			}
		}
		return unresolved(pastBound, "major-in-progress", detail)
	}

	// A reboot the run needs cannot be confirmed without the boot time it started
	// from, and an unchanged release does not show the update was applied.
	if !advanced && meta.RebootExpected() && meta.BootTime == 0 {
		return unresolved(pastBound, "boot-time-unknown",
			"the boot time when the update was triggered is not known, so its restart cannot be confirmed")
	}

	// Packages only: the release did not change, or the run does not reboot and
	// the release moved first. Either way the plan says what must be installed.
	reason := "packages-applied"
	if advanced {
		reason = "advanced"
	}
	need := meta.checkable()
	if len(need) == 0 {
		if !advanced {
			reason = "nothing-to-verify"
		}
		return completed(in, meta, version, rebooted, reason)
	}
	if p.Installed == nil {
		return unresolved(pastBound, "pkg-query", "the package database could not be read")
	}
	installed, err := p.Installed(ctx)
	if err != nil {
		return unresolved(pastBound, "pkg-query", fmt.Sprintf("the package database could not be read (%v)", err))
	}
	var missing []string
	for _, pkg := range need {
		if !AtLeast(installed[pkg.Name], pkg.Version) {
			missing = append(missing, pkg.Name)
		}
	}
	if len(missing) == 0 {
		return completed(in, meta, version, rebooted, reason)
	}

	// Something is still installing: an update the agent's child started keeps
	// running after the agent is stopped, so an incomplete plan is not yet a
	// failed one.
	if running, err := toolsBusy(ctx, p); err != nil || running {
		return unresolved(pastBound, "packages-updating", "package tools are still running")
	}
	release := "still " + version
	if advanced {
		release = version
	}
	return Verdict{
		Action: Fail,
		Reason: "packages-missing",
		Message: fmt.Sprintf("The firmware update did not apply: %s not at the planned version (installed release %s).",
			describeMissing(missing), release),
		Missing: missing,
	}
}

// completed builds the COMPLETED verdict for a recorded run.
func completed(in Input, meta Meta, toVersion string, rebooted bool, reason string) Verdict {
	data := map[string]interface{}{
		"resolved_mode":    meta.Mode,
		"from_version":     meta.FromVersion,
		"to_version":       toVersion,
		"reboot_performed": rebooted,
		"reboots_expected": meta.ExpectedReboots(),
		"applied":          true,
		"no_update":        false,
		"packages_applied": PackagesApplied(meta.Packages),
		"mixed_state":      !meta.Reboot && HasBaseOrKernel(meta.Packages),
	}
	if in.Sentinel != "" {
		data["status_sentinel"] = in.Sentinel
	} else {
		data["reconciled"] = true
	}
	message, err := json.Marshal(data)
	if err != nil { // unreachable for these value types
		message = []byte(`{"applied":true}`)
	}
	return Verdict{Action: Complete, Reason: reason, Message: string(message)}
}

// describeMissing names up to missingShown packages.
func describeMissing(names []string) string {
	shown := names
	if len(shown) > missingShown {
		shown = shown[:missingShown]
	}
	list := strings.Join(shown, ", ")
	if more := len(names) - len(shown); more > 0 {
		list += fmt.Sprintf(" and %d more", more)
	}
	if len(names) == 1 {
		return "package " + list + " is"
	}
	return fmt.Sprintf("%d packages (%s) are", len(names), list)
}

// unresolved is Wait until the deadline and Fail after it.
func unresolved(pastBound bool, reason, detail string) Verdict {
	if !pastBound {
		return Verdict{Action: Wait, Reason: reason, Message: detail}
	}
	return Verdict{
		Action:  Fail,
		Reason:  reason + "-past-deadline",
		Message: "The firmware update could not be confirmed before the task's time ran out: " + detail,
	}
}
