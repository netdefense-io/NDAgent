package track

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/netdefense-io/ndagent/internal/firmware"
	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// waitReady waits until OPNsense's firmware backend reports ready. An API that
// does not answer counts as not ready, and a backend that never frees up is an
// error: a request made while it is busy is dropped.
func (e *Engine) waitReady(ctx context.Context) error {
	return e.waitReadyUntil(ctx, time.Time{})
}

// waitReadyUntil is waitReady that also gives up at limit (the zero time: only
// Timing.ReadyWait ends it). A backend that is ready when it is looked at ends
// the wait whatever the limit says.
func (e *Engine) waitReadyUntil(ctx context.Context, limit time.Time) error {
	deadline := e.now().Add(e.timing.ReadyWait)
	if !limit.IsZero() && limit.Before(deadline) {
		deadline = limit
	}
	for {
		state, err := e.dev.Running(ctx)
		if err == nil && state == firmware.RunReady {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if e.now().After(deadline) {
			return errBackendBusy
		}
		if err := e.sleep(ctx, e.timing.Poll); err != nil {
			return err
		}
	}
}

// What a task still needs once the firmware API answers, which the waits before
// it leave unspent: an enroll is one forced check, an advance the check, the
// update, its reboot and the settle (5 to 6 minutes measured), and a step that
// carries `major` the whole series upgrade.
//
// majorWork is the least time left at which a series upgrade may still start. The
// upgrade was measured at 230 to 275 seconds on a fast link, so 45 minutes is the
// floor (twice the longest); 60 minutes covers its 1244208 KB download at about 3
// Mbit/s or faster, and a slower link ends the step FAILED_NO_RESPONSE at its
// expiry, which a later answer at the target clears.
const (
	enrollWork  = time.Minute
	advanceWork = 8 * time.Minute
	majorWork   = 60 * time.Minute
)

// work is what the step needs once its waits are over: the least time that has to
// be left before it asks OPNsense for anything it cannot take back. A step that
// carries `major` needs a series upgrade's time whichever path it ends up taking,
// since the path is not known until the waits are over.
func (o *op) work() time.Duration {
	switch {
	case o.in.Payload.Action != ActionAdvance:
		return enrollWork
	case o.in.Payload.Major != "":
		return majorWork
	}
	return advanceWork
}

// updateLimit is the last moment an advance may still wait on another firmware
// job before it asks OPNsense for the update: what is left of the signed expiry
// has to hold the update (work), so a wait that goes on past this moment is a task
// that spent its time behind another job, which is what held_firmware_busy says,
// and not a task that ran past its expiry.
func (o *op) updateLimit() time.Time { return o.in.Expires.Add(-o.work()) }

// retryFor runs read until it succeeds or wait has passed and returns its last
// error. The wait is counted in polls as well as by the clock, which a test may
// hold still. failing, if given, is called once with the first error.
func (e *Engine) retryFor(ctx context.Context, wait time.Duration, read func() error, failing func(error)) error {
	tries := 1
	if wait > 0 && e.timing.Poll > 0 {
		tries += int(wait / e.timing.Poll)
	}
	deadline := e.now().Add(wait)
	for try := 0; ; try++ {
		err := read()
		if err == nil {
			return nil
		}
		if ctx.Err() != nil || try+1 >= tries || !e.now().Before(deadline) {
			return err
		}
		if try == 0 && failing != nil {
			failing(err)
		}
		if e.sleep(ctx, e.timing.Poll) != nil {
			return err
		}
	}
}

// awaitAPI waits until the firmware settings and the installed release can be
// read, for at most Timing.APIWait and never into the time the task needs for its
// work. A task can arrive before OPNsense's web GUI and configd are up (the agent
// starts earlier in the boot), and a device that is merely not up yet is neither
// a hold nor, for an unenroll, a failure. It decides nothing: what is still
// unreadable at the end is met by the task's own reads, which hold it as ever.
func (e *Engine) awaitAPI(ctx context.Context, o *op) {
	wait := e.timing.APIWait
	if left := o.in.Expires.Sub(e.now()) - o.work(); left < wait {
		wait = left
	}
	if wait <= 0 {
		return
	}
	read := func() error {
		if _, err := e.dev.Settings(ctx); err != nil {
			return err
		}
		_, err := e.dev.Installed(ctx)
		return err
	}
	_ = e.retryFor(ctx, wait, read, func(err error) {
		e.log.Infow("The firmware API does not answer yet; waiting for it", "task_id", o.in.TaskID, "error", describeErr(err))
		o.progress("Waiting for OPNsense's firmware API...")
	})
}

// firmwareIdle reports whether nothing runs on OPNsense's firmware backend or in
// the package tools: the state in which the flavour may be written. A write
// moves the repositories the running job is reading from, so anything that
// cannot be told apart from busy counts as busy.
func (e *Engine) firmwareIdle(ctx context.Context) bool {
	if state, err := e.dev.Running(ctx); err != nil || state != firmware.RunReady {
		return false
	}
	if updating := e.dev.Probes().Updating; updating != nil {
		if busy, err := updating(ctx); err != nil || busy {
			return false
		}
	}
	return true
}

// forcedCheck asks OPNsense for a check (which refetches every catalog, `pkg
// update -f`) and returns its result once it is there. It is the check that has
// to follow every change of the flavour: `/set` flushes the cached result and
// fetches no catalog, so until a check runs the local catalog still holds the
// previous directory's packages.
//
// A request OPNsense drops (its launcher takes its lock with `flock -n`) leaves
// the old result in place and the backend idle; that is told from a check that
// ran by the result's last_check, which only a new check changes.
func (e *Engine) forcedCheck(ctx context.Context) (*opnapi.FirmwareUpgradeStatus, error) {
	if err := e.waitReady(ctx); err != nil {
		return nil, err
	}
	before, err := e.dev.Status(ctx)
	if err != nil {
		return nil, fmt.Errorf("read the firmware status: %w", err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := e.dev.TriggerCheck(ctx); err != nil {
			return nil, fmt.Errorf("ask for a firmware check: %w", err)
		}
		st, err := e.awaitCheck(ctx, before.LastCheck)
		if errors.Is(err, errCheckDropped) {
			if err := e.waitReady(ctx); err != nil {
				return nil, err
			}
			continue
		}
		return st, err
	}
	return nil, errCheckDropped
}

func (e *Engine) awaitCheck(ctx context.Context, beforeLast string) (*opnapi.FirmwareUpgradeStatus, error) {
	start := e.now()
	deadline := start.Add(e.timing.CheckTimeout)
	ran := false
	for {
		if err := e.sleep(ctx, e.timing.Poll); err != nil {
			return nil, err
		}
		state, err := e.dev.Running(ctx)
		switch {
		case err != nil || state == firmware.RunUnknown:
			// A gap in the API (OPNsense restarts services during an update) is no verdict.
		case state == firmware.RunBusy:
			ran = true
		default:
			if st, err := e.dev.Status(ctx); err == nil && st.Completed() && st.LastCheck != beforeLast {
				return st, nil
			}
			if !ran && e.now().Sub(start) >= e.timing.CheckIdleDrop {
				return nil, errCheckDropped
			}
		}
		if e.now().After(deadline) {
			return nil, errCheckTimeout
		}
	}
}

// usable judges a check that finished: it has to have used the mirror and have
// been made against the installed release. An empty plan under a check that did
// not is a failure, never "up to date"; there is no fallback to an older result.
func usable(st *opnapi.FirmwareUpgradeStatus) error {
	switch {
	case !st.Completed():
		return errors.New("the firmware check left no result")
	case st.Stale():
		return fmt.Errorf("the firmware check describes release %s, not the installed %s", st.ProductVersion, st.InstalledVersion)
	case !st.Clean():
		return fmt.Errorf("the firmware check could not use the mirror (status %s, connection %s, repository %s)",
			st.Status, st.Connection, st.Repository)
	}
	return nil
}

// probe asks the mirror whether a URL is there, remembering a folder that is
// there for a short while so a fleet's windows do not hammer it. A 404 is not
// remembered: two misses of a folder release a device, and an answer served from
// the cache would make them one observation.
func (e *Engine) probe(ctx context.Context, rawURL string) ProbeResult {
	e.probeMu.Lock()
	entry, ok := e.probes[rawURL]
	e.probeMu.Unlock()
	if ok && e.now().Sub(entry.at) < e.timing.ProbeCacheTTL && entry.result == ProbeFound {
		return entry.result
	}
	result := e.dev.Probe(ctx, rawURL)
	e.log.Debugw("Probed the mirror", "url", redactURL(rawURL), "result", result.String())
	e.probeMu.Lock()
	e.probes[rawURL] = probeEntry{result: result, at: e.now()}
	e.probeMu.Unlock()
	return result
}

// forgetProbes drops what was learned about the mirror. A folder that was just
// pinned to or restored from is looked at again by the next task.
func (e *Engine) forgetProbes() {
	e.probeMu.Lock()
	e.probes = make(map[string]probeEntry)
	e.probeMu.Unlock()
}

// probeDir asks whether the release directory is on the mirror, its aux part
// too when the device uses one: an aux repository without a directory fails a
// check as surely as a missing one.
func (e *Engine) probeDir(ctx context.Context, m RepoBase, dir string, aux bool) ProbeResult {
	switch r := e.probe(ctx, m.FolderURL(dir, false)); r {
	case ProbeFound:
	default:
		return r
	}
	if aux {
		return e.probe(ctx, m.FolderURL(dir, true))
	}
	return ProbeFound
}

// pickDir finds the directory that holds the installed release on the device's
// mirror: its own name first (a hotfix directory after a series' final release),
// then the release it is a revision of (a release's directory takes hotfix
// revisions in place). Missing means every candidate answered 404; Unreachable
// means one could not be asked, which is never taken for missing.
func (e *Engine) pickDir(ctx context.Context, m RepoBase, installed string, aux bool) (string, ProbeResult) {
	for _, dir := range DirCandidates(installed) {
		switch r := e.probeDir(ctx, m, dir, aux); r {
		case ProbeFound:
			return dir, ProbeFound
		case ProbeUnreachable:
			return "", ProbeUnreachable
		}
	}
	return "", ProbeMissing
}

// jitterOnce delays the first request of a task to the mirror by a random time.
func (e *Engine) jitterOnce(ctx context.Context, o *op) {
	if o.jittered {
		return
	}
	o.jittered = true
	if d := e.jitter(e.timing.Jitter); d > 0 {
		_ = e.sleep(ctx, d)
	}
}

// foreignError is a compare-and-swap that found the flavour holding a value the
// agent did not write.
type foreignError struct{ current string }

func (f *foreignError) Error() string {
	return fmt.Sprintf("the firmware flavour is %q, which the agent did not write", f.current)
}

// writeFlavour sets the flavour, reads it back and logs both values (no secrets
// are in either: a flavour is a release path). The call can be applied and still
// report an error (a timeout after OPNsense saved), so a failed call is judged
// by what the setting reads afterwards.
func (e *Engine) writeFlavour(ctx context.Context, want, why string) error {
	before, _ := e.dev.Settings(ctx)
	setErr := e.dev.SetFlavour(ctx, want)
	after, err := e.dev.Settings(ctx)
	switch {
	case err != nil && setErr != nil:
		return setErr
	case err != nil:
		return fmt.Errorf("read the firmware flavour back: %w", err)
	case after.Flavour != want:
		if setErr != nil {
			return setErr
		}
		return fmt.Errorf("the firmware flavour reads %q after it was set to %q", after.Flavour, want)
	}
	if setErr != nil {
		e.log.Warnw("Setting the firmware flavour reported an error but it took effect", "error", setErr)
	}
	firmware.NoteTriggered()
	e.forgetProbes()
	e.log.Infow("Firmware flavour written", "why", why, "before", before.Flavour, "after", after.Flavour)
	return nil
}

// restoreFlavour is the compare-and-swap that undoes a pin: it writes `to` only
// when the flavour still equals one of the values the agent wrote, and reads it
// back. Anything else is somebody else's value and stays.
func (e *Engine) restoreFlavour(ctx context.Context, owned func(string) bool, to, why string) error {
	cur, err := e.dev.Settings(ctx)
	if err != nil {
		return err
	}
	if cur.Flavour == to {
		return nil
	}
	if !owned(cur.Flavour) {
		return &foreignError{current: cur.Flavour}
	}
	return e.writeFlavour(ctx, to, why)
}

// settingsProblem is a short reason the device is not one the pin may touch, or
// "" when it is: a subscription or a release type of its own (a business
// mirror), whose mirror and series differ from the community pin.
func settingsProblem(s opnapi.FirmwareSettings) string {
	switch {
	case s.SubscriptionSet:
		return "a subscription is set"
	case s.Type != "":
		return fmt.Sprintf("the release type is %q", s.Type)
	}
	return ""
}

func describeErr(err error) string {
	if err == nil {
		return ""
	}
	return strings.TrimSpace(err.Error())
}
