package tasks

// firmware_rest.go — the REST-driven runs of FIRMWARE_UPGRADE: minor and major
// with reboot=true.
//
// The agent asks OPNsense to run the update (POST /core/firmware/update or
// /upgrade) and then only watches. The work is OPNsense's: a detached process
// tree that holds a lock for as long as it runs, outlives this handler whenever
// the run replaces the agent's own package or the box reboots, and can fail
// while still printing its end marker. So this file is careful about three
// things: not to trigger into a backend that would silently drop the request,
// not to mistake a gap in the API (OPNsense restarts its own services in the
// first minute) or a dropped connection for the end of the run, and not to
// believe an end marker without asking the device (firmware.Evaluate).

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/netdefense-io/ndagent/internal/firmware"
	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/network"
	"github.com/netdefense-io/ndagent/internal/opnapi"
	"github.com/netdefense-io/ndagent/internal/util"
)

// The progress-log line OPNsense's launcher writes when it starts a request.
const (
	updateRequestMarker  = "***GOT REQUEST TO UPDATE***"
	upgradeRequestMarker = "***GOT REQUEST TO UPGRADE***"
)

// Waits and polls, as variables so tests do not sit through them.
var (
	// firmwarePreTriggerWaitVar bounds how long a run waits for the firmware
	// backend to be free before it asks OPNsense to start. launcher.sh takes its
	// lock with `flock -n`, so a request that finds it held (a check the GUI or
	// the heavy-telemetry collector started, or another update) is dropped
	// without a word: triggering into a busy backend means no update at all.
	firmwarePreTriggerWaitVar = 5 * time.Minute
	firmwarePreTriggerPollVar = 3 * time.Second
	// firmwareStartWindowVar is how long a run is given to show it started once
	// OPNsense accepted the request.
	firmwareStartWindowVar = 15 * time.Second
	firmwareStartPollVar   = time.Second
	// firmwareSettleIntervalVar is how often the evaluation is repeated while it
	// still has to wait for something.
	firmwareSettleIntervalVar = 5 * time.Second
)

// newFirmwareProbes reads the device through client; tests substitute their own.
var newFirmwareProbes = func(client firmwareOPNAPIClient) firmware.Probes {
	return firmware.NewProbes(client)
}

// restRun describes one of the two REST-driven runs.
type restRun struct {
	mode string
	// verb is "update" or "upgrade", for messages.
	verb string
	// marker is the progress-log line that shows OPNsense started the request.
	marker string
	// progress is the IN_PROGRESS message, given the release the run starts from.
	progress func(fromVersion string) string
	// trigger asks OPNsense to start the run and returns the status it answered.
	trigger func(ctx context.Context) (status string, err error)
}

// handleMinorWithReboot implements: minor + reboot=true
// REST POST /update, then watch until OPNsense says it is done or the box
// reboots. See runRESTUpdate.
func handleMinorWithReboot(
	ctx context.Context,
	ws *network.WebSocketClient,
	cmd network.Command,
	client firmwareOPNAPIClient,
	payload *firmwareUpgradePayload,
	initialStatus *opnapi.FirmwareUpgradeStatus,
) error {
	return runRESTUpdate(ctx, ws, cmd, client, initialStatus, restRun{
		mode:   "minor",
		verb:   "update",
		marker: updateRequestMarker,
		progress: func(from string) string {
			return fmt.Sprintf("Triggering minor update from %s; OPNsense will reboot...", from)
		},
		trigger: func(ctx context.Context) (string, error) {
			resp, err := client.TriggerFirmwareUpdate(ctx)
			if err != nil {
				return "", err
			}
			return resp.Status, nil
		},
	})
}

// handleMajorWithReboot implements: major + reboot=true
// REST POST /upgrade, then watch (up to two reboots). See runRESTUpdate.
func handleMajorWithReboot(
	ctx context.Context,
	ws *network.WebSocketClient,
	cmd network.Command,
	client firmwareOPNAPIClient,
	payload *firmwareUpgradePayload,
	initialStatus *opnapi.FirmwareUpgradeStatus,
) error {
	return runRESTUpdate(ctx, ws, cmd, client, initialStatus, restRun{
		mode:   "major",
		verb:   "upgrade",
		marker: upgradeRequestMarker,
		progress: func(string) string {
			return fmt.Sprintf("Triggering major upgrade from series %s to %s; OPNsense may reboot up to 2 times...",
				initialStatus.ProductSeries, initialStatus.UpgradeMajorVersion)
		},
		trigger: func(ctx context.Context) (string, error) {
			resp, err := client.TriggerFirmwareUpgrade(ctx)
			if err != nil {
				return "", err
			}
			return resp.Status, nil
		},
	})
}

// runRESTUpdate runs one REST-driven update.
//
// Before anything is triggered it records where the run starts (the row can
// outlive this process from the trigger on), waits for the backend to be free,
// and after the trigger checks that OPNsense really started, asking once more if
// it did not. Then it watches, through gaps in the API, until:
//
//   - OPNsense announces the reboot: the box is going down and takes the agent
//     with it. The handler stays, holding the firmware slot so that a task queued
//     behind it does not run against a box that is shutting down, until the agent
//     is stopped (the row is then left IN_PROGRESS for the reconciler, which
//     resolves it once the box is back and idle) or the run's deadline passes
//     without the box going down (the device is asked, as below);
//   - OPNsense prints its end marker, or the run's deadline passes: the same
//     evaluation the reconciler uses decides the outcome, because the marker is
//     printed after a partial failure too;
//   - the connection or the agent goes away: the row is left IN_PROGRESS too.
func runRESTUpdate(
	ctx context.Context,
	ws *network.WebSocketClient,
	cmd network.Command,
	client firmwareOPNAPIClient,
	status *opnapi.FirmwareUpgradeStatus,
	run restRun,
) error {
	log := logging.Named("FIRMWARE_UPGRADE")
	fail := func(message string) error {
		return firmwareSendResponse(ws, cmd.TaskID, NewFailureResult(message))
	}

	fromVersion, err := installedVersion(ctx, client)
	if err != nil {
		return fail("Could not read the installed OPNsense release: " + err.Error())
	}
	meta := recordFirmwareRun(ws, cmd, log, run.mode, true, fromVersion, status)
	deadline := firmwareDeadline(meta.Expiry())

	if err := firmwareSendInProgress(ws, cmd.TaskID, run.progress(fromVersion)); err != nil {
		log.Warnw("Failed to send IN_PROGRESS", "error", err)
	}

	for attempt := 1; ; attempt++ {
		if err := waitUntilFirmwareReady(ctx, client, log); err != nil {
			if ctx.Err() != nil {
				return ctx.Err() // nothing was triggered: the dispatcher records the cancellation
			}
			return fail("The firmware " + run.verb + " was not started: " + err.Error())
		}
		baseline := progressLog(ctx, client)

		if attempt == 1 {
			markFirmwareTriggered(ws, cmd, log, &meta)
		}
		answer, err := run.trigger(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fail(fmt.Sprintf("Failed to trigger firmware %s: %v", run.verb, err))
		}
		if answer != "ok" {
			return fail(fmt.Sprintf("Firmware %s returned status %q (expected \"ok\")", run.verb, answer))
		}
		log.Infow("Firmware "+run.verb+" triggered; checking that it started",
			"task_id", cmd.TaskID, "from_version", fromVersion, "attempt", attempt)

		if firmwareRunStarted(ctx, client, baseline, run.marker) {
			break
		}
		if ctx.Err() != nil {
			log.Infow("Context cancelled right after the trigger; leaving IN_PROGRESS", "task_id", cmd.TaskID)
			return nil
		}
		if attempt == 2 {
			return fail("OPNsense accepted the " + run.verb + " request but did not start it (another firmware job " +
				"probably held its lock). Nothing was applied.")
		}
		log.Warnw("OPNsense accepted the request but did not start the run; asking once more",
			"task_id", cmd.TaskID)
	}

	pollCtx, stopPolling := context.WithDeadline(ctx, deadline)
	defer stopPolling()
	sentinel := pollUpgradeStatus(pollCtx, client, log)
	log.Infow("Firmware "+run.verb+" sentinel", "task_id", cmd.TaskID, "sentinel", sentinel)

	if sentinel == "reboot" {
		// The box is going down, and the agent with it. What is recorded is what
		// tells the reconciler a reboot was needed; it resolves the row once the
		// box is back and idle.
		meta.RebootSeen = true
		persistFirmwareMeta(ws, cmd, log, meta)
		// update.sh holds OPNsense's lock until the shutdown, so the run has not
		// ended although this handler has nothing left to do: keep the slot, or a
		// task queued behind it would run its check against a box that is going
		// down. The end of the wait is the agent being stopped by the reboot; if the
		// box never goes down, the deadline is, and the device is asked.
		log.Infow("System rebooting; holding the firmware slot until the agent is stopped", "task_id", cmd.TaskID)
		<-pollCtx.Done()
		sentinel = ""
	}
	if ctx.Err() != nil {
		log.Infow("Context cancelled while watching the run (connection lost or agent stopping); leaving IN_PROGRESS",
			"task_id", cmd.TaskID)
		return nil
	}
	return settleRESTRun(ctx, ws, cmd, client, log, meta, sentinel)
}

// settleRESTRun asks the device how the run ended and reports it. sentinel is
// "done" when OPNsense said so, or "" when the deadline ran out first.
func settleRESTRun(
	ctx context.Context,
	ws *network.WebSocketClient,
	cmd network.Command,
	client firmwareOPNAPIClient,
	log interface{ Infow(string, ...interface{}) },
	meta firmware.Meta,
	sentinel string,
) error {
	probes := newFirmwareProbes(client)
	in := firmware.Input{
		Meta:         &meta,
		RowStartedAt: time.Unix(meta.StartedAt, 0),
		Sentinel:     sentinel,
	}
	for {
		// Both move while the evaluation waits, and the bound needs the process to
		// have been up for the grace: a process that was young when the run's watch
		// ended is not young for the rest of the wait.
		in.Now = firmwareNow()
		in.ProcessUptime = firmwareUptime()
		v := firmware.Evaluate(ctx, in, probes)
		switch v.Action {
		case firmware.Complete:
			log.Infow("Firmware run evaluated: completed", "task_id", cmd.TaskID, "reason", v.Reason)
			return firmwareSendResponse(ws, cmd.TaskID, TaskResult{Success: true, Message: v.Message})
		case firmware.Fail:
			log.Infow("Firmware run evaluated: failed", "task_id", cmd.TaskID, "reason", v.Reason)
			return firmwareSendResponse(ws, cmd.TaskID, NewFailureResult(v.Message))
		}
		log.Infow("Firmware run not settled yet", "task_id", cmd.TaskID, "reason", v.Reason, "detail", v.Message)
		if err := util.ShutdownAwareSleep(ctx, firmwareSettleIntervalVar); err != nil {
			// The connection or the agent went away: the reconciler takes over.
			return nil
		}
	}
}

// persistFirmwareMeta rewrites a run's recorded metadata.
func persistFirmwareMeta(ws *network.WebSocketClient, cmd network.Command, log interface{ Warnw(string, ...interface{}) }, meta firmware.Meta) {
	store := firmwareTaskStore(ws)
	if store == nil {
		return
	}
	if err := store.SetTaskMeta(cmd.TaskID, meta); err != nil {
		log.Warnw("Failed to update FIRMWARE_UPGRADE metadata", "task_id", cmd.TaskID, "error", err)
	}
}

// waitUntilFirmwareReady waits until the firmware backend reports "ready". An
// API that does not answer counts as not ready, and a backend that never frees
// up is an error: the request would be dropped.
func waitUntilFirmwareReady(ctx context.Context, client firmwareOPNAPIClient, log interface{ Infow(string, ...interface{}) }) error {
	deadline := time.Now().Add(firmwarePreTriggerWaitVar)
	var last string
	for {
		running, err := client.GetFirmwareRunning(ctx)
		switch {
		case err != nil:
			last = "the firmware API did not answer (" + err.Error() + ")"
		case running != nil && running.Status == "ready":
			return nil
		case running != nil:
			last = fmt.Sprintf("the firmware backend reported %q", running.Status)
		default:
			last = "the firmware API answered nothing"
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("OPNsense's firmware backend did not become free within %s (%s), and a request "+
				"made while it is busy is dropped", firmwarePreTriggerWaitVar, last)
		}
		log.Infow("Waiting for the firmware backend to be free before starting", "detail", last)
		if err := util.ShutdownAwareSleep(ctx, firmwarePreTriggerPollVar); err != nil {
			return err
		}
	}
}

// progressLog reads OPNsense's progress log, "" when it cannot.
func progressLog(ctx context.Context, client firmwareOPNAPIClient) string {
	prog, err := client.GetFirmwareUpgradeProgress(ctx)
	if err != nil || prog == nil {
		return ""
	}
	return prog.Log
}

// firmwareRunStarted reports whether OPNsense started the request just made. Its
// launcher takes a lock with `flock -n` and drops a request that finds it held
// without saying so, while the API still answers "ok", so the answer proves
// nothing. A run shows it started when the progress log changed and carries the
// request marker (an unchanged log is the previous run's), or the backend turned
// busy.
func firmwareRunStarted(ctx context.Context, client firmwareOPNAPIClient, baseline, marker string) bool {
	deadline := time.Now().Add(firmwareStartWindowVar)
	for {
		if log := progressLog(ctx, client); log != baseline && strings.Contains(log, marker) {
			return true
		}
		if running, err := client.GetFirmwareRunning(ctx); err == nil && running != nil && running.Status == "busy" {
			return true
		}
		if ctx.Err() != nil || time.Now().After(deadline) {
			return false
		}
		if err := util.ShutdownAwareSleep(ctx, firmwareStartPollVar); err != nil {
			return false
		}
	}
}

// upgradeStatusPollInterval is the time between /upgradestatus polls.
// Overridable in tests via setUpgradeStatusPollIntervalForTest.
var upgradeStatusPollInterval = 5 * time.Second

// pollUpgradeStatus polls GET /upgradestatus until OPNsense's end marker
// appears or the context ends. It returns "done", "reboot", or "" when the
// context ended first.
//
// It does not give up on anything else. The API disappears while OPNsense
// replaces its own core package (configd and the web GUI restart, in the first
// minute of every core update) and again for the reboot; it answers "error" when
// the progress log is empty, which is what a log being truncated looks like.
// None of that is the end of the run, so errors and "error" are retried until
// the context ends. A gap is not a verdict either way: the caller asks the
// device what happened once there is a marker or the deadline.
func pollUpgradeStatus(ctx context.Context, client firmwareOPNAPIClient, log interface{ Infow(string, ...interface{}) }) string {
	ticker := time.NewTicker(upgradeStatusPollInterval)
	defer ticker.Stop()

	failures := 0
	for {
		select {
		case <-ctx.Done():
			return ""
		case <-ticker.C:
			prog, err := client.GetFirmwareUpgradeProgress(ctx)
			if err != nil || prog == nil {
				if failures++; failures == 1 || failures%12 == 0 {
					log.Infow("Firmware progress not readable; still watching", "failures", failures, "error", err)
				}
				continue
			}
			failures = 0
			switch prog.Status {
			case "done", "reboot":
				return prog.Status
			}
		}
	}
}
