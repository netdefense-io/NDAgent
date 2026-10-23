package tasks

// firmware_major.go — FIRMWARE_UPGRADE mode=major.
//
// A series upgrade asked for outside a firmware track is judged by the rules a
// track's series upgrade is judged by (internal/firmware/track). A `POST
// /core/firmware/upgrade` without a real offer rebooted a 26.1.9 box, and a
// cached, failed or stale check, or a partial one (sets without a series, a
// message alone), can show an offer that is not there. So:
//
//   - the run is judged only by a check this task makes, told from an older one
//     by its last_check, whatever check_first says, and the check has to be
//     usable (track.UsableCheck);
//   - the target is the hop table's for the installed series, and the offer has
//     to be that series with its three sets and nothing else pending
//     (track.JudgeMajorOffer);
//   - right before the POST the status (still that check) and the installed
//     release are read again.
//
// No offer is a no-op; anything else that stops the run is a failure that says
// why. Neither POSTs.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/netdefense-io/ndagent/internal/firmware"
	"github.com/netdefense-io/ndagent/internal/firmware/track"
	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/network"
	"github.com/netdefense-io/ndagent/internal/opnapi"
	"github.com/netdefense-io/ndagent/internal/util"
)

// The check of a series upgrade is waited for as a track's series upgrade
// waits for its own (track.DefaultTiming): majorCheckTimeoutVar bounds the
// check, and firmwareCheckIdleDropVar is how long the backend may read idle
// after it was asked for, without having been seen busy, before the request
// counts as dropped. A slow mirror must not fail one where it passes the
// other. Variables so tests do not sit through them.
var (
	majorCheckTimeoutVar     = track.DefaultTiming().CheckTimeout
	firmwareCheckIdleDropVar = track.DefaultTiming().CheckIdleDrop
)

var errFirmwareCheckDropped = errors.New("OPNsense did not run the firmware check (another firmware job held its lock)")

// majorOffer is a series upgrade this task's check offered.
type majorOffer struct {
	checked *opnapi.FirmwareUpgradeStatus
	series  string // the installed series
	target  string // the series offered, the hop table's for series
	from    string // the installed release at the check
	// checkFirstIgnored: the payload asked for no check (check_first=false).
	checkFirstIgnored bool
}

// handleMajor runs mode=major once the task holds the firmware slot.
func handleMajor(ctx context.Context, ws *network.WebSocketClient, cmd network.Command, client firmwareOPNAPIClient,
	payload *firmwareUpgradePayload, marked bool) error {
	log := logging.Named("FIRMWARE_UPGRADE")
	ignored := !payload.CheckFirst
	notRequested := func(why string) error {
		message := "The series upgrade was not requested: " + why + ". Nothing was applied."
		if ignored {
			message += " " + firmware.CheckFirstIgnoredNote
		}
		return firmwareSendResponse(ws, cmd.TaskID, NewFailureResult(message))
	}
	// result is a COMPLETED answer's JSON, noting a check_first=false the task did
	// not honour.
	result := func(data map[string]interface{}) error {
		if ignored {
			data["check_first_ignored"] = true
		}
		return firmwareSendResponse(ws, cmd.TaskID, TaskResult{Success: true, Message: firmwareSuccessJSON(data)})
	}

	if ignored {
		log.Infow("check_first=false does not apply to a series upgrade; checking first", "task_id", cmd.TaskID)
	}
	checked, err := firmwareCheckByThisTask(ctx, client, log)
	if err == nil {
		err = track.UsableCheck(checked)
	}
	if err != nil {
		if ctx.Err() != nil {
			return leftBeforeTheTrigger(ctx, log, cmd, marked)
		}
		return notRequested(err.Error())
	}
	from, err := installedVersion(ctx, client)
	if err != nil {
		if ctx.Err() != nil {
			return leftBeforeTheTrigger(ctx, log, cmd, marked)
		}
		return notRequested("the installed OPNsense release could not be read (" + err.Error() + ")")
	}
	if checked.ProductVersion != "" && checked.ProductVersion != from {
		return notRequested(fmt.Sprintf("the firmware check describes release %s, not the installed %s",
			checked.ProductVersion, from))
	}
	series, _ := track.SeriesOf(from)
	verdict, target, why := track.JudgeMajorOffer(checked, series)
	log.Infow("Series upgrade judged",
		"task_id", cmd.TaskID,
		"from_version", from,
		"offered", checked.UpgradeMajorVersion,
		"target", target,
		"upgrade_sets", len(checked.UpgradeSets),
		"last_check", checked.LastCheck,
		"verdict", verdict,
		"why", why,
	)

	switch verdict {
	case track.MajorNotOffered:
		return result(map[string]interface{}{
			"resolved_mode":    "major",
			"from_version":     from,
			"no_update":        true,
			"applied":          false,
			"reboot_performed": false,
			"opnsense_status":  checked.Status,
		})
	case track.MajorRefused:
		return notRequested(why)
	}

	offer := majorOffer{checked: checked, series: series, target: target, from: from, checkFirstIgnored: ignored}
	if payload.DryRun {
		return result(map[string]interface{}{
			"resolved_mode":    "major",
			"from_version":     from,
			"to_version":       target,
			"reboot_performed": false,
			"reboots_expected": firmware.Meta{Mode: "major", Reboot: true}.ExpectedReboots(),
			"applied":          false,
			"dry_run":          true,
			"no_update":        false,
			"packages_applied": firmware.PackagesApplied(firmware.PlannedPackages(checked)),
			"mixed_state":      false,
			"opnsense_status":  checked.Status,
			"needs_reboot":     checked.NeedsReboot,
		})
	}
	return handleMajorWithReboot(ctx, ws, cmd, client, offer)
}

// stillStands reads the status and the installed release again, right before
// the request: the status has to be the same check, still usable and still
// offering the same upgrade, and the release the one it was made for.
func (o majorOffer) stillStands(ctx context.Context, client firmwareOPNAPIClient) error {
	again, err := client.GetFirmwareUpgradeStatus(ctx)
	if err != nil {
		return fmt.Errorf("the firmware status could not be read again before the request (%v)", err)
	}
	if again.LastCheck != o.checked.LastCheck {
		return fmt.Errorf("the firmware status changed after this task's check (last check %q, now %q)",
			o.checked.LastCheck, again.LastCheck)
	}
	if err := track.UsableCheck(again); err != nil {
		return err
	}
	if verdict, target, why := track.JudgeMajorOffer(again, o.series); verdict != track.MajorOffered || target != o.target {
		if why == "" {
			why = "the check no longer offers the upgrade to " + o.target
		}
		return errors.New(why)
	}
	now, err := installedVersion(ctx, client)
	if err != nil {
		return fmt.Errorf("the installed OPNsense release could not be read again before the request (%v)", err)
	}
	if now != o.from {
		return fmt.Errorf("the installed OPNsense release changed from %s to %s after the check", o.from, now)
	}
	return nil
}

// firmwareCheckByThisTask asks OPNsense for a firmware check and returns its
// result. The status read before the request names the check it replaces, and
// only a result with another last_check is this task's: a request OPNsense drops
// (its launcher takes its lock with `flock -n`) leaves the old result in place
// and the backend idle, and is asked once more.
func firmwareCheckByThisTask(ctx context.Context, client firmwareOPNAPIClient,
	log interface{ Infow(string, ...interface{}) }) (*opnapi.FirmwareUpgradeStatus, error) {
	if err := waitUntilFirmwareReady(ctx, client, log); err != nil {
		return nil, err
	}
	before, err := client.GetFirmwareUpgradeStatus(ctx)
	if err != nil {
		return nil, fmt.Errorf("the firmware status could not be read (%v)", err)
	}
	for attempt := 1; ; attempt++ {
		if err := client.TriggerFirmwareCheck(ctx); err != nil {
			return nil, fmt.Errorf("the firmware check could not be requested (%v)", err)
		}
		st, err := awaitFirmwareCheck(ctx, client, before.LastCheck)
		if !errors.Is(err, errFirmwareCheckDropped) || attempt == 2 {
			return st, err
		}
		log.Infow("OPNsense did not run the firmware check; asking once more")
		if err := waitUntilFirmwareReady(ctx, client, log); err != nil {
			return nil, err
		}
	}
}

// awaitFirmwareCheck waits for the result of a check asked for after the one
// named beforeLast: a finished result with another last_check. A backend never
// seen busy and idle past firmwareCheckIdleDropVar dropped the request. A gap in
// the API is no verdict either way.
func awaitFirmwareCheck(ctx context.Context, client firmwareOPNAPIClient, beforeLast string) (*opnapi.FirmwareUpgradeStatus, error) {
	start := time.Now()
	ran := false
	for {
		if err := util.ShutdownAwareSleep(ctx, firmwareCheckPollIntervalVar); err != nil {
			return nil, err
		}
		running, err := client.GetFirmwareRunning(ctx)
		switch {
		case err != nil || running == nil:
		case running.Status == "ready":
			if st, err := client.GetFirmwareUpgradeStatus(ctx); err == nil && st.Completed() && st.LastCheck != beforeLast {
				return st, nil
			}
			if !ran && time.Since(start) >= firmwareCheckIdleDropVar {
				return nil, errFirmwareCheckDropped
			}
		default:
			ran = true
		}
		if time.Since(start) >= majorCheckTimeoutVar {
			return nil, fmt.Errorf("the firmware check did not finish within %s", majorCheckTimeoutVar)
		}
	}
}
