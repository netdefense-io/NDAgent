package tasks

// firmware_meta.go — what a FIRMWARE_UPGRADE run records about itself before it
// starts, so that whoever decides its outcome later (the handler in-session, or
// the reconciler after the handler is gone) can judge it against where it began.

import (
	"context"
	"errors"
	"time"

	"github.com/netdefense-io/ndagent/internal/firmware"
	"github.com/netdefense-io/ndagent/internal/network"
	"github.com/netdefense-io/ndagent/internal/opnapi"
	"github.com/netdefense-io/ndagent/internal/taskstore"
)

// firmwareTaskStore returns the task registry, or nil when there is none (a
// device where /var/db/ndagent could not be opened, and tests). Tests replace it.
var firmwareTaskStore = func(ws *network.WebSocketClient) *taskstore.Store {
	if ws == nil {
		return nil
	}
	return ws.GetTaskStore()
}

// firmwareBootTime reads the box's boot time, firmwareNow is the clock and
// firmwareUptime is how long this process has run. Tests replace them.
var (
	firmwareBootTime = firmware.BootTime
	firmwareNow      = time.Now
	firmwareUptime   = firmware.Uptime
	// firmwareDeadline is when a run stops watching and asks the device for a
	// verdict whatever it has seen.
	firmwareDeadline = firmware.Deadline
)

// installedVersion reads the release installed on the device, the way every
// FIRMWARE_UPGRADE version is read: from the local version file, never from the
// cached result of a firmware check (whose top-level product_version is stale
// after an update and absent after every flush).
func installedVersion(ctx context.Context, client firmwareOPNAPIClient) (string, error) {
	release, err := client.InstalledRelease(ctx)
	if err != nil {
		return "", err
	}
	if release.Raw == "" {
		return "", errors.New("no product version")
	}
	return release.Raw, nil
}

// firmwareExpiry is when NDManager gives up on the task: the signed dispatch
// expiry, or the mode's lifetime from started when the command carries none.
func firmwareExpiry(cmd network.Command, started time.Time, mode string) time.Time {
	if cmd.ExpiresAt > 0 {
		return time.Unix(cmd.ExpiresAt, 0)
	}
	return started.Add(firmware.TTL(mode))
}

// recordFirmwareMarker persists, before the task waits for its turn, that it was
// taken up and has triggered nothing. An agent that stops now leaves a row the
// reconciler can tell from one an older agent wrote (which recorded nothing and
// is completed once the device is idle): this one never touched the device. It
// reports whether the record was written.
func recordFirmwareMarker(
	ws *network.WebSocketClient,
	cmd network.Command,
	log interface{ Warnw(string, ...interface{}) },
	mode string,
	reboot bool,
) bool {
	store := firmwareTaskStore(ws)
	if store == nil {
		return false
	}
	started := firmwareNow()
	if err := store.SetTaskMeta(cmd.TaskID, firmware.NewMarker(mode, reboot, started, firmwareExpiry(cmd, started, mode))); err != nil {
		log.Warnw("Failed to persist FIRMWARE_UPGRADE marker; if the agent stops before the task starts, its outcome will be less precise",
			"task_id", cmd.TaskID, "error", err)
		return false
	}
	// The write is an update of the task's row and says nothing when there is
	// none, so ask whether the row carries the marker.
	var marker firmware.Meta
	found, err := store.GetTaskMeta(cmd.TaskID, &marker)
	return err == nil && found && marker.Mode == mode
}

// recordFirmwareRun persists the run's metadata on its task row and returns it.
// It records where the run starts, not that it has been triggered (see
// markFirmwareTriggered), and it must be called before anything is triggered: the
// row can outlive this process from then on. A store that cannot be written is
// logged and does not stop the run; the row is then resolved as one with no
// metadata.
func recordFirmwareRun(
	ws *network.WebSocketClient,
	cmd network.Command,
	log interface{ Warnw(string, ...interface{}) },
	mode string,
	reboot bool,
	fromVersion string,
	status *opnapi.FirmwareUpgradeStatus,
) firmware.Meta {
	started := firmwareNow()
	bootTime, err := firmwareBootTime()
	if err != nil {
		bootTime = 0
		log.Warnw("Could not read the boot time; a reboot cannot be checked later",
			"task_id", cmd.TaskID, "error", err)
	}
	meta := firmware.NewMeta(mode, reboot, fromVersion, status, bootTime, started, firmwareExpiry(cmd, started, mode))

	if store := firmwareTaskStore(ws); store != nil {
		if err := store.SetTaskMeta(cmd.TaskID, meta); err != nil {
			log.Warnw("Failed to persist FIRMWARE_UPGRADE metadata; the outcome after a restart will be less precise",
				"task_id", cmd.TaskID, "error", err)
		}
	}
	return meta
}

// markFirmwareTriggered persists, and sets on meta, the moment the run is
// requested. It is called right before the request: from then on the row is
// judged as a run that started, and the log of a failure is only looked for from
// this moment on. It also tells the firmware guard, so that giving the slot
// back asks the heavy-telemetry collector for a check.
func markFirmwareTriggered(
	ws *network.WebSocketClient,
	cmd network.Command,
	log interface{ Warnw(string, ...interface{}) },
	meta *firmware.Meta,
) {
	meta.TriggeredAt = firmwareNow().Unix()
	persistFirmwareMeta(ws, cmd, log, *meta)
	firmware.NoteTriggered()
}
