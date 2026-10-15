package tasks

// firmware_track.go — the FIRMWARE_TRACK task: staged OPNsense updates. A device
// in a track is held at a release by OPNsense's own firmware flavour setting
// (`<series>/MINT/<dir>/latest`), and a window moves it to the release its track
// approved. The pin lifecycle (enroll, advance, unenroll, the reconcile, the
// releases the agent makes by itself) is internal/firmware/track's; this file is
// the handler around it: it reads the signed payload, records the task before it
// waits for its turn, takes the firmware slot every firmware job shares, runs the
// engine and turns its outcome into the task's answer.
//
// The task is server-created only and carries no client input. An agent that
// predates it answers the unknown type FAILED and does nothing (the dispatcher's
// rule for a type it has no handler for), and NDManager does not send it to one.
//
// Answers:
//   - COMPLETED with the result JSON (track.Result) for every end that is not a
//     failure, holds included: a hold costs one window, where a wrong FAILED
//     stops a release for the whole organization.
//   - FAILED with plain text for an operation that started and did not finish,
//     with the release it was moving to in the signed side-channel
//     (firmware_track_failure), which the control plane counts the failure against.
//   - Nothing, with the row left IN_PROGRESS, when the context ends (the
//     connection dropped, the agent is stopping, the box rebooted for the
//     update), or when an update that completed cannot be recorded yet because
//     its release or the agent's record cannot be read: the row's reconciler
//     decides it from the device (core).

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/netdefense-io/ndagent/internal/firmware"
	"github.com/netdefense-io/ndagent/internal/firmware/track"
	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/network"
)

// trackEngine is the process's engine. It is built once, by the lifecycle
// manager, because the periodic reconcile and the dead-man use the same one: they
// share its lock with the tasks, so they never run over each other.
var trackEngine atomic.Pointer[track.Engine]

// SetFirmwareTrackEngine installs the engine the handler runs tasks on. Without
// one (a device with no OPNsense API credentials) every task is held.
func SetFirmwareTrackEngine(e *track.Engine) { trackEngine.Store(e) }

// firmwareTrackSend is the indirection every FIRMWARE_TRACK answer goes through;
// tests replace it.
var firmwareTrackSend = func(ws *network.WebSocketClient, taskID string, result TaskResult) error {
	return SendTaskResponse(ws, taskID, result)
}

// firmwareTrackInProgress is the indirection for IN_PROGRESS messages.
var firmwareTrackInProgress = func(ws *network.WebSocketClient, taskID, message string) error {
	return SendInProgressResponse(ws, taskID, message)
}

// HandleFirmwareTrack handles the FIRMWARE_TRACK task type.
//
// It never returns the error of sending an answer. SendTaskResponse records the
// outcome before it writes it, and the next connect's drain sends what was
// recorded; an error returned instead is read by the dispatcher, when the
// connection ended, as a task that was cancelled, and the FAILED it sends then
// replaces the recorded answer.
func HandleFirmwareTrack(ctx context.Context, ws *network.WebSocketClient, cmd network.Command) error {
	log := logging.Named("FIRMWARE_TRACK")
	send := func(result TaskResult) error {
		if err := firmwareTrackSend(ws, cmd.TaskID, result); err != nil {
			log.Warnw("Could not send the FIRMWARE_TRACK answer; it is recorded and goes out on the next connect",
				"task_id", cmd.TaskID, "error", err)
		}
		return nil
	}

	payload, fault := track.ParsePayload(cmd.Payload)
	if fault != nil {
		log.Warnw("Invalid FIRMWARE_TRACK payload", "task_id", cmd.TaskID, "fault", fault.Kind, "detail", fault.Detail)
		return send(NewFailureResult("Invalid FIRMWARE_TRACK payload: " + fault.Error()))
	}
	log.Infow("Received FIRMWARE_TRACK command",
		"task_id", cmd.TaskID, "action", payload.Action, "track", payload.Track, "reboot", payload.Reboot,
		"approved", len(payload.Approved))

	engine := trackEngine.Load()
	if engine == nil {
		log.Warnw("FIRMWARE_TRACK cannot run: no OPNsense API credentials are configured", "task_id", cmd.TaskID)
		if payload.Action == track.ActionUnenroll {
			return send(NewFailureResult("OPNsense API client not configured (api_key/api_secret missing); the firmware pin was not touched"))
		}
		return send(outcomeResult(track.Held(*payload, track.ReasonHeldCheckFailed)))
	}

	started := firmwareNow()
	expires := track.DefaultExpiry(*payload, started)
	if cmd.ExpiresAt > 0 {
		expires = time.Unix(cmd.ExpiresAt, 0)
	}

	// The task is recorded before it waits for its turn: an agent that stops while
	// the task is queued behind another firmware job leaves a row the reconciler
	// can answer, with the action and track the answer has to echo.
	saveJob := func(job track.Job) {
		store := firmwareTaskStore(ws)
		if store == nil {
			return
		}
		if err := store.SetTaskMeta(cmd.TaskID, job); err != nil {
			log.Warnw("Failed to persist FIRMWARE_TRACK job; if the agent stops, its outcome will be less precise",
				"task_id", cmd.TaskID, "error", err)
		}
	}
	// persistJob is the write the engine makes before it asks OPNsense for anything
	// it cannot take back (the update, the series upgrade): the job is on disk when
	// it returns, or the error says it may not be. A store that does not exist (the
	// agent runs without persistence) cannot lose what it never kept, and is no
	// reason to refuse the task.
	persistJob := func(job track.Job) error {
		store := firmwareTaskStore(ws)
		if store == nil {
			return nil
		}
		return store.SetTaskMetaDurable(cmd.TaskID, job)
	}
	saveJob(track.NewJob(*payload, started, expires))

	// One firmware job at a time: OPNsense runs one, and a request that finds its
	// lock held is dropped. The wait is bounded by the task's own expiry.
	waitCtx, endWait := firmwareWaitContext(ctx, cmd)
	defer endWait()
	release, err := firmware.Acquire(waitCtx, func() {
		log.Infow("Another firmware task is running on this device; waiting for it", "task_id", cmd.TaskID)
		if err := firmwareTrackInProgress(ws, cmd.TaskID, "Waiting for another firmware task on this device to finish..."); err != nil {
			log.Warnw("Failed to send IN_PROGRESS", "error", err)
		}
	})
	if err != nil {
		if ctx.Err() != nil {
			log.Infow("Context ended before the FIRMWARE_TRACK task got its turn; leaving it IN_PROGRESS", "task_id", cmd.TaskID)
			return nil
		}
		return send(outcomeResult(track.Held(*payload, track.ReasonHeldFirmwareBusy)))
	}
	defer release()
	if firmwareExpired(cmd) {
		return send(outcomeResult(track.Held(*payload, track.ReasonHeldFirmwareBusy)))
	}

	outcome := engine.Execute(ctx, track.Input{
		TaskID:   cmd.TaskID,
		Payload:  *payload,
		Started:  started,
		Expires:  expires,
		TestMode: ws.IsTestMode(),
		Save:     saveJob,
		Persist:  persistJob,
		Progress: func(message string) {
			if err := firmwareTrackInProgress(ws, cmd.TaskID, message); err != nil {
				log.Warnw("Failed to send IN_PROGRESS", "error", err)
			}
		},
	})
	if outcome.Aborted {
		// The context ended, or the update completed and cannot be recorded yet: the
		// row stays IN_PROGRESS and the reconciler decides it.
		return nil
	}
	return send(outcomeResult(outcome))
}

// outcomeResult turns the engine's outcome into the task's answer.
func outcomeResult(out *track.Outcome) TaskResult {
	if out.Result != nil {
		return TaskResult{Success: true, Message: out.Message}
	}
	result := NewFailureResult(out.Failure)
	if detail := out.Detail.Map(); detail != nil {
		result.Data = map[string]interface{}{track.FailureKey: detail}
	}
	return result
}
