package tasks

import (
	"context"
	"os/exec"
	"syscall"
	"time"

	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/network"
)

// restartHelperScript runs in a detached subprocess so it survives the
// current agent's graceful shutdown. The sleep gives the running daemon(8)
// supervisor time to exit cleanly (releasing the pidfile) before rc.d's
// stop/start pair runs. `service ndagent restart` then brings up a fresh
// rc.d-supervised agent with a real pidfile, so `service ndagent status`
// stays accurate.
const restartHelperScript = "sleep 2 && exec service ndagent restart"

// HandleShutdown handles the SHUTDOWN task.
// Executes: shutdown -p now
// Blocked in test mode for safety.
func HandleShutdown(ctx context.Context, ws *network.WebSocketClient, cmd network.Command) error {
	log := logging.Named("SHUTDOWN")

	log.Infow("Received SHUTDOWN command",
		"task_id", cmd.TaskID,
	)

	isTestMode := ws.IsTestMode()
	if isTestMode {
		log.Warn("Test mode detected - SHUTDOWN command will be blocked")
	}

	// Send IN_PROGRESS response before executing
	if err := SendInProgressResponse(ws, cmd.TaskID, "Initiating system shutdown..."); err != nil {
		log.Errorw("Failed to send IN_PROGRESS response",
			"error", err,
		)
	}

	// Small delay to ensure response is sent
	time.Sleep(1 * time.Second)

	// Block in test mode
	if isTestMode {
		log.Warn("Test environment detected - SHUTDOWN command blocked for safety")
		result := NewFailureResult("SHUTDOWN blocked in test environment for safety")
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	// Execute shutdown command
	log.Info("Executing system shutdown command")
	cmdExec := exec.Command("shutdown", "-p", "now")
	if err := cmdExec.Start(); err != nil {
		log.Errorw("Failed to execute shutdown command",
			"error", err,
		)
		result := NewFailureResult("Error executing shutdown: " + err.Error())
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	// We don't wait for the process to complete since it will shut down the system
	log.Info("System shutdown command executed")
	return nil
}

// HandleReboot handles the REBOOT task.
// Executes: shutdown -r now
// Blocked in test mode for safety.
func HandleReboot(ctx context.Context, ws *network.WebSocketClient, cmd network.Command) error {
	log := logging.Named("REBOOT")

	log.Infow("Received REBOOT command",
		"task_id", cmd.TaskID,
	)

	isTestMode := ws.IsTestMode()
	if isTestMode {
		log.Warn("Test mode detected - REBOOT command will be blocked")
	}

	// Send IN_PROGRESS response before executing
	if err := SendInProgressResponse(ws, cmd.TaskID, "Initiating system reboot..."); err != nil {
		log.Errorw("Failed to send IN_PROGRESS response",
			"error", err,
		)
	}

	// Small delay to ensure response is sent
	time.Sleep(1 * time.Second)

	// Block in test mode
	if isTestMode {
		log.Warn("Test environment detected - REBOOT command blocked for safety")
		result := NewFailureResult("REBOOT blocked in test environment for safety")
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	// Execute reboot command
	log.Info("Executing system reboot command")
	cmdExec := exec.Command("shutdown", "-r", "now")
	if err := cmdExec.Start(); err != nil {
		log.Errorw("Failed to execute reboot command",
			"error", err,
		)
		result := NewFailureResult("Error executing reboot: " + err.Error())
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	// We don't wait for the process to complete since it will reboot the system
	log.Info("System reboot command executed")
	return nil
}

// HandleRestart handles the RESTART task by delegating to rc.d.
//
// A detached `sh -c "sleep 2 && exec service ndagent restart"` is launched
// as a session leader so it survives our exit, then graceful shutdown is
// triggered. After the current daemon(8) supervisor reaps us and exits,
// rc.d's restart spawns a fresh daemon-wrapped agent — same pidfile, same
// supervision as the original boot.
//
// On platforms without `service` (developer macOS), the spawn still
// succeeds but rc.d won't be there; the resulting state mirrors the
// developer running ./run by hand and is not a supported production path.
func HandleRestart(ctx context.Context, ws *network.WebSocketClient, cmd network.Command) error {
	log := logging.Named("RESTART")

	log.Infow("Received RESTART command",
		"task_id", cmd.TaskID,
	)

	if ws.IsTestMode() {
		log.Info("Running RESTART command in test mode - will use graceful shutdown mechanism")
	}

	// Send IN_PROGRESS response before executing
	if err := SendInProgressResponse(ws, cmd.TaskID, "Initiating agent restart..."); err != nil {
		log.Errorw("Failed to send IN_PROGRESS response",
			"error", err,
		)
	}

	helper := exec.Command("/bin/sh", "-c", restartHelperScript)
	helper.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	helper.Stdin = nil
	helper.Stdout = nil
	helper.Stderr = nil

	if err := helper.Start(); err != nil {
		log.Errorw("Failed to spawn restart helper",
			"error", err,
		)
		result := NewFailureResult("Failed to spawn restart helper: " + err.Error())
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	// Detach: we never Wait on the helper. It's a session leader and will
	// outlive us; reaping is irrelevant once we exit.
	log.Infow("Spawned restart helper",
		"pid", helper.Process.Pid,
	)

	// Send terminal SUCCESS now so the task gets a definitive status. After
	// this point the helper takes over, and our final shutdown will lose the
	// websocket — no further responses possible.
	result := NewSuccessResult("Agent restart scheduled via rc.d")
	if err := SendTaskResponse(ws, cmd.TaskID, result); err != nil {
		log.Warnw("Failed to send SUCCESS response", "error", err)
	}

	// Give the response a beat to flush before tearing down the connection.
	time.Sleep(500 * time.Millisecond)

	log.Info("Triggering graceful shutdown; rc.d will respawn us in ~2s")
	ws.RequestShutdown()

	return nil
}
