package tasks

import (
	"context"
	"os"
	"os/exec"
	"time"

	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/network"
)

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

// HandleRestart handles the RESTART task.
// Spawns a new agent process and triggers graceful shutdown of the current process.
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

	// Small delay to ensure response is sent
	time.Sleep(1 * time.Second)

	// Get the executable path
	execPath, err := os.Executable()
	if err != nil {
		log.Errorw("Failed to get executable path",
			"error", err,
		)
		result := NewFailureResult("Failed to get executable path: " + err.Error())
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	// If binary_path is configured, use that instead
	binaryPath := ws.GetBinaryPath()
	if binaryPath != "" {
		execPath = binaryPath
	}

	log.Infow("Starting new agent process",
		"path", execPath,
	)

	// Start new process (it will run independently)
	cmdExec := exec.Command(execPath)
	cmdExec.Stdout = nil
	cmdExec.Stderr = nil
	cmdExec.Stdin = nil

	if err := cmdExec.Start(); err != nil {
		log.Errorw("Failed to start new agent process",
			"error", err,
		)
		result := NewFailureResult("Failed to start new agent process: " + err.Error())
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	log.Infow("Started new agent process",
		"pid", cmdExec.Process.Pid,
	)

	// Trigger graceful shutdown of current process
	log.Info("Triggering graceful shutdown for restart")
	ws.RequestShutdown()

	return nil
}
