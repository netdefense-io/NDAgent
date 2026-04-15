package tasks

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"

	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/network"
	"github.com/netdefense-io/ndagent/internal/security"
)

// HandlePing handles the PING task.
// Expected command payload:
//
//	{
//	  "target": "8.8.8.8",
//	  "count": 4   // Optional; defaults to 4 if not provided.
//	}
func HandlePing(ctx context.Context, ws *network.WebSocketClient, cmd network.Command) error {
	log := logging.Named("PING")

	log.Infow("Received PING command",
		"task_id", cmd.TaskID,
		"payload", cmd.Payload,
	)

	// Validate payload exists
	if cmd.Payload == nil {
		result := NewFailureResult("No payload provided in ping command")
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	// Extract target
	targetRaw, ok := cmd.Payload["target"]
	if !ok {
		result := NewFailureResult("No target specified for ping")
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	target, ok := targetRaw.(string)
	if !ok {
		result := NewFailureResult("Invalid target format: must be a string")
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	// Validate target using security validation
	if err := security.ValidatePingTarget(target); err != nil {
		log.Warnw("Invalid ping target",
			"target", target,
			"error", err,
		)
		result := NewFailureResult(fmt.Sprintf("Invalid target: %v", err))
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	// Extract count (default to 4)
	count := 4
	if countRaw, ok := cmd.Payload["count"]; ok {
		switch v := countRaw.(type) {
		case float64:
			count = int(v)
		case int:
			count = v
		case string:
			if parsed, err := strconv.Atoi(v); err == nil {
				count = parsed
			}
		}
	}

	// Limit count to reasonable range
	if count < 1 {
		count = 1
	} else if count > 100 {
		count = 100
	}

	log.Infow("Executing ping",
		"target", target,
		"count", count,
	)

	// Execute ping command
	cmdExec := exec.CommandContext(ctx, "ping", "-c", strconv.Itoa(count), target)
	output, err := cmdExec.CombinedOutput()

	// Check for context cancellation
	if ctx.Err() != nil {
		log.Info("PING task cancelled")
		result := NewFailureResult("PING task was cancelled during execution")
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	if err != nil {
		// Ping failed (non-zero exit code or execution error)
		log.Warnw("Ping command failed",
			"target", target,
			"error", err,
			"output", string(output),
		)
		result := NewFailureResult(string(output))
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	// Success
	log.Infow("Ping command completed",
		"target", target,
	)
	result := NewSuccessResult(string(output))
	return SendTaskResponse(ws, cmd.TaskID, result)
}
