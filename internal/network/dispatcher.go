package network

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/signing"
	"github.com/netdefense-io/ndagent/internal/state"
)

// Task type constants
const (
	TaskTypePing     = "PING"
	TaskTypeShutdown = "SHUTDOWN"
	TaskTypeReboot   = "REBOOT"
	TaskTypeRestart  = "RESTART"
	TaskTypePull     = "PULL"
	TaskTypeSync     = "SYNC"
	TaskTypeBackup   = "BACKUP"
	TaskTypeConnect  = "CONNECT"
)

// TaskHandler is a function that handles a specific task type.
// It receives the WebSocket client, command, and context.
// It should send appropriate responses via the WebSocket.
type TaskHandler func(ctx context.Context, ws *WebSocketClient, cmd Command) error

// CommandDispatcher handles command dispatching to task handlers.
type CommandDispatcher struct {
	handlers    map[string]TaskHandler
	activeTasks sync.Map // map[string]context.CancelFunc
	mu          sync.Mutex
	taskCount   int

	// State store for replay barrier (PAYLOAD-SIGNATURES-DESIGN.md §13).
	state *state.Store
	// Static NDM pubkey table (primary + emergency) — populated from
	// the agent's conf at startup.
	ndmKeys map[string]ed25519.PublicKey // hex(kid) -> pubkey
	// The agent's own UUID, bound into envelope verification.
	deviceUUID string
}

// NewCommandDispatcher creates a new command dispatcher.
//
// `ndmKeys` maps lowercase-hex kid → pubkey for the NDManager primary
// and emergency keys (loaded from the agent conf). `stateStore`
// persists the `last_executed_task_id` replay barrier across restarts.
func NewCommandDispatcher(stateStore *state.Store, ndmKeys map[string]ed25519.PublicKey, deviceUUID string) *CommandDispatcher {
	d := &CommandDispatcher{
		handlers:   make(map[string]TaskHandler),
		state:      stateStore,
		ndmKeys:    ndmKeys,
		deviceUUID: deviceUUID,
	}

	// Note: Task handlers are registered by tasks.RegisterHandlers()

	return d
}

// RegisterHandler registers a handler for a specific task type.
func (d *CommandDispatcher) RegisterHandler(taskType string, handler TaskHandler) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.handlers[taskType] = handler
}

// ReceiveCommands reads and dispatches commands from the WebSocket.
//
// Each frame goes through envelope verification (v=2 amendments per
// PAYLOAD-SIGNATURES-FINDINGS-FIXES.md §3 Findings 1, 4, 7) before
// reaching the handler:
//  1. Decode the outer frame (envelope must be present — closed beta has
//     no fallthrough for unsigned dispatches).
//  2. Verify the COSE_Sign1 envelope against the agent's DISPATCH key set
//     ONLY (primary). Emergency is loaded into a separate map for rotation
//     directives and is never consulted here.
//  3. Validate header bindings: v=2, iss=ndmanager, device_uuid matches
//     own UUID, signed exp not yet expired, task_id strictly greater than
//     the persisted last_executed_task_id.
//  4. Persist the new last_executed_task_id BEFORE dispatching the
//     handler so a mid-handler crash + replay is rejected.
//  5. Reconstruct the verified Command using the SIGNED task_type
//     (decoded.Type), never the raw outer frame field. Payload comes
//     from the verified envelope; pathfinder_session for CONNECT lives
//     inside the signed payload (NDManager seals it at task creation).
func (d *CommandDispatcher) ReceiveCommands(ctx context.Context, ws *WebSocketClient) error {
	log := logging.Named("dispatcher")

	for {
		// Check for cancellation
		select {
		case <-ctx.Done():
			log.Info("Command receiver cancelled")
			return ctx.Err()
		default:
		}

		// Read message
		_, message, err := ws.ReadMessage()
		if err != nil {
			log.Errorw("Error reading WebSocket message",
				"error", err,
			)
			return err
		}

		// Parse outer frame
		var raw rawCommandFrame
		if err := json.Unmarshal(message, &raw); err != nil {
			log.Errorw("Error parsing command JSON", "error", err)
			continue
		}

		outerTaskIDStr := taskIDToString(raw.TaskID)

		if raw.Envelope == "" {
			log.Errorw("Refusing unsigned dispatch — closed beta requires envelope",
				"task_id", outerTaskIDStr,
			)
			continue
		}

		envelopeBytes, err := base64.StdEncoding.DecodeString(raw.Envelope)
		if err != nil {
			log.Errorw("Envelope base64 malformed", "task_id", outerTaskIDStr, "error", err)
			continue
		}

		decoded, err := signing.VerifyDispatchEnvelope(envelopeBytes, d.lookupNDMKey)
		if err != nil {
			log.Errorw("Envelope signature verification failed",
				"task_id", outerTaskIDStr,
				"error", err,
			)
			continue
		}

		// Header binding checks. v=2 amendments:
		// - drop iat ±300s skew (replaced by signed exp; Finding 4)
		// - signed exp must not have passed
		// - signed type must be present (we route from it; Finding 1)
		if decoded.Iss != "ndmanager" {
			log.Errorw("Envelope iss mismatch",
				"task_id", outerTaskIDStr, "iss", decoded.Iss)
			continue
		}
		if decoded.DeviceUUID != d.deviceUUID {
			log.Errorw("Envelope device_uuid mismatch",
				"task_id", outerTaskIDStr, "envelope_device", decoded.DeviceUUID, "agent_device", d.deviceUUID)
			continue
		}
		if outerTaskIDStr != "" {
			outerInt, parseErr := strconv.ParseInt(outerTaskIDStr, 10, 64)
			if parseErr != nil || outerInt != decoded.TaskID {
				log.Errorw("Outer/inner task_id mismatch",
					"outer", outerTaskIDStr, "inner", decoded.TaskID)
				continue
			}
		}
		if decoded.Type == "" {
			log.Errorw("Envelope missing signed task_type", "task_id", decoded.TaskID)
			continue
		}
		if decoded.Exp == 0 {
			log.Errorw("Envelope missing signed exp", "task_id", decoded.TaskID)
			continue
		}
		nowSec := time.Now().Unix()
		if nowSec > decoded.Exp {
			log.Warnw("Envelope expired before dispatch",
				"task_id", decoded.TaskID, "exp", decoded.Exp, "now", nowSec)
			continue
		}

		// Replay barrier (dispatch-side; per-NDM monotonic task_id).
		last := d.state.LastExecutedTaskID()
		if decoded.TaskID <= last {
			log.Warnw("Envelope replay rejected",
				"task_id", decoded.TaskID, "last_executed", last)
			continue
		}
		if err := d.state.SetLastExecutedTaskID(decoded.TaskID); err != nil {
			log.Errorw("Failed to persist last_executed_task_id",
				"task_id", decoded.TaskID, "error", err)
			continue
		}

		// Reconstruct verified Command. TaskType is from the SIGNED
		// envelope, not the unsigned outer frame field (Finding 1).
		// pathfinder_session for CONNECT is now inside the signed
		// payload (Finding 6); we pull it out below if present.
		cmd := Command{
			TaskID:   fmt.Sprintf("%d", decoded.TaskID),
			TaskType: decoded.Type,
		}
		if len(decoded.Payload) > 0 {
			if err := json.Unmarshal(decoded.Payload, &cmd.Payload); err != nil {
				log.Errorw("Verified payload not a JSON object",
					"task_id", cmd.TaskID, "error", err)
				continue
			}
			if pfRaw, ok := cmd.Payload["pathfinder_session"]; ok {
				if pfStr, isStr := pfRaw.(string); isStr {
					cmd.PathfinderSession = pfStr
				}
			}
		}

		log.Infow("Received signed command",
			"task_id", cmd.TaskID,
			"task_type", cmd.TaskType,
			"kid", hex.EncodeToString(decoded.Kid),
		)

		// Dispatch command in a goroutine
		go d.dispatchCommand(ctx, ws, cmd)
	}
}

func (d *CommandDispatcher) lookupNDMKey(kid []byte) (ed25519.PublicKey, error) {
	pub, ok := d.ndmKeys[hex.EncodeToString(kid)]
	if !ok {
		return nil, fmt.Errorf("kid %s not in NDM key table", hex.EncodeToString(kid))
	}
	return pub, nil
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

// dispatchCommand dispatches a command to the appropriate handler.
func (d *CommandDispatcher) dispatchCommand(ctx context.Context, ws *WebSocketClient, cmd Command) {
	log := logging.Named("dispatcher")

	// Create a cancellable context for this task
	taskCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Track the task
	d.activeTasks.Store(cmd.TaskID, cancel)
	d.mu.Lock()
	d.taskCount++
	d.mu.Unlock()

	defer func() {
		d.activeTasks.Delete(cmd.TaskID)
		d.mu.Lock()
		d.taskCount--
		d.mu.Unlock()
	}()

	// Get handler
	d.mu.Lock()
	handler, exists := d.handlers[cmd.TaskType]
	d.mu.Unlock()

	if !exists {
		log.Errorw("Unknown command type",
			"task_type", cmd.TaskType,
			"task_id", cmd.TaskID,
		)
		// Send error response
		if err := ws.SendTaskResponse(cmd.TaskID, TaskStatusFailed, "Unknown command type: "+cmd.TaskType, nil); err != nil {
			log.Errorw("Failed to send error response",
				"error", err,
			)
		}
		return
	}

	// Execute handler
	if err := handler(taskCtx, ws, cmd); err != nil {
		// Check if it was cancelled
		if taskCtx.Err() != nil {
			log.Infow("Task cancelled",
				"task_id", cmd.TaskID,
				"task_type", cmd.TaskType,
			)
			// Try to send cancellation response
			if sendErr := ws.SendTaskResponse(cmd.TaskID, TaskStatusFailed, cmd.TaskType+" task was cancelled", nil); sendErr != nil {
				log.Errorw("Failed to send cancellation response",
					"error", sendErr,
				)
			}
			return
		}

		log.Errorw("Task handler error",
			"task_id", cmd.TaskID,
			"task_type", cmd.TaskType,
			"error", err,
		)
	}
}

// CancelTask cancels a specific task by ID.
func (d *CommandDispatcher) CancelTask(taskID string) bool {
	if cancelFn, ok := d.activeTasks.Load(taskID); ok {
		cancelFn.(context.CancelFunc)()
		return true
	}
	return false
}

// CleanupTasks cancels all active tasks.
func (d *CommandDispatcher) CleanupTasks() {
	log := logging.Named("dispatcher")

	count := 0
	d.activeTasks.Range(func(key, value interface{}) bool {
		cancel := value.(context.CancelFunc)
		cancel()
		count++
		return true
	})

	if count > 0 {
		log.Infow("Cancelled active tasks",
			"count", count,
		)
	}
}

// ActiveTaskCount returns the number of currently active tasks.
func (d *CommandDispatcher) ActiveTaskCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.taskCount
}

// placeholderHandler is a temporary handler that sends a "not implemented" response.
// Used for tasks not yet implemented.
func (d *CommandDispatcher) placeholderHandler(ctx context.Context, ws *WebSocketClient, cmd Command) error {
	log := logging.Named("dispatcher")

	log.Warnw("Task handler not yet implemented",
		"task_type", cmd.TaskType,
		"task_id", cmd.TaskID,
	)

	// Send "not implemented" response
	return ws.SendTaskResponse(
		cmd.TaskID,
		TaskStatusFailed,
		cmd.TaskType+" handler not yet implemented",
		nil,
	)
}

// GetDispatcher returns the command dispatcher.
func (w *WebSocketClient) GetDispatcher() *CommandDispatcher {
	return w.dispatcher
}
