package network

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/netdefense-io/ndagent/internal/logging"
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
}

// NewCommandDispatcher creates a new command dispatcher.
func NewCommandDispatcher() *CommandDispatcher {
	d := &CommandDispatcher{
		handlers: make(map[string]TaskHandler),
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

		// Parse command
		var cmd Command
		if err := json.Unmarshal(message, &cmd); err != nil {
			log.Errorw("Error parsing command JSON",
				"error", err,
				"message", string(message),
			)
			continue // Skip invalid messages
		}

		log.Infow("Received command",
			"task_id", cmd.TaskID,
			"task_type", cmd.TaskType,
		)

		// Dispatch command in a goroutine
		go d.dispatchCommand(ctx, ws, cmd)
	}
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
