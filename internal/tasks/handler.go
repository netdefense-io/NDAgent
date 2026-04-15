// Package tasks provides task handlers for NDAgent commands.
package tasks

import (
	"context"

	"github.com/netdefense-io/ndagent/internal/network"
)

// TaskResult represents the result of a task execution.
type TaskResult struct {
	Success bool
	Message string
	Data    map[string]interface{}
}

// NewSuccessResult creates a successful task result.
func NewSuccessResult(message string) TaskResult {
	return TaskResult{
		Success: true,
		Message: message,
	}
}

// NewSuccessResultWithData creates a successful task result with additional data.
func NewSuccessResultWithData(message string, data map[string]interface{}) TaskResult {
	return TaskResult{
		Success: true,
		Message: message,
		Data:    data,
	}
}

// NewFailureResult creates a failed task result.
func NewFailureResult(message string) TaskResult {
	return TaskResult{
		Success: false,
		Message: message,
	}
}

// SendTaskResponse sends a task response to the server.
func SendTaskResponse(ws *network.WebSocketClient, taskID string, result TaskResult) error {
	status := network.TaskStatusCompleted
	if !result.Success {
		status = network.TaskStatusFailed
	}
	return ws.SendTaskResponse(taskID, status, result.Message, result.Data)
}

// SendInProgressResponse sends an IN_PROGRESS status for long-running tasks.
func SendInProgressResponse(ws *network.WebSocketClient, taskID, message string) error {
	return ws.SendTaskResponse(taskID, network.TaskStatusInProgress, message, nil)
}

// Handler is the function signature for task handlers.
type Handler func(ctx context.Context, ws *network.WebSocketClient, cmd network.Command) error
