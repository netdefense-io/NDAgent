// Package network provides networking functionality for NDAgent.
package network

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/netdefense-io/ndagent/internal/config"
	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/opnapi"
	"github.com/netdefense-io/ndagent/internal/util"
	"github.com/netdefense-io/ndagent/pkg/version"
)

// WebSocket message types
const (
	MsgTypeAuthentication = "authentication"
	MsgTypeHeartbeat      = "heartbeat"
	MsgTypeTaskResponse   = "task_response"
)

// Authentication message sent on connection
type AuthMessage struct {
	Type       string `json:"type"`
	TokenUUID  string `json:"token_uuid"`
	DeviceUUID string `json:"device_uuid"`
	Version    string `json:"version"`
}

// AuthResponse from server
type AuthResponse struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// Command received from server
type Command struct {
	TaskID   string                 `json:"task_id"`
	TaskType string                 `json:"task_type"`
	Payload  map[string]interface{} `json:"payload"`
}

// UnmarshalJSON handles flexible JSON parsing for Command.
// - task_id can be string or number
// - payload can be object or JSON string
func (c *Command) UnmarshalJSON(data []byte) error {
	// Use a temporary struct with flexible types
	type rawCommand struct {
		TaskID   interface{} `json:"task_id"`
		TaskType string      `json:"task_type"`
		Payload  interface{} `json:"payload"`
	}

	var raw rawCommand
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	// Handle task_id as string or number
	switch v := raw.TaskID.(type) {
	case string:
		c.TaskID = v
	case float64:
		c.TaskID = fmt.Sprintf("%.0f", v)
	case nil:
		c.TaskID = ""
	default:
		c.TaskID = fmt.Sprintf("%v", v)
	}

	c.TaskType = raw.TaskType

	// Handle payload as object or JSON string
	switch v := raw.Payload.(type) {
	case map[string]interface{}:
		c.Payload = v
	case string:
		// Payload is a JSON string, parse it
		if v != "" {
			if err := json.Unmarshal([]byte(v), &c.Payload); err != nil {
				return fmt.Errorf("failed to parse payload string: %w", err)
			}
		}
	case nil:
		c.Payload = nil
	default:
		return fmt.Errorf("unexpected payload type: %T", v)
	}

	return nil
}

// TaskResponse sent back to server.
// Extra fields from Data map are flattened to top level (matching Python behavior).
type TaskResponse struct {
	Type             string                 `json:"type"`
	TaskID           string                 `json:"task_id"`
	Status           string                 `json:"status"`
	Message          string                 `json:"message,omitempty"`
	Content          string                 `json:"content,omitempty"`           // For PULL responses
	Results          interface{}            `json:"results,omitempty"`           // For SYNC responses
	ValidationErrors interface{}            `json:"validation_errors,omitempty"` // For SYNC errors
	Data             map[string]interface{} `json:"-"`                           // Internal use, not serialized
}

// Task status constants
const (
	TaskStatusCompleted  = "COMPLETED"
	TaskStatusFailed     = "FAILED"
	TaskStatusInProgress = "IN_PROGRESS"
)

// ShutdownRequestFunc is a callback to request agent shutdown (for RESTART task).
type ShutdownRequestFunc func()

// WebSocketClient manages the WebSocket connection to the server.
type WebSocketClient struct {
	cfg  *config.Config
	conn *websocket.Conn
	mu   sync.Mutex

	// Heartbeat manager
	heartbeat *HeartbeatManager

	// Command dispatcher
	dispatcher *CommandDispatcher

	// Shutdown callback for RESTART task
	shutdownCallback ShutdownRequestFunc

	// OPNsense API client for SYNC_API (nil if not configured)
	apiClient *opnapi.Client
}

// NewWebSocketClient creates a new WebSocket client.
func NewWebSocketClient(cfg *config.Config) *WebSocketClient {
	return &WebSocketClient{
		cfg:        cfg,
		heartbeat:  NewHeartbeatManager(cfg.DeviceUUID, 60*time.Second),
		dispatcher: NewCommandDispatcher(),
	}
}

// Run connects to the WebSocket server and maintains the connection.
// It handles authentication, heartbeats, and command processing.
// Returns when context is cancelled or an unrecoverable error occurs.
func (w *WebSocketClient) Run(ctx context.Context) error {
	log := logging.Named("websocket")

	// Initialize delay tracking for reconnection
	var totalDelay float64
	const maxTotalDelay = 60.0 // Cap at around 1 minute

	for {
		// Check for shutdown at start of each iteration
		select {
		case <-ctx.Done():
			log.Info("WebSocket client shutdown requested")
			return ctx.Err()
		default:
		}

		// Attempt connection
		err := w.connect(ctx)
		if err != nil {
			// Check if it's a shutdown
			if ctx.Err() != nil {
				log.Info("WebSocket connection cancelled during connect")
				return ctx.Err()
			}

			log.Errorw("WebSocket connection failed",
				"error", err,
			)
		} else {
			// Connection was successful but ended
			// Reset delay on successful connection
			totalDelay = 0
		}

		// Calculate a random delay for reconnection (matching Python behavior)
		if totalDelay > maxTotalDelay {
			// If we're over the max, subtract a random amount
			subtractDelay := 10.0 + rand.Float64()*5.0 // 10-15 seconds
			totalDelay -= subtractDelay
		}

		// Add a new random delay
		newDelay := 5.0 + rand.Float64()*10.0 // 5-15 seconds
		totalDelay += newDelay

		actualDelay := time.Duration(totalDelay * float64(time.Second))
		log.Infow("WebSocket reconnecting",
			"delay_seconds", totalDelay,
		)

		if err := util.ShutdownAwareSleep(ctx, actualDelay); err != nil {
			log.Info("WebSocket reconnection cancelled during sleep")
			return err
		}
	}
}

// connect establishes a WebSocket connection and runs the communication loop.
func (w *WebSocketClient) connect(ctx context.Context) error {
	log := logging.Named("websocket")

	// Configure TLS
	tlsConfig := w.cfg.GetTLSConfig()
	dialer := websocket.Dialer{
		TLSClientConfig:  tlsConfig,
		HandshakeTimeout: 30 * time.Second,
	}

	log.Infow("Connecting to WebSocket server",
		"uri", w.cfg.ServerURIWS,
	)

	// Connect to WebSocket server
	conn, resp, err := dialer.DialContext(ctx, w.cfg.ServerURIWS, nil)
	if err != nil {
		if resp != nil {
			log.Errorw("WebSocket dial failed",
				"status", resp.StatusCode,
				"error", err,
			)
		}
		return fmt.Errorf("websocket dial failed: %w", err)
	}
	defer func() {
		// Send clean close frame if context was cancelled (graceful shutdown)
		if ctx.Err() != nil {
			w.CloseClean()
		} else {
			conn.Close()
		}
		w.mu.Lock()
		w.conn = nil
		w.mu.Unlock()
	}()

	w.mu.Lock()
	w.conn = conn
	w.mu.Unlock()

	log.Infow("Connected to WebSocket server",
		"device_uuid", w.cfg.DeviceUUID,
	)

	// Authenticate
	if err := w.authenticate(ctx); err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	log.Infow("Device authenticated successfully",
		"device_uuid", w.cfg.DeviceUUID,
	)

	// Run communication loop
	return w.runCommunicationLoop(ctx)
}

// authenticate sends authentication message and waits for response.
func (w *WebSocketClient) authenticate(ctx context.Context) error {
	log := logging.Named("websocket")

	authMsg := AuthMessage{
		Type:       MsgTypeAuthentication,
		TokenUUID:  w.cfg.Token,
		DeviceUUID: w.cfg.DeviceUUID,
		Version:    version.Version,
	}

	log.Infow("Sending authentication message",
		"device_uuid", w.cfg.DeviceUUID,
		"version", version.Version,
	)

	if err := w.SendJSON(authMsg); err != nil {
		return fmt.Errorf("failed to send auth message: %w", err)
	}

	// Wait for response with timeout
	w.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	defer w.conn.SetReadDeadline(time.Time{}) // Clear deadline

	_, message, err := w.conn.ReadMessage()
	if err != nil {
		return fmt.Errorf("failed to read auth response: %w", err)
	}

	var authResp AuthResponse
	if err := json.Unmarshal(message, &authResp); err != nil {
		return fmt.Errorf("failed to parse auth response: %w", err)
	}

	if authResp.Status != "authenticated" {
		return fmt.Errorf("authentication rejected: %s", authResp.Error)
	}

	return nil
}

// runCommunicationLoop runs heartbeat and command processing concurrently.
func (w *WebSocketClient) runCommunicationLoop(ctx context.Context) error {
	log := logging.Named("websocket")

	// Create a context that we can cancel when any goroutine fails
	loopCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Channel to collect errors from goroutines
	errChan := make(chan error, 3)

	// Start heartbeat goroutine
	go func() {
		err := w.heartbeat.Run(loopCtx, w)
		if err != nil && loopCtx.Err() == nil {
			log.Errorw("Heartbeat ended",
				"error", err,
			)
		}
		errChan <- err
	}()

	// Start command receiver goroutine
	go func() {
		err := w.dispatcher.ReceiveCommands(loopCtx, w)
		if err != nil && loopCtx.Err() == nil {
			log.Errorw("Command receiver ended",
				"error", err,
			)
		}
		errChan <- err
	}()

	// Start task health monitor goroutine
	go func() {
		err := w.runHealthMonitor(loopCtx)
		errChan <- err
	}()

	// Wait for any goroutine to complete or context to be cancelled
	select {
	case <-loopCtx.Done():
		log.Info("Communication loop context cancelled")
		// Wait for goroutines to finish cleanup
		w.dispatcher.CleanupTasks()
		return loopCtx.Err()

	case err := <-errChan:
		// One of the goroutines ended
		log.Warnw("Communication loop ended",
			"error", err,
		)
		cancel() // Cancel other goroutines
		w.dispatcher.CleanupTasks()
		return err
	}
}

// runHealthMonitor logs task health status periodically.
func (w *WebSocketClient) runHealthMonitor(ctx context.Context) error {
	log := logging.Named("websocket")
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			log.Infow("Task health check",
				"heartbeats_sent", w.heartbeat.Count(),
				"active_tasks", w.dispatcher.ActiveTaskCount(),
			)
		}
	}
}

// SendJSON sends a JSON message over the WebSocket connection.
func (w *WebSocketClient) SendJSON(v interface{}) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.conn == nil {
		return fmt.Errorf("websocket not connected")
	}

	return w.conn.WriteJSON(v)
}

// ReadMessage reads a message from the WebSocket connection.
func (w *WebSocketClient) ReadMessage() (messageType int, p []byte, err error) {
	w.mu.Lock()
	conn := w.conn
	w.mu.Unlock()

	if conn == nil {
		return 0, nil, fmt.Errorf("websocket not connected")
	}

	return conn.ReadMessage()
}

// SendTaskResponse sends a task response to the server.
func (w *WebSocketClient) SendTaskResponse(taskID, status, message string, data map[string]interface{}) error {
	log := logging.Named("websocket")

	resp := TaskResponse{
		Type:    MsgTypeTaskResponse,
		TaskID:  taskID,
		Status:  status,
		Message: message,
	}

	// Flatten data fields to top level (matching Python behavior)
	if data != nil {
		// Handle content - can be string or map (for PULL responses)
		if content, ok := data["content"].(string); ok {
			resp.Content = content
		} else if contentMap, ok := data["content"].(map[string]interface{}); ok {
			// Serialize map content to JSON string
			contentBytes, err := json.Marshal(contentMap)
			if err != nil {
				log.Errorw("Failed to serialize content map", "error", err)
			} else {
				resp.Content = string(contentBytes)
			}
		}
		if results, ok := data["results"]; ok {
			resp.Results = results
		}
		if validationErrors, ok := data["validation_errors"]; ok {
			resp.ValidationErrors = validationErrors
		}
	}

	log.Debugw("Sending task response",
		"task_id", taskID,
		"status", status,
		"message", message,
		"has_content", resp.Content != "",
		"has_results", resp.Results != nil,
	)

	return w.SendJSON(resp)
}

// GetTLSConfig returns the TLS configuration for the WebSocket connection.
func (w *WebSocketClient) GetTLSConfig() *tls.Config {
	return w.cfg.GetTLSConfig()
}

// IsConnected returns true if the WebSocket is connected.
func (w *WebSocketClient) IsConnected() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.conn != nil
}

// IsTestMode returns true if the agent is running in test mode.
func (w *WebSocketClient) IsTestMode() bool {
	return w.cfg.IsTestMode()
}

// GetBinaryPath returns the path to the agent binary.
func (w *WebSocketClient) GetBinaryPath() string {
	return w.cfg.BinaryPath
}

// GetConfigXMLPath returns the path to the OPNsense config.xml file.
func (w *WebSocketClient) GetConfigXMLPath() string {
	return w.cfg.ConfigXMLPath
}

// SetShutdownCallback sets the callback for requesting agent shutdown (used by RESTART task).
func (w *WebSocketClient) SetShutdownCallback(fn ShutdownRequestFunc) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.shutdownCallback = fn
}

// RequestShutdown triggers the shutdown callback if set.
func (w *WebSocketClient) RequestShutdown() {
	w.mu.Lock()
	callback := w.shutdownCallback
	w.mu.Unlock()

	if callback != nil {
		callback()
	}
}

// SetAPIClient sets the OPNsense API client for SYNC_API operations.
func (w *WebSocketClient) SetAPIClient(client *opnapi.Client) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.apiClient = client
}

// GetAPIClient returns the OPNsense API client (may be nil if not configured).
func (w *WebSocketClient) GetAPIClient() *opnapi.Client {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.apiClient
}

// GetPathfinderHost returns the Pathfinder server URL.
func (w *WebSocketClient) GetPathfinderHost() string {
	return w.cfg.PathfinderHost
}

// GetPathfinderTLSConfig returns the TLS configuration for Pathfinder connections.
func (w *WebSocketClient) GetPathfinderTLSConfig() *tls.Config {
	return w.cfg.GetPathfinderTLSConfig()
}

// GetPathfinderShell returns the shell to use for Pathfinder sessions.
func (w *WebSocketClient) GetPathfinderShell() string {
	return w.cfg.PathfinderShell
}

// GetDeviceUUID returns the device UUID for Pathfinder registration.
func (w *WebSocketClient) GetDeviceUUID() string {
	return w.cfg.DeviceUUID
}

// GetWebadminUser returns the username for webadmin sessions.
func (w *WebSocketClient) GetWebadminUser() string {
	return w.cfg.WebadminUser
}

// GetWebadminSessionDir returns the PHP session directory for webadmin.
func (w *WebSocketClient) GetWebadminSessionDir() string {
	return w.cfg.WebadminSessionDir
}

// GetWebadminPort returns the detected webadmin port.
func (w *WebSocketClient) GetWebadminPort() int {
	return w.cfg.WebadminPort
}

// CloseClean sends a WebSocket close frame before closing the connection.
// This signals to the server that the disconnect was intentional.
func (w *WebSocketClient) CloseClean() {
	w.mu.Lock()
	conn := w.conn
	w.mu.Unlock()

	if conn == nil {
		return
	}

	log := logging.Named("websocket")
	log.Debug("Sending WebSocket close frame")

	// Set write deadline for close frame
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	conn.WriteMessage(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	conn.Close()
}
