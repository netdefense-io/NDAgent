package pathfinder

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"

	"github.com/netdefense-io/ndagent/internal/logging"
)

// Message types for JSON signaling
const (
	MsgTypeRegister   = "register"
	MsgTypeRegistered = "registered"
	MsgTypePaired     = "paired"
	MsgTypeError      = "error"
)

// WebSocket keepalive constants
const (
	pingInterval = 30 * time.Second // Send ping every 30 seconds
	pongWait     = 60 * time.Second // Wait 60 seconds for pong before considering connection dead
	writeWait    = 10 * time.Second // Timeout for write operations including ping
)

// Message represents a JSON signaling message.
type Message struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
	Error   string          `json:"error,omitempty"`
}

// RegisterPayload is sent to register with Pathfinder.
type RegisterPayload struct {
	SessionKey string `json:"session_key"`
	Role       string `json:"role"`
	DeviceID   string `json:"device_id"`
}

// RegisteredPayload is received after successful registration.
type RegisteredPayload struct {
	SessionKey string `json:"session_key"`
	Role       string `json:"role"`
	PeerOnline bool   `json:"peer_online"`
}

// Client manages a WebSocket connection to a Pathfinder server.
type Client struct {
	serverURL  string
	sessionKey string
	deviceID   string
	tlsConfig  *tls.Config

	conn    *websocket.Conn
	mu      sync.Mutex
	writeMu sync.Mutex // Serializes writes to WebSocket (gorilla only supports one concurrent writer)
	closed  bool

	// Callback for incoming binary frames
	frameHandler   func([]byte)
	frameHandlerMu sync.RWMutex

	log *zap.SugaredLogger
}

// NewClient creates a new Pathfinder client.
func NewClient(serverURL, sessionKey, deviceID string, tlsConfig *tls.Config) *Client {
	return &Client{
		serverURL:  serverURL,
		sessionKey: sessionKey,
		deviceID:   deviceID,
		tlsConfig:  tlsConfig,
		log:        logging.Named("pathfinder"),
	}
}

// Connect establishes a WebSocket connection and registers as an agent.
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errors.New("client is closed")
	}
	c.mu.Unlock()

	c.log.Infow("Connecting to Pathfinder",
		"url", c.serverURL,
	)

	dialer := websocket.Dialer{
		TLSClientConfig:  c.tlsConfig,
		HandshakeTimeout: 30 * time.Second,
	}

	conn, resp, err := dialer.DialContext(ctx, c.serverURL, nil)
	if err != nil {
		if resp != nil {
			c.log.Errorw("Pathfinder dial failed",
				"status", resp.StatusCode,
				"error", err,
			)
		}
		return fmt.Errorf("dial failed: %w", err)
	}

	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()

	c.log.Debugw("Connected to Pathfinder, registering as agent")

	// Register as agent
	if err := c.register(); err != nil {
		conn.Close()
		c.mu.Lock()
		c.conn = nil
		c.mu.Unlock()
		return fmt.Errorf("registration failed: %w", err)
	}

	return nil
}

// register sends the registration message and waits for confirmation.
func (c *Client) register() error {
	payload := RegisterPayload{
		SessionKey: c.sessionKey,
		Role:       "agent",
		DeviceID:   c.deviceID,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal register payload: %w", err)
	}

	msg := Message{
		Type:    MsgTypeRegister,
		Payload: payloadBytes,
	}

	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()

	if conn == nil {
		return errors.New("not connected")
	}

	// Set read deadline for registration response
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	// Send registration
	if err := conn.WriteJSON(msg); err != nil {
		return fmt.Errorf("failed to send register message: %w", err)
	}

	c.log.Debugw("Sent register message")

	// Wait for registered response
	_, data, err := conn.ReadMessage()
	if err != nil {
		return fmt.Errorf("failed to read registration response: %w", err)
	}

	var response Message
	if err := json.Unmarshal(data, &response); err != nil {
		return fmt.Errorf("failed to parse registration response: %w", err)
	}

	switch response.Type {
	case MsgTypeRegistered:
		var registered RegisteredPayload
		if err := json.Unmarshal(response.Payload, &registered); err != nil {
			return fmt.Errorf("failed to parse registered payload: %w", err)
		}
		c.log.Infow("Registered with Pathfinder",
			"role", registered.Role,
			"peer_online", registered.PeerOnline,
		)
		return nil

	case MsgTypeError:
		return fmt.Errorf("registration error: %s", response.Error)

	default:
		return fmt.Errorf("unexpected response type: %s", response.Type)
	}
}

// WaitForPairing waits for a client to pair with this agent.
func (c *Client) WaitForPairing(ctx context.Context, timeout time.Duration) error {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()

	if conn == nil {
		return errors.New("not connected")
	}

	c.log.Debugw("Waiting for client to pair", "timeout", timeout)

	// Set deadline for pairing
	deadline := time.Now().Add(timeout)
	conn.SetReadDeadline(deadline)
	defer conn.SetReadDeadline(time.Time{})

	// Create a channel to receive pairing result
	pairChan := make(chan error, 1)

	go func() {
		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				pairChan <- fmt.Errorf("read failed while waiting for pairing: %w", err)
				return
			}

			var msg Message
			if err := json.Unmarshal(data, &msg); err != nil {
				c.log.Warnw("Failed to parse message", "error", err)
				continue
			}

			switch msg.Type {
			case MsgTypePaired:
				c.log.Infow("Client paired successfully")
				pairChan <- nil
				return

			case MsgTypeError:
				pairChan <- fmt.Errorf("pairing error: %s", msg.Error)
				return

			default:
				c.log.Debugw("Received unexpected message while waiting for pairing",
					"type", msg.Type)
			}
		}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-pairChan:
		return err
	}
}

// RunFrameLoop runs the binary frame receive loop.
// This should be called after pairing is complete.
func (c *Client) RunFrameLoop(ctx context.Context) error {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()

	if conn == nil {
		return errors.New("not connected")
	}

	c.log.Debugw("Starting binary frame relay loop")

	// Set pong handler to reset read deadline when pong is received
	conn.SetPongHandler(func(string) error {
		c.log.Debugw("Received pong from Pathfinder")
		conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	// Set initial read deadline
	conn.SetReadDeadline(time.Now().Add(pongWait))

	errChan := make(chan error, 1)

	// Start ping goroutine for keepalive
	go func() {
		ticker := time.NewTicker(pingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.writeMu.Lock()
				err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(writeWait))
				c.writeMu.Unlock()
				if err != nil {
					c.log.Warnw("Failed to send ping", "error", err)
					return
				}
				c.log.Debugw("Sent ping to Pathfinder")
			}
		}
	}()

	go func() {
		for {
			messageType, data, err := conn.ReadMessage()
			if err != nil {
				errChan <- fmt.Errorf("read failed: %w", err)
				return
			}

			// Reset read deadline on any message received
			conn.SetReadDeadline(time.Now().Add(pongWait))

			if messageType == websocket.BinaryMessage {
				c.frameHandlerMu.RLock()
				handler := c.frameHandler
				c.frameHandlerMu.RUnlock()

				if handler != nil {
					handler(data)
				}
			} else if messageType == websocket.TextMessage {
				// Handle JSON messages during relay (errors, etc.)
				var msg Message
				if err := json.Unmarshal(data, &msg); err == nil {
					if msg.Type == MsgTypeError {
						c.log.Errorw("Received error from Pathfinder", "error", msg.Error)
					}
				}
			}
		}
	}()

	select {
	case <-ctx.Done():
		c.log.Debugw("Frame loop cancelled")
		return ctx.Err()
	case err := <-errChan:
		return err
	}
}

// SendFrame sends a binary frame to the peer.
// This method is safe for concurrent use.
func (c *Client) SendFrame(data []byte) error {
	c.mu.Lock()
	conn := c.conn
	closed := c.closed
	c.mu.Unlock()

	if closed || conn == nil {
		return errors.New("not connected")
	}

	// Serialize writes - gorilla websocket only supports one concurrent writer
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	return conn.WriteMessage(websocket.BinaryMessage, data)
}

// OnFrame sets the handler for incoming binary frames.
func (c *Client) OnFrame(handler func([]byte)) {
	c.frameHandlerMu.Lock()
	c.frameHandler = handler
	c.frameHandlerMu.Unlock()
}

// Close closes the Pathfinder connection.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}

	c.closed = true

	if c.conn != nil {
		// Send close message
		c.conn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		err := c.conn.Close()
		c.conn = nil
		return err
	}

	return nil
}

// IsConnected returns true if the client is connected.
func (c *Client) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn != nil && !c.closed
}
