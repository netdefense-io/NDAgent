package pathfinder

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"

	"github.com/netdefense-io/ndagent/internal/logging"
)

// Message types for JSON signaling
const (
	MsgTypeRegister    = "register"
	MsgTypeRegistered  = "registered"
	MsgTypePaired      = "paired"
	MsgTypeError       = "error"
	MsgTypePeerOffline = "peer_offline"
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

// PeerOfflinePayload is received when the paired peer disconnects from the
// relay mid-session (e.g. the CLI/browser client closes its side while the
// agent's own connection stays up). It's an in-band signal distinct from a
// WebSocket close frame — see MsgTypePeerOffline.
type PeerOfflinePayload struct {
	PeerID string `json:"peer_id"`
	Role   string `json:"role"`
}

// Reasons for the session ends the agent detects itself. The relay's own
// close-frame reasons arrive as they are.
const (
	// ReasonClientDisconnected: the paired client left the relay. No client
	// joins a session again once its relay connection has ended (a new
	// connection asks for a new session), so the agent ends its side too.
	ReasonClientDisconnected = "client disconnected"

	// ReasonClientNeverConnected: no client paired within the pairing wait.
	ReasonClientNeverConnected = "client never connected"
)

// ErrSessionEndedCleanly indicates a natural session end, not a transport
// failure: the relay closed the WebSocket with a clean close frame —
// CloseNormalClosure (1000) or CloseGoingAway (1001), NDPathFinder's
// cleaner-driven teardown (session TTL expiry, idle timeout) — the relay
// reported the paired client gone (peer_offline), or no client paired within
// the pairing wait. An abrupt disconnect (1005/1006) or a network error is
// never one.
type ErrSessionEndedCleanly struct {
	// Reason carries the relay's close-frame text, e.g. "TTL expired (client
	// never connected)" or "idle timeout (15m0s)", or one of the Reason*
	// constants above. Callers treat it as informational only and branch on
	// the type, so a future relay reason still classifies as a natural end.
	// May be empty if the relay sent no reason text.
	Reason string
}

func (e *ErrSessionEndedCleanly) Error() string {
	if e.Reason == "" {
		return "pathfinder session ended cleanly"
	}
	return e.Reason
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
				pairChan <- pairingReadEnd(err, deadline)
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

// pairingReadEnd classifies the read error that ended a pairing wait. Its
// own deadline passing means no client came, and a clean close is the relay
// ending the session (its TTL): both are natural ends. The deadline is
// checked as well as the timeout, since a connection the kernel gave up on
// (ETIMEDOUT) reads as a timeout too.
func pairingReadEnd(err error, deadline time.Time) error {
	if clean := cleanCloseOf(err); clean != nil {
		return clean
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() && !time.Now().Before(deadline) {
		return &ErrSessionEndedCleanly{Reason: ReasonClientNeverConnected}
	}
	return fmt.Errorf("read failed while waiting for pairing: %w", err)
}

// cleanCloseOf returns the natural end a clean close frame from the relay
// (1000/1001) stands for, or nil for any other read error.
func cleanCloseOf(err error) *ErrSessionEndedCleanly {
	if !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
		return nil
	}
	reason := ""
	var closeErr *websocket.CloseError
	if errors.As(err, &closeErr) {
		reason = closeErr.Text
	}
	return &ErrSessionEndedCleanly{Reason: reason}
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
				// A clean close (1000/1001) is the relay's cleaner-driven
				// teardown path (session TTL expiry, idle timeout), which
				// always sends a real close frame rather than just
				// dropping the connection — surface it as a typed
				// sentinel so callers can classify it as a natural
				// session end rather than a transport failure. Everything
				// else (1005/1006, network errors, no close frame at all)
				// is a read failure.
				if clean := cleanCloseOf(err); clean != nil {
					errChan <- clean
					return
				}
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
				// Handle JSON messages during relay (errors, peer_offline, etc.)
				var msg Message
				if err := json.Unmarshal(data, &msg); err == nil {
					switch msg.Type {
					case MsgTypeError:
						c.log.Errorw("Received error from Pathfinder", "error", msg.Error)
					case MsgTypePeerOffline:
						// The agent's only peer is the client, so this ends
						// the session whatever the payload says.
						var offline PeerOfflinePayload
						if err := json.Unmarshal(msg.Payload, &offline); err != nil {
							c.log.Warnw("Failed to parse peer_offline payload", "error", err)
						} else {
							c.log.Infow("Peer left the relay session",
								"peer_id", offline.PeerID,
								"role", offline.Role,
							)
						}
						errChan <- &ErrSessionEndedCleanly{Reason: ReasonClientDisconnected}
						return
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
		// WriteControl, unlike WriteMessage, may run while a stream is still
		// in SendFrame: the session ends without waiting for its streams.
		c.conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			time.Now().Add(writeWait))
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
