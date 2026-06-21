package tasks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/network"
	"github.com/netdefense-io/ndagent/internal/pathfinder"
)

// Default timeout for waiting for client to pair
const defaultPairingTimeout = 5 * time.Minute

// HandleConnect handles the CONNECT task.
// It establishes a connection to Pathfinder for remote access sessions.
//
// Expected command payload:
//
//	{
//	  "pathfinder_session": "session-uuid-from-server"
//	}
func HandleConnect(ctx context.Context, ws *network.WebSocketClient, cmd network.Command) error {
	log := logging.Named("CONNECT")

	log.Infow("Received CONNECT command",
		"task_id", cmd.TaskID,
	)

	// Validate payload exists
	if cmd.Payload == nil {
		result := NewFailureResult("No payload provided in connect command")
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	// Extract pathfinder_session (required)
	sessionRaw, ok := cmd.Payload["pathfinder_session"]
	if !ok {
		result := NewFailureResult("No 'pathfinder_session' field in payload")
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	sessionID, ok := sessionRaw.(string)
	if !ok || sessionID == "" {
		result := NewFailureResult("Invalid 'pathfinder_session': must be a non-empty string")
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	// Optional read_only flag (default false → admin/root behavior preserved).
	// The flag selects between two LOCALLY configured OPNsense usernames; the
	// broker never supplies an arbitrary username (privilege-escalation guard).
	readOnly := payloadBool(cmd.Payload, "read_only")

	// Resolve the OPNsense username to forge into the PHP session.
	webadminUser := ws.GetWebadminUser()
	if readOnly {
		webadminUser = ws.GetWebadminReadOnlyUser()
	}

	log.Debugw("Connecting to Pathfinder",
		"session_id", sessionID,
		"pathfinder_host", ws.GetPathfinderHost(),
		"read_only", readOnly,
		"webadmin_user", webadminUser,
	)

	// Check for context cancellation before connection attempt
	select {
	case <-ctx.Done():
		result := NewFailureResult("CONNECT task was cancelled")
		return SendTaskResponse(ws, cmd.TaskID, result)
	default:
	}

	// Send initial response that we're connecting
	if err := SendInProgressResponse(ws, cmd.TaskID, "Connecting to Pathfinder..."); err != nil {
		log.Warnw("Failed to send in-progress response", "error", err)
	}

	// Connect to Pathfinder
	err := connectToPathfinder(ctx, ws, sessionID, webadminUser, readOnly)
	if err != nil {
		log.Errorw("Pathfinder session ended",
			"session_id", sessionID,
			"error", err,
		)

		// Determine if this was a cancellation or an error
		if ctx.Err() != nil {
			result := NewSuccessResult("Pathfinder session ended (cancelled)")
			return SendTaskResponse(ws, cmd.TaskID, result)
		}

		result := NewFailureResult(fmt.Sprintf("Pathfinder session ended: %v", err))
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	log.Infow("Pathfinder session completed successfully",
		"session_id", sessionID,
	)

	result := NewSuccessResult("Pathfinder session completed")
	return SendTaskResponse(ws, cmd.TaskID, result)
}

// connectToPathfinder establishes a connection to the Pathfinder service.
// webadminUser is the OPNsense username forged into the auto-auth PHP session
// (admin user for normal sessions, the read-only user when read_only=true).
// readOnly gates the tunnel to webadmin-only (no shell/ssh/exec) — enforced
// in the proxy regardless of what the client requests.
func connectToPathfinder(ctx context.Context, ws *network.WebSocketClient, sessionID, webadminUser string, readOnly bool) error {
	log := logging.Named("CONNECT")

	// Create cancellable context for clean shutdown when streams close
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Build Pathfinder WebSocket URL
	pathfinderHost := ws.GetPathfinderHost()
	pathfinderURL := buildPathfinderWSURL(pathfinderHost)

	log.Debugw("Connecting to Pathfinder",
		"url", pathfinderURL,
		"session_id", sessionID,
		"device_id", ws.GetDeviceUUID(),
	)

	// Create Pathfinder client
	client := pathfinder.NewClient(
		pathfinderURL,
		sessionID,
		ws.GetDeviceUUID(),
		ws.GetPathfinderTLSConfig(),
	)

	// Connect and register
	if err := client.Connect(ctx); err != nil {
		return fmt.Errorf("connect failed: %w", err)
	}
	defer client.Close()

	log.Debugw("Connected to Pathfinder, waiting for client to pair")

	// Wait for pairing
	if err := client.WaitForPairing(ctx, defaultPairingTimeout); err != nil {
		return fmt.Errorf("pairing failed: %w", err)
	}

	log.Debugw("Client paired, setting up stream proxy")

	// Create stream manager and proxy
	streamMgr := pathfinder.NewStreamManager(client)
	proxy := pathfinder.NewTCPProxyWithConfig(pathfinder.ProxyConfig{
		Shell:              ws.GetPathfinderShell(),
		WebadminUser:       webadminUser,
		WebadminSessionDir: ws.GetWebadminSessionDir(),
		WebadminPort:       ws.GetWebadminPort(),
		ReadOnly:           readOnly,
	})
	// Provide the connect-session context to the proxy so exec streams can
	// use it for command timeouts and cancellation.
	proxy.SetContext(ctx)

	// Session lifetime is tied to the PathFinder relay connection, NOT to the
	// open-stream count. We deliberately do NOT cancel when streams drop to
	// zero: webadmin rides one short-lived stream per HTTP request (the
	// browser/CLI opens and closes a stream per request), so the count
	// legitimately returns to zero between requests and after a terminal
	// stream closes. Tearing down on all-streams-closed would kill the
	// webadmin tunnel mid-session (and made read-only/terminal-less sessions
	// unusable). The session instead ends naturally when client.RunFrameLoop
	// returns — i.e. the relay/WS disconnects (bounded by the ping/pong
	// keepalive: pingInterval 30s / pongWait 60s in internal/pathfinder/
	// client.go) or the parent context is cancelled (broker PathFinder
	// session TTL / agent shutdown). CloseAll() + proxy.CloseAll() below
	// still run on return, destroying the forged PHP session, so abandoned
	// clients are reclaimed within the pong-wait window.

	// Register the proxied services. Read-only sessions get webadmin only —
	// the ssh service is not even advertised. The proxy's ProxyStreamToLocal
	// chokepoint is the authoritative guard; this keeps the offered set
	// honest as defense-in-depth.
	services := pathfinder.DefaultOPNsenseServices(ws.GetWebadminPort())
	if readOnly {
		services = pathfinder.ReadOnlyOPNsenseServices(ws.GetWebadminPort())
	}
	for _, svc := range services {
		proxy.AddService(svc)
	}

	// Handle incoming streams
	streamMgr.OnNewStream(func(stream *pathfinder.Stream) {
		log.Debugw("New stream opened",
			"stream_id", stream.ID(),
			"service", stream.ServiceName(),
		)

		if err := proxy.ProxyStreamToLocal(stream); err != nil {
			log.Errorw("Failed to proxy stream",
				"stream_id", stream.ID(),
				"service", stream.ServiceName(),
				"error", err,
			)
			stream.Close()
		}
	})

	log.Debugw("Pathfinder session active, proxying streams")

	// Run the frame loop until context is cancelled or connection ends
	err := client.RunFrameLoop(ctx)

	// Clean up any remaining streams and shell sessions
	streamMgr.CloseAll()
	proxy.CloseAll()

	if ctx.Err() != nil {
		log.Debugw("Pathfinder session cancelled")
		return nil
	}

	return err
}

// payloadBool extracts a boolean field from a command payload, tolerating the
// shapes a JSON decoder can produce (bool, float64 number, string). Missing or
// unrecognized values yield false — the safe default for read_only (admin
// behavior is the legacy default; only an explicit true downgrades the
// session).
func payloadBool(payload map[string]interface{}, key string) bool {
	raw, ok := payload[key]
	if !ok {
		return false
	}
	switch v := raw.(type) {
	case bool:
		return v
	case float64:
		return v != 0
	case string:
		return v == "true" || v == "1"
	default:
		return false
	}
}

// buildPathfinderWSURL constructs the WebSocket URL from the Pathfinder host.
func buildPathfinderWSURL(host string) string {
	// Remove trailing slash if present
	host = strings.TrimSuffix(host, "/")

	// Convert https:// to wss://
	if strings.HasPrefix(host, "https://") {
		host = "wss://" + strings.TrimPrefix(host, "https://")
	} else if strings.HasPrefix(host, "http://") {
		host = "ws://" + strings.TrimPrefix(host, "http://")
	} else if !strings.HasPrefix(host, "wss://") && !strings.HasPrefix(host, "ws://") {
		// Assume wss:// for bare hostnames
		host = "wss://" + host
	}

	// Append /ws path if not present
	if !strings.HasSuffix(host, "/ws") {
		host = host + "/ws"
	}

	return host
}
