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

	log.Debugw("Connecting to Pathfinder",
		"session_id", sessionID,
		"pathfinder_host", ws.GetPathfinderHost(),
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
	err := connectToPathfinder(ctx, ws, sessionID)
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
func connectToPathfinder(ctx context.Context, ws *network.WebSocketClient, sessionID string) error {
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
		WebadminUser:       ws.GetWebadminUser(),
		WebadminSessionDir: ws.GetWebadminSessionDir(),
		WebadminPort:       ws.GetWebadminPort(),
	})

	// Disconnect when all streams close
	streamMgr.OnAllStreamsClosed(func() {
		log.Debugw("All streams closed, ending Pathfinder session")
		cancel()
	})

	// Add default OPNsense services
	for _, svc := range pathfinder.DefaultOPNsenseServices(ws.GetWebadminPort()) {
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
