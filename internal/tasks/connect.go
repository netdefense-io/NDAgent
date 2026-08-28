package tasks

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/netdefense-io/ndagent/internal/config"
	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/network"
	"github.com/netdefense-io/ndagent/internal/pathfinder"
)

// Default timeout for waiting for client to pair
const defaultPairingTimeout = 5 * time.Minute

// peerOfflineGraceWindow bounds how soon after a peer_offline signal a
// session end (without a clean close frame) is still treated as a natural
// consequence of the peer having already departed, rather than a genuine
// transport failure. Short enough that it can't paper over an unrelated
// later failure; comfortably inside the ping/pong keepalive window
// (pingInterval 30s / pongWait 60s in internal/pathfinder/client.go).
const peerOfflineGraceWindow = 10 * time.Second

// connectSendResponse is the terminal-response sender used by HandleConnect's
// policy refusal path. Indirected so tests can assert the refusal without a
// live WebSocket, mirroring firmwareNoRebootSendResponse.
var connectSendResponse = SendTaskResponse

// effectiveReadOnly applies the device-local ceiling to the session the
// control plane asked for. The clamp is one-way by construction: a
// "readonly" ceiling forces read-only on, and no policy can turn it off
// once the caller has requested it. "disabled" never reaches here —
// HandleConnect refuses that before the payload is parsed.
func effectiveReadOnly(policy config.RemoteAccessPolicy, requested bool) bool {
	if policy == config.RemoteAccessReadOnly {
		return true
	}
	return requested
}

// pathfinderSessionOutcome is the result of classifying how a CONNECT's
// Pathfinder session ended, plus enough detail for HandleConnect to log
// appropriately at each level without re-deriving the classification.
type pathfinderSessionOutcome struct {
	result TaskResult

	// cancelled is true when the parent context was cancelled (agent
	// shutdown, task cancellation) — unchanged pre-existing behavior.
	cancelled bool

	// naturalEnd is true when the session ended via a relay clean-close
	// sentinel (*pathfinder.ErrSessionEndedCleanly) rather than a genuine
	// transport failure.
	naturalEnd bool

	// cleanCloseReason carries the relay's close-frame reason text when
	// naturalEnd is true, for logging only.
	cleanCloseReason string
}

// classifyPathfinderSessionEnd maps a connectToPathfinder error to the
// terminal task result, per the house rule that a natural session end is a
// SUCCESS, not a FAILED. It is a pure function — no network, no logging — so
// the classification can be unit tested directly against synthetic errors.
//
// ctxErr is the parent context's Err() (nil unless the CONNECT task itself
// was cancelled); err is whatever connectToPathfinder returned.
func classifyPathfinderSessionEnd(ctxErr, err error) pathfinderSessionOutcome {
	// Cancellation takes priority: it's not a Pathfinder-side outcome at
	// all, and connectToPathfinder swallows the frame-loop error in this
	// case (returns nil), so err doesn't carry useful information here.
	if ctxErr != nil {
		return pathfinderSessionOutcome{
			result:    NewSuccessResult("Pathfinder session ended (cancelled)"),
			cancelled: true,
		}
	}

	// A clean close from the relay (session TTL expiry, idle timeout — see
	// NDPathFinder's "Cleaner-driven WebSocket close frames" contract) is a
	// natural session end, not a failure. Branch on the sentinel type
	// (which itself only ever gets constructed from close code 1000/1001),
	// not on the reason text, so a future relay reason doesn't regress to
	// FAILED.
	var cleanClose *pathfinder.ErrSessionEndedCleanly
	if errors.As(err, &cleanClose) {
		return pathfinderSessionOutcome{
			result:           NewSuccessResult(fmt.Sprintf("Pathfinder session ended: %v", cleanClose)),
			naturalEnd:       true,
			cleanCloseReason: cleanClose.Reason,
		}
	}

	return pathfinderSessionOutcome{
		result: NewFailureResult(fmt.Sprintf("Pathfinder session ended: %v", err)),
	}
}

// remoteAccessRefusalMessage builds the operator-facing reason for a
// CONNECT refused by the device-local ceiling. It follows the same shape
// as dangerousSnippetRejectionMessage: name the policy, name the value,
// and state where to change it. A policy rejection is a FAILED task with
// an actionable reason, never a silently-COMPLETED one — the operator
// should see why their session was refused, not a timeout.
//
// The remedy is deliberately stated as a device-side action: this setting
// exists precisely because it cannot be changed from the control plane.
func remoteAccessRefusalMessage(policy config.RemoteAccessPolicy) string {
	return fmt.Sprintf(
		"remote access refused by local policy remote_access_policy=%s; "+
			"change it on the device under Services → NetDefense → Settings "+
			"(Remote Access Policy) — it cannot be changed remotely",
		string(policy),
	)
}

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

	// Device-local remote-access ceiling — the first of two enforcement
	// points (the second is pathfinder's ProxyStreamToLocal chokepoint).
	// Refused here, before the payload is even parsed and before any relay
	// is dialed, so a disabled device never opens an outbound session at
	// all. The command reaching this point is already signature-verified,
	// device-bound, unexpired and sequence-checked by the dispatcher, so
	// this is a policy decision on a legitimate command, not a security
	// check on an untrusted one.
	//
	// Refusing here rather than in the dispatcher is deliberate: every
	// dispatcher refusal path is a bare `continue` that sends no task
	// response, which would surface to the operator as a generic timeout.
	// Here the task_id is real, taskstore.Begin has already opened the row,
	// and SendTaskResponse produces a clean terminal FAILED record carrying
	// the reason. The dispatcher's replay barrier was already advanced and
	// persisted before this handler ran, so a refusal cannot wedge the
	// device's dispatch sequence.
	policy := ws.GetRemoteAccessPolicy()
	if policy == config.RemoteAccessDisabled {
		log.Warnw("Refusing CONNECT — remote access disabled on this device",
			"task_id", cmd.TaskID,
			"policy", string(policy),
		)
		return connectSendResponse(ws, cmd.TaskID, NewFailureResult(remoteAccessRefusalMessage(policy)))
	}

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
	requestedReadOnly := payloadBool(cmd.Payload, "read_only")

	// Apply the device-local ceiling. The control plane's request is a
	// request, not an instruction: under the "readonly" policy the device
	// clamps every session to read-only whatever the payload asked for.
	// Clamping is one-way — the policy can only ever restrict, never widen
	// a session the caller asked to be read-only.
	readOnly := effectiveReadOnly(policy, requestedReadOnly)

	// Resolve the OPNsense username to forge into the PHP session.
	webadminUser := ws.GetWebadminUser()
	if readOnly {
		webadminUser = ws.GetWebadminReadOnlyUser()
	}

	if readOnly != requestedReadOnly {
		log.Infow("Clamped CONNECT session to read-only by local policy",
			"task_id", cmd.TaskID,
			"policy", string(policy),
			"requested_read_only", requestedReadOnly,
		)
	}

	log.Debugw("Connecting to Pathfinder",
		"session_id", sessionID,
		"pathfinder_host", ws.GetPathfinderHost(),
		"policy", string(policy),
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
	err := connectToPathfinder(ctx, ws, sessionID, webadminUser, readOnly, policy)
	if err != nil {
		outcome := classifyPathfinderSessionEnd(ctx.Err(), err)

		switch {
		case outcome.cancelled:
			log.Debugw("Pathfinder session cancelled", "session_id", sessionID)
		case outcome.naturalEnd:
			log.Infow("Pathfinder session ended naturally",
				"session_id", sessionID,
				"reason", outcome.cleanCloseReason,
			)
		default:
			log.Errorw("Pathfinder session ended",
				"session_id", sessionID,
				"error", err,
			)
		}

		return SendTaskResponse(ws, cmd.TaskID, outcome.result)
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
//
// policy is the device-local ceiling, passed through to the proxy so its
// per-stream chokepoint can enforce it independently of the caller-side
// decisions made in HandleConnect.
func connectToPathfinder(ctx context.Context, ws *network.WebSocketClient, sessionID, webadminUser string, readOnly bool, policy config.RemoteAccessPolicy) error {
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
		Policy:             policy,
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

	// RunFrameLoop already classifies a clean close (1000/1001) as
	// ErrSessionEndedCleanly. When it instead returns a plain error but the
	// relay told us the peer departed shortly before, treat that as the same
	// natural end — the agent's own read failing right after the peer left
	// is an expected consequence, not an independent transport failure.
	if err != nil {
		var cleanClose *pathfinder.ErrSessionEndedCleanly
		if !errors.As(err, &cleanClose) && client.PeerOfflineRecently(peerOfflineGraceWindow) {
			log.Debugw("Session ended without a clean close, but peer_offline preceded it",
				"session_id", sessionID,
				"underlying_error", err,
			)
			return &pathfinder.ErrSessionEndedCleanly{Reason: "peer disconnected"}
		}
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
