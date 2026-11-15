package tasks

import (
	"context"
	"math"
	"regexp"
	"sync/atomic"

	"github.com/netdefense-io/ndagent/internal/config"
	"github.com/netdefense-io/ndagent/internal/directpeer"
	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/network"
)

// The transports a CONNECT task can name, and what a direct-peer task asks.
const (
	connectTransportRelay      = "relay-legacy"
	connectTransportDirectPeer = "direct-peer"
	connectActionOpen          = "open"
	connectActionClose         = "close"
)

// directPeerManager carries the device's direct-peer sessions. It is the
// process's one manager: a session outlives the control connection, and the
// handler, that opened it.
var directPeerManager atomic.Pointer[directpeer.Manager]

// SetDirectPeerManager installs the manager the CONNECT handler opens
// direct-peer sessions on.
func SetDirectPeerManager(m *directpeer.Manager) { directPeerManager.Store(m) }

type connectKind int

const (
	// connectRelay is today's task: a session on the websocket relay.
	connectRelay connectKind = iota
	connectOpen
	connectClose
	// connectUnknown names a transport or an action this agent does not
	// know. Nothing is opened for it.
	connectUnknown
)

// connectPayloadKind tells the kinds of CONNECT task apart, on the verified
// payload. No transport, or the websocket relay's, is the websocket relay,
// exactly as before there was a second one. Any other value under the key,
// a null included, fails closed: a task this agent cannot read must not fall
// back to a transport nobody asked for.
func connectPayloadKind(payload map[string]interface{}) connectKind {
	transport, present := payload["transport"]
	if !present {
		return connectRelay
	}
	switch transport {
	case connectTransportRelay:
		return connectRelay
	case connectTransportDirectPeer:
		switch payload["action"] {
		case connectActionOpen:
			return connectOpen
		case connectActionClose:
			return connectClose
		}
	}
	return connectUnknown
}

// payloadConnectID is the payload's session id when it has the form of one.
func payloadConnectID(payload map[string]interface{}) (string, bool) {
	id, _ := payload["connect_id"].(string)
	return id, directpeer.ValidConnectID(id)
}

// payloadWhole reads a whole number from lowest to highest. A JSON number is
// a float here; one with a fraction, and any other type, is not a number.
func payloadWhole(m map[string]interface{}, key string, lowest, highest int) (int, bool) {
	n, ok := m[key].(float64)
	if !ok || n != math.Trunc(n) || n < float64(lowest) || n > float64(highest) {
		return 0, false
	}
	return int(n), true
}

var (
	relayIDPattern   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	relayHostPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
	nodeKeyPattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// directPeerOpen is an open task's payload, read exactly.
type directPeerOpen struct {
	connectID                string
	protocol                 int
	relay                    directpeer.Relay
	sealed                   string
	admitServer, admitClient string
	pair, idle, max, device  int
	readOnly                 bool
}

// parseDirectPeerOpen reads an open payload. Every key the agent uses must
// be there with its type: nothing is defaulted. A read_only that is not a
// boolean in particular is not false, which would be the full session.
func parseDirectPeerOpen(payload map[string]interface{}) (directPeerOpen, bool) {
	var (
		o  directPeerOpen
		ok bool
	)
	if o.connectID, ok = payloadConnectID(payload); !ok {
		return o, false
	}
	if o.protocol, ok = payloadWhole(payload, "protocol", 1, 65535); !ok {
		return o, false
	}

	relay, _ := payload["relay"].(map[string]interface{})
	o.relay.ID, _ = relay["id"].(string)
	o.relay.Host, _ = relay["hostname"].(string)
	if !relayIDPattern.MatchString(o.relay.ID) || len(o.relay.Host) > 253 || !relayHostPattern.MatchString(o.relay.Host) {
		return o, false
	}
	if o.relay.Port, ok = payloadWhole(relay, "derp_port", 1, 65535); !ok {
		return o, false
	}
	if o.relay.STUNPort, ok = payloadWhole(relay, "stun_port", 1, 65535); !ok {
		return o, false
	}

	if o.sealed, _ = payload["sealed"].(string); o.sealed == "" {
		return o, false
	}
	keys, _ := payload["admit_keys"].(map[string]interface{})
	o.admitServer, _ = keys["server"].(string)
	o.admitClient, _ = keys["client"].(string)
	if !nodeKeyPattern.MatchString(o.admitServer) || !nodeKeyPattern.MatchString(o.admitClient) {
		return o, false
	}

	limits, _ := payload["limits"].(map[string]interface{})
	for key, dst := range map[string]*int{
		"pair_seconds": &o.pair, "idle_seconds": &o.idle, "max_seconds": &o.max, "device_sessions": &o.device,
	} {
		if *dst, ok = payloadWhole(limits, key, 1, math.MaxInt32); !ok {
			return o, false
		}
	}

	if o.readOnly, ok = payload["read_only"].(bool); !ok {
		return o, false
	}
	return o, true
}

// sessionIdentity is what the device's configuration says a session runs as.
type sessionIdentity struct {
	shell              string
	webadminUser       string
	webadminReadOnly   string
	webadminSessionDir string
	webadminPort       int
}

// sessionServices is what a direct-peer session serves: read-only when the
// task asks for it or the device's policy allows nothing more, and then as
// the device's own read-only user. The task carries the boolean only; which
// user that is never comes from outside the device.
func sessionServices(policy config.RemoteAccessPolicy, requestedReadOnly bool, id sessionIdentity) streamServiceConfig {
	readOnly := effectiveReadOnly(policy, requestedReadOnly)
	user := id.webadminUser
	if readOnly {
		user = id.webadminReadOnly
	}
	return streamServiceConfig{
		shell:              id.shell,
		webadminUser:       user,
		webadminSessionDir: id.webadminSessionDir,
		webadminPort:       id.webadminPort,
		readOnly:           readOnly,
		policy:             policy,
	}
}

// refuseDirectPeer answers an open task that opens nothing.
func refuseDirectPeer(ws *network.WebSocketClient, taskID, connectID, reason string) {
	if m := directPeerManager.Load(); m != nil {
		m.Refuse(taskID, connectID, reason)
		return
	}
	logging.Named("CONNECT").Warnw("Remote session refused", "task_id", taskID, "connect_id", connectID, "reason", reason)
	if err := ws.ReportConnectResult(taskID, directpeer.FailedResult(connectID, reason)); err != nil {
		logging.Named("CONNECT").Errorw("Cannot answer a refused remote session", "task_id", taskID, "error", err)
	}
}

// handleUnreadableConnect answers a CONNECT whose payload names a transport
// or an action this agent does not know, or is not an open or a close it can
// read. Nothing is opened. With a session id the answer names it, so the
// control plane ends the session's registration; without one it cannot.
func handleUnreadableConnect(ws *network.WebSocketClient, cmd network.Command) error {
	log := logging.Named("CONNECT")
	log.Warnw("Refusing a CONNECT this agent cannot read", "task_id", cmd.TaskID,
		"transport", cmd.Payload["transport"], "action", cmd.Payload["action"])
	if id, ok := payloadConnectID(cmd.Payload); ok {
		refuseDirectPeer(ws, cmd.TaskID, id, directpeer.FailUnsupportedAction)
		return nil
	}
	return connectSendResponse(ws, cmd.TaskID, NewFailureResult("Remote session refused: the request is not one this agent can read"))
}

// handleDirectPeerOpen opens a direct-peer session. It returns once the task
// has its first answer: ready, or refused. A session that started runs on in
// the process's manager and answers the task again when it ends.
func handleDirectPeerOpen(ctx context.Context, ws *network.WebSocketClient, cmd network.Command) error {
	log := logging.Named("CONNECT")

	// The device-local ceiling comes first, as for the websocket relay: a
	// device that allows no remote access says so whatever else is in the
	// request.
	policy := ws.GetRemoteAccessPolicy()
	if id, ok := payloadConnectID(cmd.Payload); ok && policy == config.RemoteAccessDisabled {
		refuseDirectPeer(ws, cmd.TaskID, id, directpeer.FailPolicyDisabled)
		return nil
	}
	open, ok := parseDirectPeerOpen(cmd.Payload)
	if !ok {
		return handleUnreadableConnect(ws, cmd)
	}

	services := sessionServices(policy, open.readOnly, sessionIdentity{
		shell:              ws.GetPathfinderShell(),
		webadminUser:       ws.GetWebadminUser(),
		webadminReadOnly:   ws.GetWebadminReadOnlyUser(),
		webadminSessionDir: ws.GetWebadminSessionDir(),
		webadminPort:       ws.GetWebadminPort(),
	})
	if services.readOnly != open.readOnly {
		log.Infow("Clamped CONNECT session to read-only by local policy",
			"task_id", cmd.TaskID, "policy", string(policy), "requested_read_only", open.readOnly)
	}

	m := directPeerManager.Load()
	if m == nil {
		refuseDirectPeer(ws, cmd.TaskID, open.connectID, directpeer.FailInternal)
		return nil
	}

	// What the session serves was fixed above: it outlives this connection.
	m.Open(ctx, directpeer.OpenRequest{
		TaskID:         cmd.TaskID,
		Exp:            cmd.ExpiresAt,
		ConnectID:      open.connectID,
		Protocol:       open.protocol,
		Relay:          open.relay,
		Sealed:         open.sealed,
		AdmitServer:    open.admitServer,
		AdmitClient:    open.admitClient,
		PairSeconds:    open.pair,
		IdleSeconds:    open.idle,
		MaxSeconds:     open.max,
		DeviceSessions: open.device,
		Unseal:         ws.UnsealConnect,
		Carry: func(sess *directpeer.Session) directpeer.Carrier {
			return newStreamCarrier(sess, services)
		},
	})
	return nil
}

// handleDirectPeerClose is the close instruction: the session with that id
// ends, whatever the device's policy says now.
func handleDirectPeerClose(ws *network.WebSocketClient, cmd network.Command) error {
	id, ok := payloadConnectID(cmd.Payload)
	if !ok {
		return handleUnreadableConnect(ws, cmd)
	}
	if m := directPeerManager.Load(); m != nil {
		m.Close(cmd.TaskID, id, cmd.ExpiresAt)
		return nil
	}
	if err := ws.ReportConnectResult(cmd.TaskID, directpeer.ClosedResult(id, false)); err != nil {
		logging.Named("CONNECT").Errorw("Cannot answer a close instruction", "task_id", cmd.TaskID, "error", err)
	}
	return nil
}
