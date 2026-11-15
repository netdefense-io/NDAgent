package directpeer

// Why a session is refused. The device answers the task FAILED with one of
// these, and the list is closed: the same in every module that reads it.
const (
	FailPolicyDisabled       = "policy_disabled"       // the device's own policy allows no remote access
	FailUnsupportedAction    = "unsupported_action"    // a transport or an action this agent does not know
	FailCompanionUnavailable = "companion_unavailable" // the companion is missing or is another build
	FailProtocolMismatch     = "protocol_mismatch"     // the task asks for another protocol number
	FailTooManySessions      = "too_many_sessions"     // the device already carries its maximum
	FailUnsealFailed         = "unseal_failed"         // the session's secret does not open
	FailBindingMismatch      = "binding_mismatch"      // the secret was made for another session, device or relay
	FailReplayed             = "replayed"              // the session's id was used before
	FailKeyMismatch          = "key_mismatch"          // the derived keys are not the ones registered
	FailRelayUnreachable     = "relay_unreachable"     // no connection to the relay could be made
	FailRelayRefused         = "relay_refused"         // the relay turned the device's connection away
	FailCompanionFailed      = "companion_failed"      // the companion did not come up
	FailInternal             = "internal"              // anything else
)

// FailureReasons is every reason a session is refused, in the contract's
// order.
var FailureReasons = []string{
	FailPolicyDisabled, FailUnsupportedAction, FailCompanionUnavailable, FailProtocolMismatch,
	FailTooManySessions, FailUnsealFailed, FailBindingMismatch, FailReplayed, FailKeyMismatch,
	FailRelayUnreachable, FailRelayRefused, FailCompanionFailed, FailInternal,
}

// Why a session ended. The device reports the end of every session that
// listened, with one of these.
const (
	EndClientClosed    = "client_closed"    // the client closed the connection
	EndClientTimeout   = "client_timeout"   // the client sent nothing for the receive timeout
	EndNoClient        = "no_client"        // no client connected in time
	EndIdleTimeout     = "idle_timeout"     // nothing but keepalives for the idle limit
	EndMaxDuration     = "max_duration"     // the session reached its longest life
	EndClosed          = "closed"           // the control plane asked for the session to end
	EndAgentShutdown   = "agent_shutdown"   // the agent stopped
	EndCompanionExited = "companion_exited" // the companion ended by itself
	EndError           = "error"            // anything else
)

// EndReasons is every reason a session ends, in the contract's order.
var EndReasons = []string{
	EndClientClosed, EndClientTimeout, EndNoClient, EndIdleTimeout, EndMaxDuration,
	EndClosed, EndAgentShutdown, EndCompanionExited, EndError,
}

// PathNone is the path of a session no client connected to. The other two
// are the companion's own: PathDirect and PathRelayed.
const PathNone = "none"

// SessionPaths is every path a session's end can name, in the contract's
// order.
var SessionPaths = []string{PathDirect, PathRelayed, PathNone}
