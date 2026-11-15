package directpeer

import (
	"errors"
	"math"
	"time"
)

// ResultKey is the key, beside status and message in a task's signed
// response, under which the device says what happened to a session. The
// control plane reads the session's state from it and never from the message.
const ResultKey = "connect"

// What a result reports.
const (
	ResultListening  = "listening"   // the session is ready: the client may connect
	ResultSessionEnd = "session-end" // the session is over, and why
	ResultFailed     = "failed"      // no session was opened, and why
	ResultClosed     = "closed"      // the answer to a close instruction
)

const (
	statusCompleted = "COMPLETED"
	statusFailed    = "FAILED"
)

// Result is one answer of the device about a session: a task status, the
// message a person reads and the object under ResultKey.
type Result struct {
	Status  string
	Message string
	Connect map[string]interface{}
}

// Data is the result as the data of a task response.
func (r Result) Data() map[string]interface{} {
	return map[string]interface{}{ResultKey: r.Connect}
}

// endMessages is what a person reads for each way a session ends. The texts
// are the contract's: other modules show them as they are.
var endMessages = map[string]string{
	EndClientClosed:    "the client closed the session",
	EndClientTimeout:   "the client stopped responding",
	EndNoClient:        "no client connected in time",
	EndIdleTimeout:     "idle for too long",
	EndMaxDuration:     "the maximum session time was reached",
	EndClosed:          "closed on request",
	EndAgentShutdown:   "the agent stopped",
	EndCompanionExited: "the session process stopped unexpectedly",
	EndError:           "an error ended the session",
}

// failMessages is what a person reads for each refusal. Fixed texts: nothing
// of the request and nothing the device found is ever put into one.
var failMessages = map[string]string{
	FailPolicyDisabled:       "remote access is disabled on this device (Remote Access Policy, under Services > NetDefense > Settings); it cannot be changed remotely",
	FailUnsupportedAction:    "the request is not one this agent can read",
	FailCompanionUnavailable: "the program that carries a session is missing on this device or does not match its agent; reinstall the NetDefense package",
	FailProtocolMismatch:     "this agent runs another version of the session protocol",
	FailTooManySessions:      "the device already has its maximum of remote sessions open",
	FailUnsealFailed:         "the sealed session data could not be opened",
	FailBindingMismatch:      "the sealed session data was made for another session, device or relay",
	FailReplayed:             "the session id was used before",
	FailKeyMismatch:          "the session keys are not the ones registered for the session",
	FailRelayUnreachable:     "the device could not reach the relay",
	FailRelayRefused:         "the relay refused the device's connection",
	FailCompanionFailed:      "the program that carries a session did not start",
	FailInternal:             "an internal error on the device",
}

// ListeningResult is the answer of a session that is ready.
func ListeningResult(connectID string) Result {
	return Result{
		Status:  statusCompleted,
		Message: "Remote session ready",
		Connect: map[string]interface{}{"event": ResultListening, "connect_id": connectID, "protocol": Protocol},
	}
}

// SessionEnd is how a session ended.
type SessionEnd struct {
	// Reason is one of EndReasons; anything else is reported as EndError.
	Reason string
	// Duration is the time from listening to the end.
	Duration time.Duration
	// Paired says whether a client ever connected, and PairedAfter how long
	// after listening.
	Paired      bool
	PairedAfter time.Duration
	// Path is the path in use at the end. It is PathNone without a client.
	Path string
}

func wholeSeconds(d time.Duration) int {
	if d < 0 {
		return 0
	}
	return int(d / time.Second)
}

// SessionEndResult is the second answer of an open task: the session is
// over. It is COMPLETED whatever ended the session; the reason says which.
func SessionEndResult(connectID string, end SessionEnd) Result {
	reason := end.Reason
	message, known := endMessages[reason]
	if !known {
		reason, message = EndError, endMessages[EndError]
	}
	connect := map[string]interface{}{
		"event":            ResultSessionEnd,
		"connect_id":       connectID,
		"protocol":         Protocol,
		"reason":           reason,
		"duration_seconds": wholeSeconds(end.Duration),
	}
	path := PathNone
	if end.Paired {
		connect["paired_after_seconds"] = wholeSeconds(end.PairedAfter)
		if end.Path == PathDirect || end.Path == PathRelayed {
			path = end.Path
		} else {
			// A client that connected was on a path; one the companion never
			// named went through the relay, where every session starts.
			path = PathRelayed
		}
	}
	connect["path"] = path
	return Result{Status: statusCompleted, Message: "Remote session ended: " + message, Connect: connect}
}

// FailedResult is the answer of an open task that opened no session. A
// reason outside FailureReasons is reported as FailInternal.
func FailedResult(connectID, reason string) Result {
	message, known := failMessages[reason]
	if !known {
		reason, message = FailInternal, failMessages[FailInternal]
	}
	return Result{
		Status:  statusFailed,
		Message: "Remote session refused: " + message,
		Connect: map[string]interface{}{"event": ResultFailed, "connect_id": connectID, "reason": reason},
	}
}

// ClosedResult is the answer to a close instruction: found says whether the
// device had a session with that id.
func ClosedResult(connectID string, found bool) Result {
	message := "No such remote session"
	if found {
		message = "Remote session closed"
	}
	return Result{
		Status:  statusCompleted,
		Message: message,
		Connect: map[string]interface{}{"event": ResultClosed, "connect_id": connectID, "found": found},
	}
}

// ErrNotAResult is a Reporter's answer for a result the contract does not
// accept. It will never be recorded, and is not kept.
var ErrNotAResult = errors.New("not a remote session result")

// ValidConnectID reports whether id has the form of a session id: 32
// lowercase hex characters.
func ValidConnectID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// wholeNumber reads a count that may have been through JSON, where every
// number is a float.
func wholeNumber(v interface{}) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, n >= 0
	case int64:
		return int(n), n >= 0 && n <= math.MaxInt32
	case float64:
		if n < 0 || n > math.MaxInt32 || n != math.Trunc(n) {
			return 0, false
		}
		return int(n), true
	}
	return 0, false
}

func oneOf(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

// CleanResult returns the object a response of the given status may carry
// under ResultKey, or false: only an event that goes with the status, with
// exactly its keys, each of its type, and reasons and paths of the closed
// lists. It is the last check before a response is signed, and also reads a
// result back from the task store, where numbers have become floats.
func CleanResult(status string, v interface{}) (map[string]interface{}, bool) {
	in, ok := v.(map[string]interface{})
	if !ok {
		return nil, false
	}
	event, _ := in["event"].(string)
	id, _ := in["connect_id"].(string)
	if !ValidConnectID(id) {
		return nil, false
	}
	out := map[string]interface{}{"event": event, "connect_id": id}

	wantStatus := statusCompleted
	switch event {
	case ResultListening:
		protocol, ok := wholeNumber(in["protocol"])
		if !ok || protocol < 1 || protocol > 65535 {
			return nil, false
		}
		out["protocol"] = protocol
	case ResultSessionEnd:
		protocol, okProtocol := wholeNumber(in["protocol"])
		duration, okDuration := wholeNumber(in["duration_seconds"])
		reason, _ := in["reason"].(string)
		path, _ := in["path"].(string)
		if !okProtocol || protocol < 1 || protocol > 65535 || !okDuration ||
			!oneOf(EndReasons, reason) || !oneOf(SessionPaths, path) {
			return nil, false
		}
		out["protocol"], out["duration_seconds"], out["reason"], out["path"] = protocol, duration, reason, path
		paired, present := in["paired_after_seconds"]
		if present {
			after, ok := wholeNumber(paired)
			if !ok || path == PathNone {
				return nil, false
			}
			out["paired_after_seconds"] = after
		} else if path != PathNone {
			return nil, false
		}
	case ResultFailed:
		wantStatus = statusFailed
		reason, _ := in["reason"].(string)
		if !oneOf(FailureReasons, reason) {
			return nil, false
		}
		out["reason"] = reason
	case ResultClosed:
		found, ok := in["found"].(bool)
		if !ok {
			return nil, false
		}
		out["found"] = found
	default:
		return nil, false
	}
	if status != wantStatus {
		return nil, false
	}
	return out, true
}

// ResultEvent is the event of the result recorded in data, a task response's
// data, or "" when it carries none.
func ResultEvent(data map[string]interface{}) string {
	connect, _ := data[ResultKey].(map[string]interface{})
	event, _ := connect["event"].(string)
	return event
}
