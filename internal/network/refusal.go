// Package network — permanent-refusal classification for the NDBroker
// WebSocket connection.
//
// Every disconnect used to look the same to WebSocketClient.Run: log it,
// sleep, dial again, forever. That is right for a broker restart or a
// flapping uplink and wrong for a refusal, because Run never returning
// means LifecycleManager never re-enters Phase 1, and Phase 1 is the
// only place the agent ever asks "am I still registered?". A revoked
// device therefore reconnected until someone noticed.
//
// The close codes below are the broker's two ways of saying "stop
// asking me": 1008 on the authentication leg, and 4000 mid-session when
// a device is revoked while connected. Both mean the answer now lives at
// the registration-check endpoint, not here.
package network

import (
	"errors"
	"fmt"
	"strings"

	"github.com/gorilla/websocket"
)

// Close codes the broker uses to refuse a device.
const (
	// closeCodePolicyViolation (1008) is what NDBroker sends when the
	// authentication frame is rejected. Deliberately generic on the
	// broker side: it does not leak whether the device is unknown,
	// pending, disabled or deleted. Phase 1 resolves which.
	closeCodePolicyViolation = websocket.ClosePolicyViolation

	// closeCodeDeviceRevoked (4000) is the broker's application-specific
	// push when a device is revoked during a live session; the reason
	// text carries "device revoked: <why>".
	closeCodeDeviceRevoked = 4000

	// deviceRevokedReasonPrefix matches the 4000 reason text. A 4000
	// close carrying some other reason is treated as transient — the
	// code alone is not a contract.
	deviceRevokedReasonPrefix = "device revoked:"
)

// PermanentRefusalError marks a WebSocket close the agent must not
// retry. WebSocketClient.Run returns it instead of reconnecting, which
// hands control back to LifecycleManager and re-runs Phase 1.
//
// It is a routing signal, not an authorization: nothing destructive
// happens because of it. Whether the device is disabled, deleted or
// merely pending is decided by the registration check, from a signed
// tombstone where it matters.
type PermanentRefusalError struct {
	Code   int
	Reason string
}

func (e *PermanentRefusalError) Error() string {
	return fmt.Sprintf("broker refused the connection (close %d: %s)", e.Code, e.Reason)
}

// classifyPermanentRefusal reports whether err is a close frame the
// agent must stop retrying, and returns the typed error to surface.
//
// Mirrors internal/pathfinder/client.go, which already unwraps
// *websocket.CloseError for the relay connection — the data was always
// there, this connection just never looked at it.
func classifyPermanentRefusal(err error) (*PermanentRefusalError, bool) {
	if err == nil {
		return nil, false
	}
	var closeErr *websocket.CloseError
	if !errors.As(err, &closeErr) {
		return nil, false
	}

	switch closeErr.Code {
	case closeCodePolicyViolation:
		return &PermanentRefusalError{Code: closeErr.Code, Reason: closeErr.Text}, true
	case closeCodeDeviceRevoked:
		if strings.HasPrefix(strings.TrimSpace(closeErr.Text), deviceRevokedReasonPrefix) {
			return &PermanentRefusalError{Code: closeErr.Code, Reason: closeErr.Text}, true
		}
	}
	return nil, false
}
