package network

import (
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/gorilla/websocket"
)

// The distinction this table draws is the whole fix: a refusal must stop
// the reconnect loop so Phase 1 runs again, and a transport failure must
// not, or a broker restart would send every device back to polling.
func TestClassifyPermanentRefusal(t *testing.T) {
	cases := []struct {
		name          string
		err           error
		wantPermanent bool
		wantCode      int
	}{
		{
			name:          "1008 from the auth leg, wrapped the way connect() wraps it",
			err:           fmt.Errorf("authentication failed: %w", fmt.Errorf("failed to read auth response: %w", &websocket.CloseError{Code: websocket.ClosePolicyViolation, Text: "authentication failed"})),
			wantPermanent: true,
			wantCode:      1008,
		},
		{
			name:          "4000 device revoked mid-session",
			err:           &websocket.CloseError{Code: 4000, Text: "device revoked: deleted"},
			wantPermanent: true,
			wantCode:      4000,
		},
		{
			name:          "4000 with an unrelated reason is not a revocation",
			err:           &websocket.CloseError{Code: 4000, Text: "server draining"},
			wantPermanent: false,
		},
		{
			name:          "normal closure is a reconnect, not a refusal",
			err:           &websocket.CloseError{Code: websocket.CloseNormalClosure, Text: ""},
			wantPermanent: false,
		},
		{
			name:          "going away is a reconnect",
			err:           &websocket.CloseError{Code: websocket.CloseGoingAway, Text: ""},
			wantPermanent: false,
		},
		{
			name:          "abnormal closure is a reconnect",
			err:           &websocket.CloseError{Code: websocket.CloseAbnormalClosure, Text: "unexpected EOF"},
			wantPermanent: false,
		},
		{
			name:          "dial failure is a reconnect",
			err:           fmt.Errorf("websocket dial failed: %w", &net.OpError{Op: "dial", Err: errors.New("connection refused")}),
			wantPermanent: false,
		},
		{
			name:          "nil is not a refusal",
			err:           nil,
			wantPermanent: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			refusal, permanent := classifyPermanentRefusal(tc.err)
			if permanent != tc.wantPermanent {
				t.Fatalf("permanent = %v, want %v (err: %v)", permanent, tc.wantPermanent, tc.err)
			}
			if !permanent {
				return
			}
			if refusal.Code != tc.wantCode {
				t.Fatalf("code = %d, want %d", refusal.Code, tc.wantCode)
			}
			// The typed error must survive errors.As through a wrap, or
			// WebSocketClient.Run's caller cannot tell refusals apart.
			var got *PermanentRefusalError
			if !errors.As(fmt.Errorf("wrapped: %w", error(refusal)), &got) {
				t.Fatal("PermanentRefusalError does not survive errors.As")
			}
		})
	}
}
