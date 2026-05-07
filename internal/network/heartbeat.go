package network

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/util"
)

// HeartbeatMessage is the heartbeat message sent to the server.
type HeartbeatMessage struct {
	Type      string  `json:"type"`
	Status    string  `json:"status"`
	Timestamp float64 `json:"timestamp"`
	Sequence  int64   `json:"sequence"`
}

// HeartbeatManager manages WebSocket heartbeat functionality.
type HeartbeatManager struct {
	deviceUUID string
	interval   time.Duration
	count      atomic.Int64
}

// NewHeartbeatManager creates a new heartbeat manager.
func NewHeartbeatManager(deviceUUID string, interval time.Duration) *HeartbeatManager {
	return &HeartbeatManager{
		deviceUUID: deviceUUID,
		interval:   interval,
	}
}

// Run starts the heartbeat loop.
// It sends heartbeats at the configured interval until context is cancelled.
func (h *HeartbeatManager) Run(ctx context.Context, ws *WebSocketClient) error {
	log := logging.Named("heartbeat")

	for {
		// Check for cancellation at the start
		select {
		case <-ctx.Done():
			log.Infow("Heartbeat loop cancelled",
				"total_heartbeats", h.count.Load(),
			)
			return ctx.Err()
		default:
		}

		// Send heartbeat
		if err := h.sendHeartbeat(ws); err != nil {
			log.Errorw("Failed to send heartbeat",
				"error", err,
				"sequence", h.count.Load(),
			)
			// Connection error - return to trigger reconnection
			return err
		}

		// Wait for next heartbeat interval
		if err := util.ShutdownAwareSleep(ctx, h.interval); err != nil {
			log.Infow("Heartbeat sleep cancelled",
				"total_heartbeats", h.count.Load(),
			)
			return err
		}
	}
}

// sendHeartbeat sends a single heartbeat message.
func (h *HeartbeatManager) sendHeartbeat(ws *WebSocketClient) error {
	log := logging.Named("heartbeat")

	sequence := h.count.Add(1)

	msg := HeartbeatMessage{
		Type:      MsgTypeHeartbeat,
		Status:    "active",
		Timestamp: float64(time.Now().Unix()),
		Sequence:  sequence,
	}

	log.Debugw("Sending heartbeat",
		"sequence", sequence,
		"device_uuid", h.deviceUUID,
	)

	if err := ws.SendJSON(msg); err != nil {
		return err
	}

	log.Infow("Sent heartbeat",
		"sequence", sequence,
		"device_uuid", h.deviceUUID,
	)
	ws.TouchStatus()

	return nil
}

// Count returns the number of heartbeats sent.
func (h *HeartbeatManager) Count() int64 {
	return h.count.Load()
}

// Reset resets the heartbeat counter.
func (h *HeartbeatManager) Reset() {
	h.count.Store(0)
}
