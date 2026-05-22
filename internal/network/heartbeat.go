package network

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/telemetry"
	"github.com/netdefense-io/ndagent/internal/util"
)

// HeartbeatMessage is the heartbeat message sent to the server.
//
// Telemetry is included on every heartbeat (60 s). NDBroker writes it to a
// Redis HASH with a TTL of 3× heartbeat, so the dashboard always reflects
// the most recent live frame and stale data evicts itself when an agent
// goes silent.
type HeartbeatMessage struct {
	Type      string              `json:"type"`
	Status    string              `json:"status"`
	Timestamp float64             `json:"timestamp"`
	Sequence  int64               `json:"sequence"`
	Telemetry *telemetry.Snapshot `json:"telemetry,omitempty"`
}

// HeavyProvider returns the latest heavy-telemetry snapshot, or nil if
// the collector hasn't completed its first refresh yet. The heartbeat
// embeds the result on every frame; the warm-up window is handled by
// the dashboard accepting a nil sub-object.
type HeavyProvider func() *telemetry.HeavySnapshot

// HeartbeatManager manages WebSocket heartbeat functionality.
type HeartbeatManager struct {
	deviceUUID string
	interval   time.Duration
	count      atomic.Int64
	heavyFn    HeavyProvider
}

// NewHeartbeatManager creates a new heartbeat manager.
func NewHeartbeatManager(deviceUUID string, interval time.Duration) *HeartbeatManager {
	return &HeartbeatManager{
		deviceUUID: deviceUUID,
		interval:   interval,
	}
}

// SetHeavyProvider wires the heavy-telemetry cache reader. Safe to call
// at any point — nil provider means heavy fields stay omitted.
func (h *HeartbeatManager) SetHeavyProvider(fn HeavyProvider) {
	h.heavyFn = fn
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

	snap := telemetry.Collect()
	if h.heavyFn != nil {
		snap.Heavy = h.heavyFn()
	}
	msg := HeartbeatMessage{
		Type:      MsgTypeHeartbeat,
		Status:    "active",
		Timestamp: float64(time.Now().Unix()),
		Sequence:  sequence,
		Telemetry: &snap,
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
