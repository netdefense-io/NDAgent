package network

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/netdefense-io/ndagent/internal/facts"
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
	// Facts is the slow-changing device description. Unlike Telemetry it
	// is NOT on every frame: it rides along only when its hash differs
	// from the last value this connection sent, plus one forced resend
	// per factsResyncInterval as a resync safety net. Older brokers
	// ignore the unknown field.
	Facts *facts.Facts `json:"facts,omitempty"`
}

// FactsProvider returns the current device-facts payload, or nil when
// collection failed this cycle (which is never fatal to the heartbeat).
type FactsProvider func() *facts.Facts

// factsResyncInterval forces a full facts resend even when nothing
// changed, so a broker-side copy that was lost or never stored heals
// without waiting for the operator to change something on the box.
const factsResyncInterval = time.Hour

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

	factsFn FactsProvider
	// clock is the time source for the facts resync window. Nil means
	// time.Now; tests inject a fake.
	clock func() time.Time

	factsMu       sync.Mutex
	lastFactsHash string
	lastFactsSent time.Time
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

// SetFactsProvider wires the device-facts collector. Safe to call at any
// point — nil provider means facts are never attached to a heartbeat.
func (h *HeartbeatManager) SetFactsProvider(fn FactsProvider) {
	h.factsFn = fn
}

// NoteFactsSent records that facts with this hash just went out on
// another leg (the WebSocket auth message), so the next heartbeat doesn't
// repeat them. Also restarts the resync window.
func (h *HeartbeatManager) NoteFactsSent(hash string) {
	h.factsMu.Lock()
	defer h.factsMu.Unlock()
	h.lastFactsHash = hash
	h.lastFactsSent = h.now()
}

func (h *HeartbeatManager) now() time.Time {
	if h.clock != nil {
		return h.clock()
	}
	return time.Now()
}

// factsForHeartbeat returns the payload to attach to the next heartbeat,
// or nil to omit it. Facts ride along when their hash changed since the
// last send, or when the resync window has elapsed.
func (h *HeartbeatManager) factsForHeartbeat() *facts.Facts {
	if h.factsFn == nil {
		return nil
	}
	f := h.factsFn()
	if f == nil {
		return nil
	}

	h.factsMu.Lock()
	defer h.factsMu.Unlock()

	now := h.now()
	unchanged := f.Hash == h.lastFactsHash
	withinWindow := !h.lastFactsSent.IsZero() && now.Sub(h.lastFactsSent) < factsResyncInterval
	if unchanged && withinWindow {
		return nil
	}

	h.lastFactsHash = f.Hash
	h.lastFactsSent = now
	return f
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
		Facts:     h.factsForHeartbeat(),
	}

	log.Debugw("Sending heartbeat",
		"sequence", sequence,
		"device_uuid", h.deviceUUID,
		"facts_attached", msg.Facts != nil,
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
