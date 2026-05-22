package telemetry

import (
	"context"
	"math/rand"
	"sync"
	"time"

	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/opnapi"
	"go.uber.org/zap"
)

// HeavySnapshot bundles the OPNsense-API-derived fields that are too
// expensive to probe on every 60 s heartbeat. The collector refreshes
// every `heavyRefreshInterval` in a background goroutine; the heartbeat
// sender just embeds the latest cached pointer (or nil before the first
// refresh completes).
//
// Each sub-block carries its own `as_of` because the firmware probe
// involves a deliberate 30 s wait between trigger and read, so it can
// drift relative to the others. The dashboard renders "as of N minutes
// ago" against the side of the clock we trust (NDBroker wallclock at
// receive time), but the per-block timestamps are useful for debugging
// agent-side staleness.
type HeavySnapshot struct {
	Services    *ServicesBlock `json:"services,omitempty"`
	Updates     *UpdatesBlock  `json:"updates,omitempty"`
	Certs       *CertsBlock    `json:"certs,omitempty"`
	CollectedAt float64        `json:"collected_at"`
}

type ServicesBlock struct {
	Items  []opnapi.ServiceEntry `json:"items"`
	AsOf   float64               `json:"as_of"`
}

type UpdatesBlock struct {
	*opnapi.FirmwareStatus
	AsOf float64 `json:"as_of"`
}

type CertsBlock struct {
	Items []opnapi.CertEntry `json:"items"`
	AsOf  float64            `json:"as_of"`
}

// heavyRefreshInterval is the cache cycle. 15 minutes is the sweet spot
// for an MSP dashboard — fast enough to catch a service flap or a fresh
// CVE, slow enough that 500 agents hammering `firmware/check` once per
// cycle don't slam the pkg mirror. Tunable here if we ever need it.
const heavyRefreshInterval = 15 * time.Minute

// firmwareCheckSettleSeconds is how long we wait between POSTing
// `firmware/check` (which returns immediately with a job UUID) and
// reading `firmware/status` for the result. 30 s matches what
// OPNsense's own web UI does internally.
const firmwareCheckSettleSeconds = 30

// HeavyCollector owns the cache. Lifetime is the agent process — start
// it once from `lifecycle.go` after the OPNsense API client is
// initialized, and keep it running across WS reconnects so the cache
// survives a flapping NDBroker connection.
type HeavyCollector struct {
	client *opnapi.Client
	log    *zap.SugaredLogger

	mu    sync.RWMutex
	cache *HeavySnapshot
}

func NewHeavyCollector(client *opnapi.Client) *HeavyCollector {
	return &HeavyCollector{
		client: client,
		log:    logging.Named("heavy-telemetry"),
	}
}

// Run blocks until ctx is cancelled. Refreshes the cache on a fixed
// schedule, with a random initial offset to avoid synchronised hits
// across a fleet that all came up at the same time (e.g. after a
// cluster-wide broker restart).
func (h *HeavyCollector) Run(ctx context.Context) error {
	// Stagger initial fire 0–60 s so a fleet reconnect doesn't cause
	// every agent to query OPNsense + the pkg mirror simultaneously.
	startOffset := time.Duration(rand.Intn(60)) * time.Second
	h.log.Infow("heavy-telemetry started", "first_run_in", startOffset.String(), "interval", heavyRefreshInterval.String())

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(startOffset):
	}

	h.refresh(ctx)

	t := time.NewTicker(heavyRefreshInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			h.refresh(ctx)
		}
	}
}

// Snapshot returns the most recent cached snapshot. nil before the first
// refresh has succeeded, which the heartbeat sender treats as "skip the
// `heavy` field" so older brokers + the warm-up window both work.
func (h *HeavyCollector) Snapshot() *HeavySnapshot {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.cache
}

// refresh runs all three probes. Each is independent; a failure in one
// leaves that sub-block nil and the others still ship — the dashboard
// renders "unavailable" rather than nothing.
func (h *HeavyCollector) refresh(ctx context.Context) {
	start := time.Now()
	snap := &HeavySnapshot{CollectedAt: float64(start.Unix())}

	// Service states — fast (<200 ms), runs first.
	if items, err := h.client.ListServices(ctx); err != nil {
		h.log.Warnw("heavy-telemetry: service list failed", "error", err)
	} else {
		snap.Services = &ServicesBlock{Items: items, AsOf: float64(time.Now().Unix())}
	}

	// Pending updates — POST /firmware/check is async; wait then read.
	// We fire the check first, then go do the cert probe while it's
	// settling, then come back to read the status. Cheap parallelism.
	checkOK := false
	if err := h.client.TriggerFirmwareCheck(ctx); err != nil {
		h.log.Warnw("heavy-telemetry: firmware check trigger failed", "error", err)
	} else {
		checkOK = true
	}

	// Cert list — fast, runs while firmware check is settling on
	// OPNsense's side.
	if items, err := h.client.ListCerts(ctx); err != nil {
		h.log.Warnw("heavy-telemetry: cert list failed", "error", err)
	} else {
		snap.Certs = &CertsBlock{Items: items, AsOf: float64(time.Now().Unix())}
	}

	// Now wait the remainder of the settle window, then read status.
	// We don't block forever — ctx cancellation short-circuits.
	if checkOK {
		elapsed := time.Since(start)
		remaining := firmwareCheckSettleSeconds*time.Second - elapsed
		if remaining > 0 {
			select {
			case <-ctx.Done():
				h.log.Info("heavy-telemetry: ctx cancelled during firmware settle wait")
				return
			case <-time.After(remaining):
			}
		}
		if st, err := h.client.GetFirmwareStatus(ctx); err != nil {
			h.log.Warnw("heavy-telemetry: firmware status read failed", "error", err)
		} else {
			snap.Updates = &UpdatesBlock{FirmwareStatus: st, AsOf: float64(time.Now().Unix())}
		}
	}

	h.mu.Lock()
	h.cache = snap
	h.mu.Unlock()

	h.log.Infow(
		"heavy-telemetry refresh complete",
		"duration_ms", time.Since(start).Milliseconds(),
		"services", snap.Services != nil,
		"updates", snap.Updates != nil,
		"certs", snap.Certs != nil,
	)
}
