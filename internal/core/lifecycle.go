package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/netdefense-io/ndagent/internal/config"
	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/network"
	"github.com/netdefense-io/ndagent/internal/opnapi"
	"github.com/netdefense-io/ndagent/internal/state"
	"github.com/netdefense-io/ndagent/internal/status"
	"github.com/netdefense-io/ndagent/internal/tasks"
	"github.com/netdefense-io/ndagent/internal/taskstore"
	"github.com/netdefense-io/ndagent/internal/telemetry"
)

// LifecycleManager manages the agent's two-phase lifecycle:
// 1. Registration verification phase (HTTP API calls)
// 2. WebSocket connection phase (persistent connection)
type LifecycleManager struct {
	cfg                *config.Config
	configPath         string
	shutdown           *ShutdownCoordinator
	registrationClient *network.RegistrationClient
	state              *state.Store
	status             *status.Writer
}

// NewLifecycleManager creates a new lifecycle manager.
func NewLifecycleManager(cfg *config.Config, configPath string, shutdown *ShutdownCoordinator, statusWriter *status.Writer) (*LifecycleManager, error) {
	log := logging.Named("lifecycle")

	stateStore, err := state.New(state.DefaultStatePath)
	if err != nil {
		return nil, fmt.Errorf("open agent state store at %s: %w", state.DefaultStatePath, err)
	}

	// Resolve device_privkey from /var/db/ndagent/device.key. A legacy
	// `device_privkey=` line in ndagent.conf is honored once as a migration
	// source; the new path lives outside /usr/local so configctl template
	// reloads cannot wipe the seed.
	privkey, origin, err := state.LoadOrEnsureDevicePrivkey(state.DefaultDeviceKeyPath, cfg.DevicePrivKey)
	if err != nil {
		return nil, fmt.Errorf("load device privkey from %s: %w", state.DefaultDeviceKeyPath, err)
	}
	cfg.DevicePrivKey = privkey
	switch origin {
	case state.PrivkeyFromFile:
		log.Infow("Device signing key loaded",
			"source", "file",
			"path", state.DefaultDeviceKeyPath,
		)
	case state.PrivkeyMigrated:
		log.Warnw("Device signing key migrated from ndagent.conf to durable storage",
			"path", state.DefaultDeviceKeyPath,
			"reason", "configctl template reload was wiping the conf line on every GUI Save",
		)
	case state.PrivkeyGenerated:
		log.Warnw("Generated fresh device keypair",
			"path", state.DefaultDeviceKeyPath,
			"action_required", "If this device was previously registered, response signatures will FAIL until the operator re-binds via 'ndcli device rebind-token <name>'.",
		)
	}

	return &LifecycleManager{
		cfg:                cfg,
		configPath:         configPath,
		shutdown:           shutdown,
		registrationClient: network.NewRegistrationClient(cfg),
		state:              stateStore,
		status:             statusWriter,
	}, nil
}

// maybeRotateForRebindToken rotates the device keypair when ndagent.conf
// carries a `bootstrap_token=` value the agent has not yet consumed.
//
// The rebind ceremony defends against a leaked privkey, so a new pubkey
// MUST be bound — not the same pubkey rebound to the same device row.
// Whenever a rebind token is in conf and the persisted `last_rebind_token_hash`
// doesn't match it, generate a fresh keypair (overwriting any legacy
// `device_privkey=` line) before sending DeviceRegistrationStart.
//
// Idempotent across restarts: if the operator hasn't cleared the GUI field
// after a successful rebind, the conf still has the (now-consumed) token.
// The recorded hash matches, so we skip rotation and leave the freshly-bound
// keypair alone.
func (l *LifecycleManager) maybeRotateForRebindToken() error {
	log := logging.Named("lifecycle")
	token := strings.TrimSpace(l.cfg.BootstrapToken)
	if token == "" {
		return nil
	}
	sum := sha256.Sum256([]byte(token))
	currentHash := hex.EncodeToString(sum[:])
	if l.state.LastRebindTokenHash() == currentHash {
		log.Info("Rebind token in conf already consumed by an earlier run; skipping keypair rotation")
		return nil
	}
	log.Info("Rebind token detected — rotating device keypair before registration")
	newPrivkey, err := state.RotateDevicePrivkey(state.DefaultDeviceKeyPath)
	if err != nil {
		return fmt.Errorf("rotate device keypair for rebind: %w", err)
	}
	l.cfg.DevicePrivKey = newPrivkey
	if err := l.state.SetLastRebindTokenHash(currentHash); err != nil {
		return fmt.Errorf("persist rebind-token hash: %w", err)
	}
	log.Info("Device keypair rotated for rebind ceremony")
	return nil
}

// maybeClearRebindTokenInConfig invokes the OPNsense plugin helper to
// strip the consumed bootstrapToken from /conf/config.xml so the next
// template render of ndagent.conf does not carry it. Best-effort: a
// helper failure is logged at WARN and does not abort the lifecycle —
// the token is internally inert at this point because the agent's
// state.LastRebindTokenHash already matches it.
//
// Reflects the cleared value in-process so any subsequent iteration of
// the lifecycle loop in this run sees the field as empty and does not
// retry the helper unnecessarily.
func (l *LifecycleManager) maybeClearRebindTokenInConfig(ctx context.Context) {
	if l.cfg.BootstrapToken == "" {
		return
	}
	log := logging.Named("lifecycle")
	if err := clearRebindTokenInConfig(ctx); err != nil {
		log.Warnw("Failed to clear consumed rebind token from local config; the token is internally inert and you may remove the field manually if it persists",
			"error", err)
		return
	}
	log.Info("Cleared consumed rebind token from OPNsense config; ndagent.conf will not carry it after the next template render")
	l.cfg.BootstrapToken = ""
}

// Run executes the complete agent lifecycle.
// It handles both connection phases and automatically restarts on failure.
func (l *LifecycleManager) Run(ctx context.Context) error {
	log := logging.Named("lifecycle")

	for {
		// Check for shutdown at start of each iteration
		select {
		case <-ctx.Done():
			log.Info("Shutdown event detected during lifecycle - exiting gracefully")
			return ctx.Err()
		default:
		}

		// Pre-Phase-1: rebind-token check. If the operator pasted a fresh
		// rebind token into ndagent.conf, rotate the keypair BEFORE
		// registration so the agent submits the new pubkey. Idempotent
		// across restarts via state.LastRebindTokenHash.
		if err := l.maybeRotateForRebindToken(); err != nil {
			log.Errorw("Rebind-token keypair rotation failed", "error", err)
			// Fall through; registration will likely fail too and we'll
			// retry. Don't block forever on a transient disk error.
		}

		// Phase 1: Registration verification (HTTP API calls)
		log.Info("Phase 1: Starting registration verification...")
		_ = l.status.MarkConnecting()

		err := l.registrationClient.WaitForRegistration(ctx)
		if err != nil {
			// Check if it's a shutdown/cancellation
			if ctx.Err() != nil {
				log.Info("Shutdown during registration phase - exiting gracefully")
				return ctx.Err()
			}

			// Handle device disabled/deleted errors
			if err == network.ErrDeviceDisabled || err == network.ErrDeviceDeleted {
				log.Errorw("Device status prevents registration",
					"error", err,
				)
				return err
			}

			log.Errorw("Registration verification failed, will retry",
				"error", err,
			)
			continue
		}

		// Check shutdown again before entering WebSocket phase
		select {
		case <-ctx.Done():
			log.Info("Shutdown event detected before WebSocket phase - exiting gracefully")
			return ctx.Err()
		default:
		}

		// Registration succeeded; if ndagent.conf still carries a
		// bootstrap_token=, clear it via the OPNsense plugin helper.
		// The token is single-use: the broker has already cleared its
		// server-side hash, and the agent's internal state (LastRebindTokenHash)
		// already prevents re-rotation. This step is the device-side
		// housekeeping the operator used to be told to do manually.
		// Best-effort: failure is logged but does not abort the flow.
		l.maybeClearRebindTokenInConfig(ctx)

		// Phase 2: Establish WebSocket connection and maintain it
		log.Info("Phase 2: Registration verified. Establishing WebSocket connection...")

		err = l.runWebSocketPhase(ctx)
		if err != nil {
			// Check if it's a shutdown/cancellation
			if ctx.Err() != nil {
				log.Info("Shutdown requested - ending lifecycle gracefully")
				return ctx.Err()
			}

			log.Warnw("WebSocket connection ended",
				"error", err,
			)
		}

		// Check if shutdown was requested
		select {
		case <-ctx.Done():
			log.Info("Shutdown requested - ending lifecycle gracefully")
			return ctx.Err()
		default:
		}

		// WebSocket connection has ended but we should continue the loop
		log.Warn("WebSocket connection ended. Restarting agent lifecycle...")

		// Brief delay before restarting entire lifecycle
		if err := ShutdownAwareSleep(ctx, 5*time.Second); err != nil {
			log.Info("Shutdown event detected during error recovery - exiting gracefully")
			return err
		}
	}
}

// runWebSocketPhase runs the WebSocket connection phase.
func (l *LifecycleManager) runWebSocketPhase(ctx context.Context) error {
	log := logging.Named("lifecycle")

	log.Info("Starting WebSocket client...")

	// Load NDM verification keys split into dispatch (primary) and
	// rotation (emergency) tables; only the dispatch table is wired to
	// the dispatcher. Emergency is held for the future rotation flow.
	// Trust source is the broker's /api/v1/.well-known/keys, fetched once
	// via TOFU at first connect and pinned to /var/db/ndagent/ndm-keys.json.
	ndmDispatchKeys, ndmRotationKeys, err := network.LoadOrFetchNDMKeys(
		ctx, l.cfg, network.DefaultNDMKeysCachePath,
	)
	if err != nil {
		log.Errorw("Failed to load NDM verification keys", "error", err)
		return err
	}
	dispatchKidHexes := make([]string, 0, len(ndmDispatchKeys))
	for k := range ndmDispatchKeys {
		dispatchKidHexes = append(dispatchKidHexes, k)
	}
	rotationKidHexes := make([]string, 0, len(ndmRotationKeys))
	for k := range ndmRotationKeys {
		rotationKidHexes = append(rotationKidHexes, k)
	}
	log.Infow("Loaded NDM verification keys",
		"dispatch_kids", dispatchKidHexes,
		"rotation_kids", rotationKidHexes,
	)

	// Open the per-task registry. Used by the dispatcher (Begin), by
	// SendTaskResponse (Complete + MarkDelivered), and by the boot-time
	// drain below to deliver responses for tasks that finished in a
	// previous agent process (PLUGIN_INSTALL, RESTART, REBOOT). Failure
	// to open the store is non-fatal — the agent still runs, just
	// without crash-recovery and without deferred-response delivery for
	// this boot. Operators see the warning in the logs.
	taskStoreInst, tsErr := taskstore.Open(taskstore.DefaultStorePath)
	if tsErr != nil {
		log.Warnw("Failed to open task store; per-task persistence disabled",
			"path", taskstore.DefaultStorePath, "error", tsErr,
		)
		taskStoreInst = nil
	}

	// Create WebSocket client. Only the dispatch keys reach the
	// dispatcher; emergency lives in rotation table only and is
	// untouched until a future rotation-directive flow lands. The
	// state store is owned by the LifecycleManager (opened in
	// NewLifecycleManager so the rebind-token rotation check can use
	// it before Phase 1).
	wsClient := network.NewWebSocketClient(l.cfg, l.state, taskStoreInst, tasks.LifecycleFor, ndmDispatchKeys)
	wsClient.SetStatusWriter(l.status)
	_ = ndmRotationKeys // held for future rotation-directive verify

	// Initialize OPNsense API client if credentials are configured
	if l.cfg.HasAPICreds() {
		apiClient := opnapi.NewClient(
			l.cfg.OPNsenseAPIURL,
			l.cfg.APIKey,
			l.cfg.APISecret,
			true, // Always skip TLS verification for localhost API
		)
		wsClient.SetAPIClient(apiClient)
		log.Infow("OPNsense API client initialized for SYNC_API",
			"api_url", l.cfg.OPNsenseAPIURL,
		)

		// Start the heavy-telemetry collector. Lifetime is the agent
		// process — survives WS reconnects so the cache doesn't reset
		// every time NDBroker bounces. The shutdown coordinator's
		// context cancels the goroutine on agent stop.
		heavy := telemetry.NewHeavyCollector(apiClient)
		go func() {
			if err := heavy.Run(l.shutdown.Context()); err != nil && err != context.Canceled {
				log.Warnw("heavy-telemetry collector exited", "error", err)
			}
		}()
		wsClient.SetHeavyProvider(heavy.Snapshot)
		log.Info("Heavy telemetry collector started")
	} else {
		log.Info("SYNC_API disabled: no API credentials configured")
	}

	// Register task handlers
	tasks.RegisterHandlers(wsClient)

	// Set shutdown callback for RESTART task
	wsClient.SetShutdownCallback(func() {
		log.Info("Shutdown requested by RESTART task")
		l.shutdown.RequestShutdown()
	})

	// Run WebSocket client (handles reconnection internally)
	return wsClient.Run(ctx)
}

