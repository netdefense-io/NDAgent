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

	// Resolve device_privkey from /var/db/ndagent/device.key (issue #15).
	// On a v1.4.0 → v1.4.1 upgrade, the legacy `device_privkey=` line in
	// ndagent.conf is honored once as a migration source and persisted
	// to the new file location — keypair preserved across the upgrade.
	// Subsequent configctl template reloads cannot wipe the seed because
	// the file lives outside /usr/local.
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
			"reason", "configctl template reload was wiping the conf line on every GUI Save (issue #15)",
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
// PAYLOAD-SIGNATURES-FINDINGS-FIXES.md §3 Finding 2 / UX follow-up:
// the rebind ceremony is meant to defend against a leaked privkey, so a
// new pubkey MUST be bound — not the same pubkey rebound to the same
// device row. The agent forces this at the source: any time a rebind
// token is in conf and the persisted `last_rebind_token_hash` doesn't
// match it, generate a fresh keypair (which also overwrites the old
// `device_privkey=` line) before sending DeviceRegistrationStart.
//
// Idempotent across restarts: if the operator hasn't yet cleared the
// OPNsense GUI field after a successful rebind, the conf still has the
// (now-consumed) token. The recorded hash matches, so we skip rotation
// and leave the freshly-bound keypair alone.
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
	// rotation (emergency) tables; only the dispatch table is wired
	// to the dispatcher. Emergency is held for the future rotation
	// flow only. PAYLOAD-SIGNATURES-FINDINGS-FIXES.md §3 Finding 7.
	//
	// Trust source is the broker's public /api/v1/.well-known/keys
	// endpoint, fetched once via TOFU at first connect and pinned to
	// /var/db/ndagent/ndm-keys.json thereafter. See ROTATION-DIRECTIVE.md
	// at the CoreCode root.
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

	// Create WebSocket client. Only the dispatch keys reach the
	// dispatcher; emergency lives in rotation table only and is
	// untouched until a future rotation-directive flow lands. The
	// state store is owned by the LifecycleManager (opened in
	// NewLifecycleManager so the rebind-token rotation check can use
	// it before Phase 1).
	wsClient := network.NewWebSocketClient(l.cfg, l.state, ndmDispatchKeys)
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

