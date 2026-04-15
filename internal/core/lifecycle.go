package core

import (
	"context"
	"time"

	"github.com/netdefense-io/ndagent/internal/config"
	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/network"
	"github.com/netdefense-io/ndagent/internal/opnapi"
	"github.com/netdefense-io/ndagent/internal/tasks"
)

// LifecycleManager manages the agent's two-phase lifecycle:
// 1. Registration verification phase (HTTP API calls)
// 2. WebSocket connection phase (persistent connection)
type LifecycleManager struct {
	cfg                *config.Config
	shutdown           *ShutdownCoordinator
	registrationClient *network.RegistrationClient
}

// NewLifecycleManager creates a new lifecycle manager.
func NewLifecycleManager(cfg *config.Config, shutdown *ShutdownCoordinator) *LifecycleManager {
	return &LifecycleManager{
		cfg:                cfg,
		shutdown:           shutdown,
		registrationClient: network.NewRegistrationClient(cfg),
	}
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

		// Phase 1: Registration verification (HTTP API calls)
		log.Info("Phase 1: Starting registration verification...")

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

	// Create WebSocket client
	wsClient := network.NewWebSocketClient(l.cfg)

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
