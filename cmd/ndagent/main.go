// NDAgent - NetDefense OPNSense Device Agent
//
// This is the main entry point for the NetDefense agent that provides:
// - Device registration and management
// - WebSocket communication with NetDefense servers
// - Configuration synchronization for OPNsense
// - Service mode support for OPNsense RC system
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/netdefense-io/ndagent/internal/config"
	"github.com/netdefense-io/ndagent/internal/core"
	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/pkg/version"
)

var (
	// CLI flags
	configPath string
	foreground bool
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "ndagent",
	Short: "NetDefense OPNSense Device Agent",
	Long: `NDAgent is the NetDefense device agent for OPNsense firewalls.

It provides device registration, WebSocket communication with NetDefense
servers, and configuration synchronization for OPNsense.`,
	Version: version.Version,
	RunE:    run,
}

func init() {
	// Define flags
	rootCmd.Flags().BoolVarP(&foreground, "foreground", "f", false,
		"Run in foreground mode (logs to stdout)")
	rootCmd.Flags().StringVarP(&configPath, "config", "c", config.DefaultConfigPath,
		"Path to configuration file")

	// Custom version template
	rootCmd.SetVersionTemplate(fmt.Sprintf("{{.Name}} %s\n", version.Full()))
}

func run(cmd *cobra.Command, args []string) error {
	// Determine logging mode
	logMode := logging.ModeService
	if foreground {
		logMode = logging.ModeForeground
	}

	// Load configuration
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		return err
	}

	// Setup logging
	if err := logging.Setup(logMode, cfg.LogLevel); err != nil {
		fmt.Fprintf(os.Stderr, "Logging setup error: %v\n", err)
		return err
	}
	defer logging.Sync()

	log := logging.Sugar()

	// Log startup info
	log.Infow("NDAgent starting",
		"version", version.Version,
		"mode", string(logMode),
		"config", configPath,
	)

	// Check if agent is enabled
	if !cfg.IsEnabled() {
		log.Error("Agent is disabled in configuration")
		return fmt.Errorf("agent is disabled in configuration")
	}

	// Log configuration details
	log.Infow("Configuration loaded",
		"server_host", cfg.ServerHost,
		"server_port", cfg.ServerPort,
		"ssl_verify", cfg.SSLVerify,
		"test_mode", cfg.IsTestMode(),
		"webadmin_port", cfg.WebadminPort,
		"webadmin_protocol", cfg.WebadminProtocol,
	)
	log.Infow("Server URIs",
		"ws", cfg.ServerURIWS,
		"check", cfg.ServerURICheck,
		"start", cfg.ServerURIStart,
	)

	// Warn when SSL verification is disabled
	if !cfg.SSLVerify {
		log.Warn("SSL certificate verification is DISABLED. This makes connections vulnerable to man-in-the-middle attacks.")
		log.Warn("For production use, set ssl_verify=true in configuration file.")
	}

	// Log test mode status
	if cfg.IsTestMode() {
		log.Warn("TEST MODE is ENABLED. Dangerous operations (REBOOT, SHUTDOWN) will be blocked.")
	}

	// Setup shutdown coordinator
	shutdown := core.NewShutdownCoordinator()
	shutdown.SetupSignalHandlers()

	// Create lifecycle manager (opens the agent's persistent state store
	// at /var/db/ndagent/state for replay barriers and rebind-token
	// idempotency).
	lifecycle, err := core.NewLifecycleManager(cfg, configPath, shutdown)
	if err != nil {
		log.Errorw("Failed to initialize lifecycle manager", "error", err)
		return err
	}

	// Run the agent lifecycle
	log.Info("Starting agent lifecycle...")
	err = lifecycle.Run(shutdown.Context())

	if err != nil {
		// Check if it's just a shutdown
		if shutdown.IsShutdownRequested() {
			log.Info("Agent shutdown complete")
			return nil
		}
		log.Errorw("Agent lifecycle ended with error", "error", err)
		return err
	}

	log.Info("Agent shutdown complete")
	return nil
}
