package core

import (
	"context"
	"time"

	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/network"
	"github.com/netdefense-io/ndagent/internal/opnapi"
	"github.com/netdefense-io/ndagent/internal/tasks"
	"github.com/netdefense-io/ndagent/pkg/version"
)

// decommissionRunner is the indirection point for tests; production
// builds the real sequence in internal/tasks.
var decommissionRunner = func(
	ctx context.Context,
	apiClient *opnapi.Client,
	packageName string,
	shutdown func(),
	deletedAt, kid string,
) error {
	return tasks.NewDecommissioner(apiClient, packageName, shutdown).Run(ctx, deletedAt, kid)
}

// runDecommission tears this device down after a verified tombstone.
//
// It runs in Phase 1, before any WebSocket phase, because everything it
// needs is local: the OPNsense API credentials from ndagent.conf and the
// package name stamped into the binary at build time. There is nothing
// to report to — the device row is gone — so the only record is
// /var/log/ndagent-decommission.log and syslog.
//
// The context passed in is the agent's shutdown context. That is
// deliberate: an operator stopping the service mid-sequence interrupts
// the retry sleeps, and a restarted agent that still gets DELETED plus a
// valid tombstone simply runs the sequence again.
func (l *LifecycleManager) runDecommission(ctx context.Context, req *network.DecommissionRequiredError) {
	log := logging.Named("lifecycle")

	deletedAt, kid := "", ""
	if req != nil && req.Tombstone != nil {
		deletedAt = req.Tombstone.DeletedAt
		kid = req.Tombstone.Kid
	}

	log.Warnw("Device was permanently deleted; starting self-decommission",
		"device_uuid", l.cfg.DeviceUUID,
		"deleted_at", deletedAt,
		"tombstone_kid", kid,
		"log", tasks.DecommissionLogPath,
	)
	_ = l.status.MarkDisconnected("device deleted; decommissioning")

	var apiClient *opnapi.Client
	if l.cfg.HasAPICreds() {
		apiClient = opnapi.NewClient(
			l.cfg.OPNsenseAPIURL,
			l.cfg.APIKey,
			l.cfg.APISecret,
			true, // Always skip TLS verification for localhost API
		)
	} else {
		log.Warn("No OPNsense API credentials configured; decommission will skip managed-object cleanup and go straight to uninstall")
	}

	started := time.Now()
	if err := decommissionRunner(ctx, apiClient, version.PackageName, l.shutdown.RequestShutdown, deletedAt, kid); err != nil {
		log.Errorw("Self-decommission could not complete the uninstall step",
			"error", err,
			"log", tasks.DecommissionLogPath,
			"elapsed", time.Since(started),
		)
		return
	}
	log.Warnw("Self-decommission handed off to the uninstall helper",
		"elapsed", time.Since(started),
		"log", tasks.DecommissionLogPath,
	)
}
