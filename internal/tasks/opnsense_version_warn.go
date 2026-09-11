package tasks

// opnsense_version_warn.go — visibility for the OPNsense 26.1 floor.
//
// This WARNS. It never blocks a sync, by operator decision: a device below
// the floor must still do everything it can, and the user is told rather
// than stopped. It exists because the alternative was shipping a known
// SILENT failure — on 25.x a VPN teardown strands its auto firewall rules,
// with no error, no warning, and a task that reports COMPLETED.

import (
	"context"
	"sync"

	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// unsupportedVersionConsequence is the concrete, user-visible effect of
// running below the floor, stated so someone reading the log knows what to
// go and look for on the device. "Unsupported version" on its own tells
// nobody anything actionable.
const unsupportedVersionConsequence = "removing a VPN network from this device can leave its auto-generated NetDefense firewall rules behind, " +
	"attached to a WireGuard interface group that no longer exists; look for rules described [nd-vpn:<network>] after detaching a VPN"

// versionWarnState tracks what has already been said, so the warning is
// visible without becoming noise.
//
// Once the release is known to be supported, nothing is checked again —
// OPNsense versions only move forward, so that determination cannot become
// wrong. Below the floor or unknown, the check repeats (an upgrade, or a
// transient API failure, can change the answer) but each category is logged
// at most once per agent process.
type versionWarnState struct {
	mu                sync.Mutex
	knownSupported    bool
	warnedUnsupported bool
	warnedUnknown     bool
}

var opnsenseVersionWarnings versionWarnState

// warnIfOPNsenseBelowFloor reads the installed OPNsense release and logs a
// WARN when it is below NDAgent's supported floor, or when it cannot be
// determined at all.
//
// The two cases are worded differently on purpose. Unknown is expected to be
// common — any transient API failure produces it — and a message that reads
// like "your device is too old" when the truth is "we could not tell" trains
// people to ignore both. So the unknown case says what is unknown, and never
// asserts the device is out of date.
//
// Best-effort throughout: any failure here is itself the unknown case and
// never propagates to the caller.
func warnIfOPNsenseBelowFloor(ctx context.Context, client *opnapi.Client) {
	if client == nil {
		return
	}

	opnsenseVersionWarnings.mu.Lock()
	defer opnsenseVersionWarnings.mu.Unlock()

	if opnsenseVersionWarnings.knownSupported {
		return
	}

	log := logging.Named("SYNC_API")

	release, err := client.GetProductRelease(ctx)
	if err != nil {
		if !opnsenseVersionWarnings.warnedUnknown {
			opnsenseVersionWarnings.warnedUnknown = true
			log.Warnw("Could not determine the OPNsense release, so NDAgent cannot confirm this device meets its supported minimum. This is NOT a statement that the device is out of date — only that the check did not complete. If it is in fact below the minimum, "+unsupportedVersionConsequence,
				"minimum_supported", minimumSupportedRelease(),
				"error", err,
			)
		}
		return
	}

	if release.AtLeast(opnapi.MinSupportedOPNsenseMajor, opnapi.MinSupportedOPNsenseMinor) {
		opnsenseVersionWarnings.knownSupported = true
		return
	}

	if !opnsenseVersionWarnings.warnedUnsupported {
		opnsenseVersionWarnings.warnedUnsupported = true
		log.Warnw("This device runs an OPNsense release below NDAgent's supported minimum. Configuration sync still runs and does everything it can, but "+unsupportedVersionConsequence,
			"opnsense_version", release.String(),
			"minimum_supported", minimumSupportedRelease(),
		)
	}
}

// minimumSupportedRelease renders the floor for log fields.
func minimumSupportedRelease() string {
	return opnapi.ProductRelease{
		Major: opnapi.MinSupportedOPNsenseMajor,
		Minor: opnapi.MinSupportedOPNsenseMinor,
	}.String()
}
