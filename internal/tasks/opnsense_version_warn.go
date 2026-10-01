package tasks

// opnsense_version_warn.go — visibility for the OPNsense 26.1.11 floor.
//
// This WARNS. It never blocks a sync, by operator decision: a device below
// the floor must still do everything it can, and the user is told rather
// than stopped. It exists because the alternative was shipping a known
// SILENT failure — on 25.x a VPN teardown strands its auto firewall rules,
// with no error, no warning, and a task that reports COMPLETED — or a
// weaker guarantee than the gates claim: on 26.1.0 to 26.1.10 some privileges
// the admin-equivalence catalog treats as ordinary can lead to administrator
// rights, because the upstream fixes the catalog assumes are not there yet. The
// gates count those privileges as administrator-equivalent on such a device (see
// opnapi.ElevateFloorDependentPrivsBelowFloor); the sync still runs.

import (
	"context"
	"fmt"
	"sync"

	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// unsupportedVersionConsequence is the concrete, user-visible effect of
// running below the 26.1 series, stated so someone reading the log knows what to
// go and look for on the device. "Unsupported version" on its own tells
// nobody anything actionable.
const unsupportedVersionConsequence = "removing a VPN network from this device can leave its auto-generated NetDefense firewall rules behind, " +
	"attached to a WireGuard interface group that no longer exists; look for rules described [nd-vpn:<network>] after detaching a VPN"

// unsupportedPatchConsequence is the same for a 26.1 release before the floor's
// patch.
const unsupportedPatchConsequence = "some OPNsense privileges that are ordinary from 26.1.11 can lead to administrator rights on this release, " +
	"because the privilege-escalation fixes OPNsense shipped in 26.1.11 are missing; NetDefense therefore counts them as administrator-equivalent here, " +
	"so an element that grants one, or changes an account or group that holds one, needs Superuser clearance; update OPNsense to 26.1.11 or later"

// unknownReleaseConsequence is what an unreadable release might mean, for
// either band.
const unknownReleaseConsequence = unsupportedVersionConsequence + "; and on a 26.1 release before 26.1.11, " + unsupportedPatchConsequence

// unsupportedConsequenceFor picks the consequence that applies to a release
// that is below the floor: a release of an older series strands VPN rules, one
// of the 26.1 series before the floor's patch has the privilege fixes missing.
func unsupportedConsequenceFor(release opnapi.ProductRelease) string {
	if !release.AtLeast(opnapi.MinSupportedOPNsenseMajor, opnapi.MinSupportedOPNsenseMinor, 0) {
		return unsupportedVersionConsequence
	}
	return unsupportedPatchConsequence
}

// versionWarnState tracks what has already been said, so the warning is
// visible without becoming noise.
//
// Once the release is known to be supported, nothing is checked again —
// OPNsense versions only move forward, so that determination cannot become
// wrong. Once every source has failed, nothing is checked again either: the
// question was asked and answered "unknown", and asking on every sync would
// only repeat the failure. Below the floor the check repeats (an in-place
// upgrade can change the answer without an agent restart) but each category is
// logged at most once per agent process.
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
// The two cases are worded differently on purpose. A message that reads like
// "your device is too old" when the truth is "we could not tell" trains people
// to ignore both. So the unknown case says what is unknown, and never asserts
// the device is out of date.
//
// Best-effort throughout: any failure here is itself the unknown case and
// never propagates to the caller. A cancelled context is not that case — it
// says nothing about the device — so it records nothing and the next sync asks
// again.
func warnIfOPNsenseBelowFloor(ctx context.Context, client *opnapi.Client) {
	if client == nil {
		return
	}

	opnsenseVersionWarnings.mu.Lock()
	defer opnsenseVersionWarnings.mu.Unlock()

	if opnsenseVersionWarnings.knownSupported || opnsenseVersionWarnings.warnedUnknown {
		return
	}

	log := logging.Named("SYNC_API")

	release, err := client.InstalledRelease(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		opnsenseVersionWarnings.warnedUnknown = true
		log.Warnw("Could not determine the OPNsense release, so NDAgent cannot confirm this device meets its supported minimum. This is NOT a statement that the device is out of date — only that the check did not complete. If it is in fact below the minimum, "+unknownReleaseConsequence,
			"minimum_supported", minimumSupportedRelease(),
			"error", err,
		)
		return
	}

	if release.AtLeast(opnapi.MinSupportedOPNsenseMajor, opnapi.MinSupportedOPNsenseMinor, opnapi.MinSupportedOPNsensePatch) {
		opnsenseVersionWarnings.knownSupported = true
		return
	}

	if !opnsenseVersionWarnings.warnedUnsupported {
		opnsenseVersionWarnings.warnedUnsupported = true
		log.Warnw("This device runs an OPNsense release below NDAgent's supported minimum. Configuration sync still runs and does everything it can, but "+unsupportedConsequenceFor(release),
			"opnsense_version", release.String(),
			"minimum_supported", minimumSupportedRelease(),
		)
	}
}

// minimumSupportedRelease renders the floor for log fields.
func minimumSupportedRelease() string {
	return fmt.Sprintf("%d.%d.%d", opnapi.MinSupportedOPNsenseMajor, opnapi.MinSupportedOPNsenseMinor, opnapi.MinSupportedOPNsensePatch)
}
