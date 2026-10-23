package track

import (
	"fmt"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// A series upgrade asked for outside a track (FIRMWARE_UPGRADE mode=major) is
// judged by the rules a track's series upgrade is judged by: a usable check, the
// hop table's target for the installed series, and the plan read as forMajor
// reads it. A `POST /core/firmware/upgrade` with no offer rebooted a 26.1.9 box.

// MajorOfferVerdict is how a check answers a request for a series upgrade.
type MajorOfferVerdict int

const (
	// MajorNotOffered: the check offers no series upgrade (no
	// upgrade_major_version: sets or a message alone are no offer).
	MajorNotOffered MajorOfferVerdict = iota
	// MajorOffered: the check offers the supported upgrade from the installed
	// series, with its three sets and nothing else pending.
	MajorOffered
	// MajorRefused: the check offers a series upgrade the agent does not ask
	// OPNsense to run.
	MajorRefused
)

func (v MajorOfferVerdict) String() string {
	switch v {
	case MajorNotOffered:
		return "not_offered"
	case MajorOffered:
		return "offered"
	case MajorRefused:
		return "refused"
	}
	return fmt.Sprintf("verdict(%d)", int(v))
}

// JudgeMajorOffer judges a usable check (UsableCheck) for a series upgrade from
// installedSeries. target is the hop table's target for that series, "" when the
// table has none, and why says what a refusal refuses.
func JudgeMajorOffer(st *opnapi.FirmwareUpgradeStatus, installedSeries string) (verdict MajorOfferVerdict, target, why string) {
	plan := NewPlan(st)
	if plan.Major == "" {
		return MajorNotOffered, "", ""
	}
	target, ok := HopTarget(installedSeries)
	if !ok {
		return MajorRefused, "", fmt.Sprintf("the check offers %s, and the agent runs no series upgrade from %q", plan.Major, installedSeries)
	}
	switch kind, h := plan.forMajor(target); kind {
	case majorNoOffer:
		return MajorNotOffered, target, ""
	case majorHeld:
		return MajorRefused, target, h.Why
	}
	return MajorOffered, target, ""
}

// UsableCheck says why a finished check cannot be judged: it left no result, it
// describes another release than the installed one, or it could not use the
// mirror. The ABI it ran against is the plan's business (JudgeMajorOffer).
func UsableCheck(st *opnapi.FirmwareUpgradeStatus) error { return usable(st) }
