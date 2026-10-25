// Package track is the agent's side of the FIRMWARE_TRACK task: staged OPNsense
// updates, where a device is held at a release by OPNsense's own firmware
// flavour setting and moved to the release its track approved only when a
// window says so.
//
// The wire contract (payload, result, failure detail, release names, dead-man
// figure) is NDDataModels' (Schema.py, tests/fixtures/firmware-track); this
// file is the agent's reading of it and testdata/firmware-track holds the
// shared vectors it is tested against. The engine (engine*.go) is the pin
// lifecycle: enroll, advance, unenroll, the reconcile of a pin that changed
// outside NetDefense, and the releases the agent makes by itself.
package track

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Task actions and track names, as NDManager seals them (lowercase).
const (
	ActionEnroll   = "enroll"
	ActionAdvance  = "advance"
	ActionUnenroll = "unenroll"

	TrackFast    = "fast"
	TrackRegular = "regular"
	TrackStable  = "stable"
)

// Outcomes an agent reports in a COMPLETED task. FAILED and FAILED_NO_RESPONSE
// are the control plane's.
const (
	OutcomeSuccess  = "success"
	OutcomeNoop     = "noop"
	OutcomeHeld     = "held"
	OutcomeReleased = "released"
)

// The closed set of reasons an agent may give.
const (
	ReasonAtOrAboveTarget          = "at_or_above_target"
	ReasonTargetNotYetOffered      = "target_not_yet_offered"
	ReasonSeriesNotApproved        = "series_not_approved"
	ReasonPinDrift                 = "pin_drift"
	ReasonMajorOffered             = "major_offered"
	ReasonHeldCheckFailed          = "held_check_failed"
	ReasonHeldReleaseFolderMissing = "held_release_folder_missing"
	ReasonReleaseFolderUnavailable = "release_folder_unavailable"
	ReasonHeldDowngradeRisk        = "held_downgrade_risk"
	ReasonHeldUnsupportedEdition   = "held_unsupported_edition"
	ReasonHeldCustomFlavour        = "held_custom_flavour"
	ReasonHeldFirmwareBusy         = "held_firmware_busy"
	ReasonHeldUnexpectedPlan       = "held_unexpected_plan"
	ReasonHeldRebootPending        = "held_reboot_pending"
	ReasonHeldTestMode             = "held_test_mode"
	// The five holds a series upgrade added. held_late_dispatch is for every
	// advance, a minor update as much as a series upgrade.
	ReasonHeldLateDispatch        = "held_late_dispatch"
	ReasonHeldInsufficientSpace   = "held_insufficient_space"
	ReasonHeldHAMember            = "held_ha_member"
	ReasonHeldAgentABIUnavailable = "held_agent_abi_unavailable"
	ReasonHeldUpgradeAborted      = "held_upgrade_aborted"
	ReasonHeldRevisionMismatch    = "held_revision_mismatch"
	ReasonApplied                 = "applied"
	ReasonEnrolled                = "enrolled"
	ReasonUnenrolled              = "unenrolled"
)

var (
	actions = []string{ActionEnroll, ActionAdvance, ActionUnenroll}
	tracks  = []string{TrackFast, TrackRegular, TrackStable}

	reasons = []string{
		ReasonAtOrAboveTarget, ReasonTargetNotYetOffered, ReasonSeriesNotApproved, ReasonPinDrift,
		ReasonMajorOffered, ReasonHeldCheckFailed, ReasonHeldReleaseFolderMissing,
		ReasonReleaseFolderUnavailable, ReasonHeldDowngradeRisk, ReasonHeldUnsupportedEdition,
		ReasonHeldCustomFlavour, ReasonHeldFirmwareBusy, ReasonHeldUnexpectedPlan,
		ReasonHeldRebootPending, ReasonHeldTestMode, ReasonHeldLateDispatch, ReasonHeldInsufficientSpace,
		ReasonHeldHAMember, ReasonHeldAgentABIUnavailable, ReasonHeldUpgradeAborted, ReasonHeldRevisionMismatch,
		ReasonApplied, ReasonEnrolled, ReasonUnenrolled,
	}

	// heldReasons go with the held outcome and only those do.
	heldReasons = []string{
		ReasonMajorOffered, ReasonHeldCheckFailed, ReasonHeldReleaseFolderMissing,
		ReasonHeldDowngradeRisk, ReasonHeldUnsupportedEdition, ReasonHeldCustomFlavour,
		ReasonHeldFirmwareBusy, ReasonHeldUnexpectedPlan, ReasonHeldRebootPending,
		ReasonHeldTestMode, ReasonHeldLateDispatch, ReasonHeldInsufficientSpace, ReasonHeldHAMember,
		ReasonHeldAgentABIUnavailable, ReasonHeldUpgradeAborted, ReasonHeldRevisionMismatch,
	}

	// releasedReasons go with the released outcome and only that does.
	releasedReasons = []string{ReasonReleaseFolderUnavailable}
)

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// ValidAction and ValidTrack report whether s is one of the wire names.
func ValidAction(s string) bool { return contains(actions, s) }
func ValidTrack(s string) bool  { return contains(tracks, s) }

// ValidReason reports whether s is a reason an agent may give.
func ValidReason(s string) bool { return contains(reasons, s) }

// Release names on the OPNsense mirror. `26.7` is a series and also the GA
// release's own directory, `26.7.3` a release, `24.7.12_2` a hotfix directory.
// Only the mirror's own spelling is valid: no number has a leading zero and none
// of minor, patch or hotfix is 0, so a second spelling of a name cannot order like
// the first yet compare unequal as text. The patterns carry no anchor; the full
// match is the wrapper below. Digits are [0-9], never \d.
const (
	SeriesPattern  = `[0-9]{2}\.[1-9][0-9]?`
	VersionPattern = `[0-9]{2}\.[1-9][0-9]?(?:\.[1-9][0-9]?)?(?:_[1-9][0-9]{0,2})?`
)

var (
	seriesRE   = regexp.MustCompile(`\A(?:` + SeriesPattern + `)\z`)
	versionRE  = regexp.MustCompile(`\A(?:` + VersionPattern + `)\z`)
	partsRE    = regexp.MustCompile(`\A([0-9]{2})\.([1-9][0-9]?)(?:\.([1-9][0-9]?))?(?:_([1-9][0-9]{0,2}))?\z`)
	seriesOfRE = regexp.MustCompile(`\A` + SeriesPattern)
)

// ValidSeries reports whether s is a series such as 26.7.
func ValidSeries(s string) bool { return seriesRE.MatchString(s) }

// ValidVersion reports whether s names a release directory: 26.7, 26.7.3,
// 26.7.3_11, 24.7.12_2.
func ValidVersion(s string) bool { return versionRE.MatchString(s) }

// SeriesOf is the series a release belongs to: 26.7.3_11 -> 26.7.
func SeriesOf(version string) (string, bool) {
	if !ValidVersion(version) {
		return "", false
	}
	return seriesOfRE.FindString(version), true
}

// Key orders release names: (year, minor, patch, hotfix) with a missing patch
// or hotfix as 0. Compare releases only through it, never as text, so 26.7.10
// sorts after 26.7.9 and 26.7.3_11 after 26.7.3_2.
type Key [4]int

// ParseKey returns the sort key of a release name.
func ParseKey(version string) (Key, bool) {
	m := partsRE.FindStringSubmatch(version)
	if m == nil {
		return Key{}, false
	}
	var k Key
	for i := 0; i < 4; i++ {
		if m[i+1] != "" {
			n, err := strconv.Atoi(m[i+1])
			if err != nil {
				return Key{}, false
			}
			k[i] = n
		}
	}
	return k, true
}

// Compare returns -1, 0 or 1.
func (k Key) Compare(o Key) int {
	for i := range k {
		switch {
		case k[i] < o[i]:
			return -1
		case k[i] > o[i]:
			return 1
		}
	}
	return 0
}

// SameRelease reports whether two keys name the same x.y.z, whatever their hotfix.
func (k Key) SameRelease(o Key) bool { return k[0] == o[0] && k[1] == o[1] && k[2] == o[2] }

// AtOrAbove is the key comparison of an installed release against a target:
// true when installed is the target, a hotfix revision of it, or later. It is
// only the first half of the advance decision: when the installed release shares
// the target's x.y.z, the target's directory can offer a newer hotfix revision
// in place, and then the step is an update.
func AtOrAbove(installed, target string) (bool, bool) {
	ik, ok := ParseKey(installed)
	if !ok {
		return false, false
	}
	tk, ok := ParseKey(target)
	if !ok {
		return false, false
	}
	return ik.Compare(tk) >= 0, true
}

// StripHotfix drops a release's _N suffix: 26.7.3_11 -> 26.7.3.
func StripHotfix(version string) string {
	if i := strings.IndexByte(version, '_'); i >= 0 {
		return version[:i]
	}
	return version
}

// The dead-man: after this long without an authenticated contact from an
// ENABLED device (a disabled device is refused at authentication, so it is
// silent), the agent removes its own pin and NDManager drops the device to
// Unmanaged, each on its own clock and without a message.
const (
	DeadManDays    = 30
	DeadManSeconds = DeadManDays * 24 * 60 * 60
)

// DeadManDue reports whether a device silent for the given time is due its
// release: from exactly 30 days on, never below, and never for a negative value
// (a contact stamped in the future by clock skew is not silence).
func DeadManDue(silent time.Duration) bool {
	return silent >= DeadManSeconds*time.Second
}

// Limits of the wire contract.
const (
	// ApprovedMaxEntries bounds the payload's approved map.
	ApprovedMaxEntries = 64
	// ResultMaxSize bounds a result message; the broker cuts a message at 16 KB
	// and a cut document no longer parses.
	ResultMaxSize = 2 * 1024
	// ReinstallEntriesMax bounds the reported count of same-version reinstalls.
	ReinstallEntriesMax = 100000
)

// FailureKey is the top-level key of the signed response of a FAILED task that
// carries the failure detail.
const FailureKey = "firmware_track_failure"

// KindMajor is the one value of the `kind` key of a result and of a failure
// detail: the answer is that of a series upgrade. A minor step carries no kind.
//
// The answer rule: from the moment the agent decides to run a series upgrade
// (A3 of the step sequence), every answer to the step, a hold included, carries
// kind "major", a target_version that is the series and the notes found so far;
// an answer given before that decision is the ordinary step's and carries none of
// the three, even when the payload carried `major`. A FAILED answer carries the
// same three through its detail (kind, target, notes).
const KindMajor = "major"

// The notes of a series upgrade: what the agent found on the way, as a closed set
// of tokens. They are all the contract carries about a repository or a package,
// never a name. The third-party ones are a warning and never a hold.
const (
	NoteBootEnvironmentMade          = "boot_environment_made"
	NoteBootEnvironmentSkippedNoRoom = "boot_environment_skipped_no_room"
	NoteBootEnvironmentOff           = "boot_environment_off"
	NoteBootEnvironmentUnavailable   = "boot_environment_unavailable"
	NoteThirdPartyRepository         = "third_party_repository"
	NoteThirdPartyPackage            = "third_party_package"
)

// notesMax bounds the entries of a notes list. The closed set holds fewer today:
// the bound is room for tokens added later, so a list can never reach it without
// a repeat or an unknown token.
const notesMax = 8

var noteTokens = []string{
	NoteBootEnvironmentMade, NoteBootEnvironmentSkippedNoRoom, NoteBootEnvironmentOff,
	NoteBootEnvironmentUnavailable, NoteThirdPartyRepository, NoteThirdPartyPackage,
}

// addNote appends token to notes unless it is already there: a note is made once
// per attempt however many reads find the same thing.
func addNote(notes []string, token string) []string {
	if contains(notes, token) {
		return notes
	}
	return append(notes, token)
}

// checkNotes judges a decoded notes list the way the shared validator does: a
// non-empty list of at most notesMax distinct tokens of the closed set. It returns
// whether the list is fit to go on the wire.
func checkNotes(list []interface{}) bool {
	if len(list) == 0 || len(list) > notesMax {
		return false
	}
	seen := make(map[string]bool, len(list))
	for _, v := range list {
		s, ok := v.(string)
		if !ok || !contains(noteTokens, s) || seen[s] {
			return false
		}
		seen[s] = true
	}
	return true
}
