package track

import (
	"bytes"
	"encoding/json"
)

// The parts of the result and failure-detail validators that the two share: what
// a `kind` is, what its target has to be, and what a `notes` list may hold. They
// are the agent's port of validate_firmware_track_result and
// validate_firmware_track_failure in NDDataModels, and the faults they name are
// the stable tags of the shared vectors.

// isKindMajor reports whether a decoded `kind` is exactly "major". null, an empty
// string, another case and another type are not: omit the key instead.
func isKindMajor(raw json.RawMessage) bool {
	var kind string
	if err := json.Unmarshal(bytes.TrimSpace(raw), &kind); err != nil {
		return false
	}
	return kind == KindMajor
}

// checkKindTarget judges the target of an answer that carries a kind: it is
// required, and it is the series the task was dispatched with, not the approved
// minor and not a release of the series. Without the dispatch (a nil expect: a
// stored detail replayed by the drain, a result judged by itself) it can only be
// a series some hop leads to.
func checkKindTarget(expect *Expect, target string, present bool, key string) *Fault {
	if expect != nil && expect.Major == "" {
		return fault("kind_not_dispatched", "kind is only valid for a task dispatched with a major")
	}
	if !present {
		return fault("kind_target_missing", "a kind needs a %s", key)
	}
	if expect != nil {
		if target != expect.Major {
			return fault("kind_target_mismatch", "%s is not the series the task was dispatched with", key)
		}
		return nil
	}
	if _, ok := HopSource(target); !ok {
		return fault("kind_target_mismatch", "%s is not a series a hop leads to", key)
	}
	return nil
}

// validateNotes judges a raw `notes` value: a non-empty list of at most notesMax
// distinct tokens of the closed set. null, a string, an empty list, a repeat and
// an entry that is not a token are all refused (omit the key when there is
// nothing to note).
func validateNotes(raw json.RawMessage) *Fault {
	var list []interface{}
	if err := json.Unmarshal(bytes.TrimSpace(raw), &list); err != nil || !checkNotes(list) {
		return fault("bad_notes", "notes must be a list of at most %d distinct tokens of the closed set, or omitted", notesMax)
	}
	return nil
}
