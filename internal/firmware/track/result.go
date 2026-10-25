package track

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"strconv"
)

// Result is the message of a COMPLETED FIRMWARE_TRACK task. An empty version is
// omitted from the wire, never sent as null or "".
type Result struct {
	// Action and Track echo the dispatched payload, never the agent's own local
	// state, which a track change made while the task was in flight can leave stale.
	Action string
	Track  string

	Outcome string
	Reason  string

	// Drift says the pin was found changed outside NetDefense.
	Drift bool
	// ReinstallEntries is how many same-version reinstall entries the check
	// listed. Information only: it never holds a step.
	ReinstallEntries int

	FromVersion   string
	ToVersion     string
	TargetVersion string
	PinnedVersion string

	// Kind is KindMajor on an answer of a series upgrade, a hold included, and ""
	// otherwise; under it TargetVersion is the series. Notes are the tokens the
	// attempt found so far (the closed set of contract.go), only ever with Kind.
	// Both are omitted from the wire when empty.
	Kind  string
	Notes []string

	// Revision is the fingerprint of the folder content the answer is about (see
	// revision.go); "" is omitted. Only an advance whose dispatch carried
	// revisions reports one.
	Revision string
}

type wireResult struct {
	Action           string   `json:"action"`
	Track            string   `json:"track"`
	Outcome          string   `json:"outcome"`
	Reason           string   `json:"reason"`
	Drift            bool     `json:"drift"`
	ReinstallEntries int      `json:"reinstall_entries"`
	FromVersion      string   `json:"from_version,omitempty"`
	ToVersion        string   `json:"to_version,omitempty"`
	TargetVersion    string   `json:"target_version,omitempty"`
	PinnedVersion    string   `json:"pinned_version,omitempty"`
	Kind             string   `json:"kind,omitempty"`
	Notes            []string `json:"notes,omitempty"`
	Revision         string   `json:"revision,omitempty"`
}

// Message is the result as the compact JSON text a task carries. The agent
// builds only valid results: what it would have to send invalid is refused here
// rather than on the wire. It judges the result by itself, without the dispatch;
// MessageFor judges it against the payload the task was dispatched with.
func (r Result) Message() (string, error) { return r.message(nil) }

// MessageFor is Message for a result built for the task dispatched with p: what
// the control plane checks against the signed payload (the action, the track, the
// release a target_version may name, that a kind needs a dispatched major and
// names exactly it) is checked here too, so a result the control plane would
// refuse is a bug found in the agent and not a lost answer.
func (r Result) MessageFor(p Payload) (string, error) {
	return r.message(&Expect{Action: p.Action, Track: p.Track, Approved: p.Approved, Major: p.Major, Revisions: p.Revisions})
}

func (r Result) message(expect *Expect) (string, error) {
	text, err := json.Marshal(wireResult(r))
	if err != nil {
		return "", err
	}
	if f := ValidateResult(string(text), expect); f != nil {
		return "", f
	}
	return string(text), nil
}

// Expect is what the control plane takes from the signed dispatch and checks
// the result against. A nil *Expect skips every check against the dispatch; a
// non-nil one is the dispatch itself, so an empty Major says the payload carried
// none and a kind is refused, as the shared validator refuses it when it is handed
// no major.
type Expect struct {
	Action   string
	Track    string
	Approved map[string]string
	// Major is the series the payload asked for ("" when it asked for none).
	Major string
	// Revisions is the payload's revisions map: a result may name a revision only
	// when the dispatch carried some.
	Revisions map[string]string
}

// ValidateResult is the agent's port of validate_firmware_track_result. text is
// the task message. A nil expect skips the checks against the dispatch.
func ValidateResult(text string, expect *Expect) *Fault {
	if len(text) > ResultMaxSize {
		return fault("too_large", "the result is over %d bytes", ResultMaxSize)
	}
	obj, f := parseStrictObject(text)
	if f != nil {
		return f
	}

	required := []string{"action", "track", "outcome", "reason", "drift", "reinstall_entries"}
	versionKeys := []string{"from_version", "to_version", "target_version", "pinned_version"}
	optionalKeys := []string{"kind", "notes", "revision"}
	for key := range obj {
		if !contains(required, key) && !contains(versionKeys, key) && !contains(optionalKeys, key) {
			return fault("unknown_key", "unknown key %q", key)
		}
	}
	for _, key := range required {
		if _, ok := obj[key]; !ok {
			return fault("missing_key", "missing key %q", key)
		}
	}

	enums := []struct {
		key     string
		allowed []string
	}{
		{"action", actions},
		{"track", tracks},
		{"outcome", []string{OutcomeSuccess, OutcomeNoop, OutcomeHeld, OutcomeReleased}},
		{"reason", reasons},
	}
	values := make(map[string]string, 4)
	for _, e := range enums {
		var s string
		if err := json.Unmarshal(obj[e.key], &s); err != nil || !contains(e.allowed, s) {
			return fault("bad_enum", "%q must be one of %v", e.key, e.allowed)
		}
		values[e.key] = s
	}

	held := contains(heldReasons, values["reason"])
	released := contains(releasedReasons, values["reason"])
	if (values["outcome"] == OutcomeHeld) != held || (values["outcome"] == OutcomeReleased) != released {
		return fault("reason_outcome_mismatch", "reason %q does not fit outcome %q", values["reason"], values["outcome"])
	}

	var drift bool
	if err := json.Unmarshal(obj["drift"], &drift); err != nil || string(bytes.TrimSpace(obj["drift"])) == "null" {
		return fault("bad_drift", "drift must be a boolean")
	}

	if !integerInRange(obj["reinstall_entries"], 0, ReinstallEntriesMax) {
		return fault("bad_reinstall_entries", "reinstall_entries must be an integer between 0 and %d", ReinstallEntriesMax)
	}

	versions := make(map[string]string, 4)
	for _, key := range versionKeys {
		raw, ok := obj[key]
		if !ok {
			continue
		}
		var v string
		if err := json.Unmarshal(raw, &v); err != nil || !ValidVersion(v) {
			return fault("bad_version", "%q must be a release name, or omitted", key)
		}
		versions[key] = v
	}

	// A series upgrade's answer. The checks run in the order the shared validator
	// makes them, so a result with two faults is refused as the same one.
	rawKind, hasKind := obj["kind"]
	if hasKind {
		if !isKindMajor(rawKind) {
			return fault("bad_kind", "kind must be %q, or omitted", KindMajor)
		}
		if values["action"] != ActionAdvance {
			return fault("kind_not_advance", "kind is only valid for an advance")
		}
		if values["outcome"] == OutcomeReleased {
			return fault("kind_outcome_mismatch", "kind does not fit a released outcome")
		}
		if f := checkKindTarget(expect, versions["target_version"], versions["target_version"] != "", "target_version"); f != nil {
			return f
		}
	}
	if raw, ok := obj["notes"]; ok {
		if !hasKind {
			return fault("notes_without_kind", "notes is only valid with a kind")
		}
		if f := validateNotes(raw); f != nil {
			return f
		}
	}

	_, hasRevision := obj["revision"]
	if raw, ok := obj["revision"]; ok {
		var v string
		if err := json.Unmarshal(raw, &v); err != nil || !ValidRevision(v) {
			return fault("bad_revision", "revision must be a 64-digit lowercase hex fingerprint, or omitted")
		}
		switch {
		case hasKind:
			return fault("revision_with_kind", "revision does not go with a series upgrade's answer")
		case values["action"] != ActionAdvance:
			return fault("revision_not_advance", "revision is only valid for an advance")
		case values["outcome"] == OutcomeReleased:
			return fault("revision_outcome_mismatch", "revision does not fit a released outcome")
		case expect != nil && len(expect.Revisions) == 0:
			return fault("revision_not_dispatched", "the dispatch carried no revisions")
		}
	}

	if values["reason"] == ReasonHeldRevisionMismatch {
		switch {
		case values["action"] != ActionAdvance || (expect != nil && len(expect.Revisions) == 0):
			return fault("reason_not_dispatched", "held_revision_mismatch answers an advance dispatched with revisions")
		case !hasRevision:
			return fault("revision_missing", "held_revision_mismatch names the revision it saw")
		}
	}
	if expect != nil {
		if expect.Action != "" && values["action"] != expect.Action {
			return fault("action_mismatch", "the result's action is not the dispatched one")
		}
		if expect.Track != "" && values["track"] != expect.Track {
			return fault("track_mismatch", "the result's track is not the dispatched one")
		}
		if expect.Approved != nil && !hasKind {
			if target, ok := versions["target_version"]; ok {
				if series, _ := SeriesOf(target); expect.Approved[series] != target {
					return fault("target_not_dispatched", "target_version is not the release the task dispatched for its series")
				}
			}
		}
	}
	return nil
}

var integerRE = regexp.MustCompile(`\A(?:0|[1-9][0-9]*)\z`)

// integerInRange reports whether raw is a JSON integer literal (no sign, no
// fraction, no exponent) within the bounds.
func integerInRange(raw json.RawMessage, lo, hi int) bool {
	text := string(bytes.TrimSpace(raw))
	if text == "-0" || !integerRE.MatchString(trimMinus(text)) {
		return false
	}
	n, err := strconv.Atoi(text)
	return err == nil && n >= lo && n <= hi
}

func trimMinus(s string) string {
	if len(s) > 1 && s[0] == '-' {
		return s[1:]
	}
	return s
}

// parseStrictObject parses the text as one JSON object, refusing what a lenient
// parser lets through: a repeated key, NaN or Infinity, text after the object.
// Values stay raw so each is typed by its own rule.
func parseStrictObject(text string) (map[string]json.RawMessage, *Fault) {
	trimmed := bytes.TrimSpace([]byte(text))
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, fault("not_an_object", "the result is not a JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	if _, err := dec.Token(); err != nil { // the opening brace
		return nil, fault("not_strict_json", "the result is not valid JSON")
	}
	obj := make(map[string]json.RawMessage)
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return nil, fault("not_strict_json", "the result is not valid JSON")
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, fault("not_strict_json", "the result is not valid JSON")
		}
		if _, dup := obj[key]; dup {
			return nil, fault("not_strict_json", "repeated key %q", key)
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, fault("not_strict_json", "the result is not valid JSON")
		}
		obj[key] = raw
	}
	if _, err := dec.Token(); err != nil { // the closing brace
		return nil, fault("not_strict_json", "the result is not valid JSON")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fault("not_strict_json", "text after the result object")
	}
	return obj, nil
}
