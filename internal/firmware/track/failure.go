package track

// FailureDetail is the value under FailureKey in the signed response of a FAILED
// task, beside `status` and `message` and never inside `message`: the release
// the failed step was moving to, a reason, and the pin in force when it failed.
// Each is optional and at least one is present. The control plane counts the
// failure against Target, so an agent that cannot name it leaves it out rather
// than guess.
//
// A failed series upgrade also carries Kind ("major") and Notes, and then Target
// is the series: the failure counts against the series, and blocks it in the
// tracks after this one, not against the minor release the track was sending. A
// step that carried `major` but ran the ordinary minor update fails on the
// approved minor with no Kind.
type FailureDetail struct {
	Target        string
	Reason        string
	PinnedVersion string
	Kind          string
	Notes         []string
}

// Empty reports whether the detail carries nothing, in which case the response
// has no side-channel at all.
func (d FailureDetail) Empty() bool {
	return d.Target == "" && d.Reason == "" && d.PinnedVersion == "" && d.Kind == "" && len(d.Notes) == 0
}

// Map is the detail as the wire object, or nil when it is empty. A value the
// agent does not have is omitted, never null and never "".
func (d FailureDetail) Map() map[string]interface{} {
	if d.Empty() {
		return nil
	}
	m := map[string]interface{}{}
	if d.Target != "" {
		m["target"] = d.Target
	}
	if d.Reason != "" {
		m["reason"] = d.Reason
	}
	if d.PinnedVersion != "" {
		m["pinned_version"] = d.PinnedVersion
	}
	if d.Kind != "" {
		m["kind"] = d.Kind
	}
	if len(d.Notes) > 0 {
		m["notes"] = append([]string(nil), d.Notes...)
	}
	return m
}

// ValidateFailureDetail is the agent's port of validate_firmware_track_failure.
// detail is the decoded value of the key. A nil expect skips the checks against
// the dispatch; a non-nil one is the dispatch (an empty Major says the payload
// carried none, so a kind is refused).
func ValidateFailureDetail(detail interface{}, expect *Expect) *Fault {
	m, ok := detail.(map[string]interface{})
	if !ok {
		return fault("not_an_object", "the failure detail must be an object")
	}
	for key := range m {
		switch key {
		case "target", "reason", "pinned_version", "kind", "notes":
		default:
			return fault("unknown_key", "unknown key %q", key)
		}
	}
	if len(m) == 0 {
		return fault("empty_detail", "the failure detail must carry a target, a reason or a pinned version")
	}
	if v, ok := m["target"]; ok {
		if s, isString := v.(string); !isString || !ValidVersion(s) {
			return fault("bad_target", "target must be a release name, or omitted")
		}
	}
	if v, ok := m["pinned_version"]; ok {
		if s, isString := v.(string); !isString || !ValidVersion(s) {
			return fault("bad_pinned_version", "pinned_version must be a release name, or omitted")
		}
	}
	if v, ok := m["reason"]; ok {
		if s, isString := v.(string); !isString || !ValidReason(s) {
			return fault("bad_reason", "reason must be one of the closed set")
		}
	}
	_, hasKind := m["kind"]
	if hasKind {
		if kind, isString := m["kind"].(string); !isString || kind != KindMajor {
			return fault("bad_kind", "kind must be %q, or omitted", KindMajor)
		}
		target, hasTarget := m["target"].(string)
		if f := checkKindTarget(expect, target, hasTarget, "target"); f != nil {
			return f
		}
	}
	if v, ok := m["notes"]; ok {
		if !hasKind {
			return fault("notes_without_kind", "notes is only valid with a kind")
		}
		if f := checkNotesValue(v); f != nil {
			return f
		}
	}
	if expect != nil && expect.Approved != nil && !hasKind {
		if target, ok := m["target"].(string); ok {
			if series, _ := SeriesOf(target); expect.Approved[series] != target {
				return fault("target_not_dispatched", "target is not the release the task dispatched for its series")
			}
		}
	}
	return nil
}

// checkNotesValue judges a decoded `notes`, which is a []interface{} when the
// detail was decoded from JSON (a stored answer replayed by the drain) and a
// []string when the engine built it.
func checkNotesValue(v interface{}) *Fault {
	var list []interface{}
	switch notes := v.(type) {
	case []interface{}:
		list = notes
	case []string:
		list = make([]interface{}, len(notes))
		for i, n := range notes {
			list[i] = n
		}
	default:
		return fault("bad_notes", "notes must be a list of at most %d distinct tokens of the closed set, or omitted", notesMax)
	}
	if !checkNotes(list) {
		return fault("bad_notes", "notes must be a list of at most %d distinct tokens of the closed set, or omitted", notesMax)
	}
	return nil
}

// CleanFailureDetail returns the detail in the shape the signed response may
// carry, or false when it is not a valid one. It takes the detail as a map of
// strings (a handler building it) or as the generic object a stored response
// decodes into (the drain replaying it). It knows no dispatch, so it judges the
// detail by itself: a kind still needs a target that is a series a hop leads to.
func CleanFailureDetail(detail interface{}) (map[string]interface{}, bool) {
	var generic interface{} = detail
	if typed, ok := detail.(map[string]string); ok {
		m := make(map[string]interface{}, len(typed))
		for k, v := range typed {
			m[k] = v
		}
		generic = m
	}
	if ValidateFailureDetail(generic, nil) != nil {
		return nil, false
	}
	return generic.(map[string]interface{}), true
}
