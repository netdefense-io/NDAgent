package track

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

// Fault is a refusal of a wire document, with the stable class name the shared
// vectors use for it (the fault tags of payloads.json, results.json and
// failure-details.json).
type Fault struct {
	Kind   string
	Detail string
}

func (f *Fault) Error() string {
	if f.Detail == "" {
		return f.Kind
	}
	return f.Kind + ": " + f.Detail
}

func fault(kind, format string, args ...interface{}) *Fault {
	return &Fault{Kind: kind, Detail: fmt.Sprintf(format, args...)}
}

// Payload is the verified payload of a FIRMWARE_TRACK task.
type Payload struct {
	Action string
	Track  string
	// Approved maps each series the track has a target for to that target. It is
	// required and non-empty for advance and empty for the other two actions.
	Approved map[string]string
	// Revisions maps a series of Approved to the fingerprint of the folder content
	// the track approved for it. A series without an entry is not held to a
	// revision. Present only on an advance, and then non-empty.
	Revisions map[string]string
	// Reboot is true to apply the full update, base and kernel included, and
	// reboot; false applies the userland packages only. Only advance reads it.
	Reboot bool
	// Major asks an advance to upgrade the device to that series, a series that is
	// the target of a row of the hop table ("" for a step without one). It is valid
	// only for an advance with Reboot true and need not be a key of Approved, which
	// the advance still needs: the agent tries the ordinary minor update first.
	Major string
	// BootEnvironmentOff says the device's boot-environment setting is off. The
	// key is valid only beside Major and absent means on, so the zero value is the
	// default.
	BootEnvironmentOff bool
}

// ParsePayload reads a payload the dispatcher decoded into a generic map. The
// key names are matched exactly (a decode into a struct would fold their case),
// an unknown key is refused rather than dropped, and `reboot` is a JSON boolean
// and nothing else. A nil map is a task with no payload.
func ParsePayload(raw map[string]interface{}) (*Payload, *Fault) {
	if raw == nil {
		return nil, fault("not_an_object", "the task has no payload")
	}

	for key := range raw {
		switch key {
		case "action", "track", "approved", "revisions", "reboot", "major", "boot_environment":
		default:
			return nil, fault("unknown_key", "unknown key %q", key)
		}
	}

	p := &Payload{Reboot: true}

	action, present := raw["action"]
	if !present {
		return nil, fault("missing_action", "no action")
	}
	p.Action, _ = action.(string)
	if !ValidAction(p.Action) {
		return nil, fault("bad_action", "action must be one of %v", actions)
	}

	track, present := raw["track"]
	if !present {
		return nil, fault("missing_track", "no track")
	}
	p.Track, _ = track.(string)
	if !ValidTrack(p.Track) {
		return nil, fault("bad_track", "track must be one of %v", tracks)
	}

	if reboot, present := raw["reboot"]; present {
		b, ok := reboot.(bool)
		if !ok {
			return nil, fault("reboot_not_boolean", "reboot must be a boolean")
		}
		p.Reboot = b
	}

	p.Approved = map[string]string{}
	if approved, present := raw["approved"]; present {
		m, ok := approved.(map[string]interface{})
		if !ok {
			return nil, fault("approved_not_object", "approved must be an object")
		}
		if len(m) > ApprovedMaxEntries {
			return nil, fault("too_many_approved_entries", "approved holds more than %d entries", ApprovedMaxEntries)
		}
		// Sorted, so the same payload is always refused for the same entry.
		series := make([]string, 0, len(m))
		for s := range m {
			series = append(series, s)
		}
		sort.Strings(series)
		for _, s := range series {
			version, isString := m[s].(string)
			switch {
			case !ValidSeries(s):
				return nil, fault(nonASCIIOr("bad_series", s), "approved key %q is not a series", s)
			case !isString || !ValidVersion(version):
				return nil, fault(nonASCIIOr("bad_version", version), "approved value for %q is not a release", s)
			}
			if got, _ := SeriesOf(version); got != s {
				return nil, fault("version_outside_series", "release %q does not belong to series %q", version, s)
			}
			p.Approved[s] = version
		}
	}

	if revisions, present := raw["revisions"]; present {
		m, ok := revisions.(map[string]interface{})
		switch {
		case !ok:
			return nil, fault("revisions_not_object", "revisions must be an object")
		case len(m) == 0:
			return nil, fault("revisions_empty", "revisions must not be empty")
		case p.Action != ActionAdvance:
			return nil, fault("revisions_not_allowed", "revisions is only valid for advance")
		}
		series := make([]string, 0, len(m))
		for s := range m {
			series = append(series, s)
		}
		sort.Strings(series)
		p.Revisions = make(map[string]string, len(m))
		for _, s := range series {
			if !ValidSeries(s) {
				return nil, fault("revisions_bad_series", "revisions key %q is not a series", s)
			}
			if _, approved := p.Approved[s]; !approved {
				return nil, fault("revisions_not_approved", "revisions names %q, which approved does not", s)
			}
			value, isString := m[s].(string)
			if !isString || !ValidRevision(value) {
				return nil, fault("revisions_bad_fingerprint", "the revision for %q is not a 64-digit lowercase hex fingerprint", s)
			}
			p.Revisions[s] = value
		}
	}

	// The series upgrade keys. As in the shared validator, what is wrong with a
	// key itself (not a series, no hop leads to it, not a boolean) is judged before
	// what is wrong with the payload around it.
	major, hasMajor := raw["major"]
	if hasMajor {
		s, isString := major.(string)
		switch {
		case !isString:
			return nil, fault("bad_series", "major must be a series such as 26.7, or omitted")
		case !ValidSeries(s):
			return nil, fault(nonASCIIOr("bad_series", s), "major %q is not a series", s)
		}
		if _, ok := HopSource(s); !ok {
			return nil, fault("no_hop_to_series", "major %q is not the target of a supported series hop", s)
		}
		p.Major = s
	}
	bootEnvironment, hasBootEnvironment := raw["boot_environment"]
	if hasBootEnvironment {
		b, ok := bootEnvironment.(bool)
		if !ok {
			return nil, fault("boot_environment_not_boolean", "boot_environment must be a boolean")
		}
		p.BootEnvironmentOff = !b
	}

	switch {
	case p.Action == ActionAdvance && len(p.Approved) == 0:
		return nil, fault("advance_without_approved", "advance requires a non-empty approved map")
	case p.Action != ActionAdvance && len(p.Approved) != 0:
		return nil, fault("approved_not_allowed", "approved is only valid for advance")
	}
	switch {
	case hasMajor && p.Action != ActionAdvance:
		return nil, fault("major_not_allowed", "major is only valid for advance")
	case hasMajor && !p.Reboot:
		return nil, fault("major_needs_reboot", "major requires reboot to be true")
	case !hasMajor && hasBootEnvironment:
		return nil, fault("boot_environment_without_major", "boot_environment is only valid with major")
	}
	return p, nil
}

// nonASCIIOr is the fault a name is refused with: the shared vectors tell a name
// refused for carrying non-ASCII digits (which \d and isdigit() accept) from any
// other bad spelling.
func nonASCIIOr(kind, s string) string {
	for _, r := range s {
		if r > 0x7f {
			return "non_ascii_digits"
		}
	}
	return kind
}

// ParsePayloadJSON decodes a payload from its JSON text, the way the dispatcher
// does (an object into a generic map), and parses it. Text that is not a JSON
// object is refused. Tests use it to feed the shared vectors.
func ParsePayloadJSON(text []byte) (*Payload, *Fault) {
	trimmed := bytes.TrimSpace(text)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, fault("not_an_object", "the payload is not a JSON object")
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return nil, fault("not_an_object", "the payload is not valid JSON")
	}
	return ParsePayload(raw)
}
