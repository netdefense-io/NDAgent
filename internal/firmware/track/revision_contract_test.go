package track

import (
	"strings"
	"testing"
)

var (
	fpA = strings.Repeat("a", 64)
	fpB = strings.Repeat("b", 64)
)

func TestParsePayloadRevisions(t *testing.T) {
	cases := []struct {
		name  string
		json  string
		fault string
	}{
		{"advance with a revision", `{"action":"advance","track":"fast","approved":{"26.7":"26.7.7"},"revisions":{"26.7":"` + fpA + `"}}`, ""},
		{"a revision for one of two series", `{"action":"advance","track":"fast","approved":{"26.1":"26.1.11","26.7":"26.7.7"},"revisions":{"26.7":"` + fpA + `"}}`, ""},
		{"not an object", `{"action":"advance","track":"fast","approved":{"26.7":"26.7.7"},"revisions":"x"}`, "revisions_not_object"},
		{"null", `{"action":"advance","track":"fast","approved":{"26.7":"26.7.7"},"revisions":null}`, "revisions_not_object"},
		{"empty", `{"action":"advance","track":"fast","approved":{"26.7":"26.7.7"},"revisions":{}}`, "revisions_empty"},
		{"on an enroll", `{"action":"enroll","track":"fast","revisions":{"26.7":"` + fpA + `"}}`, "revisions_not_allowed"},
		{"series not approved", `{"action":"advance","track":"fast","approved":{"26.7":"26.7.7"},"revisions":{"26.1":"` + fpA + `"}}`, "revisions_not_approved"},
		{"upper case", `{"action":"advance","track":"fast","approved":{"26.7":"26.7.7"},"revisions":{"26.7":"` + strings.ToUpper(fpA) + `"}}`, "revisions_bad_fingerprint"},
		{"short", `{"action":"advance","track":"fast","approved":{"26.7":"26.7.7"},"revisions":{"26.7":"abc"}}`, "revisions_bad_fingerprint"},
		{"not a string", `{"action":"advance","track":"fast","approved":{"26.7":"26.7.7"},"revisions":{"26.7":7}}`, "revisions_bad_fingerprint"},
	}
	for _, c := range cases {
		p, f := ParsePayloadJSON([]byte(c.json))
		switch {
		case c.fault == "" && f != nil:
			t.Errorf("%s: refused: %v", c.name, f)
		case c.fault != "" && (f == nil || f.Kind != c.fault):
			t.Errorf("%s: fault %v, want %s", c.name, f, c.fault)
		case c.fault == "" && p.Revisions["26.7"] != fpA:
			t.Errorf("%s: revisions %v", c.name, p.Revisions)
		}
	}
}

func resultFor(outcome, reason, revision string) Result {
	return Result{Action: ActionAdvance, Track: TrackFast, Outcome: outcome, Reason: reason, TargetVersion: "26.7.7", Revision: revision}
}

func TestResultRevision(t *testing.T) {
	dispatch := Payload{Action: ActionAdvance, Track: TrackFast, Approved: map[string]string{"26.7": "26.7.7"}, Revisions: map[string]string{"26.7": fpA}}
	plain := Payload{Action: ActionAdvance, Track: TrackFast, Approved: map[string]string{"26.7": "26.7.7"}}

	for name, r := range map[string]Result{
		"success":  resultFor(OutcomeSuccess, ReasonApplied, fpA),
		"noop":     resultFor(OutcomeNoop, ReasonAtOrAboveTarget, fpA),
		"mismatch": resultFor(OutcomeHeld, ReasonHeldRevisionMismatch, fpB),
		"held":     resultFor(OutcomeHeld, ReasonHeldCheckFailed, ""),
	} {
		msg, err := r.MessageFor(dispatch)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if name != "held" && !strings.Contains(msg, `"revision":"`) {
			t.Errorf("%s: no revision in %s", name, msg)
		}
	}
	if _, err := resultFor(OutcomeSuccess, ReasonApplied, fpA).MessageFor(plain); err == nil {
		t.Error("a revision went out on an answer to a dispatch without revisions")
	}
	if _, err := resultFor(OutcomeSuccess, ReasonApplied, "xyz").MessageFor(dispatch); err == nil {
		t.Error("a malformed revision went out")
	}
	if _, err := resultFor(OutcomeHeld, ReasonHeldRevisionMismatch, "").MessageFor(dispatch); err == nil {
		t.Error("held_revision_mismatch went out without the revision it saw")
	}
	if _, err := resultFor(OutcomeHeld, ReasonHeldRevisionMismatch, fpB).MessageFor(plain); err == nil {
		t.Error("held_revision_mismatch answered a dispatch without revisions")
	}
	major := resultFor(OutcomeSuccess, ReasonApplied, fpA)
	major.Kind = KindMajor
	if _, err := major.Message(); err == nil {
		t.Error("a series upgrade's answer carried a revision")
	}
	enroll := Result{Action: ActionEnroll, Track: TrackFast, Outcome: OutcomeNoop, Reason: ReasonEnrolled, Revision: fpA}
	if _, err := enroll.Message(); err == nil {
		t.Error("an enroll answer carried a revision")
	}
	released := Result{Action: ActionAdvance, Track: TrackFast, Outcome: OutcomeReleased, Reason: ReasonReleaseFolderUnavailable, Revision: fpA}
	if _, err := released.Message(); err == nil {
		t.Error("a released answer carried a revision")
	}
	if !contains(heldReasons, ReasonHeldRevisionMismatch) || contains(releasedReasons, ReasonHeldRevisionMismatch) {
		t.Error("held_revision_mismatch is not a held reason")
	}
}
