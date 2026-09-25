package opnapi

import "testing"

// TestSanitizeMemberCSV reproduces the bad stored shape a link into a
// present-but-empty `<member>` produces (see SanitizeMemberCSV's doc
// comment for the PHP mechanics): a leading comma, e.g. ",2004" instead
// of "2004".
func TestSanitizeMemberCSV(t *testing.T) {
	tests := []struct {
		name          string
		raw           string
		wantSanitized string
		wantChanged   bool
	}{
		{"absent value never touched", "", "", false},
		{"clean single member never touched", "2004", "2004", false},
		{"clean multi member never touched", "2004,2005", "2004,2005", false},
		{"leading comma from a link into a present-but-empty member", ",2004", "2004", true},
		{"trailing comma", "2004,", "2004", true},
		{"double comma between two real members", "2004,,2005", "2004,2005", true},
		{"pure artifact, no real members at all", ",", "", true},
		{"whitespace-only token treated as empty", "2004, ,2005", "2004,2005", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSanitized, gotChanged := SanitizeMemberCSV(tt.raw)
			if gotSanitized != tt.wantSanitized || gotChanged != tt.wantChanged {
				t.Errorf("SanitizeMemberCSV(%q) = (%q, %v), want (%q, %v)",
					tt.raw, gotSanitized, gotChanged, tt.wantSanitized, tt.wantChanged)
			}
		})
	}
}

// TestSanitizeMemberCSV_NeverDropsOrReordersRealTokens is a stronger,
// membership-neutrality-focused check: whatever real (non-empty) tokens
// were present survive in the same order, with the exact same bytes, and
// without deduplication -- SanitizeMemberCSV must never behave like a
// set, only like a filter over structurally-empty entries. The repeated
// "2004" here is deliberate: a naive rewrite via a set/map would collapse
// it, silently dropping a real (if duplicated) member entry.
func TestSanitizeMemberCSV_NeverDropsOrReordersRealTokens(t *testing.T) {
	got, changed := SanitizeMemberCSV(",2005,,2004,2004,")
	if !changed {
		t.Fatal("expected changed=true")
	}
	if got != "2005,2004,2004" {
		t.Errorf("SanitizeMemberCSV(%q) sanitized = %q, want \"2005,2004,2004\" (order preserved, no dedup)", ",2005,,2004,2004,", got)
	}
}

// TestSanitizeMemberCSVAgainstUsers covers the second artifact: a uid
// whose user was deleted without OPNsense scrubbing it from other groups'
// member CSV. It must be dropped like an empty token, while every uid
// still present in validUIDs -- whatever its live membership state -- is
// left untouched.
func TestSanitizeMemberCSVAgainstUsers(t *testing.T) {
	validUIDs := map[string]bool{"2004": true, "2005": true}

	tests := []struct {
		name          string
		raw           string
		wantSanitized string
		wantChanged   bool
	}{
		{"absent value never touched", "", "", false},
		{"all valid, never touched", "2004,2005", "2004,2005", false},
		{"stale uid alone is dropped", "2999", "", true},
		{"stale uid dropped, valid uid kept", "2004,2999", "2004", true},
		{"empty token and stale uid both dropped", ",2004,2999", "2004", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSanitized, gotChanged := SanitizeMemberCSVAgainstUsers(tt.raw, validUIDs)
			if gotSanitized != tt.wantSanitized || gotChanged != tt.wantChanged {
				t.Errorf("SanitizeMemberCSVAgainstUsers(%q) = (%q, %v), want (%q, %v)",
					tt.raw, gotSanitized, gotChanged, tt.wantSanitized, tt.wantChanged)
			}
		})
	}
}
