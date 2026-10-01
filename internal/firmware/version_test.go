package firmware

import "testing"

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		// equal
		{"1.19.5", "1.19.5", 0},
		{"26.7.4_1", "26.7.4_1", 0},
		{"1.0", "1.0.0", 0},
		{"1.00", "1.0", 0},
		// a revision follows the version
		{"26.7.4_1", "26.7.4", 1},
		{"26.7.4", "26.7.4_1", -1},
		{"26.7.4_2", "26.7.4_1", 1},
		{"26.7.4_10", "26.7.4_9", 1},
		// numbers compare as numbers, not text
		{"26.7.10", "26.7.9", 1},
		{"1.9", "1.10", -1},
		{"3.11.9", "3.9.10", 1},
		{"20240101120000", "20231231235959", 1},
		{"12345678901234567890", "12345678901234567891", -1},
		// the epoch, after the comma, decides first
		{"2.0,1", "3.0", 1},
		{"1.2.3_1,1", "1.2.3_9", 1},
		{"1.2.3_1,1", "1.2.3_9,1", -1},
		{"1,2", "9,1", 1},
		// pre-release words sort below the release, other words above
		{"1.0.rc1", "1.0", -1},
		{"1.0rc1", "1.0", -1},
		{"1.0alpha", "1.0beta", -1},
		{"1.0beta2", "1.0rc1", -1},
		{"1.0rc1", "1.0rc2", -1},
		{"1.0pre1", "1.0rc1", -1},
		{"1.0", "1.0a", -1},
		{"1.0a", "1.0b", -1},
		{"2.4p1", "2.4", 1},
		{"2.4p2", "2.4p1", 1},
		{"1.0.rc1", "0.9.9", 1},
		// a longer version with more components
		{"1.2.3.1", "1.2.3", 1},
		{"1.2", "1.2.0.1", -1},
	}
	for _, tc := range cases {
		if got := CompareVersions(tc.a, tc.b); got != tc.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
		if got := CompareVersions(tc.b, tc.a); got != -tc.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d (not antisymmetric)", tc.b, tc.a, got, -tc.want)
		}
	}
}

func TestAtLeast(t *testing.T) {
	cases := []struct {
		installed, planned string
		want               bool
	}{
		{"1.19.5", "1.19.5", true},
		{"1.19.6", "1.19.5", true},
		{"1.19.4", "1.19.5", false},
		{"26.7.4_2", "26.7.4_1", true},
		{"26.7.4", "26.7.4_1", false},
		{"", "1.0", false},        // not installed
		{"", "", false},           // not installed, whatever was planned
		{"1.0", "", true},         // the plan did not say which version
		{"2.0,1", "3.0", true},    // the epoch wins
		{"1.0.rc1", "1.0", false}, // a release candidate is not the release
	}
	for _, tc := range cases {
		if got := AtLeast(tc.installed, tc.planned); got != tc.want {
			t.Errorf("AtLeast(%q, %q) = %v, want %v", tc.installed, tc.planned, got, tc.want)
		}
	}
}
