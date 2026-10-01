package opnapi

import "testing"

func TestParseProductRelease(t *testing.T) {
	cases := []struct {
		in           string
		wantMajor    int
		wantMinor    int
		wantPatch    int
		wantParseErr bool
	}{
		{in: "26.1.9", wantMajor: 26, wantMinor: 1, wantPatch: 9},
		{in: "26.1.10", wantMajor: 26, wantMinor: 1, wantPatch: 10},
		{in: "26.1.11", wantMajor: 26, wantMinor: 1, wantPatch: 11},
		{in: "26.1.11_1", wantMajor: 26, wantMinor: 1, wantPatch: 11},
		{in: "26.1", wantMajor: 26, wantMinor: 1, wantPatch: 0},
		{in: "26.1_3", wantMajor: 26, wantMinor: 1, wantPatch: 0},
		{in: "25.7.9_1", wantMajor: 25, wantMinor: 7, wantPatch: 9},
		{in: "25.7.11_9", wantMajor: 25, wantMinor: 7, wantPatch: 11},
		{in: "25.7_1", wantMajor: 25, wantMinor: 7, wantPatch: 0},
		{in: "26.7.5", wantMajor: 26, wantMinor: 7, wantPatch: 5},
		{in: " 26.1.9 ", wantMajor: 26, wantMinor: 1, wantPatch: 9},
		{in: "26.10.1", wantMajor: 26, wantMinor: 10, wantPatch: 1},
		{in: "27.1.a", wantMajor: 27, wantMinor: 1, wantPatch: 0},
		{in: "26", wantParseErr: true},
		{in: "", wantParseErr: true},
		{in: "not.a.version", wantParseErr: true},
		{in: "26.x.1", wantParseErr: true},
		{in: "26.1.99999999999999999999", wantParseErr: true},
	}

	for _, tc := range cases {
		got, err := ParseProductRelease(tc.in)
		if tc.wantParseErr {
			if err == nil {
				t.Errorf("ParseProductRelease(%q) = %+v, want an error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseProductRelease(%q) error = %v", tc.in, err)
			continue
		}
		if got.Major != tc.wantMajor || got.Minor != tc.wantMinor || got.Patch != tc.wantPatch {
			t.Errorf("ParseProductRelease(%q) = %d.%d.%d, want %d.%d.%d", tc.in, got.Major, got.Minor, got.Patch, tc.wantMajor, tc.wantMinor, tc.wantPatch)
		}
	}
}

// TestSupportedFloorIsTheDocumentedLiteral pins the floor as written in the
// operator's decision, not as the constants happen to read, and ties it to the
// release the admin-equivalence catalog is classified for.
func TestSupportedFloorIsTheDocumentedLiteral(t *testing.T) {
	if MinSupportedOPNsenseMajor != 26 || MinSupportedOPNsenseMinor != 1 || MinSupportedOPNsensePatch != 11 {
		t.Fatalf("supported floor = %d.%d.%d, want 26.1.11", MinSupportedOPNsenseMajor, MinSupportedOPNsenseMinor, MinSupportedOPNsensePatch)
	}
	assumed, err := ParseProductRelease(AdminEquivalenceAssumedMinRelease())
	if err != nil {
		t.Fatal(err)
	}
	if assumed.Major != MinSupportedOPNsenseMajor || assumed.Minor != MinSupportedOPNsenseMinor || assumed.Patch != MinSupportedOPNsensePatch {
		t.Errorf("the catalog is classified for %s but the floor is %d.%d.%d: the floor-dependent IDs would be ordinary on a release the catalog did not assume",
			AdminEquivalenceAssumedMinRelease(), MinSupportedOPNsenseMajor, MinSupportedOPNsenseMinor, MinSupportedOPNsensePatch)
	}
}

// TestProductReleaseAtLeast pins the comparison against the real floor,
// including the cases a naive string or float comparison gets wrong: 26.10 is
// ABOVE 26.1, 26.1.11 is ABOVE 26.1.9, and a FreeBSD revision suffix never
// lowers a release.
func TestProductReleaseAtLeast(t *testing.T) {
	cases := []struct {
		version string
		want    bool
	}{
		{"26.1.10", false},
		{"26.1.9", false},
		{"26.1.0", false},
		{"26.1", false},
		{"26.1_2", false},
		{"26.1.11", true},
		{"26.1.11_1", true},
		{"26.1.12", true},
		{"26.1.100", true},
		{"26.2.0", true},
		{"26.7.5", true},
		{"26.10.1", true},
		{"27.1", true},
		{"27.1.a", true},
		{"25.7.11_9", false},
		{"25.7.9", false},
		{"25.7.9_1", false},
		{"25.1", false},
		{"24.7", false},
	}

	for _, tc := range cases {
		r, err := ParseProductRelease(tc.version)
		if err != nil {
			t.Fatalf("ParseProductRelease(%q): %v", tc.version, err)
		}
		if got := r.AtLeast(MinSupportedOPNsenseMajor, MinSupportedOPNsenseMinor, MinSupportedOPNsensePatch); got != tc.want {
			t.Errorf("%q AtLeast(%d.%d.%d) = %v, want %v",
				tc.version, MinSupportedOPNsenseMajor, MinSupportedOPNsenseMinor, MinSupportedOPNsensePatch, got, tc.want)
		}
	}
}

func TestProductReleaseString(t *testing.T) {
	if got := (ProductRelease{Raw: "26.1.11_1", Major: 26, Minor: 1, Patch: 11}).String(); got != "26.1.11_1" {
		t.Errorf("String() = %q, want what OPNsense reported", got)
	}
	if got := (ProductRelease{Major: 26, Minor: 1, Patch: 11}).String(); got != "26.1.11" {
		t.Errorf("String() without a reported version = %q, want 26.1.11", got)
	}
}
