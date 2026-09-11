package opnapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseProductRelease(t *testing.T) {
	cases := []struct {
		in           string
		wantMajor    int
		wantMinor    int
		wantParseErr bool
	}{
		{in: "26.1.9", wantMajor: 26, wantMinor: 1},
		{in: "26.1", wantMajor: 26, wantMinor: 1},
		{in: "25.7.9_1", wantMajor: 25, wantMinor: 7},
		{in: "25.7_1", wantMajor: 25, wantMinor: 7},
		{in: " 26.1.9 ", wantMajor: 26, wantMinor: 1},
		{in: "26.10.1", wantMajor: 26, wantMinor: 10},
		{in: "26", wantParseErr: true},
		{in: "", wantParseErr: true},
		{in: "not.a.version", wantParseErr: true},
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
		if got.Major != tc.wantMajor || got.Minor != tc.wantMinor {
			t.Errorf("ParseProductRelease(%q) = %d.%d, want %d.%d", tc.in, got.Major, got.Minor, tc.wantMajor, tc.wantMinor)
		}
	}
}

// TestProductReleaseAtLeast pins the comparison against the real floor,
// including the case that a naive string or float comparison gets wrong:
// 26.10 is ABOVE 26.1, not below it.
func TestProductReleaseAtLeast(t *testing.T) {
	cases := []struct {
		version string
		want    bool
	}{
		{"26.1.9", true},
		{"26.1", true},
		{"26.2.0", true},
		{"26.10.1", true},
		{"27.1", true},
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
		if got := r.AtLeast(MinSupportedOPNsenseMajor, MinSupportedOPNsenseMinor); got != tc.want {
			t.Errorf("%q AtLeast(%d.%d) = %v, want %v",
				tc.version, MinSupportedOPNsenseMajor, MinSupportedOPNsenseMinor, got, tc.want)
		}
	}
}

// TestGetProductReleaseReadsFirmwareInfo pins the endpoint and the field
// precedence. /core/firmware/info reports the INSTALLED product; the
// deliberate alternative, /core/firmware/status, reports the cached result
// of the most recent firmware check and so depends on whether one has run.
func TestGetProductReleaseReadsFirmwareInfo(t *testing.T) {
	var path string
	mux := http.NewServeMux()
	mux.HandleFunc("/core/firmware/info", func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"product_version": "26.1.9",
			"product": map[string]string{
				"product_version": "26.1.9",
				"product_series":  "26.1",
			},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	client := NewClient(srv.URL, "key", "secret", true)
	got, err := client.GetProductRelease(context.Background())
	if err != nil {
		t.Fatalf("GetProductRelease() error = %v", err)
	}
	if path != "/core/firmware/info" {
		t.Errorf("read from %q, want /core/firmware/info (status reflects the last firmware check, not what is installed)", path)
	}
	if got.Raw != "26.1.9" || got.Major != 26 || got.Minor != 1 {
		t.Errorf("got %+v, want 26.1.9 parsed as 26.1", got)
	}
}

// TestGetProductReleaseFallsBackToSeries covers a response carrying only the
// series, which is already the major.minor form the floor is judged on.
func TestGetProductReleaseFallsBackToSeries(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/core/firmware/info", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"product": map[string]string{"product_series": "25.7"},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	got, err := NewClient(srv.URL, "key", "secret", true).GetProductRelease(context.Background())
	if err != nil {
		t.Fatalf("GetProductRelease() error = %v", err)
	}
	if got.Major != 25 || got.Minor != 7 {
		t.Errorf("got %+v, want 25.7", got)
	}
}

// TestGetProductReleaseErrorsRatherThanGuessing pins that an unusable
// response is an ERROR, not a default. Callers must be able to tell "below
// the floor" from "could not tell"; defaulting either way makes one of those
// a lie, and the warning wording depends on the distinction.
func TestGetProductReleaseErrorsRatherThanGuessing(t *testing.T) {
	for name, body := range map[string]interface{}{
		"empty object":     map[string]interface{}{},
		"no version field": map[string]interface{}{"product": map[string]string{}},
		"unparseable":      map[string]interface{}{"product_version": "rolling"},
	} {
		t.Run(name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/core/firmware/info", func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(body)
			})
			srv := httptest.NewServer(mux)
			t.Cleanup(srv.Close)

			if got, err := NewClient(srv.URL, "key", "secret", true).GetProductRelease(context.Background()); err == nil {
				t.Errorf("got %+v with no error; an unusable response must not be reported as a version", got)
			}
		})
	}
}
