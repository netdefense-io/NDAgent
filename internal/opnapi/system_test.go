package opnapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// certSearchFixture is a /trust/cert/search response in the shape OPNsense
// sends it: valid_from and valid_to are Unix seconds in strings.
func certSearchFixture(t *testing.T) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", "trust-cert-search.json"))
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestCertEntriesReadsEpochValidTo(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	got, err := certEntries(certSearchFixture(t), now)
	if err != nil {
		t.Fatal(err)
	}
	want := []CertEntry{
		{Description: "Web GUI TLS certificate", DaysLeft: 92, ValidTo: "2027-01-01T00:00:00Z", InUse: true},
		{Description: "fw-wildcard", DaysLeft: 28, ValidTo: "2026-10-29T00:00:00Z"},
		{Description: "Old VPN server", DaysLeft: -638, ValidTo: "2025-01-01T00:00:00Z", InUse: true},
		// A certificate whose expiry cannot be read counts as expired; the
		// pending request after it, which has no certificate, is left out.
		{Description: "Unreadable certificate", DaysLeft: 0, ValidTo: ""},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// A row is left out only when nothing says it holds a certificate: no crt, no
// crt_payload and no expiry, however each is spelled.
func TestCertEntriesLeavesOutRowsWithoutACertificate(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	body := []byte(`{"rows":[
		{"descr":"absent"},
		{"descr":"null","crt":null,"crt_payload":null,"valid_to":null},
		{"descr":"empty","crt":"","crt_payload":"","valid_to":""},
		{"descr":"payload only","crt_payload":"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n","valid_to":""},
		{"descr":"expiry only","valid_to":"1798761600"}
	]}`)
	got, err := certEntries(body, now)
	if err != nil {
		t.Fatal(err)
	}
	want := []CertEntry{
		{Description: "payload only", DaysLeft: 0, ValidTo: ""},
		{Description: "expiry only", DaysLeft: 92, ValidTo: "2027-01-01T00:00:00Z"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestCertExpiryForms(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"epoch string", `"1798761600"`, "2027-01-01T00:00:00Z"},
		{"epoch string with spaces", `" 1798761600 "`, "2027-01-01T00:00:00Z"},
		{"epoch number", `1798761600`, "2027-01-01T00:00:00Z"},
		{"OpenSSL text", `"Jan  1 00:00:00 2027 GMT"`, "2027-01-01T00:00:00Z"},
		{"OpenSSL text, two-digit day", `"Jun 26 18:33:46 2025 GMT"`, "2025-06-26T18:33:46Z"},
		{"RFC 3339", `"2027-01-01T00:00:00Z"`, "2027-01-01T00:00:00Z"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expiry, ok := certExpiry(json.RawMessage(tc.raw))
			if !ok {
				t.Fatalf("certExpiry(%s) could not read it", tc.raw)
			}
			if got := expiry.UTC().Format(time.RFC3339); got != tc.want {
				t.Errorf("certExpiry(%s) = %s, want %s", tc.raw, got, tc.want)
			}
		})
	}

	for _, raw := range []string{``, `""`, `null`, `"soon"`, `"1798761600.5"`, `{}`, `[]`, `true`} {
		if expiry, ok := certExpiry(json.RawMessage(raw)); ok {
			t.Errorf("certExpiry(%q) = %v, want unreadable", raw, expiry)
		}
	}
}

// The dashboard counts days_left <= 0 as expired and 1..30 as expiring soon, so
// a certificate with hours left is 1 and one that expired hours ago is 0.
func TestDaysLeftRoundsUp(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		offset time.Duration
		want   int
	}{
		{0, 0},
		{time.Second, 1},
		{12 * time.Hour, 1},
		{24 * time.Hour, 1},
		{25 * time.Hour, 2},
		{-time.Second, 0},
		{-12 * time.Hour, 0},
		{-24 * time.Hour, -1},
		{-36 * time.Hour, -1},
		{-48 * time.Hour, -2},
	}
	for _, tc := range cases {
		if got := daysLeft(now.Add(tc.offset), now); got != tc.want {
			t.Errorf("daysLeft(now%+v) = %d, want %d", tc.offset, got, tc.want)
		}
	}
}

func TestListCertsReadsTheSearch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/trust/cert/search" {
			t.Errorf("request = %s %s, want POST /trust/cert/search", r.Method, r.URL.Path)
		}
		_, _ = w.Write(certSearchFixture(t))
	}))
	defer server.Close()

	certs, err := NewClient(server.URL, "key", "secret", true).ListCerts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 4 {
		t.Fatalf("got %d certs, want 4", len(certs))
	}
	if certs[0].ValidTo != "2027-01-01T00:00:00Z" {
		t.Errorf("valid_to = %q, want 2027-01-01T00:00:00Z", certs[0].ValidTo)
	}
	if certs[2].DaysLeft >= 0 {
		t.Errorf("a certificate that expired on 2025-01-01 has %d days left", certs[2].DaysLeft)
	}
}
