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

	// Zone data for the last_check cases, on hosts without /usr/share/zoneinfo.
	_ "time/tzdata"
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

// firmwareStatusFixture is e2e-a's /status after a clean check (trimmed): the
// installed 26.7 with opnsense 26.7.5 in the catalog, and the product_latest
// of 26.7.2 that OPNsense derives from its changelog index.
func firmwareStatusFixture(t *testing.T) map[string]any {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", "firmware-status-e2e-a.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func parseFixture(t *testing.T, doc map[string]any, loc *time.Location) *FirmwareStatus {
	t.Helper()
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	st, err := parseFirmwareStatus(body, loc)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func setUpgrades(doc map[string]any, entries ...map[string]any) {
	list := make([]any, 0, len(entries))
	for _, e := range entries {
		list = append(list, e)
	}
	doc["upgrade_packages"] = list
}

func TestFirmwareStatusLatestIsTheCorePackageCandidate(t *testing.T) {
	st := parseFixture(t, firmwareStatusFixture(t), time.UTC)

	if st.OPNsenseLatest != "26.7.5" {
		t.Errorf("opnsense_latest = %q, want the catalog's 26.7.5, never product_latest's 26.7.2", st.OPNsenseLatest)
	}
	if st.OPNsenseVersion != "26.7" || st.OPNsensePackage != "opnsense" {
		t.Errorf("version, package = %q, %q; want 26.7, opnsense", st.OPNsenseVersion, st.OPNsensePackage)
	}
	if !st.Completed() || st.Stale() {
		t.Errorf("completed=%v stale=%v, want a completed reading of the installed release", st.Completed(), st.Stale())
	}
	if st.LastCheckUnix != time.Date(2026, 10, 4, 3, 2, 47, 0, time.UTC).Unix() {
		t.Errorf("last_check_unix = %d", st.LastCheckUnix)
	}
	if st.UpgradeMajorVersion != "" {
		t.Errorf("upgrade_major_version = %q, want none offered", st.UpgradeMajorVersion)
	}
	if st.UpgradeCount != 5 || st.NewCount != 1 || !st.NeedsReboot {
		t.Errorf("counts = %d upgrades, %d new, reboot %v", st.UpgradeCount, st.NewCount, st.NeedsReboot)
	}
}

func TestFirmwareStatusLatest(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(doc map[string]any)
		want   string
	}{
		{
			name: "a clean check without a core entry: the installed release is the latest",
			mutate: func(doc map[string]any) {
				setUpgrades(doc, map[string]any{"name": "curl", "current_version": "8.21.0", "new_version": "8.22.0"})
			},
			want: "26.7",
		},
		{
			name: "an installed release with a revision keeps its own format",
			mutate: func(doc map[string]any) {
				setUpgrades(doc)
				doc["product_version"] = "26.7.5_1"
				doc["product"].(map[string]any)["product_version"] = "26.7.5_1"
			},
			want: "26.7.5_1",
		},
		{
			name: "a revision of the core package",
			mutate: func(doc map[string]any) {
				setUpgrades(doc, map[string]any{"name": "opnsense", "current_version": "26.7.4", "new_version": "26.7.4_1"})
				doc["product_version"] = "26.7.4"
				doc["product"].(map[string]any)["product_version"] = "26.7.4"
			},
			want: "26.7.4_1",
		},
		{
			name: "business edition",
			mutate: func(doc map[string]any) {
				setUpgrades(doc, map[string]any{"name": "opnsense-business", "current_version": "25.10", "new_version": "25.10.2"})
				doc["product_version"] = "25.10"
				product := doc["product"].(map[string]any)
				product["product_version"], product["product_id"], product["CORE_NAME"] = "25.10", "opnsense-business", "opnsense-business"
			},
			want: "25.10.2",
		},
		{
			name: "the mirror could not be resolved",
			mutate: func(doc map[string]any) {
				setUpgrades(doc)
				doc["status"], doc["connection"] = "error", "unresolved"
			},
			want: "",
		},
		{
			name: "the repository refused access",
			mutate: func(doc map[string]any) {
				setUpgrades(doc)
				doc["status"], doc["repository"] = "error", "forbidden"
			},
			want: "",
		},
		{
			name: "no check has completed (a check is running, or none ran since boot)",
			mutate: func(doc map[string]any) {
				product := doc["product"]
				for key := range doc {
					delete(doc, key)
				}
				doc["product"], doc["status"] = product, "none"
			},
			want: "",
		},
		{
			name: "the check ran against the release an update replaced",
			mutate: func(doc map[string]any) {
				doc["product"].(map[string]any)["product_version"] = "26.7.5"
			},
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := firmwareStatusFixture(t)
			tc.mutate(doc)
			if got := parseFixture(t, doc, time.UTC).OPNsenseLatest; got != tc.want {
				t.Errorf("opnsense_latest = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFirmwareStatusEditionAndNextSeries(t *testing.T) {
	doc := firmwareStatusFixture(t)
	doc["upgrade_major_version"] = "27.1"
	doc["product"].(map[string]any)["product_id"] = "opnsense-devel"
	st := parseFixture(t, doc, time.UTC)
	if st.UpgradeMajorVersion != "27.1" {
		t.Errorf("upgrade_major_version = %q, want 27.1", st.UpgradeMajorVersion)
	}
	if st.OPNsensePackage != "opnsense-devel" {
		t.Errorf("opnsense_package = %q, want the installed opnsense-devel", st.OPNsensePackage)
	}

	doc["product"].(map[string]any)["product_id"], doc["product"].(map[string]any)["CORE_NAME"], doc["product_id"] = "", "", "something-else"
	if st := parseFixture(t, doc, time.UTC); st.OPNsensePackage != "" {
		t.Errorf("opnsense_package = %q for a product that is not a known core package", st.OPNsensePackage)
	}
}

// Only a completed check that could use the mirror is clean; a failed one
// still completed.
func TestFirmwareStatusClean(t *testing.T) {
	if st := parseFixture(t, firmwareStatusFixture(t), time.UTC); !st.Clean() {
		t.Fatal("e2e-a's reading is not clean")
	}
	for name, mutate := range map[string]func(map[string]any){
		"connection unresolved": func(doc map[string]any) { doc["status"], doc["connection"] = "error", "unresolved" },
		"repository forbidden":  func(doc map[string]any) { doc["status"], doc["repository"] = "error", "forbidden" },
		"error status":          func(doc map[string]any) { doc["status"] = "error" },
	} {
		doc := firmwareStatusFixture(t)
		mutate(doc)
		if st := parseFixture(t, doc, time.UTC); st.Clean() || !st.Completed() {
			t.Errorf("%s: clean=%v completed=%v, want a completed reading that is not clean", name, st.Clean(), st.Completed())
		}
	}
	if st := parseFixture(t, map[string]any{"status": "none", "product": map[string]any{"product_version": "26.7"}}, time.UTC); st.Clean() {
		t.Error("a status without a check is clean")
	}
}

func TestFirmwareStatusWithoutACheck(t *testing.T) {
	st := parseFixture(t, map[string]any{
		"status":     "none",
		"status_msg": "Firmware status requires to check for update first to provide more information.",
		"product":    map[string]any{"product_version": "26.7", "product_id": "opnsense", "product_latest": "26.7.2"},
	}, time.UTC)
	if st.Completed() {
		t.Fatal("a status without a check's result reads as completed")
	}
	if st.OPNsenseVersion != "26.7" || st.OPNsenseLatest != "" || st.LastCheckUnix != 0 {
		t.Errorf("version=%q latest=%q last_check_unix=%d", st.OPNsenseVersion, st.OPNsenseLatest, st.LastCheckUnix)
	}
}

func TestFirmwareStatusStale(t *testing.T) {
	doc := firmwareStatusFixture(t)
	doc["product"].(map[string]any)["product_version"] = "26.7.5"
	st := parseFixture(t, doc, time.UTC)
	if !st.Stale() || st.CheckedVersion != "26.7" || st.OPNsenseVersion != "26.7.5" {
		t.Errorf("stale=%v checked=%q installed=%q, want the 26.7 check of a 26.7.5 device to be stale",
			st.Stale(), st.CheckedVersion, st.OPNsenseVersion)
	}
}

func TestParseCheckTime(t *testing.T) {
	saoPaulo, err := time.LoadLocation("America/Sao_Paulo")
	if err != nil {
		t.Skipf("no zone data: %v", err)
	}
	berlin, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Skipf("no zone data: %v", err)
	}
	want := time.Date(2026, 10, 4, 3, 2, 47, 0, time.UTC)
	cases := []struct {
		text string
		loc  *time.Location
	}{
		{"Sun Oct  4 03:02:47 UTC 2026", time.UTC},
		{"Sun Oct  4 03:02:47 UTC 2026", berlin},
		{"Sun Oct 4 03:02:47 UTC 2026", time.UTC},
		{"Sun Oct  4 05:02:47 CEST 2026", berlin},
		{"Sun Oct  4 00:02:47 -03 2026", saoPaulo},
	}
	for _, tc := range cases {
		got, ok := parseCheckTime(tc.text, tc.loc)
		if !ok || !got.Equal(want) {
			t.Errorf("parseCheckTime(%q, %s) = %v, %v; want %v", tc.text, tc.loc, got, ok, want)
		}
	}
	for _, text := range []string{"", "unknown", "2026-10-04T03:02:47Z"} {
		if got, ok := parseCheckTime(text, time.UTC); ok {
			t.Errorf("parseCheckTime(%q) = %v, want unreadable", text, got)
		}
	}
}

// On the wire the reading keeps its old keys and adds the new ones; the
// release the check ran against stays on the device.
func TestGetFirmwareStatusWireShape(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("testdata", "firmware-status-e2e-a.json"))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/core/firmware/status" {
			t.Errorf("request = %s %s, want GET /core/firmware/status", r.Method, r.URL.Path)
		}
		_, _ = w.Write(body)
	}))
	defer server.Close()

	st, err := NewClient(server.URL, "key", "secret", true).GetFirmwareStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"status", "status_msg", "last_check", "upgrade_count", "new_count", "reinstall_count",
		"remove_count", "needs_reboot", "connection", "repository", "opnsense_version", "opnsense_latest",
		"opnsense_package", "last_check_unix"} {
		if _, ok := wire[key]; !ok {
			t.Errorf("%s missing from %s", key, raw)
		}
	}
	for _, key := range []string{"upgrade_major_version", "CheckedVersion", "checked_version"} {
		if _, ok := wire[key]; ok {
			t.Errorf("%s present in %s", key, raw)
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
