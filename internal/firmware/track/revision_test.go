package track

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

const goldenFingerprint = "d15c519e686c26c685220bc887d20ac29948fb49fa13d91c01ca1c961cee87d2"

func TestNewCatalogFingerprint(t *testing.T) {
	records := []CatalogRecord{
		{"php85-ctype", "8.5.12", "bbb"},
		{"php85", "8.5.12", "aaa"},
		{"opnsense", "26.7.7", "2$ccc"},
	}
	c, err := NewCatalog(records)
	if err != nil {
		t.Fatal(err)
	}
	reversed := []CatalogRecord{records[2], records[1], records[0]}
	d, err := NewCatalog(reversed)
	if err != nil {
		t.Fatal(err)
	}
	if c.Fingerprint != d.Fingerprint {
		t.Errorf("the order of the records changed the fingerprint: %s, %s", c.Fingerprint, d.Fingerprint)
	}
	if !ValidRevision(c.Fingerprint) {
		t.Errorf("%q is not a wire fingerprint", c.Fingerprint)
	}
	records[1].Sum = "aab"
	e, _ := NewCatalog(records)
	if e.Fingerprint == c.Fingerprint {
		t.Error("a changed sum kept the fingerprint")
	}
	if !c.Offers("php85", "8.5.12") || c.Offers("php85", "8.5.11") || c.Offers("nothing", "1") {
		t.Error("Offers does not tell what the catalog holds")
	}
}

func TestNewCatalogRefusesWhatItCannotSpell(t *testing.T) {
	for name, records := range map[string][]CatalogRecord{
		"empty":     nil,
		"tab":       {{"a\tb", "1", "x"}},
		"newline":   {{"a", "1\n", "x"}},
		"empty sum": {{"a", "1", ""}},
	} {
		if _, err := NewCatalog(records); err == nil {
			t.Errorf("%s: a fingerprint was made", name)
		}
	}
}

// The value the control plane's reference script gives for the same lines: the
// agent and NDManager are pinned to the same bytes.
func TestCatalogFingerprintGolden(t *testing.T) {
	c, err := NewCatalog([]CatalogRecord{
		{"opnsense", "26.1.11_10", "d9f7600f3e1e2f87f945d7aa521e6be626a22d7dca262f15d22122bf65e2890d"},
		{"php83", "8.3.36", "1111111111111111111111111111111111111111111111111111111111111111"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.Fingerprint != goldenFingerprint {
		t.Errorf("fingerprint %s, want %s", c.Fingerprint, goldenFingerprint)
	}
}

func writeCatalogDB(t *testing.T, records []CatalogRecord) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("CREATE TABLE packages (id INTEGER PRIMARY KEY, name TEXT NOT NULL, version TEXT NOT NULL, cksum TEXT NOT NULL)"); err != nil {
		t.Fatal(err)
	}
	for _, r := range records {
		if _, err := db.Exec("INSERT INTO packages (name, version, cksum) VALUES (?, ?, ?)", r.Name, r.Version, r.Sum); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func TestReadCatalogMatchesTheRecords(t *testing.T) {
	records := []CatalogRecord{{"php83", "8.3.36", "s1"}, {"opnsense", "26.1.11_10", "s2"}, {"a-b", "1_2,1", "s3"}}
	want, _ := NewCatalog(records)
	got, err := ReadCatalog(context.Background(), writeCatalogDB(t, records))
	if err != nil {
		t.Fatal(err)
	}
	if got.Fingerprint != want.Fingerprint || got.Records() != 3 || !got.Offers("php83", "8.3.36") {
		t.Errorf("read %+v, want fingerprint %s", got, want.Fingerprint)
	}
}

func TestReadCatalogRefusesAMissingOrForeignFile(t *testing.T) {
	if _, err := ReadCatalog(context.Background(), filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("a missing catalog was read")
	}
	path := filepath.Join(t.TempDir(), "db")
	db, _ := sql.Open("sqlite", "file:"+path)
	_, _ = db.Exec("CREATE TABLE other (x)")
	db.Close()
	if _, err := ReadCatalog(context.Background(), path); err == nil {
		t.Error("a database without packages was read")
	}
	empty := writeCatalogDB(t, nil)
	if _, err := ReadCatalog(context.Background(), empty); err == nil {
		t.Error("an empty catalog was fingerprinted")
	}
}

func TestRepoName(t *testing.T) {
	conf := "OPNsense: {\n  fingerprints: \"/usr/local/etc/pkg/fingerprints/OPNsense\",\n  url: \"https://pkg.opnsense.org/${ABI}/26.7/latest\",\n}\n"
	if n, err := RepoName(conf); err != nil || n != "OPNsense" {
		t.Errorf("RepoName = %q, %v", n, err)
	}
	if _, err := RepoName("url: x"); err == nil {
		t.Error("a file without a stanza named a repository")
	}
	if !strings.HasSuffix(CatalogDBPath("/var/db/pkg/repos", "OPNsense"), "/OPNsense/db") {
		t.Error("CatalogDBPath")
	}
}
