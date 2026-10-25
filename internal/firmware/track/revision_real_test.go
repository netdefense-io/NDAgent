package track

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// The catalogs and checks below were read from lab boxes: e2e-a (26.7, FreeBSD:15,
// pkg 2.8) and e2e-c (26.1.11_10 with the php hotfix pending, FreeBSD:14, pkg 2.3.1),
// trimmed to the plan's packages, php83 and php85 with their siblings, every
// version spelling (`_N`, `,epoch`) and the first names in order. The expected
// fingerprints were computed apart from this code, by sorting and hashing the same
// lines.
const catalogFixtures = "testdata/catalog"

type expectedCatalog struct {
	TrimmedFingerprint string `json:"trimmed_fingerprint"`
	TrimmedRecords     int    `json:"trimmed_records"`
	FullFingerprint    string `json:"full_fingerprint"`
	FullRecords        int    `json:"full_records"`
}

func loadFixtureRecords(t *testing.T, box string) []CatalogRecord {
	t.Helper()
	f, err := os.Open(filepath.Join(catalogFixtures, box+".tsv"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var records []CatalogRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<16), 1<<20)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), "\t")
		if len(parts) != 3 {
			t.Fatalf("%s: line %q", box, sc.Text())
		}
		records = append(records, CatalogRecord{parts[0], parts[1], parts[2]})
	}
	return records
}

func loadFixtureStatus(t *testing.T, box string) *opnapi.FirmwareUpgradeStatus {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(catalogFixtures, box+"-status.json"))
	if err != nil {
		t.Fatal(err)
	}
	var raw struct {
		Upgrade []opnapi.FirmwarePackageEntry `json:"upgrade_packages"`
		New     []opnapi.FirmwarePackageEntry `json:"new_packages"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	return &opnapi.FirmwareUpgradeStatus{UpgradePackages: raw.Upgrade, NewPackages: raw.New}
}

func TestRealCatalogsFingerprintAsTheReferenceDoes(t *testing.T) {
	var expected map[string]expectedCatalog
	data, err := os.ReadFile(filepath.Join(catalogFixtures, "expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &expected); err != nil {
		t.Fatal(err)
	}
	for box, want := range expected {
		records := loadFixtureRecords(t, box)
		if len(records) != want.TrimmedRecords {
			t.Fatalf("%s: %d records, want %d", box, len(records), want.TrimmedRecords)
		}
		direct, err := NewCatalog(records)
		if err != nil {
			t.Fatal(err)
		}
		if direct.Fingerprint != want.TrimmedFingerprint {
			t.Errorf("%s: fingerprint %s, want %s", box, direct.Fingerprint, want.TrimmedFingerprint)
		}
		// Through pkg's own database layout, as the device reads it.
		read, err := ReadCatalog(context.Background(), writeCatalogDB(t, records))
		if err != nil {
			t.Fatal(err)
		}
		if read.Fingerprint != want.TrimmedFingerprint {
			t.Errorf("%s: read from a database %s, want %s", box, read.Fingerprint, want.TrimmedFingerprint)
		}
		if want.FullRecords < 900 || len(want.FullFingerprint) != RevisionLength {
			t.Errorf("%s: the full-catalog figures are not recorded", box)
		}
	}
}

func TestTheRealChecksAgreeWithTheirCatalogs(t *testing.T) {
	for _, box := range []string{"e2e-a", "e2e-c"} {
		cat, err := NewCatalog(loadFixtureRecords(t, box))
		if err != nil {
			t.Fatal(err)
		}
		status := loadFixtureStatus(t, box)
		if len(status.UpgradePackages) == 0 {
			t.Fatalf("%s: the check lists nothing", box)
		}
		if err := planAgrees(status, cat); err != nil {
			t.Errorf("%s: %v", box, err)
		}
		// One version off is a disagreement.
		status.UpgradePackages[0].NewVersionAlt += "x"
		if status.UpgradePackages[0].Name != "base" && status.UpgradePackages[0].Name != "kernel" {
			if err := planAgrees(status, cat); err == nil {
				t.Errorf("%s: a plan with another version agreed", box)
			}
		}
	}
}

func TestAPlanEntryWithoutARepositoryThatIsNotInTheCatalogIsSkipped(t *testing.T) {
	cat, _ := NewCatalog([]CatalogRecord{{"curl", "8.21.0", "s"}})
	status := &opnapi.FirmwareUpgradeStatus{UpgradePackages: []opnapi.FirmwarePackageEntry{
		{Name: "os-plugin", NewVersionAlt: "1.0"},
		{Name: "curl", Repository: "OPNsense", NewVersionAlt: "8.21.0"},
	}}
	if err := planAgrees(status, cat); err != nil {
		t.Error(err)
	}
	status.UpgradePackages = append(status.UpgradePackages, opnapi.FirmwarePackageEntry{Name: "os-plugin", Repository: "OPNsense", NewVersionAlt: "1.0"})
	if err := planAgrees(status, cat); err == nil {
		t.Error("an OPNsense entry the catalog lacks agreed")
	}
}

func TestSystemDeviceCatalogReadsOnlyOPNsensesCatalog(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "OPNsense.conf")
	text := "# generated\nNetDefense: {\n  url: \"https://repo.netdefense.io/x\",\n}\nOPNsense: {\n  url: \"https://pkg.opnsense.org/${ABI}/26.1/latest\",\n}\n"
	if err := os.WriteFile(conf, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	opn := loadFixtureRecords(t, "e2e-c")
	repos := filepath.Join(dir, "repos")
	for name, records := range map[string][]CatalogRecord{"OPNsense": opn, "NetDefense": {{"os-netdefense", "1.28_0", "zz"}}} {
		if err := os.MkdirAll(filepath.Join(repos, name), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(writeCatalogDB(t, records), filepath.Join(repos, name, "db")); err != nil {
			t.Fatal(err)
		}
	}
	oldConf, oldRepos := repoConfPath, reposDir
	repoConfPath, reposDir = conf, repos
	t.Cleanup(func() { repoConfPath, reposDir = oldConf, oldRepos })

	want, _ := NewCatalog(opn)
	got, err := (&SystemDevice{}).Catalog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Fingerprint != want.Fingerprint || got.Has("os-netdefense") {
		t.Errorf("fingerprint %s (%d records), want OPNsense's alone %s", got.Fingerprint, got.Records(), want.Fingerprint)
	}

	if err := os.Remove(filepath.Join(repos, "OPNsense", "db")); err != nil {
		t.Fatal(err)
	}
	if _, err := (&SystemDevice{}).Catalog(context.Background()); err == nil {
		t.Error("an absent catalog was read")
	}
}
