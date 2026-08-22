package pkgrepo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeRepoFile(t *testing.T, name, body string) string {
	t.Helper()
	if err := os.MkdirAll(ReposDirForTest(), 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(ReposDirForTest(), name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestForeignFileDefiningAManagedNameConflicts(t *testing.T) {
	withTempRoot(t)
	// Exactly the scenario the feature exists to prevent: an administrator
	// already configured mimugmail by hand. pkg keys repositories by the UCL
	// key inside the file, so writing our own would give it two live
	// definitions resolved by file read order.
	writeRepoFile(t, "mimugmail.conf", "mimugmail: {\n  url: \"https://elsewhere.example/repo\",\n  enabled: yes\n}\n")

	conflicts, err := ScanForeign([]string{"mimugmail"})
	if err != nil {
		t.Fatalf("ScanForeign: %v", err)
	}
	if len(conflicts) != 1 {
		t.Fatalf("expected 1 conflict, got %d: %+v", len(conflicts), conflicts)
	}
	if conflicts[0].Repository != "mimugmail" {
		t.Errorf("Repository = %q", conflicts[0].Repository)
	}
	if !strings.HasSuffix(conflicts[0].File, "mimugmail.conf") {
		t.Errorf("File = %q, should name the offending file so a human can find it", conflicts[0].File)
	}
}

func TestOurOwnFileNeverConflictsWithItself(t *testing.T) {
	withTempRoot(t)
	if _, err := Apply([]Repository{fingerprintRepo()}, true); err != nil {
		t.Fatal(err)
	}
	conflicts, err := ScanForeign([]string{"mimugmail"})
	if err != nil {
		t.Fatal(err)
	}
	if len(conflicts) != 0 {
		t.Fatalf("our own managed file reported as a conflict: %+v", conflicts)
	}
}

func TestOPNsenseOwnFilesDoNotConflict(t *testing.T) {
	withTempRoot(t)
	// OPNsense owns these three and rewrites them on firmware settings
	// changes. They must never be mistaken for a conflict just by existing.
	writeRepoFile(t, "OPNsense.conf", "OPNsense: {\n  url: \"https://pkg.opnsense.org/${ABI}/26.1/latest\",\n  priority: 11\n}\n")
	writeRepoFile(t, "FreeBSD.conf", "FreeBSD: {\n  enabled: no\n}\n")
	writeRepoFile(t, "OPNsense-aux.conf", "OPNsense-aux: {\n  enabled: no\n}\n")

	conflicts, err := ScanForeign([]string{"mimugmail"})
	if err != nil {
		t.Fatal(err)
	}
	if len(conflicts) != 0 {
		t.Fatalf("OPNsense's own files reported as conflicts: %+v", conflicts)
	}
}

// But if OPNsense's file genuinely defined a name we manage, that IS a
// conflict — the exemption is by content, not by filename.
func TestExemptionIsByContentNotFilename(t *testing.T) {
	withTempRoot(t)
	writeRepoFile(t, "OPNsense.conf", "mimugmail: {\n  url: \"https://x\"\n}\n")

	conflicts, err := ScanForeign([]string{"mimugmail"})
	if err != nil {
		t.Fatal(err)
	}
	if len(conflicts) != 1 {
		t.Fatalf("a foreign file defining a managed name must conflict regardless of its filename: %+v", conflicts)
	}
}

func TestFileDefiningSeveralRepositoriesIsFullyParsed(t *testing.T) {
	withTempRoot(t)
	writeRepoFile(t, "bundle.conf",
		"alpha: {\n  url: \"https://a\"\n}\n\nmimugmail: {\n  url: \"https://b\"\n}\n\nomega: {\n  url: \"https://c\"\n}\n")

	conflicts, err := ScanForeign([]string{"mimugmail", "omega"})
	if err != nil {
		t.Fatal(err)
	}
	if len(conflicts) != 2 {
		t.Fatalf("expected both managed names found in one file, got %+v", conflicts)
	}
}

func TestUnrelatedRepositoriesAreIgnored(t *testing.T) {
	withTempRoot(t)
	writeRepoFile(t, "somebodyelse.conf", "somebodyelse: {\n  url: \"https://x\"\n}\n")

	conflicts, err := ScanForeign([]string{"mimugmail"})
	if err != nil {
		t.Fatal(err)
	}
	if len(conflicts) != 0 {
		t.Fatalf("unrelated repository reported: %+v", conflicts)
	}
}

func TestMissingReposDirIsNotAnError(t *testing.T) {
	withTempRoot(t)
	// A device with no repos directory at all is unusual but not a failure;
	// the scan should report no conflicts rather than refusing to run.
	conflicts, err := ScanForeign([]string{"mimugmail"})
	if err != nil {
		t.Fatalf("missing repos dir should not error: %v", err)
	}
	if len(conflicts) != 0 {
		t.Fatalf("unexpected conflicts: %+v", conflicts)
	}
}

func TestCommentedDefinitionsAreNotConflicts(t *testing.T) {
	withTempRoot(t)
	writeRepoFile(t, "notes.conf", "# mimugmail: {\n#   url: \"https://x\"\n# }\n")

	conflicts, err := ScanForeign([]string{"mimugmail"})
	if err != nil {
		t.Fatal(err)
	}
	if len(conflicts) != 0 {
		t.Fatalf("a commented-out definition is not live config: %+v", conflicts)
	}
}

func TestScanIsDeterministic(t *testing.T) {
	withTempRoot(t)
	writeRepoFile(t, "b.conf", "mimugmail: {\n  url: \"https://b\"\n}\n")
	writeRepoFile(t, "a.conf", "other: {\n  url: \"https://a\"\n}\n")

	first, err := ScanForeign([]string{"mimugmail", "other"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		again, err := ScanForeign([]string{"mimugmail", "other"})
		if err != nil {
			t.Fatal(err)
		}
		if len(again) != len(first) {
			t.Fatalf("scan not deterministic")
		}
		for j := range again {
			if again[j] != first[j] {
				t.Fatalf("scan order not stable at %d: %+v vs %+v", j, again, first)
			}
		}
	}
}
