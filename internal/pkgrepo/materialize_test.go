package pkgrepo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withTempRoot(t *testing.T) {
	t.Helper()
	t.Cleanup(SetRootForTest(t.TempDir()))
}

func TestFirstApplyWritesConfAndFingerprints(t *testing.T) {
	withTempRoot(t)
	r := fingerprintRepo()

	changed, err := Apply([]Repository{r}, true)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !changed {
		t.Error("first apply should report Changed")
	}

	conf, err := os.ReadFile(ConfPath("mimugmail"))
	if err != nil {
		t.Fatalf("conf not written: %v", err)
	}
	if string(conf) != string(Render(r)) {
		t.Error("on-disk conf differs from Render output")
	}

	// pkg expects <FINGERPRINTS>/trusted/ and a revoked/ sibling. A missing
	// revoked/ makes pkg complain rather than treat it as empty.
	trusted := filepath.Join(FingerprintDir("mimugmail"), "trusted")
	entries, err := os.ReadDir(trusted)
	if err != nil {
		t.Fatalf("trusted dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 trusted fingerprint file, got %d", len(entries))
	}
	body, _ := os.ReadFile(filepath.Join(trusted, entries[0].Name()))
	if !strings.Contains(string(body), "function: sha256") ||
		!strings.Contains(string(body), "fingerprint: "+strings.Repeat("a", 64)) {
		t.Errorf("fingerprint file body wrong:\n%s", body)
	}
	if _, err := os.Stat(filepath.Join(FingerprintDir("mimugmail"), "revoked")); err != nil {
		t.Errorf("revoked/ directory missing: %v", err)
	}
}

// The core idempotency claim. Re-applying an unchanged policy must not
// rewrite anything — the forced catalog refresh downstream keys off Changed,
// and a needless `pkg update -f` on every sync is a real cost.
func TestApplyTwiceWritesNothingTheSecondTime(t *testing.T) {
	withTempRoot(t)
	repos := []Repository{fingerprintRepo()}

	if _, err := Apply(repos, true); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	before, err := os.Stat(ConfPath("mimugmail"))
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, _ := os.ReadFile(ConfPath("mimugmail"))

	changed, err := Apply(repos, true)
	if err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if changed {
		t.Error("second apply of an unchanged policy reported Changed")
	}

	after, err := os.Stat(ConfPath("mimugmail"))
	if err != nil {
		t.Fatal(err)
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Error("file was rewritten despite identical content")
	}
	secondBytes, _ := os.ReadFile(ConfPath("mimugmail"))
	if string(firstBytes) != string(secondBytes) {
		t.Error("content changed between identical applies")
	}
}

// The operator's stated worry, in test form.
func TestEnabledFlipLeavesExactlyOneDefinition(t *testing.T) {
	withTempRoot(t)

	on := fingerprintRepo()
	off := fingerprintRepo()
	off.Enabled = false

	for i, step := range []Repository{on, off, on} {
		if _, err := Apply([]Repository{step}, true); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}

		entries, err := os.ReadDir(ReposDirForTest())
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 {
			names := []string{}
			for _, e := range entries {
				names = append(names, e.Name())
			}
			t.Fatalf("step %d: expected exactly one repo file, got %v", i, names)
		}

		body, _ := os.ReadFile(ConfPath("mimugmail"))
		if n := strings.Count(string(body), "mimugmail: {"); n != 1 {
			t.Fatalf("step %d: %d definitions of mimugmail in one file", i, n)
		}
		want := "enabled: no,"
		if step.Enabled {
			want = "enabled: yes,"
		}
		if !strings.Contains(string(body), want) {
			t.Fatalf("step %d: expected %q in:\n%s", i, want, body)
		}
	}
}

func TestPruneDeletesOnlyOurFiles(t *testing.T) {
	withTempRoot(t)

	if _, err := Apply([]Repository{fingerprintRepo()}, true); err != nil {
		t.Fatal(err)
	}

	// An administrator's own file, similar name, no marker.
	foreign := filepath.Join(ReposDirForTest(), "netdefense-lookalike.conf")
	if err := os.WriteFile(foreign, []byte("lookalike: {\n  url: \"https://x\"\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Policy no longer mentions mimugmail.
	if err := Prune(nil); err != nil {
		t.Fatalf("Prune: %v", err)
	}

	if _, err := os.Stat(ConfPath("mimugmail")); !os.IsNotExist(err) {
		t.Error("our marked file should have been deleted")
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Errorf("unmarked file was deleted despite the prefix: %v", err)
	}
	if _, err := os.Stat(FingerprintDir("mimugmail")); !os.IsNotExist(err) {
		t.Error("fingerprint material should be removed with its repo")
	}
}

func TestPruneKeepsRepositoriesStillInThePolicy(t *testing.T) {
	withTempRoot(t)
	keep := fingerprintRepo()
	drop := fingerprintRepo()
	drop.Name = "other"

	if _, err := Apply([]Repository{keep, drop}, true); err != nil {
		t.Fatal(err)
	}
	if err := Prune([]string{"mimugmail"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(ConfPath("mimugmail")); err != nil {
		t.Errorf("kept repo was deleted: %v", err)
	}
	if _, err := os.Stat(ConfPath("other")); !os.IsNotExist(err) {
		t.Error("dropped repo should be gone")
	}
}

func TestPubkeyMaterialLandsAtManagedPath(t *testing.T) {
	withTempRoot(t)
	r := fingerprintRepo()
	pem := "-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----\n"
	r.Signature = Signature{Type: SignaturePubkey, Pubkey: pem}

	if _, err := Apply([]Repository{r}, true); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(PubkeyPath("mimugmail"))
	if err != nil {
		t.Fatalf("pubkey not written: %v", err)
	}
	if string(got) != pem {
		t.Errorf("pubkey body altered:\n%q", got)
	}
}

// The agent-side half of the three-layer trust model. Even if a poisoned row
// reached this far, the agent refuses on its own rather than trusting that
// someone upstream checked.
func TestUnverifiedSourcesRefusedWithoutPermission(t *testing.T) {
	t.Run("signature none", func(t *testing.T) {
		withTempRoot(t)
		r := fingerprintRepo()
		r.Signature = Signature{Type: SignatureNone}
		if _, err := Apply([]Repository{r}, false); err == nil {
			t.Fatal("expected refusal for unsigned repo without permission")
		}
		if _, err := os.Stat(ConfPath("mimugmail")); !os.IsNotExist(err) {
			t.Error("refused repo must not be written to disk")
		}
	})

	t.Run("non-https url", func(t *testing.T) {
		withTempRoot(t)
		r := fingerprintRepo()
		r.URL = "http://opn-repo.example/repo/${ABI}"
		if _, err := Apply([]Repository{r}, false); err == nil {
			t.Fatal("expected refusal for non-https repo without permission")
		}
	})

	t.Run("permitted when the org opted in", func(t *testing.T) {
		withTempRoot(t)
		r := fingerprintRepo()
		r.Signature = Signature{Type: SignatureNone}
		if _, err := Apply([]Repository{r}, true); err != nil {
			t.Fatalf("should be allowed when permitted: %v", err)
		}
	})
}

// A crash mid-write must not leave pkg reading a truncated repo config.
func TestWritesAreAtomic(t *testing.T) {
	withTempRoot(t)
	if _, err := Apply([]Repository{fingerprintRepo()}, true); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(ReposDirForTest())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") || strings.HasPrefix(e.Name(), ".") {
			t.Errorf("temp artefact left behind: %s", e.Name())
		}
	}
}
