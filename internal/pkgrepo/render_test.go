package pkgrepo

import (
	"strings"
	"testing"
)

func fingerprintRepo() Repository {
	return Repository{
		Name:     "mimugmail",
		URL:      "https://opn-repo.routerperformance.net/repo/${ABI}",
		Priority: 5,
		Enabled:  true,
		Signature: Signature{
			Type: SignatureFingerprints,
			Fingerprints: []Fingerprint{
				{Function: "sha256", Fingerprint: strings.Repeat("a", 64)},
			},
		},
	}
}

func TestRenderMatchesTheDocumentedForm(t *testing.T) {
	got := string(Render(fingerprintRepo()))
	want := `# Managed by NetDefense. Do not edit; changes are overwritten.
mimugmail: {
  url: "https://opn-repo.routerperformance.net/repo/${ABI}",
  priority: 5,
  enabled: yes,
  signature_type: "fingerprints",
  fingerprints: "/usr/local/etc/pkg/fingerprints/netdefense-mimugmail"
}
`
	if got != want {
		t.Fatalf("rendered UCL mismatch.\n got:\n%s\nwant:\n%s", got, want)
	}
}

// The single most important property in this file. pkg(8) substitutes ${ABI}
// per device at runtime; expanding it here would pin every device to whatever
// ABI the control plane happened to think of, and this codebase has been
// bitten by premature ${ABI} expansion twice already.
func TestABITokenSurvivesVerbatim(t *testing.T) {
	got := string(Render(fingerprintRepo()))
	if !strings.Contains(got, "${ABI}") {
		t.Fatalf("${ABI} did not survive rendering:\n%s", got)
	}
	for _, expanded := range []string{"FreeBSD:14", "FreeBSD:15", "amd64"} {
		if strings.Contains(got, expanded) {
			t.Fatalf("rendered output contains an expanded ABI %q:\n%s", expanded, got)
		}
	}
}

func TestEnabledRendersAsYesNo(t *testing.T) {
	// UCL takes yes/no here, not Go's true/false.
	on := string(Render(fingerprintRepo()))
	if !strings.Contains(on, "enabled: yes,") {
		t.Errorf("enabled=true should render `enabled: yes`, got:\n%s", on)
	}

	r := fingerprintRepo()
	r.Enabled = false
	off := string(Render(r))
	if !strings.Contains(off, "enabled: no,") {
		t.Errorf("enabled=false should render `enabled: no`, got:\n%s", off)
	}
	if strings.Contains(off, "true") || strings.Contains(off, "false") {
		t.Errorf("Go booleans leaked into UCL output:\n%s", off)
	}
}

func TestPubkeyPointsAtTheManagedKeyPath(t *testing.T) {
	r := fingerprintRepo()
	r.Signature = Signature{Type: SignaturePubkey, Pubkey: "-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----"}
	got := string(Render(r))
	if !strings.Contains(got, `signature_type: "pubkey"`) {
		t.Errorf("missing signature_type pubkey:\n%s", got)
	}
	if !strings.Contains(got, `pubkey: "/usr/local/etc/pkg/keys/netdefense-mimugmail.pub"`) {
		t.Errorf("pubkey path wrong:\n%s", got)
	}
	// The PEM belongs in the key file, never inline in the repo config.
	if strings.Contains(got, "BEGIN PUBLIC KEY") {
		t.Errorf("PEM body leaked into the repo config:\n%s", got)
	}
}

func TestNoneRendersExplicitly(t *testing.T) {
	r := fingerprintRepo()
	r.Signature = Signature{Type: SignatureNone}
	got := string(Render(r))
	if !strings.Contains(got, `signature_type: "none"`) {
		t.Errorf("expected explicit signature_type none:\n%s", got)
	}
	if strings.Contains(got, "fingerprints:") || strings.Contains(got, "pubkey:") {
		t.Errorf("unsigned repo should carry neither fingerprints nor pubkey:\n%s", got)
	}
}

// Idempotency starts here: if rendering were not deterministic, the
// apply-twice-no-write guarantee downstream could never hold.
func TestRenderIsDeterministic(t *testing.T) {
	a := string(Render(fingerprintRepo()))
	for i := 0; i < 10; i++ {
		if b := string(Render(fingerprintRepo())); b != a {
			t.Fatalf("render not deterministic on run %d:\n%s\nvs\n%s", i, a, b)
		}
	}
}

func TestMarkerIsTheFirstLine(t *testing.T) {
	// Deletion is confined to files carrying this marker, so its exact
	// placement is load-bearing, not cosmetic.
	got := string(Render(fingerprintRepo()))
	first := strings.SplitN(got, "\n", 2)[0]
	if first != ManagedMarker {
		t.Fatalf("first line = %q, want the managed marker %q", first, ManagedMarker)
	}
	if !IsManaged([]byte(got)) {
		t.Error("IsManaged should recognise our own output")
	}
	if IsManaged([]byte("mimugmail: {\n  url: \"https://x\"\n}\n")) {
		t.Error("IsManaged must not claim a hand-written file")
	}
}

func TestManagedPathsFollowTheNamespace(t *testing.T) {
	if got := ConfPath("mimugmail"); got != "/usr/local/etc/pkg/repos/netdefense-mimugmail.conf" {
		t.Errorf("ConfPath = %q", got)
	}
	if got := FingerprintDir("mimugmail"); got != "/usr/local/etc/pkg/fingerprints/netdefense-mimugmail" {
		t.Errorf("FingerprintDir = %q", got)
	}
	if got := PubkeyPath("mimugmail"); got != "/usr/local/etc/pkg/keys/netdefense-mimugmail.pub" {
		t.Errorf("PubkeyPath = %q", got)
	}
}
