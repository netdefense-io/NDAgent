package tasks

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// OPNsense links a certificate to its CA by subject name alone, and a CA
// write re-links every certificate to the newest CA of that name. The fake
// does the same, so these tests see what a device does.

const uuidLookalikeCA = "7a1d3c55-0f6e-4b2a-9c8d-1e2f3a4b5c6d"

// A CA whose subject name another CA already has, with another key, is
// refused before anything is written: on the device or in the same sync. The
// same name with the same key is the same CA, not a conflict.
func TestExecuteSyncTrust_RefusesTwoCAsOfOneName(t *testing.T) {
	p := newTrustPKI(t)
	recordConfigctl(t)

	t.Run("on the device", func(t *testing.T) {
		f := newFakeTrust(t)
		f.add(opnapi.TrustCA, uuidLookalikeCA, "hand-made root", newTestCA(t, "Corp Root CA", nil, nil).certPEM, "", "")
		out := runTrust(t, f, trustPayload(caSnippet(uuidRootCA, "Corp Root CA", p.root)), false, writeConfigXML(t, ""))
		assertItems(t, out.Result, "trust_ca Corp Root CA blocked blocked TRUST_CA_DN_CONFLICT")
		if msg := out.Result.Results[0].Error; !strings.Contains(msg, `the CA "hand-made root" on the device`) || !strings.Contains(msg, "G2") {
			t.Errorf("refusal = %q", msg)
		}
		if len(f.writeLog()) != 0 {
			t.Fatalf("writes = %q", f.writeLog())
		}
	})

	t.Run("in the same sync", func(t *testing.T) {
		f := newFakeTrust(t)
		other := newTestCA(t, "Corp Root CA", nil, nil)
		out := runTrust(t, f, trustPayload(
			caSnippet(uuidRootCA, "Corp Root CA", p.root),
			caSnippet(uuidOrphanCA, "Corp Root CA 2025", other),
		), false, writeConfigXML(t, ""))
		assertItems(t, out.Result,
			"trust_ca Corp Root CA blocked blocked TRUST_CA_DN_CONFLICT",
			"trust_ca Corp Root CA 2025 blocked blocked TRUST_CA_DN_CONFLICT",
		)
		if msg := out.Result.Results[0].Error; !strings.Contains(msg, `the CA "Corp Root CA 2025" in this sync`) {
			t.Errorf("refusal = %q", msg)
		}
		if len(f.writeLog()) != 0 {
			t.Fatalf("writes = %q", f.writeLog())
		}
	})

	t.Run("the same name with the same key", func(t *testing.T) {
		f := newFakeTrust(t)
		f.add(opnapi.TrustCA, uuidLookalikeCA, "hand-made copy", newTestCA(t, "Corp Root CA", nil, p.root.key).certPEM, "", "")
		out := runTrust(t, f, trustPayload(caSnippet(uuidRootCA, "Corp Root CA", p.root)), false, writeConfigXML(t, ""))
		assertItems(t, out.Result, "trust_ca Corp Root CA created success")
	})
}

// A hand-made CA of the same name takes the certificates over, as OPNsense
// re-links them to the newest CA of a name. Every pass reports it, the CA as a
// name conflict and the certificate as linked to a CA that did not issue it,
// and writes nothing, a renewal included. The CA that signed the certificate
// stays while the certificate does. Once the hand-made CA is gone, the next
// sync has OPNsense link the certificate again.
func TestExecuteSyncTrust_ReportsAHandMadeCAOfTheSameName(t *testing.T) {
	p := newTrustPKI(t)
	f := newFakeTrust(t)
	recordConfigctl(t)
	payload := trustPayload(caSnippet(uuidRootCA, "Corp Root CA", p.root), certSnippet(uuidHostCert, "fw1", p.host))

	out := runTrust(t, f, payload, false, writeConfigXML(t, ""))
	assertItems(t, out.Result, "trust_ca Corp Root CA created success", "trust_cert fw1 created success")
	root := f.find(opnapi.TrustCA, uuidRootCA)
	if got := f.find(opnapi.TrustCert, uuidHostCert).caref; got != root.refid {
		t.Fatalf("caref = %q, want the root's %q", got, root.refid)
	}

	// Someone imports another CA of the same name by hand: OPNsense links fw1 to it.
	lookalike := newTestCA(t, "Corp Root CA", nil, nil)
	f.add(opnapi.TrustCA, uuidLookalikeCA, "hand-made root", lookalike.certPEM, "", "")
	f.linkCaRefs("")
	lookalikeRef := f.find(opnapi.TrustCA, uuidLookalikeCA).refid
	if got := f.find(opnapi.TrustCert, uuidHostCert).caref; got != lookalikeRef {
		t.Fatalf("the fake did not re-link: caref = %q, want %q", got, lookalikeRef)
	}

	writes := len(f.writeLog())
	out = runTrust(t, f, payload, false, writeConfigXML(t, ""))
	assertItems(t, out.Result,
		"trust_ca Corp Root CA blocked blocked TRUST_CA_DN_CONFLICT",
		"trust_cert fw1 blocked blocked TRUST_ISSUER_MISLINKED",
	)
	if msg := out.Result.Results[1].Error; !strings.Contains(msg, `the CA "hand-made root", which did not issue it`) || !strings.Contains(msg, "Nothing was written") {
		t.Errorf("refusal = %q", msg)
	}
	if got := f.writeLog()[writes:]; len(got) != 0 {
		t.Fatalf("writes = %q", got)
	}

	// A renewal of the mislinked certificate is written all the same, since
	// its link stays the same, and still reported.
	renewed := p.root.issue(t, "fw1.example.net", true)
	out = runTrust(t, f, trustPayload(caSnippet(uuidRootCA, "Corp Root CA", p.root), certSnippet(uuidHostCert, "fw1", renewed)), false, writeConfigXML(t, ""))
	assertItems(t, out.Result,
		"trust_ca Corp Root CA blocked blocked TRUST_CA_DN_CONFLICT",
		"trust_cert fw1 blocked blocked TRUST_ISSUER_MISLINKED",
	)
	if msg := out.Result.Results[1].Error; !strings.Contains(msg, "The certificate was written") {
		t.Errorf("refusal = %q", msg)
	}
	if got := f.writeLog()[writes:]; len(got) != 1 || f.find(opnapi.TrustCert, uuidHostCert).caref != lookalikeRef {
		t.Fatalf("writes = %q, caref %q", got, f.find(opnapi.TrustCert, uuidHostCert).caref)
	}

	// The root leaves the payload while fw1, which it signed, stays: no
	// certificate names it and it counts no reference, and it is kept anyway.
	out = runTrust(t, f, trustPayload(certSnippet(uuidHostCert, "fw1", renewed)), false, f.configXML(t, ""))
	assertItems(t, out.Result,
		"trust_cert fw1 blocked blocked TRUST_ISSUER_MISLINKED",
		"trust_ca Corp Root CA retained blocked TRUST_IN_USE",
	)
	if msg := out.Result.Results[1].Error; !strings.Contains(msg, `certificate "fw1"`) {
		t.Errorf("refusal = %q", msg)
	}

	// The hand-made CA is deleted, which re-links nothing: fw1 still names it.
	// The next sync writes fw1 again and OPNsense links it to the root.
	f.cas = f.cas[:1]
	out = runTrust(t, f, trustPayload(caSnippet(uuidRootCA, "Corp Root CA", p.root), certSnippet(uuidHostCert, "fw1", renewed)), false, writeConfigXML(t, ""))
	assertItems(t, out.Result, "trust_ca Corp Root CA unchanged success", "trust_cert fw1 updated success")
	if got := f.find(opnapi.TrustCert, uuidHostCert).caref; got != root.refid {
		t.Fatalf("caref = %q, want the root's %q", got, root.refid)
	}
}

// A CA the payload drops is removed once nothing it signed is left, even when
// OPNsense still links a certificate to it by name.
func TestExecuteSyncTrust_RemovesACAThatSignedNothingLeft(t *testing.T) {
	p := newTrustPKI(t)
	f := newFakeTrust(t)
	recordConfigctl(t)
	f.add(opnapi.TrustCA, uuidRootCA, "Corp Root CA", p.root.certPEM, "", "")
	f.add(opnapi.TrustCert, uuidHandMade, "hand-made", p.inter.issue(t, "x.example.net", false).certPEM, "", "")

	out := runTrust(t, f, trustPayload(), false, f.configXML(t, ""))
	assertItems(t, out.Result, "trust_ca Corp Root CA deleted success")
}

// newNamedCA makes a CA with this subject, issued by parent (self-signed when
// nil), with an EC key; sha1 signs it with SHA-1 and an RSA key instead.
func newNamedCA(t *testing.T, subject pkix.Name, parent *testCA, sha1 bool) *testCA {
	t.Helper()
	var key crypto.Signer = newECKey(t)
	algo := x509.UnknownSignatureAlgorithm
	if sha1 {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		key, algo = k, x509.SHA1WithRSA
	}
	template := &x509.Certificate{
		SerialNumber: nextSerial(), Subject: subject,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SignatureAlgorithm: algo,
	}
	issuer, signer := template, key
	if parent != nil {
		issuer, signer = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, key.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key, certPEM: certPEMOf(der)}
}

// The overlapping layout: a root "CN=Acme,O=Acme,C=US" and its intermediate
// "CN=Acme Issuing CA,O=Acme,C=US". The root's values all occur in the
// intermediate's name, so OPNsense counts the root as an issuer of what the
// intermediate issued.
func overlappingPKI(t *testing.T) (root, inter *testCA, leaf testLeaf) {
	t.Helper()
	root = newNamedCA(t, pkix.Name{CommonName: "Acme", Organization: []string{"Acme"}, Country: []string{"US"}}, nil, false)
	inter = newNamedCA(t, pkix.Name{CommonName: "Acme Issuing CA", Organization: []string{"Acme"}, Country: []string{"US"}}, root, false)
	return root, inter, inter.issue(t, "fw1.example.net", false)
}

// OPNsense's pick compares values, not attribute types, ranks by the number of
// attribute types and then by the newest refid, and reads a type that occurs
// twice as one list.
func TestOPNsenseIssuer_TheWayOPNsensePicks(t *testing.T) {
	root, inter, leaf := overlappingPKI(t)
	ca := func(c *testCA, refid string) opnapi.TrustObject {
		return opnapi.TrustObject{UUID: refid, RefID: refid, Cert: c.cert}
	}
	pick := func(cas ...opnapi.TrustObject) string {
		r := &trustRun{cas: cas}
		if got := r.opnsenseIssuer(leaf.cert); got != nil {
			return got.RefID
		}
		return ""
	}
	if got := pick(ca(inter, "66f0000000001"), ca(root, "66f0000000002")); got != "66f0000000002" {
		t.Errorf("a newer root of as many types is picked over the intermediate: got %q", got)
	}
	if got := pick(ca(root, "66f0000000001"), ca(inter, "66f0000000002")); got != "66f0000000002" {
		t.Errorf("a newer intermediate is picked: got %q", got)
	}
	short := newNamedCA(t, pkix.Name{CommonName: "Acme Issuing CA"}, nil, false)
	if got := pick(ca(inter, "66f0000000001"), ca(short, "66f0000000009")); got != "66f0000000001" {
		t.Errorf("more attribute types win over a newer refid: got %q", got)
	}
	swapped := newNamedCA(t, pkix.Name{CommonName: "US", Organization: []string{"Acme Issuing CA"}, Country: []string{"Acme"}}, nil, false)
	if got := pick(ca(swapped, "66f0000000005")); got != "66f0000000005" {
		t.Errorf("the attribute types count for nothing: got %q", got)
	}
	twoOUs := newNamedCA(t, pkix.Name{CommonName: "Acme Issuing CA", OrganizationalUnit: []string{"a", "b"}}, nil, false)
	if got := pick(ca(twoOUs, "66f0000000006")); got != "" {
		t.Errorf("an attribute that occurs twice is one value, which the issuer lacks: got %q", got)
	}

	// Types are counted, not attributes: two OUs are one type, so the newer
	// CA of as many types wins over the one with more attributes.
	issuer := newNamedCA(t, pkix.Name{CommonName: "X", Organization: []string{"Y"}, OrganizationalUnit: []string{"a", "b"}}, nil, false)
	leafOf := issuer.issue(t, "leaf.example.net", false)
	withOUs := newNamedCA(t, pkix.Name{CommonName: "X", OrganizationalUnit: []string{"a", "b"}}, nil, false)
	withO := newNamedCA(t, pkix.Name{CommonName: "X", Organization: []string{"Y"}}, nil, false)
	r := &trustRun{cas: []opnapi.TrustObject{ca(withOUs, "66f0000000001"), ca(withO, "66f0000000002")}}
	if got := r.opnsenseIssuer(leafOf.cert); got == nil || got.RefID != "66f0000000002" {
		t.Errorf("ranked by attributes rather than types: got %+v", got)
	}
}

// A certificate OPNsense linked to a CA that did not issue it is fixed by the
// sync that adds the CA that did: the CA write re-links every certificate,
// which the agent reads again before judging them.
func TestExecuteSyncTrust_AnIssuerAddedLaterFixesTheLink(t *testing.T) {
	root, inter, leaf := overlappingPKI(t)
	f := newFakeTrust(t)
	recordConfigctl(t)
	f.add(opnapi.TrustCA, uuidRootCA, "Acme Root", root.certPEM, "", "")
	f.add(opnapi.TrustCert, uuidHostCert, "fw1", leaf.certPEM, leaf.keyPEM, "")
	f.linkCaRefs("")

	out := runTrust(t, f, trustPayload(
		caSnippet(uuidRootCA, "Acme Root", root),
		caSnippet(uuidInterCA, "Acme Issuing CA", inter),
		certSnippet(uuidHostCert, "fw1", leaf),
	), false, writeConfigXML(t, ""))
	assertItems(t, out.Result,
		"trust_ca Acme Root unchanged success",
		"trust_ca Acme Issuing CA created success",
		"trust_cert fw1 unchanged success",
	)
}

// CAs are created parent before child, so the intermediate gets the newer
// refid and OPNsense links what it issued to it, whatever order the payload
// lists them in.
func TestExecuteSyncTrust_CreatesParentsFirst(t *testing.T) {
	root, inter, leaf := overlappingPKI(t)
	f := newFakeTrust(t)
	recordConfigctl(t)
	out := runTrust(t, f, trustPayload(
		caSnippet(uuidInterCA, "Acme Issuing CA", inter),
		caSnippet(uuidRootCA, "Acme Root", root),
		certSnippet(uuidHostCert, "fw1", leaf),
	), false, writeConfigXML(t, ""))
	assertItems(t, out.Result,
		"trust_ca Acme Root created success",
		"trust_ca Acme Issuing CA created success",
		"trust_cert fw1 created success",
	)
	if got, want := f.find(opnapi.TrustCert, uuidHostCert).caref, f.find(opnapi.TrustCA, uuidInterCA).refid; got != want {
		t.Fatalf("caref = %q, want the intermediate's %q", got, want)
	}
}

// A certificate OPNsense links, or would link, to a CA that did not issue it
// is refused and nothing is written: with the root of the overlapping layout
// newer than its intermediate, and with only the root on the device.
func TestExecuteSyncTrust_RefusesALinkToACAThatDidNotIssueIt(t *testing.T) {
	root, inter, leaf := overlappingPKI(t)
	recordConfigctl(t)

	t.Run("on the device", func(t *testing.T) {
		f := newFakeTrust(t)
		i := f.add(opnapi.TrustCA, uuidInterCA, "Acme Issuing CA", inter.certPEM, "", "")
		i.caref = f.add(opnapi.TrustCA, uuidRootCA, "Acme Root", root.certPEM, "", "").refid
		f.add(opnapi.TrustCert, uuidHostCert, "fw1", leaf.certPEM, leaf.keyPEM, i.refid)
		f.linkCaRefs("")
		out := runTrust(t, f, trustPayload(
			caSnippet(uuidRootCA, "Acme Root", root),
			caSnippet(uuidInterCA, "Acme Issuing CA", inter),
			certSnippet(uuidHostCert, "fw1", leaf),
		), false, writeConfigXML(t, ""))
		assertItems(t, out.Result,
			"trust_ca Acme Root unchanged success",
			"trust_ca Acme Issuing CA unchanged success",
			"trust_cert fw1 blocked blocked TRUST_ISSUER_MISLINKED",
		)
		if msg := out.Result.Results[2].Error; !strings.Contains(msg, `the CA "Acme Root", which did not issue it`) {
			t.Errorf("refusal = %q", msg)
		}
		if len(f.writeLog()) != 0 {
			t.Fatalf("writes = %q", f.writeLog())
		}
	})

	t.Run("before a write", func(t *testing.T) {
		f := newFakeTrust(t)
		f.add(opnapi.TrustCA, uuidRootCA, "Acme Root", root.certPEM, "", "")
		out := runTrust(t, f, trustPayload(caSnippet(uuidRootCA, "Acme Root", root), certSnippet(uuidHostCert, "fw1", leaf)), false, writeConfigXML(t, ""))
		assertItems(t, out.Result,
			"trust_ca Acme Root unchanged success",
			"trust_cert fw1 blocked blocked TRUST_ISSUER_MISLINKED",
		)
		if len(f.writeLog()) != 0 {
			t.Fatalf("writes = %q", f.writeLog())
		}
	})
}

// A CA copy, the same subject and key (re-issued as a new snippet, or added
// twice), verifies whatever the other signed. A CA the payload drops is
// therefore removed when a copy of it stays, whether NetDefense manages the
// copy or not, and kept when none does.
func TestExecuteSyncTrust_DropsACAWhoseCopyStays(t *testing.T) {
	p := newTrustPKI(t)
	recordConfigctl(t)
	copyOfRoot := newTestCA(t, "Corp Root CA", nil, p.root.key)

	for _, tc := range []struct {
		name    string
		managed bool
		payload func() map[string]interface{}
		want    []string
	}{
		{"a managed copy the payload names", true,
			func() map[string]interface{} {
				return trustPayload(caSnippet(uuidInterCA, "Corp Root CA 2", copyOfRoot), certSnippet(uuidHostCert, "fw1", p.host))
			},
			[]string{"trust_ca Corp Root CA 2 unchanged success", "trust_cert fw1 unchanged success", "trust_ca Corp Root CA deleted success"}},
		{"a hand-made copy", false,
			func() map[string]interface{} { return trustPayload(certSnippet(uuidHostCert, "fw1", p.host)) },
			[]string{"trust_cert fw1 unchanged success", "trust_ca Corp Root CA deleted success"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeTrust(t)
			f.add(opnapi.TrustCA, uuidRootCA, "Corp Root CA", p.root.certPEM, "", "")
			copyUUID, copyName := uuidLookalikeCA, "hand-made copy"
			if tc.managed {
				copyUUID, copyName = uuidInterCA, "Corp Root CA 2"
			}
			c := f.add(opnapi.TrustCA, copyUUID, copyName, copyOfRoot.certPEM, "", "")
			f.add(opnapi.TrustCert, uuidHostCert, "fw1", p.host.certPEM, p.host.keyPEM, c.refid)
			out := runTrust(t, f, tc.payload(), false, f.configXML(t, ""))
			assertItems(t, out.Result, tc.want...)
		})
	}
}

// Go refuses to check SHA-1 and MD5 signatures; for such certificates the
// issuer name decides, so an old certificate is not taken for a mislinked one.
func TestSigns_AnInsecureSignatureFallsBackToTheIssuerName(t *testing.T) {
	ca := newNamedCA(t, pkix.Name{CommonName: "Old CA"}, nil, true)
	leaf := newNamedCA(t, pkix.Name{CommonName: "Old Sub CA"}, ca, true)
	if err := leaf.cert.CheckSignatureFrom(ca.cert); err == nil {
		t.Fatal("Go verified a SHA-1 signature; the test proves nothing")
	}
	if !signs(ca.cert, leaf.cert) {
		t.Error("a SHA-1 certificate under the CA of its issuer name was refused")
	}
	other := newNamedCA(t, pkix.Name{CommonName: "Other CA"}, nil, true)
	if signs(other.cert, leaf.cert) {
		t.Error("a CA of another name was accepted")
	}
}

// Dropping the newer of two copies of a CA (the same subject and key, an
// accidental duplicate snippet, say): OPNsense links every certificate to the
// newer copy, so its links must not keep it. It goes; the next pass writes the
// certificate whose issuer is gone and OPNsense links it to the copy left.
func TestExecuteSyncTrust_DropsTheNewerCopyOfACA(t *testing.T) {
	p := newTrustPKI(t)
	f := newFakeTrust(t)
	recordConfigctl(t)
	older := f.add(opnapi.TrustCA, uuidRootCA, "Corp Root CA", p.root.certPEM, "", "")
	f.add(opnapi.TrustCA, uuidOrphanCA, "Corp Root CA again", newTestCA(t, "Corp Root CA", nil, p.root.key).certPEM, "", "")
	f.add(opnapi.TrustCert, uuidHostCert, "fw1", p.host.certPEM, p.host.keyPEM, "")
	f.linkCaRefs("")
	if got := f.find(opnapi.TrustCert, uuidHostCert).caref; got != f.find(opnapi.TrustCA, uuidOrphanCA).refid {
		t.Fatalf("fw1 is not linked to the newer copy: %q", got)
	}
	payload := trustPayload(caSnippet(uuidRootCA, "Corp Root CA", p.root), certSnippet(uuidHostCert, "fw1", p.host))

	out := runTrust(t, f, payload, false, f.configXML(t, ""))
	assertItems(t, out.Result,
		"trust_ca Corp Root CA unchanged success",
		"trust_cert fw1 unchanged success",
		"trust_ca Corp Root CA again deleted success",
	)
	out = runTrust(t, f, payload, false, f.configXML(t, ""))
	assertItems(t, out.Result, "trust_ca Corp Root CA unchanged success", "trust_cert fw1 updated success")
	if got := f.find(opnapi.TrustCert, uuidHostCert).caref; got != older.refid {
		t.Fatalf("caref = %q, want the copy left %q", got, older.refid)
	}
	out = runTrust(t, f, payload, false, f.configXML(t, ""))
	assertItems(t, out.Result, "trust_ca Corp Root CA unchanged success", "trust_cert fw1 unchanged success")
}

// A CA whose issuer is on the device while OPNsense records none for it (its
// issuer was deleted, or came after it: OPNsense links a CA only when the CA
// is imported) is written again, and OPNsense links it.
func TestExecuteSyncTrust_RelinksACAThatLostItsIssuer(t *testing.T) {
	p := newTrustPKI(t)
	f := newFakeTrust(t)
	recordConfigctl(t)
	inter := f.add(opnapi.TrustCA, uuidInterCA, "Corp Issuing CA", p.inter.certPEM, "", "66f0deadbeef0")
	root := f.add(opnapi.TrustCA, uuidRootCA, "Corp Root CA", p.root.certPEM, "", "")
	f.add(opnapi.TrustCert, uuidWildcard, "fw-wildcard", p.wildcard.certPEM, p.wildcard.keyPEM, inter.refid)

	payload := trustPayload(caSnippet(uuidRootCA, "Corp Root CA", p.root), caSnippet(uuidInterCA, "Corp Issuing CA", p.inter), certSnippet(uuidWildcard, "fw-wildcard", p.wildcard))
	out := runTrust(t, f, payload, false, writeConfigXML(t, ""))
	assertItems(t, out.Result,
		"trust_ca Corp Root CA unchanged success",
		"trust_ca Corp Issuing CA updated success",
		"trust_cert fw-wildcard unchanged success",
	)
	if got := f.find(opnapi.TrustCA, uuidInterCA).caref; got != root.refid {
		t.Fatalf("the intermediate's caref = %q, want the root's %q", got, root.refid)
	}
	out = runTrust(t, f, payload, false, writeConfigXML(t, ""))
	assertItems(t, out.Result,
		"trust_ca Corp Root CA unchanged success",
		"trust_ca Corp Issuing CA unchanged success",
		"trust_cert fw-wildcard unchanged success",
	)
}

// A renewal that would move a certificate's link to a CA that did not issue it
// is refused unwritten; only one already linked to that CA is written.
func TestExecuteSyncTrust_ARenewalNeverMovesALinkToANonSigner(t *testing.T) {
	root, inter, leaf := overlappingPKI(t)
	f := newFakeTrust(t)
	recordConfigctl(t)
	r := f.add(opnapi.TrustCA, uuidRootCA, "Acme Root", root.certPEM, "", "")
	i := f.add(opnapi.TrustCA, uuidInterCA, "Acme Issuing CA", inter.certPEM, "", r.refid)
	f.add(opnapi.TrustCert, uuidHostCert, "fw1", leaf.certPEM, leaf.keyPEM, i.refid)
	// A newer copy of the root, which OPNsense has not linked anything to yet.
	f.add(opnapi.TrustCA, uuidLookalikeCA, "copy of the root", root.certPEM, "", "")

	renewed := inter.issue(t, "fw1.example.net", false)
	out := runTrust(t, f, trustPayload(
		caSnippet(uuidRootCA, "Acme Root", root),
		caSnippet(uuidInterCA, "Acme Issuing CA", inter),
		certSnippet(uuidHostCert, "fw1", renewed),
	), false, writeConfigXML(t, ""))
	assertItems(t, out.Result,
		"trust_ca Acme Root unchanged success",
		"trust_ca Acme Issuing CA unchanged success",
		"trust_cert fw1 blocked blocked TRUST_ISSUER_MISLINKED",
	)
	if msg := out.Result.Results[2].Error; !strings.Contains(msg, `the CA "copy of the root"`) || !strings.Contains(msg, "Nothing was written") {
		t.Errorf("refusal = %q", msg)
	}
	if len(f.writeLog()) != 0 {
		t.Fatalf("writes = %q", f.writeLog())
	}
}

// CAs a pass removes go child before parent by OPNsense's links as well as by
// signature, so a parent known only by a link is not judged while its child
// is still there.
func TestExecuteSyncTrust_RemovesAChainKnownByItsLinks(t *testing.T) {
	p := newTrustPKI(t)
	f := newFakeTrust(t)
	recordConfigctl(t)
	parent := f.add(opnapi.TrustCA, uuidRootCA, "Linked parent", p.root.certPEM, "", "")
	f.add(opnapi.TrustCA, uuidInterCA, "Linked child", newTestCA(t, "Unrelated CA", nil, nil).certPEM, "", parent.refid)

	out := runTrust(t, f, trustPayload(), false, f.configXML(t, ""))
	assertItems(t, out.Result,
		"trust_ca Linked child deleted success",
		"trust_ca Linked parent deleted success",
	)
}
