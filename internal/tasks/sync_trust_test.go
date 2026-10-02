package tasks

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"reflect"
	"strings"
	"testing"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// trustPKI is the PKI most tests use: a root CA, an intermediate it issued, a
// wildcard certificate from the intermediate and a host certificate from the
// root with an RSA key in PKCS#1.
type trustPKI struct {
	root, inter *testCA
	wildcard    testLeaf
	host        testLeaf
}

func newTrustPKI(t *testing.T) trustPKI {
	t.Helper()
	root := newTestCA(t, "Corp Root CA", nil, nil)
	inter := newTestCA(t, "Corp Issuing CA", root, nil)
	return trustPKI{
		root:     root,
		inter:    inter,
		wildcard: inter.issue(t, "*.example.net", false),
		host:     root.issue(t, "fw1.example.net", true),
	}
}

func (p trustPKI) payload() map[string]interface{} {
	return trustPayload(
		caSnippet(uuidRootCA, "Corp Root CA", p.root),
		caSnippet(uuidInterCA, "Corp Issuing CA", p.inter),
		certSnippet(uuidWildcard, "fw-wildcard", p.wildcard),
		certSnippet(uuidHostCert, "fw1", p.host),
	)
}

func runTrust(t *testing.T, f *fakeTrust, payload map[string]interface{}, rejectDangerous bool, configXML string) trustFamilyOutcome {
	t.Helper()
	parsed := parseAPITrustContent(payload)
	if parsed.Err != nil {
		t.Fatalf("payload does not parse: %s", parsed.Err.message())
	}
	return executeSyncTrust(context.Background(), f.client, parsed, rejectDangerous, configXML)
}

// itemsOf renders the result items as "type name action status code" lines.
func itemsOf(result SyncAPIResult) []string {
	var out []string
	for _, r := range result.Results {
		var parts []string
		for _, part := range []string{r.Type, r.Name, r.Action, r.Status, r.Code} {
			if part != "" {
				parts = append(parts, part)
			}
		}
		out = append(out, strings.Join(parts, " "))
	}
	return out
}

func assertItems(t *testing.T, result SyncAPIResult, want ...string) {
	t.Helper()
	got := itemsOf(result)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("items:\n  got  %q\n  want %q", got, want)
	}
	if len(result.Errors) > 0 {
		assertErrorHasMatchingResultItem(t, "trust", result.Errors, result.Results)
	} else if bad := countNonSuccessResults(result.Results); len(bad) > 0 {
		t.Fatalf("non-success items with no error: %+v", bad)
	}
}

func TestParseTrustContent_Valid(t *testing.T) {
	p := newTrustPKI(t)
	parsed := parseAPITrustContent(p.payload())
	if parsed.Err != nil {
		t.Fatalf("Err = %s", parsed.Err.message())
	}
	if len(parsed.CAs) != 2 || len(parsed.Certs) != 2 {
		t.Fatalf("parsed %d CAs and %d certs, want 2 and 2", len(parsed.CAs), len(parsed.Certs))
	}
	host := parsed.Certs[1]
	if host.Name != "fw1" || host.UUID != uuidHostCert || host.CertSHA256 != opnapi.CertFingerprint(p.host.cert) {
		t.Errorf("host cert = %+v", host)
	}
	if block, _ := pem.Decode([]byte(host.KeyPEM)); block == nil || block.Type != "RSA PRIVATE KEY" {
		t.Errorf("an RSA key in PKCS#1 is posted in PKCS#1")
	}
}

// A name may be up to 255 bytes, whatever its characters.
func TestParseTrustContent_NameLength(t *testing.T) {
	p := newTrustPKI(t)
	for name, accepted := range map[string]bool{
		strings.Repeat("a", 255): true,
		strings.Repeat("a", 256): false,
		strings.Repeat("é", 127): true,
		strings.Repeat("é", 128): false,
		"Corp Root CA (2026)":    true,
		"Zertifikat für Büro":    true,
	} {
		parsed := parseAPITrustContent(trustPayload(caSnippet(uuidRootCA, name, p.root)))
		if (parsed.Err == nil) != accepted {
			t.Errorf("name of %d bytes %.20q: accepted = %v, want %v", len(name), name, parsed.Err == nil, accepted)
		}
	}
}

// PEM text varies in line endings and the trailing newline; the item is the
// same whatever the spelling, and what is posted is the canonical PEM.
func TestParseTrustContent_NormalizesPEM(t *testing.T) {
	p := newTrustPKI(t)
	spellings := []func(string) string{
		func(s string) string { return s },
		func(s string) string { return strings.TrimRight(s, "\n") },
		func(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") },
		func(s string) string { return "\n\n" + s + "\n\n" },
	}
	var first trustItem
	for i, spell := range spellings {
		parsed := parseAPITrustContent(trustPayload(trustSnippet("TRUST_CERT", "fw-wildcard", map[string]string{
			"uuid": uuidWildcard, "name": "fw-wildcard", "crt": spell(p.wildcard.certPEM), "key": spell(p.wildcard.keyPEM),
		})))
		if parsed.Err != nil {
			t.Fatalf("spelling %d: %s", i, parsed.Err.message())
		}
		item := parsed.Certs[0]
		if i == 0 {
			first = item
			continue
		}
		if item.CertSHA256 != first.CertSHA256 || item.KeySHA256 != first.KeySHA256 || item.CertPEM != first.CertPEM || item.KeyPEM != first.KeyPEM {
			t.Errorf("spelling %d reads differently", i)
		}
	}
	if !strings.HasSuffix(first.CertPEM, "-----END CERTIFICATE-----\n") || strings.Contains(first.CertPEM, "\r") {
		t.Errorf("the posted certificate is not canonical PEM")
	}
}

func TestParseTrustContent_Refusals(t *testing.T) {
	p := newTrustPKI(t)
	other := p.root.issue(t, "other.example.net", false)
	encrypted := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-128-CBC,00"}, Bytes: []byte("x")}))
	pkcs8Encrypted := string(pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("x")}))
	leafAsCA := strings.TrimSpace(p.wildcard.certPEM)

	ca := func(fields map[string]string) map[string]interface{} { return trustSnippet("TRUST_CA", "ca", fields) }
	cert := func(fields map[string]string) map[string]interface{} {
		return trustSnippet("TRUST_CERT", "cert", fields)
	}
	good := map[string]string{"uuid": uuidWildcard, "name": "fw-wildcard", "crt": p.wildcard.certPEM, "key": p.wildcard.keyPEM}
	with := func(key, value string) map[string]string {
		m := map[string]string{}
		for k, v := range good {
			m[k] = v
		}
		m[key] = value
		return m
	}

	cases := map[string]map[string]interface{}{
		"an unknown key":                       cert(with("comment", "x")),
		"a key on a CA":                        ca(map[string]string{"uuid": uuidRootCA, "name": "ca", "crt": p.root.certPEM, "key": "x"}),
		"no key on a certificate":              cert(map[string]string{"uuid": uuidWildcard, "name": "c", "crt": p.wildcard.certPEM}),
		"a uuid NetDefense does not own":       cert(with("uuid", uuidHandMade)),
		"a uuid in capitals":                   cert(with("uuid", strings.ToUpper(uuidWildcard))),
		"a uuid that is not version 4":         cert(with("uuid", "221f3268-2222-1222-9222-000000000001")),
		"a name with a variable":               cert(with("name", "fw-${site}")),
		"a name with a control character":      cert(with("name", "fw\twildcard")),
		"a blank name":                         cert(with("name", "  ")),
		"an unresolved crt":                    cert(with("crt", "${fw_crt}")),
		"a crt with two certificates":          cert(with("crt", p.wildcard.certPEM+p.inter.certPEM)),
		"a crt that holds the key":             cert(with("crt", p.wildcard.certPEM+p.wildcard.keyPEM)),
		"a crt that does not parse":            cert(with("crt", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")})))),
		"a key in a CERTIFICATE block":         cert(with("key", p.wildcard.certPEM)),
		"an encrypted key":                     cert(with("key", encrypted)),
		"an encrypted PKCS#8 key":              cert(with("key", pkcs8Encrypted)),
		"two keys":                             cert(with("key", p.wildcard.keyPEM+p.wildcard.keyPEM)),
		"a key of another certificate":         cert(with("key", other.keyPEM)),
		"a CA that is not a CA":                ca(map[string]string{"uuid": uuidRootCA, "name": "ca", "crt": leafAsCA}),
		"trailing data":                        {"config_type": "TRUST_CERT", "snippet_name": "cert", "content": mustJSON(good) + ` {"x":1}`},
		"text before the crt block":            cert(with("crt", "subject=CN=x\n"+p.wildcard.certPEM)),
		"text after the crt block":             cert(with("crt", p.wildcard.certPEM+"issuer=CN=x\n")),
		"a crt line with a leading space":      cert(with("crt", strings.Replace(p.wildcard.certPEM, "\nM", "\n M", 1))),
		"a blank line inside the crt":          cert(with("crt", strings.Replace(p.wildcard.certPEM, "-----\n", "-----\n\n", 1))),
		"a crt that lost a line":               cert(with("crt", dropPEMLine(p.wildcard.certPEM, 2))),
		"armor labels that differ":             cert(with("crt", strings.Replace(p.wildcard.certPEM, "END CERTIFICATE", "END X509 CERTIFICATE", 1))),
		"a key with a header":                  cert(with("key", strings.Replace(p.wildcard.keyPEM, "-----\n", "-----\nComment: x\n\n", 1))),
		"a key that lost a line":               cert(with("key", dropPEMLine(p.host.keyPEM, 3))),
		"a key relabelled CERTIFICATE":         cert(with("crt", relabel(p.wildcard.keyPEM, "CERTIFICATE"))),
		"a public key relabelled CERTIFICATE":  cert(with("crt", relabel(publicKeyPEM(t, p.wildcard), "CERTIFICATE"))),
		"a certificate relabelled PRIVATE KEY": cert(with("key", relabel(p.wildcard.certPEM, "PRIVATE KEY"))),
		"a public key relabelled PRIVATE KEY":  cert(with("key", relabel(publicKeyPEM(t, p.wildcard), "PRIVATE KEY"))),
		"a name over 255 bytes":                cert(with("name", strings.Repeat("é", 128))),
		"a name with surrounding space":        cert(with("name", " fw-wildcard")),
		"a name with a format character":       cert(with("name", "fw\u200bwildcard")),
		"a name with a line break":             cert(with("name", "fw\nwildcard")),
		"a key spelled in capitals":            {"config_type": "TRUST_CERT", "snippet_name": "cert", "content": strings.Replace(mustJSON(good), `"crt"`, `"CRT"`, 1)},
		"a key given twice":                    {"config_type": "TRUST_CERT", "snippet_name": "cert", "content": strings.Replace(mustJSON(good), `{`, `{"name":"other",`, 1)},
		"a value that is not a string":         {"config_type": "TRUST_CERT", "snippet_name": "cert", "content": strings.Replace(mustJSON(good), `"name":"fw-wildcard"`, `"name":["fw-wildcard"]`, 1)},
		"content that is a list":               {"config_type": "TRUST_CERT", "snippet_name": "cert", "content": "[" + mustJSON(good) + "]"},
		"content that is not JSON":             {"config_type": "TRUST_CERT", "snippet_name": "cert", "content": "-----BEGIN PRIVATE KEY-----"},
	}
	for name, snippet := range cases {
		t.Run(name, func(t *testing.T) {
			parsed := parseAPITrustContent(trustPayload(caSnippet(uuidRootCA, "Corp Root CA", p.root), snippet))
			if parsed.Err == nil {
				t.Fatal("the content was accepted")
			}
			msg := parsed.Err.message()
			if !strings.HasPrefix(msg, trustCodeContentUnsupported+": ") {
				t.Errorf("message = %q", msg)
			}
			assertNoMaterial(t, "the refusal", msg, p.wildcard, other)
		})
	}
}

// relabel gives the first PEM block of text another label, body unchanged.
func relabel(text, label string) string {
	block, _ := pem.Decode([]byte(text))
	return string(pem.EncodeToMemory(&pem.Block{Type: label, Bytes: block.Bytes}))
}

// publicKeyPEM is the public key of a leaf, in PKIX PEM.
func publicKeyPEM(t *testing.T, leaf testLeaf) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(leaf.cert.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// dropPEMLine removes line n (0 is the BEGIN line) of a PEM text.
func dropPEMLine(text string, n int) string {
	lines := strings.Split(text, "\n")
	return strings.Join(append(lines[:n:n], lines[n+1:]...), "\n")
}

func mustJSON(v interface{}) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}

// The same snippet reached twice is one item; one uuid with two contents is
// content the agent cannot read.
func TestParseTrustContent_Duplicates(t *testing.T) {
	p := newTrustPKI(t)
	parsed := parseAPITrustContent(trustPayload(
		certSnippet(uuidWildcard, "fw-wildcard", p.wildcard),
		certSnippet(uuidWildcard, "fw-wildcard", p.wildcard),
	))
	if parsed.Err != nil || len(parsed.Certs) != 1 {
		t.Fatalf("a repeated snippet: Err = %v, %d certs", parsed.Err, len(parsed.Certs))
	}
	parsed = parseAPITrustContent(trustPayload(
		certSnippet(uuidWildcard, "fw-wildcard", p.wildcard),
		certSnippet(uuidWildcard, "fw-wildcard", p.host),
	))
	if parsed.Err == nil {
		t.Fatal("one uuid with two certificates was accepted")
	}
	parsed = parseAPITrustContent(trustPayload(
		caSnippet(uuidRootCA, "Corp Root CA", p.root),
		trustSnippet("TRUST_CERT", "x", map[string]string{"uuid": uuidRootCA, "name": "x", "crt": p.wildcard.certPEM, "key": p.wildcard.keyPEM}),
	))
	if parsed.Err == nil {
		t.Fatal("one uuid for a CA and a certificate was accepted")
	}
}

// A first sync creates the CAs, then the certificates, each with the action
// that keeps its material, no refid, and the issuer the device knows; a second
// sync of the same payload changes nothing.
func TestExecuteSyncTrust_CreateThenNoOp(t *testing.T) {
	p := newTrustPKI(t)
	f := newFakeTrust(t)
	calls := recordConfigctl(t)
	cfg := writeConfigXML(t, "")

	out := runTrust(t, f, p.payload(), false, cfg)
	assertItems(t, out.Result,
		"trust_ca Corp Root CA created success",
		"trust_ca Corp Issuing CA created success",
		"trust_cert fw-wildcard created success",
		"trust_cert fw1 created success",
	)
	if !out.Result.Success || out.RestartWebGUI {
		t.Fatalf("Success = %v, RestartWebGUI = %v", out.Result.Success, out.RestartWebGUI)
	}
	wantWrites := []string{"set ca " + uuidRootCA, "set ca " + uuidInterCA, "set cert " + uuidWildcard, "set cert " + uuidHostCert}
	if got := f.writeLog(); !reflect.DeepEqual(got, wantWrites) {
		t.Fatalf("writes = %q, want %q", got, wantWrites)
	}
	inter := f.find(opnapi.TrustCA, uuidInterCA)
	root := f.find(opnapi.TrustCA, uuidRootCA)
	if got := f.find(opnapi.TrustCert, uuidWildcard).caref; got != inter.refid {
		t.Errorf("wildcard caref = %q, want the intermediate's refid %q", got, inter.refid)
	}
	if got := f.find(opnapi.TrustCert, uuidHostCert).caref; got != root.refid {
		t.Errorf("host caref = %q, want the root's refid %q", got, root.refid)
	}
	if len(*calls) != 0 {
		t.Errorf("configctl calls = %q: the CA API rebuilds the system trust store itself", *calls)
	}

	*calls = nil
	out = runTrust(t, f, p.payload(), false, cfg)
	assertItems(t, out.Result,
		"trust_ca Corp Root CA unchanged success",
		"trust_ca Corp Issuing CA unchanged success",
		"trust_cert fw-wildcard unchanged success",
		"trust_cert fw1 unchanged success",
	)
	if len(f.writeLog()) != len(wantWrites) || len(*calls) != 0 {
		t.Fatalf("a repeated sync wrote %q and ran %q", f.writeLog()[len(wantWrites):], *calls)
	}
}

// A certificate imported before its CA is recorded with no issuer; the next
// sync repairs that without a reload, since the material did not change.
func TestExecuteSyncTrust_RepairsTheIssuer(t *testing.T) {
	p := newTrustPKI(t)
	f := newFakeTrust(t)
	calls := recordConfigctl(t)
	root := f.add(opnapi.TrustCA, uuidRootCA, "Corp Root CA", p.root.certPEM, "", "")
	f.add(opnapi.TrustCert, uuidHostCert, "fw1", p.host.certPEM, p.host.keyPEM, "")
	cfg := writeConfigXML(t, `<system><webgui><ssl-certref>`+f.find(opnapi.TrustCert, uuidHostCert).refid+`</ssl-certref></webgui></system>`)

	out := runTrust(t, f, trustPayload(caSnippet(uuidRootCA, "Corp Root CA", p.root), certSnippet(uuidHostCert, "fw1", p.host)), false, cfg)
	assertItems(t, out.Result,
		"trust_ca Corp Root CA unchanged success",
		"trust_cert fw1 updated success",
	)
	if got := f.find(opnapi.TrustCert, uuidHostCert).caref; got != root.refid {
		t.Errorf("caref = %q, want %q", got, root.refid)
	}
	if out.RestartWebGUI || len(*calls) != 0 {
		t.Errorf("an issuer repair reloaded: restart=%v, configctl=%q", out.RestartWebGUI, *calls)
	}
}

// A renewal keeps the refid, so every binding survives, and reloads what uses
// the certificate: one action per kind of service, one item per service. The
// web GUI is scheduled, a local account's certificate is not a service, and a
// setting with no known reload is a warning.
func TestExecuteSyncTrust_RenewalReloadsWhatUsesTheCertificate(t *testing.T) {
	p := newTrustPKI(t)
	f := newFakeTrust(t)
	calls := recordConfigctl(t)
	f.add(opnapi.TrustCA, uuidInterCA, "Corp Issuing CA", p.inter.certPEM, "", "")
	inter := f.find(opnapi.TrustCA, uuidInterCA)
	old := p.inter.issue(t, "*.example.net", false)
	cert := f.add(opnapi.TrustCert, uuidWildcard, "fw-wildcard", old.certPEM, old.keyPEM, inter.refid)
	ref := cert.refid
	cfg := writeConfigXML(t, `
<system>
  <webgui><protocol>https</protocol><ssl-certref>`+ref+`</ssl-certref></webgui>
  <user><name>alice</name><cert>`+ref+`</cert></user>
</system>
<OPNsense>
  <OpenVPN><Instances>
    <Instance uuid="aaaaaaaa-0000-4000-8000-000000000001"><description>Road warriors</description><cert>`+ref+`</cert></Instance>
    <Instance uuid="aaaaaaaa-0000-4000-8000-000000000002"><description>Site B</description><cert>`+ref+`</cert></Instance>
  </Instances></OpenVPN>
  <Swanctl><locals><local uuid="bbbbbbbb-0000-4000-8000-000000000001"><description>HQ</description><certs>other,`+ref+`</certs></local></locals></Swanctl>
  <Syslog><destinations><destination uuid="cccccccc-0000-4000-8000-000000000001"><description>SIEM</description><certificate>`+ref+`</certificate></destination></destinations></Syslog>
  <Nginx><http_server uuid="dddddddd-0000-4000-8000-000000000001"><servername>portal</servername><certificate>`+ref+`</certificate></http_server></Nginx>
</OPNsense>`)

	out := runTrust(t, f, trustPayload(caSnippet(uuidInterCA, "Corp Issuing CA", p.inter), certSnippet(uuidWildcard, "fw-wildcard", p.wildcard)), false, cfg)
	assertItems(t, out.Result,
		"trust_ca Corp Issuing CA unchanged success",
		"trust_cert fw-wildcard updated success",
		"trust_reload webgui scheduled success TRUST_RELOAD_SCHEDULED",
		"trust_reload Road warriors openvpn configure success",
		"trust_reload Site B openvpn configure success",
		"trust_reload HQ ipsec reload success",
		"trust_reload SIEM syslog restart success",
		"trust_reload opnsense.nginx.http_server dddddddd-0000-4000-8000-000000000001 none warning TRUST_CONSUMER_UNKNOWN",
	)
	if !out.Result.Success || !out.RestartWebGUI {
		t.Fatalf("Success = %v, RestartWebGUI = %v", out.Result.Success, out.RestartWebGUI)
	}
	if got := f.find(opnapi.TrustCert, uuidWildcard).refid; got != ref {
		t.Errorf("the renewal changed the refid from %q to %q", ref, got)
	}
	want := []string{"openvpn configure", "ipsec reload", "syslog stop", "syslog start"}
	if !reflect.DeepEqual(*calls, want) {
		t.Errorf("configctl calls = %q, want %q", *calls, want)
	}
	unknown := out.Result.Results[len(out.Result.Results)-1]
	if unknown.UUID != "dddddddd-0000-4000-8000-000000000001" || !strings.Contains(unknown.Error, "bound, no known reload: restart to apply") {
		t.Errorf("unknown consumer item = %+v", unknown)
	}
}

// A CA renewed in place (same subject, same key) reaches what uses the
// certificates it issued. The CA API rebuilds the system trust store itself, so
// the agent reloads nothing for it.
func TestExecuteSyncTrust_CARenewalReachesItsCertificates(t *testing.T) {
	p := newTrustPKI(t)
	f := newFakeTrust(t)
	calls := recordConfigctl(t)
	renewed := newTestCA(t, "Corp Issuing CA", p.root, p.inter.key)
	f.add(opnapi.TrustCA, uuidRootCA, "Corp Root CA", p.root.certPEM, "", "")
	rootRef := f.find(opnapi.TrustCA, uuidRootCA).refid
	inter := f.add(opnapi.TrustCA, uuidInterCA, "Corp Issuing CA", p.inter.certPEM, "", rootRef)
	cert := f.add(opnapi.TrustCert, uuidWildcard, "fw-wildcard", p.wildcard.certPEM, p.wildcard.keyPEM, inter.refid)
	cfg := writeConfigXML(t, `
<ca><refid>`+rootRef+`</refid></ca>
<ca><refid>`+inter.refid+`</refid><caref>`+rootRef+`</caref></ca>
<cert><refid>`+cert.refid+`</refid><caref>`+inter.refid+`</caref></cert>
<OPNsense><captiveportal><zones><zone uuid="eeeeeeee-0000-4000-8000-000000000001"><description>Guests</description><certificate>`+cert.refid+`</certificate></zone></zones></captiveportal></OPNsense>`)

	out := runTrust(t, f, trustPayload(
		caSnippet(uuidRootCA, "Corp Root CA", p.root),
		caSnippet(uuidInterCA, "Corp Issuing CA", renewed),
		certSnippet(uuidWildcard, "fw-wildcard", p.wildcard),
	), false, cfg)
	assertItems(t, out.Result,
		"trust_ca Corp Root CA unchanged success",
		"trust_ca Corp Issuing CA updated success",
		"trust_cert fw-wildcard unchanged success",
		"trust_reload Guests captiveportal restart success",
	)
	want := []string{"template reload OPNsense/Captiveportal", "captiveportal restart"}
	if !reflect.DeepEqual(*calls, want) {
		t.Errorf("configctl calls = %q, want %q", *calls, want)
	}
}

// A CA whose subject or key changed is not written over: the certificates it
// issued would no longer chain to it.
func TestExecuteSyncTrust_RefusesARekeyedCA(t *testing.T) {
	p := newTrustPKI(t)
	f := newFakeTrust(t)
	recordConfigctl(t)
	f.add(opnapi.TrustCA, uuidRootCA, "Corp Root CA", p.root.certPEM, "", "")
	rekeyed := newTestCA(t, "Corp Root CA", nil, nil)
	renamed := newTestCA(t, "Corp Root CA 2", nil, p.root.key)

	for name, ca := range map[string]*testCA{"a new key": rekeyed, "a new subject": renamed} {
		t.Run(name, func(t *testing.T) {
			out := runTrust(t, f, trustPayload(caSnippet(uuidRootCA, "Corp Root CA", ca)), false, writeConfigXML(t, ""))
			assertItems(t, out.Result, "trust_ca Corp Root CA blocked blocked TRUST_CA_REKEYED")
			if out.Result.Success || len(f.writeLog()) != 0 {
				t.Fatalf("Success = %v, writes = %q", out.Result.Success, f.writeLog())
			}
		})
	}
}

// An object NetDefense does not own is never adopted or written over, even
// when its name differs only in case.
func TestExecuteSyncTrust_NameCollisionWithAHandMadeObject(t *testing.T) {
	p := newTrustPKI(t)
	f := newFakeTrust(t)
	recordConfigctl(t)
	f.add(opnapi.TrustCert, uuidHandMade, "FW-Wildcard ", p.wildcard.certPEM, p.wildcard.keyPEM, "")

	out := runTrust(t, f, trustPayload(certSnippet(uuidWildcard, "fw-wildcard", p.wildcard)), false, writeConfigXML(t, ""))
	assertItems(t, out.Result, "trust_cert fw-wildcard blocked blocked NAME_COLLISION_UNMANAGED")
	if out.Result.Success || len(f.writeLog()) != 0 {
		t.Fatalf("Success = %v, writes = %q", out.Result.Success, f.writeLog())
	}
}

// With reject_dangerous_snippets on, the device refuses every add and update;
// what already matches stays unchanged and removals still happen.
func TestExecuteSyncTrust_RejectDangerousRefusesWritesNotRemovals(t *testing.T) {
	p := newTrustPKI(t)
	f := newFakeTrust(t)
	recordConfigctl(t)
	f.add(opnapi.TrustCA, uuidRootCA, "Corp Root CA", p.root.certPEM, "", "")
	f.add(opnapi.TrustCert, uuidOrphanCert, "old", p.host.certPEM, p.host.keyPEM, "")

	out := runTrust(t, f, trustPayload(
		caSnippet(uuidRootCA, "Corp Root CA", p.root),
		caSnippet(uuidInterCA, "Corp Issuing CA", p.inter),
		certSnippet(uuidWildcard, "fw-wildcard", p.wildcard),
	), true, writeConfigXML(t, ""))
	assertItems(t, out.Result,
		"trust_ca Corp Root CA unchanged success",
		"trust_ca Corp Issuing CA rejected blocked TRUST_REJECTED_DANGEROUS",
		"trust_cert fw-wildcard rejected blocked TRUST_REJECTED_DANGEROUS",
		"trust_cert old deleted success",
	)
	if out.Result.Success {
		t.Fatal("a refused write did not fail the task")
	}
	if got := f.writeLog(); !reflect.DeepEqual(got, []string{"del cert " + uuidOrphanCert}) {
		t.Fatalf("writes = %q", got)
	}
	msg := out.Result.Results[2].Error
	if !strings.Contains(msg, "reject_dangerous_snippets") || !strings.Contains(msg, `trust_cert "fw-wildcard"`) {
		t.Errorf("refusal = %q", msg)
	}
}

// Removal: certificates go before CAs, so a CA whose only certificate leaves
// in the same pass goes too; anything still used stays and fails the task.
func TestExecuteSyncTrust_RemovesWhatNothingUses(t *testing.T) {
	p := newTrustPKI(t)
	f := newFakeTrust(t)
	recordConfigctl(t)
	orphanCA := f.add(opnapi.TrustCA, uuidOrphanCA, "Old CA", p.inter.certPEM, "", "")
	f.add(opnapi.TrustCert, uuidOrphanCert, "old-cert", p.wildcard.certPEM, p.wildcard.keyPEM, orphanCA.refid)
	f.add(opnapi.TrustCert, uuidHandMade, "hand-made", p.host.certPEM, p.host.keyPEM, "")

	out := runTrust(t, f, trustPayload(), false, f.configXML(t, ""))
	assertItems(t, out.Result,
		"trust_cert old-cert deleted success",
		"trust_ca Old CA deleted success",
	)
	want := []string{"del cert " + uuidOrphanCert, "del ca " + uuidOrphanCA}
	if got := f.writeLog(); !reflect.DeepEqual(got, want) {
		t.Fatalf("writes = %q, want %q", got, want)
	}
	if f.find(opnapi.TrustCert, uuidHandMade) == nil {
		t.Fatal("a hand-made certificate was removed")
	}
}

func TestExecuteSyncTrust_KeepsWhatIsInUse(t *testing.T) {
	p := newTrustPKI(t)
	f := newFakeTrust(t)
	recordConfigctl(t)
	usedCA := f.add(opnapi.TrustCA, uuidOrphanCA, "Old CA", p.inter.certPEM, "", "")
	issued := f.add(opnapi.TrustCert, uuidHandMade, "hand-made", p.wildcard.certPEM, p.wildcard.keyPEM, usedCA.refid)
	flagged := f.add(opnapi.TrustCert, uuidOrphanCert, "flagged", p.host.certPEM, p.host.keyPEM, "")
	flagged.inUse = true
	bound := f.add(opnapi.TrustCert, "221f3268-2222-4222-9222-0000000000fe", "gui-cert", p.host.certPEM, p.host.keyPEM, "")
	cfg := f.configXML(t, `<system><webgui><ssl-certref>`+bound.refid+`</ssl-certref></webgui></system>`)
	_ = issued

	out := runTrust(t, f, trustPayload(), false, cfg)
	assertItems(t, out.Result,
		"trust_cert flagged retained blocked TRUST_IN_USE",
		"trust_cert gui-cert retained blocked TRUST_IN_USE",
		"trust_ca Old CA retained blocked TRUST_IN_USE",
	)
	if out.Result.Success || len(f.writeLog()) != 0 {
		t.Fatalf("Success = %v, writes = %q", out.Result.Success, f.writeLog())
	}
	for _, check := range []struct {
		item  int
		names string
	}{{1, "webgui"}, {2, `certificate "hand-made"`}} {
		if msg := out.Result.Results[check.item].Error; !strings.Contains(msg, check.names) {
			t.Errorf("item %d does not name %s: %q", check.item, check.names, msg)
		}
	}
}

// Content the agent cannot read makes the whole family a no-op: nothing is
// written and nothing is removed, orphans included.
func TestExecuteSyncTrust_UnreadableContentIsANoOp(t *testing.T) {
	p := newTrustPKI(t)
	f := newFakeTrust(t)
	recordConfigctl(t)
	f.add(opnapi.TrustCert, uuidOrphanCert, "old", p.host.certPEM, p.host.keyPEM, "")
	parsed := parseAPITrustContent(trustPayload(
		caSnippet(uuidRootCA, "Corp Root CA", p.root),
		trustSnippet("TRUST_CERT", "fw-wildcard", map[string]string{"uuid": uuidWildcard, "name": "fw-wildcard", "crt": p.wildcard.certPEM, "key": p.wildcard.keyPEM, "future": "x"}),
	))
	out := executeSyncTrust(context.Background(), f.client, parsed, false, writeConfigXML(t, ""))
	assertItems(t, out.Result, "trust_cert fw-wildcard unsupported blocked TRUST_CONTENT_UNSUPPORTED")
	if msg := out.Result.Errors[0]; !strings.Contains(msg, `trust_cert snippet "fw-wildcard" (index 1)`) || !strings.Contains(msg, "no CA or certificate was changed") {
		t.Errorf("message = %q", msg)
	}
	if out.Result.Success || len(f.writeLog()) != 0 {
		t.Fatalf("Success = %v, writes = %q", out.Result.Success, f.writeLog())
	}
}

// The firewall's refusal is reported by status and field names, never by what
// it wrote; the rest of the family still applies.
func TestExecuteSyncTrust_ImportFailures(t *testing.T) {
	p := newTrustPKI(t)
	f := newFakeTrust(t)
	recordConfigctl(t)
	f.failSet[uuidWildcard] = fakeFailure{status: 200, body: `{"result":"failed","validations":{"cert.prv_payload":"` + jsonEscape(p.wildcard.keyPEM) + `","<b>":"x"}}`}
	f.failSet[uuidHostCert] = fakeFailure{status: 500, body: `{"errorMessage":"` + jsonEscape(p.host.keyPEM) + `","errorTitle":"Certificate error"}`}

	out := runTrust(t, f, p.payload(), false, writeConfigXML(t, ""))
	assertItems(t, out.Result,
		"trust_ca Corp Root CA created success",
		"trust_ca Corp Issuing CA created success",
		"trust_cert fw-wildcard create error TRUST_IMPORT_FAILED",
		"trust_cert fw1 create error TRUST_IMPORT_FAILED",
	)
	if msg := out.Result.Results[2].Error; !strings.Contains(msg, "fields cert.prv_payload") || strings.Contains(msg, "<b>") {
		t.Errorf("validation refusal = %q", msg)
	}
	if msg := out.Result.Results[3].Error; !strings.Contains(msg, "status 500") {
		t.Errorf("HTTP refusal = %q", msg)
	}
	assertNoMaterial(t, "the results", mustJSON(out.Result), p.wildcard, p.host)
}

func jsonEscape(s string) string {
	raw, _ := json.Marshal(s)
	return strings.Trim(string(raw), `"`)
}

// A write the firewall answered but stored differently (a reissue from the key
// it held, say) is a failure, found by reading it back.
func TestExecuteSyncTrust_ReadBackCatchesAWrongStore(t *testing.T) {
	p := newTrustPKI(t)
	f := newFakeTrust(t)
	recordConfigctl(t)
	reissued := p.root.issue(t, "fw1.example.net", false)
	f.storeOther[uuidHostCert] = reissued.certPEM

	out := runTrust(t, f, trustPayload(caSnippet(uuidRootCA, "Corp Root CA", p.root), certSnippet(uuidHostCert, "fw1", p.host)), false, writeConfigXML(t, ""))
	assertItems(t, out.Result,
		"trust_ca Corp Root CA created success",
		"trust_cert fw1 create error TRUST_IMPORT_FAILED",
	)
	if msg := out.Result.Results[1].Error; !strings.Contains(msg, "stored a different certificate") {
		t.Errorf("message = %q", msg)
	}
}

// An issuer OPNsense picked itself is accepted when that CA did sign the
// certificate, so the family does not fight the firewall's own choice.
func TestExecuteSyncTrust_AcceptsAnotherIssuerThatSigned(t *testing.T) {
	p := newTrustPKI(t)
	f := newFakeTrust(t)
	recordConfigctl(t)
	f.add(opnapi.TrustCA, uuidHandMade, "Root (hand-made copy)", p.root.certPEM, "", "")
	f.add(opnapi.TrustCA, uuidRootCA, "Corp Root CA", p.root.certPEM, "", "")
	handMade := f.find(opnapi.TrustCA, uuidHandMade)
	f.add(opnapi.TrustCert, uuidHostCert, "fw1", p.host.certPEM, p.host.keyPEM, handMade.refid)

	out := runTrust(t, f, trustPayload(caSnippet(uuidRootCA, "Corp Root CA", p.root), certSnippet(uuidHostCert, "fw1", p.host)), false, writeConfigXML(t, ""))
	assertItems(t, out.Result,
		"trust_ca Corp Root CA unchanged success",
		"trust_cert fw1 unchanged success",
	)
}

func TestExecuteSyncTrust_DiscoveryFailureWritesNothing(t *testing.T) {
	p := newTrustPKI(t)
	f := newFakeTrust(t)
	recordConfigctl(t)
	f.failSearch[opnapi.TrustCert] = fakeFailure{status: 500, body: p.wildcard.keyPEM}

	out := runTrust(t, f, p.payload(), false, writeConfigXML(t, ""))
	assertItems(t, out.Result, "trust_cert discover error")
	if out.Result.Success || len(f.writeLog()) != 0 {
		t.Fatalf("Success = %v, writes = %q", out.Result.Success, f.writeLog())
	}
	assertNoMaterial(t, "the results", mustJSON(out.Result), p.wildcard)
}

// A reload that fails is a warning naming the service, not a failure: the
// certificate was written.
func TestExecuteSyncTrust_ReloadFailureIsAWarning(t *testing.T) {
	p := newTrustPKI(t)
	f := newFakeTrust(t)
	recordConfigctl(t, "syslog start")
	old := p.root.issue(t, "fw1.example.net", true)
	f.add(opnapi.TrustCA, uuidRootCA, "Corp Root CA", p.root.certPEM, "", "")
	cert := f.add(opnapi.TrustCert, uuidHostCert, "fw1", old.certPEM, old.keyPEM, f.find(opnapi.TrustCA, uuidRootCA).refid)
	cfg := writeConfigXML(t, `<OPNsense><Syslog><destinations><destination uuid="cccccccc-0000-4000-8000-000000000001"><description>SIEM</description><certificate>`+cert.refid+`</certificate></destination></destinations></Syslog></OPNsense>`)

	out := runTrust(t, f, trustPayload(caSnippet(uuidRootCA, "Corp Root CA", p.root), certSnippet(uuidHostCert, "fw1", p.host)), false, cfg)
	assertItems(t, out.Result,
		"trust_ca Corp Root CA unchanged success",
		"trust_cert fw1 updated success",
		"trust_reload SIEM syslog restart warning TRUST_RELOAD_FAILED",
	)
	if !out.Result.Success {
		t.Fatalf("a failed reload failed the task: %v", out.Result.Errors)
	}
	if msg := out.Result.Results[2].Error; !strings.Contains(msg, "SIEM") || !strings.Contains(msg, "system logging may have been left stopped") {
		t.Errorf("warning = %q", msg)
	}
}

// Without config.xml the agent cannot tell what uses an object: an orphan is
// kept, and a renewal says to restart what uses it.
func TestExecuteSyncTrust_UnreadableConfiguration(t *testing.T) {
	p := newTrustPKI(t)
	f := newFakeTrust(t)
	recordConfigctl(t)
	old := p.root.issue(t, "fw1.example.net", true)
	f.add(opnapi.TrustCA, uuidRootCA, "Corp Root CA", p.root.certPEM, "", "")
	f.add(opnapi.TrustCert, uuidHostCert, "fw1", old.certPEM, old.keyPEM, f.find(opnapi.TrustCA, uuidRootCA).refid)
	f.add(opnapi.TrustCert, uuidOrphanCert, "old", p.wildcard.certPEM, p.wildcard.keyPEM, "")

	out := runTrust(t, f, trustPayload(caSnippet(uuidRootCA, "Corp Root CA", p.root), certSnippet(uuidHostCert, "fw1", p.host)), false, "/nonexistent/config.xml")
	assertItems(t, out.Result,
		"trust_ca Corp Root CA unchanged success",
		"trust_cert fw1 updated success",
		"trust_cert old delete error",
		"trust_reload fw1 reload warning TRUST_RELOAD_FAILED",
	)
	if got := f.writeLog(); !reflect.DeepEqual(got, []string{"set cert " + uuidHostCert}) {
		t.Fatalf("writes = %q", got)
	}
}

// A device that does not use the family is not asked anything: no trust
// content, no managed object in config.xml and no reload waiting. One whose
// config.xml holds a managed object is read, and with nothing of its own left
// on the device reports nothing.
func TestExecuteSyncTrust_NothingToDo(t *testing.T) {
	p := newTrustPKI(t)
	f := newFakeTrust(t)
	recordConfigctl(t)
	f.add(opnapi.TrustCert, uuidHandMade, "hand-made", p.host.certPEM, p.host.keyPEM, "")
	out := runTrust(t, f, trustPayload(), false, f.configXML(t, ""))
	if len(out.Result.Results) != 0 || !out.Result.Success || f.requestCount() != 0 {
		t.Fatalf("result = %+v, %d requests", out.Result, f.requestCount())
	}

	cfg := writeConfigXML(t, `<cert uuid="`+uuidOrphanCert+`"><refid>66f0aaaaaaaaa</refid></cert>`)
	out = runTrust(t, f, trustPayload(), false, cfg)
	if len(out.Result.Results) != 0 || !out.Result.Success || f.requestCount() != 2 || len(f.writeLog()) != 0 {
		t.Fatalf("result = %+v, %d requests, writes %q", out.Result, f.requestCount(), f.writeLog())
	}
}

// Decommission runs the family with nothing desired: everything NetDefense
// put there goes, what a service uses stays, and that is not a failure.
func TestTrustDecommission_KeepsWhatIsInUse(t *testing.T) {
	p := newTrustPKI(t)
	f := newFakeTrust(t)
	recordConfigctl(t)
	f.add(opnapi.TrustCA, uuidRootCA, "Corp Root CA", p.root.certPEM, "", "")
	f.add(opnapi.TrustCert, uuidOrphanCert, "unused", p.wildcard.certPEM, p.wildcard.keyPEM, "")
	used := f.add(opnapi.TrustCert, uuidHostCert, "gui", p.host.certPEM, p.host.keyPEM, f.find(opnapi.TrustCA, uuidRootCA).refid)
	cfg := f.configXML(t, `<system><webgui><ssl-certref>`+used.refid+`</ssl-certref></webgui></system>`)

	out := executeSyncTrust(context.Background(), f.client, trustParseOutcome{}, false, cfg)
	assertItems(t, out.Result,
		"trust_cert unused deleted success",
		"trust_cert gui retained blocked TRUST_IN_USE",
		"trust_ca Corp Root CA retained blocked TRUST_IN_USE",
	)
	if err := trustDecommissionError(out.Result); err != nil {
		t.Fatalf("in-use survivors failed the decommission: %v", err)
	}

	f.failDel[uuidRootCA] = fakeFailure{status: 500}
	f.certs = nil
	out = executeSyncTrust(context.Background(), f.client, trustParseOutcome{}, false, f.configXML(t, ""))
	if err := trustDecommissionError(out.Result); err == nil {
		t.Fatal("a refused delete did not fail the decommission")
	}
}

func TestNewDecommissioner_TrustRunsFirst(t *testing.T) {
	d := NewDecommissioner(opnapi.NewClient("https://127.0.0.1/api", "k", "s", true), "os-netdefense", "dev", "/conf/config.xml", func() {})
	if names := familyNames(d.Families); len(names) == 0 || names[0] != "trust" {
		t.Fatalf("families = %v, want trust first", names)
	}
}

// TRUST types are never pullable.
func TestPullConfig_TrustIsUnsupported(t *testing.T) {
	for _, configType := range []string{"TRUST_CA", "TRUST_CERT", "trust_ca", "trust_cert"} {
		if _, _, err := pullConfig(context.Background(), nil, configType, "x"); err != errUnsupportedConfigType {
			t.Errorf("pullConfig(%s) = %v, want unsupported", configType, err)
		}
	}
}

func TestBuildSyncSummary_TrustSectionsComeFirst(t *testing.T) {
	got := buildSyncSummary([]SyncAPIItemResult{
		{Type: "alias", Action: "created", Status: "success"},
		{Type: trustTypeCert, Action: "updated", Status: "success"},
		{Type: trustTypeCA, Action: "created", Status: "success"},
		{Type: trustTypeReload, Action: "scheduled", Status: "success"},
	}, 0)
	if want := "Trust CAs +1; Trust certificates ~1; Aliases +1"; got != want {
		t.Fatalf("summary = %q, want %q", got, want)
	}
}

// The name is checked when the object would take it. A renewal of an object
// NetDefense already owns goes ahead even if a hand-made one shares its name;
// a rename onto a hand-made one's name does not.
func TestExecuteSyncTrust_NameIsCheckedOnCreateAndRename(t *testing.T) {
	p := newTrustPKI(t)
	f := newFakeTrust(t)
	recordConfigctl(t)
	old := p.root.issue(t, "fw1.example.net", true)
	f.add(opnapi.TrustCA, uuidRootCA, "Corp Root CA", p.root.certPEM, "", "")
	f.add(opnapi.TrustCert, uuidHostCert, "fw1", old.certPEM, old.keyPEM, f.find(opnapi.TrustCA, uuidRootCA).refid)
	f.add(opnapi.TrustCert, uuidHandMade, "fw1", p.wildcard.certPEM, p.wildcard.keyPEM, "")
	f.add(opnapi.TrustCert, "6f1c2a7e-4c3b-4f60-9d4e-0a8b1c2d3e50", "taken", p.wildcard.certPEM, p.wildcard.keyPEM, "")
	cfg := writeConfigXML(t, "")

	out := runTrust(t, f, trustPayload(caSnippet(uuidRootCA, "Corp Root CA", p.root), certSnippet(uuidHostCert, "fw1", p.host)), false, cfg)
	assertItems(t, out.Result, "trust_ca Corp Root CA unchanged success", "trust_cert fw1 updated success")

	out = runTrust(t, f, trustPayload(caSnippet(uuidRootCA, "Corp Root CA", p.root), certSnippet(uuidHostCert, "taken", p.host)), false, cfg)
	assertItems(t, out.Result, "trust_ca Corp Root CA unchanged success", "trust_cert taken blocked blocked NAME_COLLISION_UNMANAGED")
}

// A consumer reached by a renewed CA and by a renewed certificate it issued is
// reloaded and reported once.
func TestExecuteSyncTrust_ConsumerReloadedOnce(t *testing.T) {
	p := newTrustPKI(t)
	f := newFakeTrust(t)
	calls := recordConfigctl(t)
	renewedRoot := newTestCA(t, "Corp Root CA", nil, p.root.key)
	old := p.root.issue(t, "fw1.example.net", true)
	root := f.add(opnapi.TrustCA, uuidRootCA, "Corp Root CA", p.root.certPEM, "", "")
	cert := f.add(opnapi.TrustCert, uuidHostCert, "fw1", old.certPEM, old.keyPEM, root.refid)
	cfg := writeConfigXML(t, `<cert><refid>`+cert.refid+`</refid><caref>`+root.refid+`</caref></cert>
<OPNsense><OpenVPN><Instances><Instance uuid="u-1"><description>VPN</description><cert>`+cert.refid+`</cert><ca>`+root.refid+`</ca></Instance></Instances></OpenVPN></OPNsense>`)

	out := runTrust(t, f, trustPayload(caSnippet(uuidRootCA, "Corp Root CA", renewedRoot), certSnippet(uuidHostCert, "fw1", p.host)), false, cfg)
	assertItems(t, out.Result,
		"trust_ca Corp Root CA updated success",
		"trust_cert fw1 updated success",
		"trust_reload VPN openvpn configure success",
	)
	if !reflect.DeepEqual(*calls, []string{"openvpn configure"}) {
		t.Errorf("configctl calls = %q", *calls)
	}
}

// The outer DER shape tells a certificate from a key whatever the label says,
// as the control plane tells them apart.
func TestDERShapes(t *testing.T) {
	p := newTrustPKI(t)
	der := func(text string) []byte {
		block, _ := pem.Decode([]byte(text))
		return block.Bytes
	}
	pkixKey, err := x509.MarshalPKIXPublicKey(p.wildcard.cert.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	// An encrypted PKCS#8 key is a SEQUENCE of the algorithm SEQUENCE and the
	// encrypted OCTET STRING.
	encrypted := []byte{0x30, 0x0a, 0x30, 0x03, 0x06, 0x01, 0x00, 0x04, 0x03, 0x01, 0x02, 0x03}

	for name, tc := range map[string]struct {
		der       []byte
		cert, key bool
	}{
		"a certificate":    {der(p.wildcard.certPEM), true, false},
		"a CA certificate": {der(p.root.certPEM), true, false},
		"a PKCS#8 key":     {der(p.wildcard.keyPEM), false, true},
		"a PKCS#1 key":     {der(p.host.keyPEM), false, true},
		"a public key":     {pkixKey, false, false},
		"an encrypted key": {encrypted, false, false},
		"two SEQUENCEs":    {append(der(p.wildcard.keyPEM), der(p.wildcard.keyPEM)...), false, false},
		"a truncated body": {der(p.wildcard.certPEM)[:100], false, false},
		"nothing":          {nil, false, false},
	} {
		if got := derIsCertificate(tc.der); got != tc.cert {
			t.Errorf("%s: derIsCertificate = %v, want %v", name, got, tc.cert)
		}
		if got := derIsUnencryptedPrivateKey(tc.der); got != tc.key {
			t.Errorf("%s: derIsUnencryptedPrivateKey = %v, want %v", name, got, tc.key)
		}
	}
}

// A failed IPsec reload says what reloading would do: the renewed certificate is
// presented by a new IKE SA, not at a rekey, and established SAs keep running.
func TestExecuteSyncTrust_IPsecReloadFailureSaysWhatHappensToTheTunnels(t *testing.T) {
	p := newTrustPKI(t)
	f := newFakeTrust(t)
	recordConfigctl(t, "ipsec reload")
	old := p.root.issue(t, "fw1.example.net", true)
	root := f.add(opnapi.TrustCA, uuidRootCA, "Corp Root CA", p.root.certPEM, "", "")
	cert := f.add(opnapi.TrustCert, uuidHostCert, "fw1", old.certPEM, old.keyPEM, root.refid)
	cfg := writeConfigXML(t, `<OPNsense><Swanctl><locals><local uuid="bbbbbbbb-0000-4000-8000-000000000001"><description>HQ</description><certs>`+cert.refid+`</certs></local></locals></Swanctl></OPNsense>`)

	out := runTrust(t, f, trustPayload(caSnippet(uuidRootCA, "Corp Root CA", p.root), certSnippet(uuidHostCert, "fw1", p.host)), false, cfg)
	assertItems(t, out.Result,
		"trust_ca Corp Root CA unchanged success",
		"trust_cert fw1 updated success",
		"trust_reload HQ ipsec reload warning TRUST_RELOAD_FAILED",
	)
	if msg := out.Result.Results[2].Error; !strings.Contains(msg, "reload IPsec") || !strings.Contains(msg, "when a new IKE SA is established, not at a rekey") {
		t.Errorf("warning = %q", msg)
	}
}
