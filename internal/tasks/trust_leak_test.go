package tasks

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// materialFragments are pieces of a certificate's and its key's text, as PEM
// and as the base64 of the PEM that config.xml and every trust read hold. Any
// of them in an output means material got there.
func materialFragments(leaves ...testLeaf) []string {
	fragments := []string{"-----BEGIN", "-----END", "PRIVATE KEY"}
	for _, leaf := range leaves {
		for _, text := range []string{leaf.certPEM, leaf.keyPEM} {
			for _, line := range strings.Split(text, "\n") {
				if len(line) >= 24 && !strings.HasPrefix(line, "-----") {
					fragments = append(fragments, line[:24])
				}
			}
			encoded := base64.StdEncoding.EncodeToString([]byte(text))
			for i := 0; i+24 <= len(encoded); i += 64 {
				fragments = append(fragments, encoded[i:i+24])
			}
		}
		if fp := opnapi.PrivateKeyFingerprint([]byte(leaf.keyPEM)); fp != "" {
			fragments = append(fragments, fp)
		}
	}
	return fragments
}

// assertNoMaterial fails when text holds a fragment of the leaves' material.
func assertNoMaterial(t *testing.T, where, text string, leaves ...testLeaf) {
	t.Helper()
	for _, fragment := range materialFragments(leaves...) {
		if strings.Contains(text, fragment) {
			t.Errorf("%s holds certificate or key text (%q): %.400s", where, fragment, text)
			return
		}
	}
}

// captureLogs sends everything logged, at every level, to an observer.
func captureLogs(t *testing.T) *observer.ObservedLogs {
	t.Helper()
	core, logs := observer.New(zapcore.DebugLevel)
	restore := logging.SetForTest(zap.New(core))
	t.Cleanup(restore)
	return logs
}

func renderLogs(logs *observer.ObservedLogs) string {
	var b strings.Builder
	for _, e := range logs.All() {
		b.WriteString(e.Message)
		fields, _ := json.Marshal(e.ContextMap())
		b.Write(fields)
		b.WriteString("\n")
	}
	return b.String()
}

// No certificate or key text reaches a result item, a task error, the task
// summary or a log line, on any path the family takes: create, renewal and
// reloads, refusals by the firewall that quote the key back, unreadable
// stores, removals kept in use, and content the agent refuses. The fake device
// answers every read with the private keys in it, as OPNsense does.
func TestTrustFamily_NoMaterialReachesResultsOrLogs(t *testing.T) {
	logs := captureLogs(t)
	p := newTrustPKI(t)
	old := p.inter.issue(t, "*.example.net", false)
	recordConfigctl(t, "ipsec reload")
	leaves := []testLeaf{p.wildcard, p.host, old,
		{certPEM: p.root.certPEM}, {certPEM: p.inter.certPEM}}

	var outputs []string
	collect := func(out trustFamilyOutcome) {
		raw, _ := json.Marshal(out.Result)
		outputs = append(outputs, string(raw), strings.Join(out.Result.Errors, "\n"),
			buildSyncSummary(out.Result.Results, len(out.Result.Errors)))
	}

	// Create, with the firewall refusing one certificate by quoting its key.
	f := newFakeTrust(t)
	f.failSet[uuidHostCert] = fakeFailure{status: 200, body: `{"result":"failed","validations":{"cert.prv_payload":"` + jsonEscape(p.host.keyPEM) + `"}}`}
	collect(runTrust(t, f, p.payload(), false, writeConfigXML(t, "")))

	// A renewal with consumers, one reload failing; an orphan in use; one
	// delete refused with the key in the answer.
	f = newFakeTrust(t)
	f.add(opnapi.TrustCA, uuidInterCA, "Corp Issuing CA", p.inter.certPEM, "", "")
	cert := f.add(opnapi.TrustCert, uuidWildcard, "fw-wildcard", old.certPEM, old.keyPEM, f.find(opnapi.TrustCA, uuidInterCA).refid)
	kept := f.add(opnapi.TrustCert, uuidOrphanCert, "kept", p.host.certPEM, p.host.keyPEM, "")
	refused := f.add(opnapi.TrustCert, "221f3268-2222-4222-9222-0000000000fd", "refused", p.host.certPEM, p.host.keyPEM, "")
	f.failDel[refused.uuid] = fakeFailure{status: 500, body: p.host.keyPEM}
	cfg := writeConfigXML(t, `<system><webgui><ssl-certref>`+cert.refid+`</ssl-certref></webgui></system>
<OPNsense><Swanctl><locals><local uuid="bbbbbbbb-0000-4000-8000-000000000001"><description>HQ</description><certs>`+cert.refid+`</certs></local></locals></Swanctl>
<Nginx><server uuid="dddddddd-0000-4000-8000-000000000001"><certificate>`+cert.refid+`</certificate></server></Nginx></OPNsense>
<OPNsense><captiveportal><zones><zone uuid="eeeeeeee-0000-4000-8000-000000000001"><certificate>`+kept.refid+`</certificate></zone></zones></captiveportal></OPNsense>`)
	collect(runTrust(t, f, trustPayload(caSnippet(uuidInterCA, "Corp Issuing CA", p.inter), certSnippet(uuidWildcard, "fw-wildcard", p.wildcard)), false, cfg))

	// A store that answers 500 with key text, and a write answered with an
	// error page that quotes it.
	f = newFakeTrust(t)
	f.failSearch[opnapi.TrustCA] = fakeFailure{status: 500, body: p.host.keyPEM}
	collect(runTrust(t, f, p.payload(), false, writeConfigXML(t, "")))
	f = newFakeTrust(t)
	f.failSet[uuidRootCA] = fakeFailure{status: 200, body: "<html>" + p.root.certPEM + p.host.keyPEM}
	collect(runTrust(t, f, p.payload(), false, writeConfigXML(t, "")))

	// A read-back that fails with the key in the answer, a CA refused for its
	// subject name, and a device too old to write to.
	f = newFakeTrust(t)
	f.add(opnapi.TrustCA, uuidLookalikeCA, "lookalike", newTestCA(t, "Corp Issuing CA", nil, nil).certPEM, "", "")
	f.failGet[uuidRootCA] = fakeFailure{status: 500, body: p.host.keyPEM}
	collect(runTrust(t, f, p.payload(), false, writeConfigXML(t, "")))
	f = newFakeTrust(t)
	useTrustRelease(t, "25.7.3")
	collect(runTrust(t, f, p.payload(), false, writeConfigXML(t, "")))

	// A certificate OPNsense links to a CA that did not issue it.
	acmeRoot, acmeInter, acmeLeaf := overlappingPKI(t)
	leaves = append(leaves, acmeLeaf, testLeaf{certPEM: acmeRoot.certPEM}, testLeaf{certPEM: acmeInter.certPEM})
	f = newFakeTrust(t)
	f.add(opnapi.TrustCA, uuidRootCA, "Acme Root", acmeRoot.certPEM, "", "")
	collect(runTrust(t, f, trustPayload(caSnippet(uuidRootCA, "Acme Root", acmeRoot), certSnippet(uuidHostCert, "fw1", acmeLeaf)), false, writeConfigXML(t, "")))

	// Content the agent refuses, with a key where the certificate belongs.
	f = newFakeTrust(t)
	parsed := parseAPITrustContent(trustPayload(trustSnippet("TRUST_CERT", "fw-wildcard", map[string]string{
		"uuid": uuidWildcard, "name": "fw-wildcard", "crt": p.wildcard.keyPEM, "key": p.wildcard.certPEM,
	})))
	collect(executeSyncTrust(context.Background(), f.client, parsed, false, writeConfigXML(t, "")))

	for i, out := range outputs {
		assertNoMaterial(t, "output "+string(rune('A'+i)), out, leaves...)
	}
	assertNoMaterial(t, "the logs", renderLogs(logs), leaves...)
	if logs.Len() == 0 {
		t.Fatal("nothing was logged, so the log check proves nothing")
	}
}

// The opnapi trust client never returns or wraps what the device answered.
func TestTrustClient_ErrorsCarryNoBody(t *testing.T) {
	p := newTrustPKI(t)
	f := newFakeTrust(t)
	f.failSearch[opnapi.TrustCert] = fakeFailure{status: 403, body: p.wildcard.keyPEM}
	f.failSet[uuidWildcard] = fakeFailure{status: 200, body: `{"result":"` + jsonEscape(p.wildcard.keyPEM) + `"}`}
	f.failDel[uuidWildcard] = fakeFailure{status: 200, body: `{"result":"` + jsonEscape(p.wildcard.keyPEM) + `"}`}
	f.add(opnapi.TrustCert, uuidWildcard, "x", p.wildcard.certPEM, p.wildcard.keyPEM, "")

	_, searchErr := f.client.ListTrust(context.Background(), opnapi.TrustCert)
	setErr := f.client.SetTrustCert(context.Background(), uuidWildcard, opnapi.TrustCertWrite{Descr: "x", CrtPEM: p.wildcard.certPEM, KeyPEM: p.wildcard.keyPEM})
	delErr := f.client.DeleteTrust(context.Background(), opnapi.TrustCert, uuidWildcard)
	for name, err := range map[string]error{"search": searchErr, "set": setErr, "delete": delErr} {
		if err == nil {
			t.Fatalf("%s: no error", name)
		}
		assertNoMaterial(t, name+" error", err.Error(), p.wildcard)
	}
}
