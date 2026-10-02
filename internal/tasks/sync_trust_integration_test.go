//go:build integration
// +build integration

package tasks

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// Integration test of the trust family against a real OPNsense:
//
//	go test -tags=integration -run TestIntegration_Trust ./internal/tasks/
//
// Required environment variables (same as ./internal/opnapi/):
//
//	OPNSENSE_API_KEY, OPNSENSE_API_SECRET, OPNSENSE_API_URL
//
// It creates CAs and certificates under managed uuids of its own, renews,
// refuses and removes them, and deletes everything it created when it ends.
// configctl is recorded, not run, and the consumer scan reads a config.xml the
// test writes, so nothing on the device is reloaded. It refuses to run on a
// device that already holds NetDefense-managed trust objects, since the family
// removes the managed objects a payload does not name.

const (
	itRootCA    = "221f3268-e2e0-4000-8000-000000000001"
	itInterCA   = "221f3268-e2e0-4000-8000-000000000002"
	itExtraCA   = "221f3268-e2e0-4000-8000-000000000003"
	itWildcard  = "221f3268-e2e0-4000-8000-000000000011"
	itHost      = "221f3268-e2e0-4000-8000-000000000012"
	itHandMade  = "6f1c2a7e-e2e0-4000-8000-000000000021"
	itLookalike = "6f1c2a7e-e2e0-4000-8000-000000000022"
	itRootCopy  = "6f1c2a7e-e2e0-4000-8000-000000000023"

	// The overlapping layout: a root whose subject values all occur in its
	// intermediate's subject.
	itAcmeRoot  = "221f3268-e2e0-4000-8000-000000000031"
	itAcmeInter = "221f3268-e2e0-4000-8000-000000000032"
	itAcmeLeaf  = "221f3268-e2e0-4000-8000-000000000033"

	// Two copies of one CA, the same subject and key.
	itDupOlder = "221f3268-e2e0-4000-8000-000000000041"
	itDupNewer = "221f3268-e2e0-4000-8000-000000000042"
	itDupLeaf  = "221f3268-e2e0-4000-8000-000000000043"
)

var refIDPattern = regexp.MustCompile(`^[0-9a-f]{13}$`)

// trustLab is the state of one run against the device.
type trustLab struct {
	client  *opnapi.Client
	outputs []string
}

type trustStore struct {
	cas, certs map[string]opnapi.TrustObject
}

func (l *trustLab) read(t *testing.T) trustStore {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	store := trustStore{cas: map[string]opnapi.TrustObject{}, certs: map[string]opnapi.TrustObject{}}
	for kind, into := range map[opnapi.TrustKind]map[string]opnapi.TrustObject{opnapi.TrustCA: store.cas, opnapi.TrustCert: store.certs} {
		objects, err := l.client.ListTrust(ctx, kind)
		if err != nil {
			t.Fatalf("ListTrust(%s): %v", kind, err)
		}
		for _, o := range objects {
			into[o.UUID] = o
		}
	}
	return store
}

// sync runs the family on the device and keeps what it reported for the leak
// check. The config.xml it reads holds the device's CAs and certificates, as
// the device's own does, and then configXML.
func (l *trustLab) sync(t *testing.T, payload map[string]interface{}, rejectDangerous bool, configXML string) trustFamilyOutcome {
	t.Helper()
	store := l.read(t)
	var mirror strings.Builder
	for kind, objects := range map[string]map[string]opnapi.TrustObject{"ca": store.cas, "cert": store.certs} {
		for _, obj := range objects {
			fmt.Fprintf(&mirror, "<%s uuid=%q><refid>%s</refid><caref>%s</caref></%s>\n", kind, obj.UUID, obj.RefID, obj.CARef, kind)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	out := executeSyncTrust(ctx, l.client, parseAPITrustContent(payload), rejectDangerous, writeConfigXML(t, mirror.String()+configXML))
	raw, _ := json.Marshal(out.Result)
	l.outputs = append(l.outputs, string(raw), strings.Join(out.Result.Errors, "\n"),
		buildSyncSummary(out.Result.Results, len(out.Result.Errors)))
	if out.RestartWebGUI {
		t.Error("the run asked for a web GUI restart")
	}
	return out
}

// assertStored checks an object on the device against what was sent: its name,
// certificate and key, a refid OPNsense minted and, unless "-", its issuer.
func assertStored(t *testing.T, objects map[string]opnapi.TrustObject, uuid, name string, cert *x509.Certificate, keyPEM, caref string) opnapi.TrustObject {
	t.Helper()
	obj, ok := objects[uuid]
	if !ok {
		t.Fatalf("%s %q is not on the device", uuid, name)
	}
	if obj.Descr != name || obj.CertSHA256 != opnapi.CertFingerprint(cert) {
		t.Errorf("%s: stored name %q, certificate %s; want %q, %s", uuid, obj.Descr, obj.CertSHA256, name, opnapi.CertFingerprint(cert))
	}
	if keyPEM != "" && obj.KeySHA256 != opnapi.PrivateKeyFingerprint([]byte(keyPEM)) {
		t.Errorf("%s: the stored key is not the one sent", uuid)
	}
	if !refIDPattern.MatchString(obj.RefID) {
		t.Errorf("%s: refid %q", uuid, obj.RefID)
	}
	if caref != "-" && obj.CARef != caref {
		t.Errorf("%s: caref %q, want %q", uuid, obj.CARef, caref)
	}
	return obj
}

func TestIntegration_TrustFamily(t *testing.T) {
	logs := captureLogs(t)
	lab := &trustLab{client: integrationClient(t)}
	calls := recordConfigctl(t)

	before := lab.read(t)
	for uuid, o := range before.cas {
		if o.IsManaged() || uuid == itHandMade || uuid == itLookalike || uuid == itRootCopy {
			t.Fatalf("the device already holds the managed CA %s: refusing to run", uuid)
		}
	}
	for uuid, o := range before.certs {
		if o.IsManaged() || uuid == itHandMade || uuid == itLookalike || uuid == itRootCopy {
			t.Fatalf("the device already holds the managed certificate %s: refusing to run", uuid)
		}
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		for _, uuid := range []string{itWildcard, itHost, itAcmeLeaf, itDupLeaf} {
			_ = lab.client.DeleteTrust(ctx, opnapi.TrustCert, uuid)
		}
		for _, uuid := range []string{itInterCA, itRootCA, itExtraCA, itHandMade, itLookalike, itRootCopy, itAcmeInter, itAcmeRoot, itDupNewer, itDupOlder} {
			_ = lab.client.DeleteTrust(ctx, opnapi.TrustCA, uuid)
		}
		after := lab.read(t)
		if len(after.cas) != len(before.cas) || len(after.certs) != len(before.certs) {
			t.Errorf("the device holds %d CAs and %d certificates after the run, %d and %d before",
				len(after.cas), len(after.certs), len(before.cas), len(before.certs))
		}
		for uuid := range before.cas {
			if _, ok := after.cas[uuid]; !ok {
				t.Errorf("the CA %s that was there before is gone", uuid)
			}
		}
		for uuid := range before.certs {
			if _, ok := after.certs[uuid]; !ok {
				t.Errorf("the certificate %s that was there before is gone", uuid)
			}
		}
	})

	suffix := strconv.FormatInt(time.Now().Unix(), 36)
	name := func(s string) string { return "nd-itest " + s + " " + suffix }
	var (
		rootName, interName = name("Root CA"), name("Issuing CA")
		wildName, hostName  = name("wildcard"), name("host")
		handName, extraName = name("hand-made"), name("extra CA")
	)
	root := newTestCA(t, rootName, nil, nil)
	inter := newTestCA(t, interName, root, nil)
	wildcard := inter.issue(t, "*.itest.example.net", false)
	host := root.issue(t, "fw.itest.example.net", true)
	renewedHost := root.issue(t, "fw.itest.example.net", true)
	renewedRoot := newTestCA(t, rootName, nil, root.key)
	rekeyedRoot := newTestCA(t, rootName, nil, nil)
	handCA := newTestCA(t, handName, nil, nil)
	extraCA := newTestCA(t, extraName, nil, nil)
	leaves := []testLeaf{wildcard, host, renewedHost,
		{certPEM: root.certPEM}, {certPEM: inter.certPEM}, {certPEM: renewedRoot.certPEM},
		{certPEM: rekeyedRoot.certPEM}, {certPEM: handCA.certPEM}, {certPEM: extraCA.certPEM}}

	payload := func(rootCA *testCA, hostLeaf testLeaf, extra ...map[string]interface{}) map[string]interface{} {
		snippets := []map[string]interface{}{caSnippet(itRootCA, rootName, rootCA), caSnippet(itInterCA, interName, inter)}
		snippets = append(snippets, extra...)
		snippets = append(snippets, certSnippet(itWildcard, wildName, wildcard), certSnippet(itHost, hostName, hostLeaf))
		return trustPayload(snippets...)
	}
	unchanged := []string{
		"trust_ca " + rootName + " unchanged success",
		"trust_ca " + interName + " unchanged success",
		"trust_cert " + wildName + " unchanged success",
		"trust_cert " + hostName + " unchanged success",
	}
	var rootRef, interRef, wildRef, hostRef string

	t.Run("create", func(t *testing.T) {
		out := lab.sync(t, payload(root, host), false, "")
		assertItems(t, out.Result,
			"trust_ca "+rootName+" created success",
			"trust_ca "+interName+" created success",
			"trust_cert "+wildName+" created success",
			"trust_cert "+hostName+" created success",
		)
		store := lab.read(t)
		rootRef = assertStored(t, store.cas, itRootCA, rootName, root.cert, "", "-").RefID
		interRef = assertStored(t, store.cas, itInterCA, interName, inter.cert, "", "-").RefID
		wildRef = assertStored(t, store.certs, itWildcard, wildName, wildcard.cert, wildcard.keyPEM, interRef).RefID
		hostRef = assertStored(t, store.certs, itHost, hostName, host.cert, host.keyPEM, rootRef).RefID
		// The agent posts no issuer for a CA; OPNsense records it by subject.
		if store.cas[itRootCA].CARef != "" || store.cas[itInterCA].CARef != rootRef {
			t.Errorf("the root's caref is %q and the intermediate's %q, want none and the root's", store.cas[itRootCA].CARef, store.cas[itInterCA].CARef)
		}
		if len(*calls) != 0 {
			t.Errorf("configctl calls = %q", *calls)
		}
	})

	t.Run("a repeated sync changes nothing", func(t *testing.T) {
		out := lab.sync(t, payload(root, host), false, "")
		assertItems(t, out.Result, unchanged...)
		store := lab.read(t)
		if store.cas[itRootCA].RefID != rootRef || store.certs[itHost].RefID != hostRef {
			t.Error("a refid changed")
		}
	})

	consumers := func() string {
		return `
<ca><refid>` + rootRef + `</refid></ca>
<ca><refid>` + interRef + `</refid><caref>` + rootRef + `</caref></ca>
<cert><refid>` + wildRef + `</refid><caref>` + interRef + `</caref></cert>
<cert><refid>` + hostRef + `</refid><caref>` + rootRef + `</caref></cert>
<OPNsense>
  <OpenVPN><Instances><Instance uuid="aaaaaaaa-e2e0-4000-8000-000000000001"><description>itest VPN</description><cert>` + hostRef + `</cert></Instance></Instances></OpenVPN>
  <Swanctl><locals><local uuid="bbbbbbbb-e2e0-4000-8000-000000000001"><description>itest HQ</description><certs>` + hostRef + `</certs></local></locals></Swanctl>
  <Syslog><destinations><destination uuid="cccccccc-e2e0-4000-8000-000000000001"><description>itest SIEM</description><certificate>` + hostRef + `</certificate></destination></destinations></Syslog>
  <captiveportal><zones><zone uuid="eeeeeeee-e2e0-4000-8000-000000000001"><description>itest Guests</description><certificate>` + wildRef + `</certificate></zone></zones></captiveportal>
</OPNsense>`
	}

	t.Run("a renewed certificate keeps its refid and reloads what uses it", func(t *testing.T) {
		*calls = nil
		out := lab.sync(t, payload(root, renewedHost), false, consumers())
		assertItems(t, out.Result,
			"trust_ca "+rootName+" unchanged success",
			"trust_ca "+interName+" unchanged success",
			"trust_cert "+wildName+" unchanged success",
			"trust_cert "+hostName+" updated success",
			"trust_reload itest VPN openvpn configure success",
			"trust_reload itest HQ ipsec reload success",
			"trust_reload itest SIEM syslog restart success",
		)
		assertStored(t, lab.read(t).certs, itHost, hostName, renewedHost.cert, renewedHost.keyPEM, rootRef)
		if got := lab.read(t).certs[itHost].RefID; got != hostRef {
			t.Errorf("the renewal changed the refid from %q to %q", hostRef, got)
		}
		if want := []string{"openvpn configure", "ipsec reload", "syslog stop", "syslog start"}; strings.Join(*calls, ",") != strings.Join(want, ",") {
			t.Errorf("configctl calls = %q, want %q", *calls, want)
		}
	})

	t.Run("a CA renewed in place keeps its refid and reaches what its certificates serve", func(t *testing.T) {
		*calls = nil
		out := lab.sync(t, payload(renewedRoot, renewedHost), false, consumers())
		assertItems(t, out.Result,
			"trust_ca "+rootName+" updated success",
			"trust_ca "+interName+" unchanged success",
			"trust_cert "+wildName+" unchanged success",
			"trust_cert "+hostName+" unchanged success",
			"trust_reload itest VPN openvpn configure success",
			"trust_reload itest HQ ipsec reload success",
			"trust_reload itest SIEM syslog restart success",
			"trust_reload itest Guests captiveportal restart success",
		)
		store := lab.read(t)
		assertStored(t, store.cas, itRootCA, rootName, renewedRoot.cert, "", "-")
		if store.cas[itRootCA].RefID != rootRef || store.certs[itHost].CARef != rootRef || store.certs[itWildcard].CARef != interRef {
			t.Errorf("a refid or caref changed: root %q, host caref %q, wildcard caref %q",
				store.cas[itRootCA].RefID, store.certs[itHost].CARef, store.certs[itWildcard].CARef)
		}
		want := []string{"openvpn configure", "ipsec reload", "syslog stop", "syslog start", "template reload OPNsense/Captiveportal", "captiveportal restart"}
		if strings.Join(*calls, ",") != strings.Join(want, ",") {
			t.Errorf("configctl calls = %q, want %q", *calls, want)
		}
	})

	t.Run("a re-keyed CA is refused", func(t *testing.T) {
		*calls = nil
		out := lab.sync(t, payload(rekeyedRoot, renewedHost), false, "")
		assertItems(t, out.Result,
			"trust_ca "+rootName+" blocked blocked TRUST_CA_REKEYED",
			"trust_ca "+interName+" unchanged success",
			"trust_cert "+wildName+" unchanged success",
			"trust_cert "+hostName+" unchanged success",
		)
		assertStored(t, lab.read(t).cas, itRootCA, rootName, renewedRoot.cert, "", "-")
	})

	t.Run("a name a hand-made object has is refused", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := lab.client.SetTrustCA(ctx, itHandMade, opnapi.TrustCAWrite{Descr: handName, CrtPEM: handCA.certPEM}); err != nil {
			t.Fatalf("creating the hand-made CA: %v", err)
		}
		out := lab.sync(t, payload(renewedRoot, renewedHost, caSnippet(itExtraCA, strings.ToUpper(handName), extraCA)), false, "")
		assertItems(t, out.Result,
			"trust_ca "+rootName+" unchanged success",
			"trust_ca "+interName+" unchanged success",
			"trust_ca "+strings.ToUpper(handName)+" blocked blocked NAME_COLLISION_UNMANAGED",
			"trust_cert "+wildName+" unchanged success",
			"trust_cert "+hostName+" unchanged success",
		)
		store := lab.read(t)
		assertStored(t, store.cas, itHandMade, handName, handCA.cert, "", "-")
		if _, ok := store.cas[itExtraCA]; ok {
			t.Error("the refused CA was written")
		}
	})

	t.Run("reject_dangerous_snippets refuses a new CA", func(t *testing.T) {
		out := lab.sync(t, payload(renewedRoot, renewedHost, caSnippet(itExtraCA, extraName, extraCA)), true, "")
		assertItems(t, out.Result,
			"trust_ca "+rootName+" unchanged success",
			"trust_ca "+interName+" unchanged success",
			"trust_ca "+extraName+" rejected blocked TRUST_REJECTED_DANGEROUS",
			"trust_cert "+wildName+" unchanged success",
			"trust_cert "+hostName+" unchanged success",
		)
		if _, ok := lab.read(t).cas[itExtraCA]; ok {
			t.Error("the refused CA was written")
		}
	})

	t.Run("content the agent cannot read changes nothing", func(t *testing.T) {
		bad := trustSnippet("TRUST_CERT", wildName, map[string]string{"uuid": itWildcard, "name": wildName, "crt": wildcard.keyPEM, "key": wildcard.certPEM})
		out := lab.sync(t, trustPayload(caSnippet(itRootCA, rootName, renewedRoot), bad), false, "")
		assertItems(t, out.Result, "trust_cert "+wildName+" unsupported blocked TRUST_CONTENT_UNSUPPORTED")
		store := lab.read(t)
		for _, uuid := range []string{itInterCA, itRootCA} {
			if _, ok := store.cas[uuid]; !ok {
				t.Errorf("the CA %s was removed", uuid)
			}
		}
		for _, uuid := range []string{itWildcard, itHost} {
			if _, ok := store.certs[uuid]; !ok {
				t.Errorf("the certificate %s was removed", uuid)
			}
		}
	})

	t.Run("two CAs of one name in a sync are both refused", func(t *testing.T) {
		out := lab.sync(t, payload(renewedRoot, renewedHost, caSnippet(itExtraCA, extraName, rekeyedRoot)), false, "")
		assertItems(t, out.Result,
			"trust_ca "+rootName+" blocked blocked TRUST_CA_DN_CONFLICT",
			"trust_ca "+interName+" unchanged success",
			"trust_ca "+extraName+" blocked blocked TRUST_CA_DN_CONFLICT",
			"trust_cert "+wildName+" unchanged success",
			"trust_cert "+hostName+" unchanged success",
		)
		if _, ok := lab.read(t).cas[itExtraCA]; ok {
			t.Error("the refused CA was written")
		}
	})

	t.Run("a hand-made CA of the root's name is reported on every pass until it goes", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := lab.client.SetTrustCA(ctx, itLookalike, opnapi.TrustCAWrite{Descr: name("look-alike root"), CrtPEM: rekeyedRoot.certPEM}); err != nil {
			t.Fatalf("creating the look-alike CA: %v", err)
		}
		store := lab.read(t)
		lookalikeRef := store.cas[itLookalike].RefID
		if store.certs[itHost].CARef != lookalikeRef {
			t.Errorf("OPNsense did not re-link the host to the newest CA of its issuer's name: caref %q, look-alike %q, root %q",
				store.certs[itHost].CARef, lookalikeRef, rootRef)
		}

		out := lab.sync(t, payload(renewedRoot, renewedHost), false, "")
		assertItems(t, out.Result,
			"trust_ca "+rootName+" blocked blocked TRUST_CA_DN_CONFLICT",
			"trust_ca "+interName+" unchanged success",
			"trust_cert "+wildName+" unchanged success",
			"trust_cert "+hostName+" blocked blocked TRUST_ISSUER_MISLINKED",
		)
		if got := lab.read(t).certs[itHost].CARef; got != lookalikeRef {
			t.Errorf("the sync wrote another issuer: caref %q", got)
		}

		// A renewal of the mislinked host is written all the same, since its
		// link stays the same, and still reported.
		mislinkedRenewal := root.issue(t, "fw.itest.example.net", true)
		leaves = append(leaves, mislinkedRenewal)
		out = lab.sync(t, payload(renewedRoot, mislinkedRenewal), false, "")
		assertItems(t, out.Result,
			"trust_ca "+rootName+" blocked blocked TRUST_CA_DN_CONFLICT",
			"trust_ca "+interName+" unchanged success",
			"trust_cert "+wildName+" unchanged success",
			"trust_cert "+hostName+" blocked blocked TRUST_ISSUER_MISLINKED",
		)
		if msg := out.Result.Results[3].Error; !strings.Contains(msg, "The certificate was written") {
			t.Errorf("refusal = %q", msg)
		}
		stored := lab.read(t).certs[itHost]
		if stored.CertSHA256 != opnapi.CertFingerprint(mislinkedRenewal.cert) || stored.CARef != lookalikeRef {
			t.Errorf("the renewal was not written as it stood: caref %q", stored.CARef)
		}

		// Deleting a CA re-links nothing; the next sync writes the host again
		// and OPNsense links it to the root.
		if err := lab.client.DeleteTrust(ctx, opnapi.TrustCA, itLookalike); err != nil {
			t.Fatalf("deleting the look-alike CA: %v", err)
		}
		out = lab.sync(t, payload(renewedRoot, renewedHost), false, "")
		assertItems(t, out.Result,
			"trust_ca "+rootName+" unchanged success",
			"trust_ca "+interName+" unchanged success",
			"trust_cert "+wildName+" unchanged success",
			"trust_cert "+hostName+" updated success",
		)
		if got := lab.read(t).certs[itHost].CARef; got != rootRef {
			t.Errorf("the host's caref is %q, want the root's %q", got, rootRef)
		}
	})

	t.Run("a CA its certificates name is kept", func(t *testing.T) {
		out := lab.sync(t, trustPayload(
			caSnippet(itInterCA, interName, inter),
			certSnippet(itWildcard, wildName, wildcard),
			certSnippet(itHost, hostName, renewedHost),
		), false, "")
		assertItems(t, out.Result,
			"trust_ca "+interName+" unchanged success",
			"trust_cert "+wildName+" unchanged success",
			"trust_cert "+hostName+" unchanged success",
			"trust_ca "+rootName+" retained blocked TRUST_IN_USE",
		)
		if msg := out.Result.Results[3].Error; !strings.Contains(msg, `certificate "`+hostName+`"`) {
			t.Errorf("the refusal does not name the certificate: %q", msg)
		}
		if _, ok := lab.read(t).cas[itRootCA]; !ok {
			t.Error("the CA in use was removed")
		}
	})

	t.Run("certificates go first and take their last CA with them", func(t *testing.T) {
		out := lab.sync(t, trustPayload(caSnippet(itRootCA, rootName, renewedRoot), certSnippet(itHost, hostName, renewedHost)), false, "")
		assertItems(t, out.Result,
			"trust_ca "+rootName+" unchanged success",
			"trust_cert "+hostName+" unchanged success",
			"trust_cert "+wildName+" deleted success",
			"trust_ca "+interName+" deleted success",
		)
		store := lab.read(t)
		if _, ok := store.certs[itWildcard]; ok {
			t.Error("the wildcard certificate is still there")
		}
		if _, ok := store.cas[itInterCA]; ok {
			t.Error("the intermediate CA is still there")
		}
	})

	t.Run("a certificate a service uses is kept", func(t *testing.T) {
		cfg := `<OPNsense><OpenVPN><Instances><Instance uuid="aaaaaaaa-e2e0-4000-8000-000000000001"><description>itest VPN</description><cert>` + hostRef + `</cert></Instance></Instances></OpenVPN></OPNsense>`
		out := lab.sync(t, trustPayload(caSnippet(itRootCA, rootName, renewedRoot)), false, cfg)
		assertItems(t, out.Result,
			"trust_ca "+rootName+" unchanged success",
			"trust_cert "+hostName+" retained blocked TRUST_IN_USE",
		)
		if msg := out.Result.Results[1].Error; !strings.Contains(msg, "itest VPN") {
			t.Errorf("the refusal does not name the service: %q", msg)
		}
	})

	t.Run("an empty payload removes the rest", func(t *testing.T) {
		out := lab.sync(t, trustPayload(), false, "")
		assertItems(t, out.Result,
			"trust_cert "+hostName+" deleted success",
			"trust_ca "+rootName+" deleted success",
		)
		store := lab.read(t)
		for uuid, o := range store.cas {
			if o.IsManaged() {
				t.Errorf("the managed CA %s is still there", uuid)
			}
		}
		for uuid, o := range store.certs {
			if o.IsManaged() {
				t.Errorf("the managed certificate %s is still there", uuid)
			}
		}
		if _, ok := store.cas[itHandMade]; !ok {
			t.Error("the hand-made CA was removed")
		}
	})

	acmeRoot := newNamedCA(t, pkix.Name{CommonName: name("Acme"), Organization: []string{name("Acme")}, Country: []string{"US"}}, nil, false)
	acmeInter := newNamedCA(t, pkix.Name{CommonName: name("Acme Issuing CA"), Organization: []string{name("Acme")}, Country: []string{"US"}}, acmeRoot, false)
	acmeLeaf := acmeInter.issue(t, "acme.itest.example.net", false)
	acmeRootName, acmeInterName, acmeLeafName := name("Acme Root"), name("Acme Issuing CA"), name("Acme leaf")
	acmePayload := trustPayload(
		caSnippet(itAcmeInter, acmeInterName, acmeInter),
		caSnippet(itAcmeRoot, acmeRootName, acmeRoot),
		certSnippet(itAcmeLeaf, acmeLeafName, acmeLeaf),
	)
	leaves = append(leaves, acmeLeaf, testLeaf{certPEM: acmeRoot.certPEM}, testLeaf{certPEM: acmeInter.certPEM})

	t.Run("overlapping names: the root is created first, so the leaf links to the intermediate", func(t *testing.T) {
		out := lab.sync(t, acmePayload, false, "")
		assertItems(t, out.Result,
			"trust_ca "+acmeRootName+" created success",
			"trust_ca "+acmeInterName+" created success",
			"trust_cert "+acmeLeafName+" created success",
		)
		store := lab.read(t)
		if got, want := store.certs[itAcmeLeaf].CARef, store.cas[itAcmeInter].RefID; got != want {
			t.Errorf("the leaf's caref is %q, want the intermediate's %q (root %q)", got, want, store.cas[itAcmeRoot].RefID)
		}
	})

	t.Run("overlapping names: a newer copy of the root takes the leaf, which is reported, and its removal lets it go back", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := lab.client.SetTrustCA(ctx, itRootCopy, opnapi.TrustCAWrite{Descr: name("copy of the Acme root"), CrtPEM: acmeRoot.certPEM}); err != nil {
			t.Fatalf("creating the copy: %v", err)
		}
		store := lab.read(t)
		copyRef := store.cas[itRootCopy].RefID
		if store.certs[itAcmeLeaf].CARef != copyRef {
			t.Errorf("OPNsense did not link the leaf to the newest CA whose values its issuer holds: caref %q, copy %q", store.certs[itAcmeLeaf].CARef, copyRef)
		}

		out := lab.sync(t, acmePayload, false, "")
		assertItems(t, out.Result,
			"trust_ca "+acmeRootName+" unchanged success",
			"trust_ca "+acmeInterName+" unchanged success",
			"trust_cert "+acmeLeafName+" blocked blocked TRUST_ISSUER_MISLINKED",
		)

		if err := lab.client.DeleteTrust(ctx, opnapi.TrustCA, itRootCopy); err != nil {
			t.Fatalf("deleting the copy: %v", err)
		}
		out = lab.sync(t, acmePayload, false, "")
		assertItems(t, out.Result,
			"trust_ca "+acmeRootName+" unchanged success",
			"trust_ca "+acmeInterName+" unchanged success",
			"trust_cert "+acmeLeafName+" updated success",
		)
		store = lab.read(t)
		if got, want := store.certs[itAcmeLeaf].CARef, store.cas[itAcmeInter].RefID; got != want {
			t.Errorf("the leaf's caref is %q, want the intermediate's %q", got, want)
		}
	})

	t.Run("overlapping names: an empty payload removes them", func(t *testing.T) {
		out := lab.sync(t, trustPayload(), false, "")
		assertItems(t, out.Result,
			"trust_cert "+acmeLeafName+" deleted success",
			"trust_ca "+acmeInterName+" deleted success",
			"trust_ca "+acmeRootName+" deleted success",
		)
	})

	dupOlder := newTestCA(t, name("Dup Root"), nil, nil)
	dupNewerSame := newTestCA(t, name("Dup Root"), nil, dupOlder.key)
	dupLeaf := dupOlder.issue(t, "dup.itest.example.net", false)
	dupOlderName, dupNewerName, dupLeafName := name("Dup Root"), name("Dup Root again"), name("Dup leaf")
	leaves = append(leaves, dupLeaf, testLeaf{certPEM: dupOlder.certPEM}, testLeaf{certPEM: dupNewerSame.certPEM})

	t.Run("two copies of a CA: dropping the newer one", func(t *testing.T) {
		out := lab.sync(t, trustPayload(
			caSnippet(itDupOlder, dupOlderName, dupOlder),
			caSnippet(itDupNewer, dupNewerName, dupNewerSame),
			certSnippet(itDupLeaf, dupLeafName, dupLeaf),
		), false, "")
		assertItems(t, out.Result,
			"trust_ca "+dupOlderName+" created success",
			"trust_ca "+dupNewerName+" created success",
			"trust_cert "+dupLeafName+" created success",
		)
		store := lab.read(t)
		if got, want := store.certs[itDupLeaf].CARef, store.cas[itDupNewer].RefID; got != want {
			t.Errorf("OPNsense linked the leaf to %q, want the newer copy %q", got, want)
		}

		kept := trustPayload(caSnippet(itDupOlder, dupOlderName, dupOlder), certSnippet(itDupLeaf, dupLeafName, dupLeaf))
		out = lab.sync(t, kept, false, "")
		assertItems(t, out.Result,
			"trust_ca "+dupOlderName+" unchanged success",
			"trust_cert "+dupLeafName+" unchanged success",
			"trust_ca "+dupNewerName+" deleted success",
		)
		out = lab.sync(t, kept, false, "")
		assertItems(t, out.Result,
			"trust_ca "+dupOlderName+" unchanged success",
			"trust_cert "+dupLeafName+" updated success",
		)
		store = lab.read(t)
		if got, want := store.certs[itDupLeaf].CARef, store.cas[itDupOlder].RefID; got != want {
			t.Errorf("the leaf's caref is %q, want the older copy %q", got, want)
		}

		out = lab.sync(t, trustPayload(), false, "")
		assertItems(t, out.Result,
			"trust_cert "+dupLeafName+" deleted success",
			"trust_ca "+dupOlderName+" deleted success",
		)
	})

	t.Run("an unknown uuid reads as not found", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		for _, kind := range []opnapi.TrustKind{opnapi.TrustCA, opnapi.TrustCert} {
			if _, found, err := lab.client.GetTrust(ctx, kind, itExtraCA); err != nil || found {
				t.Errorf("GetTrust(%s): found %v, err %v", kind, found, err)
			}
		}
	})

	t.Run("a refusal by the device carries none of what was sent", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		err := lab.client.SetTrustCA(ctx, itExtraCA, opnapi.TrustCAWrite{Descr: extraName, CrtPEM: host.keyPEM})
		if err == nil {
			t.Fatal("the device saved a private key as a CA")
		}
		t.Logf("the device's refusal: %v", err)
		lab.outputs = append(lab.outputs, err.Error())
	})

	for i, out := range lab.outputs {
		assertNoMaterial(t, "output "+strconv.Itoa(i), out, leaves...)
	}
	assertNoMaterial(t, "the logs", renderLogs(logs), leaves...)
	if logs.Len() == 0 {
		t.Error("nothing was logged, so the log check proves nothing")
	}
}
