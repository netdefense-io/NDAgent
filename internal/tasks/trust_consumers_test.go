package tasks

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func parseConfigForTest(t *testing.T, body string) *trustConfig {
	t.Helper()
	cfg, err := readTrustConfig(writeConfigXML(t, body))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func consumerLines(consumers []trustConsumer) []string {
	var out []string
	for _, c := range consumers {
		out = append(out, strings.TrimSpace(c.Kind+" | "+c.UUID+" | "+c.Label))
	}
	return out
}

// Every setting the reload table knows, in the spelling config.xml uses, and
// one it does not know.
func TestTrustConsumers_Classification(t *testing.T) {
	const ref = "66f0aaaaaaaa1"
	cfg := parseConfigForTest(t, `
<system><webgui><ssl-certref>`+ref+`</ssl-certref></webgui></system>
<OPNsense>
  <OpenVPN><Instances>
    <Instance uuid="u-ovpn-1"><description>Road warriors</description><cert>`+ref+`</cert><ca>`+ref+`</ca></Instance>
  </Instances></OpenVPN>
  <Swanctl>
    <locals><local uuid="u-local"><description>HQ local</description><certs>`+ref+`</certs></local></locals>
    <remotes><remote uuid="u-remote"><description>Branch</description><certs>x,`+ref+`</certs><cacerts>`+ref+`, y</cacerts></remote></remotes>
  </Swanctl>
  <Syslog><destinations><destination uuid="u-syslog"><description>SIEM</description><certificate>`+ref+`</certificate></destination></destinations></Syslog>
  <captiveportal><zones><zone uuid="u-cp"><description>Guests</description><certificate>`+ref+`</certificate></zone></zones></captiveportal>
  <HAProxy><servers><server uuid="u-haproxy"><name>backend-a</name><sslCA>`+ref+`</sslCA></server></servers></HAProxy>
</OPNsense>
<openvpn><openvpn-server><vpnid>1</vpnid><description>Legacy server</description><certref>`+ref+`</certref><caref>`+ref+`</caref></openvpn-server></openvpn>
<ipsec><phase1><ikeid>1</ikeid><descr>Legacy tunnel</descr><certref>`+ref+`</certref></phase1></ipsec>
`)
	got := consumerLines(cfg.consumersOf(ref, false))
	want := []string{
		"webgui |  | webgui",
		"openvpn | u-ovpn-1 | Road warriors",
		"ipsec | u-local | HQ local",
		"ipsec | u-remote | Branch",
		"syslog | u-syslog | SIEM",
		"captiveportal | u-cp | Guests",
		"| u-haproxy | backend-a",
		"openvpn |  | openvpn.openvpn-server (Legacy server)",
		"ipsec |  | ipsec.phase1 (Legacy tunnel)",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("consumers:\n  got  %q\n  want %q", got, want)
	}
}

// An object's own refid, a local account's certificate and the issuer link of
// a CA, certificate or CRL name the object without using it.
func TestTrustConsumers_Exclusions(t *testing.T) {
	const ref = "66f0aaaaaaaa1"
	cfg := parseConfigForTest(t, `
<ca><refid>`+ref+`</refid><descr>Root</descr></ca>
<ca><refid>66f0bbbbbbbb2</refid><caref>`+ref+`</caref></ca>
<cert><refid>66f0cccccccc3</refid><caref>`+ref+`</caref></cert>
<crl><refid>66f0dddddddd4</refid><caref>`+ref+`</caref></crl>
<system><user><name>alice</name><cert>`+ref+`</cert></user></system>
`)
	if got := cfg.consumersOf(ref, false); len(got) != 0 {
		t.Fatalf("consumers = %q, want none", consumerLines(got))
	}
}

// A CA's renewal reaches what uses everything below it in the chain.
func TestTrustConsumers_ChainOfACA(t *testing.T) {
	cfg := parseConfigForTest(t, `
<ca><refid>root</refid></ca>
<ca><refid>inter</refid><caref>root</caref></ca>
<cert><refid>leaf</refid><caref>inter</caref></cert>
<cert><refid>other</refid><caref>elsewhere</caref></cert>
<system><webgui><ssl-certref>leaf</ssl-certref></webgui></system>
<OPNsense>
  <OpenVPN><Instances><Instance uuid="u-1"><description>VPN</description><ca>root</ca></Instance></Instances></OpenVPN>
  <Syslog><destinations><destination uuid="u-2"><description>SIEM</description><certificate>other</certificate></destination></destinations></Syslog>
</OPNsense>`)
	got := consumerLines(cfg.consumersOf("root", true))
	want := []string{"openvpn | u-1 | VPN", "webgui |  | webgui"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("consumers of the root's chain = %q, want %q", got, want)
	}
	if got := cfg.consumersOf("root", false); len(got) != 1 {
		t.Fatalf("direct consumers of the root = %q", consumerLines(got))
	}
}

func TestTrustConsumers_LabelsWithoutADescription(t *testing.T) {
	cfg := parseConfigForTest(t, `<OPNsense><Syslog><destinations><destination uuid="u-9"><certificate>r</certificate></destination></destinations></Syslog></OPNsense>
<custom><setting><certref>r</certref></setting></custom>`)
	got := consumerLines(cfg.consumersOf("r", false))
	want := []string{"syslog | u-9 | opnsense.syslog.destinations.destination u-9", "|  | custom.setting"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("consumers = %q, want %q", got, want)
	}
}

func TestReadTrustConfig_Malformed(t *testing.T) {
	for _, body := range []string{"<a><b></a>", ""} {
		path := writeConfigXML(t, "")
		if err := writeRaw(path, body); err != nil {
			t.Fatal(err)
		}
		if _, err := readTrustConfig(path); err == nil {
			t.Errorf("readTrustConfig(%q) accepted it", body)
		}
	}
	if _, err := readTrustConfig("/nonexistent/config.xml"); err == nil {
		t.Error("a missing config.xml was read")
	}
}

// One item with several settings naming the object is one consumer of the unit
// a known setting gives it, whichever setting comes first; an item whose only
// setting is unknown stays an unknown consumer.
func TestTrustConsumers_AKnownSettingDecidesTheItem(t *testing.T) {
	const ref = "66f0aaaaaaaa1"
	cfg := parseConfigForTest(t, `
<OPNsense>
  <OpenVPN><Instances>
    <Instance uuid="u-ovpn-1"><description>Road warriors</description><tls_ref>`+ref+`</tls_ref><cert>`+ref+`</cert><ca>`+ref+`</ca></Instance>
  </Instances></OpenVPN>
  <Nginx><http_server uuid="u-nginx"><servername>portal</servername><certificate>`+ref+`</certificate></http_server></Nginx>
</OPNsense>`)
	got := consumerLines(cfg.consumersOf(ref, false))
	want := []string{"openvpn | u-ovpn-1 | Road warriors", "| u-nginx | opnsense.nginx.http_server u-nginx"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("consumers:\n  got  %q\n  want %q", got, want)
	}
}

// config.xml tells whether the device holds a NetDefense CA or certificate:
// a top-level ca or cert with a managed uuid, nothing else.
func TestConfigHoldsManagedTrust(t *testing.T) {
	for _, tc := range []struct {
		body string
		want bool
	}{
		{``, false},
		{`<ca uuid="6f1c2a7e-4c3b-4f60-9d4e-0a8b1c2d3e4f"><refid>a</refid></ca>`, false},
		{`<ca uuid="221f3268-1111-4111-8111-000000000001"><refid>a</refid></ca>`, true},
		{`<cert uuid="221f3268-2222-4222-9222-000000000001"><refid>a</refid></cert>`, true},
		{`<OPNsense><Firewall><Alias><aliases><alias uuid="221f3268-0000-4000-8000-000000000001"/></aliases></Alias></Firewall></OPNsense>`, false},
		{`<OPNsense><ca uuid="221f3268-1111-4111-8111-000000000001"/></OPNsense>`, false},
	} {
		got, err := configHoldsManagedTrust(writeConfigXML(t, tc.body))
		if err != nil || got != tc.want {
			t.Errorf("%s: got %v, %v; want %v", tc.body, got, err, tc.want)
		}
	}
	if _, err := configHoldsManagedTrust("/nonexistent/config.xml"); err == nil {
		t.Error("a missing config.xml read as holding nothing")
	}
	if _, err := configHoldsManagedTrust(writeRawConfig(t, "<opnsense><ca")); err == nil {
		t.Error("a truncated config.xml read as holding nothing")
	}
}

func writeRawConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.xml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
