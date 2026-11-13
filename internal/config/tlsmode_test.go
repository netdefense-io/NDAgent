package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// loadedConfig is a Config whose trust material has been read, as Load
// leaves it.
func loadedConfig(c *Config) *Config {
	c.LoadControlPlaneTrust()
	return c
}

// assertRefusesEveryHandshake fails unless every control-plane configuration
// of c refuses the server at addr, with verification on and a root pool that
// is empty, never nil.
func assertRefusesEveryHandshake(t *testing.T, c *Config, addr string) {
	t.Helper()
	for name, cfg := range controlPlaneConfigs(c) {
		if cfg.InsecureSkipVerify {
			t.Errorf("%s: verification is off", name)
		}
		if cfg.RootCAs == nil || !cfg.RootCAs.Equal(x509.NewCertPool()) {
			t.Errorf("%s: the roots are not an empty pool", name)
		}
		if err := handshake(addr, cfg); !IsUntrustedCertificate(err) {
			t.Errorf("%s: err = %v, want the handshake refused", name, err)
		}
	}
}

type selfSignedServer struct {
	addr    string
	certPEM []byte
	cert    *x509.Certificate
}

// newSelfSignedServer serves TLS for 127.0.0.1 with a certificate that signs
// itself and is no CA. edit, when given, changes the certificate first.
func newSelfSignedServer(t *testing.T, edit ...func(*x509.Certificate)) selfSignedServer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "self-signed.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, e := range edit {
		e(template)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	srv := startTLSServer(t, testPKI{server: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}})
	return selfSignedServer{
		addr:    srv.Listener.Addr().String(),
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		cert:    cert,
	}
}

func controlPlaneChainLeaf(t *testing.T) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "control-plane-chain.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestTLSModeDefaultsToSystem(t *testing.T) {
	cfg, err := Load(createTempConfigFile(t, "enabled=true\ntoken=t\ndevice_uuid=d\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TLSMode != TLSModeSystem || cfg.TLSError != nil {
		t.Fatalf("TLSMode = %q, TLSError = %v", cfg.TLSMode, cfg.TLSError)
	}
	for name, tlsCfg := range controlPlaneConfigs(cfg) {
		if tlsCfg.InsecureSkipVerify || tlsCfg.RootCAs == nil || !tlsCfg.RootCAs.Equal(embeddedRoots()) {
			t.Errorf("%s: not the embedded roots with verification on", name)
		}
	}
}

// ssl_verify, tofu_ssl_verify and pathfinder_tls_verify no longer turn
// verification off, alone or together, for any of the three connections.
func TestOldVerifyTogglesNoLongerSkipVerification(t *testing.T) {
	pki := newTestPKI(t, "Untrusted CA")
	addr := startTLSServer(t, pki).Listener.Addr().String()

	for mask := 0; mask < 8; mask++ {
		var lines string
		for i, key := range []string{"ssl_verify", "tofu_ssl_verify", "pathfinder_tls_verify"} {
			lines += fmt.Sprintf("%s=%v\n", key, mask&(1<<i) != 0)
		}
		cfg, err := Load(createTempConfigFile(t, "enabled=true\ntoken=t\ndevice_uuid=d\n"+lines))
		if err != nil {
			t.Fatal(err)
		}
		for name, tlsCfg := range controlPlaneConfigs(cfg) {
			if tlsCfg.InsecureSkipVerify {
				t.Errorf("toggles %03b: %s skips verification", mask, name)
			}
			if err := handshake(addr, tlsCfg); !IsUntrustedCertificate(err) {
				t.Errorf("toggles %03b: %s: err = %v, want an untrusted certificate", mask, name, err)
			}
		}
	}

	cfg, err := Load(createTempConfigFile(t, "enabled=true\ntoken=t\ndevice_uuid=d\n"+
		"ssl_verify=false\ntofu_ssl_verify=false\npathfinder_tls_verify=false\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(cfg.IgnoredVerifyKeys(), ","); got != "ssl_verify,tofu_ssl_verify,pathfinder_tls_verify" {
		t.Errorf("IgnoredVerifyKeys = %s", got)
	}
	for name, tlsCfg := range controlPlaneConfigs(cfg) {
		if err := handshake(addr, tlsCfg); !IsUntrustedCertificate(err) {
			t.Errorf("loaded with every toggle off: %s: err = %v, want an untrusted certificate", name, err)
		}
	}
}

// The sentence a task result carries, as the operator's ruling words it: the
// setting is named with its key, is said to be ignored, and points to
// custom_ca.
func TestIgnoredVerifyNotice(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{"every toggle on", Config{}, ""},
		{"ssl_verify off", Config{ignoredVerify: []string{"ssl_verify"}},
			"Note: SSL Verification (ssl_verify=false) is off in this firewall's NetDefense settings and no longer honoured; " +
				"its connections to NetDefense are verified under TLS Mode system. " +
				"For a NetDefense server with a private CA, set TLS Mode to custom_ca."},
		{"two off", Config{ignoredVerify: []string{"tofu_ssl_verify", "pathfinder_tls_verify"}, TLSMode: TLSModeCustomCA},
			"Note: TOFU Key Fetch SSL Verification (tofu_ssl_verify=false) and Pathfinder SSL Verification (pathfinder_tls_verify=false) " +
				"are off in this firewall's NetDefense settings and no longer honoured; " +
				"its connections to NetDefense are verified under TLS Mode custom_ca. " +
				"For a NetDefense server with a private CA, set TLS Mode to custom_ca."},
		{"all off", Config{ignoredVerify: ignoredVerifyKeys},
			"Note: SSL Verification (ssl_verify=false), TOFU Key Fetch SSL Verification (tofu_ssl_verify=false) and " +
				"Pathfinder SSL Verification (pathfinder_tls_verify=false) are off in this firewall's NetDefense settings and no longer honoured; " +
				"its connections to NetDefense are verified under TLS Mode system. " +
				"For a NetDefense server with a private CA, set TLS Mode to custom_ca."},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.cfg.IgnoredVerifyNotice(); got != c.want {
				t.Errorf("notice = %q\nwant      %q", got, c.want)
			}
		})
	}
}

// custom_ca trusts the CAs of tls_ca_file and nothing else: not the built-in
// roots (the control plane's public chain no longer verifies), and not
// extra_ca_file, which it ignores.
func TestCustomCATrustsOnlyItsFile(t *testing.T) {
	private := newTestPKI(t, "Private CA")
	other := newTestPKI(t, "Inspection Proxy CA")
	privateAddr := startTLSServer(t, private).Listener.Addr().String()
	otherAddr := startTLSServer(t, other).Listener.Addr().String()

	dir := trustTestDirs(t, t.TempDir())
	caFile := writeFile(t, dir, "private-ca.pem", private.caPEM, 0o644)
	extraFile := writeFile(t, dir, "proxy-ca.pem", other.caPEM, 0o644)
	cfg, err := Load(createTempConfigFile(t, "enabled=true\ntoken=t\ndevice_uuid=d\n"+
		"tls_mode=custom_ca\ntls_ca_file="+caFile+"\nextra_ca_file="+extraFile+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TLSError != nil {
		t.Fatalf("TLSError = %v", cfg.TLSError)
	}
	if len(cfg.TLSCAs) != 1 || cfg.TLSCAs[0].Subject != "CN=Private CA" {
		t.Errorf("TLSCAs = %+v", cfg.TLSCAs)
	}
	if !cfg.ExtraCAFileIgnored() || cfg.ExtraCAs != nil {
		t.Errorf("extra_ca_file was read under custom_ca: ignored=%v, ExtraCAs=%v", cfg.ExtraCAFileIgnored(), cfg.ExtraCAs)
	}
	for name, tlsCfg := range controlPlaneConfigs(cfg) {
		if tlsCfg.InsecureSkipVerify {
			t.Errorf("%s: verification is off", name)
		}
		if err := handshake(privateAddr, tlsCfg); err != nil {
			t.Errorf("%s: the private CA's server was refused: %v", name, err)
		}
		if err := handshake(otherAddr, tlsCfg); !IsUntrustedCertificate(err) {
			t.Errorf("%s: extra_ca_file's CA was trusted under custom_ca: %v", name, err)
		}
	}

	leaf := controlPlaneChainLeaf(t)
	if _, err := leaf.Verify(x509.VerifyOptions{
		DNSName:     "hub.netdefense.io",
		Roots:       cfg.ControlPlaneRoots(),
		CurrentTime: leaf.NotBefore.Add(time.Hour),
	}); err == nil {
		t.Error("the built-in roots still verify the public control-plane chain under custom_ca")
	}
}

// A self-signed server certificate in tls_ca_file is trusted: custom_ca is
// the mode a self-signed NetDefense server needs.
func TestCustomCATrustsASelfSignedServer(t *testing.T) {
	selfSigned := newSelfSignedServer(t)
	dir := trustTestDirs(t, t.TempDir())
	caFile := writeFile(t, dir, "server.pem", selfSigned.certPEM, 0o644)
	cfg := loadedConfig(&Config{TLSMode: TLSModeCustomCA, TLSCAFile: caFile})
	if cfg.TLSError != nil {
		t.Fatal(cfg.TLSError)
	}
	for name, tlsCfg := range controlPlaneConfigs(cfg) {
		if err := handshake(selfSigned.addr, tlsCfg); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// custom_ca without a usable file refuses every connection: it never falls
// back to the built-in roots, which the operator chose not to trust.
func TestCustomCAFailsClosed(t *testing.T) {
	pki := newTestPKI(t, "Private CA")
	addr := startTLSServer(t, pki).Listener.Addr().String()
	dir := trustTestDirs(t, t.TempDir())
	writable := writeFile(t, dir, "writable.pem", pki.caPEM, 0o666)

	for _, c := range []struct{ name, file, reason string }{
		{"no file", "", "tls_mode custom_ca needs tls_ca_file"},
		{"a file the checks refuse", writable, "tls_ca_file " + `"` + writable + `"` + " can be written by its group or by others"},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg := loadedConfig(&Config{TLSMode: TLSModeCustomCA, TLSCAFile: c.file})
			if cfg.TLSError == nil || !strings.Contains(cfg.TLSError.Error(), c.reason) {
				t.Fatalf("TLSError = %v, want it to contain %q", cfg.TLSError, c.reason)
			}
			assertRefusesEveryHandshake(t, cfg, addr)
		})
	}
}

// tls_ca_file is held to every check extra_ca_file is, with the same reasons
// and its own name in them.
func TestCustomCAFileRefusals(t *testing.T) {
	for _, c := range caFileRefusalCases(t) {
		if c.name == "" {
			if cfg := loadedConfig(&Config{TLSMode: TLSModeCustomCA, TLSCAFile: c.path}); cfg.TLSError != nil || len(cfg.TLSCAs) != 1 {
				t.Fatalf("the good file was refused: %v", cfg.TLSError)
			}
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			cfg := loadedConfig(&Config{TLSMode: TLSModeCustomCA, TLSCAFile: c.path})
			if cfg.TLSError == nil {
				t.Fatalf("tls_ca_file %q was accepted", c.path)
			}
			msg := cfg.TLSError.Error()
			if !strings.HasPrefix(msg, "tls_ca_file") || !strings.Contains(msg, c.reason) {
				t.Errorf("refused with %q, want tls_ca_file and a reason containing %q", msg, c.reason)
			}
			if strings.Contains(msg, "NOT-A-REAL-KEY") || strings.Contains(msg, "BEGIN") {
				t.Errorf("the error quotes the file: %v", msg)
			}
			if cfg.TLSCAs != nil || !cfg.ControlPlaneRoots().Equal(x509.NewCertPool()) {
				t.Error("a refused file still added roots")
			}
		})
	}
}

// spki_pinned trusts a server whose own key is pinned, whatever signed its
// certificate, and only then.
func TestSPKIPinnedTrustsOnlyThePinnedKey(t *testing.T) {
	pki := newTestPKI(t, "Unrelated CA")
	leaf, err := x509.ParseCertificate(pki.server.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pki.caPEM)
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	// The server presents its CA's certificate after its own, so a pin of
	// that CA would match a certificate of the chain.
	pki.server.Certificate = append(pki.server.Certificate, ca.Raw)
	addr := startTLSServer(t, pki).Listener.Addr().String()
	other := newTestPKI(t, "Other")
	otherLeaf, err := x509.ParseCertificate(other.server.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name   string
		pins   string
		accept bool
	}{
		{"the server's key", SPKIPin(leaf), true},
		{"a rotation list that holds it second", SPKIPin(otherLeaf) + ", " + SPKIPin(leaf), true},
		{"another key", SPKIPin(otherLeaf), false},
		{"the key of the CA that signed the server's certificate", SPKIPin(ca), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg := loadedConfig(&Config{TLSMode: TLSModeSPKIPinned, TLSSPKIHashes: c.pins})
			if cfg.TLSError != nil {
				t.Fatal(cfg.TLSError)
			}
			for name, tlsCfg := range controlPlaneConfigs(cfg) {
				if tlsCfg.InsecureSkipVerify && tlsCfg.VerifyConnection == nil {
					t.Fatalf("%s: chain verification is off with no pin check", name)
				}
				err := handshake(addr, tlsCfg)
				if c.accept {
					if err != nil {
						t.Errorf("%s: %v", name, err)
					}
					continue
				}
				var mismatch *PinMismatchError
				if !errors.As(err, &mismatch) || mismatch.Presented != SPKIPin(leaf) {
					t.Errorf("%s: err = %v, want a pin mismatch naming %s", name, err, SPKIPin(leaf))
				}
				if !IsUntrustedCertificate(err) {
					t.Errorf("%s: a pin mismatch is not reported as untrusted", name)
				}
			}
		})
	}
}

// The pin replaces chain, hostname and expiry verification: a server whose
// pinned key signs a certificate that expired, for another name, is accepted,
// while custom_ca, which verifies all three, refuses the same certificate.
func TestSPKIPinnedIgnoresExpiryAndName(t *testing.T) {
	srv := newSelfSignedServer(t, func(c *x509.Certificate) {
		c.NotBefore = time.Now().Add(-48 * time.Hour)
		c.NotAfter = time.Now().Add(-24 * time.Hour)
		c.IPAddresses = nil
		c.DNSNames = []string{"elsewhere.test"}
	})
	pinned := loadedConfig(&Config{TLSMode: TLSModeSPKIPinned, TLSSPKIHashes: SPKIPin(srv.cert)})
	for name, tlsCfg := range controlPlaneConfigs(pinned) {
		if err := handshake(srv.addr, tlsCfg); err != nil {
			t.Errorf("%s: the pinned key was refused: %v", name, err)
		}
	}

	dir := trustTestDirs(t, t.TempDir())
	custom := loadedConfig(&Config{TLSMode: TLSModeCustomCA, TLSCAFile: writeFile(t, dir, "server.pem", srv.certPEM, 0o644)})
	if custom.TLSError != nil {
		t.Fatal(custom.TLSError)
	}
	if err := handshake(srv.addr, custom.GetTLSConfig()); err == nil {
		t.Error("custom_ca accepted an expired certificate for another name")
	}
}

// The pin format is the one an operator computes with
//
//	openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
//
// prefixed with sha256/: the value below was computed that way from the
// fixture's leaf.
func TestSPKIPinFormat(t *testing.T) {
	const want = "sha256/BrzGTXN4fCmWPH6H3CtxUF7mljQBNpOFKy5E5kZNPvY="
	if got := SPKIPin(controlPlaneChainLeaf(t)); got != want {
		t.Errorf("SPKIPin = %s, want %s", got, want)
	}
	cfg := loadedConfig(&Config{TLSMode: TLSModeSPKIPinned, TLSSPKIHashes: want})
	if cfg.TLSError != nil || len(cfg.tlsPins) != 1 {
		t.Fatalf("the operator's pin does not parse: %v", cfg.TLSError)
	}
}

func TestSPKIPinsThatDoNotReadFailClosed(t *testing.T) {
	pki := newTestPKI(t, "Pinned")
	addr := startTLSServer(t, pki).Listener.Addr().String()
	leaf, err := x509.ParseCertificate(pki.server.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	good := SPKIPin(leaf)
	short := "sha256/" + base64.StdEncoding.EncodeToString(make([]byte, sha256.Size-1))
	many := strings.Repeat(good+",", maxSPKIPins) + good

	for _, c := range []struct{ name, pins, reason string }{
		{"none", "", "needs tls_spki_hashes"},
		{"only separators", " , ,", "needs tls_spki_hashes"},
		{"no prefix", strings.TrimPrefix(good, "sha256/"), "entry 1 does not start with sha256/"},
		{"curl's double slash", "sha256//" + strings.TrimPrefix(good, "sha256/"), "entry 1 is not the base64"},
		{"a good pin, then one that is not base64", good + ",sha256/not-base64!", "entry 2 is not the base64"},
		{"a hash of the wrong length", short, "entry 1 is not the base64 of a SHA-256 hash"},
		{"too many", many, "at most 16"},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg := loadedConfig(&Config{TLSMode: TLSModeSPKIPinned, TLSSPKIHashes: c.pins})
			if cfg.TLSError == nil || !strings.Contains(cfg.TLSError.Error(), c.reason) {
				t.Fatalf("TLSError = %v, want it to contain %q", cfg.TLSError, c.reason)
			}
			assertRefusesEveryHandshake(t, cfg, addr)
		})
	}

	spaced := loadedConfig(&Config{TLSMode: TLSModeSPKIPinned, TLSSPKIHashes: " " + good + "\t" + good + " ,"})
	if spaced.TLSError != nil || len(spaced.tlsPins) != 2 {
		t.Errorf("pins separated by white space and commas: %v, %d pins", spaced.TLSError, len(spaced.tlsPins))
	}
}

func TestUnknownTLSModeFailsClosed(t *testing.T) {
	pki := newTestPKI(t, "Any")
	addr := startTLSServer(t, pki).Listener.Addr().String()
	cfg, err := Load(createTempConfigFile(t, "enabled=true\ntoken=t\ndevice_uuid=d\ntls_mode=insecure\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TLSError == nil || !strings.Contains(cfg.TLSError.Error(), `tls_mode "insecure" is not one of system, custom_ca, spki_pinned`) {
		t.Fatalf("TLSError = %v", cfg.TLSError)
	}
	assertRefusesEveryHandshake(t, cfg, addr)

	upper := loadedConfig(&Config{TLSMode: " System "})
	if upper.TLSMode != TLSModeSystem || upper.TLSError != nil {
		t.Errorf("a mode in another case: TLSMode = %q, TLSError = %v", upper.TLSMode, upper.TLSError)
	}
}

// A Config built in code for a mode with trust material of its own, and never
// loaded, has nothing to trust: it refuses, rather than reading as system.
func TestUnloadedTrustFailsClosed(t *testing.T) {
	pki := newTestPKI(t, "Pinned")
	addr := startTLSServer(t, pki).Listener.Addr().String()
	leaf, err := x509.ParseCertificate(pki.server.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	assertRefusesEveryHandshake(t, &Config{TLSMode: TLSModeSPKIPinned, TLSSPKIHashes: SPKIPin(leaf)}, addr)
	assertRefusesEveryHandshake(t, &Config{TLSMode: TLSModeCustomCA, TLSCAFile: "/nonexistent"}, addr)
}

// The refusal ERROR names the setting to change under each mode.
func TestReportUntrustedCertificateNamesTheModeSetting(t *testing.T) {
	presented, err := x509.ParseCertificate(newTestPKI(t, "Presented CA").server.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	unknown := &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{Cert: presented}}
	mismatch := &PinMismatchError{Presented: SPKIPin(presented)}

	cases := []struct {
		name   string
		cfg    *Config
		err    error
		option string
		fields map[string]interface{}
	}{
		{"custom_ca", &Config{TLSMode: TLSModeCustomCA, TLSCAFile: "/usr/local/etc/ndagent-ca.pem", tlsLoaded: true, controlPlaneRoots: x509.NewCertPool()},
			unknown, "tls_ca_file", map[string]interface{}{"tls_ca_file": "/usr/local/etc/ndagent-ca.pem", "presented_issuer": "CN=Presented CA"}},
		{"spki_pinned", &Config{TLSMode: TLSModeSPKIPinned, tlsLoaded: true},
			mismatch, "tls_spki_hashes", map[string]interface{}{"presented_spki": SPKIPin(presented)}},
		{"trust that cannot be used", &Config{TLSMode: TLSModeCustomCA, TLSError: errors.New("tls_mode custom_ca needs tls_ca_file"), tlsLoaded: true},
			unknown, "tls_mode", map[string]interface{}{"error": "tls_mode custom_ca needs tls_ca_file"}},
		{"system", &Config{}, unknown, "extra_ca_file", map[string]interface{}{"presented_issuer": "CN=Presented CA"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			untrustedMu.Lock()
			untrustedReported = map[string]time.Time{}
			untrustedMu.Unlock()
			core, logs := observer.New(zapcore.DebugLevel)
			if !c.cfg.ReportUntrustedCertificate(zap.New(core).Sugar(), "wss://hub.example/ws", c.err) {
				t.Fatal("not reported")
			}
			entries := logs.All()
			if len(entries) != 1 || entries[0].Level != zapcore.ErrorLevel {
				t.Fatalf("entries = %+v", entries)
			}
			got := entries[0].ContextMap()
			if got["option"] != c.option {
				t.Errorf("option = %v, want %s", got["option"], c.option)
			}
			for k, v := range c.fields {
				if got[k] != v {
					t.Errorf("%s = %v, want %v", k, got[k], v)
				}
			}
		})
	}
}

// The plugin's TLS Mode dropdown offers exactly the modes the agent reads, and
// its default is the agent's.
func TestPluginOffersTheAgentModes(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "plugin", "src", "usr", "local", "opnsense", "mvc", "app",
		"models", "OPNsense", "NetDefense", "Settings.xml"))
	if err != nil {
		t.Fatal(err)
	}
	var model struct {
		Items struct {
			TLSMode struct {
				Default string `xml:"Default"`
				Options struct {
					Values []struct{ XMLName xml.Name } `xml:",any"`
				} `xml:"OptionValues"`
			} `xml:"tlsMode"`
		} `xml:"items"`
	}
	if err := xml.Unmarshal(data, &model); err != nil {
		t.Fatal(err)
	}
	var offered []string
	for _, v := range model.Items.TLSMode.Options.Values {
		offered = append(offered, v.XMLName.Local)
	}
	if got := strings.Join(offered, ","); got != "system,custom_ca,spki_pinned" {
		t.Errorf("the plugin offers %s", got)
	}
	if model.Items.TLSMode.Default != string(TLSModeSystem) {
		t.Errorf("the plugin's default is %q", model.Items.TLSMode.Default)
	}
	for _, mode := range offered {
		cfg := loadedConfig(&Config{TLSMode: TLSMode(mode)})
		if cfg.TLSError != nil && strings.Contains(cfg.TLSError.Error(), "is not one of") {
			t.Errorf("the agent does not read the plugin's %s", mode)
		}
	}
}
