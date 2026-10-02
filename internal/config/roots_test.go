package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// testPKI is a CA and a server certificate it issued for 127.0.0.1.
type testPKI struct {
	caPEM  []byte
	server tls.Certificate
}

func newTestPKI(t *testing.T, name string) testPKI {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "control.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, ca, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return testPKI{
		caPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		server: tls.Certificate{Certificate: [][]byte{serverDER}, PrivateKey: serverKey},
	}
}

// startTLSServer serves TLS with the PKI's server certificate.
func startTLSServer(t *testing.T, pki testPKI) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pki.server}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func handshake(addr string, cfg *tls.Config) error {
	conn, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		return err
	}
	return conn.Close()
}

func writeFile(t *testing.T, dir, name string, data []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// trustTestDirs lets the test's user stand in for root as the owner of
// extra_ca_file and of the directories above it, up to dir, and returns dir
// with its symbolic links resolved: a test cannot make files root owns, and
// the agent refuses a path that goes through a link.
func trustTestDirs(t *testing.T, dir string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Getuid())
	savedOwner, savedTop := extraCAOwnerTrusted, extraCATop
	extraCAOwnerTrusted = func(owner uint32) bool { return owner == uid }
	extraCATop = resolved
	t.Cleanup(func() { extraCAOwnerTrusted, extraCATop = savedOwner, savedTop })
	return resolved
}

// controlPlaneConfigs are the three TLS configurations of the control plane,
// with verification on.
func controlPlaneConfigs(c *Config) map[string]*tls.Config {
	c.SSLVerify, c.TOFUSSLVerify, c.PathfinderTLSVerify = true, true, true
	return map[string]*tls.Config{
		"GetTLSConfig":           c.GetTLSConfig(),
		"GetTOFUTLSConfig":       c.GetTOFUTLSConfig(),
		"GetPathfinderTLSConfig": c.GetPathfinderTLSConfig(),
	}
}

// A nil RootCAs makes crypto/tls verify against the system bundle, so every
// control-plane configuration must carry the embedded pool.
func TestControlPlaneConfigsCarryTheEmbeddedRoots(t *testing.T) {
	for name, cfg := range controlPlaneConfigs(&Config{}) {
		if cfg.RootCAs == nil {
			t.Fatalf("%s: RootCAs is nil, which means the system bundle", name)
		}
		if !cfg.RootCAs.Equal(embeddedRoots()) {
			t.Errorf("%s: RootCAs is not the embedded root set", name)
		}
		if cfg.InsecureSkipVerify {
			t.Errorf("%s: verification is off", name)
		}
	}

	insecure := &Config{}
	for name, cfg := range map[string]*tls.Config{
		"GetTLSConfig":           insecure.GetTLSConfig(),
		"GetTOFUTLSConfig":       insecure.GetTOFUTLSConfig(),
		"GetPathfinderTLSConfig": insecure.GetPathfinderTLSConfig(),
	} {
		if !cfg.InsecureSkipVerify {
			t.Errorf("%s with its toggle off: verification is on", name)
		}
	}
}

// The control plane's chain as served (captured from hub.netdefense.io: leaf,
// WE1, GTS Root R4 cross-signed by GlobalSign) verifies against the embedded
// set, which carries GTS Root R4.
func TestEmbeddedRootsVerifyTheControlPlaneChain(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "control-plane-chain.pem"))
	if err != nil {
		t.Fatal(err)
	}
	var chain []*x509.Certificate
	for rest := data; ; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, cert)
	}
	if len(chain) < 2 {
		t.Fatalf("the fixture holds %d certificates", len(chain))
	}
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}
	for _, host := range []string{"hub.netdefense.io", "dev-hub.netdefense.io", "qa-hub.netdefense.io", "pathfinder.netdefense.io"} {
		verified, err := chain[0].Verify(x509.VerifyOptions{
			DNSName:       host,
			Roots:         (&Config{}).ControlPlaneRoots(),
			Intermediates: intermediates,
			CurrentTime:   chain[0].NotBefore.Add(time.Hour),
		})
		if err != nil {
			t.Fatalf("%s: the served chain does not verify against the embedded roots: %v", host, err)
		}
		root := verified[0][len(verified[0])-1]
		if root.Subject.CommonName != "GTS Root R4" {
			t.Errorf("%s: verified to %q, want GTS Root R4", host, root.Subject.CommonName)
		}
	}
}

// systemBundleHelperEnv makes the test binary act as the helper process of
// TestSystemBundleCAIsNotTrusted.
const systemBundleHelperEnv = "NDAGENT_SYSTEM_BUNDLE_HELPER"

// A CA in the system bundle, and only there, is not trusted by the control-plane
// connections. The system bundle is read once per process, so the check runs in
// a child process whose bundle is exactly the test CA (SSL_CERT_FILE, with an
// empty SSL_CERT_DIR). The child first proves the CA is trusted through the
// system bundle, then that each control-plane configuration refuses it. Go
// reads SSL_CERT_FILE on Linux and FreeBSD, where the test must run; elsewhere
// (macOS, Windows) the platform verifier owns the system roots and the test is
// skipped.
func TestSystemBundleCAIsNotTrusted(t *testing.T) {
	if os.Getenv(systemBundleHelperEnv) != "" {
		t.Skip("running as the helper")
	}
	if runtime.GOOS != "linux" && runtime.GOOS != "freebsd" {
		t.Skipf("Go does not read SSL_CERT_FILE on %s", runtime.GOOS)
	}
	pki := newTestPKI(t, "System Bundle Only CA")
	srv := startTLSServer(t, pki)
	dir := t.TempDir()
	bundle := writeFile(t, dir, "bundle.pem", pki.caPEM, 0o644)

	cmd := exec.Command(os.Args[0], "-test.run=^TestSystemBundleHelper$", "-test.v")
	cmd.Env = append(os.Environ(),
		systemBundleHelperEnv+"="+srv.Listener.Addr().String(),
		"SSL_CERT_FILE="+bundle,
		"SSL_CERT_DIR="+t.TempDir(),
	)
	out, err := cmd.CombinedOutput()
	switch {
	case strings.Contains(string(out), "SYSTEM-BUNDLE-UNAVAILABLE"):
		t.Fatalf("the test CA did not reach the system bundle, so nothing was proved:\n%s", out)
	case err != nil:
		t.Fatalf("helper failed: %v\n%s", err, out)
	case !strings.Contains(string(out), "CONTROL-PLANE-REFUSED"):
		t.Fatalf("helper did not report its result:\n%s", out)
	}
}

// TestSystemBundleHelper is the child process of TestSystemBundleCAIsNotTrusted.
func TestSystemBundleHelper(t *testing.T) {
	addr := os.Getenv(systemBundleHelperEnv)
	if addr == "" {
		t.Skip("only runs as the helper of TestSystemBundleCAIsNotTrusted")
	}
	if err := handshake(addr, &tls.Config{MinVersion: tls.VersionTLS12}); err != nil {
		fmt.Println("SYSTEM-BUNDLE-UNAVAILABLE:", err)
		return
	}
	for name, cfg := range controlPlaneConfigs(&Config{}) {
		err := handshake(addr, cfg)
		if err == nil {
			t.Fatalf("%s trusted a CA that is only in the system bundle", name)
		}
		if !IsUntrustedCertificate(err) {
			t.Fatalf("%s: handshake failed for another reason: %v", name, err)
		}
	}
	fmt.Println("CONTROL-PLANE-REFUSED")
}

// A CA in extra_ca_file is trusted by every control-plane configuration, and
// without the file the same server is refused as untrusted.
func TestExtraCAFileIsTrusted(t *testing.T) {
	pki := newTestPKI(t, "Inspection Proxy CA")
	srv := startTLSServer(t, pki)
	addr := srv.Listener.Addr().String()

	for name, cfg := range controlPlaneConfigs(&Config{}) {
		err := handshake(addr, cfg)
		if !IsUntrustedCertificate(err) {
			t.Errorf("%s without extra_ca_file: err = %v, want an untrusted certificate", name, err)
		}
		// The ERROR names the certificate the handshake was shown.
		var unknown x509.UnknownAuthorityError
		if errors.As(err, &unknown) && (unknown.Cert == nil || unknown.Cert.Issuer.CommonName != "Inspection Proxy CA") {
			t.Errorf("%s: the failed handshake does not carry the presented certificate", name)
		}
	}

	dir := trustTestDirs(t, t.TempDir())
	caFile := writeFile(t, dir, "proxy-ca.pem", append([]byte("# inspection proxy\n"), pki.caPEM...), 0o644)
	cfg, err := Load(createTempConfigFile(t, "enabled=true\ntoken=t\ndevice_uuid=d\nextra_ca_file="+caFile+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ExtraCAError != nil {
		t.Fatalf("ExtraCAError = %v", cfg.ExtraCAError)
	}
	if len(cfg.ExtraCAs) != 1 || cfg.ExtraCAs[0].Subject != "CN=Inspection Proxy CA" || len(cfg.ExtraCAs[0].SHA256) != 64 {
		t.Errorf("ExtraCAs = %+v", cfg.ExtraCAs)
	}
	for name, tlsCfg := range controlPlaneConfigs(cfg) {
		if err := handshake(addr, tlsCfg); err != nil {
			t.Errorf("%s with extra_ca_file: %v", name, err)
		}
	}
}

// assertExtraCARefused fails unless extra_ca_file at path is refused for the
// reason want names, without quoting the file and without adding a root.
func assertExtraCARefused(t *testing.T, path, want string) {
	t.Helper()
	cfg := &Config{ExtraCAFile: path}
	done := make(chan struct{})
	go func() {
		defer close(done)
		cfg.loadControlPlaneRoots()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("loading extra_ca_file %q did not return", path)
	}
	if cfg.ExtraCAError == nil {
		t.Fatalf("extra_ca_file %q was accepted", path)
	}
	if !strings.Contains(cfg.ExtraCAError.Error(), want) {
		t.Errorf("refused with %q, want a reason containing %q", cfg.ExtraCAError, want)
	}
	if strings.Contains(cfg.ExtraCAError.Error(), "NOT-A-REAL-KEY") || strings.Contains(cfg.ExtraCAError.Error(), "BEGIN") {
		t.Errorf("the error quotes the file: %v", cfg.ExtraCAError)
	}
	if cfg.ExtraCAs != nil || cfg.controlPlaneRoots != nil {
		t.Errorf("a refused file still added roots")
	}
	if !cfg.ControlPlaneRoots().Equal(embeddedRoots()) {
		t.Error("a refused file changed the roots")
	}
}

func TestExtraCAFileRefusals(t *testing.T) {
	pki := newTestPKI(t, "Refused CA")
	dir := trustTestDirs(t, t.TempDir())
	trustDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	saved := systemTrustDirs
	systemTrustDirs = []string{trustDir}
	t.Cleanup(func() { systemTrustDirs = saved })

	keyBlock := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("NOT-A-REAL-KEY-MATERIAL")})
	inTrustDir := writeFile(t, trustDir, "cert.pem", pki.caPEM, 0o644)
	good := writeFile(t, dir, "good.pem", pki.caPEM, 0o644)
	symlink := func(target, name string) string {
		link := filepath.Join(dir, name)
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		return link
	}
	linked := writeFile(t, dir, "linked.pem", pki.caPEM, 0o644)
	if err := os.Link(linked, filepath.Join(dir, "second-name.pem")); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo.pem")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	open := filepath.Join(dir, "open")
	if err := os.Mkdir(open, 0o755); err != nil {
		t.Fatal(err)
	}
	inOpen := writeFile(t, open, "ca.pem", pki.caPEM, 0o644)
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(dir, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, real, "ca.pem", pki.caPEM, 0o644)
	symlink(real, "alias")

	cases := []struct{ name, path, reason string }{
		{"a relative path", "ca.pem", "not an absolute path"},
		{"a file that is missing", filepath.Join(dir, "missing.pem"), "no such file"},
		{"a directory", dir, "not a regular file"},
		{"a FIFO", fifo, "not a regular file"},
		{"a writable file", writeFile(t, dir, "writable.pem", pki.caPEM, 0o666), "can be written by its group or by others"},
		{"a second link to the file", linked, "has 2 links"},
		{"a directory others can write", inOpen, "which its group or others can write"},
		{"a link to a good file", symlink(good, "link.pem"), "symbolic link"},
		{"a link to a directory on the path", filepath.Join(dir, "alias", "ca.pem"), "symbolic link"},
		{"the system certificate store", inTrustDir, "system certificate store"},
		{"a link into the store", symlink(inTrustDir, "store-link.pem"), "symbolic link"},
		{"a private key", writeFile(t, dir, "key.pem", append(append([]byte{}, pki.caPEM...), keyBlock...), 0o600), "not a CERTIFICATE"},
		{"no certificate", writeFile(t, dir, "empty.pem", []byte("nothing here\n"), 0o644), "no PEM CERTIFICATE block"},
		{"a certificate that does not parse", writeFile(t, dir, "bad.pem",
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")}), 0o644), "does not parse"},
		{"a file larger than the bound", writeFile(t, dir, "large.pem", append(append([]byte{}, pki.caPEM...), make([]byte, extraCAFileMaxBytes)...), 0o644), "larger than"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertExtraCARefused(t, c.path, c.reason)
		})
	}

	// The file the cases above refuse for other reasons is accepted as it is.
	cfg := &Config{ExtraCAFile: good}
	cfg.loadControlPlaneRoots()
	if cfg.ExtraCAError != nil || len(cfg.ExtraCAs) != 1 {
		t.Fatalf("the good file was refused: %v", cfg.ExtraCAError)
	}
}

// A file or a directory above it that is not root's is refused: whoever owns
// it can replace what the agent reads.
func TestExtraCAFileOwners(t *testing.T) {
	pki := newTestPKI(t, "Owned CA")
	dir := trustTestDirs(t, t.TempDir())
	file := writeFile(t, dir, "ca.pem", pki.caPEM, 0o644)

	t.Run("a file someone else owns", func(t *testing.T) {
		saved := extraCAOwnerTrusted
		extraCAOwnerTrusted = func(uint32) bool { return false }
		t.Cleanup(func() { extraCAOwnerTrusted = saved })
		assertExtraCARefused(t, file, "it must be root's")
	})

	t.Run("a directory someone else owns", func(t *testing.T) {
		if os.Getuid() == 0 {
			t.Skip("as root, every directory above the test's is root's too")
		}
		saved := extraCATop
		extraCATop = "/"
		t.Cleanup(func() { extraCATop = saved })
		// Above the test's own directories is one root owns, which the test's
		// user, standing in for root, does not.
		assertExtraCARefused(t, file, "every directory above the file must be root's")
	})
}

func TestReportUntrustedCertificate(t *testing.T) {
	untrustedMu.Lock()
	untrustedReported = map[string]time.Time{}
	untrustedMu.Unlock()

	core, logs := observer.New(zapcore.DebugLevel)
	log := zap.New(core).Sugar()
	cfg := &Config{ExtraCAFile: "/usr/local/etc/ndagent-ca.pem"}
	untrusted := &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}
	wrapped := fmt.Errorf("websocket dial failed: %w", untrusted)

	if !cfg.ReportUntrustedCertificate(log, "wss://hub.example/ws", wrapped) {
		t.Fatal("an unknown authority was not reported")
	}
	if !cfg.ReportUntrustedCertificate(log, "wss://hub.example/ws", wrapped) {
		t.Fatal("the second failure was not recognized")
	}
	if cfg.ReportUntrustedCertificate(log, "wss://hub.example/ws", errors.New("connection refused")) {
		t.Fatal("a refused connection was reported as an untrusted certificate")
	}
	if cfg.ReportUntrustedCertificate(log, "wss://hub.example/ws", x509.HostnameError{}) {
		t.Fatal("a name mismatch was reported as an untrusted certificate")
	}
	cfg.ReportUntrustedCertificate(log, "https://pathfinder.example", untrusted)

	// A handshake names the certificate it was shown, so the operator can
	// tell which CA to save.
	presented, err := x509.ParseCertificate(newTestPKI(t, "Inspection Proxy CA").server.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(presented.Raw)
	cfg.ReportUntrustedCertificate(log, "https://control.example", &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{Cert: presented}})

	entries := logs.All()
	if len(entries) != 3 {
		t.Fatalf("logged %d entries, want one per endpoint: %+v", len(entries), entries)
	}
	for i, e := range entries {
		fields := e.ContextMap()
		if e.Level != zapcore.ErrorLevel || !strings.Contains(e.Message, "extra_ca_file") {
			t.Errorf("entry %q at %s does not name extra_ca_file as an ERROR", e.Message, e.Level)
		}
		if fields["option"] != "extra_ca_file" || fields["extra_ca_file"] != cfg.ExtraCAFile {
			t.Errorf("entry fields = %v", fields)
		}
		_, issuer := fields["presented_issuer"]
		_, digest := fields["presented_sha256"]
		if i < 2 && (issuer || digest) {
			t.Errorf("an error without a certificate logged one: %v", fields)
		}
	}
	fields := entries[2].ContextMap()
	if fields["presented_issuer"] != "CN=Inspection Proxy CA" || fields["presented_sha256"] != hex.EncodeToString(sum[:]) {
		t.Errorf("the presented certificate is not named: %v", fields)
	}
}
