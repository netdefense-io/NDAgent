package config

// Control-plane roots.
//
// The agent verifies the control plane (registration and the broker socket,
// the trust-key fetch, the relay) against a root set built into the binary,
// never against the operating system's bundle. The firewall's certificate
// store is configuration that NetDefense itself can change: a CA synced to
// the device lands in the system bundle, and an agent anchored on that bundle
// could be pointed at an impostor by whoever controls the sync. A site whose
// traffic passes a TLS-inspection proxy adds the proxy's CA with
// extra_ca_file, a local file no sync writes: it is set by someone with a
// shell on the device, or through an administrator's session to it.

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/x509roots/fallback/bundle"
)

// embeddedRoots is the Mozilla root set the binary carries
// (golang.org/x/crypto/x509roots/fallback/bundle), refreshed with each agent
// release. A root the set constrains (distrusted after a date) keeps its
// constraint.
var embeddedRoots = sync.OnceValue(func() *x509.CertPool {
	pool := x509.NewCertPool()
	for root := range bundle.Roots() {
		cert, err := x509.ParseCertificate(root.Certificate)
		if err != nil {
			panic(fmt.Sprintf("embedded root does not parse: %v", err))
		}
		if root.Constraint == nil {
			pool.AddCert(cert)
		} else {
			pool.AddCertWithConstraint(cert, root.Constraint)
		}
	}
	return pool
})

// ExtraCA describes one certificate extra_ca_file or tls_ca_file added, for the
// startup log.
type ExtraCA struct {
	Subject  string
	SHA256   string
	NotAfter time.Time
}

// extraCAFileMaxBytes bounds the read of extra_ca_file; a CA bundle is a few
// KiB.
const extraCAFileMaxBytes = 1 << 20

// extraCAOwnerTrusted reports whether a uid may own extra_ca_file and the
// directories above it: root alone. Tests, which cannot make files root owns,
// replace it.
var extraCAOwnerTrusted = func(uid uint32) bool { return uid == 0 }

// extraCATop is where the check of the directories above extra_ca_file stops.
var extraCATop = "/"

// systemTrustDirs hold the operating system's certificate bundle, which the
// firewall's certificate store feeds, synced CAs included. extra_ca_file may
// not point into them: the agent would be anchored on that store after all.
var systemTrustDirs = []string{
	"/etc/ssl",
	"/usr/local/etc/ssl",
	"/usr/local/share/certs",
	"/usr/share/certs",
	"/usr/local/openssl",
}

// ControlPlaneRoots returns the roots the control-plane connections verify
// against: under tls_mode system the built-in set, plus the CAs of
// extra_ca_file when it loaded; under custom_ca the CAs of tls_ca_file alone.
// Never nil, because a nil RootCAs means the system bundle, and empty when the
// mode has no roots to trust.
func (c *Config) ControlPlaneRoots() *x509.CertPool {
	if c.controlPlaneRoots != nil {
		return c.controlPlaneRoots
	}
	if c.isSystemMode() {
		return embeddedRoots()
	}
	return x509.NewCertPool()
}

// loadControlPlaneRoots adds the CAs of extra_ca_file to the built-in roots.
// A file that cannot be used is reported in ExtraCAError and leaves the
// built-in roots alone: refusing to start would take the device off the
// control plane, while the built-in roots still reach it from any site
// without an inspection proxy.
func (c *Config) loadControlPlaneRoots() {
	c.ExtraCAFile = strings.TrimSpace(c.ExtraCAFile)
	if c.ExtraCAFile == "" {
		return
	}
	certs, err := loadExtraCAs(c.ExtraCAFile)
	if err != nil {
		c.ExtraCAError = err
		return
	}
	pool := embeddedRoots().Clone()
	for _, cert := range certs {
		pool.AddCert(cert)
		c.ExtraCAs = append(c.ExtraCAs, describeCA(cert))
	}
	c.controlPlaneRoots = pool
}

func describeCA(cert *x509.Certificate) ExtraCA {
	sum := sha256.Sum256(cert.Raw)
	return ExtraCA{
		Subject:  cert.Subject.String(),
		SHA256:   hex.EncodeToString(sum[:]),
		NotAfter: cert.NotAfter,
	}
}

// loadExtraCAs reads extra_ca_file; see loadCAFile.
func loadExtraCAs(path string) ([]*x509.Certificate, error) {
	return loadCAFile("extra_ca_file", path)
}

// loadCAFile reads the CA file the setting option names (extra_ca_file, or
// tls_ca_file for tls_mode=custom_ca): one or more PEM CERTIFICATE blocks and no
// other PEM block. Text around the blocks is ignored. Only root may have put it
// there: the path names the file itself, not a link to it, outside
// systemTrustDirs; the file is a regular file root owns, with one link, that
// neither its group nor others can write; and every directory above it is
// root's and writable by root alone, as sshd's StrictModes requires, since
// whoever can write a directory on the path can put a file of their own at
// it. The file is opened once, without following a link or waiting on a FIFO,
// the checks are made on the open file, and the read is bounded, so what is
// read is what was checked.
func loadCAFile(option, path string) ([]*x509.Certificate, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("%s %q is not an absolute path", option, path)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", option, err)
	}
	if resolved != filepath.Clean(path) {
		return nil, fmt.Errorf("%s %q goes through a symbolic link to %q; set the path of the file itself", option, path, resolved)
	}
	for _, dir := range systemTrustDirs {
		if inDir(resolved, dir) {
			return nil, fmt.Errorf("%s %q is in %s, the system certificate store that the firewall's certificates feed; use a file of its own", option, path, dir)
		}
	}

	f, err := os.OpenFile(resolved, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", option, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", option, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s %q is not a regular file", option, path)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	switch {
	case !ok:
		return nil, fmt.Errorf("%s %q: its owner cannot be read", option, path)
	case !extraCAOwnerTrusted(st.Uid):
		return nil, fmt.Errorf("%s %q is owned by uid %d; it must be root's", option, path, st.Uid)
	case uint64(st.Nlink) != 1:
		return nil, fmt.Errorf("%s %q has %d links; it must have one, or another file could be read under its name", option, path, st.Nlink)
	case info.Mode().Perm()&0o022 != 0:
		return nil, fmt.Errorf("%s %q can be written by its group or by others (mode %04o)", option, path, info.Mode().Perm())
	case info.Size() > extraCAFileMaxBytes:
		return nil, fmt.Errorf("%s %q is larger than %d bytes", option, path, extraCAFileMaxBytes)
	}
	if err := checkExtraCADirs(option, path, filepath.Dir(resolved)); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, extraCAFileMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", option, err)
	}
	if len(data) > extraCAFileMaxBytes {
		return nil, fmt.Errorf("%s %q is larger than %d bytes", option, path, extraCAFileMaxBytes)
	}

	var certs []*x509.Certificate
	for rest := data; ; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("%s %q holds a PEM block that is not a CERTIFICATE", option, path)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s %q: certificate %d does not parse", option, path, len(certs)+1)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("%s %q holds no PEM CERTIFICATE block", option, path)
	}
	return certs, nil
}

// checkExtraCADirs requires dir and every directory above it, up to
// extraCATop, to be owned by root and writable by no one else.
func checkExtraCADirs(option, path, dir string) error {
	for {
		info, err := os.Lstat(dir)
		if err != nil {
			return fmt.Errorf("%s: %w", option, err)
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		switch {
		case !ok:
			return fmt.Errorf("%s %q: the owner of %s cannot be read", option, path, dir)
		case !info.IsDir():
			return fmt.Errorf("%s %q: %s is not a directory", option, path, dir)
		case !extraCAOwnerTrusted(st.Uid):
			return fmt.Errorf("%s %q is in %s, which uid %d owns; every directory above the file must be root's", option, path, dir, st.Uid)
		case info.Mode().Perm()&0o022 != 0:
			return fmt.Errorf("%s %q is in %s, which its group or others can write (mode %04o)", option, path, dir, info.Mode().Perm())
		}
		parent := filepath.Dir(dir)
		if dir == extraCATop || parent == dir {
			return nil
		}
		dir = parent
	}
}

// inDir reports whether path is dir or below it, comparing against dir as
// written and as its symlinks resolve.
func inDir(path, dir string) bool {
	dirs := []string{dir}
	if resolved, err := filepath.EvalSymlinks(dir); err == nil && resolved != dir {
		dirs = append(dirs, resolved)
	}
	for _, d := range dirs {
		if path == d || strings.HasPrefix(path, d+"/") {
			return true
		}
	}
	return false
}

// IsUntrustedCertificate reports whether err is a TLS handshake that failed
// because the server's certificate does not chain to a root the agent trusts,
// or, under tls_mode=spki_pinned, because its key is not pinned.
func IsUntrustedCertificate(err error) bool {
	var unknown x509.UnknownAuthorityError
	var pin *PinMismatchError
	return errors.As(err, &unknown) || errors.As(err, &pin)
}

// untrustedReportEvery spaces the hint per endpoint, so a reconnect loop does
// not log it on every attempt.
const untrustedReportEvery = 10 * time.Minute

var (
	untrustedMu       sync.Mutex
	untrustedReported = map[string]time.Time{}
)

// ReportUntrustedCertificate logs an actionable ERROR naming the setting to
// change when err is a handshake with endpoint that the trust of tls_mode
// refused, at most once per untrustedReportEvery per endpoint. It reports
// whether err was such a failure.
func (c *Config) ReportUntrustedCertificate(log *zap.SugaredLogger, endpoint string, err error) bool {
	if !IsUntrustedCertificate(err) {
		return false
	}
	untrustedMu.Lock()
	due := time.Since(untrustedReported[endpoint]) >= untrustedReportEvery
	if due {
		untrustedReported[endpoint] = time.Now()
	}
	untrustedMu.Unlock()
	if !due {
		return true
	}

	fields := []interface{}{"endpoint", endpoint}
	var unknown x509.UnknownAuthorityError
	if errors.As(err, &unknown) && unknown.Cert != nil {
		sum := sha256.Sum256(unknown.Cert.Raw)
		fields = append(fields,
			"presented_issuer", unknown.Cert.Issuer.String(),
			"presented_sha256", hex.EncodeToString(sum[:]),
		)
	}
	switch {
	case c.TLSError != nil || (!c.tlsLoaded && !c.isSystemMode()):
		reason := "its trust material was not loaded"
		if c.TLSError != nil {
			reason = c.TLSError.Error()
		}
		log.Errorw("Every connection to NetDefense is refused: the trust material of TLS Mode cannot be used ("+reason+"). "+
			"Fix the setting named in error (NetDefense settings, Advanced, Control Plane), then apply",
			append(fields, "option", "tls_mode", "tls_mode", string(c.TLSMode), "error", reason)...,
		)
	case c.TLSMode == TLSModeSPKIPinned:
		var pin *PinMismatchError
		if errors.As(err, &pin) && pin.Presented != "" {
			fields = append(fields, "presented_spki", pin.Presented)
		}
		log.Errorw("The control plane's public key is not one of the pinned keys. "+
			"Under TLS Mode spki_pinned the agent trusts only the keys tls_spki_hashes lists. "+
			"If the server's key changed on purpose, add presented_spki (once you have checked it is your server's) "+
			"to SPKI Hashes (NetDefense settings, Advanced, Control Plane), then apply",
			append(fields, "option", "tls_spki_hashes")...,
		)
	case c.TLSMode == TLSModeCustomCA:
		log.Errorw("The control plane's TLS certificate is not signed by a CA in tls_ca_file. "+
			"Under TLS Mode custom_ca the agent trusts only the CAs of that file. "+
			"Save the CA that issued the NetDefense server's certificate "+
			"(presented_issuer names the CA that signed the certificate presented) "+
			"in CA File (NetDefense settings, Advanced, Control Plane), then apply",
			append(fields, "option", "tls_ca_file", "tls_ca_file", c.TLSCAFile)...,
		)
	default:
		log.Errorw("The control plane's TLS certificate is not signed by a root this agent trusts. "+
			"The agent trusts only its built-in public roots, never the firewall's certificate store. "+
			"If this firewall reaches the internet through a TLS-inspection proxy, save the proxy's CA certificate "+
			"(presented_issuer names the CA that signed the certificate presented) "+
			"as a PEM file on the firewall and set extra_ca_file to its path "+
			"(NetDefense settings, Advanced, Control Plane: Extra CA File), then restart the agent. "+
			"A NetDefense server with a private CA needs TLS Mode custom_ca instead",
			append(fields, "option", "extra_ca_file", "extra_ca_file", c.ExtraCAFile)...,
		)
	}
	return true
}
