package config

// TLS modes of the control-plane connections.
//
// tls_mode picks what the connections to NetDefense (registration and the
// broker socket, the trust-key fetch, the relay) verify the server against:
//
//	system       the root set built into the agent plus extra_ca_file, never
//	             the operating system's store (see roots.go); the default
//	custom_ca    only the CAs of tls_ca_file, for a NetDefense server whose
//	             certificate a private CA issued
//	spki_pinned  only the public keys tls_spki_hashes lists: the server's
//	             own key must be one of them, whatever signed its certificate
//
// Trust material a mode cannot use refuses every control-plane connection: it
// never falls back to another mode, and never to no verification. ssl_verify,
// tofu_ssl_verify and pathfinder_tls_verify no longer turn verification off;
// they are read only to say so.

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

// TLSMode is what the control-plane connections verify the server against.
type TLSMode string

const (
	TLSModeSystem     TLSMode = "system"
	TLSModeCustomCA   TLSMode = "custom_ca"
	TLSModeSPKIPinned TLSMode = "spki_pinned"
)

// spkiPinPrefix starts every tls_spki_hashes entry: the base64 of the SHA-256
// of the key's DER SubjectPublicKeyInfo follows it.
const spkiPinPrefix = "sha256/"

// maxSPKIPins bounds tls_spki_hashes; a key rotation needs two or three.
const maxSPKIPins = 16

// PinMismatchError is a handshake refused under tls_mode=spki_pinned because
// the server's public key is not one tls_spki_hashes lists.
type PinMismatchError struct {
	// Presented is the server's key in the tls_spki_hashes form, empty when
	// the server presented no certificate.
	Presented string
}

func (e *PinMismatchError) Error() string {
	if e.Presented == "" {
		return "the server presented no certificate, so its key cannot match tls_spki_hashes"
	}
	return fmt.Sprintf("the server's public key %s is not one of tls_spki_hashes", e.Presented)
}

// LoadControlPlaneTrust reads the trust material of tls_mode. Load calls it;
// a Config built in code for any mode but system must call it too, or its
// control-plane connections are refused.
func (c *Config) LoadControlPlaneTrust() {
	c.TLSError, c.TLSCAs, c.tlsPins, c.controlPlaneRoots = nil, nil, nil, nil
	c.ExtraCAs, c.ExtraCAError = nil, nil
	c.tlsLoaded = true

	raw := strings.TrimSpace(string(c.TLSMode))
	c.TLSMode = TLSMode(strings.ToLower(raw))
	if c.TLSMode == "" {
		c.TLSMode = TLSModeSystem
	}
	c.TLSCAFile = strings.TrimSpace(c.TLSCAFile)
	c.ExtraCAFile = strings.TrimSpace(c.ExtraCAFile)

	switch c.TLSMode {
	case TLSModeSystem:
		c.loadControlPlaneRoots()
	case TLSModeCustomCA:
		c.loadCustomCA()
	case TLSModeSPKIPinned:
		c.tlsPins, c.TLSError = parseSPKIPins(c.TLSSPKIHashes)
	default:
		c.TLSError = fmt.Errorf("tls_mode %q is not one of system, custom_ca, spki_pinned", raw)
	}
}

// loadCustomCA makes the CAs of tls_ca_file the only roots.
func (c *Config) loadCustomCA() {
	if c.TLSCAFile == "" {
		c.TLSError = errors.New("tls_mode custom_ca needs tls_ca_file, the PEM file of the CA that issued the NetDefense server's certificate")
		return
	}
	certs, err := loadCAFile("tls_ca_file", c.TLSCAFile)
	if err != nil {
		c.TLSError = err
		return
	}
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
		c.TLSCAs = append(c.TLSCAs, describeCA(cert))
	}
	c.controlPlaneRoots = pool
}

// parseSPKIPins reads tls_spki_hashes: entries separated by commas or white
// space, each sha256/ and the standard base64 of a SHA-256 hash. One entry
// that does not read refuses them all, so a mistyped pin is fixed rather than
// half applied.
func parseSPKIPins(raw string) ([][sha256.Size]byte, error) {
	entries := strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || unicode.IsSpace(r) })
	if len(entries) == 0 {
		return nil, errors.New("tls_mode spki_pinned needs tls_spki_hashes, the sha256/ hashes of the server keys to trust")
	}
	if len(entries) > maxSPKIPins {
		return nil, fmt.Errorf("tls_spki_hashes lists %d keys; at most %d are read", len(entries), maxSPKIPins)
	}
	pins := make([][sha256.Size]byte, 0, len(entries))
	for i, entry := range entries {
		encoded, ok := strings.CutPrefix(entry, spkiPinPrefix)
		if !ok {
			return nil, fmt.Errorf("tls_spki_hashes entry %d does not start with %s", i+1, spkiPinPrefix)
		}
		sum, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil || len(sum) != sha256.Size {
			return nil, fmt.Errorf("tls_spki_hashes entry %d is not the base64 of a SHA-256 hash", i+1)
		}
		pins = append(pins, [sha256.Size]byte(sum))
	}
	return pins, nil
}

// SPKIPin is a certificate's public key in the tls_spki_hashes form.
func SPKIPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return spkiPinPrefix + base64.StdEncoding.EncodeToString(sum[:])
}

// verifyPinned accepts a server whose own key, the leaf's, is pinned. Only
// the leaf counts: chain verification is off in this mode, so a pinned CA
// certificate in the presented chain proves nothing. The handshake has proved
// that the server holds the leaf's private key.
func verifyPinned(pins [][sha256.Size]byte) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return &PinMismatchError{}
		}
		leaf := cs.PeerCertificates[0]
		sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
		for _, pin := range pins {
			if sum == pin {
				return nil
			}
		}
		return &PinMismatchError{Presented: SPKIPin(leaf)}
	}
}

// controlPlaneTLSConfig is the TLS configuration of every control-plane
// connection, under tls_mode.
func (c *Config) controlPlaneTLSConfig() *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	switch {
	case c.TLSError != nil || (!c.tlsLoaded && !c.isSystemMode()):
		// An empty pool, never nil (the system bundle): every chain fails.
		cfg.RootCAs = x509.NewCertPool()
	case c.TLSMode == TLSModeSPKIPinned:
		// The pin check replaces chain verification; it runs on every
		// handshake, resumptions included.
		cfg.RootCAs = x509.NewCertPool()
		cfg.InsecureSkipVerify = true
		cfg.VerifyConnection = verifyPinned(c.tlsPins)
	default:
		cfg.RootCAs = c.ControlPlaneRoots()
	}
	return cfg
}

func (c *Config) isSystemMode() bool {
	return c.TLSMode == "" || c.TLSMode == TLSModeSystem
}

// ExtraCAFileIgnored reports whether extra_ca_file is set under a mode that
// does not read it.
func (c *Config) ExtraCAFileIgnored() bool {
	return strings.TrimSpace(c.ExtraCAFile) != "" && !c.isSystemMode()
}

// ignoredVerifyKeys are the settings that once turned verification off, in
// the order they are named, with the plugin's label for each.
var ignoredVerifyKeys = []string{"ssl_verify", "tofu_ssl_verify", "pathfinder_tls_verify"}

var ignoredVerifyLabels = map[string]string{
	"ssl_verify":            "SSL Verification",
	"tofu_ssl_verify":       "TOFU Key Fetch SSL Verification",
	"pathfinder_tls_verify": "Pathfinder SSL Verification",
}

// IgnoredVerifyKeys names the settings the configuration turns off that no
// longer turn verification off.
func (c *Config) IgnoredVerifyKeys() []string {
	return append([]string(nil), c.ignoredVerify...)
}

// IgnoredVerifyNotice is the sentence a task result carries while a setting
// that once turned verification off is off; empty while none is.
func (c *Config) IgnoredVerifyNotice() string {
	off := c.ignoredVerify
	if len(off) == 0 {
		return ""
	}
	names := make([]string, len(off))
	for i, key := range off {
		names[i] = fmt.Sprintf("%s (%s=false)", ignoredVerifyLabels[key], key)
	}
	verb := "is"
	if len(off) > 1 {
		verb = "are"
	}
	mode := c.TLSMode
	if mode == "" {
		mode = TLSModeSystem
	}
	return fmt.Sprintf("Note: %s %s off in this firewall's NetDefense settings and no longer honoured; "+
		"its connections to NetDefense are verified under TLS Mode %s. "+
		"For a NetDefense server with a private CA, set TLS Mode to custom_ca.",
		joinNames(names), verb, mode)
}

// ignoredVerifyMarker is in every IgnoredVerifyNotice, whatever it names.
const ignoredVerifyMarker = " off in this firewall's NetDefense settings and no longer honoured; "

// CarriesIgnoredVerifyNotice reports whether message already carries an
// IgnoredVerifyNotice, of this configuration or of the one a stored result was
// written under.
func CarriesIgnoredVerifyNotice(message string) bool {
	return strings.Contains(message, ignoredVerifyMarker)
}

func joinNames(names []string) string {
	switch len(names) {
	case 1:
		return names[0]
	case 2:
		return names[0] + " and " + names[1]
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}
