// Package pkgrepo manages the pkg(8) repository configuration a
// SoftwarePolicy declares.
//
// Repository identity in pkg(8) lives in the UCL KEY inside the file
// (`mimugmail: { … }`), not in the filename. Two files under
// /usr/local/etc/pkg/repos/ that both define `mimugmail` give pkg two live
// definitions, resolved by file read order — which is exactly the
// "same repository twice with different parameters" state this feature
// exists to prevent. Everything here follows from that fact:
//
//   - We write into a prefixed namespace (netdefense-<name>.conf) so we never
//     clobber a file an administrator wrote by hand.
//   - Every file we own carries a marker on its first line, so deletion can be
//     confined to files we created.
//   - Before writing anything, the caller scans for a foreign file defining a
//     name we manage and fails the task rather than adding a second definition
//     (see scan.go).
//
// OPNsense's own reconcile only rewrites OPNsense.conf, OPNsense-aux.conf and
// FreeBSD.conf (verified in /usr/local/opnsense/scripts/firmware/repos/OPNsense.php),
// so our prefixed files are not at risk from a firmware settings change.
package pkgrepo

import (
	"bytes"
	"fmt"
	"strings"
)

// ManagedMarker is the first line of every file this package writes. Deletion
// during reconcile is confined to files carrying it, so an administrator's own
// config is never removed by us.
const ManagedMarker = "# Managed by NetDefense. Do not edit; changes are overwritten."

// filePrefix namespaces everything we own. It exists so a hand-written
// mimugmail.conf and our netdefense-mimugmail.conf can be told apart on sight.
const filePrefix = "netdefense-"

// Device paths. Variables rather than constants purely so tests can retarget
// them at a temp directory — production never reassigns them. See testing.go.
var (
	reposDir       = "/usr/local/etc/pkg/repos"
	fingerprintsIn = "/usr/local/etc/pkg/fingerprints"
	keysDir        = "/usr/local/etc/pkg/keys"
)

// SignatureType mirrors pkg.conf(5)'s SIGNATURE_TYPE. pkg defaults this to
// NONE when absent, which is why the policy schema requires it to be declared
// explicitly — silence would otherwise mean "unverified".
type SignatureType string

const (
	SignatureFingerprints SignatureType = "fingerprints"
	SignaturePubkey       SignatureType = "pubkey"
	SignatureNone         SignatureType = "none"
)

// Fingerprint is one trusted key fingerprint. pkg expects these as files under
// <FINGERPRINTS>/trusted/, which materialize.go writes; the repo config only
// points at the directory.
type Fingerprint struct {
	Function    string `json:"function"`
	Fingerprint string `json:"fingerprint"`
}

// Signature carries verification material by value rather than by path.
// A path would have to be provisioned on every device out of band, which would
// make the policy neither self-contained nor idempotent.
type Signature struct {
	Type         SignatureType `json:"type"`
	Fingerprints []Fingerprint `json:"fingerprints,omitempty"`
	Pubkey       string        `json:"pubkey,omitempty"`
}

// Repository is one entry from a policy's repositories[] list.
type Repository struct {
	Name      string    `json:"name"`
	URL       string    `json:"url"`
	Priority  int       `json:"priority"`
	Enabled   bool      `json:"enabled"`
	Signature Signature `json:"signature"`
}

// ConfPath is where this repository's config lives.
func ConfPath(name string) string {
	return fmt.Sprintf("%s/%s%s.conf", reposDir, filePrefix, name)
}

// FingerprintDir is the directory pkg's FINGERPRINTS setting points at. pkg
// expects trusted/ and revoked/ subdirectories beneath it.
func FingerprintDir(name string) string {
	return fmt.Sprintf("%s/%s%s", fingerprintsIn, filePrefix, name)
}

// PubkeyPath is where a PEM public key is materialized.
func PubkeyPath(name string) string {
	return fmt.Sprintf("%s/%s%s.pub", keysDir, filePrefix, name)
}

// IsManaged reports whether a repo config file was written by us. Used by the
// reconcile to decide what it may delete and by the scan to tell our files
// apart from an administrator's.
func IsManaged(content []byte) bool {
	return bytes.HasPrefix(content, []byte(ManagedMarker))
}

// Render produces the UCL for one repository.
//
// The output is deterministic for a given input — the apply-twice-writes-
// nothing guarantee in materialize.go depends on it, since that compares
// rendered bytes against what is already on disk.
//
// ${ABI} in the URL is emitted verbatim. pkg substitutes it per device at
// runtime; expanding it here would pin every device to one ABI, and this
// codebase has been bitten by premature ${ABI} expansion twice (install.sh's
// shell escaping and migrate_repo_url.php's PCRE backreference). Nothing in
// this function interpolates the URL — it is written through as given.
func Render(r Repository) []byte {
	var b strings.Builder
	b.WriteString(ManagedMarker)
	b.WriteString("\n")
	fmt.Fprintf(&b, "%s: {\n", r.Name)
	fmt.Fprintf(&b, "  url: %q,\n", r.URL)
	fmt.Fprintf(&b, "  priority: %d,\n", r.Priority)
	fmt.Fprintf(&b, "  enabled: %s,\n", uclBool(r.Enabled))

	fmt.Fprintf(&b, "  signature_type: %q", string(r.Signature.Type))
	switch r.Signature.Type {
	case SignatureFingerprints:
		fmt.Fprintf(&b, ",\n  fingerprints: %q\n", FingerprintDir(r.Name))
	case SignaturePubkey:
		fmt.Fprintf(&b, ",\n  pubkey: %q\n", PubkeyPath(r.Name))
	default:
		// Unsigned: no verification material to point at. Emitting an empty
		// fingerprints/pubkey path would make pkg fail on a missing file
		// rather than do what the policy actually asked for.
		b.WriteString("\n")
	}

	b.WriteString("}\n")
	return []byte(b.String())
}

// uclBool renders a Go bool the way UCL expects it. `true`/`false` are not the
// spelling pkg's config uses here.
func uclBool(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}
