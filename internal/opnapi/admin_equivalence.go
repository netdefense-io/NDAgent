package opnapi

// admin_equivalence.go — which OPNsense privileges make a local account
// administrator-equivalent, and which names NetDefense never manages.
//
// The classification is data, not code: opnsense_admin_equivalence.json is
// reviewed in NDDataModels and copied here byte for byte, and a test pins its
// SHA-256. The plugin's PHP carries the same file.
//
// A privilege entry is one element of a USER/GROUP priv list, or a whole priv
// CSV as OPNsense stores it, so it can pack several IDs. It is split on ',',
// each token is trimmed and lowercased, empty tokens are skipped, and the
// entry is administrator-equivalent as soon as one token is. A token is when
// it is a key of the catalog's admin_equivalent map, or a key of neither map
// (an ID nobody reviewed, a lookalike spelling: a false positive costs one
// Superuser save, a false negative is an escalation), or when it matches the
// structural floor that predates the catalog (see privStructuralFloor).
//
// Normalization here is ASCII only, on purpose: every catalog key is ASCII, so
// a token with any other byte in it is unknown and therefore elevated, however
// another layer strips exotic whitespace. The shared vectors pin the verdicts.

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

//go:embed opnsense_admin_equivalence.json
var adminEquivalenceJSON []byte

// BuiltinAdminGID is the gid of OPNsense's built-in admins group. The device
// recognizes that group by gid as well as by name.
const BuiltinAdminGID = "1999"

// ElevateFloorDependentPrivsBelowFloor is the one switch for the catalog's
// floor_dependent_ids: privilege IDs that are ordinary only on OPNsense releases
// that carry an upstream privilege-escalation fix (the catalog's
// assumes_min_opnsense, which is also NDAgent's supported floor). On: a device
// below the floor, or one whose release cannot be read, treats them as
// administrator-equivalent (see PrivPolicyForRelease), because the fix they
// depend on is not there. Off: they are ordinary on every release. Only
// internal/tasks' adminPrivPolicy reads it, and everything in the agent that
// classifies a privilege takes the PrivPolicy it returns. The plugin's
// AdminEquivalence.php does not: it has no policy input, so the warning count of
// the AUTH_SERVER helper keeps reading these IDs as ordinary.
const ElevateFloorDependentPrivsBelowFloor = true

// PrivPolicy is how the catalog applies on one device. The zero value is the
// catalog as reviewed.
type PrivPolicy struct {
	// FloorDependentElevated treats the catalog's floor_dependent_ids as
	// administrator-equivalent.
	FloorDependentElevated bool
}

// PrivPolicyForRelease is the policy for a device running release, with the
// floor-dependent IDs elevated below the floor: they are elevated on a release
// below the supported floor, and on one that could not be read (known is false).
// It does not look at ElevateFloorDependentPrivsBelowFloor.
func PrivPolicyForRelease(release ProductRelease, known bool) PrivPolicy {
	return PrivPolicy{FloorDependentElevated: !known || !release.AtLeast(MinSupportedOPNsenseMajor, MinSupportedOPNsenseMinor, MinSupportedOPNsensePatch)}
}

type adminEquivalenceFile struct {
	Schema int    `json:"schema"`
	Kind   string `json:"kind"`
	Meta   struct {
		UnknownIDPolicy    string          `json:"unknown_id_policy"`
		Match              string          `json:"match"`
		AssumesMinOPNsense string          `json:"assumes_min_opnsense"`
		FloorDependentIDs  []string        `json:"floor_dependent_ids"`
		Sources            json.RawMessage `json:"sources"`
	} `json:"meta"`
	AdminEquivalent     map[string]string `json:"admin_equivalent"`
	NonAdmin            map[string]string `json:"non_admin"`
	ROBackstopAllowlist map[string]string `json:"ro_backstop_allowlist"`
	ProtectedGroups     []string          `json:"protected_groups"`
	ProtectedUsers      []string          `json:"protected_users"`
}

type privCatalog struct {
	sha256             string
	assumesMinOPNsense string
	adminEquivalent    map[string]bool
	nonAdmin           map[string]bool
	floorDependent     map[string]bool
	protectedGroups    []string
	protectedUsers     []string
}

// adminCatalog is the embedded catalog. It is loaded when the package is, and a
// catalog that does not load stops the process: a build whose classification
// cannot be read must not run, and a test pins the embedded bytes.
var adminCatalog = mustLoadPrivCatalog(adminEquivalenceJSON)

func mustLoadPrivCatalog(raw []byte) *privCatalog {
	c, err := loadPrivCatalog(raw)
	if err != nil {
		panic("opnapi: opnsense_admin_equivalence.json is invalid: " + err.Error())
	}
	return c
}

func loadPrivCatalog(raw []byte) (*privCatalog, error) {
	var doc adminEquivalenceFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}

	if doc.Schema != 1 {
		return nil, fmt.Errorf("unsupported schema version %d", doc.Schema)
	}
	if doc.Kind != "opnsense-admin-equivalence" {
		return nil, fmt.Errorf("wrong kind %q", doc.Kind)
	}
	if doc.Meta.UnknownIDPolicy != "admin_equivalent" {
		return nil, fmt.Errorf("only the fail-closed unknown_id_policy is supported")
	}
	if doc.Meta.AssumesMinOPNsense == "" {
		return nil, fmt.Errorf("meta.assumes_min_opnsense is empty")
	}

	sum := sha256.Sum256(raw)
	c := &privCatalog{
		sha256:             hex.EncodeToString(sum[:]),
		assumesMinOPNsense: doc.Meta.AssumesMinOPNsense,
		adminEquivalent:    map[string]bool{},
		nonAdmin:           map[string]bool{},
		floorDependent:     map[string]bool{},
	}

	for section, source := range map[string]map[string]string{
		"admin_equivalent":      doc.AdminEquivalent,
		"non_admin":             doc.NonAdmin,
		"ro_backstop_allowlist": doc.ROBackstopAllowlist,
	} {
		for token := range source {
			if !isNormalizedToken(token) {
				return nil, fmt.Errorf("%s has a key that is not a normalized token", section)
			}
		}
	}
	if len(doc.AdminEquivalent) == 0 || len(doc.NonAdmin) == 0 {
		return nil, fmt.Errorf("both privilege maps must be populated")
	}
	for token := range doc.AdminEquivalent {
		if _, both := doc.NonAdmin[token]; both {
			return nil, fmt.Errorf("a privilege ID is in both maps")
		}
		c.adminEquivalent[token] = true
	}
	for token := range doc.NonAdmin {
		c.nonAdmin[token] = true
	}
	for token := range doc.ROBackstopAllowlist {
		if c.nonAdmin[token] {
			return nil, fmt.Errorf("ro_backstop_allowlist may only hold elevated IDs")
		}
	}
	for _, token := range doc.Meta.FloorDependentIDs {
		if !c.nonAdmin[token] {
			return nil, fmt.Errorf("meta.floor_dependent_ids must be non_admin IDs")
		}
		c.floorDependent[token] = true
	}

	var err error
	if c.protectedGroups, err = normalizedNameList(doc.ProtectedGroups); err != nil {
		return nil, fmt.Errorf("protected_groups: %w", err)
	}
	if c.protectedUsers, err = normalizedNameList(doc.ProtectedUsers); err != nil {
		return nil, fmt.Errorf("protected_users: %w", err)
	}
	return c, nil
}

func normalizedNameList(names []string) ([]string, error) {
	if len(names) == 0 {
		return nil, fmt.Errorf("must be a non-empty list")
	}
	seen := map[string]bool{}
	for _, n := range names {
		if !isNormalizedToken(n) || seen[n] {
			return nil, fmt.Errorf("must hold unique normalized names")
		}
		seen[n] = true
	}
	return append([]string(nil), names...), nil
}

func isNormalizedToken(s string) bool {
	if s == "" || normalizePrivToken(s) != s || strings.Contains(s, ",") {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// AdminEquivalenceSHA256 is the SHA-256, in hex, of the embedded catalog.
func AdminEquivalenceSHA256() string { return adminCatalog.sha256 }

// AdminEquivalenceAssumedMinRelease is the OPNsense release the catalog's
// floor_dependent_ids are classified for.
func AdminEquivalenceAssumedMinRelease() string { return adminCatalog.assumesMinOPNsense }

// privTrimSet is the whitespace trimmed around a token or a name: ASCII only.
const privTrimSet = " \t\n\v\f\r"

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

func normalizePrivToken(raw string) string {
	return asciiLower(strings.Trim(raw, privTrimSet))
}

// privTokens splits an entry into its normalized, non-empty tokens.
func privTokens(entry string) []string {
	var tokens []string
	for _, raw := range strings.Split(entry, ",") {
		if t := normalizePrivToken(raw); t != "" {
			tokens = append(tokens, t)
		}
	}
	return tokens
}

// privStructuralFloor is the rule the catalog predates, kept as a floor so the
// union is never weaker than it was: page-all itself, any category-wide grant
// ending in -all, any ID naming both "system" and "admin", and all-pages, an
// alias this agent has always refused.
func privStructuralFloor(token string) bool {
	return token == "page-all" ||
		token == "all-pages" ||
		strings.HasSuffix(token, "-all") ||
		(strings.Contains(token, "system") && strings.Contains(token, "admin"))
}

func (p PrivPolicy) tokenElevated(token string) bool {
	if adminCatalog.adminEquivalent[token] || !adminCatalog.nonAdmin[token] || privStructuralFloor(token) {
		return true
	}
	return p.FloorDependentElevated && adminCatalog.floorDependent[token]
}

// IsAdminEquivalentPriv reports whether one privilege entry makes an account
// administrator-equivalent.
func (p PrivPolicy) IsAdminEquivalentPriv(entry string) bool {
	for _, token := range privTokens(entry) {
		if p.tokenElevated(token) {
			return true
		}
	}
	return false
}

// HasAdminEquivalentPriv reports whether any entry of a priv list does.
func (p PrivPolicy) HasAdminEquivalentPriv(entries []string) bool {
	for _, entry := range entries {
		if p.IsAdminEquivalentPriv(entry) {
			return true
		}
	}
	return false
}

// AdminEquivalentPrivNames returns the privilege IDs in entries that make an
// account administrator-equivalent and that the catalog names, in order of
// appearance and without repeats, and how many distinct elevated tokens it does
// not name. Only a catalog ID may appear in a message: any other elevated token
// is whatever the author typed.
func (p PrivPolicy) AdminEquivalentPrivNames(entries []string) (names []string, unrecognized int) {
	var tokens []string
	for _, entry := range entries {
		tokens = append(tokens, privTokens(entry)...)
	}
	return p.elevatedTokens(tokens)
}

// elevatedTokens is AdminEquivalentPrivNames over tokens that are already
// normalized.
func (p PrivPolicy) elevatedTokens(tokens []string) (names []string, unrecognized int) {
	seen := map[string]bool{}
	for _, token := range tokens {
		if seen[token] || !p.tokenElevated(token) {
			continue
		}
		seen[token] = true
		if adminCatalog.adminEquivalent[token] || adminCatalog.nonAdmin[token] {
			names = append(names, token)
		} else {
			unrecognized++
		}
	}
	return names, unrecognized
}

// normalizeAccountName is how the catalog compares group names: trimmed and
// lowercased. OPNsense links group names case-insensitively, so "Admins" is the
// real admins group on the device.
func normalizeAccountName(name string) string {
	return normalizePrivToken(name)
}

// AccountNameKey is the form in which two user names, or two group names, are
// the same account: trimmed and ASCII-lowercased. It is "" for a name that is
// nothing but padding.
func AccountNameKey(name string) string {
	return normalizeAccountName(name)
}

// ProtectedGroupCanonicalName returns the catalog's name for a group that
// NetDefense never manages when name, trimmed and lowercased, is one of them.
//
// This is the write-time rule and the one the Superuser clearance gate uses. It
// is not IsProtectedGroup, which SYNC applies when it parses a snippet and when
// it sweeps orphans, and which does not trim.
func ProtectedGroupCanonicalName(name string) (string, bool) {
	n := normalizeAccountName(name)
	for _, p := range adminCatalog.protectedGroups {
		if p == n {
			return p, true
		}
	}
	return "", false
}

// IsProtectedGroupName reports whether name, trimmed and lowercased, is a
// protected group's.
func IsProtectedGroupName(name string) bool {
	_, ok := ProtectedGroupCanonicalName(name)
	return ok
}

// SplitGroupEntry returns the trimmed, non-empty parts of one USER snippet
// `groups` entry, split on ','. The catalog reads an entry that way, so the
// device does too, even though it resolves group names one entry at a time.
func SplitGroupEntry(entry string) []string {
	var parts []string
	for _, raw := range strings.Split(entry, ",") {
		if p := strings.Trim(raw, privTrimSet); p != "" {
			parts = append(parts, p)
		}
	}
	return parts
}

// GroupEntryNamesProtectedGroup reports whether any part of a USER snippet
// `groups` entry names a protected group.
func GroupEntryNamesProtectedGroup(entry string) bool {
	for _, part := range SplitGroupEntry(entry) {
		if IsProtectedGroupName(part) {
			return true
		}
	}
	return false
}
