package track

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	_ "modernc.org/sqlite"
)

// A revision is the content of a release folder at one moment. OPNsense rewrites a
// MINT folder in place (new packagesite.pkg, same x.y.z), so the release name does
// not tell two contents apart; the fingerprint does.
//
// The fingerprint is the sha256, in lowercase hex, of one line per package record
// of the folder's catalog, `name TAB version TAB sum LF`, the lines sorted bytewise.
// It is computed from the catalog pkg keeps on the box (the file pkg itself
// consumed), where `cksum` is the catalog's `sum`, so the control plane reaches the
// same value from the mirror's packagesite.yaml.

// RevisionLength is the length of a fingerprint on the wire.
const RevisionLength = 64

var revisionRE = regexp.MustCompile(`\A[0-9a-f]{64}\z`)

// ValidRevision reports whether s is a fingerprint as the wire spells it.
func ValidRevision(s string) bool { return revisionRE.MatchString(s) }

// PkgReposDir is where pkg keeps the catalog of each repository: <dir>/<name>/db.
const PkgReposDir = "/var/db/pkg/repos"

// Catalog is what the agent reads of a repository's cached catalog.
type Catalog struct {
	// Fingerprint is the revision of the catalog.
	Fingerprint string
	// versions maps a package name to every version the catalog holds for it.
	versions map[string][]string
}

// Has reports whether the catalog holds a package called name, at any version.
func (c Catalog) Has(name string) bool { return len(c.versions[name]) > 0 }

// Offers reports whether the catalog holds name at version.
func (c Catalog) Offers(name, version string) bool {
	for _, v := range c.versions[name] {
		if v == version {
			return true
		}
	}
	return false
}

// Records is how many packages the catalog holds.
func (c Catalog) Records() int { return len(c.versions) }

// CatalogRecord is one package of a catalog, as the fingerprint reads it.
type CatalogRecord struct {
	Name, Version, Sum string
}

// NewCatalog fingerprints records. A catalog with no record, or a field that is
// empty or holds a tab or a line feed, has no fingerprint.
func NewCatalog(records []CatalogRecord) (Catalog, error) {
	if len(records) == 0 {
		return Catalog{}, errors.New("the catalog holds no package")
	}
	lines := make([]string, 0, len(records))
	versions := make(map[string][]string, len(records))
	for _, r := range records {
		for _, f := range []string{r.Name, r.Version, r.Sum} {
			if f == "" || strings.ContainsAny(f, "\t\n") {
				return Catalog{}, fmt.Errorf("the catalog holds a record the fingerprint cannot spell (%q)", r.Name)
			}
		}
		lines = append(lines, r.Name+"\t"+r.Version+"\t"+r.Sum+"\n")
		versions[r.Name] = append(versions[r.Name], r.Version)
	}
	sort.Strings(lines)
	h := sha256.New()
	for _, l := range lines {
		h.Write([]byte(l))
	}
	return Catalog{Fingerprint: hex.EncodeToString(h.Sum(nil)), versions: versions}, nil
}

var repoStanzaRE = regexp.MustCompile(`(?m)^\s*([A-Za-z0-9_.-]+)\s*:\s*\{`)

// RepoName is the name of the repository the generated repository file defines
// (OPNsense), which names its directory under PkgReposDir. A file with several
// stanzas names the one that starts with OPNsense, else the first.
func RepoName(conf string) (string, error) {
	all := repoStanzaRE.FindAllStringSubmatch(conf, -1)
	if len(all) == 0 {
		return "", errors.New("the repository file names no repository")
	}
	for _, m := range all {
		if strings.HasPrefix(m[1], "OPNsense") {
			return m[1], nil
		}
	}
	return all[0][1], nil
}

// CatalogDBPath is the file holding the cached catalog of the named repository.
func CatalogDBPath(reposDir, name string) string {
	return reposDir + "/" + name + "/db"
}

// ReadCatalog reads the cached catalog at path, read-only. pkg replaces the
// catalog while it updates it, so a busy or half-written file is the caller's to
// try again.
func ReadCatalog(ctx context.Context, path string) (Catalog, error) {
	dsn := "file:" + (&url.URL{Path: path}).EscapedPath() + "?mode=ro&_pragma=busy_timeout(3000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return Catalog{}, fmt.Errorf("open the catalog: %w", err)
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx, "SELECT name, version, cksum FROM packages")
	if err != nil {
		return Catalog{}, fmt.Errorf("read the catalog: %w", err)
	}
	defer rows.Close()
	var records []CatalogRecord
	for rows.Next() {
		var r CatalogRecord
		if err := rows.Scan(&r.Name, &r.Version, &r.Sum); err != nil {
			return Catalog{}, fmt.Errorf("read the catalog: %w", err)
		}
		records = append(records, r)
	}
	if err := rows.Err(); err != nil {
		return Catalog{}, fmt.Errorf("read the catalog: %w", err)
	}
	return NewCatalog(records)
}
