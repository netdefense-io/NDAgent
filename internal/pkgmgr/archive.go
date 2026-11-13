package pkgmgr

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// Seams for the external-package path; tests replace them.
var (
	installedVersionFunc   = installedVersionExact
	archiveNameVersionFunc = pkgArchiveNameVersionFreeBSD
	fetchEnvFunc           = pkgFetchEnvFreeBSD
)

// InstalledVersion is the installed version of the package named name, or ""
// when it is not installed. It asks by an evaluation query on the name alone
// (`pkg query -e '%n == <name>' %v`): pkg's plain `pkg query %v <name>` also
// matches a package whose name-version is <name>, and ignores case (pkg 2.3.1
// libpkg/pkgdb_query.c, MATCH_EXACT). With no pattern the query covers every
// package, so none matching is an empty answer and exit 0, and a database that
// another process holds locked is an error, not "not installed".
func InstalledVersion(ctx context.Context, name string) (string, error) {
	pkgMu.Lock()
	defer pkgMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, mutateTimeout)
	defer cancel()
	return installedVersionFunc(ctx, name)
}

// ArchiveNameVersion is the name and version a package archive on this box
// holds (`pkg query -F <file> %n %v`), read from the archive itself.
func ArchiveNameVersion(ctx context.Context, path string) (name, version string, err error) {
	pkgMu.Lock()
	defer pkgMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, mutateTimeout)
	defer cancel()
	return archiveNameVersionFunc(ctx, path)
}

// queryNamePattern is what a package name may hold to go into an evaluation
// query: an unquoted string there ends at white space, and nothing in it may be
// read as an operator.
var queryNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)

func installedVersionExact(ctx context.Context, name string) (string, error) {
	if !queryNamePattern.MatchString(name) {
		return "", fmt.Errorf("%q is not a package name", name)
	}
	out, err := runPkg(ctx, "query", "-e", "%n == "+name, "%v")
	if err != nil {
		return "", fmt.Errorf("pkg query: %w", err)
	}
	return strings.TrimSpace(out), nil
}

func pkgArchiveNameVersionFreeBSD(ctx context.Context, path string) (string, string, error) {
	if optionLike(path) {
		return "", "", errOptionLike(path)
	}
	out, err := runPkg(ctx, "query", "-F", path, "%n %v")
	if err != nil {
		return "", "", fmt.Errorf("pkg query -F: %w", err)
	}
	return parseArchiveNameVersion(out)
}

func parseArchiveNameVersion(out string) (string, string, error) {
	fields := strings.Fields(strings.TrimSpace(out))
	if len(fields) != 2 {
		return "", "", fmt.Errorf("pkg query -F answered %q, not a name and a version", strings.TrimSpace(out))
	}
	return fields[0], fields[1], nil
}

// FetchEnv is pkg.conf's PKG_ENV as KEY=value entries: the environment pkg sets
// for itself before it downloads anything (proxies, SSL_CA_CERT_FILE, fetch
// timeouts), so a download made for pkg goes the way pkg's own would.
func FetchEnv(ctx context.Context) ([]string, error) {
	pkgMu.Lock()
	defer pkgMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, mutateTimeout)
	defer cancel()
	return fetchEnvFunc(ctx)
}

func pkgFetchEnvFreeBSD(ctx context.Context) ([]string, error) {
	out, err := runPkg(ctx, "config", "PKG_ENV")
	if err != nil {
		return nil, fmt.Errorf("pkg config PKG_ENV: %w", err)
	}
	return parsePkgEnv(out), nil
}

// parsePkgEnv reads `pkg config PKG_ENV`, which prints an object as one
// "<key>: <value>" line per entry (pkg src/config.c).
func parsePkgEnv(out string) []string {
	var env []string
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(line, ": ")
		if !ok || key == "" || strings.ContainsAny(key, " =") {
			continue
		}
		env = append(env, key+"="+value)
	}
	return env
}
