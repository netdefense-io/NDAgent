// Shadow detection: which repositories offer a given package name.
//
// Repository priority is NOT a safety boundary, and the design depends on
// saying so accurately. pkg-repository(5) states that where several versions of
// the same package are available, pkg selects the HIGHEST VERSION "even if a
// lower numbered version can be found in a repository earlier in the [priority]
// list" — so a custom repository at priority 5 can still beat OPNsense's base
// repository at priority 11 simply by publishing a higher version string.
// CONSERVATIVE_UPGRADE (on by default) pins an already-installed package to its
// origin repository, but offers no protection on a FIRST install, which is
// exactly the case a policy-driven install is.
//
// Priority checks at write time therefore buy ordering hygiene, not safety. The
// real protection is here: before installing a package, ask which repositories
// offer that name, and refuse the install when more than one does rather than
// letting pkg silently pick a winner the operator never chose.
//
// This runs only for packages actually about to be installed, so a settled
// device — where everything resolves to ALREADY_PRESENT — pays nothing.
package pkgmgr

import (
	"context"
	"fmt"
	"strings"
)

// ShadowError reports a package offered by more than one repository.
type ShadowError struct {
	Package      string
	Repositories []string
}

func (e ShadowError) Error() string {
	return fmt.Sprintf(
		"package %q is offered by more than one repository (%s); refusing an ambiguous install, "+
			"because pkg selects the highest version regardless of repository priority",
		e.Package, strings.Join(e.Repositories, ", "),
	)
}

// offeredByFunc is the swap point for tests, matching this package's existing
// convention. See testing.go.
var offeredByFunc = pkgOfferedByFreeBSD

// OfferedBy returns the repositories whose catalogs offer `name`.
//
// Serialized and time-bounded like every other pkg invocation in this package:
// it shells out to pkg and reads the same catalogs an install consults, so
// letting it run alongside a mutation would reintroduce the lock contention
// that serialization exists to prevent.
//
// An error here is NOT "no conflict". The caller must fail the package rather
// than proceed, because a failed query means we could not establish that the
// install is unambiguous — and unverifiable is not the same as safe.
func OfferedBy(ctx context.Context, name string) ([]string, error) {
	pkgMu.Lock()
	defer pkgMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()
	return offeredByFunc(ctx, name)
}

// pkgOfferedByFreeBSD asks every configured repository's catalog which of them
// carries this package name.
//
// -U skips an on-the-fly catalog refresh: SoftwarePolicy sync already runs
// `pkg update` once up front, and refreshing again per package would turn a
// cheap check into a slow one.
func pkgOfferedByFreeBSD(ctx context.Context, name string) ([]string, error) {
	out, err := runPkg(ctx, "rquery", "-U", "%R", name)
	if err != nil {
		// A package in no catalog at all exits non-zero. That is not an
		// ambiguity — it is a NOT_FOUND the install path reports on its own —
		// so report no repositories rather than an error.
		if isNoMatchingPackage(out, err) {
			return nil, nil
		}
		return nil, fmt.Errorf("querying repositories offering %q: %w", name, err)
	}
	return parseOfferedBy(out), nil
}

// isNoMatchingPackage distinguishes "this name is in no catalog" from a real
// query failure. Being wrong in the permissive direction here would let an
// ambiguous install through, so only a genuinely empty result counts.
func isNoMatchingPackage(out string, err error) bool {
	return strings.TrimSpace(out) == "" && err != nil && strings.Contains(err.Error(), "exit status 1")
}

// parseOfferedBy turns `pkg rquery -U '%R'` output into a deduplicated,
// order-preserving list. A repository appears once per matching package, so the
// raw output repeats.
func parseOfferedBy(raw string) []string {
	var repos []string
	seen := map[string]bool{}
	for _, line := range strings.Split(raw, "\n") {
		name := strings.TrimSpace(line)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		repos = append(repos, name)
	}
	return repos
}
