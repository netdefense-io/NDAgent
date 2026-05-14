// Package pkgmgr is a thin wrapper over FreeBSD's pkg(8) for read-only
// queries against the local installed-package database and the
// configured remote repositories.
//
// It exists so the PLUGIN_INSTALL task handler can detect a no-op install
// (target version already installed) before forking the detached helper
// that triggers an agent shutdown — see internal/tasks/plugin_install.go.
//
// The same primitives are intended to back a future SYNC_PACKAGES task
// where NDManager ships a declarative "package snippet" (a list of
// {name, version} pairs) and the agent reconciles installed state
// against it. That handler does not exist yet; only Query is exposed
// here. When the sync task lands, an Install/Remove pair will go in
// alongside Query — splitting them out keeps the read-only side, which
// is safe to call from any handler at any time, distinct from the
// mutate path which has lifecycle concerns (pkg's pre-deinstall hook
// kills the agent for self-install, see plugin_install.go).
//
// Tests substitute the package-level queryFunc to avoid shelling out.
package pkgmgr

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strings"
)

// Status describes the installed and repository-available versions of
// one FreeBSD package, as observed at Query time.
type Status struct {
	Name string
	// InstalledVersion is the version reported by `pkg query "%v" <name>`.
	// Empty string means the package is not installed locally.
	InstalledVersion string
	// AvailableVersion is the latest version offered by any configured
	// repository, per `pkg rquery -U "%v" <name>`. Empty when the package
	// is not in any repo's catalog or the rquery call failed (the catalog
	// may be stale; we use -U to skip on-the-fly refresh).
	AvailableVersion string
}

// queryFunc is the indirection tests swap. Production wiring is
// pkgQueryFreeBSD; tests assign their own implementation.
var queryFunc = pkgQueryFreeBSD

// Query returns the installed + available state for each named package.
// Always returns one Status per name in the input order. A name that is
// not installed AND not in any repo yields a Status with both version
// fields empty — callers that care can treat that as "unknown package".
//
// One pkg(8) invocation per name (two if the package is in a repo). Fine
// for the ceiling we expect — PLUGIN_INSTALL queries 1, the future
// SYNC_PACKAGES handler is expected to cap somewhere around 50.
func Query(ctx context.Context, names []string) ([]Status, error) {
	return queryFunc(ctx, names)
}

func pkgQueryFreeBSD(ctx context.Context, names []string) ([]Status, error) {
	out := make([]Status, len(names))
	for i, n := range names {
		out[i].Name = n
		if v, err := installedVersion(ctx, n); err == nil {
			out[i].InstalledVersion = v
		}
		if v, err := availableVersion(ctx, n); err == nil {
			out[i].AvailableVersion = v
		}
	}
	return out, nil
}

// installedVersion shells out to `pkg query "%v" <name>`. Returns "" for
// not-installed (pkg-query exits non-zero with no stdout). Any other
// error — pkg(8) missing, signal, etc — is returned to the caller.
func installedVersion(ctx context.Context, name string) (string, error) {
	stdout, err := runPkg(ctx, "query", "%v", name)
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(stdout) == 0 {
			// Not installed — pkg-query exits non-zero with empty stdout.
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(stdout), nil
}

// availableVersion shells out to `pkg rquery -U "%v" <name>`. -U skips
// the on-the-fly catalog refresh so this stays a fast read of cached
// repo metadata. Returns "" if the package isn't in any configured repo
// (or the catalog can't be read).
func availableVersion(ctx context.Context, name string) (string, error) {
	stdout, err := runPkg(ctx, "rquery", "-U", "%v", name)
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(stdout) == 0 {
			return "", nil
		}
		return "", err
	}
	// Multiple repos may answer; take the first non-empty line. pkg
	// already orders by repo priority.
	for _, line := range strings.Split(stdout, "\n") {
		if v := strings.TrimSpace(line); v != "" {
			return v, nil
		}
	}
	return "", nil
}

func runPkg(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "pkg", args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = nil
	err := cmd.Run()
	return buf.String(), err
}
