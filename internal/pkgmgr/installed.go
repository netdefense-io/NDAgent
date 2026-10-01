package pkgmgr

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// installedTimeout bounds one query of the whole installed-package database.
const installedTimeout = 60 * time.Second

// installedVersionsFunc is the indirection tests swap.
var installedVersionsFunc = pkgInstalledVersionsFreeBSD

// InstalledVersions returns the version of every installed package, by name,
// from a single pkg(8) call.
//
// It is stricter than Query, on purpose. Query reads a failing `pkg query` with
// no output as "not installed" and drops every other error, so a locked
// database (pkg holds an exclusive lock while it installs), a missing binary
// or a timeout all look like an empty answer. A caller that decides an update
// failed from a package being absent cannot afford that: here any failure is an
// error, and so is an answer that lists no package at all, because a device
// always has packages and an empty list means the query did not really run.
//
// It waits for the package lock under ctx, unlike the rest of the package: a
// caller with a deadline of its own (the FIRMWARE_UPGRADE reconciler, whose sweep
// runs inside the connect) must not sit behind an install that holds the lock for
// up to ten minutes.
func InstalledVersions(ctx context.Context) (map[string]string, error) {
	if err := pkgMu.LockContext(ctx); err != nil {
		return nil, fmt.Errorf("waiting for the package lock: %w", err)
	}
	defer pkgMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, installedTimeout)
	defer cancel()
	return installedVersionsFunc(ctx)
}

func pkgInstalledVersionsFreeBSD(ctx context.Context) (map[string]string, error) {
	cmd := exec.CommandContext(ctx, "pkg", "query", "%n %v")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if msg := firstNonEmptyLine(stderr.String()); msg != "" {
			return nil, fmt.Errorf("pkg query: %w (%s)", err, msg)
		}
		return nil, fmt.Errorf("pkg query: %w", err)
	}
	return parseInstalledVersions(stdout.String())
}

// parseInstalledVersions reads `pkg query "%n %v"` output: one "name version"
// pair per line.
func parseInstalledVersions(out string) (map[string]string, error) {
	versions := make(map[string]string)
	for _, line := range strings.Split(out, "\n") {
		name, version, ok := strings.Cut(strings.TrimSpace(line), " ")
		version = strings.TrimSpace(version)
		if !ok || name == "" || version == "" {
			continue
		}
		versions[name] = version
	}
	if len(versions) == 0 {
		return nil, errors.New("pkg query listed no installed package")
	}
	return versions, nil
}
