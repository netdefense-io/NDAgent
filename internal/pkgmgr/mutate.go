// Mutating pkg(8) operations for the SoftwarePolicy SYNC handler.
//
// Kept in a separate file from Query because the failure modes here are
// different: a bad install can leave a half-applied state on the device,
// and pkg(8)'s "package not in any catalog" needs to be teased out of the
// exit code + stderr stream. Tests substitute the package-level mutators
// with stubs (see installFunc/removeFunc/updateFunc) to avoid shelling out.
package pkgmgr

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// SoftwareAction is the per-package outcome reported by the SYNC handler.
// It must stay stable in wire format — NDWeb / NDCLI render these directly.
type SoftwareAction string

const (
	ActionInstalled      SoftwareAction = "INSTALLED"
	ActionAlreadyPresent SoftwareAction = "ALREADY_PRESENT"
	ActionRemoved        SoftwareAction = "REMOVED"
	ActionAlreadyAbsent  SoftwareAction = "ALREADY_ABSENT"
	ActionNotFound       SoftwareAction = "NOT_FOUND"
	ActionInvalidName    SoftwareAction = "INVALID_NAME"
	ActionError          SoftwareAction = "ERROR"
)

// MutateOutcome describes the result of a single Install or Delete call.
// Action is enough on its own for the happy paths; ErrMsg carries the
// stderr snippet on ActionError so the user can see why pkg refused.
type MutateOutcome struct {
	Action SoftwareAction
	ErrMsg string
}

// installFunc, removeFunc, updateFunc, and isInstalledFunc are the swap
// points for tests. See pkgmgr/testing.go for the helpers other packages
// use to substitute them.
var (
	installFunc     = pkgInstallFreeBSD
	removeFunc      = pkgRemoveFreeBSD
	updateFunc      = pkgUpdateFreeBSD
	isInstalledFunc = pkgIsInstalledFreeBSD
)

// Update runs `pkg update -q` to refresh the local catalog. SoftwarePolicy
// sync calls this once at the start; subsequent IsInstalled / Install /
// Delete calls read against the freshened catalog. A stale catalog would
// produce false NOT_FOUND results.
func Update(ctx context.Context) error {
	return updateFunc(ctx)
}

// IsInstalled returns true if `pkg info -q <name>` succeeds. Reuses the
// runPkg helper from pkgmgr.go so transient errors (pkg(8) missing, signal)
// propagate the same way Query already handles them.
func IsInstalled(ctx context.Context, name string) (bool, error) {
	return isInstalledFunc(ctx, name)
}

func pkgIsInstalledFreeBSD(ctx context.Context, name string) (bool, error) {
	_, err := runPkg(ctx, "info", "-q", name)
	if err == nil {
		return true, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return false, nil
	}
	return false, err
}

// Install runs `pkg install -y <name>`. Returns ActionInstalled on success,
// ActionNotFound when no repository has the package, ActionError otherwise.
func Install(ctx context.Context, name string) MutateOutcome {
	return installFunc(ctx, name)
}

// Delete runs `pkg delete -y <name>`. Returns ActionRemoved on success,
// ActionError otherwise. "Not installed" should be detected via IsInstalled
// upstream — `pkg delete` on a missing package exits non-zero, which we'd
// otherwise misreport.
func Delete(ctx context.Context, name string) MutateOutcome {
	return removeFunc(ctx, name)
}

// pkgInstallFreeBSD is the production implementation. Captures stderr so
// we can distinguish "no package matching" (NOT_FOUND) from other failures
// (ERROR). pkg's not-found message has been stable across versions:
//   "pkg: No packages available to install matching '<name>' have been found in the repositories"
//   "pkg: No packages matching '<name>' available in the repositories"
// We match on the prefix substring.
func pkgInstallFreeBSD(ctx context.Context, name string) MutateOutcome {
	stderr, err := runPkgCaptureStderr(ctx, "install", "-y", name)
	if err == nil {
		return MutateOutcome{Action: ActionInstalled}
	}
	low := strings.ToLower(stderr)
	if strings.Contains(low, "no packages available to install matching") ||
		strings.Contains(low, "no packages matching") {
		return MutateOutcome{Action: ActionNotFound}
	}
	msg := firstNonEmptyLine(stderr)
	if msg == "" {
		msg = err.Error()
	}
	return MutateOutcome{Action: ActionError, ErrMsg: msg}
}

func pkgRemoveFreeBSD(ctx context.Context, name string) MutateOutcome {
	stderr, err := runPkgCaptureStderr(ctx, "delete", "-y", name)
	if err == nil {
		return MutateOutcome{Action: ActionRemoved}
	}
	msg := firstNonEmptyLine(stderr)
	if msg == "" {
		msg = err.Error()
	}
	return MutateOutcome{Action: ActionError, ErrMsg: msg}
}

func pkgUpdateFreeBSD(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "pkg", "update", "-q")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pkg update: %w (%s)", err, firstNonEmptyLine(stderr.String()))
	}
	return nil
}

// runPkgCaptureStderr is the mutate-side analogue of runPkg — keeps stderr
// for error classification rather than discarding it.
func runPkgCaptureStderr(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "pkg", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stderr.String(), err
}

func firstNonEmptyLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			return t
		}
	}
	return ""
}
