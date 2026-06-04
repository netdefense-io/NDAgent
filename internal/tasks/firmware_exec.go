package tasks

// firmware_exec.go — on-device execution of opnsense-update for the
// reboot=false (packages-only) path of FIRMWARE_UPGRADE.
//
// The only function exported from this file is RunFirmwarePackagesOnly;
// the exec.CommandContext indirection (firmwareExecFunc) is the stub point
// for unit tests (mirrors pkgmgr/mutate.go's installFunc pattern).

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/netdefense-io/ndagent/internal/security"
)

// allowedFirmwareSuffixes is the allowlist of valid opnsense-update type
// suffixes. The empty string ("") is the standard opnsense flavor.
// Business editions add "-business"; community editions are just "".
// The slice mirrors what pluginctl returns for system.firmware.type.
// Any value not in this list is rejected before exec to prevent injection.
var allowedFirmwareSuffixes = []string{
	"",          // standard OPNsense
	"-business", // Deciso business edition
	"-devel",    // development builds
}

// firmwareExecFunc is the indirection point for tests. Production code uses
// the real exec; tests swap it out via setFirmwareExecFuncForTest.
//
// cmd.Env is set via DeviceExecEnv() so that opnsense-update and any
// subprocesses it spawns by unqualified name (e.g. opnsense-version) can be
// resolved even when NDAgent runs under rc.d with a stripped PATH that omits
// /usr/local/sbin and /usr/local/bin.
var firmwareExecFunc = func(ctx context.Context, args ...string) ([]byte, []byte, int) {
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Env = DeviceExecEnv()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if ok := isExitError(err, &exitErr); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}
	return stdout.Bytes(), stderr.Bytes(), exitCode
}

// isExitError is a helper to avoid importing errors twice.
func isExitError(err error, target **exec.ExitError) bool {
	if e, ok := err.(*exec.ExitError); ok {
		*target = e
		return true
	}
	return false
}

// FirmwareExecResult is the outcome of a RunFirmwarePackagesOnly call.
type FirmwareExecResult struct {
	// ExitCode is the process exit code (0 = success).
	ExitCode int
	// Stdout / Stderr are the raw combined output (bounded by logTailLines).
	Stdout string
	Stderr string
	// LogTail is the last logTailLines lines of combined output.
	LogTail string
}

// logTailLines is how many trailing lines we keep in LogTail.
const logTailLines = 50

// ValidateFirmwareSuffix returns an error if suffix is not in the allowlist.
// It also validates that the resulting package name (opnsense + suffix) doesn't
// contain shell-unsafe characters, mirroring security.ValidatePingTarget in style.
func ValidateFirmwareSuffix(suffix string) error {
	for _, allowed := range allowedFirmwareSuffixes {
		if suffix == allowed {
			return nil
		}
	}
	return fmt.Errorf("firmware suffix %q not in allowlist", suffix)
}

// RunFirmwarePackagesOnly executes `opnsense-update -pt "opnsense<suffix>"`,
// which applies only the package (pkg) portion of a point release — leaving
// base and kernel for a subsequent reboot=true job. This is the reboot=false
// path; it is synchronous and returns only after the command exits.
//
// Mirroring the official update.sh:
//
//	opnsense-update ${FORCE} -pt "opnsense${SUFFIX}"
//
// where -p = packages-only, -t = target type (the OPNsense core package name).
// suffix comes from `pluginctl -g system.firmware.type`; it is validated
// against the allowlist before the exec.
func RunFirmwarePackagesOnly(ctx context.Context, suffix string) (*FirmwareExecResult, error) {
	if err := ValidateFirmwareSuffix(suffix); err != nil {
		return nil, err
	}

	packageName := "opnsense" + suffix
	// Belt-and-suspenders: validate the package name through the shared
	// security layer as well (no spaces, no special chars).
	if err := security.ValidateOPNsensePackageName(packageName); err != nil {
		return nil, fmt.Errorf("firmware package name rejected by security layer: %w", err)
	}

	stdout, stderr, exitCode := firmwareExecFunc(ctx, "/usr/local/sbin/opnsense-update", "-pt", packageName)

	combined := append(stdout, '\n')
	combined = append(combined, stderr...)
	logTail := tailLines(string(combined), logTailLines)

	return &FirmwareExecResult{
		ExitCode: exitCode,
		Stdout:   string(stdout),
		Stderr:   string(stderr),
		LogTail:  logTail,
	}, nil
}

// tailLines returns the last n lines of s.
func tailLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) <= n {
		return strings.Join(lines, "\n")
	}
	return strings.Join(lines[len(lines)-n:], "\n")
}
