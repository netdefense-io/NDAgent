package tasks

// exec.go — shared helpers for spawning on-device subprocesses.
//
// NDAgent runs under rc.d with a stripped PATH (/sbin:/bin:/usr/sbin:/usr/bin).
// Any on-device command that lives under /usr/local/sbin or /usr/local/bin —
// and any subprocess those commands spawn by name — will fail with "not found"
// unless the environment is extended before the exec.
//
// DeviceExecEnv returns an environment slice based on os.Environ() with the
// PATH entry replaced (or added) to include the full root-interactive PATH
// that FreeBSD/OPNsense provides to a login shell. All handlers that shell out
// to binaries under /usr/local/{sbin,bin} must use this.
//
// The implementation lives in internal/util to avoid an import cycle with
// internal/pathfinder. This file re-exports it under the tasks package so
// existing callers (firmware_upgrade.go, plugin_install.go, etc.) need no
// change.

import "github.com/netdefense-io/ndagent/internal/util"

// devicePATH is the PATH that a root interactive shell has on FreeBSD/OPNsense.
// Re-exported from util for any tasks package code that references it directly.
const devicePATH = util.DevicePATH

// DeviceExecEnv returns a copy of the current process environment with the
// PATH entry set to the full root-interactive PATH. See util.DeviceExecEnv for
// full documentation.
func DeviceExecEnv() []string {
	return util.DeviceExecEnv()
}
