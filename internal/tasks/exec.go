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
// internal/pathfinder; this file re-exports it for the handlers in this
// package.

import (
	"os/exec"
	"syscall"

	"github.com/netdefense-io/ndagent/internal/util"
)

// devicePATH is the PATH that a root interactive shell has on FreeBSD/OPNsense.
// Re-exported from util for any tasks package code that references it directly.
const devicePATH = util.DevicePATH

// DeviceExecEnv returns a copy of the current process environment with the
// PATH entry set to the full root-interactive PATH. See util.DeviceExecEnv for
// full documentation.
func DeviceExecEnv() []string {
	return util.DeviceExecEnv()
}

// newDetachedHelperCmd builds the command for a helper script the agent forks
// and then outlives. The helper drives pkg(8), whose hook scripts and the
// OPNsense PHP behind them call tools in /usr/local by bare name, so it gets
// the device PATH instead of the stripped one the agent inherits from rc.d.
func newDetachedHelperCmd(path string, args ...string) *exec.Cmd {
	cmd := exec.Command(path, args...)
	cmd.Env = DeviceExecEnv()
	// Detach: own session, own process group, no controlling terminal —
	// pkg's `rc.d ndagent stop` sends SIGTERM to the agent's PID/PGID, not
	// to ours. Without Setsid the helper rides the same pgrp and dies too.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	return cmd
}
