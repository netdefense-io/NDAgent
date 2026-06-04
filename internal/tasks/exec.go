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

import (
	"os"
	"strings"
)

// devicePATH is the PATH that a root interactive shell has on FreeBSD/OPNsense.
// It extends the rc.d default (/sbin:/bin:/usr/sbin:/usr/bin) with the
// /usr/local directories so that on-device tools like opnsense-update and
// pluginctl — and any subprocesses they invoke by name — can be resolved.
const devicePATH = "/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin"

// DeviceExecEnv returns a copy of the current process environment with the
// PATH entry set to devicePATH. If PATH is not present in os.Environ() it is
// added. All other environment variables are preserved as-is.
//
// Use this as cmd.Env for any exec.CommandContext call that runs a binary
// located under /usr/local/sbin or /usr/local/bin, or whose subprocess chain
// might invoke such binaries by unqualified name.
func DeviceExecEnv() []string {
	base := os.Environ()
	out := make([]string, 0, len(base))
	found := false
	for _, kv := range base {
		if strings.HasPrefix(kv, "PATH=") {
			out = append(out, "PATH="+devicePATH)
			found = true
		} else {
			out = append(out, kv)
		}
	}
	if !found {
		out = append(out, "PATH="+devicePATH)
	}
	return out
}
