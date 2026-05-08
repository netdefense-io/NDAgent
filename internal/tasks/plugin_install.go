package tasks

import (
	"context"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/network"
	"github.com/netdefense-io/ndagent/pkg/version"
)

// helperScriptPath is the on-device path of the detached pkg(8) wrapper
// shipped by the os-netdefense* package. It must outlive the agent process
// (pkg's pre-deinstall hook will kill us mid-transaction), so the helper is
// started in its own session via Setsid and inherits no agent FDs.
const helperScriptPath = "/usr/local/sbin/ndagent-plugin-install.sh"

// pluginInstallPayload is the wire-side payload subset HandlePluginInstall
// reads. NDManager additionally snapshots previous_version + sets
// expires_at on the row, but the agent doesn't need either to act —
// NDBroker resolves the task lifecycle from device.version on reauth.
type pluginInstallPayload struct {
	TargetVersion string `json:"target_version,omitempty"`
}

// HandlePluginInstall handles the PLUGIN_INSTALL task: re-installs the
// NDAgent OPNsense plugin pkg, optionally pinned to a specific semver.
//
// Mirrors HandleRestart in system.go: send IN_PROGRESS, sleep briefly to
// flush the WS frame, fork a detached helper, then RequestShutdown so the
// current agent dies cleanly before pkg's pre-deinstall does it for us.
// The helper survives both `rc.d ndagent stop` and `rc.d configd restart`
// (both run from the post-install transaction) by living in its own
// process session under init.
//
// The agent never sends a final task_response — by the time pkg finishes,
// the new binary is running and has no in-memory record of the task. The
// broker closes the lifecycle on the next WS auth via the version-compare
// path in routers/websocket.py.
func HandlePluginInstall(ctx context.Context, ws *network.WebSocketClient, cmd network.Command) error {
	log := logging.Named("PLUGIN_INSTALL")

	log.Infow("Received PLUGIN_INSTALL command",
		"task_id", cmd.TaskID,
		"package_name", version.PackageName,
		"current_version", version.Version,
	)

	if ws.IsTestMode() {
		log.Warn("Test mode detected - PLUGIN_INSTALL would normally fork pkg(8); proceeding with the helper invocation, which is itself test-mode-aware")
	}

	if version.PackageName == "unknown" || version.PackageName == "" {
		// An unstamped local build wouldn't know which channel package to
		// reinstall; refuse rather than guess.
		result := NewFailureResult("PLUGIN_INSTALL refused: PackageName not set at build time (unstamped local binary)")
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	var targetVersion string
	if cmd.Payload != nil {
		if v, ok := cmd.Payload["target_version"].(string); ok {
			targetVersion = v
		}
	}

	if _, err := os.Stat(helperScriptPath); err != nil {
		// Half-installed pkg or stripped binary. Fail fast so the operator
		// sees a clean FAILED rather than a silent IN_PROGRESS that never
		// closes (it'd eventually hit the 15-min timeout, but failing fast
		// is friendlier).
		result := NewFailureResult("PLUGIN_INSTALL helper missing at " + helperScriptPath + ": " + err.Error())
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	if err := SendInProgressResponse(ws, cmd.TaskID, "Initiating plugin install..."); err != nil {
		log.Errorw("Failed to send IN_PROGRESS response", "error", err)
	}

	// Let the IN_PROGRESS frame leave the box and the agent's other
	// goroutines settle before we fork the helper and shut ourselves down.
	time.Sleep(1 * time.Second)

	args := []string{version.PackageName}
	if targetVersion != "" {
		args = append(args, targetVersion)
	}
	cmdExec := exec.Command(helperScriptPath, args...)
	// Detach: own session, own process group, no controlling terminal —
	// pkg's `rc.d ndagent stop` sends SIGTERM to the agent's PID/PGID, not
	// to ours. Without Setsid the helper rides the same pgrp and dies too.
	cmdExec.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmdExec.Stdout = nil
	cmdExec.Stderr = nil
	cmdExec.Stdin = nil

	if err := cmdExec.Start(); err != nil {
		log.Errorw("Failed to start plugin-install helper",
			"error", err,
			"helper", helperScriptPath,
		)
		result := NewFailureResult("Failed to fork plugin-install helper: " + err.Error())
		return SendTaskResponse(ws, cmd.TaskID, result)
	}

	log.Infow("Forked detached plugin-install helper",
		"pid", cmdExec.Process.Pid,
		"package", version.PackageName,
		"target_version", targetVersion,
	)

	// Release our wait4 entry — the helper is running in its own session
	// and we won't be around to reap it.
	_ = cmdExec.Process.Release()

	log.Info("Triggering graceful shutdown for plugin install")
	ws.RequestShutdown()

	return nil
}
