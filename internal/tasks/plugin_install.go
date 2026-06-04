package tasks

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/network"
	"github.com/netdefense-io/ndagent/internal/pkgmgr"
	"github.com/netdefense-io/ndagent/internal/taskstore"
	"github.com/netdefense-io/ndagent/pkg/version"
)

// pkgmgrQuery is the indirection point for tests. Production uses
// pkgmgr.Query; unit tests stub it to avoid shelling out to pkg(8).
var pkgmgrQuery = pkgmgr.Query

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

	// Persist package name and target version in the task registry so the
	// boot-time drain can perform a version-aware resolution without the
	// original command payload. Best-effort — a store write failure does not
	// prevent the install from proceeding.
	if store := ws.GetTaskStore(); store != nil {
		meta := taskstore.PluginInstallMeta{
			PackageName:   version.PackageName,
			TargetVersion: targetVersion,
		}
		if err := store.SetTaskMeta(cmd.TaskID, meta); err != nil {
			log.Warnw("Failed to persist PLUGIN_INSTALL metadata; drain fallback may be imprecise",
				"task_id", cmd.TaskID, "error", err)
		}
	}

	// Idempotency check: if the requested version is already installed,
	// skip the helper-fork + agent-restart cycle entirely. Without this
	// pkg(8) treats "install $name $sameversion" as a no-op, the new
	// agent boots on the same version, and NDBroker's post-install
	// version-compare path marks the task FAILED because version did
	// not change. See `routers/websocket.py` post-auth update path.
	//
	// Errors querying pkg(8) (binary missing, transient signal, etc.)
	// fall through to the normal install path — better to attempt the
	// install than to fail-closed on a query glitch.
	if alreadyAt, msg := alreadyAtTargetVersion(ctx, log, targetVersion); alreadyAt {
		log.Infow("PLUGIN_INSTALL is a no-op; reporting COMPLETED without forking helper",
			"task_id", cmd.TaskID, "package", version.PackageName, "version", version.Version,
		)
		return SendTaskResponse(ws, cmd.TaskID, NewSuccessResult(msg))
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

	// Helper script args: $1=package, $2=target_version (empty = latest),
	// $3=task_id. The helper writes a drop file at
	// /var/db/ndagent/pending-results/<task_id>.json containing the pkg
	// exit code; on the next agent boot the drain step reconciles that
	// file into the task store and replays the task_response (see
	// internal/taskstore). $2 must be passed (even empty) so $3 lines up.
	args := []string{version.PackageName, targetVersion, cmd.TaskID}
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

// alreadyAtTargetVersion reports whether the requested install would be a
// no-op. Returns (true, message) if the agent is already at the requested
// version, or (false, "") otherwise.
//
// Two cases:
//   - target == "": "latest". No-op if the running version equals the
//     latest version offered by any configured pkg repository (`pkg
//     rquery -U`). On query failure we fall through and let the install
//     attempt happen — pkg may still know better than us about the
//     repo state.
//   - target != "<some semver>": no-op if the running version equals
//     target. We compare against the build-time-stamped version constant
//     rather than `pkg query` because they must agree (pkg installed it
//     in the first place); if the in-memory and on-disk versions diverge,
//     something else is broken and we want the helper to run.
func alreadyAtTargetVersion(ctx context.Context, log *zap.SugaredLogger, target string) (bool, string) {
	current := version.Version
	if current == "" || current == "unknown" || current == "dev" {
		return false, ""
	}

	if target != "" {
		if current == target {
			return true, fmt.Sprintf("Already at version %s; no install performed.", current)
		}
		return false, ""
	}

	// target == "" → "latest". Need to know what "latest" means right now.
	statuses, err := pkgmgrQuery(ctx, []string{version.PackageName})
	if err != nil || len(statuses) == 0 {
		log.Warnw("pkg query failed; proceeding with install attempt",
			"package", version.PackageName, "error", err,
		)
		return false, ""
	}
	available := statuses[0].AvailableVersion
	if available == "" {
		// Package not in any repo we know about. Let the install attempt
		// surface the real failure; we have no basis to short-circuit.
		return false, ""
	}
	if current == available {
		return true, fmt.Sprintf("Already at latest version %s; no install performed.", current)
	}
	return false, ""
}
