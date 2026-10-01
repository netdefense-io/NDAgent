package tasks

// firmware_upgrade.go — FIRMWARE_UPGRADE task handler.
//
// Implements the mode × reboot matrix:
//
//	minor + reboot=false  → exec opnsense-update -pt (packages only, synchronous)
//	minor + reboot=true   → REST POST /update (point release + auto-reboot)
//	major + reboot=true   → REST POST /upgrade (series upgrade + 1-2 reboots)
//	major + reboot=false  → FAILED (invalid; rejected at payload validation)
//
// Lifecycle:
//   - The task is marked on its row when the handler takes it up, and the run is
//     recorded in full, then stamped as triggered, before anything is triggered
//     (firmware_meta.go): the row can outlive the handler, and the reconciler
//     has to tell a run that started from one that never did.
//   - Only one FIRMWARE_UPGRADE runs at a time in this process; the others wait
//     (bounded by their own expiry) and, if the agent stops meanwhile, are left
//     IN_PROGRESS with their marker.
//   - reboot=false: the handler sends IN_PROGRESS, runs opnsense-update as its
//     own child and normally sends the terminal response before returning. If a
//     package in the run replaces the agent's own, the agent is stopped under
//     it and the row is left IN_PROGRESS.
//   - reboot=true (minor/major, firmware_rest.go): the handler triggers the REST
//     apply and watches. The run is OPNsense's detached process tree; the handler
//     ends with a verdict from firmware.Evaluate, or leaves the row IN_PROGRESS
//     when the connection is lost or the box reboots (it then holds its place
//     until the reboot stops the agent).
//   - A row left IN_PROGRESS is resolved by the reconciler (internal/core) from
//     the device's state, never by the drain's blanket rule.

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/netdefense-io/ndagent/internal/firmware"
	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/network"
	"github.com/netdefense-io/ndagent/internal/opnapi"
	"github.com/netdefense-io/ndagent/internal/util"
)

// firmwareMessageMaxBytes is the safe upper bound for the JSON message we
// put in Task.Message. NDBroker truncates at MAX_MESSAGE_BYTES = 16 KiB;
// we target 15 KiB to leave headroom for the broker's own framing.
const firmwareMessageMaxBytes = 15 * 1024

// firmwareLogTailMaxBytes is the maximum number of bytes we allow for the
// log_tail value when building the JSON message, so the whole object stays
// well under firmwareMessageMaxBytes even in worst-case log output.
const firmwareLogTailMaxBytes = 4 * 1024

// firmwareSuccessJSON serialises data as compact JSON to use as the
// Task.Message for successful FIRMWARE_UPGRADE outcomes. It caps the
// log_tail field at firmwareLogTailMaxBytes bytes and drops the
// package_names list (package count is already in packages_applied) to
// keep the payload compact. Returns the JSON string; falls back to an
// empty JSON object "{}" only if json.Marshal itself fails (which cannot
// happen for a map[string]interface{} with well-typed values).
func firmwareSuccessJSON(data map[string]interface{}) string {
	// Cap log_tail to avoid blowing the broker's 16 KiB message limit.
	if lt, ok := data["log_tail"].(string); ok && len(lt) > firmwareLogTailMaxBytes {
		data["log_tail"] = lt[len(lt)-firmwareLogTailMaxBytes:]
	}
	// Drop package_names — the count is in packages_applied; the full list
	// can be very long and is not consumed by either surface (NDCLI/NDWeb).
	delete(data, "package_names")

	b, err := json.Marshal(data)
	if err != nil {
		// Unreachable for well-typed map values, but be safe.
		return "{}"
	}
	s := string(b)
	// Final safety net: if the JSON somehow still exceeds our limit, truncate
	// gracefully and return a minimal fallback so the task is still parseable
	// as a firmware result (resolved_mode is enough for the UIs to detect it).
	if len(s) > firmwareMessageMaxBytes {
		// This can only happen if data has an unexpected large field. Remove
		// everything optional and re-marshal the core fields only.
		core := map[string]interface{}{
			"resolved_mode": data["resolved_mode"],
			"from_version":  data["from_version"],
			"to_version":    data["to_version"],
			"applied":       data["applied"],
			"no_update":     data["no_update"],
		}
		if b2, err2 := json.Marshal(core); err2 == nil {
			return string(b2)
		}
	}
	return s
}

// firmwareCheckPollInterval is how often we poll GET /core/firmware/running
// while waiting for a TriggerFirmwareCheck to complete. 3 s is responsive
// enough without flooding the OPNsense API.
const firmwareCheckPollInterval = 3 * time.Second

// firmwareCheckTimeout is the maximum time we wait for the firmware daemon to
// report "ready" after a check is triggered. After a major series upgrade the
// catalog fetch is a cold network round-trip; 120 s is generous but bounded.
// On timeout we log WARN and fall through to the /status read anyway.
const firmwareCheckTimeout = 120 * time.Second

// firmwareCheckPollIntervalVar is the poll-interval indirection for tests
// (mirrors the upgradeStatusPollInterval pattern).
var firmwareCheckPollIntervalVar = firmwareCheckPollInterval

// firmwareCheckTimeoutVar is the timeout indirection for tests.
var firmwareCheckTimeoutVar = firmwareCheckTimeout

// opnAPIClientForFirmware is the indirection for tests — production wires in
// a real *opnapi.Client via the ws.OPNsenseClient() accessor.
var opnAPIClientForFirmware firmwareOPNAPIClient

// firmwareSendResponse is the indirection point every FIRMWARE_UPGRADE path uses
// to emit terminal task responses. Tests override this to capture calls without
// needing a real WebSocket connection. The production value delegates to the
// standard SendTaskResponse helper.
//
// Signature mirrors SendTaskResponse: (ws, taskID, result) → error.
var firmwareSendResponse = func(ws *network.WebSocketClient, taskID string, result TaskResult) error {
	return SendTaskResponse(ws, taskID, result)
}

// firmwareSendInProgress is the indirection for IN_PROGRESS sends. Tests can
// override to a no-op or recorder.
var firmwareSendInProgress = func(ws *network.WebSocketClient, taskID, message string) error {
	return SendInProgressResponse(ws, taskID, message)
}

// firmwareOPNAPIClient is the narrow interface the handler needs from opnapi.
// Keeping it narrow means tests can implement a lightweight stub without
// carrying the full Client.
type firmwareOPNAPIClient interface {
	TriggerFirmwareCheck(ctx context.Context) error
	GetFirmwareUpgradeStatus(ctx context.Context) (*opnapi.FirmwareUpgradeStatus, error)
	TriggerFirmwareUpdate(ctx context.Context) (*opnapi.FirmwareUpdateResponse, error)
	TriggerFirmwareUpgrade(ctx context.Context) (*opnapi.FirmwareUpgradeResponse, error)
	GetFirmwareUpgradeProgress(ctx context.Context) (*opnapi.FirmwareProgressStatus, error)
	GetFirmwareRunning(ctx context.Context) (*opnapi.FirmwareRunning, error)
	InstalledRelease(ctx context.Context) (opnapi.ProductRelease, error)
}

// firmwareGetSuffixFunc is the indirection for reading the firmware type
// suffix from the OPNsense pluginctl command. Tests override this to avoid
// shelling out.
var firmwareGetSuffixFunc = getFirmwareSuffixOnDevice

// getFirmwareSuffixOnDevice runs `pluginctl -g system.firmware.type` and
// returns the trimmed result. An empty result (standard OPNsense) returns "".
func getFirmwareSuffixOnDevice(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "/usr/local/sbin/pluginctl", "-g", "system.firmware.type")
	cmd.Env = DeviceExecEnv()
	out, err := cmd.Output()
	if err != nil {
		// pluginctl exits non-zero when the key is unset — that means standard
		// OPNsense with no suffix. Treat exit errors as empty suffix.
		return "", nil
	}
	raw := strings.TrimSpace(string(out))
	if raw == "" {
		return "", nil
	}
	return "-" + raw, nil
}

// firmwareUpgradePayload is the wire-side payload for FIRMWARE_UPGRADE.
// Mirrors the NDDataModels FirmwareUpgradePayload contract.
type firmwareUpgradePayload struct {
	// Mode must be "minor" or "major".
	Mode string `json:"mode"`
	// Reboot controls whether to apply only packages (false, minor only)
	// or trigger a full OPNsense-managed update with reboot (true).
	// Default: true. major+reboot=false is invalid.
	Reboot bool `json:"reboot"`
	// CheckFirst triggers a fresh /check before reading /status.
	// Default: true.
	CheckFirst bool `json:"check_first"`
	// DryRun reports the plan and exits without applying anything.
	// Default: false.
	DryRun bool `json:"dry_run"`
}

// parseFirmwareUpgradePayload extracts and validates the payload from the
// task Command. Returns an error for unknown modes or major+reboot=false.
func parseFirmwareUpgradePayload(cmd network.Command) (*firmwareUpgradePayload, error) {
	p := &firmwareUpgradePayload{
		// Defaults per contract
		Reboot:     true,
		CheckFirst: true,
	}

	if cmd.Payload == nil {
		return nil, fmt.Errorf("payload is required")
	}

	if mode, ok := cmd.Payload["mode"].(string); ok {
		p.Mode = mode
	}
	if p.Mode == "" {
		return nil, fmt.Errorf("mode is required (\"minor\" or \"major\")")
	}
	if p.Mode != "minor" && p.Mode != "major" {
		return nil, fmt.Errorf("mode must be \"minor\" or \"major\", got %q", p.Mode)
	}

	// Reboot: explicit false overrides the default of true.
	if rebootRaw, ok := cmd.Payload["reboot"]; ok {
		switch v := rebootRaw.(type) {
		case bool:
			p.Reboot = v
		case float64:
			p.Reboot = v != 0
		}
	}

	// CheckFirst: explicit false overrides default of true.
	if cfRaw, ok := cmd.Payload["check_first"]; ok {
		switch v := cfRaw.(type) {
		case bool:
			p.CheckFirst = v
		case float64:
			p.CheckFirst = v != 0
		}
	}

	if drRaw, ok := cmd.Payload["dry_run"]; ok {
		switch v := drRaw.(type) {
		case bool:
			p.DryRun = v
		case float64:
			p.DryRun = v != 0
		}
	}

	// Cross-field validation: major + reboot=false is explicitly invalid.
	if p.Mode == "major" && !p.Reboot {
		return nil, fmt.Errorf("major mode requires reboot=true; major upgrades cannot run without a reboot")
	}

	return p, nil
}

// HandleFirmwareUpgrade handles the FIRMWARE_UPGRADE task type.
// See the file-level comment for the mode × reboot matrix.
func HandleFirmwareUpgrade(ctx context.Context, ws *network.WebSocketClient, cmd network.Command) error {
	log := logging.Named("FIRMWARE_UPGRADE")

	log.Infow("Received FIRMWARE_UPGRADE command", "task_id", cmd.TaskID)

	// ── Test-mode guard ──────────────────────────────────────────────────────
	// dry_run is permitted even in test mode (it doesn't mutate anything).
	// Real applies (exec or REST POST) are blocked in test mode.
	isTestMode := ws.IsTestMode()

	// ── Parse + validate payload ─────────────────────────────────────────────
	payload, err := parseFirmwareUpgradePayload(cmd)
	if err != nil {
		log.Warnw("Invalid FIRMWARE_UPGRADE payload", "task_id", cmd.TaskID, "error", err)
		return firmwareSendResponse(ws, cmd.TaskID, NewFailureResult("Invalid payload: "+err.Error()))
	}

	log.Infow("FIRMWARE_UPGRADE parameters",
		"task_id", cmd.TaskID,
		"mode", payload.Mode,
		"reboot", payload.Reboot,
		"check_first", payload.CheckFirst,
		"dry_run", payload.DryRun,
		"test_mode", isTestMode,
	)

	// Real apply in test mode → block (dry_run is exempt).
	if isTestMode && !payload.DryRun {
		log.Warn("Test mode: FIRMWARE_UPGRADE blocked (use dry_run=true to preview)")
		return firmwareSendResponse(ws, cmd.TaskID,
			NewFailureResult("FIRMWARE_UPGRADE blocked in test mode (set dry_run=true to preview the plan)"))
	}

	// ── Acquire OPNsense client ──────────────────────────────────────────────
	var client firmwareOPNAPIClient
	if opnAPIClientForFirmware != nil {
		client = opnAPIClientForFirmware
	} else if raw := ws.GetAPIClient(); raw != nil {
		client = raw
	}
	if client == nil {
		return firmwareSendResponse(ws, cmd.TaskID,
			NewFailureResult("OPNsense API client not configured (api_key/api_secret missing)"))
	}

	// ── One firmware task at a time ──────────────────────────────────────────
	// OPNsense runs one firmware job at a time and a request that finds its lock
	// held is dropped. Two tasks are dispatched in the same second every Sunday
	// (the daily and the weekly schedule) and would each trigger, poll the same
	// progress log and be judged by the other's run. The second waits for the
	// first to end and then does its own work: normally there is nothing left to
	// apply and it completes as a no-op. A first run that ends in a reboot ends
	// with the agent being stopped, and the second, which never started, is left
	// for the reconciler (the marker below is what tells it so).
	marked := recordFirmwareMarker(ws, cmd, log, payload.Mode, payload.Reboot)
	waitCtx, endWait := firmwareWaitContext(ctx, cmd)
	defer endWait()
	release, err := firmware.Acquire(waitCtx, func() {
		log.Infow("Another firmware task is running on this device; waiting for it", "task_id", cmd.TaskID)
		if err := firmwareSendInProgress(ws, cmd.TaskID,
			"Waiting for another firmware task on this device to finish..."); err != nil {
			log.Warnw("Failed to send IN_PROGRESS", "error", err)
		}
	})
	if err != nil {
		if ctx.Err() != nil {
			return leftBeforeTheTrigger(ctx, log, cmd, marked)
		}
		return firmwareSendResponse(ws, cmd.TaskID, NewFailureResult(taskExpiredWhileWaiting))
	}
	defer release()
	if firmwareExpired(cmd) {
		return firmwareSendResponse(ws, cmd.TaskID, NewFailureResult(taskExpiredWhileWaiting))
	}

	// ── Send IN_PROGRESS ─────────────────────────────────────────────────────
	if err := firmwareSendInProgress(ws, cmd.TaskID, "Checking firmware status..."); err != nil {
		log.Warnw("Failed to send IN_PROGRESS", "error", err)
	}

	// ── Optional fresh check ─────────────────────────────────────────────────
	if payload.CheckFirst {
		log.Infow("Triggering firmware check", "task_id", cmd.TaskID)
		if err := client.TriggerFirmwareCheck(ctx); err != nil {
			log.Warnw("Firmware check trigger failed; proceeding with cached status",
				"task_id", cmd.TaskID, "error", err)
		} else {
			waitForFirmwareReady(ctx, client, log)
		}
	}

	// ── Read /status → from_version + classification ─────────────────────────
	status, err := client.GetFirmwareUpgradeStatus(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return leftBeforeTheTrigger(ctx, log, cmd, marked)
		}
		return firmwareSendResponse(ws, cmd.TaskID,
			NewFailureResult("Failed to read firmware status: "+err.Error()))
	}

	// The version this task reports is the installed one, read from the local
	// version file: /status's top-level product_version is the cached result of
	// the last check. A real run insists on it (see the reboot paths); a preview
	// or a no-op can do with the status's own.
	fromVersion, versionErr := installedVersion(ctx, client)
	if versionErr != nil {
		log.Warnw("Could not read the installed release; using the firmware status's",
			"task_id", cmd.TaskID, "error", versionErr)
		fromVersion = status.ProductVersion
	}
	plan := firmware.PlannedPackages(status)
	log.Infow("Firmware status read",
		"from_version", fromVersion,
		"opnsense_status", status.Status,
		"upgrade_packages", len(status.UpgradePackages),
		"upgrade_sets", len(status.UpgradeSets),
		"upgrade_major_version", status.UpgradeMajorVersion,
		"needs_reboot", status.NeedsReboot,
	)

	// ── Classify available update ─────────────────────────────────────────────
	// Classification from plan:
	//   major signals: upgrade_sets non-empty OR upgrade_major_version/upgrade_major_message non-empty
	//   minor signals: upgrade_packages non-empty (no major signals)
	//   CORE_NEXT is informational; ignored.
	hasMajor := len(status.UpgradeSets) > 0 ||
		status.UpgradeMajorVersion != "" ||
		status.UpgradeMajorMessage != ""
	hasMinor := len(status.UpgradePackages) > 0

	// ── No-op short-circuit ──────────────────────────────────────────────────
	// Nothing to apply in the requested mode → COMPLETED with no_update=true.
	// Never FAILED for absence of work.
	switch payload.Mode {
	case "minor":
		if !hasMinor {
			log.Infow("No minor updates available; no-op", "task_id", cmd.TaskID)
			d := map[string]interface{}{
				"resolved_mode":    payload.Mode,
				"from_version":     fromVersion,
				"no_update":        true,
				"applied":          false,
				"reboot_performed": false,
				"opnsense_status":  status.Status,
			}
			return firmwareSendResponse(ws, cmd.TaskID, TaskResult{
				Success: true,
				Message: firmwareSuccessJSON(d),
			})
		}
	case "major":
		if !hasMajor {
			log.Infow("No major updates available; no-op", "task_id", cmd.TaskID)
			d := map[string]interface{}{
				"resolved_mode":    payload.Mode,
				"from_version":     fromVersion,
				"no_update":        true,
				"applied":          false,
				"reboot_performed": false,
				"opnsense_status":  status.Status,
			}
			return firmwareSendResponse(ws, cmd.TaskID, TaskResult{
				Success: true,
				Message: firmwareSuccessJSON(d),
			})
		}
	}

	// ── Dry-run: report plan and exit ────────────────────────────────────────
	if payload.DryRun {
		toVersion := ""
		reboots := 0
		if payload.Reboot {
			reboots = 1
		}
		if payload.Mode == "major" {
			reboots = 2 // major can reboot twice
			toVersion = status.UpgradeMajorVersion
		} else if toVersion = firmware.CoreVersion(plan); toVersion == "" {
			// A plan that leaves the core package alone leaves the release alone.
			toVersion = fromVersion
		}

		log.Infow("DRY_RUN: plan computed", "task_id", cmd.TaskID,
			"mode", payload.Mode, "from", fromVersion, "to", toVersion)

		d := map[string]interface{}{
			"resolved_mode":    payload.Mode,
			"from_version":     fromVersion,
			"to_version":       toVersion,
			"reboot_performed": false,
			"reboots_expected": reboots,
			"applied":          false,
			"dry_run":          true,
			"no_update":        false,
			"packages_applied": firmware.PackagesApplied(plan),
			"mixed_state":      false,
			"opnsense_status":  status.Status,
			"needs_reboot":     status.NeedsReboot,
		}
		return firmwareSendResponse(ws, cmd.TaskID, TaskResult{
			Success: true,
			Message: firmwareSuccessJSON(d),
		})
	}

	// ── Dispatch by mode × reboot ────────────────────────────────────────────
	switch {
	case payload.Mode == "minor" && !payload.Reboot:
		return handleMinorNoReboot(ctx, ws, cmd, client, payload, status)
	case payload.Mode == "minor" && payload.Reboot:
		return handleMinorWithReboot(ctx, ws, cmd, client, payload, status)
	case payload.Mode == "major" && payload.Reboot:
		return handleMajorWithReboot(ctx, ws, cmd, client, payload, status)
	default:
		// Unreachable: parseFirmwareUpgradePayload already rejected major+reboot=false.
		return firmwareSendResponse(ws, cmd.TaskID,
			NewFailureResult(fmt.Sprintf("unsupported mode/reboot combination: mode=%s reboot=%v",
				payload.Mode, payload.Reboot)))
	}
}

// taskExpiredWhileWaiting is what a task is failed with when its own lifetime
// ran out before it got its turn: NDManager has already given up on it, and
// running it now would apply an update nobody is waiting for.
const taskExpiredWhileWaiting = "The firmware task expired while it waited for another firmware task on this device; " +
	"nothing was started."

// firmwareWaitContext bounds the wait for the firmware slot by the task's own
// expiry, when the command carries one.
func firmwareWaitContext(ctx context.Context, cmd network.Command) (context.Context, context.CancelFunc) {
	if cmd.ExpiresAt <= 0 {
		return context.WithCancel(ctx)
	}
	remaining := time.Unix(cmd.ExpiresAt, 0).Sub(firmwareNow())
	if remaining < time.Nanosecond {
		remaining = time.Nanosecond
	}
	return context.WithTimeout(ctx, remaining)
}

// firmwareExpired reports whether the task's own lifetime has run out.
func firmwareExpired(cmd network.Command) bool {
	return cmd.ExpiresAt > 0 && !firmwareNow().Before(time.Unix(cmd.ExpiresAt, 0))
}

// leftBeforeTheTrigger ends a task whose context was cancelled (the connection
// dropped, or the agent is stopping) before it triggered anything. The row is
// left IN_PROGRESS with the marker, so the reconciler says the task never
// started; the dispatcher, given an error, would record the generic "task was
// cancelled" instead. Without a marker there is nothing for the reconciler to
// go on and the dispatcher's record is all there is.
func leftBeforeTheTrigger(ctx context.Context, log interface{ Infow(string, ...interface{}) }, cmd network.Command, marked bool) error {
	if !marked {
		return ctx.Err()
	}
	log.Infow("Context cancelled before the firmware update was triggered; leaving the task IN_PROGRESS for the reconciler",
		"task_id", cmd.TaskID)
	return nil
}

// waitForFirmwareReady polls GET /core/firmware/running until OPNsense reports
// the firmware daemon is idle (status == "ready"), meaning the background
// catalog refresh triggered by TriggerFirmwareCheck has completed and
// /status is safe to read.
//
// Uses util.ShutdownAwareSleep between polls so the loop respects graceful
// agent shutdown. On timeout (firmwareCheckTimeoutVar) it logs WARN and
// returns — the caller falls through to the /status read with whatever
// data is cached. This matches the "degraded but proceed" contract for
// check_first failures.
func waitForFirmwareReady(
	ctx context.Context,
	client firmwareOPNAPIClient,
	log interface {
		Infow(string, ...interface{})
		Warnw(string, ...interface{})
	},
) {
	deadline := time.Now().Add(firmwareCheckTimeoutVar)
	log.Infow("Waiting for firmware daemon to report ready",
		"poll_interval", firmwareCheckPollIntervalVar.String(),
		"timeout", firmwareCheckTimeoutVar.String())

	for {
		running, err := client.GetFirmwareRunning(ctx)
		if err != nil {
			log.Warnw("GetFirmwareRunning error; proceeding with cached /status", "error", err)
			return
		}
		if running.Status == "ready" {
			log.Infow("Firmware daemon ready; proceeding to read /status")
			return
		}
		log.Infow("Firmware daemon still running; waiting", "daemon_status", running.Status)

		if time.Now().After(deadline) {
			log.Warnw("Timed out waiting for firmware daemon to become ready; proceeding with cached /status",
				"timeout", firmwareCheckTimeoutVar.String())
			return
		}

		if err := util.ShutdownAwareSleep(ctx, firmwareCheckPollIntervalVar); err != nil {
			// Context cancelled (shutdown). Return immediately; the handler
			// will also see the cancelled context on the next API call.
			log.Warnw("Context cancelled while waiting for firmware daemon", "error", err)
			return
		}
	}
}

// handleMinorNoReboot implements: minor + reboot=false
// Exec opnsense-update -pt "opnsense${SUFFIX}" synchronously.
// This is the "split-and-apply" path that leaves base/kernel deferred.
//
// Success determination (Blocker A fix):
// exit 0 from opnsense-update is the PRIMARY truth of a successful apply.
// OPNsense caches the last /check result in /status, so an immediate re-read
// of /status after the exec returns pre-apply data until a new /check runs.
// We therefore derive all result fields from the PRE-apply /status snapshot
// (initialStatus) rather than trusting a post-apply /status count comparison:
//   - packages_applied  = non-base/kernel packages that were pending pre-exec
//   - mixed_state       = base or kernel was in the pre-apply pending list
//   - to_version        = initialStatus.ProductLatest (unchanged by exec)
//
// A post-apply /status read is still attempted for the ABI / series safety
// guard (cross-series slip detection), but its failure or stale counts do NOT
// cause the task to be reported as FAILED when exit was 0.
func handleMinorNoReboot(
	ctx context.Context,
	ws *network.WebSocketClient,
	cmd network.Command,
	client firmwareOPNAPIClient,
	payload *firmwareUpgradePayload,
	initialStatus *opnapi.FirmwareUpgradeStatus,
) error {
	log := logging.Named("FIRMWARE_UPGRADE")

	fromVersion, err := installedVersion(ctx, client)
	if err != nil {
		return firmwareSendResponse(ws, cmd.TaskID,
			NewFailureResult("Could not read the installed OPNsense release: "+err.Error()))
	}
	plan := firmware.PlannedPackages(initialStatus)
	pkgCount := firmware.PackagesApplied(plan)

	// The exec below is the agent's own child. If a package in the run replaces
	// the agent's, the agent is stopped and the row is left IN_PROGRESS, so what
	// the run started from is recorded first.
	meta := recordFirmwareRun(ws, cmd, log, "minor", false, fromVersion, initialStatus)

	if err := firmwareSendInProgress(ws, cmd.TaskID,
		fmt.Sprintf("Applying %d package(s) without reboot...", pkgCount)); err != nil {
		log.Warnw("Failed to send IN_PROGRESS", "error", err)
	}

	// Derive suffix from the on-device pluginctl; validate it before exec.
	suffix, err := firmwareGetSuffixFunc(ctx)
	if err != nil {
		return firmwareSendResponse(ws, cmd.TaskID,
			NewFailureResult("Could not determine firmware suffix: "+err.Error()))
	}
	if err := ValidateFirmwareSuffix(suffix); err != nil {
		return firmwareSendResponse(ws, cmd.TaskID,
			NewFailureResult("Invalid firmware suffix: "+err.Error()))
	}

	log.Infow("Executing opnsense-update",
		"task_id", cmd.TaskID,
		"suffix", suffix,
		"package", "opnsense"+suffix,
		"packages_pending", pkgCount,
	)

	// Run the exec (synchronous). [Error path]
	markFirmwareTriggered(ws, cmd, log, &meta)
	result, err := RunFirmwarePackagesOnly(ctx, suffix)
	if err != nil {
		return firmwareSendResponse(ws, cmd.TaskID,
			NewFailureResult("Failed to execute opnsense-update: "+err.Error()))
	}

	// A cancelled context (the connection dropped, or the agent is stopping,
	// which a package in this very run can cause) kills opnsense-update, but pkg,
	// which it started, goes on. That is not a failed run and not a finished one:
	// the row is left IN_PROGRESS with the plan recorded above, and the
	// reconciler checks it once package tools have stopped.
	if ctx.Err() != nil && result.ExitCode != 0 {
		log.Infow("Context cancelled during opnsense-update; leaving the task IN_PROGRESS for the reconciler",
			"task_id", cmd.TaskID, "exit_code", result.ExitCode)
		return nil
	}

	// [Non-zero exit path]
	if result.ExitCode != 0 {
		log.Warnw("opnsense-update exited non-zero",
			"task_id", cmd.TaskID,
			"exit_code", result.ExitCode,
			"stderr", result.Stderr,
		)
		return firmwareSendResponse(ws, cmd.TaskID, NewFailureResult(
			fmt.Sprintf("opnsense-update exited with code %d: %s",
				result.ExitCode, firstNonEmptyLogLine(result.Stderr))))
	}

	// ── exit 0: packages applied ──────────────────────────────────────────────
	// exit 0 is the source of truth for a successful apply. Derive result fields
	// from the PRE-apply snapshot to avoid reading a stale /status cache.
	preNonRebootPkgs := firmware.PackagesApplied(plan)

	// mixed_state: base or kernel was in the pending list pre-exec — they remain
	// deferred (expected outcome of the packages-only path).
	mixedState := firmware.HasBaseOrKernel(plan)

	// The release the run reaches is the core package's planned version. The
	// status's product_latest is derived from the installed changelog and does
	// not move with the update, so it is not used.
	toVersion := firmware.CoreVersion(plan)
	if toVersion == "" {
		toVersion = fromVersion
	}

	log.Infow("opnsense-update exit 0; packages applied from pre-apply snapshot",
		"task_id", cmd.TaskID,
		"packages_applied", preNonRebootPkgs,
		"mixed_state", mixedState,
		"to_version", toVersion,
	)

	// ── Optional post-apply ABI / series guard ────────────────────────────────
	// Read /status once more (best-effort) to detect a cross-series slip.
	// /status may still be stale (cached from the last /check); we only
	// fail on hard guard violations (series or ABI changed), never on count
	// comparisons against stale data.
	log.Infow("Re-reading /status for ABI/series guard (best-effort)", "task_id", cmd.TaskID)
	if postStatus, postErr := client.GetFirmwareUpgradeStatus(ctx); postErr != nil {
		log.Warnw("Post-apply /status read failed; skipping ABI/series guard", "error", postErr)
	} else {
		if postStatus.ProductSeries != initialStatus.ProductSeries {
			return firmwareSendResponse(ws, cmd.TaskID, NewFailureResult(
				fmt.Sprintf("post-apply series changed unexpectedly: %s → %s",
					initialStatus.ProductSeries, postStatus.ProductSeries)))
		}
		if postStatus.ProductABI != initialStatus.ProductABI {
			return firmwareSendResponse(ws, cmd.TaskID, NewFailureResult(
				fmt.Sprintf("post-apply ABI changed unexpectedly: %s → %s",
					initialStatus.ProductABI, postStatus.ProductABI)))
		}
	}

	// [Packages applied path]
	return sendMinorNoRebootResult(ws, cmd.TaskID, fromVersion, toVersion, initialStatus, result, false, mixedState, preNonRebootPkgs)
}

// packageNames returns the package names from a slice of FirmwarePackageEntry.
func packageNames(pkgs []opnapi.FirmwarePackageEntry) []string {
	names := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		names = append(names, p.Name)
	}
	return names
}

// sendMinorNoRebootResult sends the terminal task response for the minor/no-reboot path.
//
// preStatus is the PRE-apply snapshot (used for package names of what was
// remaining after the apply — base/kernel still in the list are the deferred
// ones). packagesApplied is the count of non-base/kernel packages applied,
// derived from the pre-apply snapshot.
func sendMinorNoRebootResult(
	ws *network.WebSocketClient,
	taskID string,
	fromVersion, toVersion string,
	preStatus *opnapi.FirmwareUpgradeStatus,
	execResult *FirmwareExecResult,
	verifyFailed bool,
	mixedState bool,
	packagesApplied int,
) error {
	// remaining_pending: base/kernel packages still in the pre-apply list
	// (they were deferred by the packages-only exec). The list used here is
	// intentionally from the pre-apply snapshot because the post-apply /status
	// may still be stale.
	remaining := make([]string, 0)
	for _, p := range preStatus.UpgradePackages {
		if p.Name == "base" || p.Name == "kernel" {
			remaining = append(remaining, p.Name)
		}
	}

	data := map[string]interface{}{
		"resolved_mode":     "minor",
		"from_version":      fromVersion,
		"to_version":        toVersion,
		"reboot_performed":  false,
		"reboots_expected":  0,
		"applied":           !verifyFailed,
		"no_update":         false,
		"mixed_state":       mixedState,
		"opnsense_status":   preStatus.Status,
		"log_tail":          execResult.LogTail,
		"packages_applied":  packagesApplied,
		"remaining_pending": remaining,
	}
	return firmwareSendResponse(ws, taskID, TaskResult{
		Success: true,
		Message: firmwareSuccessJSON(data),
	})
}

// firstNonEmptyLogLine returns the first non-empty line from s. Used to
// surface the most useful part of opnsense-update stderr in the result.
func firstNonEmptyLogLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			return t
		}
	}
	return s
}
