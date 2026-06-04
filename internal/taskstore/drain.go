package taskstore

import (
	"context"
	"encoding/json"
	"time"
)

// Responder is the minimal surface the drain step needs from a
// WebSocket-like sender. `*network.WebSocketClient` satisfies this; tests
// pass a stub. Kept narrow so this package doesn't import internal/network
// and cause an import cycle (network imports taskstore).
type Responder interface {
	SendTaskResponse(taskID, status, message string, data map[string]interface{}) error
}

// PluginInstallChecker is called by the drain to determine whether a
// PLUGIN_INSTALL task actually succeeded when no drop file is present. The
// function should query the on-device pkg(8) database and return the
// installed version of the package (empty string if not installed or on
// error). The caller (lifecycle.go) wires in pkgmgr.Query so this package
// stays free of exec dependencies and import-cycle risks.
//
// packageName is from PluginInstallMeta.PackageName (e.g. "os-netdefense").
// targetVersion is from PluginInstallMeta.TargetVersion ("" means "latest").
//
// Return values:
//   - installedVersion: empty string if the package is not installed or the
//     check failed.
//   - err: non-nil only for hard errors that should be logged; a package
//     simply not being installed is not an error.
type PluginInstallChecker func(ctx context.Context, packageName, targetVersion string) (installedVersion string, err error)

// pluginInstallDropPollInterval controls how often we re-check the
// pending-results directory while waiting for a late drop file. Kept
// short so the 30-second drain budget isn't wasted on coarse sleeps.
// Package-level var so tests can override it.
var pluginInstallDropPollInterval = 500 * time.Millisecond

// pluginInstallDropWait is the total time we are willing to spend
// waiting for the helper to produce a drop file before falling back
// to the pkg-check path. Must be well under the 30-second drain
// budget; 5 seconds covers the typical post-install helper latency.
// Package-level var so tests can override it.
var pluginInstallDropWait = 5 * time.Second

// resolveStuckPluginInstall handles PLUGIN_INSTALL rows that are still
// IN_PROGRESS at boot time when no drop file is present, implementing a
// two-step race tolerance:
//
//  1. Poll for the drop file for up to pluginInstallDropWait. If it arrives
//     within the window, ReconcileDropFiles processes it and the row becomes
//     terminal before ResolveStuck runs.
//
//  2. If no drop file appears and a PluginInstallChecker is provided, query
//     the on-device pkg(8) for the installed version and compare it to the
//     target version stored at Begin time:
//     - installed == target (or target is "" and package is installed) →
//       COMPLETED (the pkg upgrade succeeded; helper write raced the restart)
//     - installed != target or package absent → FAILED
//
// When checker is nil (tests that don't wire pkg) or meta is absent, the
// function resolves FAILED ("helper did not produce result file") exactly as
// the previous ResolveStuck behaviour.
//
// Only PLUGIN_INSTALL rows with LifecycleHelperResolves are processed here;
// all other task types are left for the generic ResolveStuck path.
func resolveStuckPluginInstall(
	ctx context.Context,
	store *Store,
	pendingResultsDir string,
	checker PluginInstallChecker,
	logf func(string, ...interface{}),
) {
	rows, err := store.InProgressByType("PLUGIN_INSTALL")
	if err != nil {
		logf("drain/plugin-install: query IN_PROGRESS rows failed: %v", err)
		return
	}
	// Filter to LifecycleHelperResolves only — be surgical.
	var candidates []Record
	for _, r := range rows {
		if r.Lifecycle == LifecycleHelperResolves {
			candidates = append(candidates, r)
		}
	}
	if len(candidates) == 0 {
		return
	}

	logf("drain/plugin-install: %d PLUGIN_INSTALL IN_PROGRESS row(s); waiting up to %s for drop file",
		len(candidates), pluginInstallDropWait)

	// Phase 1: poll for drop file arrival.
	deadline := time.Now().Add(pluginInstallDropWait)
	for time.Now().Before(deadline) {
		// Check context first.
		select {
		case <-ctx.Done():
			return
		default:
		}

		applied, _ := ReconcileDropFiles(pendingResultsDir, store)
		if applied > 0 {
			logf("drain/plugin-install: reconciled %d drop file(s) during race-wait", applied)
		}

		// Re-check which candidates are still IN_PROGRESS by querying
		// the store once and building a set.
		remaining, err := store.InProgressByType("PLUGIN_INSTALL")
		if err != nil {
			logf("drain/plugin-install: re-query failed during race-wait: %v", err)
			break
		}
		inProgress := make(map[string]struct{}, len(remaining))
		for _, r := range remaining {
			inProgress[r.TaskID] = struct{}{}
		}
		var stillPending []Record
		for _, c := range candidates {
			if _, ok := inProgress[c.TaskID]; ok {
				stillPending = append(stillPending, c)
			}
		}
		candidates = stillPending
		if len(candidates) == 0 {
			logf("drain/plugin-install: all PLUGIN_INSTALL rows resolved via drop file")
			return
		}

		// Some still pending — sleep briefly and retry.
		select {
		case <-ctx.Done():
			return
		case <-time.After(pluginInstallDropPollInterval):
		}
	}

	// Phase 2: drop file did not arrive in time; fall back to pkg check.
	logf("drain/plugin-install: %d row(s) still IN_PROGRESS after drop-file wait; falling back to pkg check",
		len(candidates))

	for _, c := range candidates {
		resolveOnePluginInstall(ctx, store, c, checker, logf)
	}
}

// resolveOnePluginInstall resolves a single stuck PLUGIN_INSTALL row via the
// pkg-check fallback. It reads the PluginInstallMeta stored at Begin time,
// invokes the checker, and calls store.Complete with the appropriate status.
func resolveOnePluginInstall(
	ctx context.Context,
	store *Store,
	row Record,
	checker PluginInstallChecker,
	logf func(string, ...interface{}),
) {
	// Read metadata written at Begin time.
	meta, err := store.GetPluginInstallMeta(row.TaskID)
	if err != nil {
		logf("drain/plugin-install: task %s: failed to read task_meta (%v); marking FAILED", row.TaskID, err)
		_ = store.Complete(row.TaskID, StatusFailed, "helper did not produce result file", nil)
		return
	}
	if meta == nil || meta.PackageName == "" || checker == nil {
		// No metadata or no checker → cannot verify; mark FAILED.
		logf("drain/plugin-install: task %s: no metadata or checker unavailable; marking FAILED", row.TaskID)
		_ = store.Complete(row.TaskID, StatusFailed, "helper did not produce result file", nil)
		return
	}

	logf("drain/plugin-install: task %s: querying pkg for package=%s target=%q",
		row.TaskID, meta.PackageName, meta.TargetVersion)

	installedVersion, err := checker(ctx, meta.PackageName, meta.TargetVersion)
	if err != nil {
		logf("drain/plugin-install: task %s: pkg check error (%v); marking FAILED", row.TaskID, err)
		_ = store.Complete(row.TaskID, StatusFailed, "helper did not produce result file", nil)
		return
	}

	if installedVersion == "" {
		// Package not installed — install must have failed.
		logf("drain/plugin-install: task %s: package %s not installed after restart; marking FAILED",
			row.TaskID, meta.PackageName)
		_ = store.Complete(row.TaskID, StatusFailed,
			"plugin install appears to have failed: package not found after restart", nil)
		return
	}

	// Package is installed. Check version match:
	//   target == ""  → "latest"; any installed version means success.
	//   target != ""  → must match exactly.
	if meta.TargetVersion != "" && installedVersion != meta.TargetVersion {
		logf("drain/plugin-install: task %s: installed=%s target=%s mismatch; marking FAILED",
			row.TaskID, installedVersion, meta.TargetVersion)
		_ = store.Complete(row.TaskID, StatusFailed,
			"plugin install appears to have failed: installed version "+installedVersion+
				" does not match target "+meta.TargetVersion, nil)
		return
	}

	logf("drain/plugin-install: task %s: installed=%s matches target; marking COMPLETED",
		row.TaskID, installedVersion)
	_ = store.Complete(row.TaskID, StatusCompleted,
		"Plugin installed successfully (version "+installedVersion+")", nil)
}

// DrainUndelivered is the boot-time replay step: reconcile any helper
// drop files into the registry, resolve any rows still IN_PROGRESS per
// their lifecycle category, then send a real task_response for each
// row whose delivered_at is still null. Each successful send is
// followed by MarkDelivered (which also runs retention).
//
// Caller order: open store, run DrainUndelivered AFTER WS auth has
// succeeded (so the responder can actually transmit) and BEFORE the
// dispatcher starts receiving new tasks (so we don't race against
// fresh writes).
//
// checker is the PLUGIN_INSTALL race-tolerance callback (see
// PluginInstallChecker). Pass nil to disable the pkg-check path (existing
// tests that don't wire pkg behaviour remain unaffected).
//
// Returns the count of responses sent. A non-nil error from a single
// send is logged but does not abort the drain — subsequent rows are
// still attempted. The first hard error is returned to the caller
// after the loop finishes.
func DrainUndelivered(ctx context.Context, store *Store, pendingResultsDir string, responder Responder, logf func(format string, args ...interface{}), checker PluginInstallChecker) (int, error) {
	if logf == nil {
		logf = func(format string, args ...interface{}) {}
	}

	// 1. Helper drop files → terminal store rows.
	if applied, err := ReconcileDropFiles(pendingResultsDir, store); err != nil {
		logf("drain: reconcile drop files failed: %v", err)
	} else if applied > 0 {
		logf("drain: reconciled %d drop file(s)", applied)
	}

	// 2. PLUGIN_INSTALL-specific race tolerance: for IN_PROGRESS rows whose
	// drop file hasn't landed yet, wait briefly and then fall back to a
	// pkg-version check. This resolves the race where pkg's post-install
	// hook restarts the agent before the helper script finishes writing the
	// drop file. Strictly scoped to PLUGIN_INSTALL + LifecycleHelperResolves
	// — no other task type is affected.
	resolveStuckPluginInstall(ctx, store, pendingResultsDir, checker, logf)

	// 3. Stuck IN_PROGRESS rows → terminal per lifecycle category.
	// By the time this runs, any PLUGIN_INSTALL rows that the step above
	// could handle have already been moved to a terminal state, so
	// ResolveStuck's LifecycleHelperResolves → FAILED fallback only fires
	// for genuinely unresolvable rows (helper absent with no pkg evidence).
	if resolved, err := store.ResolveStuck(); err != nil {
		logf("drain: resolve stuck rows failed: %v", err)
	} else if resolved > 0 {
		logf("drain: resolved %d stuck row(s)", resolved)
	}

	// 4. Replay all undelivered terminal rows.
	rows, err := store.Undelivered()
	if err != nil {
		return 0, err
	}

	sent := 0
	var firstErr error
	for _, r := range rows {
		// Context cancellation during a long drain shouldn't drop
		// half-delivered work; check before each send.
		select {
		case <-ctx.Done():
			return sent, ctx.Err()
		default:
		}

		var data map[string]interface{}
		if len(r.ResultData) > 0 {
			// Best-effort: the result blob was written by us in
			// SendTaskResponse from the inner-response map. If parsing
			// fails, send without data — the message string still
			// carries the operator-visible signal.
			if err := json.Unmarshal(r.ResultData, &data); err != nil {
				data = nil
			}
		}

		if err := responder.SendTaskResponse(r.TaskID, r.Status, r.Message, data); err != nil {
			logf("drain: SendTaskResponse for task %s failed: %v", r.TaskID, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err := store.MarkDelivered(r.TaskID); err != nil {
			logf("drain: MarkDelivered for task %s failed: %v", r.TaskID, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		sent++
	}
	return sent, firstErr
}
