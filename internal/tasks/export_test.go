package tasks

import (
	"context"
	"time"

	"github.com/netdefense-io/ndagent/internal/network"
	"github.com/netdefense-io/ndagent/internal/pkgmgr"
)

// pkgmgrQueryForTest returns the current pkgmgr query indirection so a
// test can save/restore it. Lives in export_test.go so it doesn't ship
// in the production binary.
func pkgmgrQueryForTest() func(context.Context, []string) ([]pkgmgr.Status, error) {
	return pkgmgrQuery
}

// setPkgmgrQueryForTest swaps the pkgmgr query indirection used by the
// PLUGIN_INSTALL handler. Test-only.
func setPkgmgrQueryForTest(f func(context.Context, []string) ([]pkgmgr.Status, error)) {
	pkgmgrQuery = f
}

// ── Firmware upgrade test exports ──────────────────────────────────────────

// SetFirmwareSleepNoopForTest replaces the sleep used after TriggerFirmwareCheck
// with a no-op and returns a restore function. Tests call this to avoid
// blocking for 30 s during unit tests.
func SetFirmwareSleepNoopForTest() (restore func()) {
	old := firmwareSleepFunc
	firmwareSleepFunc = func(d time.Duration) {}
	return func() { firmwareSleepFunc = old }
}

// SetUpgradeStatusPollIntervalForTest sets the poll interval for
// pollUpgradeStatus to a short duration so tests don't have to wait 5s.
// Returns a restore function.
func SetUpgradeStatusPollIntervalForTest(d time.Duration) (restore func()) {
	old := upgradeStatusPollInterval
	upgradeStatusPollInterval = d
	return func() { upgradeStatusPollInterval = old }
}

// SetFirmwareNoRebootSendResponseForTest replaces the terminal-response sender
// used by handleMinorNoReboot (and sendMinorNoRebootResult) with f and returns
// a restore function. Tests use this to capture SendTaskResponse calls without
// a real WebSocket connection — verifying that every exit path emits a
// terminal response (Blocker B coverage).
func SetFirmwareNoRebootSendResponseForTest(
	f func(ws *network.WebSocketClient, taskID string, result TaskResult) error,
) (restore func()) {
	old := firmwareNoRebootSendResponse
	firmwareNoRebootSendResponse = f
	return func() { firmwareNoRebootSendResponse = old }
}

// SetFirmwareNoRebootSendInProgressForTest replaces the IN_PROGRESS sender
// used by handleMinorNoReboot with a no-op for tests.
func SetFirmwareNoRebootSendInProgressForTest(
	f func(ws *network.WebSocketClient, taskID, message string) error,
) (restore func()) {
	old := firmwareNoRebootSendInProgress
	firmwareNoRebootSendInProgress = f
	return func() { firmwareNoRebootSendInProgress = old }
}

// SetFirmwareGetSuffixFuncForTest replaces the suffix getter used by
// handleMinorNoReboot. Tests use this to return a fixed suffix without
// shelling out to pluginctl.
func SetFirmwareGetSuffixFuncForTest(f func(ctx context.Context) (string, error)) (restore func()) {
	old := firmwareGetSuffixFunc
	firmwareGetSuffixFunc = f
	return func() { firmwareGetSuffixFunc = old }
}

// SetFirmwareExecFuncForTest replaces the exec indirection used by
// RunFirmwarePackagesOnly. Tests use this to simulate exit codes.
func SetFirmwareExecFuncForTest(f func(ctx context.Context, args ...string) ([]byte, []byte, int)) (restore func()) {
	old := firmwareExecFunc
	firmwareExecFunc = f
	return func() { firmwareExecFunc = old }
}
