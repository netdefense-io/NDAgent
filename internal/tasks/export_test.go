package tasks

import (
	"context"
	"time"

	"github.com/netdefense-io/ndagent/internal/firmware"
	"github.com/netdefense-io/ndagent/internal/network"
	"github.com/netdefense-io/ndagent/internal/pkgmgr"
	"github.com/netdefense-io/ndagent/internal/taskstore"
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

// SetFirmwareCheckPollIntervalForTest sets the poll interval used by
// waitForFirmwareReady to a short duration so tests don't block. Returns
// a restore function.
func SetFirmwareCheckPollIntervalForTest(d time.Duration) (restore func()) {
	old := firmwareCheckPollIntervalVar
	firmwareCheckPollIntervalVar = d
	return func() { firmwareCheckPollIntervalVar = old }
}

// SetFirmwareCheckTimeoutForTest sets the timeout used by waitForFirmwareReady.
// Returns a restore function.
func SetFirmwareCheckTimeoutForTest(d time.Duration) (restore func()) {
	old := firmwareCheckTimeoutVar
	firmwareCheckTimeoutVar = d
	return func() { firmwareCheckTimeoutVar = old }
}

// SetUpgradeStatusPollIntervalForTest sets the poll interval for
// pollUpgradeStatus to a short duration so tests don't have to wait 5s.
// Returns a restore function.
func SetUpgradeStatusPollIntervalForTest(d time.Duration) (restore func()) {
	old := upgradeStatusPollInterval
	upgradeStatusPollInterval = d
	return func() { upgradeStatusPollInterval = old }
}

// SetFirmwareSendResponseForTest replaces the terminal-response sender
// used by handleMinorNoReboot (and sendMinorNoRebootResult) with f and returns
// a restore function. Tests use this to capture SendTaskResponse calls without
// a real WebSocket connection — verifying that every exit path emits a
// terminal response (Blocker B coverage).
func SetFirmwareSendResponseForTest(
	f func(ws *network.WebSocketClient, taskID string, result TaskResult) error,
) (restore func()) {
	old := firmwareSendResponse
	firmwareSendResponse = f
	return func() { firmwareSendResponse = old }
}

// SetFirmwareSendInProgressForTest replaces the IN_PROGRESS sender
// used by handleMinorNoReboot with a no-op for tests.
func SetFirmwareSendInProgressForTest(
	f func(ws *network.WebSocketClient, taskID, message string) error,
) (restore func()) {
	old := firmwareSendInProgress
	firmwareSendInProgress = f
	return func() { firmwareSendInProgress = old }
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

// ── Remote-access ceiling test exports ─────────────────────────────────────

// SetConnectSendResponseForTest replaces the terminal-response sender used by
// HandleConnect's remote-access-policy refusal path and returns a restore
// function. Lets a test assert the refusal result without a live WebSocket.
func SetConnectSendResponseForTest(
	f func(ws *network.WebSocketClient, taskID string, result TaskResult) error,
) (restore func()) {
	old := connectSendResponse
	connectSendResponse = f
	return func() { connectSendResponse = old }
}

// SetFirmwareTaskStoreForTest makes the FIRMWARE_UPGRADE paths persist their
// run metadata to store instead of the client's. Returns a restore function.
func SetFirmwareTaskStoreForTest(store *taskstore.Store) (restore func()) {
	old := firmwareTaskStore
	firmwareTaskStore = func(*network.WebSocketClient) *taskstore.Store { return store }
	return func() { firmwareTaskStore = old }
}

// SetFirmwareBootTimeForTest and SetFirmwareNowForTest replace the boot time
// and the clock the run metadata is stamped with.
func SetFirmwareBootTimeForTest(f func() (int64, error)) (restore func()) {
	old := firmwareBootTime
	firmwareBootTime = f
	return func() { firmwareBootTime = old }
}

func SetFirmwareNowForTest(f func() time.Time) (restore func()) {
	old := firmwareNow
	firmwareNow = f
	return func() { firmwareNow = old }
}

// SetFirmwareUptimeForTest replaces how long the process is taken to have run.
func SetFirmwareUptimeForTest(f func() time.Duration) (restore func()) {
	old := firmwareUptime
	firmwareUptime = f
	return func() { firmwareUptime = old }
}

// SetOPNAPIClientForFirmwareForTest injects the client HandleFirmwareUpgrade
// uses.
func SetOPNAPIClientForFirmwareForTest(c firmwareOPNAPIClient) (restore func()) {
	old := opnAPIClientForFirmware
	opnAPIClientForFirmware = c
	return func() { opnAPIClientForFirmware = old }
}

// SetFirmwareWaitsForTest shortens every wait and poll the REST runs make and
// returns a restore function.
func SetFirmwareWaitsForTest(preTriggerWait, preTriggerPoll, startWindow, startPoll, settle time.Duration) (restore func()) {
	oldWait, oldPoll, oldWindow, oldStartPoll, oldSettle :=
		firmwarePreTriggerWaitVar, firmwarePreTriggerPollVar, firmwareStartWindowVar, firmwareStartPollVar, firmwareSettleIntervalVar
	firmwarePreTriggerWaitVar, firmwarePreTriggerPollVar = preTriggerWait, preTriggerPoll
	firmwareStartWindowVar, firmwareStartPollVar = startWindow, startPoll
	firmwareSettleIntervalVar = settle
	return func() {
		firmwarePreTriggerWaitVar, firmwarePreTriggerPollVar = oldWait, oldPoll
		firmwareStartWindowVar, firmwareStartPollVar = oldWindow, oldStartPoll
		firmwareSettleIntervalVar = oldSettle
	}
}

// SetFirmwareDeadlineForTest replaces how long a REST run watches.
func SetFirmwareDeadlineForTest(f func(expires time.Time) time.Time) (restore func()) {
	old := firmwareDeadline
	firmwareDeadline = f
	return func() { firmwareDeadline = old }
}

// SetFirmwareProbesForTest replaces what a REST run reads the device with.
func SetFirmwareProbesForTest(f func(client firmwareOPNAPIClient) firmware.Probes) (restore func()) {
	old := newFirmwareProbes
	newFirmwareProbes = f
	return func() { newFirmwareProbes = old }
}
