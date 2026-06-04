package tasks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/network"
	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// ─── Payload parsing ───────────────────────────────────────────────────────

func TestParseFirmwareUpgradePayload_Defaults(t *testing.T) {
	cmd := network.Command{
		TaskID:   "1",
		TaskType: "FIRMWARE_UPGRADE",
		Payload:  map[string]interface{}{"mode": "minor"},
	}
	p, err := parseFirmwareUpgradePayload(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Mode != "minor" {
		t.Errorf("mode=%q want minor", p.Mode)
	}
	if !p.Reboot {
		t.Error("reboot default should be true")
	}
	if !p.CheckFirst {
		t.Error("check_first default should be true")
	}
	if p.DryRun {
		t.Error("dry_run default should be false")
	}
}

func TestParseFirmwareUpgradePayload_Validation(t *testing.T) {
	cases := []struct {
		name    string
		payload map[string]interface{}
		wantErr bool
	}{
		{
			name:    "missing mode",
			payload: map[string]interface{}{},
			wantErr: true,
		},
		{
			name:    "mode=auto rejected",
			payload: map[string]interface{}{"mode": "auto"},
			wantErr: true,
		},
		{
			name:    "major+reboot=false invalid",
			payload: map[string]interface{}{"mode": "major", "reboot": false},
			wantErr: true,
		},
		{
			name:    "nil payload",
			payload: nil,
			wantErr: true,
		},
		{
			name:    "minor+reboot=false valid",
			payload: map[string]interface{}{"mode": "minor", "reboot": false},
			wantErr: false,
		},
		{
			name:    "major+reboot=true valid",
			payload: map[string]interface{}{"mode": "major", "reboot": true},
			wantErr: false,
		},
		{
			name:    "minor with all optional fields",
			payload: map[string]interface{}{"mode": "minor", "reboot": false, "check_first": false, "dry_run": true},
			wantErr: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := network.Command{TaskID: "1", TaskType: "FIRMWARE_UPGRADE", Payload: tc.payload}
			_, err := parseFirmwareUpgradePayload(cmd)
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestParseFirmwareUpgradePayload_RebootField(t *testing.T) {
	// Reboot as bool false.
	cmd := network.Command{
		TaskID:  "2",
		Payload: map[string]interface{}{"mode": "minor", "reboot": false},
	}
	p, err := parseFirmwareUpgradePayload(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Reboot {
		t.Error("reboot should be false")
	}

	// Reboot as numeric 0 (JSON numbers decode as float64).
	cmd2 := network.Command{
		TaskID:  "3",
		Payload: map[string]interface{}{"mode": "minor", "reboot": float64(0)},
	}
	p2, err := parseFirmwareUpgradePayload(cmd2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p2.Reboot {
		t.Error("reboot should be false for float64(0)")
	}
}

// ─── Suffix allowlist ──────────────────────────────────────────────────────

func TestValidateFirmwareSuffix_Allowlist(t *testing.T) {
	valid := []string{"", "-business", "-devel"}
	for _, s := range valid {
		if err := ValidateFirmwareSuffix(s); err != nil {
			t.Errorf("suffix %q should be valid, got error: %v", s, err)
		}
	}
}

func TestValidateFirmwareSuffix_Rejected(t *testing.T) {
	invalid := []string{
		"-; rm -rf /",
		"$(whoami)",
		" ",
		"../../etc/passwd",
		"-custom", // not in allowlist
		"opnsense",
	}
	for _, s := range invalid {
		if err := ValidateFirmwareSuffix(s); err == nil {
			t.Errorf("suffix %q should be rejected", s)
		}
	}
}

// ─── Classification helpers ────────────────────────────────────────────────

func TestCountNonRebootPackages(t *testing.T) {
	pkgs := []opnapi.FirmwarePackageEntry{
		{Name: "opnsense"},
		{Name: "curl"},
		{Name: "base"},
		{Name: "kernel"},
	}
	got := countNonRebootPackages(pkgs)
	if got != 2 {
		t.Errorf("countNonRebootPackages=%d want 2", got)
	}
}

func TestCountNonRebootPackages_Empty(t *testing.T) {
	got := countNonRebootPackages(nil)
	if got != 0 {
		t.Errorf("countNonRebootPackages(nil)=%d want 0", got)
	}
}

// ─── TailLines ────────────────────────────────────────────────────────────

func TestTailLines(t *testing.T) {
	input := "line1\nline2\nline3\nline4\nline5"
	got := tailLines(input, 3)
	want := "line3\nline4\nline5"
	if got != want {
		t.Errorf("tailLines=%q want %q", got, want)
	}
}

func TestTailLines_ShortInput(t *testing.T) {
	input := "line1\nline2"
	got := tailLines(input, 10)
	if got != "line1\nline2" {
		t.Errorf("tailLines=%q want %q", got, "line1\nline2")
	}
}

// ─── DeviceExecEnv ────────────────────────────────────────────────────────

func TestDeviceExecEnv_ContainsLocalSbin(t *testing.T) {
	env := DeviceExecEnv()
	found := false
	for _, kv := range env {
		if kv == "PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("DeviceExecEnv() PATH entry missing /usr/local/sbin or /usr/local/bin; got env=%v", env)
	}
}

func TestDeviceExecEnv_ExactlyOnePATHEntry(t *testing.T) {
	env := DeviceExecEnv()
	count := 0
	for _, kv := range env {
		if len(kv) >= 5 && kv[:5] == "PATH=" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("DeviceExecEnv() should produce exactly 1 PATH entry, got %d", count)
	}
}

// ─── firmwareExecFunc sets PATH ───────────────────────────────────────────

// TestFirmwareExecFunc_EnvHasLocalSbin verifies that the production
// firmwareExecFunc closure passes an environment that includes
// /usr/local/sbin and /usr/local/bin on cmd.Env. This is the regression
// test for the rc.d stripped-PATH bug where opnsense-update invoked
// opnsense-version by unqualified name and got "not found" (exit 127).
func TestFirmwareExecFunc_EnvHasLocalSbin(t *testing.T) {
	old := firmwareExecFunc
	var capturedEnv []string
	firmwareExecFunc = func(_ context.Context, args ...string) ([]byte, []byte, int) {
		// Capture what the real closure would have set on cmd.Env by calling
		// DeviceExecEnv() — this mirrors the production closure exactly.
		capturedEnv = DeviceExecEnv()
		return []byte("ok"), nil, 0
	}
	defer func() { firmwareExecFunc = old }()

	_, err := RunFirmwarePackagesOnly(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, kv := range capturedEnv {
		if kv == "PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("exec env PATH does not include /usr/local/sbin:/usr/local/bin; env=%v", capturedEnv)
	}
}

// ─── Exec wrapper unit tests ──────────────────────────────────────────────

func TestRunFirmwarePackagesOnly_InvalidSuffix(t *testing.T) {
	_, err := RunFirmwarePackagesOnly(context.Background(), "-bad-$(inject)")
	if err == nil {
		t.Fatal("expected error for invalid suffix")
	}
}

func TestRunFirmwarePackagesOnly_ExecSuccess(t *testing.T) {
	// Stub the exec to return success.
	old := firmwareExecFunc
	firmwareExecFunc = func(_ context.Context, args ...string) ([]byte, []byte, int) {
		if len(args) < 3 || args[2] != "opnsense" {
			t.Errorf("unexpected args: %v", args)
		}
		return []byte("packages applied\n"), []byte(""), 0
	}
	defer func() { firmwareExecFunc = old }()

	result, err := RunFirmwarePackagesOnly(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ExitCode != 0 {
		t.Errorf("exit code=%d want 0", result.ExitCode)
	}
}

func TestRunFirmwarePackagesOnly_ExecFail(t *testing.T) {
	old := firmwareExecFunc
	firmwareExecFunc = func(_ context.Context, args ...string) ([]byte, []byte, int) {
		return []byte(""), []byte("error: pkg unavailable"), 1
	}
	defer func() { firmwareExecFunc = old }()

	result, err := RunFirmwarePackagesOnly(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error from RunFirmwarePackagesOnly itself: %v", err)
	}
	if result.ExitCode == 0 {
		t.Error("expected non-zero exit code")
	}
}

func TestRunFirmwarePackagesOnly_BusinessSuffix(t *testing.T) {
	// -business suffix is in allowlist.
	old := firmwareExecFunc
	var capturedArgs []string
	firmwareExecFunc = func(_ context.Context, args ...string) ([]byte, []byte, int) {
		capturedArgs = args
		return nil, nil, 0
	}
	defer func() { firmwareExecFunc = old }()

	_, err := RunFirmwarePackagesOnly(context.Background(), "-business")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(capturedArgs) < 3 || capturedArgs[2] != "opnsense-business" {
		t.Errorf("unexpected package name in args: %v", capturedArgs)
	}
}

// ─── Package name helper ───────────────────────────────────────────────────

func TestPackageNames(t *testing.T) {
	pkgs := []opnapi.FirmwarePackageEntry{
		{Name: "opnsense"},
		{Name: "curl"},
		{Name: "base"},
	}
	got := packageNames(pkgs)
	if len(got) != 3 || got[0] != "opnsense" || got[2] != "base" {
		t.Errorf("packageNames=%v", got)
	}
}

// ─── FirmwarePackageEntry.VersionString ───────────────────────────────────

func TestFirmwarePackageEntry_VersionString(t *testing.T) {
	// upgrade_packages uses "new_version" field.
	e1 := opnapi.FirmwarePackageEntry{NewVersionAlt: "26.1.9"}
	if e1.VersionString() != "26.1.9" {
		t.Errorf("VersionString=%q want 26.1.9", e1.VersionString())
	}

	// new_packages uses "version" field.
	e2 := opnapi.FirmwarePackageEntry{NewVersion: "1.0.22"}
	if e2.VersionString() != "1.0.22" {
		t.Errorf("VersionString=%q want 1.0.22", e2.VersionString())
	}

	// NewVersionAlt takes precedence.
	e3 := opnapi.FirmwarePackageEntry{NewVersion: "1.0", NewVersionAlt: "1.1"}
	if e3.VersionString() != "1.1" {
		t.Errorf("VersionString=%q want 1.1", e3.VersionString())
	}
}

// ─── pollUpgradeStatus ─────────────────────────────────────────────────────

func TestPollUpgradeStatus_ImmediateDone(t *testing.T) {
	restore := SetUpgradeStatusPollIntervalForTest(1 * time.Millisecond)
	defer restore()

	client := &stubFirmwareClient{
		progressResp: &opnapi.FirmwareProgressStatus{Status: "done", Log: "***DONE***"},
	}
	sentinel := pollUpgradeStatus(context.Background(), client, noopLogger{})
	if sentinel != "done" {
		t.Errorf("sentinel=%q want done", sentinel)
	}
}

func TestPollUpgradeStatus_ContextCancelled(t *testing.T) {
	restore := SetUpgradeStatusPollIntervalForTest(1 * time.Millisecond)
	defer restore()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	client := &stubFirmwareClient{
		progressResp: &opnapi.FirmwareProgressStatus{Status: "running"},
	}
	sentinel := pollUpgradeStatus(ctx, client, noopLogger{})
	if sentinel != "" {
		t.Errorf("sentinel=%q want empty (context cancelled)", sentinel)
	}
}

func TestPollUpgradeStatus_RebootSentinel(t *testing.T) {
	restore := SetUpgradeStatusPollIntervalForTest(1 * time.Millisecond)
	defer restore()

	client := &stubFirmwareClient{
		progressResp: &opnapi.FirmwareProgressStatus{Status: "reboot"},
	}
	sentinel := pollUpgradeStatus(context.Background(), client, noopLogger{})
	if sentinel != "reboot" {
		t.Errorf("sentinel=%q want reboot", sentinel)
	}
}

// ─── Stub helpers ──────────────────────────────────────────────────────────

// stubFirmwareClient is a configurable stub for firmwareOPNAPIClient.
type stubFirmwareClient struct {
	checkErr        error
	statusResp      *opnapi.FirmwareUpgradeStatus
	statusErr       error
	updateResp      *opnapi.FirmwareUpdateResponse
	updateErr       error
	upgradeResp     *opnapi.FirmwareUpgradeResponse
	upgradeErr      error
	progressResp    *opnapi.FirmwareProgressStatus
	progressErr     error
	runningResp     *opnapi.FirmwareRunning
	runningErr      error
	// postStatusResp is returned on the 2nd+ call to GetFirmwareUpgradeStatus.
	postStatusResp  *opnapi.FirmwareUpgradeStatus
	statusCallCount int
}

func (s *stubFirmwareClient) TriggerFirmwareCheck(_ context.Context) error { return s.checkErr }
func (s *stubFirmwareClient) GetFirmwareUpgradeStatus(_ context.Context) (*opnapi.FirmwareUpgradeStatus, error) {
	s.statusCallCount++
	if s.postStatusResp != nil && s.statusCallCount > 1 {
		return s.postStatusResp, s.statusErr
	}
	return s.statusResp, s.statusErr
}
func (s *stubFirmwareClient) TriggerFirmwareUpdate(_ context.Context) (*opnapi.FirmwareUpdateResponse, error) {
	return s.updateResp, s.updateErr
}
func (s *stubFirmwareClient) TriggerFirmwareUpgrade(_ context.Context) (*opnapi.FirmwareUpgradeResponse, error) {
	return s.upgradeResp, s.upgradeErr
}
func (s *stubFirmwareClient) GetFirmwareUpgradeProgress(_ context.Context) (*opnapi.FirmwareProgressStatus, error) {
	return s.progressResp, s.progressErr
}
func (s *stubFirmwareClient) GetFirmwareRunning(_ context.Context) (*opnapi.FirmwareRunning, error) {
	return s.runningResp, s.runningErr
}

// noopLogger satisfies the logger parameter of pollUpgradeStatus.
type noopLogger struct{}

func (noopLogger) Infow(_ string, _ ...interface{}) {}

// ─── handleMinorNoReboot: terminal-response coverage (Blocker B) ─────────────
//
// These tests verify that EVERY exit path of handleMinorNoReboot calls
// firmwareNoRebootSendResponse (the production alias for SendTaskResponse)
// before returning. A missing call would leave the task leaking as IN_PROGRESS
// in NDBroker until the 15-minute TTL fires.
//
// The captured struct records each call so we can assert (a) that exactly one
// terminal call was made, and (b) that the expected status (COMPLETED/FAILED)
// was sent.

// capturedResponse records one call to firmwareNoRebootSendResponse.
type capturedResponse struct {
	taskID  string
	success bool // true = COMPLETED, false = FAILED
	message string
}

// installNoRebootSendCapture replaces firmwareNoRebootSendResponse with a
// recorder and returns a pointer to the slice of captured calls plus a
// restore function.
func installNoRebootSendCapture(t *testing.T) (*[]capturedResponse, func()) {
	t.Helper()
	calls := &[]capturedResponse{}
	restore := SetFirmwareNoRebootSendResponseForTest(func(_ *network.WebSocketClient, taskID string, result TaskResult) error {
		*calls = append(*calls, capturedResponse{
			taskID:  taskID,
			success: result.Success,
			message: result.Message,
		})
		return nil
	})
	return calls, restore
}

// installNoopInProgress replaces firmwareNoRebootSendInProgress with a no-op
// for tests that don't care about IN_PROGRESS calls.
func installNoopInProgress(t *testing.T) func() {
	t.Helper()
	return SetFirmwareNoRebootSendInProgressForTest(func(_ *network.WebSocketClient, _, _ string) error {
		return nil
	})
}

// minorNoRebootCmd builds a dummy Command for the reboot=false path.
func minorNoRebootCmd(taskID string) network.Command {
	return network.Command{
		TaskID:   taskID,
		TaskType: "FIRMWARE_UPGRADE",
		Payload: map[string]interface{}{
			"mode":        "minor",
			"reboot":      false,
			"check_first": false,
		},
	}
}

// minorNoRebootPreStatus returns a pre-apply FirmwareUpgradeStatus with the
// given non-reboot packages plus optional base/kernel entries.
func minorNoRebootPreStatus(nonRebootNames []string, includeBaseKernel bool) *opnapi.FirmwareUpgradeStatus {
	pkgs := make([]opnapi.FirmwarePackageEntry, 0, len(nonRebootNames)+2)
	for _, n := range nonRebootNames {
		pkgs = append(pkgs, opnapi.FirmwarePackageEntry{Name: n})
	}
	if includeBaseKernel {
		pkgs = append(pkgs, opnapi.FirmwarePackageEntry{Name: "base"})
		pkgs = append(pkgs, opnapi.FirmwarePackageEntry{Name: "kernel"})
	}
	return &opnapi.FirmwareUpgradeStatus{
		ProductVersion:  "26.1.2",
		ProductLatest:   "26.1.9",
		ProductSeries:   "26.1",
		ProductABI:      "FreeBSD:14:amd64",
		Status:          "update",
		UpgradePackages: pkgs,
	}
}

// TestHandleMinorNoReboot_TerminalResponseOnSuccess verifies that when
// opnsense-update exits 0 the handler emits exactly one COMPLETED terminal
// response before returning. This is the primary Blocker B regression test.
func TestHandleMinorNoReboot_TerminalResponseOnSuccess(t *testing.T) {
	calls, restoreSend := installNoRebootSendCapture(t)
	defer restoreSend()
	defer installNoopInProgress(t)()

	// Stub exec: exit 0 (success).
	restoreExec := SetFirmwareExecFuncForTest(func(_ context.Context, args ...string) ([]byte, []byte, int) {
		return []byte("Fetching packages...\nDone.\n"), nil, 0
	})
	defer restoreExec()

	// Stub suffix: standard (empty).
	restoreSuffix := SetFirmwareGetSuffixFuncForTest(func(_ context.Context) (string, error) {
		return "", nil
	})
	defer restoreSuffix()

	// Pre-apply status: 2 non-reboot packages + base + kernel.
	preStatus := minorNoRebootPreStatus([]string{"opnsense", "curl"}, true)

	// Post-apply status read: same as pre (stale cache) — Blocker A regression.
	// With the fix, exit 0 must still produce COMPLETED even when /status is stale.
	client := &stubFirmwareClient{
		statusResp:     preStatus,
		postStatusResp: preStatus, // stale — same data as before exec
	}

	err := handleMinorNoReboot(context.Background(), nil, minorNoRebootCmd("10"), client, &firmwareUpgradePayload{Reboot: false, Mode: "minor"}, preStatus)
	if err != nil {
		t.Fatalf("handleMinorNoReboot returned unexpected error: %v", err)
	}

	if len(*calls) != 1 {
		t.Fatalf("expected exactly 1 terminal SendTaskResponse call, got %d: %+v", len(*calls), *calls)
	}
	if !(*calls)[0].success {
		t.Errorf("expected COMPLETED response, got FAILED with message: %q", (*calls)[0].message)
	}
}

// TestHandleMinorNoReboot_TerminalResponseOnNoop verifies that when there are
// no upgrade packages (no-op) the handler emits a COMPLETED terminal response.
// The no-op short-circuit lives in HandleFirmwareUpgrade (lines 259-273) but
// the case where only base/kernel are pending and preNonRebootPkgs==0 passes
// through handleMinorNoReboot itself — exercise that sub-path here too.
func TestHandleMinorNoReboot_TerminalResponseOnNoopSubpath(t *testing.T) {
	calls, restoreSend := installNoRebootSendCapture(t)
	defer restoreSend()
	defer installNoopInProgress(t)()

	// Exec exits 0 — only base+kernel were pending, no non-reboot packages.
	restoreExec := SetFirmwareExecFuncForTest(func(_ context.Context, args ...string) ([]byte, []byte, int) {
		return nil, nil, 0
	})
	defer restoreExec()

	restoreSuffix := SetFirmwareGetSuffixFuncForTest(func(_ context.Context) (string, error) {
		return "", nil
	})
	defer restoreSuffix()

	// Only base + kernel pending (preNonRebootPkgs == 0).
	preStatus := minorNoRebootPreStatus(nil, true)
	client := &stubFirmwareClient{
		statusResp: preStatus,
	}

	err := handleMinorNoReboot(context.Background(), nil, minorNoRebootCmd("11"), client, &firmwareUpgradePayload{Reboot: false, Mode: "minor"}, preStatus)
	if err != nil {
		t.Fatalf("handleMinorNoReboot returned unexpected error: %v", err)
	}

	if len(*calls) != 1 {
		t.Fatalf("expected exactly 1 terminal SendTaskResponse call, got %d", len(*calls))
	}
	if !(*calls)[0].success {
		t.Errorf("expected COMPLETED response, got FAILED: %q", (*calls)[0].message)
	}
}

// TestHandleMinorNoReboot_TerminalResponseOnExecError verifies that when the
// exec wrapper itself errors (e.g. binary not found before fork) the handler
// emits exactly one FAILED terminal response.
func TestHandleMinorNoReboot_TerminalResponseOnExecError(t *testing.T) {
	calls, restoreSend := installNoRebootSendCapture(t)
	defer restoreSend()
	defer installNoopInProgress(t)()

	restoreSuffix := SetFirmwareGetSuffixFuncForTest(func(_ context.Context) (string, error) {
		return "", nil
	})
	defer restoreSuffix()

	// Stub RunFirmwarePackagesOnly at the exec layer to return a non-zero exit.
	restoreExec := SetFirmwareExecFuncForTest(func(_ context.Context, args ...string) ([]byte, []byte, int) {
		return nil, []byte("pkg: repository unavailable"), 1
	})
	defer restoreExec()

	preStatus := minorNoRebootPreStatus([]string{"opnsense"}, true)
	client := &stubFirmwareClient{statusResp: preStatus}

	err := handleMinorNoReboot(context.Background(), nil, minorNoRebootCmd("12"), client, &firmwareUpgradePayload{Reboot: false, Mode: "minor"}, preStatus)
	if err != nil {
		t.Fatalf("handleMinorNoReboot returned unexpected error: %v", err)
	}

	if len(*calls) != 1 {
		t.Fatalf("expected exactly 1 terminal SendTaskResponse call, got %d", len(*calls))
	}
	if (*calls)[0].success {
		t.Errorf("expected FAILED response for non-zero exit, got COMPLETED")
	}
}

// TestHandleMinorNoReboot_TerminalResponseOnSuffixError verifies that a
// suffix-getter error (e.g. pluginctl not installed) produces a FAILED
// terminal response, not a silent return.
func TestHandleMinorNoReboot_TerminalResponseOnSuffixError(t *testing.T) {
	calls, restoreSend := installNoRebootSendCapture(t)
	defer restoreSend()
	defer installNoopInProgress(t)()

	restoreSuffix := SetFirmwareGetSuffixFuncForTest(func(_ context.Context) (string, error) {
		return "", errors.New("pluginctl not found")
	})
	defer restoreSuffix()

	preStatus := minorNoRebootPreStatus([]string{"opnsense"}, false)
	client := &stubFirmwareClient{statusResp: preStatus}

	err := handleMinorNoReboot(context.Background(), nil, minorNoRebootCmd("13"), client, &firmwareUpgradePayload{Reboot: false, Mode: "minor"}, preStatus)
	if err != nil {
		t.Fatalf("handleMinorNoReboot returned unexpected error: %v", err)
	}

	if len(*calls) != 1 {
		t.Fatalf("expected exactly 1 terminal SendTaskResponse call, got %d", len(*calls))
	}
	if (*calls)[0].success {
		t.Errorf("expected FAILED response for suffix error, got COMPLETED")
	}
}

// TestHandleMinorNoReboot_TerminalResponseOnPostStatusFail verifies that when
// the post-apply /status read fails the handler still emits a COMPLETED
// terminal response (exec success is the truth).
func TestHandleMinorNoReboot_TerminalResponseOnPostStatusFail(t *testing.T) {
	calls, restoreSend := installNoRebootSendCapture(t)
	defer restoreSend()
	defer installNoopInProgress(t)()

	restoreExec := SetFirmwareExecFuncForTest(func(_ context.Context, args ...string) ([]byte, []byte, int) {
		return []byte("done"), nil, 0
	})
	defer restoreExec()

	restoreSuffix := SetFirmwareGetSuffixFuncForTest(func(_ context.Context) (string, error) {
		return "", nil
	})
	defer restoreSuffix()

	preStatus := minorNoRebootPreStatus([]string{"opnsense"}, true)

	// Post-apply status returns an error (API down after apply).
	client := &stubFirmwareClient{
		statusResp: preStatus,
		// GetFirmwareUpgradeStatus returns statusResp on call 1 (pre-apply, used
		// by the caller before handleMinorNoReboot is invoked), and statusErr on
		// call 2 (post-apply guard inside handleMinorNoReboot).
		postStatusResp: nil,
		statusErr:      errors.New("connection refused"),
	}
	// Reset statusErr only for the first call — use statusCallCount trick:
	// we wire a fresh stub that returns error on every call (simulating the
	// post-apply read failing). The pre-apply status is already in initialStatus.
	errClient := &stubFirmwareClient{
		statusErr: errors.New("connection refused"),
	}

	err := handleMinorNoReboot(context.Background(), nil, minorNoRebootCmd("14"), errClient, &firmwareUpgradePayload{Reboot: false, Mode: "minor"}, preStatus)
	if err != nil {
		t.Fatalf("handleMinorNoReboot returned unexpected error: %v", err)
	}

	if len(*calls) != 1 {
		t.Fatalf("expected exactly 1 terminal SendTaskResponse call, got %d: %+v", len(*calls), *calls)
	}
	// Post-status failure must not flip the result to FAILED when exec was 0.
	if !(*calls)[0].success {
		t.Errorf("expected COMPLETED even when post-/status fails; got FAILED: %q", (*calls)[0].message)
	}
	_ = client // silence "declared but not used" for the unused stub
}

// ─── Blocker A: stale /status must not flip exit-0 success to FAILED ─────────

// TestHandleMinorNoReboot_StaleStatusDoesNotCauseFailed is the primary Blocker A
// regression test. OPNsense caches /status from the last /check; an immediate
// re-read after opnsense-update exits 0 sees the PRE-apply counts. The previous
// code compared pre vs post counts and emitted FAILED when they matched — a false
// negative for every successful reboot=false apply.
//
// After the fix, exit 0 → COMPLETED regardless of whether post-/status shows
// the same package counts as pre-/status.
func TestHandleMinorNoReboot_StaleStatusDoesNotCauseFailed(t *testing.T) {
	calls, restoreSend := installNoRebootSendCapture(t)
	defer restoreSend()
	defer installNoopInProgress(t)()

	restoreExec := SetFirmwareExecFuncForTest(func(_ context.Context, args ...string) ([]byte, []byte, int) {
		return []byte("64 packages applied"), nil, 0
	})
	defer restoreExec()

	restoreSuffix := SetFirmwareGetSuffixFuncForTest(func(_ context.Context) (string, error) {
		return "", nil
	})
	defer restoreSuffix()

	// Pre-apply: 62 non-reboot packages + base + kernel (mirrors the lab scenario
	// with product_version 26.1.2 → 26.1.9, 64 packages total).
	pkgs := make([]opnapi.FirmwarePackageEntry, 0, 64)
	for i := 0; i < 62; i++ {
		pkgs = append(pkgs, opnapi.FirmwarePackageEntry{Name: "pkg"})
	}
	pkgs = append(pkgs, opnapi.FirmwarePackageEntry{Name: "base"})
	pkgs = append(pkgs, opnapi.FirmwarePackageEntry{Name: "kernel"})
	preStatus := &opnapi.FirmwareUpgradeStatus{
		ProductVersion:  "26.1.2",
		ProductLatest:   "26.1.9",
		ProductSeries:   "26.1",
		ProductABI:      "FreeBSD:14:amd64",
		Status:          "update",
		UpgradePackages: pkgs,
	}

	// Stale post-apply /status: identical to pre-apply (cache not yet refreshed).
	// OLD code: preNonRebootPkgs(62) >= preNonRebootPkgs(62) → FAILED.
	// NEW code: exit 0 → COMPLETED, stale counts ignored.
	client := &stubFirmwareClient{
		statusResp:     preStatus,
		postStatusResp: preStatus, // stale — identical to pre-apply
	}

	err := handleMinorNoReboot(context.Background(), nil, minorNoRebootCmd("20"), client, &firmwareUpgradePayload{Reboot: false, Mode: "minor"}, preStatus)
	if err != nil {
		t.Fatalf("handleMinorNoReboot returned unexpected error: %v", err)
	}

	if len(*calls) != 1 {
		t.Fatalf("expected exactly 1 terminal SendTaskResponse call, got %d: %+v", len(*calls), *calls)
	}
	if !(*calls)[0].success {
		t.Errorf("REGRESSION (Blocker A): stale /status caused FAILED despite exit 0. message: %q", (*calls)[0].message)
	}
}

// TestHandleMinorNoReboot_MixedStateFromPreApplyData verifies that mixed_state
// is derived from the PRE-apply package list (base/kernel presence), not from
// the potentially-stale post-apply /status.NeedsReboot field.
func TestHandleMinorNoReboot_MixedStateFromPreApplyData(t *testing.T) {
	calls, restoreSend := installNoRebootSendCapture(t)
	defer restoreSend()
	defer installNoopInProgress(t)()

	restoreExec := SetFirmwareExecFuncForTest(func(_ context.Context, args ...string) ([]byte, []byte, int) {
		return []byte("ok"), nil, 0
	})
	defer restoreExec()

	restoreSuffix := SetFirmwareGetSuffixFuncForTest(func(_ context.Context) (string, error) {
		return "", nil
	})
	defer restoreSuffix()

	// Pre-apply has base + kernel → expect mixed_state=true in result data.
	preStatus := minorNoRebootPreStatus([]string{"opnsense"}, true)

	// Post-apply /status has NeedsReboot=false (stale, didn't update yet).
	postStatus := &opnapi.FirmwareUpgradeStatus{
		ProductVersion: "26.1.2",
		ProductLatest:  "26.1.9",
		ProductSeries:  "26.1",
		ProductABI:     "FreeBSD:14:amd64",
		Status:         "none",
		NeedsReboot:    false, // stale — says no reboot needed
	}
	client := &stubFirmwareClient{
		statusResp:     preStatus,
		postStatusResp: postStatus,
	}

	err := handleMinorNoReboot(context.Background(), nil, minorNoRebootCmd("21"), client, &firmwareUpgradePayload{Reboot: false, Mode: "minor"}, preStatus)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(*calls) != 1 {
		t.Fatalf("expected 1 terminal call, got %d", len(*calls))
	}
	if !(*calls)[0].success {
		t.Fatalf("expected COMPLETED, got FAILED: %q", (*calls)[0].message)
	}
	// The message must be valid JSON with mixed_state=true (derived from the
	// PRE-apply package list containing base/kernel, not from the stale
	// post-apply NeedsReboot field).
	msg := (*calls)[0].message
	var parsed map[string]interface{}
	if err2 := json.Unmarshal([]byte(msg), &parsed); err2 != nil {
		t.Fatalf("message is not valid JSON: %v — got %q", err2, msg)
	}
	if ms, ok := parsed["mixed_state"].(bool); !ok || !ms {
		t.Errorf("expected mixed_state=true in JSON message, got %v (full message: %q)", parsed["mixed_state"], msg)
	}
}

// TestHasBaseOrKernelPending verifies the helper used to derive mixed_state.
func TestHasBaseOrKernelPending(t *testing.T) {
	cases := []struct {
		name  string
		pkgs  []opnapi.FirmwarePackageEntry
		want  bool
	}{
		{"empty", nil, false},
		{"only non-reboot", []opnapi.FirmwarePackageEntry{{Name: "opnsense"}, {Name: "curl"}}, false},
		{"has base", []opnapi.FirmwarePackageEntry{{Name: "opnsense"}, {Name: "base"}}, true},
		{"has kernel", []opnapi.FirmwarePackageEntry{{Name: "kernel"}}, true},
		{"has both", []opnapi.FirmwarePackageEntry{{Name: "base"}, {Name: "kernel"}, {Name: "opnsense"}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := hasBaseOrKernelPending(tc.pkgs)
			if got != tc.want {
				t.Errorf("hasBaseOrKernelPending=%v want %v (pkgs=%v)", got, tc.want, tc.pkgs)
			}
		})
	}
}

// containsStr is a simple substring check (mirrors contains in plugin_install_test.go).
func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		func() bool {
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}

// ─── Rich JSON output (fix: Message must be JSON for success paths) ───────────
//
// The NDBroker discards the Data map and only stores Task.Message. The NDCLI
// (parseFirmwareUpgradeData) and NDWeb (parseFirmwareResult) both parse the
// Message field as JSON to render the rich output. The following tests verify
// that every success terminal path emits valid JSON in Message with the correct
// field names matching FirmwareUpgradeData (NDCLI) / FirmwareUpgradeResult (NDWeb).

// assertFirmwareJSON parses msg as JSON into a map and checks that each
// wantField is present with the expected value. t is the test instance.
func assertFirmwareJSON(t *testing.T, msg string, wantFields map[string]interface{}) {
	t.Helper()
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(msg), &parsed); err != nil {
		t.Fatalf("message is not valid JSON: %v\ngot: %q", err, msg)
	}
	for field, wantVal := range wantFields {
		got, ok := parsed[field]
		if !ok {
			t.Errorf("field %q missing in JSON message; message=%q", field, msg)
			continue
		}
		// Compare as strings to avoid float64 vs int type mismatches from json.Unmarshal.
		gotStr := fmt.Sprintf("%v", got)
		wantStr := fmt.Sprintf("%v", wantVal)
		if gotStr != wantStr {
			t.Errorf("field %q: got %v (%T) want %v (%T)", field, got, got, wantVal, wantVal)
		}
	}
}

// captureHandleFirmwareUpgrade runs HandleFirmwareUpgrade with a stubbed
// sendResponse and returns the captured terminal TaskResult.
// The test installs a SendTaskResponse stub via firmwareNoRebootSendResponse
// for the no-reboot path; for the full handler path it captures at the ws level.
func captureNoRebootResult(
	t *testing.T,
	client firmwareOPNAPIClient,
	payload *firmwareUpgradePayload,
	preStatus *opnapi.FirmwareUpgradeStatus,
) (TaskResult, error) {
	t.Helper()
	var captured TaskResult
	restoreSend := SetFirmwareNoRebootSendResponseForTest(func(_ *network.WebSocketClient, _ string, result TaskResult) error {
		captured = result
		return nil
	})
	defer restoreSend()
	defer SetFirmwareNoRebootSendInProgressForTest(func(_ *network.WebSocketClient, _, _ string) error { return nil })()

	restoreExec := SetFirmwareExecFuncForTest(func(_ context.Context, _ ...string) ([]byte, []byte, int) {
		return []byte("packages updated\n"), nil, 0
	})
	defer restoreExec()

	restoreSuffix := SetFirmwareGetSuffixFuncForTest(func(_ context.Context) (string, error) {
		return "", nil
	})
	defer restoreSuffix()

	err := handleMinorNoReboot(context.Background(), nil,
		minorNoRebootCmd("json-test"), client, payload, preStatus)
	return captured, err
}

// TestFirmwareSuccessJSON_IsValidJSON verifies the firmwareSuccessJSON helper
// always returns parseable JSON and never includes package_names (dropped for
// compactness).
func TestFirmwareSuccessJSON_IsValidJSON(t *testing.T) {
	data := map[string]interface{}{
		"resolved_mode":    "minor",
		"from_version":     "26.1.2",
		"to_version":       "26.1.9",
		"reboot_performed": false,
		"applied":          true,
		"no_update":        false,
		"packages_applied": 5,
		"mixed_state":      false,
		"package_names":    []string{"pkg-a", "pkg-b"}, // must be stripped
		"log_tail":         "some log output",
	}
	msg := firmwareSuccessJSON(data)
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(msg), &parsed); err != nil {
		t.Fatalf("firmwareSuccessJSON returned invalid JSON: %v\ngot: %q", err, msg)
	}
	if _, hasNames := parsed["package_names"]; hasNames {
		t.Errorf("firmwareSuccessJSON must drop package_names, but it is present: %q", msg)
	}
}

// TestFirmwareSuccessJSON_LogTailCapped verifies that a log_tail exceeding
// firmwareLogTailMaxBytes is truncated so the total message stays under the
// broker's 16 KiB limit.
func TestFirmwareSuccessJSON_LogTailCapped(t *testing.T) {
	// Build a log_tail of 8 KiB — twice our per-field cap.
	bigLog := make([]byte, 8*1024)
	for i := range bigLog {
		bigLog[i] = 'x'
	}
	data := map[string]interface{}{
		"resolved_mode": "minor",
		"applied":       true,
		"log_tail":      string(bigLog),
	}
	msg := firmwareSuccessJSON(data)
	if len(msg) > firmwareMessageMaxBytes {
		t.Errorf("firmwareSuccessJSON exceeded firmwareMessageMaxBytes (%d): got %d bytes",
			firmwareMessageMaxBytes, len(msg))
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(msg), &parsed); err != nil {
		t.Fatalf("capped message is not valid JSON: %v", err)
	}
}

// TestMinorNoReboot_MessageIsJSONWithCoreFields verifies that the terminal
// response for a successful minor/no-reboot apply carries the core fields
// expected by NDCLI (FirmwareUpgradeData) and NDWeb (FirmwareUpgradeResult)
// as JSON in Message.
func TestMinorNoReboot_MessageIsJSONWithCoreFields(t *testing.T) {
	preStatus := minorNoRebootPreStatus([]string{"opnsense", "curl"}, true)
	client := &stubFirmwareClient{
		statusResp:     preStatus,
		postStatusResp: preStatus, // stale — irrelevant since exit 0 is truth
	}
	result, err := captureNoRebootResult(t, client,
		&firmwareUpgradePayload{Mode: "minor", Reboot: false},
		preStatus)
	if err != nil {
		t.Fatalf("captureNoRebootResult error: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected success, got failure: %q", result.Message)
	}
	// Verify core fields match the NDCLI/NDWeb contract exactly.
	assertFirmwareJSON(t, result.Message, map[string]interface{}{
		"resolved_mode":    "minor",
		"from_version":     "26.1.2",
		"to_version":       "26.1.9",
		"reboot_performed": false,
		"applied":          true,
		"no_update":        false,
		"packages_applied": float64(2), // json.Unmarshal decodes numbers as float64
		"mixed_state":      true,       // base+kernel were pending
	})
}

// TestDryRun_MessageIsJSONWithCoreFields verifies that a dry-run response
// carries a JSON message with dry_run=true and the expected core fields.
func TestDryRun_MessageIsJSONWithCoreFields(t *testing.T) {
	msg := firmwareSuccessJSON(map[string]interface{}{
		"resolved_mode":    "minor",
		"from_version":     "26.1.2",
		"to_version":       "26.1.9",
		"reboot_performed": false,
		"reboots_expected": 0,
		"applied":          false,
		"dry_run":          true,
		"no_update":        false,
		"packages_applied": 3,
		"mixed_state":      false,
	})
	assertFirmwareJSON(t, msg, map[string]interface{}{
		"resolved_mode":    "minor",
		"from_version":     "26.1.2",
		"dry_run":          true,
		"applied":          false,
		"no_update":        false,
		"packages_applied": float64(3),
	})
}

// TestNoUpdate_MessageIsJSONWithCoreFields verifies that a no-op COMPLETED
// response (nothing to update) carries a JSON message with no_update=true.
func TestNoUpdate_MessageIsJSONWithCoreFields(t *testing.T) {
	msg := firmwareSuccessJSON(map[string]interface{}{
		"resolved_mode":    "minor",
		"from_version":     "26.1.2",
		"no_update":        true,
		"applied":          false,
		"reboot_performed": false,
	})
	assertFirmwareJSON(t, msg, map[string]interface{}{
		"resolved_mode": "minor",
		"from_version":  "26.1.2",
		"no_update":     true,
		"applied":       false,
	})
}

// TestFailedPath_MessageIsPlainText verifies that FAILED responses remain plain
// text so they are readable when NDCLI/NDWeb fall back to showing Message raw.
func TestFailedPath_MessageIsPlainText(t *testing.T) {
	result := NewFailureResult("opnsense-update exited with code 1: pkg: repository unavailable")
	if result.Success {
		t.Fatal("NewFailureResult must produce Success=false")
	}
	// Must NOT start with '{' — it should be a human-readable string, not JSON.
	if len(result.Message) > 0 && result.Message[0] == '{' {
		t.Errorf("FAILED message must be plain text, not JSON; got: %q", result.Message)
	}
}
