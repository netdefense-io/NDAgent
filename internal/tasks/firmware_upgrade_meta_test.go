package tasks

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/config"
	"github.com/netdefense-io/ndagent/internal/firmware"
	"github.com/netdefense-io/ndagent/internal/network"
	"github.com/netdefense-io/ndagent/internal/opnapi"
	"github.com/netdefense-io/ndagent/internal/taskstore"
)

var metaTestNow = time.Date(2026, 9, 27, 9, 0, 0, 0, time.UTC)

// firmwareFixture wires the FIRMWARE_UPGRADE paths to an in-memory task store,
// a fixed clock and boot time, and recorders for what they send.
type firmwareFixture struct {
	t     *testing.T
	store *taskstore.Store

	mu        sync.Mutex // the handlers under test send from their own goroutines
	terminals []capturedResponse
	progress  []string
}

func newFirmwareFixture(t *testing.T) *firmwareFixture {
	t.Helper()
	store, err := taskstore.OpenInMemory()
	if err != nil {
		t.Fatalf("OpenInMemory: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	f := &firmwareFixture{t: t, store: store}
	for _, restore := range []func(){
		SetFirmwareTaskStoreForTest(store),
		SetFirmwareBootTimeForTest(func() (int64, error) { return 1_780_000_000, nil }),
		SetFirmwareNowForTest(func() time.Time { return metaTestNow }),
		// The fixture's clock is fixed in the past, but a context deadline is real
		// time: a run must not find its deadline already gone.
		SetFirmwareDeadlineForTest(func(time.Time) time.Time { return time.Now().Add(time.Minute) }),
		SetFirmwareSendResponseForTest(func(_ *network.WebSocketClient, id string, r TaskResult) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.terminals = append(f.terminals, capturedResponse{taskID: id, success: r.Success, message: r.Message})
			return nil
		}),
		SetFirmwareSendInProgressForTest(func(_ *network.WebSocketClient, _, msg string) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.progress = append(f.progress, msg)
			return nil
		}),
		SetUpgradeStatusPollIntervalForTest(time.Millisecond),
		SetFirmwareWaitsForTest(50*time.Millisecond, time.Millisecond, 50*time.Millisecond, time.Millisecond, time.Millisecond),
		SetFirmwareGetSuffixFuncForTest(func(context.Context) (string, error) { return "", nil }),
	} {
		t.Cleanup(restore)
	}
	return f
}

func (f *firmwareFixture) begin(id string) {
	f.t.Helper()
	if err := f.store.Begin(id, "FIRMWARE_UPGRADE", taskstore.LifecycleRestartCompletes); err != nil {
		f.t.Fatalf("Begin %s: %v", id, err)
	}
}

func (f *firmwareFixture) meta(id string) (firmware.Meta, bool) {
	f.t.Helper()
	var m firmware.Meta
	found, err := f.store.GetTaskMeta(id, &m)
	if err != nil {
		f.t.Fatalf("GetTaskMeta: %v", err)
	}
	return m, found
}

// planStatus is a pending update: the core package, a few others, one new
// package, and the base system and kernel. product_latest is deliberately stale.
func planStatus() *opnapi.FirmwareUpgradeStatus {
	return &opnapi.FirmwareUpgradeStatus{
		ProductVersion: "26.7.3_8",
		ProductLatest:  "26.7.3_8",
		ProductSeries:  "26.7",
		Status:         "update",
		NeedsReboot:    true,
		UpgradePackages: []opnapi.FirmwarePackageEntry{
			{Name: "opnsense", CurrentVersion: "26.7.3_8", NewVersionAlt: "26.7.4_1"},
			{Name: "os-netdefense", CurrentVersion: "1.19.4", NewVersionAlt: "1.19.5"},
			{Name: "base", CurrentVersion: "26.7.3", NewVersionAlt: "26.7.4"},
			{Name: "kernel", CurrentVersion: "26.7.3", NewVersionAlt: "26.7.4"},
		},
		NewPackages: []opnapi.FirmwarePackageEntry{{Name: "py311-newdep", NewVersion: "1.0"}},
	}
}

// stoppedByTheReboot is a context that ends soon after it is created: a run that
// reaches ***REBOOT*** keeps its handler until the box takes the agent down, and
// this stands in for that.
func stoppedByTheReboot(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	t.Cleanup(cancel)
	return ctx
}

func rebootCmd(id, mode string, expires int64) network.Command {
	return network.Command{
		TaskID: id, TaskType: "FIRMWARE_UPGRADE", ExpiresAt: expires,
		Payload: map[string]interface{}{"mode": mode, "check_first": false},
	}
}

// The run's metadata must be on the row before the update is triggered: from the
// POST on the row can outlive this process, and it is judged against this.
func TestHandleMinorWithReboot_RecordsTheRunBeforeThePost(t *testing.T) {
	f := newFirmwareFixture(t)
	f.begin("41")

	var atPost firmware.Meta
	var recordedAtPost bool
	client := &stubFirmwareClient{
		statusResp:   planStatus(),
		release:      "26.7.3_8",
		updateResp:   &opnapi.FirmwareUpdateResponse{Status: "ok"},
		runningResp:  &opnapi.FirmwareRunning{Status: "ready"},
		progressResp: &opnapi.FirmwareProgressStatus{Status: "reboot", Log: updateRequestMarker},
	}
	client.onUpdate = func() { atPost, recordedAtPost = f.meta("41") }

	exp := metaTestNow.Add(11 * time.Minute).Unix()
	err := handleMinorWithReboot(stoppedByTheReboot(t), nil, rebootCmd("41", "minor", exp), client,
		&firmwareUpgradePayload{Mode: "minor", Reboot: true}, planStatus())
	if err != nil {
		t.Fatalf("handleMinorWithReboot: %v", err)
	}

	if !recordedAtPost {
		t.Fatal("no metadata on the row when the update was triggered")
	}
	want := firmware.Meta{
		Mode: "minor", Reboot: true, FromVersion: "26.7.3_8", NeedsReboot: true,
		BootTime: 1_780_000_000, StartedAt: metaTestNow.Unix(), TriggeredAt: metaTestNow.Unix(), ExpiresAt: exp,
		Packages: []firmware.Package{
			{Name: "opnsense", Version: "26.7.4_1"}, {Name: "os-netdefense", Version: "1.19.5"},
			{Name: "base", Version: "26.7.4"}, {Name: "kernel", Version: "26.7.4"},
			{Name: "py311-newdep", Version: "1.0"},
		},
	}
	gotJSON, _ := json.Marshal(atPost)
	wantJSON, _ := json.Marshal(want)
	if string(gotJSON) != string(wantJSON) {
		t.Fatalf("metadata at the POST:\n got %s\nwant %s", gotJSON, wantJSON)
	}
}

// A command without a signed expiry (an older NDManager) falls back to the
// task's mode TTL.
func TestHandleMinorWithReboot_WithoutASignedExpiryUsesTheModeTTL(t *testing.T) {
	for mode, ttl := range map[string]time.Duration{"minor": firmware.MinorTTL, "major": firmware.MajorTTL} {
		t.Run(mode, func(t *testing.T) {
			f := newFirmwareFixture(t)
			f.begin("42")
			st := planStatus()
			st.UpgradeMajorVersion = "26.9"
			client := &stubFirmwareClient{
				statusResp:   st,
				release:      "26.7.3_8",
				updateResp:   &opnapi.FirmwareUpdateResponse{Status: "ok"},
				upgradeResp:  &opnapi.FirmwareUpgradeResponse{Status: "ok"},
				runningResp:  &opnapi.FirmwareRunning{Status: "ready"},
				progressResp: &opnapi.FirmwareProgressStatus{Status: "reboot", Log: updateRequestMarker + upgradeRequestMarker},
			}
			handler := handleMinorWithReboot
			if mode == "major" {
				handler = handleMajorWithReboot
			}
			if err := handler(context.Background(), nil, rebootCmd("42", mode, 0), client,
				&firmwareUpgradePayload{Mode: mode, Reboot: true}, st); err != nil {
				t.Fatalf("handler: %v", err)
			}
			m, found := f.meta("42")
			if !found || m.Mode != mode || m.ExpiresAt != metaTestNow.Add(ttl).Unix() {
				t.Fatalf("meta = %+v (found %v), want mode %s expiring after %v", m, found, mode, ttl)
			}
		})
	}
}

func TestHandleMajorWithReboot_RecordsTheRunBeforeThePost(t *testing.T) {
	f := newFirmwareFixture(t)
	f.begin("43")

	st := planStatus()
	st.UpgradeMajorVersion = "26.9"
	var recorded bool
	client := &stubFirmwareClient{
		statusResp:   st,
		release:      "26.7.3_8",
		upgradeResp:  &opnapi.FirmwareUpgradeResponse{Status: "ok"},
		runningResp:  &opnapi.FirmwareRunning{Status: "ready"},
		progressResp: &opnapi.FirmwareProgressStatus{Status: "reboot", Log: upgradeRequestMarker},
	}
	client.onUpgrade = func() { _, recorded = f.meta("43") }

	if err := handleMajorWithReboot(stoppedByTheReboot(t), nil, rebootCmd("43", "major", 0), client,
		&firmwareUpgradePayload{Mode: "major", Reboot: true}, st); err != nil {
		t.Fatalf("handleMajorWithReboot: %v", err)
	}
	if !recorded {
		t.Fatal("no metadata on the row when the upgrade was triggered")
	}
}

// Nothing may be triggered from a release that could not be read: every later
// comparison would be against a guess.
func TestRebootPaths_RefuseToStartWhenTheInstalledReleaseCannotBeRead(t *testing.T) {
	for name, run := range map[string]func(*stubFirmwareClient, *opnapi.FirmwareUpgradeStatus) error{
		"minor": func(c *stubFirmwareClient, st *opnapi.FirmwareUpgradeStatus) error {
			return handleMinorWithReboot(context.Background(), nil, rebootCmd("44", "minor", 0), c,
				&firmwareUpgradePayload{Mode: "minor", Reboot: true}, st)
		},
		"major": func(c *stubFirmwareClient, st *opnapi.FirmwareUpgradeStatus) error {
			return handleMajorWithReboot(context.Background(), nil, rebootCmd("44", "major", 0), c,
				&firmwareUpgradePayload{Mode: "major", Reboot: true}, st)
		},
		"minor without reboot": func(c *stubFirmwareClient, st *opnapi.FirmwareUpgradeStatus) error {
			return handleMinorNoReboot(context.Background(), nil, minorNoRebootCmd("44"), c,
				&firmwareUpgradePayload{Mode: "minor", Reboot: false}, st)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFirmwareFixture(t)
			f.begin("44")
			triggered := false
			client := &stubFirmwareClient{
				statusResp: planStatus(), releaseErr: errors.New("no version file"),
				updateResp:  &opnapi.FirmwareUpdateResponse{Status: "ok"},
				upgradeResp: &opnapi.FirmwareUpgradeResponse{Status: "ok"},
				onUpdate:    func() { triggered = true }, onUpgrade: func() { triggered = true },
			}
			restoreExec := SetFirmwareExecFuncForTest(func(context.Context, ...string) ([]byte, []byte, int) {
				triggered = true
				return nil, nil, 0
			})
			defer restoreExec()

			if err := run(client, planStatus()); err != nil {
				t.Fatalf("handler: %v", err)
			}
			if triggered {
				t.Fatal("the update was triggered although the installed release is unknown")
			}
			if len(f.terminals) != 1 || f.terminals[0].success ||
				!strings.Contains(f.terminals[0].message, "installed OPNsense release") {
				t.Fatalf("terminal responses = %+v, want one FAILED naming the release", f.terminals)
			}
			if _, found := f.meta("44"); found {
				t.Fatal("metadata was recorded for a run that never started")
			}
		})
	}
}

// The reboot=false path runs in the agent's own child, which a package in the
// run can kill. What the run started from has to be on the row before the exec.
func TestHandleMinorNoReboot_RecordsTheRunBeforeTheExec(t *testing.T) {
	f := newFirmwareFixture(t)
	f.begin("45")

	var atExec firmware.Meta
	var recorded bool
	restoreExec := SetFirmwareExecFuncForTest(func(context.Context, ...string) ([]byte, []byte, int) {
		atExec, recorded = f.meta("45")
		return []byte("ok"), nil, 0
	})
	defer restoreExec()

	st := planStatus()
	client := &stubFirmwareClient{statusResp: st, release: "26.7.3_8"}
	if err := handleMinorNoReboot(context.Background(), nil, minorNoRebootCmd("45"), client,
		&firmwareUpgradePayload{Mode: "minor", Reboot: false}, st); err != nil {
		t.Fatalf("handleMinorNoReboot: %v", err)
	}
	if !recorded {
		t.Fatal("no metadata on the row when opnsense-update ran")
	}
	if atExec.Mode != "minor" || atExec.Reboot || atExec.FromVersion != "26.7.3_8" || len(atExec.Packages) != 5 {
		t.Fatalf("metadata at the exec = %+v", atExec)
	}
	if atExec.RebootExpected() {
		t.Fatal("a reboot=false run defers base and kernel and never expects a reboot")
	}
	if !atExec.Triggered() {
		t.Fatalf("metadata at the exec = %+v, want the run marked triggered: the exec is the trigger", atExec)
	}
}

// to_version is the core package's planned version. product_latest reads the
// installed changelog and does not move with the update.
func TestHandleMinorNoReboot_ToVersionComesFromThePlanNotProductLatest(t *testing.T) {
	cases := []struct {
		name     string
		core     []opnapi.FirmwarePackageEntry
		wantFrom string
		wantTo   string
	}{
		{
			name:     "the plan reaches a newer release",
			core:     []opnapi.FirmwarePackageEntry{{Name: "opnsense", CurrentVersion: "26.7.3_8", NewVersionAlt: "26.7.4_1"}},
			wantFrom: "26.7.3_8", wantTo: "26.7.4_1",
		},
		{
			name:     "a plan that leaves the core package alone leaves the release alone",
			core:     nil,
			wantFrom: "26.7.3_8", wantTo: "26.7.3_8",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFirmwareFixture(t)
			f.begin("46")
			restoreExec := SetFirmwareExecFuncForTest(func(context.Context, ...string) ([]byte, []byte, int) {
				return []byte("ok"), nil, 0
			})
			defer restoreExec()

			st := planStatus()
			st.ProductLatest = "26.7.3_8" // stale: it must never be the answer
			st.UpgradePackages = append(tc.core, opnapi.FirmwarePackageEntry{Name: "curl", NewVersionAlt: "8.9.1_1"})
			st.NewPackages = nil
			client := &stubFirmwareClient{statusResp: st, release: "26.7.3_8"}
			if err := handleMinorNoReboot(context.Background(), nil, minorNoRebootCmd("46"), client,
				&firmwareUpgradePayload{Mode: "minor", Reboot: false}, st); err != nil {
				t.Fatalf("handleMinorNoReboot: %v", err)
			}
			if len(f.terminals) != 1 || !f.terminals[0].success {
				t.Fatalf("terminal responses = %+v", f.terminals)
			}
			assertFirmwareJSON(t, f.terminals[0].message, map[string]interface{}{
				"from_version": tc.wantFrom, "to_version": tc.wantTo,
			})
		})
	}
}

// New packages are installed by the update too.
func TestHandleMinorNoReboot_PackagesAppliedCountsNewPackages(t *testing.T) {
	f := newFirmwareFixture(t)
	f.begin("47")
	restoreExec := SetFirmwareExecFuncForTest(func(context.Context, ...string) ([]byte, []byte, int) {
		return []byte("ok"), nil, 0
	})
	defer restoreExec()

	st := planStatus() // opnsense, os-netdefense, base, kernel + one new package
	client := &stubFirmwareClient{statusResp: st, release: "26.7.3_8"}
	if err := handleMinorNoReboot(context.Background(), nil, minorNoRebootCmd("47"), client,
		&firmwareUpgradePayload{Mode: "minor", Reboot: false}, st); err != nil {
		t.Fatalf("handleMinorNoReboot: %v", err)
	}
	assertFirmwareJSON(t, f.terminals[0].message, map[string]interface{}{
		"packages_applied": float64(3), "mixed_state": true,
	})
}

// A preview reports the same numbers the run would.
func TestHandleFirmwareUpgrade_DryRunReportsThePlannedRelease(t *testing.T) {
	f := newFirmwareFixture(t)
	restore := SetOPNAPIClientForFirmwareForTest(&stubFirmwareClient{statusResp: planStatus(), release: "26.7.3_8"})
	defer restore()

	ws := network.NewWebSocketClient(&config.Config{}, nil, nil, nil, nil)
	cmd := network.Command{
		TaskID: "48", TaskType: "FIRMWARE_UPGRADE",
		Payload: map[string]interface{}{"mode": "minor", "check_first": false, "dry_run": true},
	}
	if err := HandleFirmwareUpgrade(context.Background(), ws, cmd); err != nil {
		t.Fatalf("HandleFirmwareUpgrade: %v", err)
	}
	if len(f.terminals) != 1 || !f.terminals[0].success {
		t.Fatalf("terminal responses = %+v", f.terminals)
	}
	assertFirmwareJSON(t, f.terminals[0].message, map[string]interface{}{
		"dry_run": true, "applied": false,
		"from_version": "26.7.3_8", "to_version": "26.7.4_1",
		"packages_applied": float64(3),
	})
}
