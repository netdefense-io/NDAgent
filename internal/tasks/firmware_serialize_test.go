package tasks

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/config"
	"github.com/netdefense-io/ndagent/internal/firmware"
	"github.com/netdefense-io/ndagent/internal/network"
	"github.com/netdefense-io/ndagent/internal/opnapi"
	"github.com/netdefense-io/ndagent/internal/taskstore"
)

// gatedCheckClient blocks the first firmware check until released and counts how
// many run at once.
type gatedCheckClient struct {
	*stubFirmwareClient
	firstCheck chan struct{} // closed by the test to let the first check return
	entered    chan struct{} // receives once the first check is inside

	mu        sync.Mutex
	checks    int
	inside    atomic.Int32
	maxInside atomic.Int32
}

func (c *gatedCheckClient) TriggerFirmwareCheck(ctx context.Context) error {
	c.mu.Lock()
	c.checks++
	n := c.checks
	c.mu.Unlock()

	now := c.inside.Add(1)
	for {
		m := c.maxInside.Load()
		if now <= m || c.maxInside.CompareAndSwap(m, now) {
			break
		}
	}
	defer c.inside.Add(-1)

	if n == 1 {
		close(c.entered)
		select {
		case <-c.firstCheck:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (c *gatedCheckClient) checkCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.checks
}

func nothingPendingStatus() *opnapi.FirmwareUpgradeStatus {
	return &opnapi.FirmwareUpgradeStatus{ProductVersion: "26.7.4_1", ProductSeries: "26.7", Status: "ok"}
}

func newGatedClient() *gatedCheckClient {
	return &gatedCheckClient{
		stubFirmwareClient: &stubFirmwareClient{
			statusResp:  nothingPendingStatus(),
			runningResp: &opnapi.FirmwareRunning{Status: "ready"},
		},
		firstCheck: make(chan struct{}),
		entered:    make(chan struct{}),
	}
}

func firmwareWS() *network.WebSocketClient {
	return network.NewWebSocketClient(&config.Config{}, nil, nil, nil, nil)
}

func minorCmd(id string) network.Command {
	return network.Command{
		TaskID: id, TaskType: "FIRMWARE_UPGRADE",
		Payload: map[string]interface{}{"mode": "minor"},
	}
}

// After every test in this file the process-wide slot must be free again.
func requireSlotFree(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		if firmware.Busy() {
			t.Error("the firmware slot was left taken")
		}
	})
}

// The Sunday schedules dispatch a daily and a weekly task in the same second.
// They must not each trigger a check and poll the same progress log: the second
// waits for the first, then does its own work, which by then is usually nothing.
func TestHandleFirmwareUpgrade_TwoTasksRunOneAfterTheOther(t *testing.T) {
	requireSlotFree(t)
	f := newFirmwareFixture(t)
	c := newGatedClient()
	defer SetOPNAPIClientForFirmwareForTest(c)()
	ws := firmwareWS()

	firstDone := make(chan error, 1)
	go func() { firstDone <- HandleFirmwareUpgrade(context.Background(), ws, minorCmd("81")) }()
	<-c.entered // the first task is inside its check, holding the slot

	secondDone := make(chan error, 1)
	go func() { secondDone <- HandleFirmwareUpgrade(context.Background(), ws, minorCmd("82")) }()

	time.Sleep(80 * time.Millisecond)
	if n := c.checkCount(); n != 1 {
		t.Fatalf("%d checks started while the first task was running, want 1: the second must wait", n)
	}
	f.mu.Lock()
	waiting := append([]string(nil), f.progress...)
	f.mu.Unlock()
	if !containsMessage(waiting, "Waiting for another firmware task") {
		t.Fatalf("IN_PROGRESS messages = %v, want the second task to say it is waiting", waiting)
	}

	close(c.firstCheck)
	for i, done := range []chan error{firstDone, secondDone} {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("task %d returned %v", i+1, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("task %d never finished", i+1)
		}
	}

	if c.maxInside.Load() != 1 {
		t.Fatalf("%d firmware checks overlapped, want none", c.maxInside.Load())
	}
	if c.checkCount() != 2 {
		t.Fatalf("%d checks in all, want one per task", c.checkCount())
	}
	// Each answers for itself: the second one's own check found nothing to do.
	byTask := map[string]capturedResponse{}
	f.mu.Lock()
	for _, r := range f.terminals {
		byTask[r.taskID] = r
	}
	f.mu.Unlock()
	for _, id := range []string{"81", "82"} {
		r, ok := byTask[id]
		if !ok || !r.success || !strings.Contains(r.message, `"no_update":true`) {
			t.Fatalf("task %s answered %+v, want a COMPLETED no-op", id, r)
		}
	}
}

func containsMessage(list []string, sub string) bool {
	for _, s := range list {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// A task cancelled while it waits for the slot starts nothing.
func TestHandleFirmwareUpgrade_ACancelledWaiterStartsNothing(t *testing.T) {
	requireSlotFree(t)
	newFirmwareFixture(t)
	c := newGatedClient()
	defer SetOPNAPIClientForFirmwareForTest(c)()
	ws := firmwareWS()

	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		_ = HandleFirmwareUpgrade(context.Background(), ws, minorCmd("83"))
	}()
	<-c.entered
	defer func() {
		close(c.firstCheck)
		<-firstDone // the first task must be finished before the fixture is torn down
	}()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- HandleFirmwareUpgrade(ctx, ws, minorCmd("84")) }()
	time.Sleep(30 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("the cancelled waiter returned %v; the dispatcher needs the cancellation to record it", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the cancelled waiter never returned")
	}
	if c.checkCount() != 1 {
		t.Fatalf("%d checks, want only the first task's", c.checkCount())
	}
}

// Every way out of the handler gives the slot back.
func TestHandleFirmwareUpgrade_EveryExitReleasesTheSlot(t *testing.T) {
	ws := firmwareWS()
	cases := []struct {
		name    string
		payload map[string]interface{}
		client  func() firmwareOPNAPIClient
	}{
		{
			name:    "no update pending",
			payload: map[string]interface{}{"mode": "minor", "check_first": false},
			client:  func() firmwareOPNAPIClient { return &stubFirmwareClient{statusResp: nothingPendingStatus()} },
		},
		{
			name:    "status cannot be read",
			payload: map[string]interface{}{"mode": "minor", "check_first": false},
			client:  func() firmwareOPNAPIClient { return &stubFirmwareClient{statusErr: errors.New("boom")} },
		},
		{
			name:    "dry run",
			payload: map[string]interface{}{"mode": "minor", "check_first": false, "dry_run": true},
			client:  func() firmwareOPNAPIClient { return &stubFirmwareClient{statusResp: planStatus(), release: "26.7.3_8"} },
		},
		{
			name:    "invalid payload",
			payload: map[string]interface{}{"mode": "sideways"},
			client:  func() firmwareOPNAPIClient { return &stubFirmwareClient{} },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			requireSlotFree(t)
			newFirmwareFixture(t)
			defer SetOPNAPIClientForFirmwareForTest(tc.client())()

			cmd := network.Command{TaskID: "85", TaskType: "FIRMWARE_UPGRADE", Payload: tc.payload}
			if err := HandleFirmwareUpgrade(context.Background(), ws, cmd); err != nil {
				t.Fatalf("HandleFirmwareUpgrade: %v", err)
			}
			if firmware.Busy() {
				t.Fatal("the slot is still taken after the handler returned")
			}
		})
	}
}

// rebootFlowClient is OPNsense as an update that ends in a reboot shows itself:
// idle until the update is requested, then busy and holding the firmware lock
// (a check made now is dropped without a word), then announcing the reboot, then,
// once the box shuts down, unreachable. It records what the tasks ask of it.
type rebootFlowClient struct {
	*stubFirmwareClient

	mu       sync.Mutex
	phase    string // idle, updating, rebooting, down
	checks   int
	statuses int
	posted   chan struct{}
	postOnce sync.Once
	// gate, when set, holds the first firmware check until it is closed.
	gate chan struct{}
	// onPost runs when the update is requested.
	onPost func()
}

func newRebootFlowClient() *rebootFlowClient {
	return &rebootFlowClient{
		stubFirmwareClient: &stubFirmwareClient{
			statusResp: planStatus(), release: "26.7.3_8",
			updateResp: &opnapi.FirmwareUpdateResponse{Status: "ok"},
		},
		phase:  "idle",
		posted: make(chan struct{}),
	}
}

func (c *rebootFlowClient) set(phase string) {
	c.mu.Lock()
	c.phase = phase
	c.mu.Unlock()
}

func (c *rebootFlowClient) counts() (checks, statuses int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.checks, c.statuses
}

var errBoxDown = errors.New("dial tcp 127.0.0.1:443: connect: connection refused")

func (c *rebootFlowClient) TriggerFirmwareCheck(ctx context.Context) error {
	c.mu.Lock()
	c.checks++
	first := c.checks == 1
	gate, phase := c.gate, c.phase
	c.mu.Unlock()
	if first && gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if phase == "down" {
		return errBoxDown
	}
	return nil // accepted, and dropped by the launcher while the lock is held
}

func (c *rebootFlowClient) GetFirmwareRunning(context.Context) (*opnapi.FirmwareRunning, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch c.phase {
	case "idle":
		return &opnapi.FirmwareRunning{Status: "ready"}, nil
	case "down":
		return nil, errBoxDown
	default:
		return &opnapi.FirmwareRunning{Status: "busy"}, nil
	}
}

func (c *rebootFlowClient) GetFirmwareUpgradeStatus(context.Context) (*opnapi.FirmwareUpgradeStatus, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.statuses++
	if c.phase == "down" {
		return nil, errBoxDown
	}
	return planStatus(), nil
}

func (c *rebootFlowClient) TriggerFirmwareUpdate(context.Context) (*opnapi.FirmwareUpdateResponse, error) {
	if c.onPost != nil {
		c.onPost()
	}
	c.mu.Lock()
	c.phase = "updating"
	c.mu.Unlock()
	c.postOnce.Do(func() { close(c.posted) })
	return &opnapi.FirmwareUpdateResponse{Status: "ok"}, nil
}

func (c *rebootFlowClient) GetFirmwareUpgradeProgress(context.Context) (*opnapi.FirmwareProgressStatus, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch c.phase {
	case "idle":
		return &opnapi.FirmwareProgressStatus{Status: "done", Log: "the previous run\n***DONE***"}, nil
	case "updating":
		return &opnapi.FirmwareProgressStatus{Status: "running", Log: updateRequestMarker + "\nupgrading..."}, nil
	case "rebooting":
		return &opnapi.FirmwareProgressStatus{Status: "reboot", Log: updateRequestMarker + "\n***REBOOT***"}, nil
	default:
		return nil, errBoxDown
	}
}

func (f *firmwareFixture) progressMessages() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.progress...)
}

func (f *firmwareFixture) terminalResponses() []capturedResponse {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]capturedResponse(nil), f.terminals...)
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// The update reboots the box, which stops the agent, and the second task of the
// Sunday pair is queued behind it. update.sh holds OPNsense's lock until the
// shutdown, so the first handler keeps its place after the reboot announcement: a
// second task let in then would run its check against a busy, soon unreachable
// box and end FAILED "Failed to read firmware status". The second waits for the
// run to end, which here means for the agent to be stopped, and then leaves its
// row for the reconciler instead of reporting anything.
func TestHandleFirmwareUpgrade_TheSecondTaskWaitsOutARebootingRun(t *testing.T) {
	requireSlotFree(t)
	f := newFirmwareFixture(t)
	defer SetFirmwareCheckPollIntervalForTest(time.Millisecond)()
	c := newRebootFlowClient()
	defer SetOPNAPIClientForFirmwareForTest(c)()
	ws := firmwareWS()
	f.begin("91")
	f.begin("92")

	agent, stopAgent := context.WithCancel(context.Background())
	defer stopAgent()
	firstDone, secondDone := make(chan error, 1), make(chan error, 1)
	go func() { firstDone <- HandleFirmwareUpgrade(agent, ws, minorCmd("91")) }()
	<-c.posted
	go func() { secondDone <- HandleFirmwareUpgrade(agent, ws, minorCmd("92")) }()
	waitUntil(t, "the second task to say it is waiting", func() bool {
		return containsMessage(f.progressMessages(), "Waiting for another firmware task")
	})

	c.set("rebooting") // ***REBOOT*** is printed: the first run has done what it does
	time.Sleep(50 * time.Millisecond)
	c.set("down") // update.sh sleeps, then rc.reboot takes the box down
	time.Sleep(150 * time.Millisecond)

	if checks, _ := c.counts(); checks != 1 {
		t.Fatalf("%d firmware checks were made, want the first task's alone: the second must not touch a box that is rebooting (terminals so far: %+v)",
			checks, f.terminalResponses())
	}
	if got := f.terminalResponses(); len(got) != 0 {
		t.Fatalf("terminal responses = %+v while the box was going down, want none", got)
	}

	stopAgent() // the reboot stops the agent
	for i, done := range []chan error{firstDone, secondDone} {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("task %d returned %v; a task left for the reconciler is not an error (the dispatcher would record it FAILED)", i+1, err)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("task %d never returned after the agent was stopped", i+1)
		}
	}
	if got := f.terminalResponses(); len(got) != 0 {
		t.Fatalf("terminal responses = %+v after the agent was stopped, want none: both rows are the reconciler's", got)
	}
	for _, id := range []string{"91", "92"} {
		if rec, _, _ := f.store.Get(id); rec.Status != taskstore.StatusInProgress {
			t.Fatalf("row %s is %s, want IN_PROGRESS", id, rec.Status)
		}
	}
	if m, found := f.meta("92"); !found || m.Mode != "minor" || m.Triggered() {
		t.Fatalf("meta of the second task = %+v (found %v), want the not-yet-triggered record of its run", m, found)
	}
}

// The other order of the Sunday pair: the task with nothing to do goes first, and
// the one with an update to apply waits for it and then runs undisturbed.
func TestHandleFirmwareUpgrade_ARebootRunQueuedBehindANoOpRunsAfterIt(t *testing.T) {
	requireSlotFree(t)
	f := newFirmwareFixture(t)
	c := newRebootFlowClient()
	c.gate = make(chan struct{})
	var terminalsAtThePost []capturedResponse
	c.onPost = func() { terminalsAtThePost = f.terminalResponses() }
	defer SetOPNAPIClientForFirmwareForTest(c)()
	ws := firmwareWS()
	f.begin("101")
	f.begin("102")

	agent, stopAgent := context.WithCancel(context.Background())
	defer stopAgent()
	noOpDone, updateDone := make(chan error, 1), make(chan error, 1)
	// The status shows minor updates only: a major task has nothing to do.
	major := network.Command{TaskID: "101", TaskType: "FIRMWARE_UPGRADE", Payload: map[string]interface{}{"mode": "major"}}
	go func() { noOpDone <- HandleFirmwareUpgrade(agent, ws, major) }()
	waitUntil(t, "the first task to be inside its check", func() bool { checks, _ := c.counts(); return checks == 1 })
	go func() { updateDone <- HandleFirmwareUpgrade(agent, ws, minorCmd("102")) }()
	waitUntil(t, "the second task to say it is waiting", func() bool {
		return containsMessage(f.progressMessages(), "Waiting for another firmware task")
	})
	if checks, _ := c.counts(); checks != 1 {
		t.Fatalf("%d checks while the first task held the slot, want its own alone", checks)
	}

	close(c.gate)
	select {
	case err := <-noOpDone:
		if err != nil {
			t.Fatalf("the no-op task returned %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the no-op task never finished")
	}
	<-c.posted
	c.set("rebooting")
	time.Sleep(30 * time.Millisecond)
	stopAgent() // the reboot stops the agent
	if err := <-updateDone; err != nil {
		t.Fatalf("the update task returned %v", err)
	}

	if len(terminalsAtThePost) != 1 || terminalsAtThePost[0].taskID != "101" || !terminalsAtThePost[0].success ||
		!strings.Contains(terminalsAtThePost[0].message, `"no_update":true`) {
		t.Fatalf("terminal responses when the update was requested = %+v, want the no-op task's COMPLETED alone", terminalsAtThePost)
	}
	if got := f.terminalResponses(); len(got) != 1 {
		t.Fatalf("terminal responses = %+v, want only the no-op task's: the update task's row is the reconciler's", got)
	}
	if m, found := f.meta("102"); !found || !m.Triggered() || m.Mode != "minor" {
		t.Fatalf("meta of the update task = %+v (found %v), want the triggered run", m, found)
	}
}

// A task whose own lifetime runs out while it waits for its turn is failed, and
// starts nothing: NDManager stopped waiting for it, and an update applied now
// would be one nobody asked for.
func TestHandleFirmwareUpgrade_AWaiterWhoseTimeRunsOutIsFailedAndStartsNothing(t *testing.T) {
	requireSlotFree(t)
	f := newFirmwareFixture(t)
	c := newGatedClient()
	defer SetOPNAPIClientForFirmwareForTest(c)()
	ws := firmwareWS()
	exp := metaTestNow.Add(time.Minute).Unix()
	defer SetFirmwareNowForTest(func() time.Time { return time.Unix(exp, 0).Add(-40 * time.Millisecond) })()
	f.begin("93")
	f.begin("94")

	firstDone := make(chan struct{})
	go func() { defer close(firstDone); _ = HandleFirmwareUpgrade(context.Background(), ws, minorCmd("93")) }()
	<-c.entered
	defer func() {
		close(c.firstCheck)
		<-firstDone
	}()

	waiter := minorCmd("94")
	waiter.ExpiresAt = exp
	done := make(chan error, 1)
	go func() { done <- HandleFirmwareUpgrade(context.Background(), ws, waiter) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the waiter returned %v, want a FAILED response", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the waiter outlived its own task")
	}

	got := f.terminalResponses()
	if len(got) != 1 || got[0].taskID != "94" || got[0].success || !strings.Contains(got[0].message, "expired while it waited") {
		t.Fatalf("terminal responses = %+v, want one FAILED for the waiter saying it expired while waiting", got)
	}
	if c.checkCount() != 1 {
		t.Fatalf("%d checks, want the first task's alone: the expired task must not touch the device", c.checkCount())
	}
}

func TestHandleFirmwareUpgrade_ATaskThatArrivesExpiredStartsNothing(t *testing.T) {
	requireSlotFree(t)
	f := newFirmwareFixture(t)
	client := &stubFirmwareClient{statusResp: planStatus(), release: "26.7.3_8", runningResp: &opnapi.FirmwareRunning{Status: "ready"}}
	defer SetOPNAPIClientForFirmwareForTest(client)()
	f.begin("95")

	cmd := minorCmd("95")
	cmd.ExpiresAt = metaTestNow.Add(-time.Minute).Unix()
	if err := HandleFirmwareUpgrade(context.Background(), firmwareWS(), cmd); err != nil {
		t.Fatalf("HandleFirmwareUpgrade: %v", err)
	}
	got := f.terminalResponses()
	if len(got) != 1 || got[0].success || !strings.Contains(got[0].message, "expired") {
		t.Fatalf("terminal responses = %+v, want one FAILED saying the task expired", got)
	}
	if client.statusCallCount != 0 {
		t.Fatalf("the device was asked for its status %d times by a task that had expired", client.statusCallCount)
	}
	if firmware.Busy() {
		t.Fatal("the slot was left taken")
	}
}

// A waiter that is cancelled (the connection dropped, the agent is stopping)
// starts nothing and leaves its row, with the record that it never started, for
// the reconciler; the dispatcher's generic "task was cancelled" would say less.
func TestHandleFirmwareUpgrade_ACancelledWaiterLeavesItsRowForTheReconciler(t *testing.T) {
	requireSlotFree(t)
	f := newFirmwareFixture(t)
	c := newGatedClient()
	defer SetOPNAPIClientForFirmwareForTest(c)()
	ws := firmwareWS()
	f.begin("96")
	f.begin("97")

	firstDone := make(chan struct{})
	go func() { defer close(firstDone); _ = HandleFirmwareUpgrade(context.Background(), ws, minorCmd("96")) }()
	<-c.entered
	defer func() {
		close(c.firstCheck)
		<-firstDone
	}()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- HandleFirmwareUpgrade(ctx, ws, minorCmd("97")) }()
	waitUntil(t, "the waiter to say it is waiting", func() bool {
		return containsMessage(f.progressMessages(), "Waiting for another firmware task")
	})
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the cancelled waiter returned %v; the row is left for the reconciler, which is not an error", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the cancelled waiter never returned")
	}
	if rec, _, _ := f.store.Get("97"); rec.Status != taskstore.StatusInProgress {
		t.Fatalf("row is %s, want IN_PROGRESS", rec.Status)
	}
	if m, found := f.meta("97"); !found || m.Mode != "minor" || !m.Reboot || m.Triggered() {
		t.Fatalf("meta = %+v (found %v), want the record of a task that never triggered anything", m, found)
	}
	if len(f.terminalResponses()) != 0 {
		t.Fatalf("terminal responses = %+v, want none", f.terminalResponses())
	}
}

// The mixed pair. The task that does not reboot runs the update in the agent's
// own child, and a package in it replaces the agent, which stops the agent under
// it. The weekly task that reboots is still waiting. Neither may end up looking
// like a row an older agent wrote (which is completed as soon as the box is idle,
// so the weekly update and its reboot would never run and would be reported done).
func TestHandleFirmwareUpgrade_AnAgentStoppedByItsOwnUpgradeLeavesBothRowsDistinguishable(t *testing.T) {
	requireSlotFree(t)
	f := newFirmwareFixture(t)
	client := &stubFirmwareClient{
		statusResp: packagesOnlyStatus(), release: "26.7.3_8",
		runningResp: &opnapi.FirmwareRunning{Status: "ready"}, updateResp: &opnapi.FirmwareUpdateResponse{Status: "ok"},
	}
	defer SetOPNAPIClientForFirmwareForTest(client)()
	inExec := make(chan struct{})
	defer SetFirmwareExecFuncForTest(func(ctx context.Context, _ ...string) ([]byte, []byte, int) {
		close(inExec)
		<-ctx.Done() // pkg replaces the agent's own package: the agent is stopped under the exec
		return nil, []byte("signal: killed"), -1
	})()
	ws := firmwareWS()
	f.begin("98")
	f.begin("99")

	agent, stopAgent := context.WithCancel(context.Background())
	defer stopAgent()
	noReboot := network.Command{TaskID: "98", TaskType: "FIRMWARE_UPGRADE",
		Payload: map[string]interface{}{"mode": "minor", "reboot": false, "check_first": false}}
	weekly := network.Command{TaskID: "99", TaskType: "FIRMWARE_UPGRADE",
		Payload: map[string]interface{}{"mode": "minor", "check_first": false}}
	firstDone, secondDone := make(chan error, 1), make(chan error, 1)
	go func() { firstDone <- HandleFirmwareUpgrade(agent, ws, noReboot) }()
	<-inExec
	go func() { secondDone <- HandleFirmwareUpgrade(agent, ws, weekly) }()
	waitUntil(t, "the weekly task to say it is waiting", func() bool {
		return containsMessage(f.progressMessages(), "Waiting for another firmware task")
	})

	stopAgent()
	for _, done := range []chan error{firstDone, secondDone} {
		if err := <-done; err != nil {
			t.Fatalf("a handler returned %v", err)
		}
	}
	if got := f.terminalResponses(); len(got) != 0 {
		t.Fatalf("terminal responses = %+v, want none: both rows are the reconciler's", got)
	}
	first, _ := f.meta("98")
	if !first.Triggered() || first.Reboot || len(first.Packages) == 0 {
		t.Fatalf("meta of the task whose exec was killed = %+v, want its triggered run with the plan", first)
	}
	second, found := f.meta("99")
	if !found || second.Mode != "minor" || !second.Reboot || second.Triggered() {
		t.Fatalf("meta of the waiting weekly task = %+v (found %v), want the record of a task that never triggered", second, found)
	}
}
