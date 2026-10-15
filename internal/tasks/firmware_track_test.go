package tasks

import (
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/config"
	"github.com/netdefense-io/ndagent/internal/firmware"
	"github.com/netdefense-io/ndagent/internal/firmware/track"
	"github.com/netdefense-io/ndagent/internal/network"
	"github.com/netdefense-io/ndagent/internal/opnapi"
	"github.com/netdefense-io/ndagent/internal/taskstore"
)

// quietDevice is a device the handler tests drive: it reads as a healthy
// community 26.7.3_11 and holds nothing the pin lifecycle would write. The
// methods of a series upgrade are the embedded interface's, which is nil: these
// tests never ask for one, and a call that did would fail loudly.
type quietDevice struct {
	track.Device
	settings  opnapi.FirmwareSettings
	installed string
	block     chan struct{} // when set, reading the settings waits for it or the context
}

func (d *quietDevice) Settings(ctx context.Context) (opnapi.FirmwareSettings, error) {
	if d.block != nil {
		select {
		case <-d.block:
		case <-ctx.Done():
			return opnapi.FirmwareSettings{}, ctx.Err()
		}
	}
	return d.settings, nil
}
func (d *quietDevice) SetFlavour(context.Context, string) error  { return errors.New("not expected") }
func (d *quietDevice) Installed(context.Context) (string, error) { return d.installed, nil }
func (d *quietDevice) RepoBase(context.Context) (track.RepoBase, error) {
	return track.RepoBase{}, errors.New("no mirror")
}
func (d *quietDevice) RepoPath(context.Context) (string, error) { return "", errors.New("no file") }
func (d *quietDevice) Probe(context.Context, string) track.ProbeResult {
	return track.ProbeUnreachable
}
func (d *quietDevice) Running(context.Context) (firmware.RunState, error) {
	return firmware.RunReady, nil
}
func (d *quietDevice) TriggerCheck(context.Context) error { return errors.New("not expected") }
func (d *quietDevice) Status(context.Context) (*opnapi.FirmwareUpgradeStatus, error) {
	return &opnapi.FirmwareUpgradeStatus{}, nil
}
func (d *quietDevice) TriggerUpdate(context.Context) (string, error) {
	return "", errors.New("not expected")
}
func (d *quietDevice) Progress(context.Context) (*opnapi.FirmwareProgressStatus, error) {
	return nil, errors.New("not expected")
}
func (d *quietDevice) ApplyPackagesOnly(context.Context) (track.ExecResult, error) {
	return track.ExecResult{}, errors.New("not expected")
}
func (d *quietDevice) Probes() firmware.Probes { return firmware.Probes{} }

type sentAnswer struct {
	taskID string
	result TaskResult
}

type trackHarness struct {
	t     *testing.T
	ws    *network.WebSocketClient
	store *taskstore.Store
	dev   *quietDevice
	state *track.StateStore

	mu       sync.Mutex
	answers  []sentAnswer
	progress []string
}

func newTrackHarness(t *testing.T, withEngine bool) *trackHarness {
	t.Helper()
	firmware.ResetGuardForTest()
	t.Cleanup(firmware.ResetGuardForTest)
	h := &trackHarness{t: t, dev: &quietDevice{installed: "26.7.3_11"}}
	h.ws = network.NewWebSocketClient(&config.Config{}, nil, nil, nil, nil)

	store, err := taskstore.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	h.store = store

	prevStore, prevSend, prevProgress := firmwareTaskStore, firmwareTrackSend, firmwareTrackInProgress
	firmwareTaskStore = func(*network.WebSocketClient) *taskstore.Store { return store }
	firmwareTrackSend = func(_ *network.WebSocketClient, taskID string, result TaskResult) error {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.answers = append(h.answers, sentAnswer{taskID, result})
		return nil
	}
	firmwareTrackInProgress = func(_ *network.WebSocketClient, _ string, message string) error {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.progress = append(h.progress, message)
		return nil
	}
	t.Cleanup(func() {
		firmwareTaskStore, firmwareTrackSend, firmwareTrackInProgress = prevStore, prevSend, prevProgress
		SetFirmwareTrackEngine(nil)
	})

	if withEngine {
		h.state = track.NewStateStore(filepath.Join(t.TempDir(), "firmware-track.json"))
		SetFirmwareTrackEngine(track.New(h.dev, h.state, nil,
			track.WithTiming(track.Timing{Poll: time.Millisecond, ReadyWait: 20 * time.Millisecond, CheckTimeout: 50 * time.Millisecond,
				CheckIdleDrop: 5 * time.Millisecond, StartWindow: 20 * time.Millisecond, StartPoll: time.Millisecond, Settle: time.Millisecond}),
			track.WithJitter(func(time.Duration) time.Duration { return 0 })))
	} else {
		SetFirmwareTrackEngine(nil)
	}
	return h
}

func (h *trackHarness) answerList() []sentAnswer {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]sentAnswer(nil), h.answers...)
}

func (h *trackHarness) dispatch(ctx context.Context, taskID string, payload map[string]interface{}, expires time.Time) error {
	if err := h.store.Begin(taskID, network.TaskTypeFirmwareTrack, LifecycleFor(network.TaskTypeFirmwareTrack)); err != nil {
		h.t.Fatal(err)
	}
	cmd := network.Command{TaskID: taskID, TaskType: network.TaskTypeFirmwareTrack, Payload: payload}
	if !expires.IsZero() {
		cmd.ExpiresAt = expires.Unix()
	}
	return HandleFirmwareTrack(ctx, h.ws, cmd)
}

func (h *trackHarness) onlyAnswer() sentAnswer {
	h.t.Helper()
	got := h.answerList()
	if len(got) != 1 {
		h.t.Fatalf("answers = %+v, want exactly one", got)
	}
	return got[0]
}

func TestHandleFirmwareTrack_APayloadThatIsNotTheContractIsFailed(t *testing.T) {
	h := newTrackHarness(t, true)
	for name, payload := range map[string]map[string]interface{}{
		"nothing":            nil,
		"an unknown key":     {"action": "enroll", "track": "fast", "flavour": "26.7/MINT/26.7.3/latest"},
		"an unknown action":  {"action": "upgrade", "track": "fast"},
		"advance, no target": {"action": "advance", "track": "fast"},
		"reboot as a string": {"action": "enroll", "track": "fast", "reboot": "true"},
	} {
		h.answers = nil
		if err := h.dispatch(context.Background(), "9"+name[:1], payload, time.Time{}); err != nil {
			t.Fatal(err)
		}
		got := h.onlyAnswer()
		if got.result.Success || !strings.HasPrefix(got.result.Message, "Invalid FIRMWARE_TRACK payload") {
			t.Errorf("%s: answer %+v", name, got.result)
		}
		if got.result.Data != nil {
			t.Errorf("%s: a refused payload must not name a release it was not moving to", name)
		}
	}
}

func TestHandleFirmwareTrack_WithoutAnEngineAnEnrollIsHeldAndAnUnenrollFails(t *testing.T) {
	h := newTrackHarness(t, false)
	if err := h.dispatch(context.Background(), "11", map[string]interface{}{"action": "enroll", "track": "regular"}, time.Time{}); err != nil {
		t.Fatal(err)
	}
	got := h.onlyAnswer()
	if !got.result.Success {
		t.Fatalf("answer %+v", got.result)
	}
	if f := track.ValidateResult(got.result.Message, &track.Expect{Action: "enroll", Track: "regular", Approved: map[string]string{}}); f != nil {
		t.Fatalf("result %s refused: %v", got.result.Message, f)
	}
	if !strings.Contains(got.result.Message, `"outcome":"held"`) || !strings.Contains(got.result.Message, `"reason":"held_check_failed"`) {
		t.Errorf("result %s", got.result.Message)
	}

	h.answers = nil
	if err := h.dispatch(context.Background(), "12", map[string]interface{}{"action": "unenroll", "track": "regular"}, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if got := h.onlyAnswer(); got.result.Success || !strings.Contains(got.result.Message, "API client not configured") {
		t.Errorf("answer %+v", got.result)
	}
}

func TestHandleFirmwareTrack_RecordsTheTaskBeforeItRunsAndAnswersWithTheResult(t *testing.T) {
	h := newTrackHarness(t, true)
	exp := time.Now().Add(5 * time.Minute)
	if err := h.dispatch(context.Background(), "21", map[string]interface{}{"action": "unenroll", "track": "stable"}, exp); err != nil {
		t.Fatal(err)
	}
	got := h.onlyAnswer()
	if got.taskID != "21" || !got.result.Success {
		t.Fatalf("answer %+v", got)
	}
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(got.result.Message), &result); err != nil {
		t.Fatalf("the message is not the result JSON: %q", got.result.Message)
	}
	if result["action"] != "unenroll" || result["track"] != "stable" || result["outcome"] != "noop" || result["reason"] != "unenrolled" {
		t.Errorf("result %v", result)
	}

	// The job the row carries names what the answer has to echo, and the signed
	// expiry the task was given.
	var job track.Job
	found, err := h.store.GetTaskMeta("21", &job)
	if err != nil || !found {
		t.Fatalf("the task row carries no job: found=%v err=%v", found, err)
	}
	if job.Action != "unenroll" || job.Track != "stable" || job.ExpiresAt != exp.Unix() {
		t.Errorf("job %+v", job)
	}
}

func TestHandleFirmwareTrack_ATestModeAdvanceIsAHoldAndNotAFailure(t *testing.T) {
	h := newTrackHarness(t, true)
	h.ws = network.NewWebSocketClient(&config.Config{TestMode: true}, nil, nil, nil, nil)
	h.dev.settings = opnapi.FirmwareSettings{}
	payload := map[string]interface{}{"action": "advance", "track": "fast", "approved": map[string]interface{}{"26.7": "26.7.5"}}
	if err := h.dispatch(context.Background(), "31", payload, time.Time{}); err != nil {
		t.Fatal(err)
	}
	got := h.onlyAnswer()
	if !got.result.Success {
		t.Fatalf("answer %+v: a FAILED advance is counted against a release for the whole organization, even when it names none", got.result)
	}
	if f := track.ValidateResult(got.result.Message, &track.Expect{Action: "advance", Track: "fast", Approved: map[string]string{"26.7": "26.7.5"}}); f != nil {
		t.Fatalf("result %s refused: %v", got.result.Message, f)
	}
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(got.result.Message), &result); err != nil {
		t.Fatalf("the message is not the result JSON: %q", got.result.Message)
	}
	if result["outcome"] != "held" || result["reason"] != "held_test_mode" || result["target_version"] != "26.7.5" || result["from_version"] != "26.7.3_11" {
		t.Errorf("result %v", result)
	}
	if got.result.Data != nil {
		t.Errorf("data %v: a completed result carries no failure detail", got.result.Data)
	}
}

func TestHandleFirmwareTrack_AnUnenrollThatCannotRestoreIsFailedAndNamesNoRelease(t *testing.T) {
	h := newTrackHarness(t, true)
	const pin = "26.7/MINT/26.7.3/latest"
	if err := h.state.Save(&track.State{Pinned: true, Track: "fast", PinnedFlavour: pin, PinnedVersion: "26.7.3_11"}); err != nil {
		t.Fatal(err)
	}
	h.dev.settings = opnapi.FirmwareSettings{Flavour: pin}
	if err := h.dispatch(context.Background(), "32", map[string]interface{}{"action": "unenroll", "track": "fast"}, time.Time{}); err != nil {
		t.Fatal(err)
	}
	got := h.onlyAnswer()
	if got.result.Success || !strings.Contains(got.result.Message, "Could not restore the firmware setting") {
		t.Fatalf("answer %+v: an unenroll that did not restore the setting must fail, never hold", got.result)
	}
	if got.result.Data != nil {
		t.Errorf("data %v: an unenroll moves to no release", got.result.Data)
	}
	if st, err := h.state.Load(); err != nil || st == nil || !st.Pinned {
		t.Errorf("the record must keep the pin: %+v (%v)", st, err)
	}
}

// The connection dropping under a running task leaves it IN_PROGRESS: answering
// would be a guess, and a FAILED blocks a release.
func TestHandleFirmwareTrack_ACancelledTaskIsLeftAlone(t *testing.T) {
	h := newTrackHarness(t, true)
	h.dev.block = make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- h.dispatch(ctx, "41", map[string]interface{}{"action": "enroll", "track": "fast"}, time.Time{})
	}()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("handler error %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the handler did not return")
	}
	if got := h.answerList(); len(got) != 0 {
		t.Fatalf("answers %+v: a cancelled task must not be answered", got)
	}
	if rec, _, _ := h.store.Get("41"); rec.Status != taskstore.StatusInProgress {
		t.Errorf("the row is %s", rec.Status)
	}
}

func TestHandleFirmwareTrack_WaitsForAnotherFirmwareJobAndSaysSo(t *testing.T) {
	h := newTrackHarness(t, true)
	release, err := firmware.Acquire(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = h.dispatch(ctx, "51", map[string]interface{}{"action": "enroll", "track": "fast"}, time.Time{})
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		h.mu.Lock()
		told := len(h.progress) > 0
		h.mu.Unlock()
		if told {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the task did not say it was waiting")
		}
		time.Sleep(time.Millisecond)
	}
	// While it waits, the row already says what the task is.
	var job track.Job
	if found, _ := h.store.GetTaskMeta("51", &job); !found || job.Action != "enroll" || job.Phase != track.PhaseStarted {
		t.Errorf("job %+v (found %v)", job, found)
	}
	cancel()
	<-done
	release()
	if got := h.answerList(); len(got) != 0 {
		t.Errorf("answers %+v: a task that never got its turn and was cut short is left to the reconciler", got)
	}
}

func TestHandleFirmwareTrack_ATaskWhoseTimeRanOutWaitingIsHeldAsBusy(t *testing.T) {
	h := newTrackHarness(t, true)
	release, err := firmware.Acquire(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if err := h.dispatch(context.Background(), "61", map[string]interface{}{"action": "enroll", "track": "fast"}, time.Now().Add(30*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	got := h.onlyAnswer()
	if !got.result.Success || !strings.Contains(got.result.Message, `"reason":"held_firmware_busy"`) {
		t.Fatalf("answer %+v", got.result)
	}
}

func TestLifecycleForFirmwareTrackIsNeverCompletedByTheAgentComingBack(t *testing.T) {
	if got := LifecycleFor(network.TaskTypeFirmwareTrack); got != taskstore.LifecycleSynchronous {
		t.Errorf("lifecycle %v: a FIRMWARE_TRACK row left IN_PROGRESS must never be completed because the agent returned", got)
	}
}

// The answer is recorded before it is written. A send that failed because the
// connection ended must not become the handler's error: the dispatcher reads that,
// on a cancelled task, as one to answer FAILED, and the FAILED it records replaces
// the answer the next connect would have sent.
func TestHandleFirmwareTrack_ASendThatFailsIsNotTheHandlersError(t *testing.T) {
	for name, tc := range map[string]struct {
		withEngine bool
		payload    map[string]interface{}
	}{
		"a payload the contract refuses": {true, map[string]interface{}{"action": "upgrade", "track": "fast"}},
		"no engine, an enroll":           {false, map[string]interface{}{"action": "enroll", "track": "fast"}},
		"no engine, an unenroll":         {false, map[string]interface{}{"action": "unenroll", "track": "fast"}},
		"an unenroll with nothing to do": {true, map[string]interface{}{"action": "unenroll", "track": "fast"}},
	} {
		t.Run(name, func(t *testing.T) {
			h := newTrackHarness(t, tc.withEngine)
			sends := 0
			firmwareTrackSend = func(*network.WebSocketClient, string, TaskResult) error {
				sends++
				return errors.New("websocket: close sent")
			}
			if err := h.dispatch(context.Background(), "77", tc.payload, time.Time{}); err != nil {
				t.Fatalf("the handler returned %v: the dispatcher would answer FAILED over the recorded outcome", err)
			}
			if sends != 1 {
				t.Errorf("answers attempted: %d", sends)
			}
		})
	}
}

// A step that carries `major` is a series upgrade's: three reboots, its own lifetime
// (the control plane's TTL), and the series in the job the row keeps, so that whoever
// settles the row after a restart can restore the dispatch it must answer. A step
// without one keeps the minor's.
func TestHandleFirmwareTrack_AStepThatCarriesMajorHasTheSeriesUpgradesLifetimeAndRecordsIt(t *testing.T) {
	for name, tc := range map[string]struct {
		major string
		ttl   time.Duration
	}{
		"with a major":    {"26.7", track.MajorAdvanceTTL},
		"without a major": {"", track.AdvanceTTL},
	} {
		t.Run(name, func(t *testing.T) {
			h := newTrackHarness(t, true)
			h.ws = network.NewWebSocketClient(&config.Config{TestMode: true}, nil, nil, nil, nil)
			h.dev.installed = "26.1.11_10"
			payload := map[string]interface{}{"action": "advance", "track": "fast", "reboot": true,
				"approved": map[string]interface{}{"26.1": "26.1.11_10"}}
			expect := &track.Expect{Action: "advance", Track: "fast", Approved: map[string]string{"26.1": "26.1.11_10"}}
			if tc.major != "" {
				payload["major"] = tc.major
				expect.Major = tc.major
			}
			if err := h.dispatch(context.Background(), "81", payload, time.Time{}); err != nil {
				t.Fatal(err)
			}
			got := h.onlyAnswer()
			if !got.result.Success {
				t.Fatalf("answer %+v", got.result)
			}
			if f := track.ValidateResult(got.result.Message, expect); f != nil {
				t.Fatalf("result %s refused: %v", got.result.Message, f)
			}
			if strings.Contains(got.result.Message, `"kind"`) || strings.Contains(got.result.Message, `"notes"`) {
				t.Errorf("result %s: a hold before the step chose the series upgrade is the ordinary step's", got.result.Message)
			}

			var job track.Job
			if found, err := h.store.GetTaskMeta("81", &job); err != nil || !found {
				t.Fatalf("the task row carries no job: found=%v err=%v", found, err)
			}
			if job.Major != tc.major {
				t.Errorf("job major %q, want %q", job.Major, tc.major)
			}
			if lifetime := time.Duration(job.ExpiresAt-job.StartedAt) * time.Second; lifetime != tc.ttl {
				t.Errorf("lifetime %v, want %v", lifetime, tc.ttl)
			}
		})
	}
}

// The engine writes the job through Input.Persist before it asks OPNsense for
// anything it cannot take back, and the handler's Persist is the task store's durable
// write, which checkpoints the log into the database file. A handler that dropped
// either would lose the record to a power cut in the minutes after the request.
func TestHandleFirmwareTrack_PersistsTheJobDurably(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "firmware_track.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var handler *ast.FuncDecl
	for _, d := range file.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == "HandleFirmwareTrack" {
			handler = fn
		}
	}
	if handler == nil {
		t.Fatal("HandleFirmwareTrack not found")
	}

	var persistValue ast.Expr
	var persistFunc *ast.FuncLit
	ast.Inspect(handler.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.KeyValueExpr:
			if key, ok := n.Key.(*ast.Ident); ok && key.Name == "Persist" {
				persistValue = n.Value
			}
		case *ast.AssignStmt:
			if len(n.Lhs) == 1 && len(n.Rhs) == 1 {
				if id, ok := n.Lhs[0].(*ast.Ident); ok && id.Name == "persistJob" {
					persistFunc, _ = n.Rhs[0].(*ast.FuncLit)
				}
			}
		}
		return true
	})
	if id, ok := persistValue.(*ast.Ident); !ok || id.Name != "persistJob" {
		t.Fatalf("the engine's input does not carry persistJob as its Persist: %v", persistValue)
	}
	if persistFunc == nil {
		t.Fatal("persistJob is not a function literal of the handler")
	}
	durable := false
	ast.Inspect(persistFunc.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "SetTaskMetaDurable" {
				durable = true
			}
		}
		return true
	})
	if !durable {
		t.Error("persistJob does not write through SetTaskMetaDurable")
	}
}
