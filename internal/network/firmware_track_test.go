package network

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/firmware/track"
	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/taskstore"
	"github.com/netdefense-io/ndagent/internal/testbroker"
)

// The failure detail of a FIRMWARE_TRACK task is a top-level key of the signed
// response. The function copies only the keys it knows, so a detail that is not
// listed there is dropped with no error; and what it copies is held to the
// shared vectors, because the control plane counts the failure against the
// release it names.
func TestBuildTaskResponseInner_CarriesAValidFailureDetailOnAFailedTask(t *testing.T) {
	log := logging.Named("test")
	data := map[string]interface{}{
		track.FailureKey: track.FailureDetail{Target: "26.7.5", PinnedVersion: "26.7.3"}.Map(),
	}
	inner := buildTaskResponseInner(TaskStatusFailed, "The firmware update did not apply", data, log)
	got, ok := inner[track.FailureKey].(map[string]interface{})
	if !ok || got["target"] != "26.7.5" || got["pinned_version"] != "26.7.3" {
		t.Fatalf("inner = %#v", inner)
	}
}

func TestBuildTaskResponseInner_FailureDetailAgreesWithEverySharedVector(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "firmware", "track", "testdata", "firmware-track", "failure-details.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Vectors []struct {
			Description string                 `json:"description"`
			Response    map[string]interface{} `json:"response"`
			Valid       bool                   `json:"valid"`
			Fault       string                 `json:"fault"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Vectors) < 25 {
		t.Fatalf("only %d vectors", len(vectors.Vectors))
	}
	log := logging.Named("test")
	for _, vec := range vectors.Vectors {
		detail, present := vec.Response[track.FailureKey]
		if !present {
			continue
		}
		if vec.Fault == "kind_not_dispatched" {
			// Only the dispatch says a kind was not asked for, and the response builder,
			// like the drain that replays a stored response, has none: the engine that
			// builds the detail holds it to the dispatch (the track package's vectors).
			continue
		}
		inner := buildTaskResponseInner(TaskStatusFailed, "failed", map[string]interface{}{track.FailureKey: detail}, log)
		_, sent := inner[track.FailureKey]
		if sent != vec.Valid {
			t.Errorf("%s: sent=%v, want %v", vec.Description, sent, vec.Valid)
		}
	}
}

func TestBuildTaskResponseInner_FailureDetailOnlyOnAFailedTask(t *testing.T) {
	log := logging.Named("test")
	data := map[string]interface{}{track.FailureKey: map[string]interface{}{"target": "26.7.5"}}
	for _, status := range []string{TaskStatusCompleted, TaskStatusInProgress} {
		if _, ok := buildTaskResponseInner(status, "x", data, log)[track.FailureKey]; ok {
			t.Errorf("a %s response carries a failure detail", status)
		}
	}
	if _, ok := buildTaskResponseInner(TaskStatusFailed, "x", nil, log)[track.FailureKey]; ok {
		t.Error("a failure with no detail grew one")
	}
}

// The detail has to survive the store: the response is recorded before it is
// sent and replayed from the record after a reconnect.
func TestFailureDetailSurvivesTheStoreAndTheReplay(t *testing.T) {
	b := testbroker.New(t)
	w, store := newDrainClient(t, b)
	if err := store.Begin("201", TaskTypeFirmwareTrack, taskstore.LifecycleSynchronous); err != nil {
		t.Fatal(err)
	}

	connectOnce(t, w)
	b.WaitForHeartbeats(1, 5*time.Second)

	won, err := w.CompleteInProgressTaskWithData("201", TaskStatusFailed, "The firmware update did not apply", map[string]interface{}{
		track.FailureKey: track.FailureDetail{Target: "26.7.5", PinnedVersion: "26.7.3_11"}.Map(),
	})
	if err != nil || !won {
		t.Fatalf("won=%v err=%v", won, err)
	}
	b.WaitFor("the failed answer", 5*time.Second, func() bool { return len(b.TaskResponses()) >= 1 })
	var detail map[string]string
	got := b.TaskResponses()[0]
	if got.Status != TaskStatusFailed || json.Unmarshal(got.Inner[track.FailureKey], &detail) != nil ||
		detail["target"] != "26.7.5" || detail["pinned_version"] != "26.7.3_11" {
		t.Fatalf("response %+v", got)
	}

	// What the store kept is what a replay sends.
	rec, found, err := store.Get("201")
	if err != nil || !found {
		t.Fatal(err)
	}
	var stored map[string]interface{}
	if err := json.Unmarshal(rec.ResultData, &stored); err != nil {
		t.Fatal(err)
	}
	replayed := buildTaskResponseInner(rec.Status, rec.Message, stored, logging.Named("test"))
	if _, ok := replayed[track.FailureKey]; !ok {
		t.Errorf("the replay of a stored response lost the failure detail: %#v", replayed)
	}
}

// An agent that does not know a task type answers it FAILED and does nothing,
// which is what an agent from before FIRMWARE_TRACK does with one: the server's
// version gate is the first guarantee, and this is the second.
func TestAnUnregisteredTaskTypeIsRefusedAndNothingRuns(t *testing.T) {
	b := testbroker.New(t)
	w, _ := newDrainClient(t, b)
	connectOnce(t, w)
	b.WaitForHeartbeats(1, 5*time.Second)

	if err := b.Dispatch(testbroker.Dispatch{
		DeviceUUID: w.cfg.DeviceUUID, TaskID: 301, Seq: 1, TaskType: TaskTypeFirmwareTrack,
		Payload: map[string]interface{}{"action": "advance", "track": "fast", "approved": map[string]interface{}{"26.7": "26.7.5"}},
		Exp:     time.Now().Add(20 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	b.WaitFor("the refusal", 5*time.Second, func() bool { return len(b.TaskResponses()) >= 1 })
	got := b.TaskResponses()[0]
	if got.TaskID != 301 || got.Status != TaskStatusFailed || got.Message != "Unknown command type: FIRMWARE_TRACK" {
		t.Fatalf("response %+v", got)
	}
	if _, ok := got.Inner[track.FailureKey]; ok {
		t.Error("a refusal of an unknown type must not name a release: it would block that release for the organization")
	}
}
