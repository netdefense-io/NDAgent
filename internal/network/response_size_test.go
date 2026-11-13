package network

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/signing"
	"github.com/netdefense-io/ndagent/internal/taskstore"
	"github.com/netdefense-io/ndagent/internal/testbroker"
)

// The bound is checked against a real envelope and frame, with every header
// at its widest.
func TestFrameSizeForBoundsTheRealFrame(t *testing.T) {
	pub, priv, err := signing.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, 1, 100, 10000, 700000} {
		payload := []byte(strings.Repeat("a", n))
		env, err := signing.BuildResponseEnvelope(priv, signing.KidFromPubkey(pub), math.MaxInt64,
			"3a1e88a3-0000-4000-8000-0000000000aa", payload, math.MaxInt64, math.MaxInt64)
		if err != nil {
			t.Fatal(err)
		}
		frame, err := json.Marshal(map[string]interface{}{
			"type": MsgTypeTaskResponse, "task_id": int64(math.MaxInt64), "envelope": env,
		})
		if err != nil {
			t.Fatal(err)
		}
		real := len(frame) + 1 // WriteJSON ends the message with a newline
		if bound := frameSizeFor(n); bound < real || bound > real+128 {
			t.Errorf("inner %d bytes: bound %d, real frame %d", n, bound, real)
		}
	}
}

func bigContent() map[string]interface{} {
	return map[string]interface{}{"content": strings.Repeat("A", MaxTaskResponseFrame)}
}

func TestSendTaskResponse_AResultTooLargeForTheBrokerIsAnsweredFailed(t *testing.T) {
	b := testbroker.New(t)
	w, store := newDrainClient(t, b)
	connectOnce(t, w)
	b.WaitForHeartbeats(1, 5*time.Second)
	_ = store.Begin("106", TaskTypeBackup, taskstore.LifecycleSynchronous)

	if err := w.SendTaskResponse("106", TaskStatusCompleted, "Backup completed successfully", bigContent()); err != nil {
		t.Fatal(err)
	}
	b.WaitFor("the response", 5*time.Second, func() bool { return len(b.TaskResponses()) >= 1 })
	got := b.TaskResponses()
	if len(got) != 1 || got[0].Status != "FAILED" || !strings.Contains(got[0].Message, "could not be delivered") {
		t.Fatalf("task responses = %+v", got)
	}
	rec, _, _ := store.Get("106")
	if rec.Status != TaskStatusFailed || !rec.Delivered || len(rec.ResultData) > 4096 {
		t.Errorf("the row must hold the small failure, delivered: status=%s delivered=%v result=%d bytes", rec.Status, rec.Delivered, len(rec.ResultData))
	}
}

// A device that stored such a response with an older agent replays it at
// every connect, and the broker drops each connection: the drain sends the
// failure instead, and the device stays connected.
func TestConnect_AStoredResponseTooLargeForTheBrokerIsReplayedAsAFailure(t *testing.T) {
	b := testbroker.New(t)
	w, store := newDrainClient(t, b)
	_ = store.Begin("107", TaskTypeBackup, taskstore.LifecycleSynchronous)
	stored, _ := json.Marshal(map[string]interface{}{
		"status": TaskStatusCompleted, "message": "Backup completed successfully", "content": bigContent()["content"],
	})
	if err := store.Complete("107", TaskStatusCompleted, "Backup completed successfully", stored); err != nil {
		t.Fatal(err)
	}

	connectOnce(t, w)
	b.WaitForHeartbeats(1, 5*time.Second)
	got := b.TaskResponses()
	if len(got) != 1 || got[0].TaskID != 107 || got[0].Status != "FAILED" || !strings.Contains(got[0].Message, "could not be delivered") {
		t.Fatalf("task responses = %+v", got)
	}
	if s := statusOf(t, store, "107"); s != "FAILED (delivered)" {
		t.Errorf("row is %q", s)
	}
}

func TestCompleteInProgressTaskWithData_NeverStoresAResultTooLargeForTheBroker(t *testing.T) {
	b := testbroker.New(t)
	w, store := newDrainClient(t, b)
	_ = store.Begin("108", TaskTypeFirmwareTrack, taskstore.LifecycleSynchronous)
	connectOnce(t, w)
	b.WaitForHeartbeats(1, 5*time.Second)

	won, err := w.CompleteInProgressTaskWithData("108", TaskStatusCompleted, "done", bigContent())
	if !won || err != nil {
		t.Fatalf("won=%v err=%v", won, err)
	}
	rec, _, _ := store.Get("108")
	if rec.Status != TaskStatusFailed || len(rec.ResultData) > 4096 {
		t.Errorf("status=%s result=%d bytes", rec.Status, len(rec.ResultData))
	}
}

func TestSendTaskResponse_AnInProgressFrameTooLargeIsNotSent(t *testing.T) {
	b := testbroker.New(t)
	w, _ := newDrainClient(t, b)
	connectOnce(t, w)
	b.WaitForHeartbeats(1, 5*time.Second)

	if err := w.SendTaskResponse("109", TaskStatusInProgress, strings.Repeat("x", MaxTaskResponseFrame), nil); err == nil {
		t.Fatal("want an error for an IN_PROGRESS frame over the limit")
	}
	if got := b.TaskResponses(); len(got) != 0 {
		t.Errorf("task responses = %+v", got)
	}
}
