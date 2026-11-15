package network

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/directpeer"
	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/taskstore"
	"github.com/netdefense-io/ndagent/internal/testbroker"
)

const (
	connectVectorPath = "../directpeer/testdata/contract/connect-direct-peer-v1.json"
	connectVectorID   = "eff97f3e3ad593d08e250b5a5e492449"
)

func connectVectorResponses(t *testing.T) map[string]map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(connectVectorPath)
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Responses map[string]map[string]interface{} `json:"responses"`
	}
	if err := json.Unmarshal(data, &v); err != nil || len(v.Responses) != 4 {
		t.Fatalf("vector responses: %v (%d)", err, len(v.Responses))
	}
	return v.Responses
}

// signedObject is the whole object a response carried under its signature.
func signedObject(t *testing.T, r testbroker.TaskResponse) map[string]interface{} {
	t.Helper()
	out := make(map[string]interface{}, len(r.Inner))
	for key, raw := range r.Inner {
		var v interface{}
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatalf("signed key %s: %v", key, err)
		}
		out[key] = v
	}
	return out
}

func waitResponses(t *testing.T, b *testbroker.Broker, n int) []testbroker.TaskResponse {
	t.Helper()
	b.WaitFor("task responses", 5*time.Second, func() bool { return len(b.TaskResponses()) >= n })
	// Anything beyond n is a failure of its own: give a stray frame a moment.
	time.Sleep(50 * time.Millisecond)
	got := b.TaskResponses()
	if len(got) != n {
		t.Fatalf("%d task responses, want %d: %+v", len(got), n, got)
	}
	return got
}

func vectorSessionEnd() directpeer.Result {
	return directpeer.SessionEndResult(connectVectorID, directpeer.SessionEnd{
		Reason: directpeer.EndClientClosed, Duration: 1832 * time.Second,
		Paired: true, PairedAfter: 4 * time.Second, Path: directpeer.PathDirect,
	})
}

// What the device signs for a session is the contract's vector, key for key:
// the control plane reads the session's state from this object.
func TestReportConnectResult_SignsTheVectorsResponses(t *testing.T) {
	want := connectVectorResponses(t)
	cases := []struct {
		name   string
		taskID string
		result directpeer.Result
	}{
		{"listening", "201", directpeer.ListeningResult(connectVectorID)},
		{"session_end", "202", vectorSessionEnd()},
		{"failed", "203", directpeer.FailedResult(connectVectorID, directpeer.FailUnsealFailed)},
		{"closed", "204", directpeer.ClosedResult(connectVectorID, true)},
	}

	b := testbroker.New(t)
	w, store := newDrainClient(t, b)
	connectOnce(t, w)
	b.WaitForHeartbeats(1, 5*time.Second)

	for i, c := range cases {
		if err := w.ReportConnectResult(c.taskID, c.result); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := waitResponses(t, b, i+1)[i]
		if signed := signedObject(t, got); !reflect.DeepEqual(signed, want[c.name]) {
			gotJSON, _ := json.Marshal(signed)
			wantJSON, _ := json.Marshal(want[c.name])
			t.Errorf("%s:\n signed %s\n vector %s", c.name, gotJSON, wantJSON)
		}
		if s := statusOf(t, store, c.taskID); s != c.result.Status+" (delivered)" {
			t.Errorf("%s: row is %q", c.name, s)
		}
	}
}

// The second result of a session, hours after the first was delivered, while
// the control connection is down: it is on record, and the next connect
// delivers it.
func TestReportConnectResult_ASessionEndWhileDisconnectedGoesOutAtTheNextConnect(t *testing.T) {
	b := testbroker.New(t)
	w, store := newDrainClient(t, b)
	cancel, wait := connectOnce(t, w)
	b.WaitForHeartbeats(1, 5*time.Second)
	_ = store.Begin("301", TaskTypeConnect, taskstore.LifecycleSynchronous)
	if err := w.ReportConnectResult("301", directpeer.ListeningResult(connectVectorID)); err != nil {
		t.Fatal(err)
	}
	waitResponses(t, b, 1)
	if s := statusOf(t, store, "301"); s != "COMPLETED (delivered)" {
		t.Fatalf("after listening the row is %q", s)
	}

	cancel()
	wait()

	if err := w.ReportConnectResult("301", vectorSessionEnd()); err != nil {
		t.Fatalf("a result that cannot be sent now must still be recorded: %v", err)
	}
	if s := statusOf(t, store, "301"); s != "COMPLETED (undelivered)" {
		t.Fatalf("the session-end recorded while disconnected is %q, want undelivered", s)
	}
	if n := len(b.TaskResponses()); n != 1 {
		t.Fatalf("%d responses while disconnected, want the 1 from before", n)
	}

	connectOnce(t, w)
	got := waitResponses(t, b, 2)[1]
	if got.TaskID != 301 || directpeer.ResultEvent(signedObject(t, got)) != "session-end" {
		t.Fatalf("the reconnect delivered %+v, want the session-end of 301", got)
	}
	if s := statusOf(t, store, "301"); s != "COMPLETED (delivered)" {
		t.Fatalf("after the reconnect the row is %q", s)
	}
}

// Both results while disconnected: the task has one row, so only the end
// goes out, once.
func TestReportConnectResult_OnlyTheLatestOfTwoUnsentResultsGoesOut(t *testing.T) {
	b := testbroker.New(t)
	w, store := newDrainClient(t, b)

	if err := w.ReportConnectResult("401", directpeer.ListeningResult(connectVectorID)); err != nil {
		t.Fatal(err)
	}
	if err := w.ReportConnectResult("401", vectorSessionEnd()); err != nil {
		t.Fatal(err)
	}
	connectOnce(t, w)
	got := waitResponses(t, b, 1)[0]
	if directpeer.ResultEvent(signedObject(t, got)) != "session-end" {
		t.Fatalf("delivered %+v, want the session-end", got)
	}
	if s := statusOf(t, store, "401"); s != "COMPLETED (delivered)" {
		t.Fatalf("row is %q", s)
	}
}

// Once a session's end is on record, nothing replaces it: a session that
// ended must never read as ready again.
func TestReportConnectResult_ASessionEndIsFinal(t *testing.T) {
	b := testbroker.New(t)
	w, store := newDrainClient(t, b)
	connectOnce(t, w)
	b.WaitForHeartbeats(1, 5*time.Second)

	if err := w.ReportConnectResult("501", vectorSessionEnd()); err != nil {
		t.Fatal(err)
	}
	waitResponses(t, b, 1)

	later := []directpeer.Result{
		directpeer.ListeningResult(connectVectorID),
		directpeer.FailedResult(connectVectorID, directpeer.FailInternal),
		directpeer.SessionEndResult(connectVectorID, directpeer.SessionEnd{Reason: directpeer.EndError}),
	}
	for _, r := range later {
		if err := w.ReportConnectResult("501", r); err != nil {
			t.Fatalf("%v", err)
		}
	}
	waitResponses(t, b, 1)
	rec, _, _ := store.Get("501")
	var data map[string]interface{}
	_ = json.Unmarshal(rec.ResultData, &data)
	connect, _ := data["connect"].(map[string]interface{})
	if connect["event"] != "session-end" || connect["reason"] != "client_closed" || !rec.Delivered {
		t.Fatalf("the record is now %s (delivered %v)", rec.ResultData, rec.Delivered)
	}
}

// The drain marks a row delivered by its task id. A result written while the
// drain is sending the one before would be marked delivered, unsent; so the
// report waits for the drain.
func TestReportConnectResult_WaitsForTheDrain(t *testing.T) {
	b := testbroker.New(t)
	w, store := newDrainClient(t, b)

	w.drainMu.Lock()
	done := make(chan error, 1)
	go func() { done <- w.ReportConnectResult("601", vectorSessionEnd()) }()

	select {
	case err := <-done:
		w.drainMu.Unlock()
		t.Fatalf("the report did not wait for the drain (err %v)", err)
	case <-time.After(200 * time.Millisecond):
	}
	if _, found, _ := store.Get("601"); found {
		w.drainMu.Unlock()
		t.Fatal("the report wrote its row while the drain held the lock")
	}
	w.drainMu.Unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if s := statusOf(t, store, "601"); s != "COMPLETED (undelivered)" {
		t.Fatalf("row is %q", s)
	}
}

func TestReportConnectResult_RefusesWhatIsNotASessionResult(t *testing.T) {
	b := testbroker.New(t)
	w, store := newDrainClient(t, b)

	bad := directpeer.ListeningResult(connectVectorID)
	bad.Status = TaskStatusFailed
	if err := w.ReportConnectResult("701", bad); err == nil {
		t.Fatal("a listening result with status FAILED was recorded")
	}
	if _, found, _ := store.Get("701"); found {
		t.Fatal("a row was written")
	}

	noStore := NewWebSocketClient(w.cfg, w.state, nil, drainLifecycle, b.NDMKeys())
	if err := noStore.ReportConnectResult("702", vectorSessionEnd()); err == nil {
		t.Fatal("a client without a task store says the result is on record")
	}
}

// A task delivered a second time gets the answer it did not get.
func TestResendConnectResult(t *testing.T) {
	b := testbroker.New(t)
	w, store := newDrainClient(t, b)
	connectOnce(t, w)
	b.WaitForHeartbeats(1, 5*time.Second)

	if w.ResendConnectResult("801") {
		t.Fatal("a task with no record was answered")
	}
	_ = store.Begin("802", TaskTypeConnect, taskstore.LifecycleSynchronous)
	if w.ResendConnectResult("802") {
		t.Fatal("a task still in progress was answered")
	}
	if err := w.SendTaskResponse("803", TaskStatusFailed, "CONNECT task was cancelled", nil); err != nil {
		t.Fatal(err)
	}
	waitResponses(t, b, 1)
	if w.ResendConnectResult("803") {
		t.Fatal("a result that is not a session's was sent again")
	}

	if err := w.ReportConnectResult("804", directpeer.ListeningResult(connectVectorID)); err != nil {
		t.Fatal(err)
	}
	first := waitResponses(t, b, 2)[1]
	if !w.ResendConnectResult("804") {
		t.Fatal("the recorded result was not sent again")
	}
	second := waitResponses(t, b, 3)[2]
	if !reflect.DeepEqual(signedObject(t, first), signedObject(t, second)) {
		t.Fatalf("sent again as %+v, first %+v", signedObject(t, second), signedObject(t, first))
	}
	if s := statusOf(t, store, "804"); s != "COMPLETED (delivered)" {
		t.Fatalf("row is %q", s)
	}
}

// The signed object is a whitelist. A session object that does not go with
// the status never reaches the wire, and no other response gains the key.
func TestBuildTaskResponseInner_Connect(t *testing.T) {
	log := logging.Named("test")
	listening := directpeer.ListeningResult(connectVectorID)

	inner := buildTaskResponseInner(TaskStatusCompleted, listening.Message, listening.Data(), log)
	if _, ok := inner["connect"].(map[string]interface{}); !ok {
		t.Fatalf("a valid session result is missing: %#v", inner)
	}
	for name, c := range map[string]struct {
		status string
		data   map[string]interface{}
	}{
		"listening as FAILED":      {TaskStatusFailed, listening.Data()},
		"listening as IN_PROGRESS": {TaskStatusInProgress, listening.Data()},
		"not an object":            {TaskStatusCompleted, map[string]interface{}{"connect": "listening"}},
		"an unknown event":         {TaskStatusCompleted, map[string]interface{}{"connect": map[string]interface{}{"event": "ready", "connect_id": connectVectorID}}},
		"no data":                  {TaskStatusCompleted, nil},
	} {
		if inner := buildTaskResponseInner(c.status, "m", c.data, log); len(inner) != 2 {
			t.Errorf("%s: %#v", name, inner)
		}
	}

	// Keys beside the contract's are not signed.
	extra := listening.Data()
	extra["connect"].(map[string]interface{})["node_key"] = "secret"
	inner = buildTaskResponseInner(TaskStatusCompleted, "m", extra, log)
	if _, has := inner["connect"].(map[string]interface{})["node_key"]; has {
		t.Fatal("a key outside the contract was signed")
	}
}

// An agent whose task store could not be opened keeps no record of any task.
// A session result is then sent as it is made, and the error says when it
// was not, so the caller keeps it for the next connection.
func TestReportConnectResult_WithoutATaskStoreItIsSent(t *testing.T) {
	b := testbroker.New(t)
	withStore, _ := newDrainClient(t, b)
	w := NewWebSocketClient(withStore.cfg, withStore.state, nil, drainLifecycle, b.NDMKeys())

	if err := w.ReportConnectResult("901", directpeer.ListeningResult(connectVectorID)); err == nil {
		t.Fatal("not connected and no store: the result is nowhere, and no error says so")
	}

	connectOnce(t, w)
	b.WaitForHeartbeats(1, 5*time.Second)
	if err := w.ReportConnectResult("901", directpeer.ListeningResult(connectVectorID)); err != nil {
		t.Fatal(err)
	}
	got := waitResponses(t, b, 1)[0]
	if got.TaskID != 901 || directpeer.ResultEvent(signedObject(t, got)) != "listening" {
		t.Fatalf("sent %+v", got)
	}
}

// The device's own identity key opens what a client sealed to it, and only
// that key: the handler is handed this method, never the key.
func TestUnsealConnect_OpensWithTheDevicesKey(t *testing.T) {
	data, err := os.ReadFile(connectVectorPath)
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		DeviceKey struct {
			SeedB64 string `json:"ed25519_seed_b64"`
		} `json:"device_key"`
		Sealed struct {
			SealedB64   string `json:"sealed_b64"`
			MustNotOpen struct {
				TamperedB64 string `json:"tampered_b64"`
			} `json:"must_not_open"`
		} `json:"sealed"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}

	b := testbroker.New(t)
	other, _ := newDrainClient(t, b)
	cfg := *other.cfg
	cfg.DevicePrivKey = v.DeviceKey.SeedB64
	w := NewWebSocketClient(&cfg, other.state, nil, drainLifecycle, b.NDMKeys())

	secret, err := w.UnsealConnect(v.Sealed.SealedB64)
	if err != nil {
		t.Fatalf("the vector's blob with the vector's device key: %v", err)
	}
	if secret.ConnectID != connectVectorID || secret.DeviceUUID != "3f2b8c1e-6a4d-4e0b-9c57-d1a2b3c4e5f6" || secret.Exp != 1794700800 {
		t.Fatalf("opened %v", secret)
	}
	if _, err := w.UnsealConnect(v.Sealed.MustNotOpen.TamperedB64); err == nil {
		t.Fatal("a tampered blob opened")
	}
	if _, err := other.UnsealConnect(v.Sealed.SealedB64); err == nil {
		t.Fatal("another device's key opened the blob")
	}
}

// A session that is ready is never reported as refused afterwards: the
// control plane ends a session's relay admission on a FAILED.
func TestReportConnectResult_ARefusalNeverReplacesListening(t *testing.T) {
	b := testbroker.New(t)
	w, store := newDrainClient(t, b)
	connectOnce(t, w)
	b.WaitForHeartbeats(1, 5*time.Second)

	if err := w.ReportConnectResult("1001", directpeer.ListeningResult(connectVectorID)); err != nil {
		t.Fatal(err)
	}
	waitResponses(t, b, 1)
	if err := w.ReportConnectResult("1001", directpeer.FailedResult(connectVectorID, directpeer.FailPolicyDisabled)); err != nil {
		t.Fatal(err)
	}
	waitResponses(t, b, 1)
	rec, _, _ := store.Get("1001")
	if rec.Status != "COMPLETED" || !rec.Delivered {
		t.Fatalf("the row is now %s (delivered %v)", rec.Status, rec.Delivered)
	}

	// The session's end still follows.
	if err := w.ReportConnectResult("1001", vectorSessionEnd()); err != nil {
		t.Fatal(err)
	}
	if got := waitResponses(t, b, 2)[1]; directpeer.ResultEvent(signedObject(t, got)) != "session-end" {
		t.Fatalf("after listening: %+v", got)
	}

	// The control: a refusal as a task's first answer is recorded and sent.
	if err := w.ReportConnectResult("1002", directpeer.FailedResult(connectVectorID, directpeer.FailPolicyDisabled)); err != nil {
		t.Fatal(err)
	}
	if got := waitResponses(t, b, 3)[2]; got.Status != "FAILED" {
		t.Fatalf("a first refusal: %+v", got)
	}
}
