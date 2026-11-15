package network

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/netdefense-io/ndagent/internal/directpeer"
	"github.com/netdefense-io/ndagent/internal/logging"
)

// recordedConnectEvent is the event of the result on record for taskID: ""
// when there is none, or it is not a session result.
func (w *WebSocketClient) recordedConnectEvent(taskID string) (event, status, message string, data map[string]interface{}) {
	rec, found, err := w.taskStore.Get(taskID)
	if err != nil || !found || (rec.Status != TaskStatusCompleted && rec.Status != TaskStatusFailed) {
		return "", "", "", nil
	}
	if len(rec.ResultData) == 0 || json.Unmarshal(rec.ResultData, &data) != nil {
		return "", rec.Status, rec.Message, nil
	}
	return directpeer.ResultEvent(data), rec.Status, rec.Message, data
}

// ReportConnectResult records a result of a direct-peer CONNECT task and
// sends it. Such a task has two: its session is ready, and, up to hours
// later, its session is over. Each is written as undelivered, so one that
// cannot be sent now (the control connection is down, as it may be for the
// whole of a session) goes out with the drain of the next connect, signed
// then.
//
// The error says the result is NOT on record, and the caller keeps it. A
// result that is recorded and could not be sent is no error. Without a task
// store there is no record: the error then says the result was not sent.
//
// The end of a session is final: once it is on record, nothing replaces it,
// so a session that ended never reads as ready again. A session that is ready
// is never replaced by a refusal either.
func (w *WebSocketClient) ReportConnectResult(taskID string, result directpeer.Result) error {
	log := logging.Named("websocket")
	data := result.Data()
	if _, valid := directpeer.CleanResult(result.Status, result.Connect); !valid {
		return fmt.Errorf("task %s: %w", taskID, directpeer.ErrNotAResult)
	}
	if w.taskStore == nil {
		// An agent whose task store could not be opened keeps no record of
		// any task: the result is sent, and is lost if that fails. The error
		// lets the caller keep it for the next connection.
		return w.sendTaskResponse(taskID, result.Status, result.Message, data, false)
	}

	// Serialized with the drain's replay: the drain marks a row delivered by
	// its task id, whatever the row holds by then, so a result written while
	// it sends the one before would be marked delivered unsent.
	w.drainMu.Lock()
	defer w.drainMu.Unlock()

	switch event, _, _, _ := w.recordedConnectEvent(taskID); {
	case event == directpeer.ResultSessionEnd:
		log.Infow("A remote session's end is already on record; nothing replaces it", "task_id", taskID)
		return nil
	case event == directpeer.ResultListening && directpeer.ResultEvent(data) == directpeer.ResultFailed:
		// A refusal is a task's first answer or none: the control plane ends
		// a session's relay admission on it, and this one is running.
		log.Warnw("A remote session that is ready is not reported as refused", "task_id", taskID)
		return nil
	}

	message := withVerifyNotice(w.verifyNotice(), result.Status, result.Message)
	inner, err := json.Marshal(buildTaskResponseInner(result.Status, message, data, log))
	if err != nil {
		return fmt.Errorf("marshal inner response: %w", err)
	}
	if err := w.taskStore.CompleteAgain(taskID, TaskTypeConnect, result.Status, message, inner); err != nil {
		return err
	}
	if err := w.sendTaskResponse(taskID, result.Status, message, data, false); err != nil {
		log.Infow("A remote session result is recorded and will be sent at the next connect",
			"task_id", taskID, "event", directpeer.ResultEvent(data), "error", err)
	}
	return nil
}

// ResendConnectResult sends again the session result on record for taskID,
// for a task the control plane delivered a second time: it did not get the
// answer. It reports whether there was one.
func (w *WebSocketClient) ResendConnectResult(taskID string) bool {
	if w.taskStore == nil {
		return false
	}
	log := logging.Named("websocket")
	w.drainMu.Lock()
	defer w.drainMu.Unlock()

	event, status, message, data := w.recordedConnectEvent(taskID)
	if event == "" {
		return false
	}
	inner, err := json.Marshal(buildTaskResponseInner(status, message, data, log))
	if err != nil {
		return false
	}
	if err := w.taskStore.CompleteAgain(taskID, TaskTypeConnect, status, message, inner); err != nil {
		log.Warnw("Cannot mark a remote session result for sending again", "task_id", taskID, "error", err)
		return false
	}
	if err := w.sendTaskResponse(taskID, status, message, data, false); err != nil {
		log.Infow("A remote session result will be sent again at the next connect", "task_id", taskID, "error", err)
	}
	return true
}

// UnsealConnect opens the sealed secret of a direct-peer session with the
// device's identity key. The key stays here: the caller gets the secret.
func (w *WebSocketClient) UnsealConnect(sealed string) (*directpeer.Secret, error) {
	priv, _, err := w.devicePrivkey()
	if err != nil {
		return nil, errors.New("the device key cannot be loaded")
	}
	return directpeer.Unseal(priv, sealed)
}
