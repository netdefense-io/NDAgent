package taskstore

import (
	"context"
	"encoding/json"
)

// Responder is the minimal surface the drain step needs from a
// WebSocket-like sender. `*network.WebSocketClient` satisfies this; tests
// pass a stub. Kept narrow so this package doesn't import internal/network
// and cause an import cycle (network imports taskstore).
type Responder interface {
	SendTaskResponse(taskID, status, message string, data map[string]interface{}) error
}

// DrainUndelivered is the boot-time replay step: reconcile any helper
// drop files into the registry, resolve any rows still IN_PROGRESS per
// their lifecycle category, then send a real task_response for each
// row whose delivered_at is still null. Each successful send is
// followed by MarkDelivered (which also runs retention).
//
// Caller order: open store, run DrainUndelivered AFTER WS auth has
// succeeded (so the responder can actually transmit) and BEFORE the
// dispatcher starts receiving new tasks (so we don't race against
// fresh writes).
//
// Returns the count of responses sent. A non-nil error from a single
// send is logged but does not abort the drain — subsequent rows are
// still attempted. The first hard error is returned to the caller
// after the loop finishes.
func DrainUndelivered(ctx context.Context, store *Store, pendingResultsDir string, responder Responder, logf func(format string, args ...interface{})) (int, error) {
	if logf == nil {
		logf = func(format string, args ...interface{}) {}
	}

	// 1. Helper drop files → terminal store rows.
	if applied, err := ReconcileDropFiles(pendingResultsDir, store); err != nil {
		logf("drain: reconcile drop files failed: %v", err)
	} else if applied > 0 {
		logf("drain: reconciled %d drop file(s)", applied)
	}

	// 2. Stuck IN_PROGRESS rows → terminal per lifecycle category.
	if resolved, err := store.ResolveStuck(); err != nil {
		logf("drain: resolve stuck rows failed: %v", err)
	} else if resolved > 0 {
		logf("drain: resolved %d stuck row(s)", resolved)
	}

	// 3. Replay all undelivered terminal rows.
	rows, err := store.Undelivered()
	if err != nil {
		return 0, err
	}

	sent := 0
	var firstErr error
	for _, r := range rows {
		// Context cancellation during a long drain shouldn't drop
		// half-delivered work; check before each send.
		select {
		case <-ctx.Done():
			return sent, ctx.Err()
		default:
		}

		var data map[string]interface{}
		if len(r.ResultData) > 0 {
			// Best-effort: the result blob was written by us in
			// SendTaskResponse from the inner-response map. If parsing
			// fails, send without data — the message string still
			// carries the operator-visible signal.
			if err := json.Unmarshal(r.ResultData, &data); err != nil {
				data = nil
			}
		}

		if err := responder.SendTaskResponse(r.TaskID, r.Status, r.Message, data); err != nil {
			logf("drain: SendTaskResponse for task %s failed: %v", r.TaskID, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err := store.MarkDelivered(r.TaskID); err != nil {
			logf("drain: MarkDelivered for task %s failed: %v", r.TaskID, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		sent++
	}
	return sent, firstErr
}
