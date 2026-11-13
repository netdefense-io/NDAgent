package network

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"go.uber.org/zap"
)

// MaxTaskResponseFrame is the largest message NDBroker reads (its ws_max_size).
// A larger one makes it close the connection (1009) with nothing recorded.
const MaxTaskResponseFrame = 1 << 20

const (
	// taskResponseEnvelopeOverhead bounds what the COSE_Sign1 envelope adds to
	// the inner response: the protected header, the signature and the CBOR
	// framing (about 230 bytes with every header at its widest).
	taskResponseEnvelopeOverhead = 256
	// taskResponseFrameOverhead bounds the frame's JSON around the envelope's
	// base64, with the widest task id, and the newline WriteJSON adds.
	taskResponseFrameOverhead = 80
)

// TaskResponseFrameSize bounds the size of the frame that carries this
// response to the broker.
func TaskResponseFrameSize(status, message string, data map[string]interface{}) (int, error) {
	innerBytes, err := json.Marshal(buildTaskResponseInner(status, message, data, zap.NewNop().Sugar()))
	if err != nil {
		return 0, err
	}
	return frameSizeFor(len(innerBytes)), nil
}

func frameSizeFor(innerLen int) int {
	return base64.StdEncoding.EncodedLen(innerLen+taskResponseEnvelopeOverhead) + taskResponseFrameOverhead
}

func oversizedResponseMessage(frameSize int) string {
	return fmt.Sprintf("The task ran, but its result could not be delivered: it is too large for one message to the control plane, "+
		"about %d bytes once signed and encoded, over the limit of %d bytes.", frameSize, MaxTaskResponseFrame)
}

// fitTaskResponse answers a terminal response whose frame would be over
// MaxTaskResponseFrame with a small FAILED that names the size instead: the
// broker drops the connection on such a frame, and a stored one is replayed,
// and drops it again, at every connect. It returns the response to record and
// send, with its inner JSON. The FAILED carries no data, so a FIRMWARE_TRACK
// failure detail would go too, and NDManager would count the failure against
// the track's release; no track result comes near the limit. The FAILED
// carries notice too (see withVerifyNotice).
func fitTaskResponse(taskID, status, message, notice string, data map[string]interface{}, innerBytes []byte, log *zap.SugaredLogger) (string, string, map[string]interface{}, []byte, error) {
	size := frameSizeFor(len(innerBytes))
	if size <= MaxTaskResponseFrame {
		return status, message, data, innerBytes, nil
	}
	if status != TaskStatusCompleted && status != TaskStatusFailed {
		return "", "", nil, nil, fmt.Errorf("task %s: a %s frame of about %d bytes is over the broker's %d-byte limit", taskID, status, size, MaxTaskResponseFrame)
	}
	log.Errorw("Task result is too large for one message to the broker; answering FAILED instead",
		"task_id", taskID, "status", status, "frame_bytes", size, "limit", MaxTaskResponseFrame)
	message = withVerifyNotice(notice, TaskStatusFailed, oversizedResponseMessage(size))
	innerBytes, err := json.Marshal(buildTaskResponseInner(TaskStatusFailed, message, nil, log))
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("marshal inner response: %w", err)
	}
	return TaskStatusFailed, message, nil, innerBytes, nil
}
