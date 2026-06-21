package pathfinder

// exec.go — ExecManager: persistent MCP-driven command execution stream.
//
// # Wire contract (pin these for the NDCLI implementer)
//
// Stream name: "exec"
// Transport: FrameTypeData frames on the exec Stream, one JSON object per frame.
//
// ## Request (client → agent)
//
//	{
//	  "id":              "<req-uuid>",        // echoed on every response for this command
//	  "command":         "pfctl -s info",     // shell command; run via /bin/sh -c
//	  "timeout_seconds": 60                   // optional; <=0 → defaultExecTimeout (60 s)
//	}
//
// ## Responses (agent → client), in this order for each request
//
//	Zero or more stdout chunks:
//	  { "id": "<req-uuid>", "type": "stdout", "data": "<base64>" }
//
//	Zero or more stderr chunks:
//	  { "id": "<req-uuid>", "type": "stderr", "data": "<base64>" }
//
//	Exactly one result, always last:
//	  { "id": "<req-uuid>", "type": "result", "exit_code": 0, "truncated": false }
//
// ## Wire contract decisions (immutable — NDCLI must match byte-for-byte)
//
//  1. DATA ENCODING: the "data" field is standard base64 (RFC 4648, no line
//     breaks; encoding/base64.StdEncoding). This handles binary output and
//     terminal control bytes without JSON escaping issues. The client must
//     base64-decode the "data" field before presenting output to the user.
//
//  2. FRAMING: each JSON response object is encoded as exactly one FrameTypeData
//     frame. A response is never split across frames, and multiple responses are
//     never coalesced into one frame. The client must treat each received
//     FrameTypeData payload as a complete, independent JSON object. This is
//     guaranteed because execResponseChunkSize (24000 raw bytes) is chosen so
//     that the base64-encoded chunk plus JSON overhead stays below the
//     Stream.Write internal 32 KiB chunk boundary.
//
//  3. TIMEOUT DEFAULT: 60 s (defaultExecTimeout). Applied when timeout_seconds
//     is absent (zero value) or explicitly <=0. Maximum: 3600 s (maxExecTimeout);
//     values above the cap are silently clamped.
//
//  4. TIMEOUT EXIT CODE: 124 (ExecTimeoutExitCode). This matches the convention
//     used by GNU coreutils timeout(1). On timeout the agent kills the entire
//     process group (SIGKILL to -pgid), emits a stderr chunk with the literal
//     text "command timed out\n", then sends the result frame.
//
//  5. SIGNAL EXIT CODE: for processes terminated by a signal the agent reports
//     exit_code = 128 + signal_number (e.g. SIGKILL=9 → exit_code=137), which
//     follows the POSIX shell convention. If the signal number cannot be
//     determined, exit_code=-1 is reported.
//
//  6. OUTPUT CAP: 1 MiB (execOutputCap = 1<<20 bytes) combined across stdout
//     and stderr. When the cap is hit, stdout is trimmed first (up to the full
//     cap), then stderr fills the remainder; any bytes beyond the cap are
//     discarded and result.truncated=true. The process is still awaited and its
//     exit code is faithfully reported.
//
//  7. SERIALISATION: one command at a time. The agent holds a mutex across the
//     full lifecycle of each command. If the client sends a request before
//     receiving the result for the previous one, the new request is queued in the
//     JSON decoder's buffer and processed after the current command finishes.
//     The NDCLI/MCP layer SHOULD wait for the result frame before sending the
//     next request, but the agent handles the queued case gracefully.
//
//  8. MALFORMED REQUEST: a request that cannot be JSON-parsed yields:
//       { "id": "", "type": "stderr", "data": "<base64 of error text>" }
//       { "id": "", "type": "result", "exit_code": -1, "truncated": false }
//     The stream stays open; subsequent requests are processed normally.
//
//  9. PRIVILEGE: commands run as the agent process owner (root on OPNsense) with
//     DeviceExecEnv() providing PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin,
//     HOME=/root, working directory /root.
//
// 10. STREAM LIFETIME: the exec stream stays open across many commands. It closes
//     only when the client sends a FrameTypeClose frame, handled by the normal
//     StreamManager.handleClose path. The ExecManager never closes the stream
//     itself. Closing the exec stream does NOT end the CONNECT session: session
//     lifetime is tied to the PathFinder relay connection (see
//     internal/tasks/connect.go), not the open-stream count, so the webadmin
//     tunnel survives the exec/terminal stream closing.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/util"
)

const (
	// defaultExecTimeout is the command deadline when timeout_seconds is absent or <=0.
	defaultExecTimeout = 60 * time.Second

	// maxExecTimeout caps timeout_seconds to prevent indefinitely long sessions.
	maxExecTimeout = 3600 * time.Second

	// execOutputCap is the combined stdout+stderr byte cap per command (1 MiB).
	execOutputCap = 1 << 20

	// ExecTimeoutExitCode is the exit_code in the result frame when the command
	// is killed by the agent's timeout. Matches GNU coreutils timeout(1).
	ExecTimeoutExitCode = 124

	// execResponseChunkSize is the maximum raw byte count per stdout/stderr chunk
	// before base64 encoding. It is sized so that the base64-encoded output
	// (ceil(raw * 4/3)) plus JSON object overhead (~80 bytes) stays below the
	// Stream.Write internal chunk size of 32 KiB, ensuring each sendMessage call
	// produces exactly one FrameTypeData frame.
	//
	// Math: maxRaw = (32768 - 80) * 3/4 ≈ 24516. We use 24000 for a round margin.
	execResponseChunkSize = 24000
)

// ExecRequest is the JSON object sent by the client (NDCLI) for each command.
type ExecRequest struct {
	ID             string `json:"id"`
	Command        string `json:"command"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

// ExecResponse is any JSON object sent by the agent to the client.
//
//   - type "stdout"/"stderr": Data is base64-encoded raw bytes; ExitCode and
//     Truncated are zero/false and must be ignored by the client.
//   - type "result": Data is empty; ExitCode is the process exit code;
//     Truncated is true if the output cap was reached.
type ExecResponse struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Data      string `json:"data,omitempty"`
	ExitCode  int    `json:"exit_code,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

// ExecManager owns a single persistent "exec" stream and serialises command
// execution over it. Construct once per CONNECT session via NewExecManager and
// call HandleExecStream in a goroutine.
type ExecManager struct {
	mu  sync.Mutex // serialises runCommand across concurrent calls
	log *zap.SugaredLogger
}

// NewExecManager creates a new ExecManager.
func NewExecManager() *ExecManager {
	return &ExecManager{
		log: logging.Named("pathfinder.exec"),
	}
}

// HandleExecStream reads JSON requests from the exec stream, runs each command,
// and writes JSON responses back. It blocks until the stream closes (EOF or
// error) or ctx is cancelled. Call this in a goroutine.
func (em *ExecManager) HandleExecStream(ctx context.Context, stream *Stream) {
	em.log.Debugw("Exec stream opened", "stream_id", stream.ID())

	dec := json.NewDecoder(stream)

	for {
		var req ExecRequest
		if err := dec.Decode(&req); err != nil {
			if err == io.EOF || isExecStreamClosed(err) {
				em.log.Debugw("Exec stream closed", "stream_id", stream.ID(), "error", err)
				return
			}
			// Check if context was cancelled while we were blocked in Decode.
			if ctx.Err() != nil {
				em.log.Debugw("Exec stream context cancelled", "stream_id", stream.ID())
				return
			}
			// Malformed JSON — report error, keep the stream open.
			em.log.Warnw("Malformed exec request", "stream_id", stream.ID(), "error", err)
			em.sendError(stream, "", fmt.Sprintf("malformed JSON request: %v", err))
			continue
		}

		// Serialise: acquire mutex for the full duration of the command.
		em.mu.Lock()
		em.runCommand(ctx, stream, req)
		em.mu.Unlock()

		// Check context after each command (runCommand may have used a timeout
		// derived from ctx; if ctx itself is done, stop processing).
		if ctx.Err() != nil {
			em.log.Debugw("Exec stream context cancelled after command", "stream_id", stream.ID())
			return
		}
	}
}

// runCommand executes req.Command under a /bin/sh -c wrapper, streams collected
// output back as stdout/stderr frames, then sends the final result frame.
// Must be called with em.mu held.
func (em *ExecManager) runCommand(ctx context.Context, stream *Stream, req ExecRequest) {
	log := em.log.With("req_id", req.ID, "stream_id", stream.ID())

	// Resolve timeout.
	timeout := defaultExecTimeout
	if req.TimeoutSeconds > 0 {
		d := time.Duration(req.TimeoutSeconds) * time.Second
		if d > maxExecTimeout {
			d = maxExecTimeout
		}
		timeout = d
	}

	log.Debugw("Executing command", "command", req.Command, "timeout", timeout)

	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var stdoutBuf, stderrBuf bytes.Buffer

	cmd := exec.CommandContext(cmdCtx, "/bin/sh", "-c", req.Command)
	cmd.Env = util.DeviceExecEnv()
	// Use /root as working directory (root's home on FreeBSD/OPNsense).
	// Fall back to no explicit Dir (inherits current directory) on platforms
	// where /root does not exist (e.g. macOS developer machines).
	if _, err := os.Stat("/root"); err == nil {
		cmd.Dir = "/root"
	}
	// Place the child in its own process group so we can kill the whole tree
	// on timeout (kill -pgid).
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	waitErr := cmd.Run()

	// Determine whether the context deadline was the cause of failure.
	timedOut := cmdCtx.Err() == context.DeadlineExceeded

	if timedOut && cmd.Process != nil {
		// cmd.Run() already attempted to kill the process when the context
		// expired, but it only kills the direct process. Kill the entire
		// process group to ensure subprocesses are reaped too.
		if pgid, err := syscall.Getpgid(cmd.Process.Pid); err == nil {
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
		}
	}

	// Apply output cap.
	stdoutData := stdoutBuf.Bytes()
	stderrData := stderrBuf.Bytes()
	truncated := false

	combined := len(stdoutData) + len(stderrData)
	if combined > execOutputCap {
		truncated = true
		if len(stdoutData) >= execOutputCap {
			// stdout alone exceeds the cap; discard all stderr.
			stdoutData = stdoutData[:execOutputCap]
			stderrData = nil
		} else {
			// stdout fits; trim stderr to fill the remainder.
			remaining := execOutputCap - len(stdoutData)
			stderrData = stderrData[:remaining]
		}
	}

	// Emit stdout chunks.
	if len(stdoutData) > 0 {
		em.sendChunked(stream, req.ID, "stdout", stdoutData)
	}

	// Emit stderr chunks; append timeout notice if applicable.
	if timedOut {
		stderrData = append(stderrData, []byte("command timed out\n")...)
	}
	if len(stderrData) > 0 {
		em.sendChunked(stream, req.ID, "stderr", stderrData)
	}

	// Resolve exit code.
	exitCode := resolveExitCode(waitErr, timedOut)

	log.Debugw("Command finished",
		"exit_code", exitCode,
		"truncated", truncated,
		"timed_out", timedOut,
	)

	em.sendResult(stream, req.ID, exitCode, truncated)
}

// resolveExitCode converts the error returned by cmd.Run() into a numeric exit
// code following the contract documented in the wire contract above.
func resolveExitCode(waitErr error, timedOut bool) int {
	if timedOut {
		return ExecTimeoutExitCode
	}
	if waitErr == nil {
		return 0
	}
	exitErr, ok := waitErr.(*exec.ExitError)
	if !ok {
		return -1
	}
	code := exitErr.ExitCode()
	if code != -1 {
		return code
	}
	// ExitCode() returns -1 when the process was killed by a signal.
	// Remap to 128+signum following the POSIX shell convention.
	if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return 128 + int(status.Signal())
	}
	return -1
}

// sendChunked base64-encodes data and sends it in up to execResponseChunkSize
// raw-byte chunks, each as a separate FrameTypeData frame carrying exactly one
// JSON object. The chunk size is chosen so that base64(chunk) + JSON overhead
// stays below the Stream.Write internal 32 KiB chunk size, preserving the
// one-JSON-per-frame invariant.
func (em *ExecManager) sendChunked(stream *Stream, id, msgType string, data []byte) {
	for len(data) > 0 {
		n := execResponseChunkSize
		if n > len(data) {
			n = len(data)
		}
		em.sendMessage(stream, ExecResponse{
			ID:   id,
			Type: msgType,
			Data: base64.StdEncoding.EncodeToString(data[:n]),
		})
		data = data[n:]
	}
}

// sendError emits a stderr chunk followed by a failed result frame. Used for
// pre-execution failures (malformed request, command start error).
func (em *ExecManager) sendError(stream *Stream, id, msg string) {
	em.sendMessage(stream, ExecResponse{
		ID:   id,
		Type: "stderr",
		Data: base64.StdEncoding.EncodeToString([]byte(msg)),
	})
	em.sendResult(stream, id, -1, false)
}

// sendResult emits the final result frame for a command.
func (em *ExecManager) sendResult(stream *Stream, id string, exitCode int, truncated bool) {
	em.sendMessage(stream, ExecResponse{
		ID:        id,
		Type:      "result",
		ExitCode:  exitCode,
		Truncated: truncated,
	})
}

// sendMessage JSON-encodes resp and writes it as a single FrameTypeData frame.
// Each call produces exactly one frame on the stream.
func (em *ExecManager) sendMessage(stream *Stream, resp ExecResponse) {
	data, err := json.Marshal(resp)
	if err != nil {
		em.log.Errorw("Failed to marshal exec response", "error", err)
		return
	}
	if _, err := stream.Write(data); err != nil {
		em.log.Warnw("Failed to write exec response",
			"type", resp.Type,
			"id", resp.ID,
			"error", err,
		)
	}
}

// isExecStreamClosed returns true for errors that indicate the stream or
// underlying connection was closed, so the read loop can exit cleanly.
func isExecStreamClosed(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "stream closed") ||
		strings.Contains(msg, "use of closed network connection")
}

// CloseAll is a no-op. Stream lifetime is managed by StreamManager; ExecManager
// never closes the stream itself. Provided for symmetry with ShellManager.
func (em *ExecManager) CloseAll() {}
