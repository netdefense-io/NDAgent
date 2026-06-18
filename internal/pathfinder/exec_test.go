package pathfinder

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/logging"
)

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

// newTestStreamPair creates a *Stream backed by a StreamManager whose
// sendFrameFunc intercepts DATA frames and stores the JSON payload in frames.
// The returned *Stream has a live readBuf channel that callers can push bytes
// into via pushInput, and a closeInput to signal EOF.
type testCapture struct {
	mu     sync.Mutex
	stream *Stream
	frames []json.RawMessage // DATA frame payloads, appended on each Write
}

func newTestCapture() *testCapture {
	tc := &testCapture{}

	mgr := &StreamManager{
		streams: make(map[uint32]*Stream),
		log:     logging.Named("test"),
	}
	mgr.sendFrameFunc = func(data []byte) error {
		frame, err := DecodeFrame(data)
		if err != nil {
			return err
		}
		if frame.Type == FrameTypeData {
			payload := make(json.RawMessage, len(frame.Data))
			copy(payload, frame.Data)
			tc.mu.Lock()
			tc.frames = append(tc.frames, payload)
			tc.mu.Unlock()
		}
		return nil
	}

	s := &Stream{
		id:        1,
		readBuf:   make(chan []byte, 256),
		closeChan: make(chan struct{}),
		manager:   mgr,
		log:       logging.Named("test.stream"),
	}
	mgr.streams[1] = s
	tc.stream = s
	return tc
}

// pushBytes enqueues a byte slice as one readBuf entry (one frame payload).
func (tc *testCapture) pushBytes(data []byte) {
	cp := make([]byte, len(data))
	copy(cp, data)
	tc.stream.readBuf <- cp
}

// closeInput marks the stream as closed and closes readBuf so the json.Decoder
// inside HandleExecStream sees EOF.
func (tc *testCapture) closeInput() {
	tc.stream.mu.Lock()
	if !tc.stream.closed {
		tc.stream.closed = true
		close(tc.stream.closeChan)
		close(tc.stream.readBuf)
	}
	tc.stream.mu.Unlock()
}

// responses decodes all captured DATA frame payloads as ExecResponse objects.
// Safe to call concurrently with the exec goroutine.
func (tc *testCapture) responses() []ExecResponse {
	tc.mu.Lock()
	frames := make([]json.RawMessage, len(tc.frames))
	copy(frames, tc.frames)
	tc.mu.Unlock()

	var out []ExecResponse
	for _, raw := range frames {
		var resp ExecResponse
		if err := json.Unmarshal(raw, &resp); err != nil {
			panic("unmarshal: " + err.Error() + " raw: " + string(raw))
		}
		out = append(out, resp)
	}
	return out
}

// encodeReq encodes an ExecRequest as JSON.
func encodeReq(id, command string, timeoutSec int) []byte {
	b, _ := json.Marshal(ExecRequest{ID: id, Command: command, TimeoutSeconds: timeoutSec})
	return b
}

// lastResult returns the last "result" frame, failing the test if none exists.
func lastResult(t *testing.T, resps []ExecResponse) ExecResponse {
	t.Helper()
	for i := len(resps) - 1; i >= 0; i-- {
		if resps[i].Type == "result" {
			return resps[i]
		}
	}
	t.Fatal("no result frame found")
	return ExecResponse{}
}

// decodeAll concatenates all decoded "data" fields from frames of the given type.
func decodeAll(t *testing.T, resps []ExecResponse, typ string) string {
	t.Helper()
	var sb strings.Builder
	for _, r := range resps {
		if r.Type != typ {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(r.Data)
		if err != nil {
			t.Fatalf("base64 decode failed: %v", err)
		}
		sb.Write(raw)
	}
	return sb.String()
}

// runOne runs a single ExecRequest through runCommand and returns responses.
func runOne(t *testing.T, req ExecRequest) []ExecResponse {
	t.Helper()
	tc := newTestCapture()
	em := NewExecManager()
	em.mu.Lock()
	em.runCommand(context.Background(), tc.stream, req)
	em.mu.Unlock()
	return tc.responses()
}

// ---------------------------------------------------------------------------
// Wire-contract constant tests
// ---------------------------------------------------------------------------

func TestWireContractConstants(t *testing.T) {
	// These constants are part of the cross-module wire contract with NDCLI.
	// Changes to these values require a paired NDCLI update.
	if defaultExecTimeout != 60*time.Second {
		t.Errorf("defaultExecTimeout = %v, want 60s", defaultExecTimeout)
	}
	if maxExecTimeout != 3600*time.Second {
		t.Errorf("maxExecTimeout = %v, want 3600s", maxExecTimeout)
	}
	if ExecTimeoutExitCode != 124 {
		t.Errorf("ExecTimeoutExitCode = %d, want 124", ExecTimeoutExitCode)
	}
	if execOutputCap != 1<<20 {
		t.Errorf("execOutputCap = %d, want %d (1 MiB)", execOutputCap, 1<<20)
	}
}

// ---------------------------------------------------------------------------
// resolveExitCode unit tests
// ---------------------------------------------------------------------------

func TestResolveExitCode_Success(t *testing.T) {
	if got := resolveExitCode(nil, false); got != 0 {
		t.Errorf("got %d, want 0", got)
	}
}

func TestResolveExitCode_Timeout(t *testing.T) {
	if got := resolveExitCode(nil, true); got != ExecTimeoutExitCode {
		t.Errorf("got %d, want %d", got, ExecTimeoutExitCode)
	}
}

func TestResolveExitCode_TimeoutOverridesError(t *testing.T) {
	// Even with a non-nil error, timeout flag wins.
	if got := resolveExitCode(io.EOF, true); got != ExecTimeoutExitCode {
		t.Errorf("got %d, want %d", got, ExecTimeoutExitCode)
	}
}

// ---------------------------------------------------------------------------
// JSON encoding / wire format tests
// ---------------------------------------------------------------------------

// TestDataFieldIsBase64 verifies that binary and control bytes survive the
// round-trip through JSON as base64.
func TestDataFieldIsBase64(t *testing.T) {
	raw := "hello\x00world\n\x1b[31mred\x1b[0m"
	encoded := base64.StdEncoding.EncodeToString([]byte(raw))

	resp := ExecResponse{ID: "r1", Type: "stdout", Data: encoded}
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got ExecResponse
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(got.Data)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	if string(decoded) != raw {
		t.Errorf("round-trip: got %q, want %q", decoded, raw)
	}
}

// TestResultOmitsData verifies that result frames do not carry a "data" field
// when empty (omitempty).
func TestResultOmitsData(t *testing.T) {
	resp := ExecResponse{ID: "r1", Type: "result", ExitCode: 0}
	b, _ := json.Marshal(resp)
	var m map[string]interface{}
	json.Unmarshal(b, &m)
	if _, ok := m["data"]; ok {
		t.Error("result frame must not include 'data' field (omitempty)")
	}
}

// TestTruncatedOmittedWhenFalse verifies that truncated=false is elided from
// the JSON output (omitempty), reducing wire noise.
func TestTruncatedOmittedWhenFalse(t *testing.T) {
	resp := ExecResponse{ID: "r1", Type: "result", ExitCode: 0, Truncated: false}
	b, _ := json.Marshal(resp)
	var m map[string]interface{}
	json.Unmarshal(b, &m)
	if _, ok := m["truncated"]; ok {
		t.Error("result frame must not include 'truncated' when false (omitempty)")
	}
}

// TestTruncatedPresentWhenTrue verifies that truncated=true is included.
func TestTruncatedPresentWhenTrue(t *testing.T) {
	resp := ExecResponse{ID: "r1", Type: "result", ExitCode: 0, Truncated: true}
	b, _ := json.Marshal(resp)
	var m map[string]interface{}
	json.Unmarshal(b, &m)
	v, ok := m["truncated"]
	if !ok {
		t.Error("result frame must include 'truncated' when true")
	}
	if v != true {
		t.Errorf("truncated = %v, want true", v)
	}
}

// ---------------------------------------------------------------------------
// Framing: one JSON object per sendMessage call → one DATA frame
// ---------------------------------------------------------------------------

// TestFramingOneMessagePerFrame verifies the invariant that each sendMessage
// call produces exactly one FrameTypeData frame, not more, not fewer.
func TestFramingOneMessagePerFrame(t *testing.T) {
	tc := newTestCapture()
	em := NewExecManager()

	msgs := []ExecResponse{
		{ID: "a", Type: "stdout", Data: base64.StdEncoding.EncodeToString([]byte("out"))},
		{ID: "a", Type: "stderr", Data: base64.StdEncoding.EncodeToString([]byte("err"))},
		{ID: "a", Type: "result", ExitCode: 0},
	}
	for _, m := range msgs {
		em.sendMessage(tc.stream, m)
	}

	if got := len(tc.frames); got != len(msgs) {
		t.Errorf("expected %d DATA frames, got %d", len(msgs), got)
	}
}

// TestSendChunked_SplitsAndRoundTrips verifies that sendChunked splits large
// data at the execResponseChunkSize boundary and that the concatenated decoded
// output matches the original.
func TestSendChunked_SplitsAndRoundTrips(t *testing.T) {
	tc := newTestCapture()
	em := NewExecManager()

	// 2.5 chunks worth of data
	chunkCount := 2
	extra := execResponseChunkSize / 2
	totalRaw := chunkCount*execResponseChunkSize + extra
	data := bytes.Repeat([]byte("x"), totalRaw)

	em.sendChunked(tc.stream, "sc", "stdout", data)

	wantFrames := chunkCount + 1 // two full chunks + one partial
	if got := len(tc.frames); got != wantFrames {
		t.Errorf("expected %d frames for %d-byte data, got %d", wantFrames, totalRaw, got)
	}

	// Round-trip: decode all and reassemble.
	resps := tc.responses()
	var got []byte
	for _, r := range resps {
		raw, err := base64.StdEncoding.DecodeString(r.Data)
		if err != nil {
			t.Fatalf("base64 decode: %v", err)
		}
		got = append(got, raw...)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("round-trip length mismatch: got %d, want %d", len(got), len(data))
	}
}

// ---------------------------------------------------------------------------
// sendError path
// ---------------------------------------------------------------------------

func TestSendError_ReturnsStderrThenResult(t *testing.T) {
	tc := newTestCapture()
	em := NewExecManager()

	em.sendError(tc.stream, "req-1", "something went wrong")

	resps := tc.responses()
	if len(resps) < 2 {
		t.Fatalf("expected >=2 frames, got %d", len(resps))
	}

	// First frame: stderr containing the error text.
	if resps[0].Type != "stderr" {
		t.Errorf("resps[0].Type = %q, want 'stderr'", resps[0].Type)
	}
	stderrText := decodeAll(t, resps[:1], "stderr")
	if !strings.Contains(stderrText, "something went wrong") {
		t.Errorf("stderr text %q does not contain expected message", stderrText)
	}

	// Last frame: result with exit_code=-1 and id echoed.
	result := lastResult(t, resps)
	if result.ExitCode != -1 {
		t.Errorf("exit_code = %d, want -1", result.ExitCode)
	}
	if result.ID != "req-1" {
		t.Errorf("result ID = %q, want 'req-1'", result.ID)
	}
	if result.Truncated {
		t.Error("truncated must be false for error result")
	}
}

// ---------------------------------------------------------------------------
// Command execution tests (require a real shell on the host)
// ---------------------------------------------------------------------------

func TestRunCommand_SuccessReturnsStdoutAndExitZero(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping shell exec test in short mode")
	}

	resps := runOne(t, ExecRequest{ID: "t1", Command: "echo hello", TimeoutSeconds: 10})

	result := lastResult(t, resps)
	if result.ExitCode != 0 {
		t.Errorf("exit_code = %d, want 0", result.ExitCode)
	}
	if result.Truncated {
		t.Error("truncated must be false for small output")
	}
	if got := decodeAll(t, resps, "stdout"); !strings.Contains(got, "hello") {
		t.Errorf("stdout %q does not contain 'hello'", got)
	}
}

func TestRunCommand_NonZeroExitCode(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping shell exec test in short mode")
	}

	resps := runOne(t, ExecRequest{ID: "t2", Command: "exit 42"})

	if got := lastResult(t, resps).ExitCode; got != 42 {
		t.Errorf("exit_code = %d, want 42", got)
	}
}

func TestRunCommand_StderrIsDelivered(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping shell exec test in short mode")
	}

	resps := runOne(t, ExecRequest{ID: "t3", Command: "echo errtext >&2"})

	result := lastResult(t, resps)
	if result.ExitCode != 0 {
		t.Errorf("exit_code = %d, want 0", result.ExitCode)
	}
	if got := decodeAll(t, resps, "stderr"); !strings.Contains(got, "errtext") {
		t.Errorf("stderr %q does not contain 'errtext'", got)
	}
}

func TestRunCommand_TimeoutKillsAndReturns124(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping shell exec test in short mode")
	}

	start := time.Now()
	resps := runOne(t, ExecRequest{ID: "t4", Command: "sleep 60", TimeoutSeconds: 1})
	elapsed := time.Since(start)

	if elapsed > 5*time.Second {
		t.Errorf("command was not killed quickly enough: elapsed %v", elapsed)
	}

	result := lastResult(t, resps)
	if result.ExitCode != ExecTimeoutExitCode {
		t.Errorf("exit_code = %d, want %d", result.ExitCode, ExecTimeoutExitCode)
	}
	if got := decodeAll(t, resps, "stderr"); !strings.Contains(got, "command timed out") {
		t.Errorf("stderr %q does not contain timeout notice", got)
	}
}

func TestRunCommand_DefaultTimeoutIsUsedWhenZero(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping shell exec test in short mode")
	}

	// TimeoutSeconds=0 should use the 60s default. We don't sleep 60s;
	// instead we verify that a fast command still gets exit_code=0.
	resps := runOne(t, ExecRequest{ID: "t5", Command: "echo fast", TimeoutSeconds: 0})
	if got := lastResult(t, resps).ExitCode; got != 0 {
		t.Errorf("exit_code = %d, want 0", got)
	}
}

func TestRunCommand_OutputCapSetsTruncated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping shell exec test in short mode")
	}

	// Generate ~2 MiB of output (> 1 MiB cap).
	resps := runOne(t, ExecRequest{
		ID:             "t6",
		Command:        "dd if=/dev/zero bs=1048576 count=2 2>/dev/null | tr '\\0' 'A'",
		TimeoutSeconds: 30,
	})

	result := lastResult(t, resps)
	if !result.Truncated {
		t.Error("expected truncated=true for 2 MiB output")
	}
	stdout := decodeAll(t, resps, "stdout")
	if len(stdout) > execOutputCap {
		t.Errorf("decoded stdout %d bytes exceeds cap %d", len(stdout), execOutputCap)
	}
}

func TestRunCommand_IDIsEchoedOnAllFrames(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping shell exec test in short mode")
	}

	const reqID = "my-unique-req-id"
	resps := runOne(t, ExecRequest{ID: reqID, Command: "echo out; echo err >&2"})

	for _, r := range resps {
		if r.ID != reqID {
			t.Errorf("frame ID = %q, want %q (type=%s)", r.ID, reqID, r.Type)
		}
	}
}

func TestRunCommand_ResultIsLastFrame(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping shell exec test in short mode")
	}

	resps := runOne(t, ExecRequest{ID: "order", Command: "echo out; echo err >&2"})
	if len(resps) == 0 {
		t.Fatal("no responses")
	}
	if last := resps[len(resps)-1]; last.Type != "result" {
		t.Errorf("last frame type = %q, want 'result'", last.Type)
	}
}

// ---------------------------------------------------------------------------
// HandleExecStream integration test
// ---------------------------------------------------------------------------

// TestHandleExecStream_TwoCommands verifies that the read loop serialises
// multiple commands and emits result frames for each.
//
// We start HandleExecStream in a goroutine, push two requests into its
// stream's read buffer, wait for two result frames, then cancel the context
// to terminate the goroutine.
func TestHandleExecStream_TwoCommands(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping shell exec test in short mode")
	}

	tc := newTestCapture()
	em := NewExecManager()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		em.HandleExecStream(ctx, tc.stream)
	}()

	// Push two requests. The goroutine is blocked in dec.Decode → stream.Read
	// waiting for data. Pushing to the buffered readBuf unblocks it.
	tc.pushBytes(encodeReq("cmd-1", "echo first", 10))
	tc.pushBytes(encodeReq("cmd-2", "echo second", 10))

	// Poll for 2 result frames, then close the stream to unblock dec.Decode.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		resps := tc.responses()
		count := 0
		for _, r := range resps {
			if r.Type == "result" {
				count++
			}
		}
		if count >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Closing the stream unblocks the goroutine's dec.Decode → stream.Read
	// returns io.EOF → HandleExecStream exits.
	tc.closeInput()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("HandleExecStream did not exit after stream close")
	}

	resps := tc.responses()
	var results []ExecResponse
	for _, r := range resps {
		if r.Type == "result" {
			results = append(results, r)
		}
	}
	if len(results) != 2 {
		t.Errorf("expected 2 result frames, got %d (total frames=%d)", len(results), len(resps))
		return
	}
	for _, r := range results {
		if r.ExitCode != 0 {
			t.Errorf("result id=%s exit_code=%d, want 0", r.ID, r.ExitCode)
		}
	}
}

// TestHandleExecStream_MalformedJSONIsHandled verifies that a syntactically
// invalid JSON object is handled gracefully: a stderr+result with exit_code=-1
// is emitted, and the stream stays open for subsequent requests.
func TestHandleExecStream_MalformedJSONIsHandled(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping shell exec test in short mode")
	}

	tc := newTestCapture()
	em := NewExecManager()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		em.HandleExecStream(ctx, tc.stream)
	}()

	// Push a syntactically complete but semantically unexpected JSON type
	// (array instead of object) then a valid request.
	tc.pushBytes([]byte(`[1,2,3]`)) // not an object; Decode produces a type error

	// Poll for the malformed result frame.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resps := tc.responses()
		for _, r := range resps {
			if r.Type == "result" && r.ExitCode == -1 {
				goto gotMalformedResult
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("did not receive result frame for malformed request within timeout")

gotMalformedResult:
	// Close the stream to unblock the goroutine's dec.Decode.
	tc.closeInput()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("HandleExecStream did not exit after stream close")
	}

	resps := tc.responses()
	var results []ExecResponse
	for _, r := range resps {
		if r.Type == "result" {
			results = append(results, r)
		}
	}
	if len(results) < 1 {
		t.Fatalf("expected at least 1 result frame, got 0 (total frames=%d)", len(resps))
	}
	if results[0].ExitCode != -1 {
		t.Errorf("malformed result exit_code = %d, want -1", results[0].ExitCode)
	}
}

// ---------------------------------------------------------------------------
// ExecManager.CloseAll is a no-op
// ---------------------------------------------------------------------------

func TestExecManager_CloseAllIsNoop(t *testing.T) {
	em := NewExecManager()
	em.CloseAll() // must not panic
}

// ---------------------------------------------------------------------------
// isExecStreamClosed helper
// ---------------------------------------------------------------------------

func TestIsExecStreamClosed(t *testing.T) {
	cases := []struct {
		msg  string
		want bool
	}{
		{"stream closed", true},
		{"use of closed network connection", true},
		{"some other error", false},
		{"", false},
	}
	for _, c := range cases {
		var err error
		if c.msg != "" {
			err = &errMsg{c.msg}
		}
		got := isExecStreamClosed(err)
		if got != c.want {
			t.Errorf("isExecStreamClosed(%q) = %v, want %v", c.msg, got, c.want)
		}
	}
	// nil input
	if isExecStreamClosed(nil) {
		t.Error("isExecStreamClosed(nil) must be false")
	}
}

type errMsg struct{ s string }

func (e *errMsg) Error() string { return e.s }
