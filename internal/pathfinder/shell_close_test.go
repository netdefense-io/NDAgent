package pathfinder

import (
	"sync"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/logging"
)

// shellFrameCapture records the type-ordered sequence of frames emitted for the
// shell data stream (id 1), so a test can assert that the shell's output DATA is
// flushed and a single CLOSE frame is reliably the final frame on the stream.
type shellFrameCapture struct {
	mu      sync.Mutex
	dataLen int  // total DATA bytes seen on the shell stream
	closes  int  // number of CLOSE frames seen on the shell stream
	lastWas byte // type of the last frame on the shell stream
}

// newShellTestSession wires a ShellSession whose shell/ctl streams share a
// StreamManager with a capturing sendFrameFunc. The shell stream is id 1; the
// ctl stream is id 2. Returns the session and the capture.
func newShellTestSession(t *testing.T, shellCmd string) (*ShellSession, *shellFrameCapture) {
	t.Helper()

	cap := &shellFrameCapture{}

	mgr := &StreamManager{
		streams: make(map[uint32]*Stream),
		log:     logging.Named("test"),
	}
	mgr.sendFrameFunc = func(data []byte) error {
		frame, err := DecodeFrame(data)
		if err != nil {
			return err
		}
		if frame.StreamID != 1 { // only track the shell data stream
			return nil
		}
		cap.mu.Lock()
		switch frame.Type {
		case FrameTypeData:
			cap.dataLen += len(frame.Data)
		case FrameTypeClose:
			cap.closes++
		}
		cap.lastWas = frame.Type
		cap.mu.Unlock()
		return nil
	}

	newStream := func(id uint32) *Stream {
		s := &Stream{
			id:        id,
			readBuf:   make(chan []byte, 256),
			closeChan: make(chan struct{}),
			manager:   mgr,
			log:       logging.Named("test.stream"),
		}
		mgr.streams[id] = s
		return s
	}

	sess := &ShellSession{
		shellStream: newStream(1),
		ctlStream:   newStream(2),
		shell:       shellCmd,
		dir:         t.TempDir(), // /root may not exist on CI/dev hosts
		log:         logging.Named("test.shell"),
	}
	return sess, cap
}

// TestShellRun_ImmediateExit_FlushesOutputThenSingleClose reproduces the
// fast-logout race: a shell that writes a final banner and exits immediately.
// The agent must flush that output to the client AND deliver exactly one CLOSE
// frame as the last frame on the shell stream, so the client's reader observes
// all output and then EOF. Before the fix, cmd.Wait() returning ahead of the
// output-copy drain could drop the trailing output and/or reorder the CLOSE.
func TestShellRun_ImmediateExit_FlushesOutputThenSingleClose(t *testing.T) {
	// /bin/sh is present on the FreeBSD target and on the dev/CI hosts; it
	// emits the banner then exits at once, mimicking selecting logout (0).
	sess, cap := newShellTestSession(t, "/bin/sh")

	// Drive a single command then EOF so the PTY-attached shell prints output
	// and exits promptly — the immediate-logout window.
	go func() {
		sess.shellStream.readBuf <- []byte("printf 'LOGOUT-BANNER\\n'; exit\n")
	}()

	done := make(chan struct{})
	go func() {
		_ = sess.run()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("shell session did not end within 10s")
	}

	cap.mu.Lock()
	defer cap.mu.Unlock()

	if cap.closes != 1 {
		t.Fatalf("expected exactly one CLOSE frame on shell stream, got %d", cap.closes)
	}
	if cap.lastWas != FrameTypeClose {
		t.Fatalf("expected CLOSE to be the last frame on the shell stream, last was type 0x%02x", cap.lastWas)
	}
	if cap.dataLen == 0 {
		t.Fatal("expected the shell's banner output to be flushed as DATA before CLOSE, got 0 DATA bytes")
	}
}

// TestStreamSendCloseFrame_AlwaysEmits proves SendCloseFrame writes a CLOSE
// frame even when the stream is already marked closed (the no-op case for
// Close()). This is the unit-level guarantee behind the fast-logout fix.
func TestStreamSendCloseFrame_AlwaysEmits(t *testing.T) {
	s, sent := newCloseTestStream()

	// Pre-close the stream as an incoming client CLOSE would.
	s.mu.Lock()
	s.closed = true
	close(s.closeChan)
	s.mu.Unlock()

	if err := s.SendCloseFrame(); err != nil {
		t.Fatalf("SendCloseFrame returned error: %v", err)
	}
	if len(*sent) != 1 || (*sent)[0] != FrameTypeClose {
		t.Fatalf("expected SendCloseFrame to emit one CLOSE frame despite the stream being already closed, got types %v", *sent)
	}
}
