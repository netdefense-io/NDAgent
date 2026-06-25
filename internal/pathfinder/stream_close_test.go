package pathfinder

import (
	"io"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/logging"
)

// newCloseTestStream builds a Stream backed by a StreamManager whose
// sendFrameFunc records emitted frame types, so a test can assert that an
// agent-initiated Close reliably emits a CLOSE frame.
func newCloseTestStream() (*Stream, *[]byte) {
	var sent []byte
	mgr := &StreamManager{
		streams: make(map[uint32]*Stream),
		log:     logging.Named("test"),
	}
	mgr.sendFrameFunc = func(data []byte) error {
		f, err := DecodeFrame(data)
		if err != nil {
			return err
		}
		sent = append(sent, f.Type)
		return nil
	}
	s := &Stream{
		id:        7,
		readBuf:   make(chan []byte, 8),
		closeChan: make(chan struct{}),
		manager:   mgr,
		log:       logging.Named("test.stream"),
	}
	mgr.streams[7] = s
	return s, &sent
}

// TestStreamClose_EmitsCloseFrame is the core delivery guarantee: an
// agent-initiated Close MUST synchronously emit exactly one CLOSE frame. The
// shell handler relies on this so the client observes EOF and transitions to
// the webadmin keep-alive on logout.
func TestStreamClose_EmitsCloseFrame(t *testing.T) {
	s, sent := newCloseTestStream()

	if err := s.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	if len(*sent) != 1 || (*sent)[0] != FrameTypeClose {
		t.Fatalf("expected exactly one CLOSE frame emitted, got types %v", *sent)
	}

	// Idempotent: a second Close is a no-op (no duplicate CLOSE frame).
	if err := s.Close(); err != nil {
		t.Fatalf("second Close returned error: %v", err)
	}
	if len(*sent) != 1 {
		t.Fatalf("expected Close to be idempotent (1 CLOSE frame total), got %v", *sent)
	}
}

// TestStreamClose_UnblocksParkedReader proves the input-copy-goroutine leak fix:
// a reader parked in Read (waiting on readBuf) must observe io.EOF when the
// stream is closed agent-side. Before the fix, agent-side Close closed only
// closeChan (not readBuf) and Read waited solely on readBuf, so the shell input
// copy goroutine leaked forever after logout.
func TestStreamClose_UnblocksParkedReader(t *testing.T) {
	s, _ := newCloseTestStream()

	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 16)
		_, err := s.Read(buf)
		readDone <- err
	}()

	// Give the reader a moment to park on readBuf, then close agent-side.
	time.Sleep(20 * time.Millisecond)
	if err := s.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	select {
	case err := <-readDone:
		if err != io.EOF {
			t.Fatalf("parked Read after agent Close: got err %v, want io.EOF", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("parked Read did not unblock after agent-initiated Close (goroutine leak)")
	}
}

// TestStreamClose_DrainsBufferedDataBeforeEOF guards the close path's drain: if
// a DATA frame was buffered just before close, the next Read returns that data
// rather than dropping it for an immediate EOF.
func TestStreamClose_DrainsBufferedDataBeforeEOF(t *testing.T) {
	s, _ := newCloseTestStream()

	s.readBuf <- []byte("tail")
	if err := s.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	buf := make([]byte, 16)
	n, err := s.Read(buf)
	if err != nil {
		t.Fatalf("expected buffered data before EOF, got err %v", err)
	}
	if got := string(buf[:n]); got != "tail" {
		t.Fatalf("expected to read buffered %q, got %q", "tail", got)
	}

	// Next read is EOF.
	if _, err := s.Read(buf); err != io.EOF {
		t.Fatalf("expected io.EOF after draining buffered data, got %v", err)
	}
}
