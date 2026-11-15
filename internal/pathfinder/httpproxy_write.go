package pathfinder

import (
	"bufio"
	"io"
	"net/http"
	"sync"
	"time"
)

// responseBufferSize is the most a response puts in one DATA frame, the
// stream's own chunk size.
const responseBufferSize = 32 * 1024

// bufferedFlush is the longest a byte of a response waits in the buffer
// before it is sent: an event stream or a slow page must not sit there while
// the upstream is quiet or trickles.
const bufferedFlush = 20 * time.Millisecond

var responseBuffers = sync.Pool{New: func() any { return bufio.NewWriterSize(nil, responseBufferSize) }}

// writeResponse writes resp to the stream through a buffer, so its status line,
// its header lines and the start of its body leave in one DATA frame instead of
// one frame for each write resp.Write makes. What is buffered is sent when the
// buffer is full, bufferedFlush after the first byte went into it, and at the
// end of the response.
func writeResponse(stream io.Writer, resp *http.Response) error {
	bw := responseBuffers.Get().(*bufio.Writer)
	bw.Reset(stream)
	w := &timedFlushWriter{bw: bw}
	err := resp.Write(w)
	if ferr := w.finish(); err == nil {
		err = ferr
	}
	bw.Reset(nil)
	responseBuffers.Put(bw)
	return err
}

// timedFlushWriter is the buffer of one response. Its timer flushes it while
// resp.Write may be blocked reading the body, so every use takes the lock.
type timedFlushWriter struct {
	mu    sync.Mutex
	bw    *bufio.Writer
	timer *time.Timer
	armed bool
	done  bool
}

func (w *timedFlushWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.bw.Write(p)
	if !w.armed && w.bw.Buffered() > 0 {
		w.armed = true
		if w.timer == nil {
			w.timer = time.AfterFunc(bufferedFlush, w.flush)
		} else {
			w.timer.Reset(bufferedFlush)
		}
	}
	return n, err
}

func (w *timedFlushWriter) flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.armed = false
	if !w.done {
		// An error stays in the writer and is returned by its next write.
		_ = w.bw.Flush()
	}
}

// finish sends what is left and gives up the buffer: a timer that fires
// later finds it done.
func (w *timedFlushWriter) finish() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.done = true
	if w.timer != nil {
		w.timer.Stop()
	}
	return w.bw.Flush()
}
