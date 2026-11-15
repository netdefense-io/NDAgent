package pathfinder

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// The rules of a session carried over a byte stream. They are what its two
// ends agree on, so they change only together with the other end.
const (
	// StreamFrameMaxData is the most data one frame may hold on a byte
	// stream. A sender never exceeds it, and a receiver that reads a larger
	// length ends the session. The agent's own frames fit: a stream write is
	// split at 32 KiB.
	StreamFrameMaxData = 65536

	// streamKeepAliveInterval: an end that has sent nothing for this long
	// sends a KeepAlive frame.
	streamKeepAliveInterval = 20 * time.Second

	// streamReceiveTimeout: an end that has received no frame at all for this
	// long ends the session. Nothing else tells it that the other end died.
	streamReceiveTimeout = 60 * time.Second

	// streamCloseGrace is how long the other end of the byte stream has to
	// close its side once this one has closed its own. It covers a companion
	// process closing toward the client in order: sending what it was given,
	// then waiting for the client to close in answer.
	streamCloseGrace = 6 * time.Second
)

// Errors that end a StreamConn.
var (
	// ErrFrameTruncated: the stream ended inside a frame.
	ErrFrameTruncated = errors.New("the stream ended inside a frame")
	// ErrFrameTooLarge: a frame holds more data than a frame may on a byte
	// stream. For a frame read, nothing after it can be read as frames.
	ErrFrameTooLarge = errors.New("frame larger than the limit")
	// ErrWriteStalled: a frame could not be written within the write timeout.
	// The frame may be written in part, so nothing more can be sent.
	ErrWriteStalled = errors.New("the peer stopped taking frames")
	// ErrPeerSilent: no frame arrived within the receive timeout.
	ErrPeerSilent = errors.New("the peer stopped sending frames")
)

// StreamConn carries a session's frames over a byte stream instead of one
// relay message per frame. Frames follow one another with nothing in between,
// each found by the length in its header (frame.go): the same bytes a relay
// message holds. It is the FrameConn of a session whose connection is a pair
// of pipes.
//
// Two things exist only here. A frame holds at most StreamFrameMaxData bytes.
// And once the peer is connected, each end sends a KeepAlive frame when it has
// sent nothing for a while and ends the session when it has received nothing
// at all for longer: on the relay the relay itself says when a peer is gone.
//
// A write that fails or stalls ends the connection, and Run returns the
// cause. A frame written in part leaves the other end unable to find the next
// one.
//
// Ending the connection closes the writing side at once and the reading side
// only when the other end has closed it, or after a grace period. The other
// end is a process that, told by the end of its input that the session is
// over, still has the client's last bytes to pass on while it closes toward
// the client in order; with the reading side gone its write would fail in the
// middle of that. What arrives after the end is read and dropped.
type StreamConn struct {
	r io.ReadCloser
	w io.WriteCloser

	writeTimeout      time.Duration // per frame; writeWait unless a test shortens it
	keepAliveInterval time.Duration
	receiveTimeout    time.Duration
	closeGrace        time.Duration

	writeMu sync.Mutex // one frame at a time

	handlerMu sync.RWMutex
	handler   func([]byte)

	// created is when the connection was made. The three marks are how long
	// after it something last happened, plus one (0: never). Time is counted
	// on the monotonic clock this way: a wall clock that is set forward must
	// not make a busy session look idle or a live peer look silent.
	created      time.Time
	lastSent     atomic.Int64 // any frame written
	lastReceived atomic.Int64 // any frame read
	lastActivity atomic.Int64 // a frame other than KeepAlive, either way

	endOnce    sync.Once
	ended      chan struct{}
	cause      error       // why the connection was ended from this side; set before ended closes
	forceClose *time.Timer // closes the reading side when the other end does not; set with cause

	// closeReader closes the reading side once. A second caller waits for
	// the first to finish: a second Close of an *os.File returns before the
	// first has closed the descriptor.
	closeReader func()
}

// NewStreamConn returns a StreamConn that reads frames from r and writes them
// to w. When w has write deadlines (a pipe from os.Pipe does), each frame gets
// writeWait to be written.
func NewStreamConn(r io.ReadCloser, w io.WriteCloser) *StreamConn {
	c := &StreamConn{
		r:                 r,
		w:                 w,
		writeTimeout:      writeWait,
		keepAliveInterval: streamKeepAliveInterval,
		receiveTimeout:    streamReceiveTimeout,
		closeGrace:        streamCloseGrace,
		created:           time.Now(),
		ended:             make(chan struct{}),
	}
	c.closeReader = sync.OnceFunc(func() { _ = c.r.Close() })
	return c
}

func (c *StreamConn) mark(at *atomic.Int64) {
	at.Store(int64(time.Since(c.created)) + 1)
}

// OnFrame sets the handler for incoming frames. It is called from Run, one
// frame at a time, with the whole encoded frame. KeepAlive frames are not
// handed over. Nothing is read while the handler runs, so a handler that
// holds a frame for the length of the receive timeout makes a live peer look
// silent: the stream manager's hands each frame on without waiting.
func (c *StreamConn) OnFrame(handler func([]byte)) {
	c.handlerMu.Lock()
	c.handler = handler
	c.handlerMu.Unlock()
}

// SendFrame writes one encoded frame. It is safe for concurrent use. A frame
// with more data than StreamFrameMaxData, or whose header does not announce
// exactly the data it carries, is refused and not written: the other end
// finds the next frame by that length.
func (c *StreamConn) SendFrame(data []byte) error {
	if len(data) < frameHeaderSize {
		return errors.New("frame too short: missing header")
	}
	if len(data)-frameHeaderSize > StreamFrameMaxData {
		return fmt.Errorf("%w: %d bytes to send", ErrFrameTooLarge, len(data)-frameHeaderSize)
	}
	if announced := binary.BigEndian.Uint32(data[5:9]); int64(announced) != int64(len(data)-frameHeaderSize) {
		return fmt.Errorf("frame header announces %d bytes of data and carries %d", announced, len(data)-frameHeaderSize)
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	select {
	case <-c.ended:
		return errors.New("not connected")
	default:
	}
	if deadliner, ok := c.w.(interface{ SetWriteDeadline(time.Time) error }); ok {
		_ = deadliner.SetWriteDeadline(time.Now().Add(c.writeTimeout))
	}
	if _, err := c.w.Write(data); err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			err = ErrWriteStalled
		}
		c.end(err)
		return err
	}
	c.mark(&c.lastSent)
	if data[0] != FrameTypeKeepAlive {
		c.mark(&c.lastActivity)
	}
	return nil
}

// Run reads frames and hands them to the handler until the stream ends. The
// peer is connected once connected is closed (nil: it already is); from then
// on Run sends KeepAlive frames and ends the connection when the peer is
// silent for too long.
//
// It returns nil when the stream ended between two frames (the other end
// closed it: the session is over) or Close was called, the cause when this
// side ended the connection (ErrPeerSilent, ErrWriteStalled, a failed write,
// ErrFrameTooLarge), ErrFrameTruncated when the stream ended inside a frame,
// and ctx's error when ctx ended first. When this side ended the connection,
// Run returns once the other end has closed its side too, or the grace period
// for that has passed. Both ends are closed when it returns.
func (c *StreamConn) Run(ctx context.Context, connected <-chan struct{}) error {
	stop := context.AfterFunc(ctx, func() { c.end(ctx.Err()) })
	defer stop()
	defer func() {
		c.end(nil)
		c.forceClose.Stop()
		c.closeReader()
	}()
	go c.keepAlive(connected)

	header := make([]byte, frameHeaderSize)
	for {
		if _, err := io.ReadFull(c.r, header); err != nil {
			return c.readEnded(err, errors.Is(err, io.EOF))
		}
		size := binary.BigEndian.Uint32(header[5:9])
		if size > StreamFrameMaxData {
			c.end(fmt.Errorf("%w: %d bytes announced", ErrFrameTooLarge, size))
			return c.cause
		}
		frame := bytes.NewBuffer(make([]byte, 0, frameHeaderSize+int(size)))
		frame.Write(header)
		if _, err := io.CopyN(frame, c.r, int64(size)); err != nil {
			return c.readEnded(err, false)
		}
		select {
		case <-c.ended:
			continue // over on this side: what still arrives is read and dropped
		default:
		}
		c.mark(&c.lastReceived)
		if header[0] == FrameTypeKeepAlive {
			continue
		}
		c.mark(&c.lastActivity)

		c.handlerMu.RLock()
		handler := c.handler
		c.handlerMu.RUnlock()
		if handler != nil {
			handler(frame.Bytes())
		}
	}
}

// keepAlive sends a KeepAlive frame whenever nothing was sent for the
// keepalive interval, and ends the connection when nothing was received for
// the receive timeout. Both clocks start when the peer connects.
func (c *StreamConn) keepAlive(connected <-chan struct{}) {
	if connected != nil {
		select {
		case <-connected:
		case <-c.ended:
			return
		}
	}
	connectedAt := time.Since(c.created)
	// quiet is how long ago at was last marked, counted from the connection
	// when it was not marked since.
	quiet := func(at *atomic.Int64) time.Duration {
		now := time.Since(c.created)
		last := time.Duration(at.Load() - 1)
		if last < connectedAt {
			last = connectedAt
		}
		return now - last
	}

	keepAlive := EncodeFrame(&Frame{Type: FrameTypeKeepAlive})
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
		case <-c.ended:
			return
		}
		silent := quiet(&c.lastReceived)
		if silent >= c.receiveTimeout {
			c.end(ErrPeerSilent)
			return
		}
		unsent := quiet(&c.lastSent)
		if unsent >= c.keepAliveInterval {
			if err := c.SendFrame(keepAlive); err != nil {
				return
			}
			unsent = 0
		}
		timer.Reset(min(c.keepAliveInterval-unsent, c.receiveTimeout-silent))
	}
}

// readEnded is what Run returns for a failed read. A connection this side
// ended fails its read too, so what was recorded then is the answer: the
// cause, or nil for a plain Close.
func (c *StreamConn) readEnded(err error, betweenFrames bool) error {
	select {
	case <-c.ended:
		return c.cause
	default:
	}
	switch {
	case betweenFrames:
		return nil
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return ErrFrameTruncated
	default:
		return fmt.Errorf("read failed: %w", err)
	}
}

// end ends the connection once, recording why: the writing side closes now,
// the reading side when the other end has closed it or the grace period for
// that has passed.
func (c *StreamConn) end(cause error) {
	c.endOnce.Do(func() {
		c.cause = cause
		c.forceClose = time.AfterFunc(c.closeGrace, c.closeReader)
		close(c.ended)
		_ = c.w.Close()
	})
}

// Close ends the connection. A Run in progress returns once the other end
// has closed its side, or after the grace period.
func (c *StreamConn) Close() error {
	c.end(nil)
	return nil
}

// LastActivity is when the last frame other than a KeepAlive was read or
// written, or the zero time before any. A session's idle time is counted from
// it: KeepAlive frames say the peer is there, not that the session is in use.
func (c *StreamConn) LastActivity() time.Time {
	marked := c.lastActivity.Load()
	if marked == 0 {
		return time.Time{}
	}
	return c.created.Add(time.Duration(marked - 1))
}
