package pathfinder

import (
	"errors"
	"io"
	"sync"

	"go.uber.org/zap"

	"github.com/netdefense-io/ndagent/internal/logging"
)

// StreamManager manages multiplexed streams over a single Pathfinder connection.
type StreamManager struct {
	client *Client

	streams   map[uint32]*Stream
	streamsMu sync.RWMutex

	// Callback for new incoming streams
	newStreamHandler func(*Stream)
	// Callback when all streams have closed
	onAllClosed func()
	handlerMu   sync.RWMutex

	// sendFrameFunc, when non-nil, replaces the default client.SendFrame call
	// in sendFrame. Used by tests to intercept outgoing frames without a real
	// WebSocket connection.
	sendFrameFunc func([]byte) error

	// Track if we ever had streams (don't fire onAllClosed before first stream)
	hadStreams bool

	log *zap.SugaredLogger
}

// NewStreamManager creates a new stream manager.
func NewStreamManager(client *Client) *StreamManager {
	sm := &StreamManager{
		client:  client,
		streams: make(map[uint32]*Stream),
		log:     logging.Named("pathfinder.stream"),
	}

	// Set up frame handler
	client.OnFrame(sm.handleFrame)

	return sm
}

// OnNewStream sets the callback for new incoming streams.
func (sm *StreamManager) OnNewStream(handler func(*Stream)) {
	sm.handlerMu.Lock()
	sm.newStreamHandler = handler
	sm.handlerMu.Unlock()
}

// OnAllStreamsClosed sets the callback to be called when the last stream closes.
// The callback is only fired if at least one stream was opened during the session.
func (sm *StreamManager) OnAllStreamsClosed(fn func()) {
	sm.handlerMu.Lock()
	sm.onAllClosed = fn
	sm.handlerMu.Unlock()
}

// handleFrame processes incoming binary frames.
func (sm *StreamManager) handleFrame(data []byte) {
	frame, err := DecodeFrame(data)
	if err != nil {
		sm.log.Errorw("Failed to decode frame", "error", err)
		return
	}

	sm.log.Debugw("Received frame",
		"type", frame.TypeString(),
		"stream_id", frame.StreamID,
		"data_len", len(frame.Data),
	)

	switch frame.Type {
	case FrameTypeOpen:
		sm.handleOpen(frame)
	case FrameTypeData:
		sm.handleData(frame)
	case FrameTypeClose:
		sm.handleClose(frame)
	case FrameTypeAck:
		sm.handleAck(frame)
	default:
		sm.log.Warnw("Unknown frame type", "type", frame.Type)
	}
}

// handleOpen processes an OPEN frame (new stream request from client).
func (sm *StreamManager) handleOpen(frame *Frame) {
	serviceName := string(frame.Data)

	sm.log.Debugw("Received stream open request",
		"stream_id", frame.StreamID,
		"service", serviceName,
	)

	// Create new stream
	stream := &Stream{
		id:          frame.StreamID,
		serviceName: serviceName,
		manager:     sm,
		readBuf:     make(chan []byte, 1024),
		closeChan:   make(chan struct{}),
		closed:      false,
		log:         sm.log.With("stream_id", frame.StreamID, "service", serviceName),
	}

	sm.streamsMu.Lock()
	sm.streams[frame.StreamID] = stream
	sm.hadStreams = true
	sm.streamsMu.Unlock()

	// Send ACK (via sendFrame so the sendFrameFunc test seam applies, matching
	// Stream.Write/Close).
	ackFrame := &Frame{
		Type:     FrameTypeAck,
		StreamID: frame.StreamID,
	}
	if err := sm.sendFrame(ackFrame); err != nil {
		sm.log.Errorw("Failed to send ACK", "error", err)
		stream.Close()
		return
	}

	sm.log.Debugw("Sent ACK for stream", "stream_id", frame.StreamID)

	// Notify handler
	sm.handlerMu.RLock()
	handler := sm.newStreamHandler
	sm.handlerMu.RUnlock()

	if handler != nil {
		go handler(stream)
	} else {
		sm.log.Warnw("No stream handler set, closing stream", "stream_id", frame.StreamID)
		stream.Close()
	}
}

// handleData processes a DATA frame.
func (sm *StreamManager) handleData(frame *Frame) {
	sm.streamsMu.RLock()
	stream, ok := sm.streams[frame.StreamID]
	sm.streamsMu.RUnlock()

	if !ok {
		sm.log.Warnw("Received data for unknown stream", "stream_id", frame.StreamID)
		return
	}

	stream.mu.Lock()
	if stream.closed {
		stream.mu.Unlock()
		return
	}
	stream.mu.Unlock()

	// Non-blocking send to avoid deadlocking the frame loop
	// If the buffer is full, we drop the data (consumer is too slow)
	select {
	case stream.readBuf <- frame.Data:
		// Success
	case <-stream.closeChan:
		// Stream closing, discard remaining data
		return
	default:
		// Buffer full, drop the frame to prevent deadlock
		sm.log.Warnw("Stream buffer full, dropping data",
			"stream_id", frame.StreamID,
			"data_len", len(frame.Data),
		)
	}
}

// handleClose processes a CLOSE frame.
func (sm *StreamManager) handleClose(frame *Frame) {
	sm.streamsMu.Lock()
	stream, ok := sm.streams[frame.StreamID]
	if ok {
		delete(sm.streams, frame.StreamID)
	}
	count := len(sm.streams)
	hadStreams := sm.hadStreams
	sm.streamsMu.Unlock()

	// Log with service name if we found the stream
	if ok && stream != nil {
		sm.log.Debugw("Received stream close", "stream_id", frame.StreamID, "service", stream.serviceName)

		stream.mu.Lock()
		if !stream.closed {
			stream.closed = true
			close(stream.closeChan) // Signal closure to unblock handleData
			close(stream.readBuf)
		}
		stream.mu.Unlock()
	} else {
		sm.log.Debugw("Received stream close for unknown stream", "stream_id", frame.StreamID)
	}

	// Fire callback if last stream closed and we had streams
	if count == 0 && hadStreams {
		sm.handlerMu.RLock()
		callback := sm.onAllClosed
		sm.handlerMu.RUnlock()
		if callback != nil {
			callback()
		}
	}
}

// handleAck processes an ACK frame (not typically received by agent).
func (sm *StreamManager) handleAck(frame *Frame) {
	sm.log.Debugw("Received ACK", "stream_id", frame.StreamID)
}

// sendFrame sends a frame via the client. If sendFrameFunc is set (typically in
// tests), it is called instead of the real client.SendFrame.
func (sm *StreamManager) sendFrame(frame *Frame) error {
	encoded := EncodeFrame(frame)
	if sm.sendFrameFunc != nil {
		return sm.sendFrameFunc(encoded)
	}
	return sm.client.SendFrame(encoded)
}

// removeStream removes a stream from the manager and fires the onAllClosed
// callback if this was the last stream.
func (sm *StreamManager) removeStream(id uint32) {
	sm.streamsMu.Lock()
	delete(sm.streams, id)
	count := len(sm.streams)
	hadStreams := sm.hadStreams
	sm.streamsMu.Unlock()

	// Fire callback if last stream closed and we had streams
	if count == 0 && hadStreams {
		sm.handlerMu.RLock()
		callback := sm.onAllClosed
		sm.handlerMu.RUnlock()
		if callback != nil {
			callback()
		}
	}
}

// CloseAll closes all streams.
func (sm *StreamManager) CloseAll() {
	sm.streamsMu.Lock()
	streams := make([]*Stream, 0, len(sm.streams))
	for _, s := range sm.streams {
		streams = append(streams, s)
	}
	sm.streamsMu.Unlock()

	for _, s := range streams {
		s.Close()
	}
}

// ActiveStreamCount returns the number of active streams.
func (sm *StreamManager) ActiveStreamCount() int {
	sm.streamsMu.RLock()
	defer sm.streamsMu.RUnlock()
	return len(sm.streams)
}

// Stream represents a single multiplexed stream.
type Stream struct {
	id          uint32
	serviceName string
	manager     *StreamManager

	readBuf   chan []byte
	closeChan chan struct{} // Signals stream closure to unblock handleData
	pending   []byte        // Partially read data from previous Read call

	closed bool
	mu     sync.Mutex

	log *zap.SugaredLogger
}

// ID returns the stream ID.
func (s *Stream) ID() uint32 {
	return s.id
}

// ServiceName returns the requested service name.
func (s *Stream) ServiceName() string {
	return s.serviceName
}

// Read implements io.Reader.
func (s *Stream) Read(p []byte) (n int, err error) {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()

	// Return any pending data first (partial frame from a previous Read).
	if len(s.pending) > 0 {
		n = copy(p, s.pending)
		s.pending = s.pending[n:]
		return n, nil
	}

	// If the stream is closed, drain any data still buffered in readBuf before
	// reporting EOF. An agent-side Close() closes closeChan but NOT readBuf, so
	// a frame delivered just before close must not be dropped — the consumer
	// (e.g. the client's terminal output copy) needs every byte before EOF.
	if closed {
		select {
		case data, ok := <-s.readBuf:
			if ok {
				n = copy(p, data)
				if n < len(data) {
					s.pending = data[n:]
				}
				return n, nil
			}
		default:
		}
		return 0, io.EOF
	}

	// Wait for data from buffer, or for the stream to close. We select on
	// closeChan as well as readBuf because there are two distinct close paths:
	// an incoming CLOSE frame (handleClose) closes readBuf, but an agent-side
	// Close() only closes closeChan (it cannot safely close readBuf without
	// racing handleData's send). Without the closeChan case, a reader parked
	// here on an agent-closed stream — e.g. the shell input copy after logout —
	// would block forever.
	select {
	case data, ok := <-s.readBuf:
		if !ok {
			return 0, io.EOF
		}
		n = copy(p, data)
		if n < len(data) {
			s.pending = data[n:]
		}
		return n, nil
	case <-s.closeChan:
		// Drain any buffered data already delivered before the close so we don't
		// lose a frame that raced the close signal.
		select {
		case data, ok := <-s.readBuf:
			if ok {
				n = copy(p, data)
				if n < len(data) {
					s.pending = data[n:]
				}
				return n, nil
			}
		default:
		}
		return 0, io.EOF
	}
}

// Write implements io.Writer.
func (s *Stream) Write(p []byte) (n int, err error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, errors.New("stream closed")
	}
	s.mu.Unlock()

	// Send data in chunks if necessary
	const maxChunkSize = 32 * 1024 // 32KB chunks

	for len(p) > 0 {
		chunkSize := len(p)
		if chunkSize > maxChunkSize {
			chunkSize = maxChunkSize
		}

		frame := &Frame{
			Type:     FrameTypeData,
			StreamID: s.id,
			Data:     p[:chunkSize],
		}

		if err := s.manager.sendFrame(frame); err != nil {
			return n, err
		}

		n += chunkSize
		p = p[chunkSize:]
	}

	return n, nil
}

// Close implements io.Closer.
func (s *Stream) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.closeChan) // Signal closure to unblock handleData and parked Read
	s.mu.Unlock()

	s.log.Debugw("Closing stream")

	// Send CLOSE frame
	frame := &Frame{
		Type:     FrameTypeClose,
		StreamID: s.id,
	}

	err := s.manager.sendFrame(frame)
	s.manager.removeStream(s.id)

	return err
}

// SendCloseFrame writes a CLOSE frame for this stream to the peer regardless of
// the local closed flag, then performs the normal local teardown (idempotent).
//
// Why this exists: Stream.Close() short-circuits to a no-op when the stream is
// already marked closed — which happens when the *client* closes its end first
// (an incoming CLOSE handled by handleClose marks the stream closed and removes
// it). On a fast/immediate logout the client closes the shell (and shell-ctl)
// streams toward the agent before the agent's shell goroutine — woken by the
// shell process exiting — reaches Close(). The plain Close() then no-ops and the
// agent never emits ITS CLOSE back toward the client. But the client's output
// reader (io.Copy from the shell stream) only observes EOF when it receives the
// AGENT's CLOSE — the relay does not echo the client's own CLOSE back to it. So
// the client wedges, never transitioning to the webadmin keep-alive.
//
// The shell handler uses SendCloseFrame so the agent's shell-exit CLOSE is
// delivered unconditionally — it is the authoritative "the shell process ended"
// signal the client needs. A duplicate CLOSE (if the agent also sent one via a
// prior Close) is harmless: the client treats CLOSE as EOF idempotently and the
// stream is already removed from the manager.
func (s *Stream) SendCloseFrame() error {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		close(s.closeChan)
	}
	s.mu.Unlock()

	frame := &Frame{
		Type:     FrameTypeClose,
		StreamID: s.id,
	}
	err := s.manager.sendFrame(frame)
	s.manager.removeStream(s.id)

	return err
}

// IsClosed returns true if the stream is closed.
func (s *Stream) IsClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// CloseChan returns a channel that is closed when the stream closes.
// This can be used to cancel operations when the stream ends.
func (s *Stream) CloseChan() <-chan struct{} {
	return s.closeChan
}
