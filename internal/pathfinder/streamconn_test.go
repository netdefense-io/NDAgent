package pathfinder

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"testing/iotest"
	"time"
)

var _ FrameConn = (*Client)(nil)
var _ FrameConn = (*StreamConn)(nil)

// frameBytes spells a frame out by hand: type, stream id and data length,
// big endian, then the data. The other end of a session writes exactly this.
func frameBytes(frameType byte, streamID uint32, data string) []byte {
	out := []byte{
		frameType,
		byte(streamID >> 24), byte(streamID >> 16), byte(streamID >> 8), byte(streamID),
		byte(len(data) >> 24), byte(len(data) >> 16), byte(len(data) >> 8), byte(len(data)),
	}
	return append(out, data...)
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

// collect runs conn until its stream ends and returns the frames it handed
// over and what Run returned.
func collect(t *testing.T, r io.Reader) ([][]byte, error) {
	t.Helper()
	conn := NewStreamConn(io.NopCloser(r), nopWriteCloser{io.Discard})
	var frames [][]byte
	conn.OnFrame(func(frame []byte) { frames = append(frames, append([]byte(nil), frame...)) })
	done := make(chan error, 1)
	go func() { done <- conn.Run(context.Background(), nil) }()
	select {
	case err := <-done:
		return frames, err
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return at the end of the stream")
		return nil, nil
	}
}

// Frames follow one another with nothing in between, and arrive whole and in
// order however the stream is cut into reads.
func TestStreamConnFindsFramesInAByteStream(t *testing.T) {
	want := [][]byte{
		frameBytes(0x03, 7, "webadmin"),
		frameBytes(0x01, 7, "GET / HTTP/1.1\r\n\r\n"),
		frameBytes(0x04, 7, ""),
		frameBytes(0x01, 0xfffffffe, string(bytes.Repeat([]byte{0xab}, 65536))),
		frameBytes(0x02, 7, ""),
	}
	stream := bytes.Join(want, nil)

	// The first frame, byte for byte: one byte of type, the stream id and
	// the data length as four big-endian bytes each, then the data.
	if !bytes.Equal(want[0], []byte{0x03, 0, 0, 0, 7, 0, 0, 0, 8, 'w', 'e', 'b', 'a', 'd', 'm', 'i', 'n'}) {
		t.Fatalf("the hand-built frame is %x", want[0])
	}
	if !bytes.Equal(want[0], EncodeFrame(&Frame{Type: FrameTypeOpen, StreamID: 7, Data: []byte("webadmin")})) {
		t.Fatal("EncodeFrame no longer writes the frame the other end reads")
	}

	for name, r := range map[string]io.Reader{
		"all at once":        bytes.NewReader(stream),
		"one byte at a time": iotest.OneByteReader(bytes.NewReader(stream)),
		"in halves":          iotest.HalfReader(bytes.NewReader(stream)),
		"with empty reads":   iotest.DataErrReader(bytes.NewReader(stream)),
	} {
		got, err := collect(t, r)
		if err != nil {
			t.Errorf("%s: Run = %v, want nil at the end of the stream", name, err)
		}
		if len(got) != len(want) {
			t.Errorf("%s: %d frames, want %d", name, len(got), len(want))
			continue
		}
		for i := range want {
			if !bytes.Equal(got[i], want[i]) {
				t.Errorf("%s: frame %d differs (%d bytes, want %d)", name, i, len(got[i]), len(want[i]))
			}
		}
	}
}

func TestStreamConnTellsAStreamCutInsideAFrame(t *testing.T) {
	whole := frameBytes(0x01, 1, "0123456789")
	cases := map[string][]byte{
		"inside the header":    whole[:5],
		"right after a header": whole[:9],
		"inside the data":      whole[:14],
		"after a whole frame":  append(append([]byte{}, whole...), whole[:3]...),
	}
	for name, stream := range cases {
		_, err := collect(t, bytes.NewReader(stream))
		if !errors.Is(err, ErrFrameTruncated) {
			t.Errorf("%s: Run = %v, want ErrFrameTruncated", name, err)
		}
	}
	if _, err := collect(t, bytes.NewReader(nil)); err != nil {
		t.Errorf("an empty stream: Run = %v, want nil", err)
	}
}

// A header that announces more than a frame may hold ends the connection:
// what follows cannot be read as frames, and the announced size is never
// allocated. The bound is 65,536 bytes of data, not the relay's.
func TestStreamConnRefusesAFrameOverTheLimit(t *testing.T) {
	header := []byte{0x01, 0, 0, 0, 1, 0x00, 0x01, 0x00, 0x01} // 65,537
	frames, err := collect(t, io.MultiReader(bytes.NewReader(header), neverEnds{}))
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("Run = %v, want ErrFrameTooLarge", err)
	}
	if len(frames) != 0 {
		t.Errorf("%d frames handed over", len(frames))
	}

	atLimit := []byte{0x01, 0, 0, 0, 1, 0x00, 0x01, 0x00, 0x00} // exactly 65,536, then nothing
	if _, err := collect(t, bytes.NewReader(atLimit)); !errors.Is(err, ErrFrameTruncated) {
		t.Errorf("a frame of exactly the limit, cut short: Run = %v, want ErrFrameTruncated", err)
	}
}

// A sender never exceeds the bound: the frame is refused, nothing of it is
// written, and the connection stays usable.
func TestStreamConnDoesNotSendAFrameOverTheLimit(t *testing.T) {
	conn, _, fromConn := osPipes(t)
	tooLarge := frameBytes(0x01, 1, string(make([]byte, 65537)))
	if err := conn.SendFrame(tooLarge); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("SendFrame of 65,537 bytes of data = %v, want ErrFrameTooLarge", err)
	}
	if err := conn.SendFrame([]byte{0x01, 0, 0}); err == nil {
		t.Error("SendFrame took three bytes for a frame")
	}
	// A header that announces other than what follows would have the other
	// end look for the next frame in the wrong place.
	for name, frame := range map[string][]byte{
		"more announced than carried": {0x01, 0, 0, 0, 1, 0, 0, 0, 5, 'a', 'b'},
		"less announced than carried": {0x01, 0, 0, 0, 1, 0, 0, 0, 1, 'a', 'b'},
		"data without a length":       {0x01, 0, 0, 0, 1, 0, 0, 0, 0, 'a'},
	} {
		if err := conn.SendFrame(frame); err == nil {
			t.Errorf("%s: SendFrame took it", name)
		}
	}
	go func() {
		// The largest frame allowed does not fit a pipe in one go: read
		// along.
		if err := conn.SendFrame(frameBytes(0x01, 1, string(make([]byte, 65536)))); err != nil {
			t.Errorf("SendFrame of exactly 65,536 bytes of data: %v", err)
		}
		conn.Close()
	}()
	fromConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	got, err := io.ReadAll(fromConn)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 9+65536 {
		t.Errorf("%d bytes reached the other end, want one frame of 9+65536 and nothing of the refused ones", len(got))
	}
}

type neverEnds struct{}

func (neverEnds) Read(p []byte) (int, error) { return len(p), nil }

// osPipes is a StreamConn over real pipes, with the other end of each.
func osPipes(t *testing.T) (conn *StreamConn, toConn *os.File, fromConn *os.File) {
	t.Helper()
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		inR.Close()
		inW.Close()
		outR.Close()
		outW.Close()
	})
	conn = NewStreamConn(inR, outW)
	// Most tests leave the other end open when the connection ends: they
	// are not about how long its reading side then waits for it.
	conn.closeGrace = 200 * time.Millisecond
	return conn, inW, outR
}

// Frames sent from many goroutines never interleave: the other end finds
// every one of them whole.
func TestStreamConnWritesOneFrameAtATime(t *testing.T) {
	conn, _, fromConn := osPipes(t)

	const senders, each = 40, 25
	var wg sync.WaitGroup
	for s := 0; s < senders; s++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			data := string(bytes.Repeat([]byte{byte(s)}, 300+s*61))
			for i := 0; i < each; i++ {
				if err := conn.SendFrame(frameBytes(0x01, uint32(s), data)); err != nil {
					t.Errorf("SendFrame: %v", err)
					return
				}
			}
		}()
	}
	go func() {
		wg.Wait()
		conn.Close()
	}()

	// Read the stream back as frames with a second StreamConn.
	reader := NewStreamConn(fromConn, nopWriteCloser{io.Discard})
	count := make(map[uint32]int)
	reader.OnFrame(func(raw []byte) {
		frame, err := DecodeFrame(raw)
		if err != nil {
			t.Errorf("a frame the reader cannot decode: %v", err)
			return
		}
		want := bytes.Repeat([]byte{byte(frame.StreamID)}, 300+int(frame.StreamID)*61)
		if !bytes.Equal(frame.Data, want) {
			t.Errorf("stream %d: a frame of %d bytes that is not what was sent", frame.StreamID, len(frame.Data))
		}
		count[frame.StreamID]++
	})
	if err := reader.Run(context.Background(), nil); err != nil {
		t.Fatalf("reading the frames back: %v", err)
	}
	for s := 0; s < senders; s++ {
		if count[uint32(s)] != each {
			t.Errorf("sender %d: %d frames arrived, want %d", s, count[uint32(s)], each)
		}
	}
}

// A peer that stops reading must end the session, as a relay write that
// times out does: the frame may be written in part, and nothing after it can
// be found by the other end.
func TestStreamConnEndsWhenTheOtherEndStopsReading(t *testing.T) {
	conn, _, _ := osPipes(t)
	conn.writeTimeout = 200 * time.Millisecond

	runDone := make(chan error, 1)
	go func() { runDone <- conn.Run(context.Background(), nil) }()

	// Nobody reads the other end: the pipe fills, then a write stalls.
	frame := frameBytes(0x01, 1, string(make([]byte, 32<<10)))
	sent := make(chan error, 1)
	go func() {
		var err error
		for i := 0; i < 64 && err == nil; i++ {
			err = conn.SendFrame(frame)
		}
		sent <- err
	}()
	select {
	case err := <-sent:
		if !errors.Is(err, ErrWriteStalled) {
			t.Fatalf("SendFrame into a full pipe = %v, want ErrWriteStalled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SendFrame is still waiting on a full pipe after 5 s, with a write timeout of 200 ms")
	}
	select {
	case err := <-runDone:
		if !errors.Is(err, ErrWriteStalled) {
			t.Errorf("Run = %v, want ErrWriteStalled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after the write stalled")
	}
	if err := conn.SendFrame(frame); err == nil {
		t.Error("SendFrame succeeded on a connection that has ended")
	}
}

// The write timeout is the relay's: ten seconds for a frame.
func TestStreamConnWriteTimeoutIsTenSeconds(t *testing.T) {
	conn, _, _ := osPipes(t)
	if conn.writeTimeout != 10*time.Second {
		t.Errorf("write timeout = %v, want 10s", conn.writeTimeout)
	}
}

func TestStreamConnRunEndsWithItsContextAndOnClose(t *testing.T) {
	t.Run("context", func(t *testing.T) {
		conn, toConn, _ := osPipes(t)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- conn.Run(ctx, nil) }()
		time.Sleep(50 * time.Millisecond)
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("Run = %v, want context.Canceled", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Run did not return when its context ended")
		}
		if _, err := toConn.Write([]byte("x")); err == nil {
			t.Error("the read end is still open after Run returned")
		}
	})

	t.Run("Close", func(t *testing.T) {
		conn, _, fromConn := osPipes(t)
		done := make(chan error, 1)
		go func() { done <- conn.Run(context.Background(), nil) }()
		time.Sleep(50 * time.Millisecond)
		conn.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run = %v after Close, want nil", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Run did not return after Close")
		}
		if n, err := fromConn.Read(make([]byte, 1)); n != 0 || err != io.EOF {
			t.Errorf("the other end read %d, %v after Close; want the end of the stream", n, err)
		}
	})

	t.Run("the other end closing", func(t *testing.T) {
		conn, toConn, _ := osPipes(t)
		done := make(chan error, 1)
		go func() { done <- conn.Run(context.Background(), nil) }()
		if _, err := toConn.Write(frameBytes(0x01, 1, "last")); err != nil {
			t.Fatal(err)
		}
		toConn.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run = %v, want nil: the stream ended between frames", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Run did not return when the other end closed")
		}
	})
}

// The numbers both ends of a session rely on, spelled out.
func TestStreamConnRulesAreTheAgreedOnes(t *testing.T) {
	conn, _, _ := osPipes(t)
	if StreamFrameMaxData != 65536 {
		t.Errorf("frame bound = %d, want 65536", StreamFrameMaxData)
	}
	if conn.keepAliveInterval != 20*time.Second || conn.receiveTimeout != 60*time.Second {
		t.Errorf("keepalive every %v, receive timeout %v; want 20s and 60s", conn.keepAliveInterval, conn.receiveTimeout)
	}
	if fresh := NewStreamConn(io.NopCloser(bytes.NewReader(nil)), nopWriteCloser{io.Discard}); fresh.closeGrace != 6*time.Second {
		t.Errorf("the reading side waits %v for the other end to close, want 6s", fresh.closeGrace)
	}
	if FrameTypeKeepAlive != 0x05 {
		t.Errorf("KeepAlive frame type = %#x, want 0x05", FrameTypeKeepAlive)
	}
}

// keepAliveBytes is a KeepAlive frame as the other end writes it: type 0x05,
// stream 0, no data.
var keepAliveBytes = []byte{0x05, 0, 0, 0, 0, 0, 0, 0, 0}

// readFrames reads whole frames from r into a channel until r ends.
func readFrames(r io.Reader) <-chan []byte {
	frames := make(chan []byte, 256)
	go func() {
		defer close(frames)
		for {
			header := make([]byte, 9)
			if _, err := io.ReadFull(r, header); err != nil {
				return
			}
			data := make([]byte, int(header[5])<<24|int(header[6])<<16|int(header[7])<<8|int(header[8]))
			if _, err := io.ReadFull(r, data); err != nil {
				return
			}
			frames <- append(header, data...)
		}
	}()
	return frames
}

// Once the peer is connected, an end that has sent nothing for the keepalive
// interval sends a KeepAlive frame, and only then.
func TestStreamConnSendsKeepAlivesWhenItHasNothingToSay(t *testing.T) {
	conn, toConn, fromConn := osPipes(t)
	conn.keepAliveInterval = 100 * time.Millisecond
	conn.receiveTimeout = time.Hour
	connected := make(chan struct{})
	go conn.Run(context.Background(), connected)
	frames := readFrames(fromConn)
	defer toConn.Close()

	// Not before the peer is there.
	select {
	case frame := <-frames:
		t.Fatalf("a frame (%x) was sent before the peer connected", frame)
	case <-time.After(350 * time.Millisecond):
	}

	close(connected)
	began := time.Now()
	for i := 0; i < 3; i++ {
		select {
		case frame := <-frames:
			if !bytes.Equal(frame, keepAliveBytes) {
				t.Fatalf("frame %d = %x, want a KeepAlive %x", i, frame, keepAliveBytes)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("no KeepAlive %d within 5 s of the peer connecting", i+1)
		}
	}
	if elapsed := time.Since(began); elapsed < 250*time.Millisecond {
		t.Errorf("three KeepAlives in %v with an interval of 100 ms", elapsed)
	}

}

// An end that keeps sending needs no KeepAlive: here a frame every 50 ms
// against an interval of two seconds.
func TestStreamConnSendsNoKeepAliveWhileItIsSending(t *testing.T) {
	conn, toConn, fromConn := osPipes(t)
	conn.keepAliveInterval = 2 * time.Second
	conn.receiveTimeout = time.Hour
	go conn.Run(context.Background(), nil)
	frames := readFrames(fromConn)
	defer toConn.Close()

	busy := frameBytes(0x01, 4, "busy")
	stop := time.Now().Add(3 * time.Second)
	sent := 0
	for time.Now().Before(stop) {
		if err := conn.SendFrame(busy); err != nil {
			t.Fatal(err)
		}
		sent++
		time.Sleep(50 * time.Millisecond)
	}
	for i := 0; i < sent; i++ {
		select {
		case frame := <-frames:
			if !bytes.Equal(frame, busy) {
				t.Fatalf("frame %d of %d = %x: an end that sent a frame every 50 ms sent something else", i+1, sent, frame)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("only %d of %d frames arrived", i, sent)
		}
	}
}

// Nothing else tells this end that the other one died: an end that receives
// no frame at all for the receive timeout ends the session.
func TestStreamConnEndsWhenThePeerGoesSilent(t *testing.T) {
	t.Run("a connected peer that says nothing", func(t *testing.T) {
		conn, toConn, fromConn := osPipes(t)
		defer toConn.Close()
		go io.Copy(io.Discard, fromConn)
		conn.keepAliveInterval = 50 * time.Millisecond
		conn.receiveTimeout = 300 * time.Millisecond
		connected := make(chan struct{})
		done := make(chan error, 1)
		go func() { done <- conn.Run(context.Background(), connected) }()

		// The clock starts when the peer connects, not before.
		select {
		case err := <-done:
			t.Fatalf("Run = %v while no peer has connected yet", err)
		case <-time.After(600 * time.Millisecond):
		}
		close(connected)
		began := time.Now()
		select {
		case err := <-done:
			if !errors.Is(err, ErrPeerSilent) {
				t.Errorf("Run = %v, want ErrPeerSilent", err)
			}
			if elapsed := time.Since(began); elapsed < 250*time.Millisecond {
				t.Errorf("the silent peer was given up on after %v, before the 300 ms it has", elapsed)
			}
		case <-time.After(20 * time.Second):
			t.Fatal("Run did not end for a peer that never sent a frame")
		}
	})

	t.Run("a peer that sends only KeepAlives stays, and is idle", func(t *testing.T) {
		// A KeepAlive every 100 ms against a receive timeout of two
		// seconds: wide apart, so a slow machine does not make the peer
		// look silent between two of them.
		conn, toConn, fromConn := osPipes(t)
		go io.Copy(io.Discard, fromConn)
		conn.keepAliveInterval = 50 * time.Millisecond
		conn.receiveTimeout = 2 * time.Second
		handed := make(chan []byte, 16)
		conn.OnFrame(func(frame []byte) { handed <- append([]byte(nil), frame...) })
		done := make(chan error, 1)
		go func() { done <- conn.Run(context.Background(), nil) }()

		if _, err := toConn.Write(frameBytes(0x01, 1, "work")); err != nil {
			t.Fatal(err)
		}
		<-handed
		active := conn.LastActivity()
		if active.IsZero() {
			t.Fatal("LastActivity is zero after a data frame")
		}

		stop := time.Now().Add(3500 * time.Millisecond)
		for time.Now().Before(stop) {
			if _, err := toConn.Write(keepAliveBytes); err != nil {
				t.Fatalf("writing a KeepAlive: %v", err)
			}
			time.Sleep(100 * time.Millisecond)
		}
		select {
		case err := <-done:
			t.Fatalf("Run = %v for a peer that sent a KeepAlive every 100 ms for 3.5 s, with a receive timeout of 2 s", err)
		default:
		}
		select {
		case frame := <-handed:
			t.Errorf("a KeepAlive frame was handed to the session's handler: %x", frame)
		default:
		}
		if !conn.LastActivity().Equal(active) {
			t.Errorf("KeepAlive frames moved LastActivity from %v to %v: they are not activity", active, conn.LastActivity())
		}

		// Then the peer stops.
		select {
		case err := <-done:
			if !errors.Is(err, ErrPeerSilent) {
				t.Errorf("Run = %v, want ErrPeerSilent", err)
			}
		case <-time.After(20 * time.Second):
			t.Fatal("Run did not end after the KeepAlives stopped")
		}
	})
}

// Idle time is counted from the last frame, in either direction, that is not
// a KeepAlive.
func TestStreamConnLastActivityMovesWithFramesBothWays(t *testing.T) {
	conn, toConn, fromConn := osPipes(t)
	conn.keepAliveInterval = 30 * time.Millisecond
	if !conn.LastActivity().IsZero() {
		t.Errorf("LastActivity = %v before any frame", conn.LastActivity())
	}
	received := make(chan struct{}, 1)
	conn.OnFrame(func([]byte) { received <- struct{}{} })
	go conn.Run(context.Background(), nil)
	go io.Copy(io.Discard, fromConn)

	// Its own KeepAlives are not activity either.
	time.Sleep(150 * time.Millisecond)
	if !conn.LastActivity().IsZero() {
		t.Errorf("LastActivity = %v after only KeepAlives were sent", conn.LastActivity())
	}

	before := time.Now()
	if _, err := toConn.Write(frameBytes(0x01, 1, "in")); err != nil {
		t.Fatal(err)
	}
	<-received
	afterRead := conn.LastActivity()
	if afterRead.Before(before) {
		t.Errorf("LastActivity = %v after a frame was read at %v", afterRead, before)
	}

	time.Sleep(20 * time.Millisecond)
	if err := conn.SendFrame(frameBytes(0x01, 1, "out")); err != nil {
		t.Fatal(err)
	}
	if !conn.LastActivity().After(afterRead) {
		t.Errorf("LastActivity did not move when a frame was written")
	}
}

// The stream manager works over a StreamConn as it does over the relay: an
// OPEN that arrives on the stream reaches the new-stream handler, the ACK and
// the stream's data go back out as frames.
func TestStreamManagerOverAStreamConn(t *testing.T) {
	conn, toConn, fromConn := osPipes(t)
	mgr := NewStreamManager(conn)
	mgr.OnNewStream(func(stream *Stream) {
		buf := make([]byte, 5)
		if _, err := io.ReadFull(stream, buf); err != nil {
			t.Errorf("reading the stream: %v", err)
			return
		}
		stream.Write([]byte(stream.ServiceName() + " got " + string(buf)))
		stream.Close()
	})
	go conn.Run(context.Background(), nil)

	// A frame of a type this end does not know is read and ignored: what
	// follows it is still found.
	stream := bytes.Join([][]byte{
		frameBytes(0x7f, 3, "from a newer peer"),
		frameBytes(0x03, 9, "exec"),
		keepAliveBytes,
		frameBytes(0x01, 9, "hello"),
	}, nil)
	if _, err := toConn.Write(stream); err != nil {
		t.Fatal(err)
	}

	want := bytes.Join([][]byte{
		frameBytes(0x04, 9, ""),
		frameBytes(0x01, 9, "exec got hello"),
		frameBytes(0x02, 9, ""),
	}, nil)
	got := make([]byte, len(want))
	fromConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(fromConn, got); err != nil {
		t.Fatalf("reading the answer: %v (got %x)", err, got)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("answer = %x\nwant     %x", got, want)
	}
}

// Ending the connection closes its writing side at once and keeps reading:
// the other end, told by that close that the session is over, may still be
// writing, and its writes must not fail while it finishes in order. What it
// writes is dropped, and Run returns when it has closed its side.
func TestStreamConnKeepsReadingUntilTheOtherEndHasClosed(t *testing.T) {
	conn, toConn, fromConn := osPipes(t)
	conn.closeGrace = 30 * time.Second
	handed := make(chan []byte, 8)
	conn.OnFrame(func(frame []byte) { handed <- append([]byte(nil), frame...) })
	done := make(chan error, 1)
	go func() { done <- conn.Run(context.Background(), nil) }()

	if _, err := toConn.Write(frameBytes(0x01, 1, "before")); err != nil {
		t.Fatal(err)
	}
	<-handed
	conn.Close()

	// The writing side is closed now.
	_ = fromConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := fromConn.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("the other end read %d, %v after Close; want the end of the stream at once", n, err)
	}
	if err := conn.SendFrame(frameBytes(0x01, 1, "late")); err == nil {
		t.Error("SendFrame succeeded after Close")
	}

	// The reading side is not: the other end can still write.
	for i := 0; i < 20; i++ {
		if _, err := toConn.Write(frameBytes(0x01, 1, "after")); err != nil {
			t.Fatalf("the other end's write %d failed after Close: %v", i+1, err)
		}
	}
	select {
	case err := <-done:
		t.Fatalf("Run = %v while the other end is still writing", err)
	case frame := <-handed:
		t.Fatalf("a frame that arrived after Close was handed on: %x", frame)
	case <-time.After(300 * time.Millisecond):
	}

	toConn.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run = %v, want nil after Close", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return when the other end closed its side")
	}
}

// An other end that never closes its side does not hold Run for ever.
func TestStreamConnGivesUpOnAnOtherEndThatDoesNotClose(t *testing.T) {
	conn, toConn, _ := osPipes(t)
	conn.closeGrace = 300 * time.Millisecond
	done := make(chan error, 1)
	go func() { done <- conn.Run(context.Background(), nil) }()
	time.Sleep(50 * time.Millisecond)
	began := time.Now()
	conn.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run = %v, want nil after Close", err)
		}
		if waited := time.Since(began); waited < 250*time.Millisecond {
			t.Errorf("Run returned %v after Close, before the other end had its 300 ms", waited)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after the grace period")
	}
	if _, err := toConn.Write([]byte("x")); err == nil {
		t.Error("the reading side is still open after Run returned")
	}
}

// slowCloser closes as an *os.File does when a read is blocked on it: the
// first Close wakes the read at once and finishes closing a moment later,
// and a second Close in between returns at once, without waiting for it.
type slowCloser struct {
	closing   chan struct{}
	startOnce sync.Once
	closed    chan struct{}
}

func newSlowCloser() *slowCloser {
	return &slowCloser{closing: make(chan struct{}), closed: make(chan struct{})}
}

func (s *slowCloser) Read([]byte) (int, error) {
	<-s.closing
	return 0, os.ErrClosed
}

func (s *slowCloser) Close() error {
	first := false
	s.startOnce.Do(func() { first = true })
	if !first {
		return os.ErrClosed
	}
	close(s.closing)
	time.Sleep(100 * time.Millisecond)
	close(s.closed)
	return nil
}

// Run returns only once the reading side is closed, also when the grace
// period's close is still under way as the read it woke returns.
func TestStreamConnRunReturnsOnlyOnceTheReadingSideIsClosed(t *testing.T) {
	for name, end := range map[string]func(*StreamConn, context.CancelFunc){
		"Close":   func(c *StreamConn, _ context.CancelFunc) { c.Close() },
		"context": func(_ *StreamConn, cancel context.CancelFunc) { cancel() },
	} {
		t.Run(name, func(t *testing.T) {
			r := newSlowCloser()
			conn := NewStreamConn(r, nopWriteCloser{io.Discard})
			conn.closeGrace = 10 * time.Millisecond
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- conn.Run(ctx, nil) }()
			end(conn, cancel)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("Run did not return after the grace period")
			}
			select {
			case <-r.closed:
			default:
				t.Error("Run returned while the reading side was still being closed")
			}
		})
	}
}
