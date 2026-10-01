package pathfinder

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/logging"
)

// newEarlyAnswerBackend stands in for an OPNsense web server that answers a
// request as soon as it has read the request's head, before reading its body,
// and then holds the connection without reading from it, as lighttpd does with
// a request whose head it refuses (431) before the body arrives.
func newEarlyAnswerBackend(t *testing.T, response string) *httptest.Server {
	t.Helper()
	release := make(chan struct{})
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, response)
		select {
		case <-release:
		case <-time.After(30 * time.Second):
		}
	}))
	ts.StartTLS()
	t.Cleanup(func() {
		close(release)
		ts.Close()
	})
	return ts
}

// TestHandleStream_ReadOnlyWithheldResponseLeavesTheBodyToTheTransport: an
// upstream that answers before reading the request body leaves the transport
// reading that body from the stream after RoundTrip has returned, and closing
// it, which reads the rest, once the connection goes. Here the answer is not
// the JSON the route answers with, so the proxy withholds it, and it must not
// read the stream itself until the transport has let go of the body: under
// -race a proxy that starts discarding at once is a data race on the stream's
// reader, and it can corrupt the reader the transport is still using.
func TestHandleStream_ReadOnlyWithheldResponseLeavesTheBodyToTheTransport(t *testing.T) {
	const page = "<html><body>Login SECRET-LEAK</body></html>"
	ts := newEarlyAnswerBackend(t, fmt.Sprintf(
		"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(page), page))
	proxy := newHandleStreamTestProxy(t, ts, true)
	stream, cap := newHandleStreamTestStream()
	done := runHandleStream(proxy, stream)

	const target = "/api/auth/user/search"
	if scrubRuleFor("POST", target) == nil {
		t.Fatalf("precondition: POST %s must be a route whose answer is cleaned", target)
	}
	// Far larger than the socket buffers: the transport is still writing it,
	// and so still reading the stream, when the answer arrives.
	body := "searchPhrase=" + strings.Repeat("a", 16<<20)
	stream.readBuf <- []byte(rawRequest("POST", target, "application/x-www-form-urlencoded", body))

	resp := waitForHandleStreamResponse(t, cap)
	if want := "502 Bad Gateway (read-only session: response withheld)"; resp.Status != want {
		t.Fatalf("status = %q, want %q", resp.Status, want)
	}
	// Give the transport the time to finish with the body, and a read of the
	// stream that does not wait for it the time to show.
	time.Sleep(500 * time.Millisecond)
	if extra := cap.afterFirstResponse(); len(extra) != 0 {
		t.Errorf("the stream carried more than the withheld response: %.200q", extra)
	}
	if bytes.Contains(cap.dataBytes(), []byte("SECRET")) {
		t.Errorf("part of the upstream answer reached the client: %.300q", cap.dataBytes())
	}
	if cap.closeSent() {
		t.Error("the proxy closed the stream right behind the withheld response; the client closes it once it has read the response")
	}

	start := time.Now()
	closeHandleStreamTestStream(stream)
	if err := waitHandleStreamDone(t, done); err != nil {
		t.Errorf("HandleStream returned %v", err)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("HandleStream took %v to return after the client closed the stream", took)
	}
}

// TestEndAfterReply_ReadsNothingUntilTheBodyIsReleased drives endAfterReply with
// a release the test controls. Until the transport lets go of the request body,
// nothing else reads the stream: what the client sends stays queued, and a
// client that keeps sending holds up neither the session's frame loop nor a
// second stream of the same session. Once the body is released, the rest is
// read and discarded, and the client's close ends it.
func TestEndAfterReply_ReadsNothingUntilTheBodyIsReleased(t *testing.T) {
	ts, hits := newSentinelBackend("forwarded")
	defer ts.Close()
	proxy := newHandleStreamTestProxy(t, ts, true)
	proxy.replyLinger = time.Minute

	var mu sync.Mutex
	sent := map[uint32][]*Frame{}
	sm := &StreamManager{streams: make(map[uint32]*Stream), log: logging.Named("test")}
	sm.sendFrameFunc = func(b []byte) error {
		f, err := DecodeFrame(b)
		if err != nil {
			return err
		}
		mu.Lock()
		sent[f.StreamID] = append(sent[f.StreamID], f)
		mu.Unlock()
		return nil
	}
	held := make(chan *Stream, 1)
	served := make(chan error, 1)
	sm.OnNewStream(func(s *Stream) {
		if s.ID() == 1 {
			held <- s
			return
		}
		served <- proxy.HandleStream(s)
	})
	dataOf := func(id uint32) []byte {
		mu.Lock()
		defer mu.Unlock()
		var b bytes.Buffer
		for _, f := range sent[id] {
			if f.Type == FrameTypeData {
				b.Write(f.Data)
			}
		}
		return b.Bytes()
	}
	closeSentFor := func(id uint32) bool {
		mu.Lock()
		defer mu.Unlock()
		for _, f := range sent[id] {
			if f.Type == FrameTypeClose {
				return true
			}
		}
		return false
	}

	sm.handleFrame(EncodeFrame(&Frame{Type: FrameTypeOpen, StreamID: 1, Data: []byte(ServiceWebadmin)}))
	stream := <-held
	released := make(chan struct{})
	ended := make(chan struct{})
	go func() {
		defer close(ended)
		proxy.endAfterReply(stream, bufio.NewReader(stream), released)
	}()

	// The client keeps sending, more frames than the stream's queue holds.
	flooded := make(chan struct{})
	go func() {
		defer close(flooded)
		chunk := bytes.Repeat([]byte("x"), 1024)
		for i := 0; i < cap(stream.readBuf)+64; i++ {
			sm.handleFrame(EncodeFrame(&Frame{Type: FrameTypeData, StreamID: 1, Data: chunk}))
		}
	}()
	select {
	case <-flooded:
	case <-time.After(10 * time.Second):
		t.Fatal("the session's frame loop waited on a stream nothing reads")
	}
	time.Sleep(200 * time.Millisecond)
	if n := len(stream.readBuf); n != cap(stream.readBuf) {
		t.Fatalf("%d of the %d queued frames are left: the stream was read before the transport let go of the body", n, cap(stream.readBuf))
	}

	// A second stream of the same session is served meanwhile.
	sm.handleFrame(EncodeFrame(&Frame{Type: FrameTypeOpen, StreamID: 2, Data: []byte(ServiceWebadmin)}))
	sm.handleFrame(EncodeFrame(&Frame{Type: FrameTypeData, StreamID: 2, Data: []byte("GET /api/core/menu/tree HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")}))
	deadline := time.Now().Add(5 * time.Second)
	var resp *http.Response
	for resp == nil && time.Now().Before(deadline) {
		if r, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(dataOf(2))), nil); err == nil {
			if body, err := io.ReadAll(r.Body); err == nil && string(body) == "forwarded" {
				resp = r
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if resp == nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("the second stream was not served while the first was held: %q", dataOf(2))
	}

	// Released: the rest is read and discarded; the client's close ends it.
	close(released)
	deadline = time.Now().Add(5 * time.Second)
	for len(stream.readBuf) != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := len(stream.readBuf); n != 0 {
		t.Fatalf("%d frames still queued after the release", n)
	}
	select {
	case <-ended:
		t.Fatal("endAfterReply returned before the client closed the stream")
	case <-time.After(100 * time.Millisecond):
	}
	sm.handleFrame(EncodeFrame(&Frame{Type: FrameTypeClose, StreamID: 1}))
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("endAfterReply did not return after the client closed the stream")
	}
	if closeSentFor(1) {
		t.Error("the proxy sent CLOSE for a stream the client closed")
	}

	sm.handleFrame(EncodeFrame(&Frame{Type: FrameTypeClose, StreamID: 2}))
	select {
	case err := <-served:
		if err != nil {
			t.Errorf("HandleStream of the second stream returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the second stream's handler did not return after its client closed it")
	}
	if got := atomic.LoadInt32(hits); got != 1 {
		t.Errorf("OPNsense was reached %d time(s), want 1 (the second stream's request)", got)
	}
}
