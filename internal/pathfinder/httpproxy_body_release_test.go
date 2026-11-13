package pathfinder

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/logging"
)

// TestHandleStream_TheNextRequestWaitsForTheTransportToLetGoOfTheBody: an
// upstream that answers before reading the request body leaves the transport
// reading that body from the stream after RoundTrip has returned. In a
// read-write session, as in a read-only one, the proxy must not read the next
// request from the stream until the transport has let go of the body (#108,
// #117). Read at once, the next "request" is the rest of the body, and under
// -race the two reads of the stream's reader are a data race. Once the
// transport has closed the body, which reads the rest, the next request is
// where it should be and is served.
func TestHandleStream_TheNextRequestWaitsForTheTransportToLetGoOfTheBody(t *testing.T) {
	const page = "early"
	ts := newEarlyAnswerBackend(t, fmt.Sprintf(
		"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s", len(page), page))
	proxy := newHandleStreamTestProxy(t, ts, false)
	stream, cap := newHandleStreamTestStream()
	done := runHandleStream(proxy, stream)

	// Far larger than the socket buffers: the transport is still writing it,
	// and so still reading the stream, when the answer arrives. With
	// Connection: close net/http's own Close of the body leaves it unread.
	body := strings.Repeat("a", 16<<20)
	first := strings.Replace(rawRequest("POST", "/api/core/firmware/status", "text/plain", body),
		"\r\n", "\r\nConnection: close\r\n", 1)
	stream.readBuf <- []byte(first + rawRequest("GET", "/index.php", "", ""))

	if resp := waitForHandleStreamResponse(t, cap); resp.StatusCode != http.StatusOK {
		t.Fatalf("first status = %d, want the upstream's 200", resp.StatusCode)
	}
	var second *http.Response
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if rest := cap.afterFirstResponse(); len(rest) > 0 {
			if resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(rest)), nil); err == nil {
				second = resp
				break
			}
		}
	}
	if second == nil || second.StatusCode != http.StatusOK {
		t.Fatalf("the request after the body was not served: %v, stream %.300q", second, cap.afterFirstResponse())
	}

	closeHandleStreamTestStream(stream)
	if err := waitHandleStreamDone(t, done); err != nil {
		t.Errorf("HandleStream returned %v: it read the rest of the body as a request", err)
	}
}

// A transport that keeps a request body past the linger gets the stream closed,
// never read: there is no request boundary to read the next request from.
func TestAwaitRelease_ABodyKeptPastTheLingerClosesTheStream(t *testing.T) {
	proxy := &HTTPProxy{replyLinger: 100 * time.Millisecond, log: logging.Named("TEST")}
	stream, cap := newHandleStreamTestStream()
	kept := make(chan struct{})

	start := time.Now()
	if proxy.awaitRelease(stream, kept, true) {
		t.Fatal("a body never let go of was reported released")
	}
	if took := time.Since(start); took < 100*time.Millisecond || took > 2*time.Second {
		t.Errorf("gave up after %v, want the linger", took)
	}
	if !stream.IsClosed() || !cap.closeSent() {
		t.Error("the stream was not closed")
	}

	released := make(chan struct{})
	close(released)
	if !proxy.awaitRelease(stream, released, true) {
		t.Error("a released body was reported kept")
	}
}
