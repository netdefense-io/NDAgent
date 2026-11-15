package pathfinder

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"
)

// dataFrames counts the DATA frames the stream carried.
func (c *handleStreamCapture) dataFrames() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, f := range c.frames {
		if f.Type == FrameTypeData {
			n++
		}
	}
	return n
}

// framedExchange is exchangeWith that also reports how many DATA frames the
// response took.
func framedExchange(t *testing.T, readOnly bool, handler http.HandlerFunc, raw string) (*http.Response, string, int) {
	t.Helper()
	ts := httptest.NewTLSServer(handler)
	defer ts.Close()
	proxy := newHandleStreamTestProxy(t, ts, readOnly)
	stream, cap := newHandleStreamTestStream()
	done := runHandleStream(proxy, stream)
	stream.readBuf <- []byte(raw)
	resp := waitForHandleStreamResponse(t, cap)
	body, _ := io.ReadAll(resp.Body)
	time.Sleep(50 * time.Millisecond)
	frames := cap.dataFrames()
	closeHandleStreamTestStream(stream)
	waitHandleStreamDone(t, done)
	return resp, string(body), frames
}

// serveManyHeaders answers with a dozen header lines, as OPNsense's PHP pages
// do, and a body of the given size with its length.
func serveManyHeaders(size int) http.HandlerFunc {
	body := bytes.Repeat([]byte("x"), size)
	return func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		for i := range 12 {
			h.Set(fmt.Sprintf("X-Header-%d", i), "value")
		}
		h.Set("Content-Type", "application/octet-stream")
		h.Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write(body)
	}
}

// resp.Write makes a write for each header line; the head and the start of
// the body leave together, and a long body in frames as full as the stream's
// chunk size.
func TestHandleStream_AResponseLeavesInFewFrames(t *testing.T) {
	tests := []struct {
		name      string
		size      int
		maxFrames int
	}{
		{"a small body", 200, 1},
		{"a body of 100 KiB", 100 * 1024, (100*1024+1024)/responseBufferSize + 1},
	}
	for _, session := range proxySessions {
		for _, tt := range tests {
			t.Run(session.name+"/"+tt.name, func(t *testing.T) {
				resp, body, frames := framedExchange(t, session.readOnly, serveManyHeaders(tt.size), rawGet("/download"))
				if resp.StatusCode != http.StatusOK || len(body) != tt.size || resp.Header.Get("X-Header-11") != "value" {
					t.Fatalf("status %d, %d body bytes, want 200 and %d", resp.StatusCode, len(body), tt.size)
				}
				if frames > tt.maxFrames {
					t.Errorf("the response took %d DATA frames, want at most %d", frames, tt.maxFrames)
				}
			})
		}
	}
}

// A reply the proxy writes itself leaves in one frame too.
func TestHandleStream_ARefusalLeavesInOneFrame(t *testing.T) {
	ts, _ := newSentinelBackend("never")
	defer ts.Close()
	proxy := newHandleStreamTestProxy(t, ts, true)
	stream, cap := newHandleStreamTestStream()
	done := runHandleStream(proxy, stream)
	stream.readBuf <- []byte(rawMethod("POST", "/api/core/service/restart/x"))
	resp := waitForHandleStreamResponse(t, cap)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status %d, want 405", resp.StatusCode)
	}
	if n := cap.dataFrames(); n != 1 {
		t.Errorf("the refusal took %d DATA frames, want 1", n)
	}
	closeHandleStreamTestStream(stream)
	waitHandleStreamDone(t, done)
}

// The head of a response whose body is late is not held for the body: a
// client sees the status while the upstream still works on the rest.
func TestHandleStream_AHeadIsNotHeldForALateBody(t *testing.T) {
	for _, session := range proxySessions {
		t.Run(session.name, func(t *testing.T) {
			release := make(chan struct{})
			releaseBody := sync.OnceFunc(func() { close(release) })
			defer releaseBody()
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				select {
				case <-release:
				case <-r.Context().Done():
					return
				}
				_, _ = io.WriteString(w, "data: late\n\n")
			}))
			defer ts.Close()
			proxy := newHandleStreamTestProxy(t, ts, session.readOnly)
			stream, cap := newHandleStreamTestStream()
			defer closeHandleStreamTestStream(stream)
			done := runHandleStream(proxy, stream)
			stream.readBuf <- []byte(rawGet("/api/diagnostics/traffic/stream"))

			if !waitUntilCaptured(cap, "HTTP/1.1 200") {
				t.Fatal("the head did not arrive while the body was still to come")
			}
			releaseBody()
			if !waitUntilCaptured(cap, "data: late") {
				t.Fatal("the body did not arrive")
			}
			closeHandleStreamTestStream(stream)
			waitHandleStreamDone(t, done)
		})
	}
}

// An upstream that trickles small writes faster than the flush delay still
// gets each one out within that delay, not when the buffer fills.
func TestHandleStream_ATricklingAnswerIsNotHeldInTheBuffer(t *testing.T) {
	finished := make(chan struct{})
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(finished)
		w.Header().Set("Content-Type", "text/event-stream")
		for i := range 100 {
			_, _ = fmt.Fprintf(w, "data: %d\n\n", i)
			w.(http.Flusher).Flush()
			select {
			case <-time.After(5 * time.Millisecond):
			case <-r.Context().Done():
				return
			}
		}
	}))
	defer ts.Close()
	proxy := newHandleStreamTestProxy(t, ts, false)
	stream, cap := newHandleStreamTestStream()
	defer closeHandleStreamTestStream(stream)
	done := runHandleStream(proxy, stream)
	stream.readBuf <- []byte(rawGet("/api/diagnostics/traffic/stream"))

	if !waitUntilCaptured(cap, "data: 3\n") {
		t.Fatal("the first events never arrived")
	}
	select {
	case <-finished:
		t.Error("the first events arrived only after the upstream had sent them all")
	default:
	}
	<-finished
	closeHandleStreamTestStream(stream)
	waitHandleStreamDone(t, done)
}
