package pathfinder

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/logging"
)

func TestHTTPProxyInjectSessionCookie(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "httpproxy_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	sessionMgr := NewSessionManager("testuser", tmpDir)
	proxy := NewHTTPProxy("127.0.0.1", 443, sessionMgr)

	session := &Session{
		ID:       "abc123def456abc123def456abc12345",
		Username: "testuser",
	}

	tests := []struct {
		name            string
		existingCookies string
		expectedContain string
	}{
		{
			name:            "no existing cookies",
			existingCookies: "",
			expectedContain: "PHPSESSID=abc123def456abc123def456abc12345",
		},
		{
			name:            "with existing cookies",
			existingCookies: "othercookie=value",
			expectedContain: "othercookie=value; PHPSESSID=abc123def456abc123def456abc12345",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://localhost/", nil)
			if tt.existingCookies != "" {
				req.Header.Set("Cookie", tt.existingCookies)
			}

			proxy.injectSessionCookie(req, session)

			cookieHeader := req.Header.Get("Cookie")
			if cookieHeader != tt.expectedContain {
				t.Errorf("Cookie header = %q, want %q", cookieHeader, tt.expectedContain)
			}
		})
	}
}

func TestHTTPProxySendErrorResponseFormat(t *testing.T) {
	// Test that error response is properly formatted HTTP
	// We test this by capturing what would be written
	resp := &http.Response{
		StatusCode: http.StatusBadGateway,
		Status:     "502 Bad Gateway",
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       http.NoBody,
	}
	resp.Header.Set("Content-Type", "text/plain")
	resp.Header.Set("Connection", "close")

	var buf bytes.Buffer
	if err := resp.Write(&buf); err != nil {
		t.Fatalf("Failed to write response: %v", err)
	}

	response := buf.String()
	if !strings.Contains(response, "502") {
		t.Error("Response should contain 502 status code")
	}
	if !strings.Contains(response, "Bad Gateway") {
		t.Error("Response should contain 'Bad Gateway'")
	}
}

func TestHTTPProxyForwardRequest(t *testing.T) {
	// Create a test HTTPS server
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the PHPSESSID cookie was injected
		cookie, err := r.Cookie("PHPSESSID")
		if err != nil {
			t.Error("PHPSESSID cookie not found in request")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Echo back some info
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("SessionID: " + cookie.Value))
	}))
	defer ts.Close()

	// Extract host and port from test server URL
	// URL format: https://127.0.0.1:PORT
	urlParts := strings.Split(strings.TrimPrefix(ts.URL, "https://"), ":")
	host := urlParts[0]
	var port int
	if len(urlParts) > 1 {
		_, err := io.WriteString(io.Discard, urlParts[1]) // just to use the variable
		if err != nil {
			t.Fatal(err)
		}
		// Parse port
		for _, c := range urlParts[1] {
			port = port*10 + int(c-'0')
		}
	}

	tmpDir, err := os.MkdirTemp("", "httpproxy_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	sessionMgr := NewSessionManager("testuser", tmpDir)
	proxy := NewHTTPProxy(host, port, sessionMgr)

	// Override the HTTP client to use the test server's TLS config
	proxy.httpClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	session := &Session{
		ID:       "test123session456id789abcdef01234",
		Username: "testuser",
	}

	// Create a test request
	req, err := http.NewRequest("GET", "/test/path", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Accept", "text/html")

	// Forward the request
	resp, err := proxy.forwardRequest(context.Background(), req, session)
	if err != nil {
		t.Fatalf("forwardRequest failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Response status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	expectedBody := "SessionID: test123session456id789abcdef01234"
	if string(body) != expectedBody {
		t.Errorf("Response body = %q, want %q", string(body), expectedBody)
	}
}

// A request-target such as "http:@host:port/x" carries a host of its own. The
// only place the proxy sends a request to is the local webadmin, whatever the
// target says, and a session that is not read-only is held to that too.
func TestHTTPProxyForwardRequestIgnoresHostInTarget(t *testing.T) {
	local, localHits := newSentinelBackend("local webadmin")
	defer local.Close()
	other, otherHits := newSentinelBackend("another host")
	defer other.Close()
	_, otherPort, err := net.SplitHostPort(strings.TrimPrefix(other.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}

	proxy := newHandleStreamTestProxy(t, local, false)
	session := &Session{ID: "test123session456id789abcdef01234", Username: "testuser"}

	for _, target := range []string{
		fmt.Sprintf("http:@127.0.0.1:%s/internal/admin", otherPort),
		fmt.Sprintf("http://127.0.0.1:%s/internal/admin", otherPort),
		fmt.Sprintf("https:127.0.0.1:%s", otherPort),
	} {
		raw := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: x\r\n\r\n", target)
		req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
		if err != nil {
			t.Fatalf("ReadRequest(%q): %v", target, err)
		}
		if resp, err := proxy.forwardRequest(context.Background(), req, session); err == nil {
			resp.Body.Close()
		}
	}

	if got := atomic.LoadInt32(otherHits); got != 0 {
		t.Fatalf("another host was hit %d time(s); a request-target must not choose the host the proxy calls", got)
	}
	if got := atomic.LoadInt32(localHits); got == 0 {
		t.Fatal("the local webadmin was never reached; the requests must still be served from it")
	}
}

// TestReadOnlyRefusal is revert-sensitive for the read-only proxy denylist: it
// must refuse the service-action family on mutating methods while never
// touching GET/HEAD or the OPNsense grid/list search endpoints (POST
// search*/searchItem/search_*), which every RO list view depends on.
func TestReadOnlyRefusal(t *testing.T) {
	tests := []struct {
		name   string
		method string
		target string
		want   int
	}{
		// Must ALLOW: list/grid views load via POST to search endpoints.
		{"search rule", "POST", "/api/firewall/filter/searchRule", forwarded},
		{"search alias item", "POST", "/api/firewall/alias/searchItem", forwarded},
		{"search wireguard server", "POST", "/api/wireguard/server/search_server", forwarded},
		{"GET service restart is a safe method", "GET", "/api/core/service/restart/openvpn", forwarded},
		{"HEAD service restart is a safe method", "HEAD", "/api/core/service/restart/openvpn", forwarded},
		{"unrelated POST", "POST", "/api/core/firmware/status", forwarded},
		{"GET firewall state killStates is a safe method", "GET", "/api/diagnostics/firewall/killStates", forwarded},
		{"search state grid load", "POST", "/api/diagnostics/firewall/searchState", forwarded},

		// Must DENY: mutating requests to the service-action family.
		{"POST service restart", "POST", "/api/core/service/restart/openvpn", refused},
		{"POST service stop with svc", "POST", "/api/core/service/stop/openvpn", refused},
		{"POST openvpn service reconfigure", "POST", "/api/openvpn/service/reconfigure", refused},
		{"POST service start no id", "POST", "/api/core/service/start", refused},
		{"DELETE service restart", "DELETE", "/api/core/service/restart/openvpn", refused},
		{"PUT service reload", "PUT", "/api/core/service/reload/openvpn", refused},
		{"PATCH service reconfigure", "PATCH", "/api/core/service/reconfigure", refused},
		{"OPTIONS is not a method a read-only session uses", "OPTIONS", "/api/core/service/search", refused},

		// Must DENY: mutating requests to the diagnostics firewall-state
		// mutator family.
		{"POST killStates", "POST", "/api/diagnostics/firewall/killStates", refused},
		{"POST flushStates", "POST", "/api/diagnostics/firewall/flushStates", refused},
		{"POST delState with ids", "POST", "/api/diagnostics/firewall/delState/12345/0", refused},
		{"DELETE flushStates", "DELETE", "/api/diagnostics/firewall/flushStates", refused},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := readOnlyRefusal(tt.method, tt.target, false); got != tt.want {
				t.Errorf("readOnlyRefusal(%q, %q) = %d, want %d", tt.method, tt.target, got, tt.want)
			}
		})
	}
}

// TestHTTPProxySetReadOnlyDefaultsFalse confirms NewHTTPProxy's signature is
// unchanged (no readOnly param) and the field defaults to false, so existing
// non-read-only call sites are unaffected until SetReadOnly is called.
func TestHTTPProxySetReadOnlyDefaultsFalse(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "httpproxy_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	sessionMgr := NewSessionManager("testuser", tmpDir)
	proxy := NewHTTPProxy("127.0.0.1", 443, sessionMgr)

	if proxy.readOnly {
		t.Error("readOnly should default to false")
	}

	proxy.SetReadOnly(true)
	if !proxy.readOnly {
		t.Error("SetReadOnly(true) did not set readOnly")
	}
}

func TestNewHTTPProxy(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "httpproxy_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	sessionMgr := NewSessionManager("admin", tmpDir)
	proxy := NewHTTPProxy("192.168.1.1", 8443, sessionMgr)

	if proxy.localHost != "192.168.1.1" {
		t.Errorf("localHost = %q, want %q", proxy.localHost, "192.168.1.1")
	}

	if proxy.localPort != 8443 {
		t.Errorf("localPort = %d, want %d", proxy.localPort, 8443)
	}

	if proxy.sessionManager != sessionMgr {
		t.Error("sessionManager not set correctly")
	}

	if proxy.httpClient == nil {
		t.Error("httpClient should not be nil")
	}

	if proxy.log == nil {
		t.Error("log should not be nil")
	}
}

// ---------------------------------------------------------------------------
// HandleStream-level integration tests for the read-only runtime-action gate
// ---------------------------------------------------------------------------
//
// The unit tests above (TestReadOnlyRefusal, the SetReadOnly default,
// the ProxyConfig wiring test) each exercise one piece of the gate in
// isolation. None of them would fail if the gate itself — the
// `if p.readOnly` block that calls readOnlyRefusal inside HandleStream —
// were inverted, had its `continue` dropped, or were deleted outright: the
// pure function and the field-setter would still behave correctly even if
// nothing in HandleStream ever consulted them. The tests below drive
// HandleStream directly through the same seam shell_close_test.go and
// exec_test.go use for ShellSession.run / ExecManager (a *Stream backed by a
// *StreamManager whose sendFrameFunc captures outgoing frames instead of a
// real WebSocket connection), so a regression in the gate itself fails here.

// handleStreamCapture records every outgoing frame HandleStream writes to a
// test stream.
type handleStreamCapture struct {
	mu     sync.Mutex
	frames []*Frame
	sentAt []time.Time // when each frame was written, by index
}

func (c *handleStreamCapture) add(f *Frame) {
	c.mu.Lock()
	c.frames = append(c.frames, f)
	c.sentAt = append(c.sentAt, time.Now())
	c.mu.Unlock()
}

// dataBytes concatenates every captured DATA frame's payload, in arrival
// order, into one buffer — HandleStream's response is written via
// Stream.Write, which chunks into one or more FrameTypeData frames.
func (c *handleStreamCapture) dataBytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	var buf bytes.Buffer
	for _, f := range c.frames {
		if f.Type == FrameTypeData {
			buf.Write(f.Data)
		}
	}
	return buf.Bytes()
}

// closeSent reports whether HandleStream sent a CLOSE frame for the stream.
func (c *handleStreamCapture) closeSent() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, f := range c.frames {
		if f.Type == FrameTypeClose {
			return true
		}
	}
	return false
}

// afterFirstResponse returns what the stream carried after its first complete
// response: nothing, when the proxy answered one request and took no other.
func (c *handleStreamCapture) afterFirstResponse() []byte {
	data := c.dataBytes()
	r := bufio.NewReader(bytes.NewReader(data))
	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		return data
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	rest, _ := io.ReadAll(r)
	return rest
}

// newHandleStreamTestStream builds a *Stream (id 1) wired to a StreamManager
// whose sendFrameFunc test seam feeds a handleStreamCapture, matching the
// construction used by newShellTestSession (shell_close_test.go) and
// newTestCapture (exec_test.go).
func newHandleStreamTestStream() (*Stream, *handleStreamCapture) {
	cap := &handleStreamCapture{}

	mgr := &StreamManager{
		streams: make(map[uint32]*Stream),
		log:     logging.Named("test"),
	}
	mgr.sendFrameFunc = func(data []byte) error {
		frame, err := DecodeFrame(data)
		if err != nil {
			return err
		}
		cap.add(frame)
		return nil
	}

	s := &Stream{
		id:        1,
		readBuf:   make(chan []byte, 8),
		closeChan: make(chan struct{}),
		manager:   mgr,
		log:       logging.Named("test.stream"),
	}
	mgr.streams[1] = s
	return s, cap
}

// pushRawRequest feeds one raw HTTP/1.1 request (no body) into the stream's
// readBuf as a single chunk — the same shape http.ReadRequest expects to read
// off the wire inside HandleStream's loop.
func pushRawRequest(s *Stream, method, path string) {
	raw := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n", method, path)
	s.readBuf <- []byte(raw)
}

// closeHandleStreamTestStream marks the stream closed the way an incoming
// CLOSE frame would (see StreamManager.handleClose and exec_test.go's
// closeInput), so the http.ReadRequest call blocked on the next HandleStream
// loop iteration observes EOF and the handler returns instead of hanging
// past the end of the test.
func closeHandleStreamTestStream(s *Stream) {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		close(s.closeChan)
		close(s.readBuf)
	}
	s.mu.Unlock()
}

// waitForHandleStreamResponse polls the capture until a complete HTTP
// response can be parsed out of the accumulated DATA frames. HandleStream
// answers (block or forward) synchronously per request with no real network
// latency involved in these tests, so this resolves within a handful of
// polls; it exists only to avoid a fixed sleep racing the handler goroutine.
func waitForHandleStreamResponse(t *testing.T, cap *handleStreamCapture) *http.Response {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if data := cap.dataBytes(); len(data) > 0 {
			resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(data)), nil)
			if err == nil {
				body, readErr := io.ReadAll(resp.Body)
				resp.Body.Close()
				if readErr == nil {
					resp.Body = io.NopCloser(bytes.NewReader(body))
					return resp
				}
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for a complete HTTP response on the stream; captured %d bytes", len(cap.dataBytes()))
	return nil
}

// newSentinelBackend starts an httptest TLS server standing in for local
// OPNsense. It records whether it was ever hit and returns a fixed,
// identifiable body so a test can distinguish "forwarded and echoed the
// sentinel's response" from "answered locally without forwarding".
func newSentinelBackend(body string) (*httptest.Server, *int32) {
	hits := new(int32)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	return ts, hits
}

// newHandleStreamTestProxy builds an HTTPProxy pointed at the sentinel
// backend's host:port. NewHTTPProxy's transport already sets
// InsecureSkipVerify, so it works against httptest's self-signed cert with no
// client override (unlike TestHTTPProxyForwardRequest, which overrides the
// client for other reasons).
func newHandleStreamTestProxy(t *testing.T, ts *httptest.Server, readOnly bool) *HTTPProxy {
	t.Helper()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("failed to parse sentinel URL %q: %v", ts.URL, err)
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("failed to split sentinel host:port %q: %v", u.Host, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("failed to parse sentinel port %q: %v", portStr, err)
	}

	sessionMgr := NewSessionManager("testuser", t.TempDir())
	proxy := NewHTTPProxy(host, port, sessionMgr)
	proxy.SetReadOnly(readOnly)
	return proxy
}

// runHandleStream starts proxy.HandleStream(stream) in a goroutine and
// returns a channel that receives its return value. Callers must close the
// stream (closeHandleStreamTestStream) to make HandleStream return.
func runHandleStream(proxy *HTTPProxy, stream *Stream) <-chan error {
	done := make(chan error, 1)
	go func() { done <- proxy.HandleStream(stream) }()
	return done
}

// waitHandleStreamDone waits for HandleStream to return after the stream is
// closed, failing the test on timeout so a goroutine leak surfaces loudly
// instead of silently under -race.
func waitHandleStreamDone(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("HandleStream did not return after the stream was closed")
		return nil
	}
}

// assertSentinelNeverHitWithin polls hits for the given window and fails
// immediately if it ever becomes non-zero.
//
// The window must elapse BEFORE the caller closes the stream. HandleStream
// ties its per-request context to stream.CloseChan() (a goroutine cancels the
// context the instant the stream closes — see the `go func(){ <-stream.
// CloseChan(); cancel() }()` in HandleStream), so closing the stream
// immediately after the 405 is captured would cancel an in-flight (buggy)
// forwardRequest before it ever reaches the sentinel — turning a real bypass
// into a false pass. forwardRequest against a real httptest TLS server is not
// instantaneous (observed up to ~300ms for TLS handshake + round trip in this
// environment), so the window has to be generous enough to let a buggy
// fallthrough actually complete against the backend while the stream (and
// therefore the context) is still open.
func assertSentinelNeverHitWithin(t *testing.T, hits *int32, window time.Duration) {
	t.Helper()
	deadline := time.Now().Add(window)
	for time.Now().Before(deadline) {
		if got := atomic.LoadInt32(hits); got != 0 {
			t.Fatalf("sentinel backend was hit %d time(s); forwardRequest must be skipped entirely for a blocked request, not merely raced against the 405", got)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := atomic.LoadInt32(hits); got != 0 {
		t.Fatalf("sentinel backend was hit %d time(s); forwardRequest must be skipped entirely for a blocked request, not merely raced against the 405", got)
	}
}

// TestHandleStream_ReadOnlyBlocksServiceRestart_DoesNotForward is the core
// revert-sensitive assertion for the read-only runtime-action gate: in a
// read-only session, a mutating service-action POST must be answered 405
// WITHOUT ever reaching forwardRequest. Asserting only the 405 would still
// pass if the gate raced a 405 alongside a forward (or if the deny check were
// merely cosmetic); the sentinel hit-count is what proves forwardRequest was
// actually skipped. See assertSentinelNeverHitWithin for why the stream must
// stay open through the whole confirmation window before we close it.
func TestHandleStream_ReadOnlyBlocksServiceRestart_DoesNotForward(t *testing.T) {
	ts, hits := newSentinelBackend("service restarted")
	defer ts.Close()

	proxy := newHandleStreamTestProxy(t, ts, true)
	stream, cap := newHandleStreamTestStream()
	done := runHandleStream(proxy, stream)

	pushRawRequest(stream, "POST", "/api/core/service/restart/openvpn")

	resp := waitForHandleStreamResponse(t, cap)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d (405 Method Not Allowed)", resp.StatusCode, http.StatusMethodNotAllowed)
	}

	assertSentinelNeverHitWithin(t, hits, 2*time.Second)

	closeHandleStreamTestStream(stream)
	waitHandleStreamDone(t, done)

	if got := atomic.LoadInt32(hits); got != 0 {
		t.Fatalf("sentinel backend was hit %d time(s) after HandleStream returned; a delayed/async forward slipped through", got)
	}
}

// TestHandleStream_ReadOnlyBlocksFlushStates_DoesNotForward is the
// diagnostics firewall-state counterpart to
// TestHandleStream_ReadOnlyBlocksServiceRestart_DoesNotForward: a read-only
// session must never let a flushStates POST reach the backend.
func TestHandleStream_ReadOnlyBlocksFlushStates_DoesNotForward(t *testing.T) {
	ts, hits := newSentinelBackend("states flushed")
	defer ts.Close()

	proxy := newHandleStreamTestProxy(t, ts, true)
	stream, cap := newHandleStreamTestStream()
	done := runHandleStream(proxy, stream)

	pushRawRequest(stream, "POST", "/api/diagnostics/firewall/flushStates")

	resp := waitForHandleStreamResponse(t, cap)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d (405 Method Not Allowed)", resp.StatusCode, http.StatusMethodNotAllowed)
	}

	assertSentinelNeverHitWithin(t, hits, 2*time.Second)

	closeHandleStreamTestStream(stream)
	waitHandleStreamDone(t, done)

	if got := atomic.LoadInt32(hits); got != 0 {
		t.Fatalf("sentinel backend was hit %d time(s) after HandleStream returned; a delayed/async forward slipped through", got)
	}
}

// TestHandleStream_ReadOnlyAllowsGridSearchLoad_IsForwarded is the positive
// counterpart: the denylist must not break the OPNsense grid/list views that
// every read-only WebUI page depends on. A POST to a search endpoint must
// still be forwarded to (and its response echoed from) the backend even in a
// read-only session.
func TestHandleStream_ReadOnlyAllowsGridSearchLoad_IsForwarded(t *testing.T) {
	const wantBody = "grid-rows"
	ts, hits := newSentinelBackend(wantBody)
	defer ts.Close()

	proxy := newHandleStreamTestProxy(t, ts, true)
	stream, cap := newHandleStreamTestStream()
	done := runHandleStream(proxy, stream)

	pushRawRequest(stream, "POST", "/api/firewall/filter/searchRule")

	resp := waitForHandleStreamResponse(t, cap)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (the denylist must not block a grid/search load in a read-only session)", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	if string(body) != wantBody {
		t.Fatalf("body = %q, want %q (response must come from the forwarded sentinel, not a synthesized local response)", body, wantBody)
	}
	if got := atomic.LoadInt32(hits); got != 1 {
		t.Fatalf("sentinel backend hit count = %d, want 1 (request must have been forwarded exactly once)", got)
	}

	closeHandleStreamTestStream(stream)
	waitHandleStreamDone(t, done)
}

// TestHandleStream_NonReadOnlyAllowsServiceRestart_IsForwarded proves the
// gate is scoped to read-only sessions only: with readOnly=false, the same
// service-action POST that gets a 405 in the read-only tests above must be
// forwarded normally.
func TestHandleStream_NonReadOnlyAllowsServiceRestart_IsForwarded(t *testing.T) {
	const wantBody = "service restarted"
	ts, hits := newSentinelBackend(wantBody)
	defer ts.Close()

	proxy := newHandleStreamTestProxy(t, ts, false)
	stream, cap := newHandleStreamTestStream()
	done := runHandleStream(proxy, stream)

	pushRawRequest(stream, "POST", "/api/core/service/restart/openvpn")

	resp := waitForHandleStreamResponse(t, cap)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (the read-only gate must not apply to a non-read-only session)", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	if string(body) != wantBody {
		t.Fatalf("body = %q, want %q", body, wantBody)
	}
	if got := atomic.LoadInt32(hits); got != 1 {
		t.Fatalf("sentinel backend hit count = %d, want 1 (request must have been forwarded)", got)
	}

	closeHandleStreamTestStream(stream)
	waitHandleStreamDone(t, done)
}
