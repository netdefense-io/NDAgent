package pathfinder

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/logging"
)

// The tests in this file are about the responses the read-only proxy answers
// itself, a refusal or a response it withheld: what of them reaches a client,
// and what the proxy does with the rest of the stream.

// tunnelClient is the client end of a relayed session, modelled on the tunnel
// of `ndcli device connect --webadmin-only`: a local TCP listener, a stream per
// connection, and the frames the relay delivers handed to each stream's reader
// through a queue and a worker goroutine. Like ndcli's, a stream whose CLOSE
// arrives while frames are still queued can lose them: the worker may stop with
// a frame in hand, and the reader gives up at CLOSE on whatever the worker has
// not passed on yet. That client is in the field, and a reply has to reach it.
type tunnelClient struct {
	toAgent chan<- []byte
	stop    <-chan struct{}
	dropped atomic.Int32 // frames the queue had no room for; the tests need 0

	mu      sync.Mutex
	streams map[uint32]*tunnelStream
	nextID  uint32
}

type tunnelStream struct {
	id     uint32
	client *tunnelClient

	queued    chan []byte // filled by the relay reader, which never blocks on it
	delivered chan []byte // what Read hands out, filled by work
	closed    chan struct{}

	closeOnce, closedOnce sync.Once
}

func (c *tunnelClient) send(f *Frame) error {
	select {
	case c.toAgent <- EncodeFrame(f):
		return nil
	case <-c.stop:
		return errors.New("relay stopped")
	}
}

func (c *tunnelClient) open() (*tunnelStream, error) {
	c.mu.Lock()
	c.nextID++
	s := &tunnelStream{
		id:        c.nextID,
		client:    c,
		queued:    make(chan []byte, 4096),
		delivered: make(chan []byte, 4096),
		closed:    make(chan struct{}),
	}
	c.streams[s.id] = s
	c.mu.Unlock()
	go s.work()
	return s, c.send(&Frame{Type: FrameTypeOpen, StreamID: s.id, Data: []byte(ServiceWebadmin)})
}

// receive takes one frame off the relay.
func (c *tunnelClient) receive(raw []byte) {
	f, err := DecodeFrame(raw)
	if err != nil {
		return
	}
	c.mu.Lock()
	s := c.streams[f.StreamID]
	if f.Type == FrameTypeClose {
		delete(c.streams, f.StreamID)
	}
	c.mu.Unlock()
	if s == nil {
		return
	}
	switch f.Type {
	case FrameTypeData:
		select {
		case s.queued <- f.Data:
		case <-s.closed:
		default:
			c.dropped.Add(1)
		}
	case FrameTypeClose:
		s.closedOnce.Do(func() { close(s.closed) })
	}
}

func (s *tunnelStream) work() {
	for {
		select {
		case data := <-s.queued:
			select {
			case s.delivered <- data:
			case <-s.closed:
				return
			}
		case <-s.closed:
			for {
				select {
				case data := <-s.queued:
					select {
					case s.delivered <- data:
					default:
						return
					}
				default:
					return
				}
			}
		}
	}
}

func (s *tunnelStream) Read(p []byte) (int, error) {
	select {
	case data := <-s.delivered:
		return copy(p, data), nil
	default:
	}
	select {
	case data := <-s.delivered:
		return copy(p, data), nil
	case <-s.closed:
		select {
		case data := <-s.delivered:
			return copy(p, data), nil
		default:
		}
		return 0, io.EOF
	}
}

func (s *tunnelStream) Write(p []byte) (int, error) {
	select {
	case <-s.closed:
		return 0, io.ErrClosedPipe
	default:
	}
	if err := s.client.send(&Frame{Type: FrameTypeData, StreamID: s.id, Data: append([]byte(nil), p...)}); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (s *tunnelStream) Close() error {
	s.closeOnce.Do(func() {
		_ = s.client.send(&Frame{Type: FrameTypeClose, StreamID: s.id})
		s.closedOnce.Do(func() { close(s.closed) })
		s.client.mu.Lock()
		delete(s.client.streams, s.id)
		s.client.mu.Unlock()
	})
	return nil
}

// serve carries one TCP connection over a stream of its own, both ways, and
// ends it when either way ends.
func (c *tunnelClient) serve(conn net.Conn) {
	defer conn.Close()
	s, err := c.open()
	if err != nil {
		return
	}
	done := make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(done) }) }
	go func() {
		_, _ = io.Copy(s, conn)
		_ = s.Close()
		finish()
	}()
	go func() {
		_, _ = io.Copy(conn, s)
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		finish()
	}()
	<-done
}

// relayedSession runs the agent's side of a CONNECT session, a stream manager
// whose streams the proxy serves through ProxyStreamToLocal as connect.go wires
// it, behind a relay that delivers frames in order each way, and a tunnelClient
// listening on a local port in front of it.
type relayedSession struct {
	addr   string
	client *tunnelClient
	active atomic.Int32 // stream handlers still running
}

func newRelayedSession(t *testing.T, proxy *TCPProxy) *relayedSession {
	t.Helper()
	toAgent := make(chan []byte, 4096)
	toClient := make(chan []byte, 4096)
	stop := make(chan struct{})

	rs := &relayedSession{}
	sm := &StreamManager{streams: make(map[uint32]*Stream), log: logging.Named("test")}
	sm.sendFrameFunc = func(b []byte) error {
		select {
		case toClient <- append([]byte(nil), b...):
			return nil
		case <-stop:
			return errors.New("relay stopped")
		}
	}
	sm.OnNewStream(func(s *Stream) {
		rs.active.Add(1)
		defer rs.active.Add(-1)
		if err := proxy.ProxyStreamToLocal(s); err != nil {
			s.Close()
		}
	})
	rs.client = &tunnelClient{toAgent: toAgent, stop: stop, streams: make(map[uint32]*tunnelStream)}

	go func() {
		for {
			select {
			case f := <-toAgent:
				sm.handleFrame(f)
			case <-stop:
				return
			}
		}
	}()
	go func() {
		for {
			select {
			case f := <-toClient:
				rs.client.receive(f)
			case <-stop:
				return
			}
		}
	}()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	rs.addr = ln.Addr().String()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go rs.client.serve(conn)
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		deadline := time.Now().Add(10 * time.Second)
		for rs.active.Load() != 0 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		close(stop)
		if n := rs.active.Load(); n != 0 {
			t.Errorf("%d stream handler(s) still running at the end of the test", n)
		}
		if n := rs.client.dropped.Load(); n != 0 {
			t.Errorf("the tunnel dropped %d frame(s) for lack of room; the test does not measure what it should", n)
		}
	})
	return rs
}

// readOnlyTCPProxy is a read-only proxy whose webadmin service is the backend.
func readOnlyTCPProxy(t *testing.T, backend *httptest.Server, linger time.Duration) *TCPProxy {
	t.Helper()
	proxy := NewTCPProxyWithConfig(ProxyConfig{ReadOnly: true, WebadminSessionDir: t.TempDir()})
	host, port, err := net.SplitHostPort(strings.TrimPrefix(backend.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	proxy.httpProxy.localHost = host
	fmt.Sscanf(port, "%d", &proxy.httpProxy.localPort)
	proxy.httpProxy.replyLinger = linger
	return proxy
}

// withConnectionHeader adds Connection: close to a raw request when asked to.
func withConnectionHeader(raw string, connectionClose bool) string {
	if !connectionClose {
		return raw
	}
	line, rest, _ := strings.Cut(raw, "\r\n")
	return line + "\r\nConnection: close\r\n" + rest
}

// tcpExchange is what a client on the tunnel's port got for one request.
type tcpExchange struct {
	status   string
	body     string
	received int   // bytes read off the connection
	err      error // why no complete response could be read
}

// exchangeOverTCP sends raw on a connection of its own. Without Connection:
// close the client reads one response by its length and closes, as a browser
// would; with it, the client reads until the connection ends, as the lab's raw
// socket drivers did.
func exchangeOverTCP(addr, raw string, connectionClose bool, wait time.Duration) tcpExchange {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return tcpExchange{err: err}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(wait))
	if _, err := io.WriteString(conn, withConnectionHeader(raw, connectionClose)); err != nil {
		return tcpExchange{err: err}
	}

	var received bytes.Buffer
	var r *bufio.Reader
	if connectionClose {
		if _, err := io.Copy(&received, conn); err != nil {
			return tcpExchange{received: received.Len(), err: fmt.Errorf("the connection did not end: %w", err)}
		}
		r = bufio.NewReader(bytes.NewReader(received.Bytes()))
	} else {
		r = bufio.NewReader(io.TeeReader(conn, &received))
	}
	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		return tcpExchange{received: received.Len(), err: err}
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return tcpExchange{status: resp.Status, received: received.Len(), err: err}
	}
	if connectionClose {
		if rest, _ := io.ReadAll(r); len(rest) != 0 {
			return tcpExchange{status: resp.Status, received: received.Len(), err: fmt.Errorf("%d byte(s) after the response", len(rest))}
		}
	}
	return tcpExchange{status: resp.Status, body: string(body), received: received.Len()}
}

// replyCase is one request whose answer the proxy writes itself.
type replyCase struct {
	name   string
	raw    string
	status string // the status line the client must get, after "HTTP/1.1 "
	body   string // the body it must get; empty when there is none
}

func refusalReply(code int) string {
	return fmt.Sprintf("%d %s (read-only session)", code, http.StatusText(code))
}

// refusalFamilies holds one request for each way readOnlyRefusal refuses.
func refusalFamilies() []replyCase {
	form := "application/x-www-form-urlencoded"
	return []replyCase{
		{name: "a method that is never forwarded", raw: rawRequest("OPTIONS", "/api/diagnostics/netflow/setconfig", "application/json", jsonBody), status: refusalReply(refused)},
		{name: "a target the router and lighttpd read differently", raw: rawRequest("POST", "/%2e/interfaces.php", form, "apply=1"), status: refusalReply(malformed)},
		{name: "a target that names a host", raw: "GET http://evil.example/x HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n", status: refusalReply(malformed)},
		{name: "a body on a GET", raw: rawRequest("GET", "/api/core/service/search", "application/json", `{}`), status: refusalReply(malformed)},
		{name: "a handler that acts whatever the method", raw: rawRequest("GET", "/api/interfaces/vip_settings/set_item/"+certUUID, "", ""), status: refusalReply(refused)},
		{name: "a private key", raw: rawRequest("POST", "/api/trust/cert/generate_file/"+certUUID+"/prv", "", ""), status: refusalReply(refused)},
		{name: "the generated swanctl.conf", raw: rawRequest("GET", "/api/ipsec/connections/swanctl", "", ""), status: refusalReply(refused)},
		{name: "a HEAD to a cleaned route", raw: rawRequest("HEAD", "/api/auth/user/get/"+certUUID, "", ""), status: refusalReply(refused)},
		{name: "a HEAD to a cleaned page", raw: rawRequest("HEAD", "/interfaces_ppps_edit.php?id=0", "", ""), status: refusalReply(refused)},
		{name: "a POST to a legacy page", raw: rawRequest("POST", "/crash_reporter.php", form, "action=delete"), status: refusalReply(refused)},
		{name: "a lifecycle verb", raw: rawRequest("POST", "/api/core/service/restart/openvpn", "", ""), status: refusalReply(refused)},
		{name: "a named mutator", raw: rawRequest("POST", "/api/core/system/dismiss_status", "application/json", `{"subject":"crashreporter"}`), status: refusalReply(refused)},
		{name: "the account's own dashboard save", raw: rawRequest("POST", "/api/core/dashboard/saveWidgets", "application/json", `{"widgets":[]}`), status: refusalReply(refused)},
		{name: "a log clear", raw: rawRequest("POST", "/api/diagnostics/log/core/system/clear", "", ""), status: refusalReply(refused)},
	}
}

// assertRepliesArriveWhole sends every case repeats times in each connection
// mode, side by side, and fails on every exchange whose client did not get the
// whole reply.
func assertRepliesArriveWhole(t *testing.T, rs *relayedSession, cases []replyCase, repeats int, wait time.Duration) {
	t.Helper()
	type outcome struct {
		mode string
		tcpExchange
	}
	results := make([][]outcome, len(cases))
	var mu sync.Mutex
	var wg sync.WaitGroup
	slots := make(chan struct{}, 64)
	for i, c := range cases {
		for _, connectionClose := range []bool{false, true} {
			mode := "keep-alive"
			if connectionClose {
				mode = "Connection: close"
			}
			for n := 0; n < repeats; n++ {
				wg.Add(1)
				slots <- struct{}{}
				go func(i int, raw, mode string, connectionClose bool) {
					defer wg.Done()
					defer func() { <-slots }()
					ex := exchangeOverTCP(rs.addr, raw, connectionClose, wait)
					mu.Lock()
					results[i] = append(results[i], outcome{mode, ex})
					mu.Unlock()
				}(i, c.raw, mode, connectionClose)
			}
		}
	}
	wg.Wait()

	for i, c := range cases {
		lost := map[string]int{}
		var sample string
		for _, o := range results[i] {
			ok := o.err == nil && o.status == c.status && o.body == c.body
			if ok {
				continue
			}
			kind := "partial"
			if o.received == 0 {
				kind = "empty"
			} else if o.err == nil {
				kind = "wrong"
			}
			lost[o.mode+" "+kind]++
			if sample == "" {
				sample = fmt.Sprintf("%s: %d byte(s), status %q, error %v", o.mode, o.received, o.status, o.err)
			}
		}
		if len(lost) != 0 {
			t.Errorf("%s (%s): the client did not get the whole %q reply in %v of %d exchanges; e.g. %s",
				c.name, strings.SplitN(c.raw, "\r\n", 2)[0], c.status, lost, len(results[i]), sample)
		}
	}
}

// TestHandleStream_ReadOnlyRefusalReachesTheClientWhole puts every kind of
// refused request through a relayed session to a client that, like ndcli's
// tunnel, can lose frames its CLOSE arrives right behind, many times over and in
// both connection modes. Every client must get the whole refusal, and nothing
// may reach OPNsense. A proxy that sends CLOSE right behind its reply loses most
// of them here, as it did through ndcli in the lab.
func TestHandleStream_ReadOnlyRefusalReachesTheClientWhole(t *testing.T) {
	ts, hits := newSentinelBackend("forwarded")
	defer ts.Close()
	const linger = time.Second
	rs := newRelayedSession(t, readOnlyTCPProxy(t, ts, linger))

	assertRepliesArriveWhole(t, rs, refusalFamilies(), 6, linger+10*time.Second)

	if got := atomic.LoadInt32(hits); got != 0 {
		t.Fatalf("OPNsense was reached %d time(s); a refused request must never be forwarded", got)
	}
}

// TestHandleStream_ReadOnlyWithheldResponseReachesTheClientWhole does the same
// for a response the proxy withholds because it cannot clean it: the 502 that
// replaces it must reach the client whole.
func TestHandleStream_ReadOnlyWithheldResponseReachesTheClientWhole(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><body>Login SECRET-LEAK</body></html>")
	}))
	defer ts.Close()
	const linger = time.Second
	rs := newRelayedSession(t, readOnlyTCPProxy(t, ts, linger))

	withheld := []replyCase{{
		name:   "a response that is not the JSON the route answers",
		raw:    rawRequest("GET", "/api/auth/user/get/"+certUUID, "", ""),
		status: "502 Bad Gateway (read-only session: response withheld)",
		body:   "the response is not the JSON document this route answers with, so it cannot be cleaned of secrets\n",
	}}
	assertRepliesArriveWhole(t, rs, withheld, 6, linger+10*time.Second)
}

// TestHandleStream_ReadOnlyReadsNothingMoreAfterARefusal sends a refused POST
// whose body is itself a request, and another request behind it on the same
// stream. Neither may be read as a request: the stream carries the one refusal,
// OPNsense is never reached, the proxy leaves the stream for the client to
// close, and the client's close ends the handler.
func TestHandleStream_ReadOnlyReadsNothingMoreAfterARefusal(t *testing.T) {
	ts, hits := newSentinelBackend("forwarded")
	defer ts.Close()
	proxy := newHandleStreamTestProxy(t, ts, true)
	stream, cap := newHandleStreamTestStream()
	done := runHandleStream(proxy, stream)

	allowed := "GET /api/core/menu/tree HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n"
	stream.readBuf <- []byte(rawRequest("POST", "/api/core/service/restart/openvpn", "text/plain", allowed))
	stream.readBuf <- []byte(allowed)

	resp := waitForHandleStreamResponse(t, cap)
	if want := refusalReply(refused); resp.Status != want {
		t.Fatalf("status = %q, want %q", resp.Status, want)
	}
	// Hold the stream open (TESTING.md): a request the proxy wrongly took up
	// must have the time to reach OPNsense.
	waitNeverHit(t, time.Second, hits)
	if extra := cap.afterFirstResponse(); len(extra) != 0 {
		t.Errorf("the stream carried more than the refusal: %q", extra)
	}
	if cap.closeSent() {
		t.Error("the proxy closed the stream right behind its reply; the client closes it once it has read the reply")
	}

	start := time.Now()
	closeHandleStreamTestStream(stream)
	if err := waitHandleStreamDone(t, done); err != nil {
		t.Errorf("HandleStream returned %v", err)
	}
	if took := time.Since(start); took > defaultReplyLinger/2 {
		t.Errorf("HandleStream took %v to return after the client closed the stream; the client's close ends it", took)
	}
	if got := atomic.LoadInt32(hits); got != 0 {
		t.Fatalf("OPNsense was reached %d time(s)", got)
	}
}

// TestHandleStream_ReadOnlyClosesAStreamTheClientLeavesOpen: a client that
// waits for the stream to end gets that end from the proxy once the linger is
// over, and not before; the CLOSE follows the whole reply. The frames carry the
// time they were written, so the check does not depend on when the test notices
// the reply.
func TestHandleStream_ReadOnlyClosesAStreamTheClientLeavesOpen(t *testing.T) {
	ts, hits := newSentinelBackend("forwarded")
	defer ts.Close()
	proxy := newHandleStreamTestProxy(t, ts, true)
	const linger = time.Second
	proxy.replyLinger = linger
	stream, cap := newHandleStreamTestStream()
	done := runHandleStream(proxy, stream)

	stream.readBuf <- []byte(rawRequest("POST", "/api/core/service/restart/openvpn", "", ""))
	resp := waitForHandleStreamResponse(t, cap)
	if want := refusalReply(refused); resp.Status != want {
		t.Fatalf("status = %q, want %q", resp.Status, want)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("HandleStream returned %v", err)
		}
	case <-time.After(linger + 5*time.Second):
		t.Fatal("the proxy never closed a stream the client left open")
	}

	cap.mu.Lock()
	frames := append([]*Frame(nil), cap.frames...)
	sentAt := append([]time.Time(nil), cap.sentAt...)
	cap.mu.Unlock()
	closes, lastData := 0, -1
	for i, f := range frames {
		switch f.Type {
		case FrameTypeClose:
			closes++
		case FrameTypeData:
			lastData = i
		}
	}
	last := len(frames) - 1
	if closes != 1 || lastData < 0 || frames[last].Type != FrameTypeClose {
		t.Fatalf("want exactly one CLOSE, after the whole reply; got %d CLOSE frame(s) in %d frames", closes, len(frames))
	}
	if after := sentAt[last].Sub(sentAt[lastData]); after < linger {
		t.Errorf("the proxy closed the stream %v after its reply, before the linger (%v) was over", after, linger)
	}
	if extra := cap.afterFirstResponse(); len(extra) != 0 {
		t.Errorf("the stream carried more than the refusal: %q", extra)
	}
	if got := atomic.LoadInt32(hits); got != 0 {
		t.Fatalf("OPNsense was reached %d time(s)", got)
	}
}

// TestHandleStream_ReadOnlyWithheldResponseEndsTheExchange: after a response
// it withheld, the proxy takes no other request on the stream, and leaves the
// stream for the client to close.
func TestHandleStream_ReadOnlyWithheldResponseEndsTheExchange(t *testing.T) {
	var forwarded atomic.Int32
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><body>Login SECRET-LEAK</body></html>")
	}))
	defer ts.Close()
	proxy := newHandleStreamTestProxy(t, ts, true)
	stream, cap := newHandleStreamTestStream()
	done := runHandleStream(proxy, stream)

	stream.readBuf <- []byte(rawGet("/api/auth/user/get/u1") + rawGet("/api/auth/user/get/u2"))
	resp := waitForHandleStreamResponse(t, cap)
	if want := "502 Bad Gateway (read-only session: response withheld)"; resp.Status != want {
		t.Fatalf("status = %q, want %q", resp.Status, want)
	}
	time.Sleep(time.Second)
	if got := forwarded.Load(); got != 1 {
		t.Errorf("OPNsense was reached %d time(s), want 1: the request behind a withheld response must not be taken up", got)
	}
	if extra := cap.afterFirstResponse(); len(extra) != 0 {
		t.Errorf("the stream carried more than the withheld response: %q", extra)
	}
	if cap.closeSent() {
		t.Error("the proxy closed the stream right behind the withheld response; the client closes it once it has read the response")
	}
	closeHandleStreamTestStream(stream)
	if err := waitHandleStreamDone(t, done); err != nil {
		t.Errorf("HandleStream returned %v", err)
	}
}
