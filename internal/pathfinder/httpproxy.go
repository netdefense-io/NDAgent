package pathfinder

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/netdefense-io/ndagent/internal/logging"
)

// HTTPProxy proxies HTTP requests from a stream to a local HTTPS server.
// It creates a single PHP session for pre-authenticated access to OPNsense webadmin
// that is shared across all streams.
type HTTPProxy struct {
	localHost      string
	localPort      int
	sessionManager *SessionManager
	httpClient     *http.Client
	log            *zap.SugaredLogger

	// Shared session for all webadmin streams
	session   *Session
	sessionMu sync.Mutex

	// readOnly gates requests (see readOnlyRefusal) within the webadmin HTTP
	// stream.
	readOnly bool

	// replyLinger bounds how long endAfterReply waits for the client to close
	// a stream before closing it itself.
	replyLinger time.Duration
}

// defaultReplyLinger is how long a stream whose last response said
// Connection: close stays open for the client to close it. Clients that close
// on Connection: close (browsers, curl, NDWeb's WebAdmin bridge) end it at
// once; the limit is for one that waits for the stream to end instead.
const defaultReplyLinger = 5 * time.Second

// transportBody is the body of a forwarded request as the transport gets it.
// The transport may go on reading it, from the stream's reader, after it has
// returned the response (an upstream can answer before it reads the body), and
// closes it once it is done with it, after reading the rest; released is
// closed then.
type transportBody struct {
	io.ReadCloser
	once     sync.Once
	released chan struct{}
}

func newTransportBody(body io.ReadCloser) *transportBody {
	return &transportBody{ReadCloser: body, released: make(chan struct{})}
}

func (b *transportBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(func() { close(b.released) })
	return err
}

// nothingHeld is the release of a request body no transport holds.
var nothingHeld = func() <-chan struct{} {
	c := make(chan struct{})
	close(c)
	return c
}()

// NewHTTPProxy creates a new HTTP proxy for webadmin access.
// host and port specify the local OPNsense web interface (typically 127.0.0.1:443).
// sessionMgr handles PHP session creation/destruction.
func NewHTTPProxy(host string, port int, sessionMgr *SessionManager) *HTTPProxy {
	// Create HTTP client that skips TLS verification for localhost.
	// Use transport-level timeouts for connection/handshake, but no client-level
	// timeout to support streaming endpoints that never complete.
	// Request cancellation is handled via context when the stream closes.
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
		// Disable connection pooling to avoid issues with session cookies
		DisableKeepAlives: true,
		// Timeouts for connection establishment (not response body)
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		// Don't follow redirects - pass them through to the client
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		// No Timeout - streaming endpoints never complete.
		// Cancellation is handled via context when stream closes.
	}

	return &HTTPProxy{
		localHost:      host,
		localPort:      port,
		sessionManager: sessionMgr,
		httpClient:     client,
		log:            logging.Named("pathfinder.httpproxy"),
		replyLinger:    defaultReplyLinger,
	}
}

// SetReadOnly configures whether this proxy refuses the requests a read-only
// session must not make (see readOnlyRefusal). Left false by default so
// existing callers of NewHTTPProxy are unaffected; NewTCPProxyWithConfig calls
// this after construction when ProxyConfig.ReadOnly is set.
func (p *HTTPProxy) SetReadOnly(readOnly bool) {
	p.readOnly = readOnly
}

// getOrCreateSession returns the shared session, creating it if necessary.
func (p *HTTPProxy) getOrCreateSession() (*Session, error) {
	p.sessionMu.Lock()
	defer p.sessionMu.Unlock()

	if p.session != nil {
		return p.session, nil
	}

	session, err := p.sessionManager.CreateSession()
	if err != nil {
		return nil, err
	}

	p.session = session
	p.log.Debugw("Created shared PHP session for webadmin",
		"session_id", session.ID,
		"username", session.Username,
	)

	return p.session, nil
}

// Close destroys the shared session if one exists.
// This should be called when the Pathfinder connection ends.
func (p *HTTPProxy) Close() {
	p.sessionMu.Lock()
	defer p.sessionMu.Unlock()

	if p.session != nil {
		if err := p.sessionManager.DestroySession(p.session.ID); err != nil {
			p.log.Warnw("Failed to destroy session", "session_id", p.session.ID, "error", err)
		} else {
			p.log.Debugw("Destroyed shared PHP session", "session_id", p.session.ID)
		}
		p.session = nil
	}
}

// HandleStream processes HTTP requests from a stream and proxies them to local OPNsense.
// All streams share the same PHP session for authentication.
func (p *HTTPProxy) HandleStream(stream *Stream) error {
	// Get or create the shared session
	session, err := p.getOrCreateSession()
	if err != nil {
		return fmt.Errorf("failed to get session: %w", err)
	}

	// Create context that cancels when stream closes.
	// This allows streaming endpoints to be cancelled immediately when the
	// browser navigates away, instead of waiting for the HTTP client timeout.
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-stream.CloseChan()
		cancel()
	}()
	defer cancel()

	p.log.Debugw("Started HTTP proxy stream",
		"stream_id", stream.ID(),
		"session_id", session.ID,
	)

	// Process HTTP requests from the stream until it closes
	reader := bufio.NewReader(stream)

	for {
		// Check if stream is closed
		if stream.IsClosed() {
			p.log.Debugw("Stream closed, ending HTTP proxy stream", "stream_id", stream.ID())
			break
		}

		// Read HTTP request from stream
		req, err := http.ReadRequest(reader)
		if err != nil {
			if err == io.EOF || stream.IsClosed() {
				p.log.Debugw("Stream closed while reading request", "stream_id", stream.ID())
				break
			}
			// Peek at the first few bytes to diagnose the issue
			peekData, _ := reader.Peek(min(reader.Buffered(), 32))
			p.log.Errorw("Failed to read HTTP request",
				"error", err,
				"stream_id", stream.ID(),
				"buffered_bytes", reader.Buffered(),
				"peek_data_hex", fmt.Sprintf("%x", peekData),
			)
			return fmt.Errorf("failed to read request: %w", err)
		}

		p.log.Debugw("Received HTTP request",
			"stream_id", stream.ID(),
			"method", req.Method,
			"path", req.URL.Path,
		)

		// Read-only enforcement, before anything is forwarded.
		var scrub *scrubRule
		if p.readOnly {
			if status := readOnlyRefusal(req.Method, req.RequestURI, requestHasBody(req)); status != 0 {
				p.log.Warnw("Refusing request in read-only session",
					"stream_id", stream.ID(),
					"method", req.Method,
					"target", req.RequestURI,
					"status", status,
				)
				p.sendErrorResponse(stream, status, http.StatusText(status)+" (read-only session)")
				p.endAfterReply(stream, reader, nothingHeld)
				break
			}
			if scrub = scrubRuleFor(req.Method, req.RequestURI); scrub != nil {
				// The body is rewritten whole, so it must arrive whole and in the
				// clear: no compression the transport would leave on it, no range.
				req.Header.Del("Accept-Encoding")
				req.Header.Del("Range")
				req.Header.Del("If-Range")
			}
		}

		// An answer that is withheld can come before the transport has read the
		// request body; until the transport closes the body, it is the only
		// reader of the stream.
		bodyReleased := nothingHeld
		if scrub != nil && req.Body != nil && req.Body != http.NoBody {
			body := newTransportBody(req.Body)
			req.Body = body
			bodyReleased = body.released
		}

		// Forward request to local OPNsense
		resp, err := p.forwardRequest(ctx, req, session)
		if err != nil {
			// Check if error is due to context cancellation (stream closed)
			if ctx.Err() != nil {
				p.log.Debugw("Request cancelled due to stream closure",
					"stream_id", stream.ID(),
					"path", req.URL.Path,
				)
				break
			}
			p.log.Errorw("Failed to forward request", "error", err, "stream_id", stream.ID())
			// Send error response back to client
			p.sendErrorResponse(stream, http.StatusBadGateway, "Bad Gateway")
			continue
		}

		// Secrets are blanked out of the response before its first byte is
		// written. One that cannot be read is withheld, never forwarded.
		if scrub != nil {
			blanked, err := scrubResponse(resp, scrub)
			if err != nil {
				p.log.Warnw("Withholding response in read-only session",
					"stream_id", stream.ID(),
					"method", req.Method,
					"target", req.RequestURI,
					"status", resp.StatusCode,
					"error", err,
				)
				p.sendErrorResponse(stream, http.StatusBadGateway, "Bad Gateway (read-only session: response withheld)", withheldCause(err))
				p.endAfterReply(stream, reader, bodyReleased)
				break
			}
			p.log.Debugw("Cleaned response in read-only session",
				"stream_id", stream.ID(),
				"target", req.RequestURI,
				"blanked", blanked,
			)
		}

		// Write response back to stream
		if err := resp.Write(stream); err != nil {
			resp.Body.Close()
			if stream.IsClosed() {
				p.log.Debugw("Stream closed while writing response", "stream_id", stream.ID())
				break
			}
			p.log.Errorw("Failed to write response", "error", err, "stream_id", stream.ID())
			return fmt.Errorf("failed to write response: %w", err)
		}

		// Close response body
		resp.Body.Close()

		p.log.Debugw("Forwarded response",
			"stream_id", stream.ID(),
			"status", resp.StatusCode,
			"location", resp.Header.Get("Location"),
		)
	}

	p.log.Debugw("HTTP proxy stream ended", "stream_id", stream.ID())
	return nil
}

// endAfterReply ends a stream after a response that said Connection: close.
// Nothing more is read as a request: whatever the client still sends, the body
// of a refused request included, is discarded, but only once released is
// closed, because until then the transport may still be reading a request body
// from the same reader. The stream stays open until the client closes it, and
// the proxy closes it itself only after replyLinger.
//
// A CLOSE frame ends a stream in both directions, and a client may drop reply
// bytes it has not handed on yet when one arrives (ndcli's tunnel does), so the
// proxy never sends one right behind a reply. Frames that arrive while nothing
// reads the stream wait in its queue, or are dropped when it is full; the
// session's frame loop never waits for them.
func (p *HTTPProxy) endAfterReply(stream *Stream, pending io.Reader, released <-chan struct{}) {
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		<-released
		_, _ = io.Copy(io.Discard, pending)
	}()

	linger := time.NewTimer(p.replyLinger)
	defer linger.Stop()
	select {
	case <-drained:
		p.log.Debugw("Client closed the stream after the reply", "stream_id", stream.ID())
		stream.Close()
		return
	case <-linger.C:
		p.log.Debugw("Closing a stream the client left open after the reply",
			"stream_id", stream.ID(),
			"linger", p.replyLinger,
		)
	}
	stream.Close()

	// Every read of a closed stream ends, the transport's too, so the reader
	// above ends once the transport has let go of the body. Do not wait
	// forever for a transport that never does.
	wait := time.NewTimer(p.replyLinger)
	defer wait.Stop()
	select {
	case <-drained:
	case <-wait.C:
		p.log.Warnw("The transport still holds a request body of a closed stream", "stream_id", stream.ID())
	}
}

// forwardRequest sends the HTTP request to the local OPNsense instance.
// The context is used to cancel the request when the stream closes.
func (p *HTTPProxy) forwardRequest(ctx context.Context, req *http.Request, session *Session) (*http.Response, error) {
	// The scheme, host and port come from the local configuration; only the
	// path and query come from the request. A request-target such as
	// "http:@host:port/x" carries a host of its own and must not choose one.
	target := url.URL{
		Scheme:     "https",
		Host:       net.JoinHostPort(p.localHost, strconv.Itoa(p.localPort)),
		Path:       req.URL.Path,
		RawPath:    req.URL.RawPath,
		RawQuery:   req.URL.RawQuery,
		ForceQuery: req.URL.ForceQuery,
	}

	// Create new request with context (can't reuse the original request directly)
	proxyReq, err := http.NewRequestWithContext(ctx, req.Method, target.String(), req.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to create proxy request: %w", err)
	}

	// Copy headers from original request
	for key, values := range req.Header {
		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}

	// Inject PHPSESSID cookie for authentication
	p.injectSessionCookie(proxyReq, session)

	// Set Host header to match the request
	if req.Host != "" {
		proxyReq.Host = req.Host
	}

	// Set content length if present
	proxyReq.ContentLength = req.ContentLength

	// Forward the request
	resp, err := p.httpClient.Do(proxyReq)
	if err != nil {
		return nil, fmt.Errorf("failed to forward request: %w", err)
	}

	return resp, nil
}

// injectSessionCookie adds the PHPSESSID cookie to the request, replacing any existing one.
func (p *HTTPProxy) injectSessionCookie(req *http.Request, session *Session) {
	// Get existing cookies
	existingCookies := req.Header.Get("Cookie")

	// Build PHPSESSID cookie
	sessionCookie := fmt.Sprintf("PHPSESSID=%s", session.ID)

	if existingCookies != "" {
		// Remove any existing PHPSESSID cookie and replace with ours
		newCookies := removeExistingPHPSESSID(existingCookies)
		if newCookies != "" {
			req.Header.Set("Cookie", newCookies+"; "+sessionCookie)
		} else {
			req.Header.Set("Cookie", sessionCookie)
		}
	} else {
		req.Header.Set("Cookie", sessionCookie)
	}

	p.log.Debugw("Injected session cookie")
}

// removeExistingPHPSESSID removes any PHPSESSID cookie from the cookie string.
func removeExistingPHPSESSID(cookies string) string {
	var result []string
	for _, cookie := range splitCookies(cookies) {
		cookie = strings.TrimSpace(cookie)
		if cookie != "" && !strings.HasPrefix(cookie, "PHPSESSID=") {
			result = append(result, cookie)
		}
	}
	return strings.Join(result, "; ")
}

// splitCookies splits a cookie header value into individual cookies.
func splitCookies(cookies string) []string {
	return strings.Split(cookies, ";")
}

// requestHasBody reports whether the request declares a body, whatever its
// method. A chunked body has no declared length, which ContentLength reports
// as -1.
func requestHasBody(req *http.Request) bool {
	return req.ContentLength != 0
}

// sendErrorResponse sends an HTTP error response to the stream. A detail, when
// there is one, is its plain-text body.
func (p *HTTPProxy) sendErrorResponse(stream *Stream, statusCode int, message string, detail ...string) {
	resp := &http.Response{
		StatusCode: statusCode,
		Status:     fmt.Sprintf("%d %s", statusCode, message),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       http.NoBody,
	}
	if body := strings.Join(detail, ""); body != "" {
		body += "\n"
		resp.Body = io.NopCloser(strings.NewReader(body))
		resp.ContentLength = int64(len(body))
	}
	resp.Header.Set("Content-Type", "text/plain")
	resp.Header.Set("Connection", "close")

	if err := resp.Write(stream); err != nil {
		p.log.Debugw("Failed to send error response", "error", err)
	}
}
