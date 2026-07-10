package pathfinder

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
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

	// readOnly gates mutating runtime-action requests (service
	// start/stop/restart/reload/reconfigure) within the webadmin HTTP
	// stream. See isMutatingRuntimeAction.
	readOnly bool
}

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
	}
}

// SetReadOnly configures whether this proxy blocks mutating runtime-action
// requests (see isMutatingRuntimeAction). Left false by default so existing
// callers of NewHTTPProxy are unaffected; NewTCPProxyWithConfig calls this
// after construction when ProxyConfig.ReadOnly is set.
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

		// Read-only enforcement: block the residual mutating runtime-action
		// routes (service start/stop/restart/reload/reconfigure; firewall
		// state kill/flush/delete) that ACL allows through even for the
		// forged read-only identity. This is a narrow denylist, NOT a
		// method allowlist — OPNsense's grid/list views (firewall rules,
		// aliases, NAT, WireGuard peers, users, certs, DNS) load via POST
		// to search*/searchItem/search_* endpoints, so a GET/HEAD/OPTIONS-
		// only allowlist would 405 every list page in the read-only WebUI.
		if p.readOnly && isMutatingRuntimeAction(req.Method, req.URL.Path) {
			p.log.Warnw("Refusing mutating runtime-action request in read-only session",
				"stream_id", stream.ID(),
				"method", req.Method,
				"path", req.URL.Path,
			)
			p.sendErrorResponse(stream, http.StatusMethodNotAllowed, "Method Not Allowed (read-only session)")
			continue
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

// forwardRequest sends the HTTP request to the local OPNsense instance.
// The context is used to cancel the request when the stream closes.
func (p *HTTPProxy) forwardRequest(ctx context.Context, req *http.Request, session *Session) (*http.Response, error) {
	// Build target URL
	targetURL := fmt.Sprintf("https://%s:%d%s", p.localHost, p.localPort, req.URL.RequestURI())

	// Create new request with context (can't reuse the original request directly)
	proxyReq, err := http.NewRequestWithContext(ctx, req.Method, targetURL, req.Body)
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

// serviceActionPattern matches the OPNsense MVC service-control route family
// (e.g. /api/core/service/restart/openvpn, /api/openvpn/service/reconfigure)
// on any plugin namespace. This is the one runtime-action family confirmed
// against the opnapi client / OPNsense MVC controller convention:
// /api/<module>/service/<start|stop|restart|reload|reconfigure>[/<id>].
var serviceActionPattern = regexp.MustCompile(`^/api/[^/]+/service/(start|stop|restart|reload|reconfigure)(/|$)`)

// firewallStateActionPattern matches the diagnostics firewall-state mutators
// exposed by OPNsense\Diagnostics\Api\FirewallController: killStates (kill by
// filter/ruleid), flushStates (reset all states), and delState/<id>/<creator>
// (delete a single row). These are runtime actions, not config writes, so
// they bypass the user-config-readonly backstop the same way the
// service-action family does. The grid itself loads via a separate
// search-named endpoint (e.g. searchState), which this pattern's exact
// action-name anchoring never matches.
var firewallStateActionPattern = regexp.MustCompile(`^/api/diagnostics/firewall/(killStates|flushStates|delState)(/|$)`)

// isMutatingRuntimeAction reports whether the given method+path is a
// mutating request to a runtime-action route that OPNsense's ACL model
// permits even for a read-only operator (see the ACL split documented in
// CLAUDE.md: service start/stop/restart/reload/reconfigure, and firewall
// state kill/flush, bypass the user-config-readonly backstop because they
// are not config writes). GET/HEAD/OPTIONS are never mutating and must pass
// through untouched — in particular, every OPNsense grid/list view loads via
// POST to search*/searchItem/search_* endpoints, which this function does
// not match.
func isMutatingRuntimeAction(method, path string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return serviceActionPattern.MatchString(path) || firewallStateActionPattern.MatchString(path)
}

// sendErrorResponse sends an HTTP error response to the stream.
func (p *HTTPProxy) sendErrorResponse(stream *Stream, statusCode int, message string) {
	resp := &http.Response{
		StatusCode: statusCode,
		Status:     fmt.Sprintf("%d %s", statusCode, message),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       http.NoBody,
	}
	resp.Header.Set("Content-Type", "text/plain")
	resp.Header.Set("Connection", "close")

	if err := resp.Write(stream); err != nil {
		p.log.Debugw("Failed to send error response", "error", err)
	}
}
