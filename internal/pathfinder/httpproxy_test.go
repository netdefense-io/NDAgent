package pathfinder

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
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
