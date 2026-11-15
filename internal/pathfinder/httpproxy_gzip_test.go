package pathfinder

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// phpPage stands in for the HTML a PHP page of OPNsense writes.
var phpPage = strings.Repeat(`<div class="row"><a href="/ui/firewall/alias">Aliases</a></div>`+"\n", 400)

func gunzip(t *testing.T, b string) string {
	t.Helper()
	zr, err := gzip.NewReader(strings.NewReader(b))
	if err != nil {
		t.Fatalf("the body is not gzip: %v", err)
	}
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("the gzip body does not decode: %v", err)
	}
	return string(out)
}

// servePHP answers with phpPage as PHP does through lighttpd: in chunks, no
// length, and no encoding whatever the request asked for.
func servePHP(contentType string, status int, headers ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i+1 < len(headers); i += 2 {
			w.Header().Set(headers[i], headers[i+1])
		}
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(status)
		if !bodyAllowedForStatus(status) {
			return
		}
		half := len(phpPage) / 2
		_, _ = io.WriteString(w, phpPage[:half])
		w.(http.Flusher).Flush()
		_, _ = io.WriteString(w, phpPage[half:])
	}
}

// serveWithLength answers with phpPage and its length.
func serveWithLength(contentType string, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Header().Set("ETag", `"abc"`)
		w.Header().Set("Accept-Ranges", "bytes")
		_, _ = io.WriteString(w, body)
	}
}

const browserAE = "Accept-Encoding: gzip, deflate, br, zstd"

// What PHP writes reaches a client that accepts gzip compressed, in chunks,
// and decodes to what PHP wrote.
func TestHandleStream_CompressesWhatPHPWrites(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		headers []string
	}{
		{"a chunked page", servePHP("text/html; charset=UTF-8", http.StatusOK), []string{browserAE}},
		{"JSON with a length", serveWithLength("application/json; charset=UTF-8", phpPage), []string{browserAE}},
		{"an SVG", serveWithLength("image/svg+xml", phpPage), []string{"Accept-Encoding: gzip"}},
		{"a client that accepts any encoding", servePHP("text/css", http.StatusOK), []string{"Accept-Encoding: *"}},
		{"Accept-Encoding on two lines", servePHP("text/javascript", http.StatusOK), []string{"Accept-Encoding: br", "Accept-Encoding: gzip;q=0.5"}},
		{"a page of the same origin", servePHP("text/html", http.StatusOK), []string{browserAE, "Sec-Fetch-Site: same-origin", "Origin: http://127.0.0.1", "Referer: http://127.0.0.1/ui/core/dashboard"}},
		{"a request the user made", servePHP("text/html", http.StatusOK), []string{browserAE, "Sec-Fetch-Site: none"}},
		{"a not found page", servePHP("text/html", http.StatusNotFound), []string{browserAE}},
	}
	for _, session := range proxySessions {
		for _, tt := range tests {
			t.Run(session.name+"/"+tt.name, func(t *testing.T) {
				ex := exchangeWith(t, session.readOnly, tt.handler, rawGet("/ui/core/dashboard", tt.headers...))
				if enc := ex.resp.Header.Get("Content-Encoding"); enc != "gzip" {
					t.Fatalf("Content-Encoding = %q, want gzip", enc)
				}
				if !slices.Contains(ex.resp.TransferEncoding, "chunked") || ex.resp.Header.Get("Content-Length") != "" {
					t.Errorf("the compressed body is not chunked: Transfer-Encoding %q, Content-Length %q",
						ex.resp.TransferEncoding, ex.resp.Header.Get("Content-Length"))
				}
				if !headerHasToken(ex.resp.Header.Values("Vary"), "Accept-Encoding") {
					t.Errorf("Vary = %q, want Accept-Encoding in it", ex.resp.Header.Values("Vary"))
				}
				if got := gunzip(t, ex.body); got != phpPage {
					t.Errorf("the body decodes to %d bytes, want the %d PHP wrote", len(got), len(phpPage))
				}
				if len(ex.body) >= len(phpPage)/4 {
					t.Errorf("the body is %d bytes compressed, from %d", len(ex.body), len(phpPage))
				}
			})
		}
	}
}

// The validators and ranges of the plain body do not describe the compressed one.
func TestHandleStream_ACompressedBodyKeepsNoStrongValidator(t *testing.T) {
	ex := exchangeWith(t, false, serveWithLength("application/json", phpPage), rawGet("/api/core/menu/search/", browserAE))
	if got := ex.resp.Header.Get("ETag"); got != `W/"abc"` {
		t.Errorf("ETag = %q, want the weak W/\"abc\"", got)
	}
	if got := ex.resp.Header.Get("Accept-Ranges"); got != "" {
		t.Errorf("Accept-Ranges = %q on a compressed body", got)
	}
}

// Everything else passes as it came, with its framing.
func TestHandleStream_LeavesUncompressed(t *testing.T) {
	small := strings.Repeat("x", gzipMinLength-1)
	tests := []struct {
		name    string
		method  string
		proto   string
		handler http.HandlerFunc
		headers []string
	}{
		{"no Accept-Encoding", "GET", "", servePHP("text/html", http.StatusOK), nil},
		{"gzip refused with q=0", "GET", "", servePHP("text/html", http.StatusOK), []string{"Accept-Encoding: br, gzip;q=0"}},
		{"gzip refused although * is accepted", "GET", "", servePHP("text/html", http.StatusOK), []string{"Accept-Encoding: *, gzip;q=0"}},
		{"identity only", "GET", "", servePHP("text/html", http.StatusOK), []string{"Accept-Encoding: identity"}},
		{"a q that does not parse", "GET", "", servePHP("text/html", http.StatusOK), []string{"Accept-Encoding: gzip;q=high"}},
		{"HEAD", "HEAD", "", servePHP("text/html", http.StatusOK), []string{browserAE}},
		{"an HTTP/1.0 client", "GET", "HTTP/1.0", servePHP("text/html", http.StatusOK), []string{browserAE}},
		{"no content", "GET", "", servePHP("text/html", http.StatusNoContent), []string{browserAE}},
		{"not modified", "GET", "", servePHP("text/html", http.StatusNotModified), []string{browserAE}},
		{"a range", "GET", "", servePHP("text/html", http.StatusPartialContent, "Content-Range", "bytes 0-9/100"), []string{browserAE}},
		{"no-transform", "GET", "", servePHP("text/html", http.StatusOK, "Cache-Control", "private, no-transform"), []string{browserAE}},
		{"an event stream", "GET", "", servePHP("text/event-stream", http.StatusOK), []string{browserAE}},
		{"an image", "GET", "", servePHP("image/png", http.StatusOK), []string{browserAE}},
		{"no Content-Type", "GET", "", servePHP("", http.StatusOK), []string{browserAE}},
		{"a small body", "GET", "", serveWithLength("application/json", small), []string{browserAE}},
		{"a page of another site", "GET", "", servePHP("text/html", http.StatusOK), []string{browserAE, "Sec-Fetch-Site: cross-site"}},
		{"a page of the same site", "GET", "", servePHP("text/html", http.StatusOK), []string{browserAE, "Sec-Fetch-Site: same-site"}},
		{"an Origin of another host", "POST", "", servePHP("text/html", http.StatusOK), []string{browserAE, "Origin: https://attacker.example"}},
		{"a null Origin", "POST", "", servePHP("text/html", http.StatusOK), []string{browserAE, "Origin: null"}},
		{"a Referer of another host", "GET", "", servePHP("text/html", http.StatusOK), []string{browserAE, "Referer: https://attacker.example/page"}},
	}
	for _, session := range proxySessions {
		for _, tt := range tests {
			t.Run(session.name+"/"+tt.name, func(t *testing.T) {
				raw := rawMethod(tt.method, "/ui/core/dashboard", tt.headers...)
				if tt.proto != "" {
					raw = strings.Replace(raw, "HTTP/1.1", tt.proto, 1)
				}
				if tt.method == "POST" {
					raw = strings.Replace(raw, "\r\n\r\n", "\r\nContent-Length: 0\r\n\r\n", 1)
				}
				ex := exchangeWith(t, session.readOnly, tt.handler, raw)
				if session.readOnly && tt.method == "POST" {
					// A read-only session refuses a POST outside /api/: nothing to compress.
					if ex.resp.StatusCode != http.StatusMethodNotAllowed {
						t.Fatalf("status = %d, want the read-only refusal", ex.resp.StatusCode)
					}
					return
				}
				if enc := ex.resp.Header.Get("Content-Encoding"); enc != "" {
					t.Errorf("Content-Encoding = %q, want none", enc)
				}
				if headerHasToken(ex.resp.Header.Values("Vary"), "Accept-Encoding") {
					t.Errorf("Vary = %q on a response that was not compressed", ex.resp.Header.Values("Vary"))
				}
				if tt.method == "HEAD" || !bodyAllowedForStatus(ex.resp.StatusCode) {
					return
				}
				want := phpPage
				if tt.name == "a small body" {
					want = small
				}
				if ex.body != want {
					t.Errorf("the body is %d bytes, want the %d the upstream sent", len(ex.body), len(want))
				}
			})
		}
	}
}

// A read-only session asks OPNsense for the body in the clear and cleans it;
// what it then sends a client that accepts gzip is the cleaned body,
// compressed.
func TestHandleStream_ReadOnlyCompressesTheCleanedBody(t *testing.T) {
	var mu sync.Mutex
	var asked []string
	body := `{"user":{"name":"alice","otp_seed":"SECRETOTPSEED","comment":"` + strings.Repeat("a", 2000) + `"}}`
	cleaned := strings.Replace(body, "SECRETOTPSEED", "", 1)
	handler := func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked = append(asked, r.Header.Values("Accept-Encoding")...)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		_, _ = io.WriteString(w, body)
	}
	ex := exchangeWith(t, true, handler, rawGet("/api/auth/user/get/u1", browserAE))

	mu.Lock()
	defer mu.Unlock()
	if len(asked) != 0 {
		t.Errorf("OPNsense was asked for %q; a scrubbed route asks for the body in the clear", asked)
	}
	if enc := ex.resp.Header.Get("Content-Encoding"); enc != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", enc)
	}
	if got := gunzip(t, ex.body); got != cleaned {
		t.Errorf("the body decodes to %s\nwant %s", got, cleaned)
	}
}

// A compressed answer that streams still streams: what has arrived can be
// decoded before the rest is sent.
func TestHandleStream_ACompressedAnswerStillStreams(t *testing.T) {
	first := strings.Repeat("<p>first part</p>\n", 200)
	second := strings.Repeat("<p>second part</p>\n", 200)
	for _, session := range proxySessions {
		t.Run(session.name, func(t *testing.T) {
			release := make(chan struct{})
			releaseSecond := sync.OnceFunc(func() { close(release) })
			defer releaseSecond()
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				_, _ = io.WriteString(w, first)
				w.(http.Flusher).Flush()
				select {
				case <-release:
				case <-r.Context().Done():
					return
				}
				_, _ = io.WriteString(w, second)
			}))
			defer ts.Close()
			proxy := newHandleStreamTestProxy(t, ts, session.readOnly)
			stream, cap := newHandleStreamTestStream()
			defer closeHandleStreamTestStream(stream)
			done := runHandleStream(proxy, stream)
			stream.readBuf <- []byte(rawGet("/ui/diagnostics/log/core/system", browserAE))

			if !decodesTo(cap, first) {
				t.Fatalf("the first part could not be decoded while the answer was still open (%d bytes captured)", len(cap.dataBytes()))
			}
			releaseSecond()
			resp := waitForHandleStreamResponse(t, cap)
			body, _ := io.ReadAll(resp.Body)
			if got := gunzip(t, string(body)); got != first+second {
				t.Errorf("the answer decodes to %d bytes, want %d", len(got), len(first+second))
			}
			closeHandleStreamTestStream(stream)
			waitHandleStreamDone(t, done)
		})
	}
}

// decodesTo reports whether the captured response's body so far decodes to
// at least want, within 5 seconds.
func decodesTo(cap *handleStreamCapture, want string) bool {
	return eventually(func() bool {
		_, rest, ok := bytes.Cut(cap.dataBytes(), []byte("\r\n\r\n"))
		if !ok {
			return false
		}
		chunks := httputil.NewChunkedReader(bytes.NewReader(rest))
		zr, err := gzip.NewReader(bufio.NewReader(chunks))
		if err != nil {
			return false
		}
		got := make([]byte, len(want))
		if _, err := io.ReadFull(zr, got); err != nil {
			return false
		}
		return string(got) == want
	})
}

func eventually(cond func() bool) bool {
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(5 * time.Millisecond)
	}
	return true
}

func TestAcceptsGzip(t *testing.T) {
	tests := []struct {
		lines []string
		want  bool
	}{
		{nil, false},
		{[]string{""}, false},
		{[]string{"gzip"}, true},
		{[]string{"GZIP"}, true},
		{[]string{"x-gzip"}, true},
		{[]string{"deflate, gzip;q=0.1"}, true},
		{[]string{"gzip; q=0"}, false},
		{[]string{"gzip;q=0.000"}, false},
		{[]string{"*"}, true},
		{[]string{"*;q=0"}, false},
		{[]string{"*, gzip;q=0"}, false},
		{[]string{"br", "gzip"}, true},
		{[]string{"identity"}, false},
		{[]string{"gzip;q=x"}, false},
	}
	for _, tt := range tests {
		if got := acceptsGzip(tt.lines); got != tt.want {
			t.Errorf("acceptsGzip(%q) = %v, want %v", tt.lines, got, tt.want)
		}
	}
}
