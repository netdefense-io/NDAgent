package pathfinder

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// exchange is what a client on a webadmin stream sees of one request.
type exchange struct {
	resp   *http.Response
	body   string
	raw    []byte // every byte the stream carried to the client
	closed bool   // the proxy sent CLOSE before the client closed the stream
}

func rawGet(target string, headers ...string) string {
	return rawMethod("GET", target, headers...)
}

func rawMethod(method, target string, headers ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: 127.0.0.1\r\n", method, target)
	for _, h := range headers {
		b.WriteString(h + "\r\n")
	}
	b.WriteString("\r\n")
	return b.String()
}

// exchangeWith puts one request on a stream of its own, behind a proxy that is
// read-only or not, against the handler standing in for local OPNsense.
func exchangeWith(t *testing.T, readOnly bool, handler http.HandlerFunc, raw string) *exchange {
	t.Helper()
	ts := httptest.NewTLSServer(handler)
	defer ts.Close()
	proxy := newHandleStreamTestProxy(t, ts, readOnly)
	stream, cap := newHandleStreamTestStream()
	done := runHandleStream(proxy, stream)
	stream.readBuf <- []byte(raw)

	resp := waitForHandleStreamResponse(t, cap)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the response the client got: %v", err)
	}
	// Give a late write, or a CLOSE sent right behind the response, a moment to show.
	time.Sleep(50 * time.Millisecond)
	ex := &exchange{resp: resp, body: string(body), raw: append([]byte(nil), cap.dataBytes()...), closed: cap.closeSent()}
	closeHandleStreamTestStream(stream)
	if err := waitHandleStreamDone(t, done); err != nil {
		t.Errorf("HandleStream returned %v", err)
	}
	return ex
}

func jsonHandler(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		_, _ = io.WriteString(w, body)
	}
}

const userGetBody = `{"user":{"name":"alice","password":"","apikeys":"","otp_seed":"SECRETOTPSEED","otp_uri":"otpauth://totp/alice@fw?secret=SECRETOTPSEED","shell":{"/bin/sh":{"value":"/bin/sh","selected":1}}}}`
const userGetCleaned = `{"user":{"name":"alice","password":"","apikeys":"","otp_seed":"","otp_uri":"","shell":{"/bin/sh":{"value":"/bin/sh","selected":1}}}}`

func TestHandleStream_ReadOnlyScrubsAJSONResponse(t *testing.T) {
	ex := exchangeWith(t, true, jsonHandler(userGetBody), rawGet("/api/auth/user/get/u1"))

	if ex.resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", ex.resp.StatusCode)
	}
	if ex.body != userGetCleaned {
		t.Errorf("body = %s\nwant   %s", ex.body, userGetCleaned)
	}
	if bytes.Contains(ex.raw, []byte("SECRET")) {
		t.Errorf("a secret reached the stream: %s", ex.raw)
	}
	if got := ex.resp.Header.Get("Content-Type"); got != "application/json; charset=UTF-8" {
		t.Errorf("Content-Type = %q", got)
	}
	if ex.resp.ContentLength != int64(len(userGetCleaned)) {
		t.Errorf("Content-Length = %d, want %d", ex.resp.ContentLength, len(userGetCleaned))
	}
	if len(ex.resp.TransferEncoding) != 0 {
		t.Errorf("Transfer-Encoding = %v on a body of known length", ex.resp.TransferEncoding)
	}
	if ex.closed {
		t.Error("the stream was closed after a response that was fine")
	}
}

// A read-write session is not filtered, and the same backend hands it the secret.
func TestHandleStream_ReadWriteSessionIsNotScrubbed(t *testing.T) {
	ex := exchangeWith(t, false, jsonHandler(userGetBody), rawGet("/api/auth/user/get/u1"))
	if ex.body != userGetBody {
		t.Errorf("a read-write session got %s\nwant %s", ex.body, userGetBody)
	}
}

// The body is rewritten whole, so the request must ask for it in the clear: the
// client's Accept-Encoding and Range never reach OPNsense, and what the
// transport decodes is what is cleaned.
func TestHandleStream_ReadOnlyScrubbedRouteAsksForAWholeIdentityBody(t *testing.T) {
	var mu sync.Mutex
	var seen http.Header
	handler := func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = r.Header.Clone()
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			zw := gzip.NewWriter(w)
			_, _ = io.WriteString(zw, userGetBody)
			_ = zw.Close()
			return
		}
		_, _ = io.WriteString(w, userGetBody)
	}
	ex := exchangeWith(t, true, handler, rawGet("/api/auth/user/get/u1",
		"Accept-Encoding: gzip, deflate, br", "Range: bytes=0-20", "If-Range: \"abc\"", "Accept: application/json"))

	mu.Lock()
	defer mu.Unlock()
	if ae := seen.Get("Accept-Encoding"); strings.Contains(ae, "br") || strings.Contains(ae, "deflate") {
		t.Errorf("the client's Accept-Encoding reached OPNsense: %q", ae)
	}
	if seen.Get("Range") != "" || seen.Get("If-Range") != "" {
		t.Errorf("Range reached OPNsense: %q %q", seen.Get("Range"), seen.Get("If-Range"))
	}
	if seen.Get("Accept") != "application/json" {
		t.Errorf("Accept = %q, the other headers must still be forwarded", seen.Get("Accept"))
	}
	if ex.body != userGetCleaned {
		t.Errorf("a gzip response was not cleaned: %s", ex.body)
	}
	if enc := ex.resp.Header.Get("Content-Encoding"); enc != "" {
		t.Errorf("Content-Encoding = %q on a body the proxy decoded", enc)
	}
}

// A route that is not scrubbed is forwarded as it always was, headers included.
func TestHandleStream_ReadOnlyUnscrubbedRouteKeepsItsHeaders(t *testing.T) {
	var mu sync.Mutex
	var seen http.Header
	handler := func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = r.Header.Clone()
		mu.Unlock()
		jsonHandler(`{"rows":[]}`)(w, r)
	}
	exchangeWith(t, true, handler, rawGet("/api/firewall/filter/get_interface_list", "Accept-Encoding: identity", "Range: bytes=0-5"))
	mu.Lock()
	defer mu.Unlock()
	if seen.Get("Accept-Encoding") != "identity" || seen.Get("Range") != "bytes=0-5" {
		t.Errorf("headers of an unscrubbed route changed: %v", seen)
	}
}

// An upstream body without a length, sent in pieces, is held and written with one.
func TestHandleStream_ReadOnlyScrubbedChunkedUpstream(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fl := w.(http.Flusher)
		for _, part := range []string{`{"rows":[{"name":"a","pass`, `word":"SECRET-ONE"},{"name":"b",`, `"password":"SECRET-TWO"}],"total":2}`} {
			_, _ = io.WriteString(w, part)
			fl.Flush()
			time.Sleep(10 * time.Millisecond)
		}
	}
	ex := exchangeWith(t, true, handler, rawMethod("POST", "/api/firewall/alias/search_item", "Content-Length: 0"))
	const want = `{"rows":[{"name":"a","password":""},{"name":"b","password":""}],"total":2}`
	if ex.body != want {
		t.Errorf("body = %s\nwant   %s", ex.body, want)
	}
	if bytes.Contains(ex.raw, []byte("SECRET")) {
		t.Errorf("a secret reached the stream: %s", ex.raw)
	}
	if ex.resp.ContentLength != int64(len(want)) {
		t.Errorf("Content-Length = %d, want %d", ex.resp.ContentLength, len(want))
	}
}

// The next request of the same stream is answered after a cleaned response.
func TestHandleStream_ReadOnlyStreamContinuesAfterAScrubbedResponse(t *testing.T) {
	ts := httptest.NewTLSServer(jsonHandler(userGetBody))
	defer ts.Close()
	proxy := newHandleStreamTestProxy(t, ts, true)
	stream, cap := newHandleStreamTestStream()
	done := runHandleStream(proxy, stream)

	for i := 0; i < 2; i++ {
		stream.readBuf <- []byte(rawGet("/api/auth/user/get/u1"))
		deadline := time.Now().Add(5 * time.Second)
		for strings.Count(string(cap.dataBytes()), userGetCleaned) < i+1 {
			if time.Now().After(deadline) {
				t.Fatalf("request %d was not answered: %s", i+1, cap.dataBytes())
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	if bytes.Contains(cap.dataBytes(), []byte("SECRET")) {
		t.Errorf("a secret reached the stream: %s", cap.dataBytes())
	}
	closeHandleStreamTestStream(stream)
	waitHandleStreamDone(t, done)
}

// A response the proxy cannot clean is withheld whole: nothing of it reaches the
// client, and the exchange ends.
func TestHandleStream_ReadOnlyWithholdsWhatItCannotClean(t *testing.T) {
	const loginPage = "<html><body>Login SECRET-LEAK</body></html>"
	tests := []struct {
		name    string
		target  string
		handler http.HandlerFunc
		cause   string // what the body of the answer says
	}{
		{
			name:   "an HTML page where JSON is expected",
			cause:  "not the JSON",
			target: "/api/auth/user/get/u1",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				_, _ = io.WriteString(w, loginPage)
			},
		},
		{
			name:   "an HTML error page",
			cause:  "not the JSON",
			target: "/api/trust/cert/get/c1",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = io.WriteString(w, loginPage)
			},
		},
		{
			name:    "a JSON document that is cut short",
			cause:   "not the JSON",
			target:  "/api/auth/user/get/u1",
			handler: jsonHandler(`{"user":{"otp_seed":"SECRET-LEAK","name":"al`),
		},
		{
			name:   "a body that ends before its declared length",
			cause:  "could not be read",
			target: "/api/auth/user/get/u1",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Length", "500")
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"user":{"otp_seed":"SECRET-LEAK"`)
				if hj, ok := w.(http.Hijacker); ok {
					c, _, _ := hj.Hijack()
					_ = c.Close()
				}
			},
		},
		{
			name:   "an encoding the proxy cannot undo",
			cause:  "encoded",
			target: "/api/auth/user/get/u1",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Content-Encoding", "br")
				_, _ = io.WriteString(w, `{"user":{"otp_seed":"SECRET-LEAK"}}`)
			},
		},
		{
			name:   "a body larger than the proxy holds",
			cause:  "larger than 8 MiB",
			target: "/api/auth/user/search",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"rows":[{"otp_seed":"SECRET-LEAK","pad":"`)
				_, _ = w.Write(bytes.Repeat([]byte("a"), maxScrubBytes))
				_, _ = io.WriteString(w, `"}]}`)
			},
		},
		{
			name:   "an HTML page with an input tag that is not closed",
			cause:  "not closed",
			target: "/interfaces_ppps_edit.php?id=0",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				_, _ = io.WriteString(w, `<html><input name="password" value="SECRET-LEAK"`)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method := "GET"
			raw := rawGet(tt.target)
			if strings.HasSuffix(tt.target, "/search") {
				method, raw = "POST", rawMethod("POST", tt.target, "Content-Length: 0")
			}
			_ = method
			ex := exchangeWith(t, true, tt.handler, raw)
			if ex.resp.StatusCode != http.StatusBadGateway {
				t.Errorf("status = %d, want 502", ex.resp.StatusCode)
			}
			if bytes.Contains(ex.raw, []byte("SECRET-LEAK")) || bytes.Contains(ex.raw, []byte("Login")) {
				t.Errorf("part of the upstream response reached the client: %.200s", ex.raw)
			}
			if want := "502 Bad Gateway (read-only session: response withheld)"; ex.resp.Status != want {
				t.Errorf("Status = %q, want %q", ex.resp.Status, want)
			}
			if !strings.Contains(ex.body, tt.cause) {
				t.Errorf("the body of the answer is %q, want it to name the cause (%q)", ex.body, tt.cause)
			}
			if ex.closed {
				t.Error("the proxy closed the stream right behind a withheld response; the client closes it once it has read the response")
			}
			if !ex.resp.Close {
				t.Error("the response does not say Connection: close")
			}
		})
	}
}

// What has no body, or none to clean, is forwarded as it is.
func TestHandleStream_ReadOnlyScrubbedRouteForwardsWhatHasNothingToClean(t *testing.T) {
	t.Run("an empty body", func(t *testing.T) {
		ex := exchangeWith(t, true, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }, rawGet("/api/auth/user/get/u1"))
		if ex.resp.StatusCode != http.StatusOK || ex.body != "" || ex.closed {
			t.Errorf("got %d %q (closed %v)", ex.resp.StatusCode, ex.body, ex.closed)
		}
	})
	t.Run("no content", func(t *testing.T) {
		ex := exchangeWith(t, true, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }, rawGet("/api/auth/user/get/u1"))
		if ex.resp.StatusCode != http.StatusNoContent || ex.closed {
			t.Errorf("got %d (closed %v)", ex.resp.StatusCode, ex.closed)
		}
	})
	t.Run("not modified", func(t *testing.T) {
		ex := exchangeWith(t, true, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotModified) }, rawGet("/api/auth/user/get/u1", "If-None-Match: \"x\""))
		if ex.resp.StatusCode != http.StatusNotModified || ex.closed {
			t.Errorf("got %d (closed %v)", ex.resp.StatusCode, ex.closed)
		}
	})
	t.Run("a refusal in JSON is cleaned like any other", func(t *testing.T) {
		handler := func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"status":403,"message":"User alice denied for write access (user-config-readonly set)","password":"echo"}`)
		}
		ex := exchangeWith(t, true, handler, rawGet("/api/auth/user/get/u1"))
		if ex.resp.StatusCode != http.StatusForbidden || !strings.Contains(ex.body, "user-config-readonly") || strings.Contains(ex.body, "echo") {
			t.Errorf("got %d %s", ex.resp.StatusCode, ex.body)
		}
	})
}

// A HEAD runs the handler and answers with the length of the body it does not send,
// which is the length of the response before its secrets are blanked. The proxy has
// no body to clean in it, so a HEAD to a route whose response is cleaned is refused,
// and never reaches OPNsense.
func TestHandleStream_ReadOnlyRefusesAHEADToAScrubbedRoute(t *testing.T) {
	ts, hits := newSentinelBackend("the length of this body is the length of a secret")
	defer ts.Close()

	var requests []streamRequest
	for _, tt := range scrubCases {
		requests = append(requests, streamRequest{rawMethod("HEAD", tt.target, "Content-Length: 0"), refused})
	}
	requests = append(requests,
		streamRequest{rawMethod("HEAD", "/interfaces_ppps_edit.php?id=0", "Content-Length: 0"), refused},
		streamRequest{rawMethod("HEAD", "/INTERFACES_PPPS_EDIT.php?id=0", "Content-Length: 0"), refused},
	)
	assertRefusedOnStreams(t, newHandleStreamTestProxy(t, ts, true), requests, hits)
}

// The legacy pages go through the same gate: a page is cleaned of its fields and
// keeps the rest.
func TestHandleStream_ReadOnlyScrubsALegacyPage(t *testing.T) {
	page := pageHead +
		`<input name="username" type="text" id="username" value="isp-user" />` + "\n" +
		`<input name="password" type="password" autocomplete="new-password" id="password" value="SECRET-PPP" />` + "\n</form></body></html>"
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		_, _ = io.WriteString(w, page)
	}
	ex := exchangeWith(t, true, handler, rawGet("/interfaces_ppps_edit.php?id=0", "Accept-Encoding: gzip"))
	want := strings.Replace(page, "SECRET-PPP", "", 1)
	if ex.body != want {
		t.Errorf("page = %q\nwant   %q", ex.body, want)
	}
	if bytes.Contains(ex.raw, []byte("SECRET")) {
		t.Errorf("a secret reached the stream: %s", ex.raw)
	}
	if got := ex.resp.Header.Get("Content-Type"); got != "text/html; charset=UTF-8" {
		t.Errorf("Content-Type = %q", got)
	}
}

// A route that is not scrubbed still streams: the proxy writes each piece as it
// arrives instead of holding the response.
func TestHandleStream_ReadOnlyUnscrubbedRouteStillStreams(t *testing.T) {
	release := make(chan struct{})
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fl := w.(http.Flusher)
		_, _ = io.WriteString(w, "data: first\n\n")
		fl.Flush()
		<-release
		_, _ = io.WriteString(w, "data: second\n\n")
		fl.Flush()
	}
	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	proxy := newHandleStreamTestProxy(t, ts, true)
	stream, cap := newHandleStreamTestStream()
	done := runHandleStream(proxy, stream)
	stream.readBuf <- []byte(rawGet("/api/diagnostics/firewall/stream_log"))

	deadline := time.Now().Add(5 * time.Second)
	for !bytes.Contains(cap.dataBytes(), []byte("data: first")) {
		if time.Now().After(deadline) {
			t.Fatalf("the first event did not arrive while the response was still open: %s", cap.dataBytes())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if bytes.Contains(cap.dataBytes(), []byte("data: second")) {
		t.Fatal("the second event arrived before it was sent")
	}
	close(release)
	deadline = time.Now().Add(5 * time.Second)
	for !bytes.Contains(cap.dataBytes(), []byte("data: second")) {
		if time.Now().After(deadline) {
			t.Fatalf("the second event never arrived: %s", cap.dataBytes())
		}
		time.Sleep(5 * time.Millisecond)
	}
	closeHandleStreamTestStream(stream)
	waitHandleStreamDone(t, done)
}

// Every route of the audit, through the proxy, gives a client none of the planted
// secrets, whatever the method of the request.
func TestHandleStream_ReadOnlyCleansEveryAuditedRoute(t *testing.T) {
	for _, tt := range scrubCases {
		t.Run(tt.method+" "+tt.target, func(t *testing.T) {
			raw := rawMethod(tt.method, tt.target)
			if tt.method == "POST" {
				raw = rawMethod("POST", tt.target, "Content-Length: 0")
			}
			ex := exchangeWith(t, true, jsonHandler(tt.body), raw)
			if ex.resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d: %s", ex.resp.StatusCode, ex.body)
			}
			if bytes.Contains(ex.raw, []byte("SECRET")) {
				t.Errorf("a secret reached the stream: %.300s", ex.raw)
			}
			for _, keep := range tt.keeps {
				if !strings.Contains(ex.body, keep) {
					t.Errorf("%q is gone from %s", keep, ex.body)
				}
			}
		})
	}
}
