package opnapi

// read_retry_test.go — reads are repeated when their response arrives
// corrupt; nothing else is.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// lighttpdChunk is the chunk size lighttpd streams API responses in.
const lighttpdChunk = 0xfff8

// scriptedRequest is what a scriptedServer received for one request.
type scriptedRequest struct {
	line          string // "METHOD path"
	authorization string
	contentType   string
	body          []byte
}

func (r scriptedRequest) String() string {
	return fmt.Sprintf("%s authorization=%q content-type=%q body=%q", r.line, r.authorization, r.contentType, r.body)
}

// scriptedServer is a raw TCP server that answers the Nth request with the Nth
// canned response (the last one repeats) and closes the connection, so every
// attempt is a fresh connection. httptest cannot emit a malformed chunk.
type scriptedServer struct {
	URL string

	mu      sync.Mutex
	replies [][]byte
	seen    []scriptedRequest
}

func newScriptedServer(t *testing.T, replies ...[]byte) *scriptedServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	s := &scriptedServer{URL: "http://" + ln.Addr().String(), replies: replies}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(conn)
		}
	}()
	return s
}

func (s *scriptedServer) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	br := bufio.NewReader(conn)
	requestLine, err := br.ReadString('\n')
	if err != nil {
		return
	}
	fields := strings.Fields(requestLine)
	if len(fields) < 2 {
		return
	}
	req := scriptedRequest{line: fields[0] + " " + fields[1]}

	contentLength := 0
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		if line == "\r\n" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch {
		case strings.EqualFold(name, "Content-Length"):
			contentLength, _ = strconv.Atoi(value)
		case strings.EqualFold(name, "Authorization"):
			req.authorization = value
		case strings.EqualFold(name, "Content-Type"):
			req.contentType = value
		}
	}
	req.body = make([]byte, contentLength)
	n, _ := io.ReadFull(br, req.body)
	req.body = req.body[:n]

	s.mu.Lock()
	s.seen = append(s.seen, req)
	reply := s.replies[min(len(s.seen), len(s.replies))-1]
	s.mu.Unlock()

	_, _ = conn.Write(reply)
}

// requests lists "METHOD path" for every request received, in order.
func (s *scriptedServer) requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	lines := make([]string, len(s.seen))
	for i, req := range s.seen {
		lines[i] = req.line
	}
	return lines
}

// requireIdenticalAttempts fails unless the server received exactly attempts
// requests and every one repeats the first: method, path, credentials, content
// type and body. A retry that drops or changes the body of a search POST
// would ask OPNsense a different question, and get back a different row set.
// It returns the first request for further checks.
func requireIdenticalAttempts(t *testing.T, srv *scriptedServer, attempts int) scriptedRequest {
	t.Helper()

	srv.mu.Lock()
	got := append([]scriptedRequest(nil), srv.seen...)
	srv.mu.Unlock()

	if len(got) != attempts {
		t.Fatalf("server received %d requests, want %d: %v", len(got), attempts, got)
	}

	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("key:secret"))
	first := got[0]
	if first.authorization != wantAuth {
		t.Errorf("attempt 1 authorization = %q, want %q", first.authorization, wantAuth)
	}
	for i, again := range got[1:] {
		if again.line != first.line ||
			again.authorization != first.authorization ||
			again.contentType != first.contentType ||
			!bytes.Equal(again.body, first.body) {
			t.Errorf("attempt %d is not the same request as attempt 1:\n  attempt 1: %v\n  attempt %d: %v", i+2, first, i+2, again)
		}
	}
	return first
}

const chunkedHead = "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=UTF-8\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"

func appendChunk(dst []byte, declared int, data []byte) []byte {
	dst = append(dst, fmt.Sprintf("%x\r\n", declared)...)
	dst = append(dst, data...)
	return append(dst, "\r\n"...)
}

// goodReply is body as lighttpd frames it when nothing goes wrong.
func goodReply(body []byte) []byte {
	out := []byte(chunkedHead)
	for rest := body; len(rest) > 0; {
		n := min(len(rest), lighttpdChunk)
		out = appendChunk(out, n, rest[:n])
		rest = rest[n:]
	}
	return append(out, "0\r\n\r\n"...)
}

// replayCorruptedReply is the shape captured from lighttpd 1.4.85 on FreeBSD
// 15.1 kTLS: the first chunk declares 0xfff8 bytes but the sender re-sends the
// 16136 bytes it had just written (a 16 KiB-aligned replay) before going on,
// so the bytes after the declared size are data where the chunk's CRLF belongs.
func replayCorruptedReply(body []byte) []byte {
	const replay = 16136
	at := 48904 + replay

	first := append([]byte(nil), body[:at]...)
	first = append(first, body[at-replay:at]...)
	first = append(first, body[at:lighttpdChunk]...)

	out := appendChunk([]byte(chunkedHead), lighttpdChunk, first)
	out = appendChunk(out, len(body)-lighttpdChunk, body[lighttpdChunk:])
	return append(out, "0\r\n\r\n"...)
}

// garbledChunkSizeReply puts bytes where a chunk-size line belongs.
func garbledChunkSizeReply(body []byte) []byte {
	out := appendChunk([]byte(chunkedHead), lighttpdChunk, body[:lighttpdChunk])
	return append(out, "zz replayed bytes\r\n"...)
}

// cutShortReply closes the connection after the first chunk, the "bad length"
// truncation at 65,528 bytes seen in lighttpd's log.
func cutShortReply(body []byte) []byte {
	return appendChunk([]byte(chunkedHead), lighttpdChunk, body[:lighttpdChunk])
}

// invalidJSONReply is well framed but the body stops mid-document.
func invalidJSONReply(body []byte) []byte {
	return goodReply(body[:len(body)/2])
}

func statusReply(code int, body string) []byte {
	return []byte(fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, http.StatusText(code), len(body), body))
}

// listBody is a JSON list response of about 120 KB, larger than one lighttpd
// chunk, shaped so it decodes as a search response and as a service list.
func listBody(t *testing.T) []byte {
	t.Helper()
	rows := make([]map[string]interface{}, 600)
	for i := range rows {
		rows[i] = map[string]interface{}{
			"uuid":        fmt.Sprintf("221f3268-0001-4abc-9001-%012d", i),
			"name":        fmt.Sprintf("row-%d", i),
			"description": strings.Repeat("padding ", 24),
			"running":     1,
		}
	}
	body, err := json.Marshal(map[string]interface{}{"rows": rows, "rowCount": len(rows), "total": len(rows)})
	if err != nil {
		t.Fatal(err)
	}
	if len(body) < 2*lighttpdChunk {
		t.Fatalf("fixture body is %d bytes, want more than two chunks", len(body))
	}
	return body
}

func fastRetries(t *testing.T) {
	t.Helper()
	prev := readRetryBackoff
	readRetryBackoff = time.Millisecond
	t.Cleanup(func() { readRetryBackoff = prev })
}

func newRetryClient(url string) *Client {
	return NewClient(url, "key", "secret", true)
}

func TestReadRetry_RecoversFromCorruption(t *testing.T) {
	fastRetries(t)
	body := listBody(t)

	cases := map[string]struct {
		replies [][]byte
		wantHit int
	}{
		"replayed block inside a chunk": {[][]byte{replayCorruptedReply(body), goodReply(body)}, 2},
		"garbage as a chunk size":       {[][]byte{garbledChunkSizeReply(body), goodReply(body)}, 2},
		"connection cut after a chunk":  {[][]byte{cutShortReply(body), goodReply(body)}, 2},
		"body stops mid-document":       {[][]byte{invalidJSONReply(body), goodReply(body)}, 2},
		"corrupt twice, then intact":    {[][]byte{replayCorruptedReply(body), cutShortReply(body), goodReply(body)}, 3},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			srv := newScriptedServer(t, tc.replies...)

			services, err := newRetryClient(srv.URL).ListServices(context.Background())
			if err != nil {
				t.Fatalf("ListServices() error = %v", err)
			}
			if len(services) != 600 {
				t.Errorf("got %d services, want 600", len(services))
			}
			requireIdenticalAttempts(t, srv, tc.wantHit)
		})
	}
}

// TestReadRetry_RecoversSearchPOST runs a page of the rule search: a retry must
// ask the same question, page included, or OPNsense answers with a different
// row set.
func TestReadRetry_RecoversSearchPOST(t *testing.T) {
	fastRetries(t)
	body := listBody(t)
	srv := newScriptedServer(t, replayCorruptedReply(body), cutShortReply(body), goodReply(body))

	resp, err := newRetryClient(srv.URL).searchRulePage(context.Background(), "nd-", 2, ruleSearchPageSize)
	if err != nil {
		t.Fatalf("searchRulePage() error = %v", err)
	}
	if len(resp.Rows) != 600 {
		t.Errorf("got %d rules, want 600", len(resp.Rows))
	}

	first := requireIdenticalAttempts(t, srv, 3)
	if first.line != "POST /firewall/filter/searchRule" {
		t.Errorf("request = %q, want the rule search POST", first.line)
	}
	if first.contentType != "application/json" {
		t.Errorf("content type = %q, want application/json", first.contentType)
	}
	var sent RuleSearchRequest
	if err := json.Unmarshal(first.body, &sent); err != nil {
		t.Fatalf("body %q is not the search request: %v", first.body, err)
	}
	if sent.Current != 2 || sent.SearchPhrase != "nd-" || sent.RowCount != ruleSearchPageSize {
		t.Errorf("body = %+v, want the page, phrase and row count the caller asked for", sent)
	}
}

func TestReadRetry_EveryReadOnlyPOSTIsRetried(t *testing.T) {
	fastRetries(t)
	body := listBody(t)

	for path := range readOnlyPOSTs {
		t.Run(path, func(t *testing.T) {
			srv := newScriptedServer(t, replayCorruptedReply(body), goodReply(body))
			got, err := newRetryClient(srv.URL).doRequest(context.Background(), "POST", path, SearchRequest{SearchPhrase: "needle"})
			if err != nil {
				t.Fatalf("doRequest() error = %v", err)
			}
			if !bytes.Equal(got, body) {
				t.Errorf("returned %d bytes, want the intact %d", len(got), len(body))
			}

			first := requireIdenticalAttempts(t, srv, 2)
			if want := "POST " + path; first.line != want {
				t.Errorf("request = %q, want %q", first.line, want)
			}
			if first.contentType != "application/json" || string(first.body) != `{"searchPhrase":"needle"}` {
				t.Errorf("request carried content type %q and body %q, want the JSON search", first.contentType, first.body)
			}
		})
	}
}

// TestReadRetry_CapHolds pins the bound: one attempt plus two retries, then the
// last failure is returned as it always was.
func TestReadRetry_CapHolds(t *testing.T) {
	fastRetries(t)
	body := listBody(t)

	t.Run("framing error", func(t *testing.T) {
		srv := newScriptedServer(t, replayCorruptedReply(body))
		_, err := newRetryClient(srv.URL).ListServices(context.Background())
		if err == nil || !strings.Contains(err.Error(), "malformed chunked encoding") {
			t.Fatalf("error = %v, want malformed chunked encoding", err)
		}
		if got := len(srv.requests()); got != 3 {
			t.Errorf("took %d requests, want 3 (1 attempt + 2 retries)", got)
		}
	})

	t.Run("truncation", func(t *testing.T) {
		srv := newScriptedServer(t, cutShortReply(body))
		_, err := newRetryClient(srv.URL).ListServices(context.Background())
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("error = %v, want unexpected EOF", err)
		}
		if got := len(srv.requests()); got != 3 {
			t.Errorf("took %d requests, want 3", got)
		}
	})

	t.Run("invalid JSON reaches the caller's own decode error", func(t *testing.T) {
		srv := newScriptedServer(t, invalidJSONReply(body))
		_, err := newRetryClient(srv.URL).ListServices(context.Background())
		if err == nil || !strings.Contains(err.Error(), "service search decode") {
			t.Fatalf("error = %v, want the caller's decode error", err)
		}
		if got := len(srv.requests()); got != 3 {
			t.Errorf("took %d requests, want 3", got)
		}
	})
}

// TestReadRetry_NeverRetriesMutations is the safety half of the feature: a
// mutation whose response arrives corrupt may have been applied, and asking
// again is not the client's decision to make.
func TestReadRetry_NeverRetriesMutations(t *testing.T) {
	fastRetries(t)
	body := listBody(t)
	ctx := context.Background()
	const uuid = "221f3268-0001-4abc-9001-000000000001"

	mutations := map[string]func(*Client) error{
		"SetAlias":              func(c *Client) error { return c.SetAlias(ctx, uuid, map[string]string{"name": "a"}) },
		"DeleteAlias":           func(c *Client) error { return c.DeleteAlias(ctx, uuid) },
		"ReconfigureAliases":    func(c *Client) error { return c.ReconfigureAliases(ctx) },
		"SetRule":               func(c *Client) error { return c.SetRule(ctx, uuid, map[string]string{"description": "r"}) },
		"DeleteRule":            func(c *Client) error { return c.DeleteRule(ctx, uuid) },
		"ApplyRules":            func(c *Client) error { return c.ApplyRules(ctx) },
		"AddUser":               func(c *Client) error { _, err := c.AddUser(ctx, User{Name: "u"}); return err },
		"DeleteUser":            func(c *Client) error { return c.DeleteUser(ctx, uuid) },
		"DeleteGroup":           func(c *Client) error { return c.DeleteGroup(ctx, uuid) },
		"ReconfigureUnbound":    func(c *Client) error { return c.ReconfigureUnbound(ctx) },
		"ReconfigureWireGuard":  func(c *Client) error { return c.ReconfigureWireGuard(ctx) },
		"ReconfigureZabbix":     func(c *Client) error { return c.ReconfigureZabbix(ctx) },
		"DeleteServer":          func(c *Client) error { return c.DeleteServer(ctx, uuid) },
		"ToggleZabbixAlias":     func(c *Client) error { return c.ToggleZabbixAlias(ctx, uuid, nil) },
		"TriggerFirmwareCheck":  func(c *Client) error { return c.TriggerFirmwareCheck(ctx) },
		"TriggerFirmwareUpdate": func(c *Client) error { _, err := c.TriggerFirmwareUpdate(ctx); return err },
		"TriggerFirmwareUpgrade": func(c *Client) error {
			_, err := c.TriggerFirmwareUpgrade(ctx)
			return err
		},
	}

	for name, call := range mutations {
		t.Run(name, func(t *testing.T) {
			srv := newScriptedServer(t, replayCorruptedReply(body), goodReply([]byte(`{"result":"saved"}`)))
			if err := call(newRetryClient(srv.URL)); err == nil {
				t.Error("want the corrupt response returned as an error")
			}
			if got := len(srv.requests()); got != 1 {
				t.Errorf("sent %d requests, want exactly 1: %v", got, srv.requests())
			}
		})
	}
}

func TestReadRetry_OnlyReadsAreRepeatable(t *testing.T) {
	cases := []struct {
		method, path string
		want         bool
	}{
		{"GET", "/core/firmware/status", true},
		{"GET", "/firewall/filter/getRule/221f3268-0002-4abc-9001-000000000001", true},
		{"GET", "/zabbixagent/settings/searchAliases/?searchPhrase=nd-", true},
		{"POST", "/firewall/filter/searchRule", true},
		{"POST", "/firewall/alias/searchItem", true},
		{"POST", "/firewall/alias/setItem/221f3268-0001-4abc-9001-000000000001", false},
		{"POST", "/firewall/alias/reconfigure", false},
		{"POST", "/firewall/filter/apply", false},
		{"POST", "/core/firmware/check", false},
		{"POST", "/core/firmware/update", false},
		{"POST", "/core/firmware/upgrade", false},
		{"POST", "/auth/user/add", false},
		{"POST", "/firewall/filter/searchRule/extra", false},
		{"POST", "/firewall/filter/searchRules", false},
		{"PUT", "/firewall/filter/searchRule", false},
		{"DELETE", "/firewall/filter/searchRule", false},
	}
	for _, tc := range cases {
		if got := isIdempotentRead(tc.method, tc.path); got != tc.want {
			t.Errorf("isIdempotentRead(%s %s) = %v, want %v", tc.method, tc.path, got, tc.want)
		}
	}
}

// TestReadRetry_OnlyCorruptionIsRetried keeps the classifier narrow: a refusal,
// a dead server and a timeout are answers, and repeating them only delays them.
func TestReadRetry_OnlyCorruptionIsRetried(t *testing.T) {
	fastRetries(t)

	t.Run("an API error is returned at once", func(t *testing.T) {
		for _, code := range []int{400, 401, 403, 404, 500, 503} {
			srv := newScriptedServer(t, statusReply(code, `{"message":"no"}`), goodReply([]byte(`{}`)))
			_, err := newRetryClient(srv.URL).doRequest(context.Background(), "GET", "/core/service/search", nil)
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != code {
				t.Errorf("status %d: error = %v, want an APIError with that code", code, err)
			}
			if got := len(srv.requests()); got != 1 {
				t.Errorf("status %d: sent %d requests, want 1", code, got)
			}
		}
	})

	t.Run("an error body quoting the framing failure is still an API error", func(t *testing.T) {
		srv := newScriptedServer(t, statusReply(502, `{"message":"malformed chunked encoding"}`), goodReply([]byte(`{}`)))
		_, err := newRetryClient(srv.URL).doRequest(context.Background(), "GET", "/core/service/search", nil)
		if err == nil {
			t.Fatal("want an error")
		}
		if got := len(srv.requests()); got != 1 {
			t.Errorf("sent %d requests, want 1", got)
		}
	})

	t.Run("a timeout is not retried", func(t *testing.T) {
		var hits atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}
		}))
		t.Cleanup(srv.Close)

		client := newRetryClient(srv.URL)
		client.httpClient.Timeout = 50 * time.Millisecond
		if _, err := client.doRequest(context.Background(), "GET", "/core/service/search", nil); err == nil {
			t.Fatal("want a timeout error")
		}
		if got := hits.Load(); got != 1 {
			t.Errorf("server saw %d requests, want 1", got)
		}
	})

	t.Run("an empty-but-valid body needs no retry", func(t *testing.T) {
		srv := newScriptedServer(t, goodReply([]byte(`{"rows":[]}`)))
		if _, err := newRetryClient(srv.URL).doRequest(context.Background(), "GET", "/core/service/search", nil); err != nil {
			t.Fatal(err)
		}
		if got := len(srv.requests()); got != 1 {
			t.Errorf("sent %d requests, want 1", got)
		}
	})
}

// TestReadRetry_BackoffSchedule pins the documented waits, with the production
// default in force: 200 ms before the first retry, 400 ms before the second,
// and nothing once the attempts are spent.
func TestReadRetry_BackoffSchedule(t *testing.T) {
	var waits []time.Duration
	prev := retrySleep
	retrySleep = func(_ context.Context, d time.Duration) error {
		waits = append(waits, d)
		return nil
	}
	t.Cleanup(func() { retrySleep = prev })

	srv := newScriptedServer(t, replayCorruptedReply(listBody(t)))
	if _, err := newRetryClient(srv.URL).ListServices(context.Background()); err == nil {
		t.Fatal("want the corruption returned once the retries are spent")
	}

	want := []time.Duration{200 * time.Millisecond, 400 * time.Millisecond}
	if !slices.Equal(waits, want) {
		t.Errorf("waits = %v, want %v", waits, want)
	}
}

func TestReadRetry_StopsWhenContextEnds(t *testing.T) {
	prev := readRetryBackoff
	readRetryBackoff = time.Hour
	t.Cleanup(func() { readRetryBackoff = prev })

	srv := newScriptedServer(t, replayCorruptedReply(listBody(t)))

	core, logs := observer.New(zap.DebugLevel)
	client := newRetryClient(srv.URL)
	client.log = zap.New(core).Sugar()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := client.ListServices(ctx)
		done <- err
	}()

	// The retry is logged just before the backoff begins.
	deadline := time.Now().Add(5 * time.Second)
	for logs.FilterMessageSnippet("Retrying read").Len() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the read was never retried")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("error = %v, want the cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the backoff outlived the cancelled context")
	}
	if got := len(srv.requests()); got != 1 {
		t.Errorf("sent %d requests, want 1", got)
	}
}

// TestReadRetry_LogsEachRetryAtDebug pins that a retry is visible with its
// endpoint but never above DEBUG: it is routine on an affected box.
func TestReadRetry_LogsEachRetryAtDebug(t *testing.T) {
	fastRetries(t)
	body := listBody(t)
	srv := newScriptedServer(t, replayCorruptedReply(body), cutShortReply(body), goodReply(body))

	core, logs := observer.New(zap.DebugLevel)
	client := newRetryClient(srv.URL)
	client.log = zap.New(core).Sugar()

	if _, err := client.ListServices(context.Background()); err != nil {
		t.Fatal(err)
	}

	retries := logs.FilterMessageSnippet("Retrying read").All()
	if len(retries) != 2 {
		t.Fatalf("got %d retry log entries, want 2: %+v", len(retries), retries)
	}
	for i, entry := range retries {
		if entry.Level != zap.DebugLevel {
			t.Errorf("retry %d logged at %v, want DEBUG", i+1, entry.Level)
		}
		fields := entry.ContextMap()
		if fields["path"] != "/core/service/search" || fields["method"] != "GET" {
			t.Errorf("retry %d fields = %v, want the method and endpoint", i+1, fields)
		}
	}
	if warn := logs.FilterLevelExact(zap.WarnLevel).Len() + logs.FilterLevelExact(zap.InfoLevel).Len(); warn != 0 {
		t.Errorf("a recovered read logged %d entries above DEBUG", warn)
	}
}

// TestReadOnlyPOSTAllowlistMatchesCallSites keeps readOnlyPOSTs honest in both
// directions. It is a cross-check, not the mechanism: the list stays explicit
// so a new endpoint is never retried until someone decides it only reads.
//
// AST-based so a comment naming an endpoint does not count as a call site; only
// literal paths are visible, and every POST built from a UUID is a mutation.
func TestReadOnlyPOSTAllowlistMatchesCallSites(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}

	fset := token.NewFileSet()
	literalPOSTs := map[string]bool{}
	scanned := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		scanned++

		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) < 3 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "doRequest" {
				return true
			}
			method, okMethod := call.Args[1].(*ast.BasicLit)
			path, okPath := call.Args[2].(*ast.BasicLit)
			if okMethod && okPath && method.Kind == token.STRING && path.Kind == token.STRING {
				if m, _ := strconv.Unquote(method.Value); m == "POST" {
					p, _ := strconv.Unquote(path.Value)
					literalPOSTs[p] = true
				}
			}
			return true
		})
	}
	if scanned == 0 || len(literalPOSTs) == 0 {
		t.Fatalf("scanned %d files and found %d literal POST call sites; this check would pass vacuously", scanned, len(literalPOSTs))
	}

	lastSegment := func(path string) string { return path[strings.LastIndex(path, "/")+1:] }

	for path := range readOnlyPOSTs {
		if !literalPOSTs[path] {
			t.Errorf("readOnlyPOSTs lists %s, which no call site sends; drop the stale entry", path)
		}
		if !strings.HasPrefix(lastSegment(path), "search") {
			t.Errorf("readOnlyPOSTs lists %s, which is not a search endpoint; only endpoints that read may be listed", path)
		}
	}
	for path := range literalPOSTs {
		if strings.HasPrefix(lastSegment(path), "search") && !readOnlyPOSTs[path] {
			t.Errorf("POST %s looks like a search but is not in readOnlyPOSTs; add it, or it is never retried", path)
		}
	}
}
