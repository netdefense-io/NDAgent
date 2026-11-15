package pathfinder

import (
	"bytes"
	"compress/gzip"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

// gzipLevel spares the firewall's CPU: PHP pages and JSON shrink to about a
// fifth at this level, close to what the highest level gets.
const gzipLevel = 5

// gzipMinLength is the smallest body with a known length that is compressed.
const gzipMinLength = 1024

// gzipTypes are the media types the proxy compresses. lighttpd already
// compresses its static files, so this is for what PHP writes.
var gzipTypes = map[string]bool{
	"text/html":              true,
	"application/json":       true,
	"text/javascript":        true,
	"application/javascript": true,
	"text/css":               true,
	"image/svg+xml":          true,
}

type gzipState struct {
	zw  *gzip.Writer
	in  []byte
	out bytes.Buffer
}

var gzipStates = sync.Pool{New: func() any {
	zw, _ := gzip.NewWriterLevel(io.Discard, gzipLevel)
	return &gzipState{zw: zw, in: make([]byte, responseBufferSize)}
}}

// gzipAllowed reports whether a response to the request may be compressed:
// the client accepts gzip, takes chunks, and is not a page of another site.
// The headers are the client's own, read before anything is removed from
// them for the upstream.
func gzipAllowed(req *http.Request) bool {
	return req.Method != http.MethodHead && req.ProtoAtLeast(1, 1) &&
		acceptsGzip(req.Header.Values("Accept-Encoding")) && !fromAnotherSite(req)
}

// fromAnotherSite reports whether the request comes from a page of another
// origin. A secret in a compressed response can be read by its length when an
// attacker's page can add text of its choosing to the same response and see
// how long the answer is (BREACH): no answer to such a request is compressed.
func fromAnotherSite(req *http.Request) bool {
	switch strings.ToLower(strings.TrimSpace(req.Header.Get("Sec-Fetch-Site"))) {
	case "cross-site", "same-site":
		return true
	}
	for _, name := range []string{"Origin", "Referer"} {
		v := req.Header.Get(name)
		if v == "" {
			continue
		}
		u, err := url.Parse(v)
		if err != nil || !strings.EqualFold(u.Host, req.Host) {
			return true
		}
	}
	return false
}

// acceptsGzip reports whether the Accept-Encoding lines accept gzip: named
// with a q above 0, or not named and accepted by a "*" with a q above 0.
func acceptsGzip(lines []string) bool {
	gzipQ, starQ := -1.0, -1.0
	for _, line := range lines {
		for item := range strings.SplitSeq(line, ",") {
			name, params, _ := strings.Cut(item, ";")
			q := 1.0
			for param := range strings.SplitSeq(params, ";") {
				k, v, ok := strings.Cut(strings.TrimSpace(param), "=")
				if ok && strings.EqualFold(strings.TrimSpace(k), "q") {
					parsed, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
					if err != nil {
						parsed = 0
					}
					q = parsed
				}
			}
			switch strings.ToLower(strings.TrimSpace(name)) {
			case "gzip", "x-gzip":
				gzipQ = max(gzipQ, q)
			case "*":
				starQ = max(starQ, q)
			}
		}
	}
	if gzipQ >= 0 {
		return gzipQ > 0
	}
	return starQ > 0
}

// gzipWanted reports whether the proxy compresses the response: one with a
// body of a compressible type that the upstream did not encode, is not a
// range and does not forbid a transformation.
func gzipWanted(resp *http.Response) bool {
	if !bodyAllowedForStatus(resp.StatusCode) || resp.StatusCode == http.StatusPartialContent ||
		len(resp.Header.Values("Content-Encoding")) > 0 ||
		(resp.ContentLength >= 0 && resp.ContentLength < gzipMinLength) ||
		headerHasToken(resp.Header.Values("Cache-Control"), "no-transform") {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	return err == nil && gzipTypes[mediaType]
}

// gzipResponse compresses the response's body as it is read and sets the
// headers to match. The body has no length any more, so it goes out in
// chunks (chunkIfUnframed).
func gzipResponse(resp *http.Response) {
	resp.Body = newGzipBody(resp.Body)
	resp.ContentLength = -1
	resp.TransferEncoding = nil
	resp.Header.Del("Content-Length")
	resp.Header.Del("Accept-Ranges")
	resp.Header.Set("Content-Encoding", "gzip")
	if !headerHasToken(resp.Header.Values("Vary"), "accept-encoding") && !headerHasToken(resp.Header.Values("Vary"), "*") {
		resp.Header.Add("Vary", "Accept-Encoding")
	}
	// The compressed body is another representation: a strong validator of
	// the plain one does not name its bytes.
	if etag := resp.Header.Get("ETag"); strings.HasPrefix(etag, `"`) {
		resp.Header.Set("ETag", "W/"+etag)
	}
}

// headerHasToken reports whether a comma-separated header names the token,
// ignoring case and any parameters.
func headerHasToken(lines []string, token string) bool {
	for _, line := range lines {
		for item := range strings.SplitSeq(line, ",") {
			name, _, _ := strings.Cut(item, "=")
			if strings.EqualFold(strings.TrimSpace(name), token) {
				return true
			}
		}
	}
	return false
}

// gzipBody compresses the body it wraps as it is read. Every read of the
// upstream ends in a gzip flush, so what has arrived can be decoded at once
// and an answer that streams still streams.
type gzipBody struct {
	src   io.ReadCloser
	state *gzipState
	err   error
}

func newGzipBody(src io.ReadCloser) *gzipBody {
	state := gzipStates.Get().(*gzipState)
	state.out.Reset()
	state.zw.Reset(&state.out)
	return &gzipBody{src: src, state: state}
}

func (b *gzipBody) Read(p []byte) (int, error) {
	if b.state == nil {
		return 0, io.ErrClosedPipe
	}
	s := b.state
	for s.out.Len() == 0 {
		if b.err != nil {
			return 0, b.err
		}
		n, err := b.src.Read(s.in)
		if n > 0 {
			// Writes to a bytes.Buffer do not fail.
			_, _ = s.zw.Write(s.in[:n])
			if err == nil {
				_ = s.zw.Flush()
			}
		}
		switch {
		case err == io.EOF:
			_ = s.zw.Close()
			b.err = io.EOF
		case err != nil:
			b.err = err
		}
	}
	return s.out.Read(p)
}

func (b *gzipBody) Close() error {
	if b.state != nil {
		gzipStates.Put(b.state)
		b.state = nil
	}
	return b.src.Close()
}
