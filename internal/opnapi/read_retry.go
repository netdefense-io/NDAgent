package opnapi

// read_retry.go — asking again when a read's response arrives corrupt.
//
// OPNsense's web server (lighttpd over FreeBSD 15 kTLS, opnsense/src#301) can
// replay or drop bytes of a large HTTP/1.1 response on some releases. The
// damage is per response and intermittent, so a repeat usually succeeds — but
// only a request whose repeat changes nothing on the device may be repeated.

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/netdefense-io/ndagent/internal/util"
)

// maxReadRetries bounds the repeats of one read, on top of the first attempt.
const maxReadRetries = 2

// readRetryBackoff is the pause before the first retry; the second waits twice
// as long.
var readRetryBackoff = 200 * time.Millisecond

// retrySleep waits out one backoff; tests replace it to observe the schedule.
var retrySleep = util.ShutdownAwareSleep

// readOnlyPOSTs are the POST endpoints that only read. OPNsense grids take
// their query in a POST body, so the verb alone cannot tell a search from a
// change; an endpoint missing here is sent once.
var readOnlyPOSTs = map[string]bool{
	"/firewall/alias/searchItem":           true,
	"/firewall/filter/searchRule":          true,
	"/auth/user/search":                    true,
	"/auth/group/search":                   true,
	"/auth/priv/search":                    true,
	"/unbound/settings/searchHostOverride": true,
	"/unbound/settings/searchForward":      true,
	"/unbound/settings/searchHostAlias":    true,
	"/unbound/settings/searchAcl":          true,
	"/wireguard/server/search_server":      true,
	"/wireguard/client/search_client":      true,
	"/trust/ca/search":                     true,
	"/trust/cert/search":                   true,
}

// isIdempotentRead reports whether a request may be repeated. A GET is taken to
// be a read, so a GET endpoint that changes device state must be excluded here
// before the client calls it; a POST qualifies only through readOnlyPOSTs.
func isIdempotentRead(method, path string) bool {
	switch method {
	case http.MethodGet:
		return true
	case http.MethodPost:
		return readOnlyPOSTs[path]
	default:
		return false
	}
}

// isCorruptResponse reports whether a response is worth asking for again: the
// transport broke the body's framing or cut it short, or a 2xx body is not
// JSON. A refusal (APIError), a timeout or a dead connection is not corruption
// and is never retried.
func isCorruptResponse(body []byte, err error) bool {
	if err == nil {
		return !json.Valid(body)
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return false
	}
	// net/http exports no error for a broken chunk, only its text.
	msg := err.Error()
	return errors.Is(err, io.ErrUnexpectedEOF) ||
		strings.Contains(msg, "malformed chunked encoding") ||
		strings.Contains(msg, "invalid byte in chunk length")
}
