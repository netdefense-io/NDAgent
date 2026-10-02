package pathfinder

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// A grid matches its search phrase against every stored field of a row, secret
// included, before the proxy blanks the secret out of the rows that come back,
// so which rows come back says whether a phrase occurs in one. On the
// certificate and CA lists the rows hold private keys, and a phrase grown one
// character at a time from the header every PEM key begins with reads a key
// whole. A read-only session may list them but not search them: a request that
// carries a phrase, wherever OPNsense would read it from, is refused.

// phraseSearchRefusedPattern matches the grids a read-only session may not
// search.
var phraseSearchRefusedPattern = regexp.MustCompile(`^/api/trust/(ca|cert)/search(/|$)`)

// searchBodyLimit bounds the body read from a search request. The grid sends a
// few hundred bytes; a body it cannot read whole is not forwarded.
const searchBodyLimit = 64 << 10

// searchRefusalDetail is the body of the answer to a search with a phrase.
const searchRefusalDetail = "a read-only session cannot search this list"

// phraseSearchRefused reports whether a request target names a grid a
// read-only session may not search.
func phraseSearchRefused(target string) bool {
	path, ok := requestPath(target)
	return ok && phraseSearchRefusedPattern.MatchString(canonicalRoute(path))
}

// searchPhraseRefusal returns the status a read-only session answers a search
// of a grid in phraseSearchRefusedPattern with, or 0 to forward it: 405 when it
// carries a search phrase, 400 when it cannot be read. OPNsense reads the
// phrase from $_REQUEST, which holds the query string, the cookies and the
// body, and the API fills it from a JSON body whatever the method, so all of
// them are read. A request with a body has it read here and replaced by the
// bytes read, so the proxy forwards what it checked.
func searchPhraseRefusal(req *http.Request) int {
	_, query, _ := strings.Cut(req.RequestURI, "?")
	if formCarriesPhrase(query, "&;") {
		return http.StatusMethodNotAllowed
	}
	for _, cookies := range req.Header.Values("Cookie") {
		if formCarriesPhrase(cookies, ";") {
			return http.StatusMethodNotAllowed
		}
	}
	if req.Body == nil || req.Body == http.NoBody {
		return 0
	}

	body, err := io.ReadAll(io.LimitReader(req.Body, searchBodyLimit+1))
	if err != nil || len(body) > searchBodyLimit {
		return http.StatusBadRequest
	}
	req.ContentLength = int64(len(body))
	if len(body) == 0 {
		req.Body = http.NoBody
		return 0
	}
	req.Body = io.NopCloser(bytes.NewReader(body))

	contentType := strings.ToLower(strings.Join(req.Header.Values("Content-Type"), ","))
	if strings.Contains(contentType, "multipart") {
		return http.StatusBadRequest
	}
	if formCarriesPhrase(string(body), "&;") {
		return http.StatusMethodNotAllowed
	}
	declaredJSON := strings.Contains(contentType, "json")
	if trimmed := bytes.TrimSpace(body); declaredJSON || bytes.HasPrefix(trimmed, []byte("{")) {
		carries, ok := jsonCarriesPhrase(body)
		if carries {
			return http.StatusMethodNotAllowed
		}
		if !ok && declaredJSON {
			return http.StatusBadRequest
		}
	}
	return 0
}

// formCarriesPhrase reports whether a query string, a form body or a cookie
// header holds a search phrase with a value, or one in array form. Pairs are
// split on any of seps, and names and values are percent-decoded the way PHP
// decodes them.
func formCarriesPhrase(data, seps string) bool {
	pairs := strings.FieldsFunc(data, func(r rune) bool { return strings.ContainsRune(seps, r) })
	for _, pair := range pairs {
		name, value, _ := strings.Cut(pair, "=")
		name = phpURLDecode(name)
		if isSearchPhraseName(name) && (phpURLDecode(value) != "" || strings.Contains(name, "[")) {
			return true
		}
	}
	return false
}

// jsonCarriesPhrase reports whether a JSON body is an object that holds a
// search phrase key with any value but "" or null; ok is false when the body
// is not exactly one JSON value. Every occurrence of a repeated key is read.
func jsonCarriesPhrase(body []byte) (carries, ok bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return false, false
	}
	if delim, isDelim := tok.(json.Delim); !isDelim || delim != '{' {
		return false, json.Valid(body)
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return false, false
		}
		key, _ := keyTok.(string)
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return false, false
		}
		if isSearchPhraseName(key) {
			switch string(bytes.TrimSpace(value)) {
			case `""`, `null`:
			default:
				carries = true
			}
		}
	}
	if _, err := dec.Token(); err != nil {
		return false, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return false, false
	}
	return carries, true
}

// isSearchPhraseName reports whether a request variable name reads as
// searchPhrase. PHP drops leading white space, ends a name at "[" (array form)
// and at a NUL, and turns "." and " " into "_"; the comparison here also
// ignores case and every "_", ".", and " ", so it matches more names than PHP
// would read as the phrase, never fewer.
func isSearchPhraseName(name string) bool {
	name = strings.TrimLeft(name, " \t\n\r\v\f")
	if i := strings.IndexAny(name, "[\x00"); i >= 0 {
		name = name[:i]
	}
	folded := strings.Map(func(r rune) rune {
		switch r {
		case '_', '.', ' ':
			return -1
		}
		return r
	}, strings.ToLower(name))
	return folded == "searchphrase"
}

// phpURLDecode decodes like PHP's urldecode: "+" is a space, a valid %XX is
// its byte, and anything else stays as it is.
func phpURLDecode(s string) string {
	if !strings.ContainsAny(s, "+%") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '+':
			b.WriteByte(' ')
		case c == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]):
			b.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
			i += 2
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}
