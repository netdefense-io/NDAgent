package pathfinder

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// valueKinds is the set of JSON value types that a named secret field may hold
// and have blanked.
type valueKinds uint8

const (
	kindString valueKinds = 1 << iota
	kindNumber
	kindArray
	kindObject

	// kindsScalar is what a secret field holds: OPNsense serialises every model
	// field as a string. A value of another type under the same name is not the
	// secret (an option list can carry an entry that is called "password"), so it
	// is left alone and searched instead.
	kindsScalar = kindString | kindNumber
)

// jsonKey names an object key whose value is blanked wherever the key occurs.
type jsonKey struct {
	name string
	// kinds are the value types that are blanked; zero means kindsScalar.
	kinds valueKinds
	// userinfo strips the credentials out of a URL instead of blanking it.
	userinfo bool
}

// jsonPath names one position in a document: the keys and array indexes from
// the root, where "*" stands for any single key or index.
type jsonPath struct {
	segments []string
	// kinds are the value types that are blanked; zero means kindsScalar.
	kinds valueKinds
}

func (p jsonPath) matches(at []string) bool {
	if len(p.segments) != len(at) {
		return false
	}
	for i, segment := range p.segments {
		if segment != "*" && segment != at[i] {
			return false
		}
	}
	return true
}

// jsonSecrets is what to blank in one JSON document.
type jsonSecrets struct {
	keys  map[string]jsonKey
	paths []jsonPath
}

// target is what the scrubber does to one value that is a secret.
type target struct {
	kinds    valueKinds
	userinfo bool
}

func newTarget(kinds valueKinds, userinfo bool) *target {
	if kinds == 0 {
		kinds = kindsScalar
	}
	return &target{kinds: kinds, userinfo: userinfo}
}

func (t *target) blanks(kind valueKinds) bool {
	return t != nil && t.kinds&kind != 0
}

var (
	errNotJSON     = errors.New("body is not a single JSON value")
	errJSONTrailer = errors.New("data after the JSON value")
)

// scrubJSON blanks the named secrets of a JSON document and returns the result
// with the number of values it changed.
//
// The edit is exact: the document is validated first, every byte outside the
// blanked values is copied as it arrived (key order, number spelling, string
// escapes and white space included), and a value is replaced only where its key,
// or its position from the root, is one the rules name. A body that is not one
// valid JSON value is an error, never a pass-through.
func scrubJSON(body []byte, secrets jsonSecrets) ([]byte, int, error) {
	if !json.Valid(body) {
		return nil, 0, errNotJSON
	}
	s := &jsonScrubber{
		body:    body,
		dec:     json.NewDecoder(bytes.NewReader(body)),
		secrets: secrets,
	}
	s.dec.UseNumber()
	if err := s.value(nil); err != nil {
		return nil, 0, err
	}
	if _, err := s.dec.Token(); !errors.Is(err, io.EOF) {
		return nil, 0, errJSONTrailer
	}
	s.out.Write(body[s.cursor:])
	return s.out.Bytes(), s.changed, nil
}

type jsonScrubber struct {
	body    []byte
	dec     *json.Decoder
	secrets jsonSecrets

	out     bytes.Buffer
	cursor  int // the first byte of body not yet copied to out
	changed int
	path    []string
}

// valueStart is the offset of the first byte of the value the decoder reads
// next: the white space, and the one comma or colon, that precede it are skipped.
// No value starts with any of them.
func (s *jsonScrubber) valueStart() int {
	i := int(s.dec.InputOffset())
	for i < len(s.body) {
		switch s.body[i] {
		case ' ', '\t', '\r', '\n', ',', ':':
			i++
		default:
			return i
		}
	}
	return i
}

// replace drops body[from:to] in favour of text.
func (s *jsonScrubber) replace(from, to int, text string) {
	if string(s.body[from:to]) == text {
		return
	}
	s.out.Write(s.body[s.cursor:from])
	s.out.WriteString(text)
	s.cursor = to
	s.changed++
}

// value reads the next value. A non-nil field says the value is a secret, to be
// blanked if it has one of the types the field names.
func (s *jsonScrubber) value(field *target) error {
	start := s.valueStart()
	tok, err := s.dec.Token()
	if err != nil {
		return err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			if field.blanks(kindObject) {
				return s.blankComposite(start, "{}")
			}
			return s.object()
		case '[':
			if field.blanks(kindArray) {
				return s.blankComposite(start, "[]")
			}
			return s.array()
		}
		return fmt.Errorf("unexpected delimiter %q", rune(t))
	case string:
		if field.blanks(kindString) {
			if field.userinfo {
				s.replace(start, int(s.dec.InputOffset()), stripURLUserinfo(t, s.body[start:int(s.dec.InputOffset())]))
			} else {
				s.replace(start, int(s.dec.InputOffset()), `""`)
			}
		}
	case json.Number:
		if field.blanks(kindNumber) {
			s.replace(start, int(s.dec.InputOffset()), "0")
		}
	}
	return nil
}

// blankComposite skips an object or array whose opening delimiter was just read
// and replaces it, whole, with its empty form.
func (s *jsonScrubber) blankComposite(start int, empty string) error {
	for depth := 1; depth > 0; {
		tok, err := s.dec.Token()
		if err != nil {
			return err
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
		}
	}
	s.replace(start, int(s.dec.InputOffset()), empty)
	return nil
}

// object reads the members of an object whose opening brace was just read.
func (s *jsonScrubber) object() error {
	for s.dec.More() {
		tok, err := s.dec.Token()
		if err != nil {
			return err
		}
		key, ok := tok.(string)
		if !ok {
			return fmt.Errorf("object key is %T", tok)
		}
		s.path = append(s.path, key)
		err = s.value(s.fieldFor(key))
		s.path = s.path[:len(s.path)-1]
		if err != nil {
			return err
		}
	}
	_, err := s.dec.Token()
	return err
}

// array reads the elements of an array whose opening bracket was just read.
func (s *jsonScrubber) array() error {
	for i := 0; s.dec.More(); i++ {
		s.path = append(s.path, strconv.Itoa(i))
		err := s.value(s.pathTarget())
		s.path = s.path[:len(s.path)-1]
		if err != nil {
			return err
		}
	}
	_, err := s.dec.Token()
	return err
}

// fieldFor says whether the value under key, at the current path, is a secret:
// the key names it, or the path does, or both, and then it is blanked if any of
// them names its type.
func (s *jsonScrubber) fieldFor(key string) *target {
	byPath := s.pathTarget()
	k, ok := s.secrets.keys[key]
	if !ok {
		return byPath
	}
	byKey := newTarget(k.kinds, k.userinfo)
	if byPath == nil {
		return byKey
	}
	merged := &target{kinds: byKey.kinds | byPath.kinds, userinfo: byKey.userinfo}
	if byPath.kinds&kindString != 0 {
		merged.userinfo = false
	}
	return merged
}

// pathTarget says whether the value at the current path is a secret.
func (s *jsonScrubber) pathTarget() *target {
	var found *target
	for _, p := range s.secrets.paths {
		if !p.matches(s.path) {
			continue
		}
		if found == nil {
			found = newTarget(p.kinds, false)
		} else {
			found.kinds |= newTarget(p.kinds, false).kinds
		}
	}
	return found
}

// stripURLUserinfo returns the JSON spelling of a URL without its user:password
// part. A value that is not a URL with an authority, but has an @ in it, is
// blanked: better to lose a URL than to keep a credential.
//
// So is a URL with an @ after its authority. The authority ends at the first /, ?
// or #, but the value is stored and rendered as typed, so a password that holds one
// of them unescaped ends the authority early and leaves the @ that closes the
// userinfo in what reads as the path. Such a value cannot be told from a literal @
// in a path, and a monit collector URL has no use for one.
func stripURLUserinfo(value string, original []byte) string {
	scheme := strings.Index(value, "://")
	if scheme < 0 {
		if strings.Contains(value, "@") {
			return `""`
		}
		return string(original)
	}
	rest := value[scheme+3:]
	authority := rest
	if end := strings.IndexAny(rest, "/?#"); end >= 0 {
		authority = rest[:end]
	}
	at := strings.LastIndex(authority, "@")
	if at < 0 {
		if strings.Contains(rest[len(authority):], "@") {
			return `""`
		}
		return string(original)
	}
	cleaned, err := json.Marshal(value[:scheme+3] + rest[at+1:])
	if err != nil {
		return `""`
	}
	return string(cleaned)
}
