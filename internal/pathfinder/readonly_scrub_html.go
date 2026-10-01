package pathfinder

import (
	"bytes"
	"errors"
)

// maxInputTagBytes bounds how far an <input> tag may run before its closing ">":
// an element that is not closed by then is malformed, and the page is refused.
const maxInputTagBytes = 16 << 10

var errUnterminatedInput = errors.New("an <input> tag is not closed")

// scrubHTMLInputs blanks the value attribute of every <input> element of an HTML
// page whose name is one of names, and returns the page with the number of
// values it changed.
//
// It is for the legacy pages, which render a stored secret into the page as the
// value of a form field. The page escapes that value with htmlspecialchars
// (legacy_html_escape_form_data), so the value cannot close its own quotes or its
// tag and the tag is read the way a browser reads it. Every byte outside the
// named fields' value attributes is copied as it arrived. An element that is not
// closed, or an attribute whose quote is not, is an error: the page is refused,
// never passed along half understood.
//
// Elements are found wherever the text has them, inside a script or a comment
// included: blanking more than a browser would show is harmless.
func scrubHTMLInputs(page []byte, names map[string]bool) ([]byte, int, error) {
	var out bytes.Buffer
	cursor, changed := 0, 0
	for i := 0; i < len(page); {
		lt := bytes.IndexByte(page[i:], '<')
		if lt < 0 {
			break
		}
		i += lt
		if !startsInputTag(page, i) {
			i++
			continue
		}
		attrs, end, err := parseInputTag(page, i+len("<input"))
		if err != nil {
			return nil, 0, err
		}
		if isNamedInput(page, attrs, names) {
			for _, a := range attrs {
				if a.name != "value" || !a.hasValue || a.from == a.to {
					continue
				}
				out.Write(page[cursor:a.from])
				if a.quote == 0 {
					out.WriteString(`""`)
				}
				cursor = a.to
				changed++
			}
		}
		i = end
	}
	if changed == 0 {
		return page, 0, nil
	}
	out.Write(page[cursor:])
	return out.Bytes(), changed, nil
}

// startsInputTag reports whether an <input element begins at page[i], which is
// a "<": the name ends right there or at white space, a slash or the ">".
func startsInputTag(page []byte, i int) bool {
	const name = "<input"
	if len(page)-i < len(name) {
		return false
	}
	for j := 1; j < len(name); j++ {
		c := page[i+j]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != name[j] {
			return false
		}
	}
	if len(page)-i == len(name) {
		return true
	}
	switch page[i+len(name)] {
	case ' ', '\t', '\n', '\f', '\r', '/', '>':
		return true
	}
	return false
}

// htmlAttr is one attribute of a tag: its lower-cased name and, when it has a
// value, the range of the value between its quotes (the whole of it when unquoted).
type htmlAttr struct {
	name     string
	hasValue bool
	quote    byte
	from, to int
}

func isHTMLSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\f' || c == '\r'
}

// parseInputTag reads the attributes of a start tag from page[i], just after the
// tag name, the way a browser does: white space and slashes separate them, a
// value is double-quoted, single-quoted or bare. It returns them with the offset
// after the closing ">".
func parseInputTag(page []byte, i int) ([]htmlAttr, int, error) {
	limit := i + maxInputTagBytes
	if limit > len(page) {
		limit = len(page)
	}
	var attrs []htmlAttr
	for {
		for i < limit && (isHTMLSpace(page[i]) || page[i] == '/') {
			i++
		}
		if i >= limit {
			return nil, 0, errUnterminatedInput
		}
		if page[i] == '>' {
			return attrs, i + 1, nil
		}

		nameFrom := i
		i++ // an "=" that starts a name is part of it
		for i < limit && !isHTMLSpace(page[i]) && page[i] != '/' && page[i] != '>' && page[i] != '=' {
			i++
		}
		attr := htmlAttr{name: lowerASCII(page[nameFrom:i])}
		for i < limit && isHTMLSpace(page[i]) {
			i++
		}
		if i < limit && page[i] == '=' {
			i++
			for i < limit && isHTMLSpace(page[i]) {
				i++
			}
			if i >= limit {
				return nil, 0, errUnterminatedInput
			}
			attr.hasValue = true
			switch q := page[i]; q {
			case '"', '\'':
				close := bytes.IndexByte(page[i+1:limit], q)
				if close < 0 {
					return nil, 0, errUnterminatedInput
				}
				attr.quote = q
				attr.from, attr.to = i+1, i+1+close
				i = attr.to + 1
			default:
				attr.from = i
				for i < limit && !isHTMLSpace(page[i]) && page[i] != '>' {
					i++
				}
				attr.to = i
			}
		}
		attrs = append(attrs, attr)
	}
}

func lowerASCII(b []byte) string {
	lower := make([]byte, len(b))
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		lower[i] = c
	}
	return string(lower)
}

// isNamedInput reports whether any name attribute of the tag is one of names.
func isNamedInput(page []byte, attrs []htmlAttr, names map[string]bool) bool {
	for _, a := range attrs {
		if a.name == "name" && a.hasValue && names[string(page[a.from:a.to])] {
			return true
		}
	}
	return false
}
