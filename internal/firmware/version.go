package firmware

import "strings"

// CompareVersions orders two package versions as pkg-version(8) does for the
// shapes OPNsense's packages use: [version][_revision][,epoch], where version is
// dot-separated numbers that may carry words ("1.0.rc1", "2.4p1", "1.0a").
//
// The epoch (after the comma) decides first, then the version, then the
// revision (after the underscore). Numbers compare as numbers, however long, so
// "26.7.10" is above "26.7.9". A missing component counts as 0, so "1.0" equals
// "1.0.0". A pre-release word (alpha, beta, pre, rc) sorts below the same
// version without it, any other word above: "1.0.rc1" < "1.0" < "1.0a".
//
// It returns -1, 0 or 1.
func CompareVersions(a, b string) int {
	epochA, bodyA, revA := splitVersion(a)
	epochB, bodyB, revB := splitVersion(b)
	if c := compareNumbers(epochA, epochB); c != 0 {
		return c
	}
	if c := compareBodies(bodyA, bodyB); c != 0 {
		return c
	}
	return compareNumbers(revA, revB)
}

// AtLeast reports whether the installed version of a package satisfies the
// version an update planned for it. An empty planned version means "any": the
// plan named the package without saying which version. An empty installed
// version means it is not installed.
func AtLeast(installed, planned string) bool {
	if installed == "" {
		return false
	}
	return planned == "" || installed == planned || CompareVersions(installed, planned) >= 0
}

func splitVersion(v string) (epoch, body, revision string) {
	body = strings.TrimSpace(v)
	if i := strings.LastIndexByte(body, ','); i >= 0 {
		epoch, body = body[i+1:], body[:i]
	}
	if i := strings.LastIndexByte(body, '_'); i >= 0 {
		revision, body = body[i+1:], body[:i]
	}
	return epoch, body, revision
}

// versionToken is a run of digits or a run of letters.
type versionToken struct {
	text  string
	isNum bool
}

func tokenizeVersion(s string) []versionToken {
	var tokens []versionToken
	for i := 0; i < len(s); {
		switch c := s[i]; {
		case isDigit(c):
			j := i
			for j < len(s) && isDigit(s[j]) {
				j++
			}
			tokens = append(tokens, versionToken{text: s[i:j], isNum: true})
			i = j
		case isLetter(c):
			j := i
			for j < len(s) && isLetter(s[j]) {
				j++
			}
			tokens = append(tokens, versionToken{text: strings.ToLower(s[i:j])})
			i = j
		default: // '.', '+', '-', '~': separators
			i++
		}
	}
	return tokens
}

func isDigit(c byte) bool  { return c >= '0' && c <= '9' }
func isLetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

func compareBodies(a, b string) int {
	ta, tb := tokenizeVersion(a), tokenizeVersion(b)
	for i := 0; i < len(ta) || i < len(tb); i++ {
		if c := compareTokens(tokenAt(ta, i), tokenAt(tb, i)); c != 0 {
			return c
		}
	}
	return 0
}

// tokenAt is the i-th token, or the number 0 past the end.
func tokenAt(tokens []versionToken, i int) versionToken {
	if i < len(tokens) {
		return tokens[i]
	}
	return versionToken{text: "0", isNum: true}
}

func compareTokens(a, b versionToken) int {
	switch {
	case a.isNum && b.isNum:
		return compareNumbers(a.text, b.text)
	case a.isNum: // number against word: a pre-release word is below it, any other above
		return -wordSide(b.text)
	case b.isNum:
		return wordSide(a.text)
	default:
		return compareWords(a.text, b.text)
	}
}

// preRelease ranks the words that sort below a release. Anything not listed is
// treated as a suffix above it.
var preRelease = map[string]int{"alpha": 1, "beta": 2, "pre": 3, "rc": 4}

// wordSide is -1 for a pre-release word and 1 for any other: which side of the
// plain number it falls on.
func wordSide(w string) int {
	if _, ok := preRelease[w]; ok {
		return -1
	}
	return 1
}

func compareWords(a, b string) int {
	ra, aPre := preRelease[a]
	rb, bPre := preRelease[b]
	switch {
	case aPre && bPre:
		return compareInts(ra, rb)
	case aPre:
		return -1
	case bPre:
		return 1
	default:
		return strings.Compare(a, b)
	}
}

func compareInts(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// compareNumbers compares two strings of digits by value without converting
// them, so a 14-digit date stamp cannot overflow. An empty string is 0. If
// either is not all digits they compare as text.
func compareNumbers(a, b string) int {
	if !allDigits(a) || !allDigits(b) {
		return strings.Compare(a, b)
	}
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if c := compareInts(len(a), len(b)); c != 0 {
		return c
	}
	return strings.Compare(a, b)
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return true
}
