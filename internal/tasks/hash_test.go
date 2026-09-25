package tasks

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

// jsonUnicodeEscape builds a JSON `\uXXXX` escape sequence from its parts
// (backslash + "u" + 4 hex digits) rather than as a literal escape in this
// file's source text. A literal four-hex-digit \u sequence typed directly
// into this file has repeatedly been silently unescaped into the actual
// Unicode character by tooling somewhere between authoring and disk (a
// real, reproducible hazard hit while writing this very test — the
// "backslash" and "u" below are deliberately never adjacent as typed
// characters, only after Sprintf joins them at runtime).
func jsonUnicodeEscape(codepoint uint32) string {
	backslash := string(rune(0x5c))
	return fmt.Sprintf("%s%s%04x", backslash, "u", codepoint)
}

// TestJSONMarshalSorted_MatchesPythonEnsureASCII pins the ASCII-escape
// parity fix: Go's payload serialization must byte-for-byte match
// NDManager's Python `json.dumps(sort_keys=True, ensure_ascii=True,
// separators=(",", ":"))` — including escaping every non-ASCII codepoint
// as \uXXXX (a UTF-16 surrogate pair above the BMP) rather than emitting
// raw UTF-8. The expected string and hash below were computed
// independently with Python's own json/hashlib modules against the
// identical payload shape (see the reasoning comment on
// jsonMarshalSorted); this is not a fixture copied from NDManager's repo
// (NDManager's #3/#4 has not shipped yet), so re-derive/replace it once
// NDManager publishes a shared fixture for this — the two sides must never
// drift.
func TestJSONMarshalSorted_MatchesPythonEnsureASCII(t *testing.T) {
	payload := map[string]interface{}{
		"b":     float64(1),
		"a":     "OU=Usu" + string(rune(0x00e1)) + "rios", // "OU=Usuários"
		"c":     true,
		"d":     nil,
		"e":     []interface{}{float64(1), "x"},
		"emoji": string(rune(0x1f600)), // an astral codepoint (above the BMP)
	}

	got, err := jsonMarshalSorted(payload)
	if err != nil {
		t.Fatalf("jsonMarshalSorted: %v", err)
	}

	want := `{"a":"OU=Usu` + jsonUnicodeEscape(0x00e1) + `rios","b":1,"c":true,"d":null,"e":[1,"x"],"emoji":"` +
		jsonUnicodeEscape(0xd83d) + jsonUnicodeEscape(0xde00) + `"}`
	if string(got) != want {
		t.Fatalf("jsonMarshalSorted mismatch:\n got:  %s\n want: %s", got, want)
	}

	wantHash := "cc301546291b6c8e039b5cbcfdb2b83d9c421faf20c5666376d517f0d72668e8"
	gotHash := fmt.Sprintf("%x", sha256.Sum256(got))
	if gotHash != wantHash {
		t.Fatalf("sha256 mismatch: got %s, want %s", gotHash, wantHash)
	}
}

// TestComputePayloadHash_NonASCIIAuthContent exercises the actual
// production entry point (computePayloadHash/verifyPayloadHash) with a
// payload shaped like a real AUTH_SERVER sync: an ldap_basedn carrying
// non-ASCII (explicitly allowed). Before the ASCII-escape parity fix this
// would never match a NDManager-computed payload_hash for the same content.
func TestComputePayloadHash_NonASCIIAuthContent(t *testing.T) {
	basedn := "OU=Usu" + string(rune(0x00e1)) + "rios"
	content := fmt.Sprintf(`{"name":"Corp AD","type":"ldap","host":"dc.example.com","ldap_basedn":%q}`, basedn)

	buildPayload := func() map[string]interface{} {
		return map[string]interface{}{
			"snippets": []interface{}{
				map[string]interface{}{
					"config_type": "AUTH_SERVER",
					"content":     content,
				},
			},
		}
	}

	hash1 := computePayloadHash(buildPayload())
	if hash1 == "" {
		t.Fatal("computePayloadHash returned empty string")
	}

	// Deterministic: computing it again from an equivalent (freshly built)
	// map produces the identical hash.
	hash2 := computePayloadHash(buildPayload())
	if hash1 != hash2 {
		t.Fatalf("hash not deterministic: %s vs %s", hash1, hash2)
	}

	payload := buildPayload()
	payload["payload_hash"] = hash1
	if !verifyPayloadHash(payload, hash1) {
		t.Fatal("verifyPayloadHash rejected a hash it just computed")
	}
}

// TestAsciiEscapeJSON pins the escape helper directly against a small
// table, independent of the map-ordering machinery above.
func TestAsciiEscapeJSON(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{`"abc"`, `"abc"`},
		{`"caf` + string(rune(0x00e9)) + `"`, `"caf` + jsonUnicodeEscape(0x00e9) + `"`},
		{
			string(rune(0x65e5)) + string(rune(0x672c)) + string(rune(0x8a9e)),
			jsonUnicodeEscape(0x65e5) + jsonUnicodeEscape(0x672c) + jsonUnicodeEscape(0x8a9e),
		},
		{
			string(rune(0x1f600)),
			jsonUnicodeEscape(0xd83d) + jsonUnicodeEscape(0xde00),
		},
		// DEL (0x7F) is < 0x80 but outside Python's printable-ASCII range
		// (0x20-0x7E), so ensure_ascii=True escapes it too. Confirmed
		// independently: `python3 -c 'json.dumps({"a":"x\x7fy"},
		// ensure_ascii=True)'` prints `{"a": "x\u007fy"}`. Every other
		// control character (0x00-0x1F) is already turned into a JSON
		// escape sequence by Go's own encoder before asciiEscapeJSON ever
		// runs, so DEL was the one byte silently passed through raw.
		{
			"x" + string(rune(0x7f)) + "y",
			"x" + jsonUnicodeEscape(0x7f) + "y",
		},
	}
	for _, c := range cases {
		got := string(asciiEscapeJSON([]byte(c.in)))
		if got != c.want {
			t.Errorf("asciiEscapeJSON(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
