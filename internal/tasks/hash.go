package tasks

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/netdefense-io/ndagent/internal/logging"
)

// verifyPayloadHash verifies the payload hash matches the computed hash.
func verifyPayloadHash(payload map[string]interface{}, expectedHash string) bool {
	log := logging.Named("SYNC")
	computed := computePayloadHash(payload)
	log.Debugw("Hash verification",
		"expected", expectedHash,
		"computed", computed,
		"match", computed == expectedHash,
	)
	return computed == expectedHash
}

// computePayloadHash computes SHA-256 hash of payload.
// Excludes the payload_hash field itself.
func computePayloadHash(payload map[string]interface{}) string {
	log := logging.Named("SYNC")

	// Create a copy without the hash field
	payloadCopy := make(map[string]interface{})
	for k, v := range payload {
		if k != "payload_hash" {
			payloadCopy[k] = v
		}
	}

	// Use deterministic serialization (sorted keys)
	serialized, err := jsonMarshalSorted(payloadCopy)
	if err != nil {
		log.Errorw("Failed to serialize payload for hash", "error", err)
		return ""
	}

	// A resolved AUTH payload's serialized bytes can
	// carry ldap_bindpw in plaintext (already substituted by NDManager
	// before dispatch) — never log a content preview here, only its
	// length. "Never echo values" is a PHP-helper rule (auth_servers.php),
	// but the same discipline applies to every place in NDAgent that
	// touches a resolved secret.
	log.Debugw("Serialized payload for hash", "length", len(serialized))

	hash := sha256.Sum256(serialized)
	return fmt.Sprintf("sha256:%x", hash)
}

// jsonMarshalSorted marshals JSON with sorted keys for deterministic
// output, matching NDManager's Python `json.dumps(sort_keys=True,
// ensure_ascii=True)` (sync_service.py's payload-hash computation)
// byte-for-byte — including its ASCII canonicalization: every codepoint
// outside 0x00-0x7F is escaped as `\uXXXX` (a UTF-16 surrogate pair for
// anything above the Basic Multilingual Plane), never emitted as a raw
// UTF-8 byte sequence. Before this, a payload whose non-ASCII content came
// from an OPNsense-side agent computation would hash differently on each
// side; AUTH_SERVER content is the first field NDManager canonicalizes
// this way that a device sync also re-hashes end to end (non-ASCII is
// explicitly allowed in ldap_basedn/ldap_authcn, e.g. "OU=Usuários"), so a
// mismatch here would fail EVERY sync carrying non-ASCII AUTH content at
// the payload-integrity check, before any AUTH-specific logic ever runs.
//
// asciiEscapeJSON is applied exactly once, over the fully-assembled
// top-level result: every non-ASCII byte in valid JSON output is
// necessarily inside a string literal (numbers/bools/null/structural
// characters are pure ASCII by the JSON grammar), so escaping the whole
// buffer in one pass is equivalent to escaping each string as it is
// written, and avoids doing it once per recursive call.
func jsonMarshalSorted(v interface{}) ([]byte, error) {
	result, err := jsonMarshalSortedRaw(v)
	if err != nil {
		return nil, err
	}
	return asciiEscapeJSON(result), nil
}

func jsonMarshalSortedRaw(v interface{}) ([]byte, error) {
	// For maps, we need to sort keys
	if m, ok := v.(map[string]interface{}); ok {
		return marshalSortedMap(m)
	}
	// Use encoder with HTML escaping disabled
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(v); err != nil {
		return nil, err
	}
	// Remove trailing newline added by Encode
	result := buf.Bytes()
	if len(result) > 0 && result[len(result)-1] == '\n' {
		result = result[:len(result)-1]
	}
	return result, nil
}

// asciiEscapeJSON rewrites every non-ASCII rune in already-valid JSON bytes
// as its `\uXXXX` escape (lowercase hex, matching Python's json encoder),
// splitting any codepoint above U+FFFF into a UTF-16 surrogate pair the
// same way Python's `py_encode_basestring_ascii` does. ASCII bytes,
// including every JSON structural character and every escape sequence
// already produced upstream, pass through unchanged.
func asciiEscapeJSON(b []byte) []byte {
	var out bytes.Buffer
	out.Grow(len(b))
	for _, r := range string(b) {
		// Python's py_encode_basestring_ascii (json.dumps(ensure_ascii=True))
		// escapes anything outside the PRINTABLE ASCII range 0x20-0x7E —
		// not just non-ASCII. 0x7F (DEL) is < 0x80 but outside that
		// printable range, so `python3 -c 'json.dumps({"a":"x\x7fy"})'`
		// (with ensure_ascii=True) emits `\u007f`, never a raw byte.
		// Go's own json.Marshal already turned every JSON-mandated
		// control character (0x00-0x1F) into an escape sequence before
		// this function ever runs, so DEL is the one gap: treating it as
		// plain ASCII here silently broke byte-for-byte parity with
		// NDManager for any payload string containing it.
		if r == 0x7f {
			fmt.Fprintf(&out, `\u%04x`, r)
			continue
		}
		if r < 0x80 {
			out.WriteRune(r)
			continue
		}
		if r > 0xFFFF {
			r -= 0x10000
			hi := 0xd800 + (r >> 10)
			lo := 0xdc00 + (r & 0x3ff)
			fmt.Fprintf(&out, `\u%04x\u%04x`, hi, lo)
			continue
		}
		fmt.Fprintf(&out, `\u%04x`, r)
	}
	return out.Bytes()
}

func marshalSortedMap(m map[string]interface{}) ([]byte, error) {
	// Get sorted keys
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build JSON manually with sorted keys
	var sb strings.Builder
	sb.WriteString("{")

	for i, k := range keys {
		if i > 0 {
			sb.WriteString(",")
		}

		// Marshal key
		keyBytes, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		sb.Write(keyBytes)
		sb.WriteString(":")

		// Marshal value (recursively handle nested maps/arrays)
		valueBytes, err := marshalValue(m[k])
		if err != nil {
			return nil, err
		}
		sb.Write(valueBytes)
	}

	sb.WriteString("}")
	return []byte(sb.String()), nil
}

func marshalValue(v interface{}) ([]byte, error) {
	switch val := v.(type) {
	case map[string]interface{}:
		return marshalSortedMap(val)
	case []interface{}:
		var sb strings.Builder
		sb.WriteString("[")
		for i, item := range val {
			if i > 0 {
				sb.WriteString(",")
			}
			itemBytes, err := marshalValue(item)
			if err != nil {
				return nil, err
			}
			sb.Write(itemBytes)
		}
		sb.WriteString("]")
		return []byte(sb.String()), nil
	default:
		// Use encoder with HTML escaping disabled
		return marshalNoEscape(v)
	}
}

// marshalNoEscape marshals a value without HTML escaping.
func marshalNoEscape(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(v); err != nil {
		return nil, err
	}
	// Remove trailing newline added by Encode
	result := buf.Bytes()
	if len(result) > 0 && result[len(result)-1] == '\n' {
		result = result[:len(result)-1]
	}
	return result, nil
}
