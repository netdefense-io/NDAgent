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

	// Debug: show first 200 chars of serialized payload
	preview := string(serialized)
	if len(preview) > 200 {
		preview = preview[:200] + "..."
	}
	log.Debugw("Serialized payload for hash", "preview", preview)

	hash := sha256.Sum256(serialized)
	return fmt.Sprintf("sha256:%x", hash)
}

// jsonMarshalSorted marshals JSON with sorted keys for deterministic output.
// Uses non-HTML-escaped output to match Python's json.dumps behavior.
func jsonMarshalSorted(v interface{}) ([]byte, error) {
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
