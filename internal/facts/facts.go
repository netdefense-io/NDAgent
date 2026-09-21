// Package facts builds the device-facts payload the agent reports to the
// control plane: a small, versioned, slow-changing description of the box
// (timezone, interface roles, OPNsense/OS version, hostname).
//
// Facts are INFORMATIONAL ONLY. The channel is unsigned JSON over the
// authenticated WebSocket, so the server never converts user input with
// the reported timezone and never makes an authorization or scheduling
// decision from anything in here.
//
// Two rules govern what may be added to this payload:
//
//   - Never secrets. No API key or secret, device private key, bootstrap
//     token, VPN/WireGuard key or certificate private material.
//   - Never raw config. Everything here is a curated, agent-computed
//     summary; config.xml and raw OPNsense API responses are never
//     passed through.
package facts

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

// errPayloadTooLarge is returned when a payload still exceeds the
// contract size limit after every shrinkable part has been shed.
var errPayloadTooLarge = errors.New("facts payload exceeds the contract size limit")

// Version is the payload schema version. NDDataModels rejects anything
// else, so bump it on both sides together.
const Version = 1

// Contract bounds, shared byte-for-byte with NDDataModels'
// validate_device_facts_payload. Lengths are in characters, and the
// clamps below also keep the UTF-8 byte length within the same limit so
// a Python-side len() and a Go-side len() can never disagree.
const (
	MaxInterfaces      = 64
	MaxTimezoneName    = 64
	MaxTimezoneAbbrev  = 8
	MaxInterfaceRole   = 32
	MaxInterfaceIf     = 32
	MaxInterfaceDescr  = 64
	MaxOPNsenseVersion = 32
	MaxOPNsenseSeries  = 16
	MaxOSPlatform      = 32
	MaxOSVersion       = 64
	MaxHostname        = 253
	MaxPayloadBytes    = 8192

	// MinUTCOffsetSec / MaxUTCOffsetSec bracket the real-world range of
	// IANA offsets (UTC-14:00 … UTC+14:00).
	MinUTCOffsetSec = -50400
	MaxUTCOffsetSec = 50400
)

// Facts is the wire shape. Every sub-object is optional: a probe that
// fails is omitted rather than reported wrong, and never fails the
// connect or heartbeat that carries it.
//
// Optional leaves follow the same rule one level down: a value the agent
// does not have is OMITTED, never serialized as "". NDDataModels'
// validate_device_facts_payload rejects a present-but-empty string leaf
// and drops the whole document, so every optional string carries
// omitempty and Normalize blanks it (clamp trims, so whitespace-only
// collapses to "") before it is serialized.
type Facts struct {
	V          int         `json:"v"`
	Hash       string      `json:"hash,omitempty"`
	Timezone   *Timezone   `json:"timezone,omitempty"`
	Interfaces []Interface `json:"interfaces,omitempty"`
	OPNsense   *OPNsense   `json:"opnsense,omitempty"`
	OS         *OS         `json:"os,omitempty"`
	Hostname   string      `json:"hostname,omitempty"`
}

// Timezone carries the IANA name plus the offset and abbreviation as of
// collection time. The name is the durable fact; the offset is a
// convenience for display and is DST-correct only for "now", which is
// why consumers that reason about a future instant must use the name.
type Timezone struct {
	Name         string `json:"name"`
	UTCOffsetSec int    `json:"utc_offset_sec"`
	Abbrev       string `json:"abbrev,omitempty"`
}

// Interface is one configured OPNsense interface. Role is the config.xml
// element name (wan, lan, opt1, …) — the mapping that is otherwise
// invisible to the control plane.
type Interface struct {
	Role    string `json:"role,omitempty"`
	If      string `json:"if"`
	Descr   string `json:"descr,omitempty"`
	Enabled bool   `json:"enabled"`
}

// OPNsense is the installed product version and its series.
type OPNsense struct {
	Version string `json:"version,omitempty"`
	Series  string `json:"series,omitempty"`
}

// OS is the underlying FreeBSD platform and release.
type OS struct {
	Platform string `json:"platform,omitempty"`
	Version  string `json:"version,omitempty"`
}

// Normalize clamps every field to the contract bounds, strips control
// characters, blanks optional leaves that hold nothing (so omitempty
// leaves them out rather than sending ""), drops sub-objects and
// interface entries whose identity leaf is missing, and finally
// shrinks the payload until it serializes within MaxPayloadBytes. It is
// idempotent and never returns an error: an unrepresentable part is
// dropped, not reported wrong.
//
// The returned slice names what was clamped or dropped, for a WARN log.
func (f *Facts) Normalize() []string {
	var notes []string

	f.V = Version

	if f.Timezone != nil {
		name, clamped := clamp(f.Timezone.Name, MaxTimezoneName)
		if clamped {
			notes = append(notes, "timezone.name clamped")
		}
		abbrev, clamped := clamp(f.Timezone.Abbrev, MaxTimezoneAbbrev)
		if clamped {
			notes = append(notes, "timezone.abbrev clamped")
		}
		switch {
		case name == "":
			f.Timezone = nil
			notes = append(notes, "timezone dropped (no name)")
		case f.Timezone.UTCOffsetSec < MinUTCOffsetSec || f.Timezone.UTCOffsetSec > MaxUTCOffsetSec:
			f.Timezone = nil
			notes = append(notes, "timezone dropped (offset out of range)")
		default:
			f.Timezone.Name = name
			f.Timezone.Abbrev = abbrev
		}
	}

	if len(f.Interfaces) > MaxInterfaces {
		notes = append(notes, fmt.Sprintf("interfaces truncated to %d", MaxInterfaces))
		f.Interfaces = f.Interfaces[:MaxInterfaces]
	}
	kept := f.Interfaces[:0]
	for _, iface := range f.Interfaces {
		role, roleClamped := clamp(iface.Role, MaxInterfaceRole)
		if role == "" {
			notes = append(notes, "interface dropped (no role)")
			continue
		}
		ifName, ifClamped := clamp(iface.If, MaxInterfaceIf)
		if ifName == "" {
			// `if` is the entry's identity and the one leaf the
			// contract requires: an entry without it is dropped
			// rather than sent with an empty value.
			notes = append(notes, "interface "+role+" dropped (no if)")
			continue
		}
		// clamp trims surrounding whitespace, so a descr that is blank
		// on the device collapses to "" here and omitempty leaves the
		// key out entirely — never `"descr":""`, which the shared
		// validator rejects.
		descr, descrClamped := clamp(iface.Descr, MaxInterfaceDescr)
		if roleClamped || ifClamped || descrClamped {
			notes = append(notes, "interface "+role+" clamped")
		}
		kept = append(kept, Interface{Role: role, If: ifName, Descr: descr, Enabled: iface.Enabled})
	}
	f.Interfaces = kept
	if len(f.Interfaces) == 0 {
		f.Interfaces = nil
	}

	if f.OPNsense != nil {
		f.OPNsense.Version, _ = clamp(f.OPNsense.Version, MaxOPNsenseVersion)
		f.OPNsense.Series, _ = clamp(f.OPNsense.Series, MaxOPNsenseSeries)
		if f.OPNsense.Version == "" && f.OPNsense.Series == "" {
			f.OPNsense = nil
			notes = append(notes, "opnsense dropped (empty)")
		}
	}

	if f.OS != nil {
		f.OS.Platform, _ = clamp(f.OS.Platform, MaxOSPlatform)
		f.OS.Version, _ = clamp(f.OS.Version, MaxOSVersion)
		if f.OS.Platform == "" && f.OS.Version == "" {
			f.OS = nil
			notes = append(notes, "os dropped (empty)")
		}
	}

	var hostnameClamped bool
	f.Hostname, hostnameClamped = clamp(f.Hostname, MaxHostname)
	if hostnameClamped {
		notes = append(notes, "hostname clamped")
	}

	return append(notes, f.shrinkToLimit()...)
}

// shrinkToLimit drops interfaces (the only part that can grow) until the
// payload fits MaxPayloadBytes, hash included. The 64-character hash is
// accounted for by measuring with a placeholder of that width.
func (f *Facts) shrinkToLimit() []string {
	var notes []string
	for {
		probe := *f
		probe.Hash = strings.Repeat("0", 64)
		encoded, err := json.Marshal(&probe)
		if err != nil || len(encoded) <= MaxPayloadBytes {
			return notes
		}
		if len(f.Interfaces) == 0 {
			// Nothing left to shed: refuse to send a payload the
			// server would reject anyway.
			notes = append(notes, "payload over size limit with no interfaces to shed")
			return notes
		}
		f.Interfaces = f.Interfaces[:len(f.Interfaces)-1]
		if len(f.Interfaces) == 0 {
			f.Interfaces = nil
		}
		notes = append(notes, "interface dropped to fit size limit")
	}
}

// TooLarge reports whether the payload still exceeds the contract size
// limit after normalization. Callers must not send such a payload.
func (f *Facts) TooLarge() bool {
	encoded, err := json.Marshal(f)
	return err != nil || len(encoded) > MaxPayloadBytes
}

// SetHash computes the contract hash and stores it on the payload: the
// first 16 hex characters of SHA-256 over the canonical JSON (sorted
// keys, no whitespace) of the object WITHOUT the hash key.
func (f *Facts) SetHash() error {
	sum, err := f.computeHash()
	if err != nil {
		return err
	}
	f.Hash = sum
	return nil
}

func (f *Facts) computeHash() (string, error) {
	bare := *f
	bare.Hash = "" // omitempty drops it from the canonical form
	canonical, err := canonicalJSON(&bare)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:])[:16], nil
}

// canonicalJSON serializes v with object keys sorted at every depth and
// no whitespace. It round-trips through a generic value because Go emits
// struct fields in declaration order but map keys in sorted order; the
// decoder keeps numbers verbatim so an integer never becomes a float.
func canonicalJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return nil, err
	}
	return json.Marshal(generic)
}

// clamp strips control characters and trims the value to limit, in both
// characters and UTF-8 bytes. It reports whether anything was removed.
func clamp(s string, limit int) (string, bool) {
	cleaned := strings.Map(func(r rune) rune {
		if r == unicode.ReplacementChar || unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	cleaned = strings.TrimSpace(cleaned)
	changed := cleaned != s

	runes := []rune(cleaned)
	if len(runes) > limit {
		runes = runes[:limit]
		changed = true
	}
	for len(runes) > 0 && len(string(runes)) > limit {
		runes = runes[:len(runes)-1]
		changed = true
	}
	return string(runes), changed
}
