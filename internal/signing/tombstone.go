package signing

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/veraison/go-cose"
)

// Tombstone issuer and payload constants. Both sides of the wire pin
// these literals: NDManager mints them in build_tombstone_envelope, the
// agent refuses anything else.
const (
	// TombstoneIss is the only issuer a tombstone may carry. Same value
	// dispatch envelopes use — the tombstone is signed with the same
	// NDManager key, and the agent verifies it against the same pinned
	// trust set.
	TombstoneIss = "ndmanager"

	// TombstoneKind is the payload's `kind` discriminator. It exists so
	// a signed blob minted for some other purpose can never be replayed
	// into the decommission path just because it verifies.
	TombstoneKind = "device_tombstone"

	// TombstoneStatus is the only device status a tombstone may assert.
	TombstoneStatus = "DELETED"
)

// Tombstone is the verified contents of a device tombstone: NDManager's
// signed statement that a device row was permanently deleted.
//
// It is NOT a task. There is no task_id, no exp and no dispatch_seq —
// a tombstone is a statement about the device itself, it never expires
// (a deleted device is never revived: see the decommission contract),
// and it is delivered over the registration-check response rather than
// the WS dispatch path, so it never touches the replay barrier.
//
// DeletedAt is informational — the agent logs it and acts on the
// tombstone regardless of its value. Nothing in the decommission
// decision depends on the clock.
type Tombstone struct {
	Kind       string `json:"kind"`
	Status     string `json:"status"`
	DeviceUUID string `json:"device_uuid"`
	DeletedAt  string `json:"deleted_at"`

	// Kid is the hex-encoded kid of the pinned NDM key that verified
	// the signature; Iat is the protected-header issue time. Both are
	// carried for logging only.
	Kid string `json:"-"`
	Iat int64  `json:"-"`
}

// VerifyTombstone verifies a base64 COSE_Sign1 device tombstone.
//
// Sibling of VerifyDispatchEnvelope: same COSE library, same protected
// header labels, same kid-lookup abstraction, same pinned NDM trust set.
// The differences are deliberate and all in the direction of "this is
// not a task":
//
//   - No task_id is required (or expected) in the protected header.
//   - No exp is checked. Tombstones do not expire.
//   - The payload is checked, not just the header: kind, status and the
//     payload's own device_uuid must all be what a tombstone for THIS
//     device would say.
//
// Everything a tombstone is trusted for is irreversible, so every check
// here is fail-closed: any error means "do not decommission", and the
// caller stops the agent instead of wiping the box.
//
// `lookup` must resolve only keys the agent has already pinned. Callers
// must never fetch keys in order to verify a tombstone — an attacker who
// can answer the registration check can also answer a key fetch, and the
// TOFU pin is the whole trust anchor.
func VerifyTombstone(b64 string, lookup VerifyKeyByKid, ownUUID string) (*Tombstone, error) {
	if b64 == "" {
		return nil, fmt.Errorf("tombstone missing")
	}
	if ownUUID == "" {
		return nil, fmt.Errorf("own device_uuid unknown; cannot bind tombstone")
	}

	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("tombstone base64 decode: %w", err)
	}

	msg, err := verifySign1(raw, lookup)
	if err != nil {
		return nil, err
	}

	dec, err := decodeProtectedHeader(msg.Headers.Protected, msg.Payload, false)
	if err != nil {
		return nil, err
	}

	if dec.Alg != int64(cose.AlgorithmEd25519) {
		return nil, fmt.Errorf("tombstone alg %d unsupported (only Ed25519/-8 in v=%d)", dec.Alg, EnvelopeVersion)
	}
	if dec.Version != int64(EnvelopeVersion) {
		return nil, fmt.Errorf(
			"tombstone schema version %d unsupported; this build requires v=%d",
			dec.Version, EnvelopeVersion,
		)
	}
	if dec.Iss != TombstoneIss {
		return nil, fmt.Errorf("tombstone iss %q is not %q", dec.Iss, TombstoneIss)
	}
	if dec.DeviceUUID != ownUUID {
		return nil, fmt.Errorf("tombstone header device_uuid %q is not this device", dec.DeviceUUID)
	}

	var ts Tombstone
	if err := json.Unmarshal(dec.Payload, &ts); err != nil {
		return nil, fmt.Errorf("tombstone payload parse: %w", err)
	}
	if ts.Kind != TombstoneKind {
		return nil, fmt.Errorf("tombstone kind %q is not %q", ts.Kind, TombstoneKind)
	}
	if ts.Status != TombstoneStatus {
		return nil, fmt.Errorf("tombstone status %q is not %q", ts.Status, TombstoneStatus)
	}
	if ts.DeviceUUID != ownUUID {
		return nil, fmt.Errorf("tombstone payload device_uuid %q is not this device", ts.DeviceUUID)
	}

	ts.Kid = hex.EncodeToString(dec.Kid)
	ts.Iat = dec.Iat
	return &ts, nil
}
