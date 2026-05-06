// Package signing implements COSE_Sign1 envelope build/verify for the
// NDAgent payload-signing protocol. See PAYLOAD-SIGNATURES-DESIGN.md.
package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

// COSE protected-header label numbers — must match
// NDManager/src/lib/signing.py and NDBroker/src/lib/signing.py.
const (
	HdrAlg        = int64(1)
	HdrKid        = int64(4)
	HdrIss        = int64(-65537)
	HdrIat        = int64(-65538)
	HdrTaskID    = int64(-65539)
	HdrDeviceUUID = int64(-65540)
	HdrVersion   = int64(-65541)
	// v=2 amendments per PAYLOAD-SIGNATURES-FINDINGS-FIXES.md §4.1.
	HdrTaskType = int64(-65542) // dispatch envelopes only
	HdrSeq      = int64(-65543) // response envelopes only
	HdrExp      = int64(-65544) // dispatch envelopes only

	// Bumped from 1 to 2 for the v=2 amendment. Verifiers reject anything else.
	EnvelopeVersion = 2
	// Response-leg freshness window — the agent generates iat fresh at
	// send time, so bounding to ±300s blocks captured-frame replay. The
	// dispatch leg uses signed `exp` instead of an iat skew check.
	IatFreshnessSeconds = 300
)

// KidFromPubkey returns the first 16 bytes of SHA-256(pubkey_raw).
func KidFromPubkey(pub ed25519.PublicKey) []byte {
	if len(pub) != ed25519.PublicKeySize {
		panic(fmt.Sprintf("ed25519 pubkey must be %d bytes, got %d", ed25519.PublicKeySize, len(pub)))
	}
	sum := sha256.Sum256(pub)
	return sum[:16]
}

// GenerateKeypair generates a fresh Ed25519 keypair using crypto/rand.
func GenerateKeypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ed25519 keygen: %w", err)
	}
	return pub, priv, nil
}

// PrivateKeyFromBase64 decodes a base64-encoded raw 32-byte Ed25519 seed
// (stored in ndagent.conf as `device_privkey`) into a usable private key.
//
// Note: ed25519.PrivateKey is 64 bytes (seed + pubkey). We store only the
// 32-byte seed because that's the canonical Ed25519 representation
// shared with the rest of the platform; this function expands it.
func PrivateKeyFromBase64(b64 string) (ed25519.PrivateKey, error) {
	seed, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode private key: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("ed25519 seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// PublicKeyFromBase64 decodes a base64-encoded raw 32-byte Ed25519 pubkey.
func PublicKeyFromBase64(b64 string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("ed25519 pubkey must be %d bytes, got %d", ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

// SeedFromPrivateKey extracts the 32-byte seed (canonical form) from a
// 64-byte Ed25519 private key.
func SeedFromPrivateKey(priv ed25519.PrivateKey) []byte {
	return priv.Seed()
}

// PublicKeyFromPrivate derives the public key from a private key.
func PublicKeyFromPrivate(priv ed25519.PrivateKey) ed25519.PublicKey {
	return priv.Public().(ed25519.PublicKey)
}

// VerifyKeyByKid is a function that maps a kid to a verifying public
// key. Agents typically use a small static table (primary +
// emergency NDM pubkeys); the broker uses a JWKS cache.
type VerifyKeyByKid func(kid []byte) (ed25519.PublicKey, error)

// DecodedEnvelope is the verified contents of a COSE_Sign1 envelope.
//
// Type and Exp are populated on dispatch envelopes (NDManager → agent);
// Seq is populated on response envelopes (agent → broker). The other side
// of each pair is left at the zero value.
type DecodedEnvelope struct {
	Payload    []byte
	Alg        int64
	Kid        []byte
	Iss        string
	Iat        int64
	TaskID     int64
	DeviceUUID string
	Version    int64
	Type       string // dispatch only
	Exp        int64  // dispatch only
	Seq        uint64 // response only
}

// BuildResponseEnvelope signs `payload` with the device's private key
// and produces a COSE_Sign1 envelope tagged with CBOR tag 18, ready
// to base64-encode and place in the WS frame's `envelope` field.
//
// `seq` is the device-monotonic response replay token (Finding 3a). The
// caller MUST acquire it under a critical section that also covers the
// subsequent WS write so seq order matches wire order.
//
// `iat` is filled with the current wall-clock seconds when zero.
func BuildResponseEnvelope(
	priv ed25519.PrivateKey,
	kid []byte,
	taskID int64,
	deviceUUID string,
	payload []byte,
	seq uint64,
	iat int64,
) ([]byte, error) {
	if iat == 0 {
		iat = time.Now().Unix()
	}

	hdr := cose.Headers{
		Protected: cose.ProtectedHeader{
			cose.HeaderLabelAlgorithm: cose.AlgorithmEd25519,
			cose.HeaderLabelKeyID:     kid,
			HdrIss:                    fmt.Sprintf("device:%s", deviceUUID),
			HdrIat:                    iat,
			HdrTaskID:                 taskID,
			HdrDeviceUUID:             deviceUUID,
			HdrVersion:                int64(EnvelopeVersion),
			HdrSeq:                    int64(seq),
		},
	}

	signer, err := cose.NewSigner(cose.AlgorithmEd25519, priv)
	if err != nil {
		return nil, fmt.Errorf("new cose signer: %w", err)
	}

	msg := cose.Sign1Message{Headers: hdr, Payload: payload}
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		return nil, fmt.Errorf("cose sign: %w", err)
	}

	encoded, err := msg.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("cose marshal: %w", err)
	}
	return encoded, nil
}

// VerifyDispatchEnvelope verifies an NDManager-signed envelope received
// over the WS dispatch path. Caller supplies a kid lookup function — for
// dispatch verifies, the agent passes ONLY its primary table here (per
// PAYLOAD-SIGNATURES-FINDINGS-FIXES.md §3 Finding 7, the emergency key is
// never consulted for dispatch).
//
// Returns the verified header fields. The caller is responsible for the
// semantic checks beyond signature: iss == "ndmanager", device_uuid match,
// task_id strict-greater replay barrier, exp not yet expired, type matches
// expected routing. v=2 also enforces alg=Ed25519 inline below.
func VerifyDispatchEnvelope(envelope []byte, lookup VerifyKeyByKid) (*DecodedEnvelope, error) {
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(envelope); err != nil {
		return nil, fmt.Errorf("cose unmarshal: %w", err)
	}

	kid, err := extractKid(msg.Headers.Protected)
	if err != nil {
		return nil, fmt.Errorf("read kid: %w", err)
	}

	pub, err := lookup(kid)
	if err != nil {
		return nil, fmt.Errorf("kid lookup %s: %w", hex.EncodeToString(kid), err)
	}

	verifier, err := cose.NewVerifier(cose.AlgorithmEd25519, pub)
	if err != nil {
		return nil, fmt.Errorf("new cose verifier: %w", err)
	}
	if err := msg.Verify(nil, verifier); err != nil {
		return nil, fmt.Errorf("cose verify: %w", err)
	}

	dec, err := protectedHeaderToDecoded(msg.Headers.Protected, msg.Payload)
	if err != nil {
		return nil, err
	}

	// Finding 8 — alg policy. Today only Ed25519 is supported; reject
	// anything else explicitly so a future PQ rotation has to opt in
	// rather than silently sliding through.
	if dec.Alg != int64(cose.AlgorithmEd25519) {
		return nil, fmt.Errorf("envelope alg %d unsupported (only Ed25519/-8 in v=2)", dec.Alg)
	}

	if dec.Version != int64(EnvelopeVersion) {
		return nil, fmt.Errorf(
			"envelope schema version %d unsupported; this build requires v=%d",
			dec.Version, EnvelopeVersion,
		)
	}
	return dec, nil
}

func extractKid(phdr cose.ProtectedHeader) ([]byte, error) {
	raw, ok := phdr[cose.HeaderLabelKeyID]
	if !ok {
		return nil, fmt.Errorf("envelope missing kid")
	}
	switch v := raw.(type) {
	case []byte:
		return v, nil
	case cbor.RawMessage:
		var b []byte
		if err := cbor.Unmarshal(v, &b); err != nil {
			return nil, err
		}
		return b, nil
	default:
		return nil, fmt.Errorf("envelope kid wrong type: %T", raw)
	}
}

func protectedHeaderToDecoded(phdr cose.ProtectedHeader, payload []byte) (*DecodedEnvelope, error) {
	dec := &DecodedEnvelope{Payload: payload}

	if v, ok := phdr[cose.HeaderLabelAlgorithm]; ok {
		switch x := v.(type) {
		case int64:
			dec.Alg = x
		case cose.Algorithm:
			dec.Alg = int64(x)
		default:
			return nil, fmt.Errorf("alg wrong type: %T", v)
		}
	}

	if kid, err := extractKid(phdr); err == nil {
		dec.Kid = kid
	}

	for _, item := range []struct {
		label int64
		dst   interface{}
		name  string
	}{
		{HdrIss, &dec.Iss, "iss"},
		{HdrIat, &dec.Iat, "iat"},
		{HdrTaskID, &dec.TaskID, "task_id"},
		{HdrDeviceUUID, &dec.DeviceUUID, "device_uuid"},
		{HdrVersion, &dec.Version, "v"},
	} {
		raw, ok := phdr[item.label]
		if !ok {
			return nil, fmt.Errorf("envelope missing required header field: %s", item.name)
		}
		switch ptr := item.dst.(type) {
		case *string:
			s, ok := raw.(string)
			if !ok {
				return nil, fmt.Errorf("envelope %s wrong type: %T", item.name, raw)
			}
			*ptr = s
		case *int64:
			i, err := coerceInt64(raw)
			if err != nil {
				return nil, fmt.Errorf("envelope %s: %w", item.name, err)
			}
			*ptr = i
		}
	}

	// v=2 optional fields (presence depends on direction).
	if raw, ok := phdr[HdrTaskType]; ok {
		s, isStr := raw.(string)
		if !isStr {
			return nil, fmt.Errorf("envelope type wrong type: %T", raw)
		}
		dec.Type = s
	}
	if raw, ok := phdr[HdrExp]; ok {
		i, err := coerceInt64(raw)
		if err != nil {
			return nil, fmt.Errorf("envelope exp: %w", err)
		}
		dec.Exp = i
	}
	if raw, ok := phdr[HdrSeq]; ok {
		i, err := coerceInt64(raw)
		if err != nil {
			return nil, fmt.Errorf("envelope seq: %w", err)
		}
		if i < 0 {
			return nil, fmt.Errorf("envelope seq must be non-negative, got %d", i)
		}
		dec.Seq = uint64(i)
	}
	return dec, nil
}

func coerceInt64(v interface{}) (int64, error) {
	switch x := v.(type) {
	case int64:
		return x, nil
	case uint64:
		return int64(x), nil
	case int:
		return int64(x), nil
	default:
		return 0, fmt.Errorf("not an integer: %T", v)
	}
}
