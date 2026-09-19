package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/veraison/go-cose"
)

// buildTestTombstone mints a tombstone exactly the way NDManager's
// build_tombstone_envelope does: COSE_Sign1 over a UTF-8 JSON payload,
// protected header carrying alg/kid/iss/iat/device_uuid/v and nothing
// task-shaped. The knobs exist so each test can bend one field at a time.
type tombstoneOpts struct {
	iss           string
	headerUUID    string
	payloadUUID   string
	kind          string
	status        string
	version       int64
	omitDeviceHdr bool
	addTaskID     bool
}

func buildTestTombstone(t *testing.T, priv ed25519.PrivateKey, kid []byte, o tombstoneOpts) string {
	t.Helper()

	payload, err := json.Marshal(map[string]string{
		"kind":        o.kind,
		"status":      o.status,
		"device_uuid": o.payloadUUID,
		"deleted_at":  "2026-09-18T23:40:12Z",
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	phdr := cose.ProtectedHeader{
		cose.HeaderLabelAlgorithm: cose.AlgorithmEd25519,
		cose.HeaderLabelKeyID:     kid,
		HdrIss:                    o.iss,
		HdrIat:                    time.Now().Unix(),
		HdrVersion:                o.version,
	}
	if !o.omitDeviceHdr {
		phdr[HdrDeviceUUID] = o.headerUUID
	}
	if o.addTaskID {
		phdr[HdrTaskID] = int64(0)
	}

	signer, err := cose.NewSigner(cose.AlgorithmEd25519, priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	msg := cose.Sign1Message{Headers: cose.Headers{Protected: phdr}, Payload: payload}
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		t.Fatalf("sign: %v", err)
	}
	encoded, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return base64.StdEncoding.EncodeToString(encoded)
}

func defaultOpts(uuid string) tombstoneOpts {
	return tombstoneOpts{
		iss:         TombstoneIss,
		headerUUID:  uuid,
		payloadUUID: uuid,
		kind:        TombstoneKind,
		status:      TombstoneStatus,
		version:     int64(EnvelopeVersion),
	}
}

func lookupFor(kid []byte, pub ed25519.PublicKey) VerifyKeyByKid {
	return func(got []byte) (ed25519.PublicKey, error) {
		if string(got) != string(kid) {
			return nil, errUnknownKid
		}
		return pub, nil
	}
}

var errUnknownKid = &kidError{}

type kidError struct{}

func (e *kidError) Error() string { return "kid not in NDM key table" }

const testUUID = "3a1e88a3-0000-4000-8000-000000000001"

func TestVerifyTombstone_Valid(t *testing.T) {
	pub, priv, _ := GenerateKeypair()
	kid := KidFromPubkey(pub)

	b64 := buildTestTombstone(t, priv, kid, defaultOpts(testUUID))

	ts, err := VerifyTombstone(b64, lookupFor(kid, pub), testUUID)
	if err != nil {
		t.Fatalf("VerifyTombstone: %v", err)
	}
	if ts.DeletedAt != "2026-09-18T23:40:12Z" {
		t.Errorf("deleted_at = %q", ts.DeletedAt)
	}
	if ts.Kid == "" {
		t.Error("kid not reported")
	}
	if ts.Iat == 0 {
		t.Error("iat not reported")
	}
}

// A tombstone carrying a task_id must still verify: the field is not
// required, only unused. This keeps the agent tolerant if NDManager's
// signer ever grows a sentinel task_id.
func TestVerifyTombstone_TaskIDToleratedButNotRequired(t *testing.T) {
	pub, priv, _ := GenerateKeypair()
	kid := KidFromPubkey(pub)

	o := defaultOpts(testUUID)
	o.addTaskID = true
	b64 := buildTestTombstone(t, priv, kid, o)

	if _, err := VerifyTombstone(b64, lookupFor(kid, pub), testUUID); err != nil {
		t.Fatalf("VerifyTombstone with task_id present: %v", err)
	}
}

func TestVerifyTombstone_Rejections(t *testing.T) {
	pub, priv, _ := GenerateKeypair()
	kid := KidFromPubkey(pub)
	otherPub, otherPriv, _ := GenerateKeypair()
	otherKid := KidFromPubkey(otherPub)

	cases := []struct {
		name      string
		b64       func(t *testing.T) string
		lookup    VerifyKeyByKid
		ownUUID   string
		wantInErr string
	}{
		{
			name: "wrong device_uuid in header and payload",
			b64: func(t *testing.T) string {
				return buildTestTombstone(t, priv, kid, defaultOpts("00000000-0000-4000-8000-000000000999"))
			},
			lookup:    lookupFor(kid, pub),
			ownUUID:   testUUID,
			wantInErr: "header device_uuid",
		},
		{
			name: "payload device_uuid disagrees with header",
			b64: func(t *testing.T) string {
				o := defaultOpts(testUUID)
				o.payloadUUID = "00000000-0000-4000-8000-000000000999"
				return buildTestTombstone(t, priv, kid, o)
			},
			lookup:    lookupFor(kid, pub),
			ownUUID:   testUUID,
			wantInErr: "payload device_uuid",
		},
		{
			name: "wrong iss",
			b64: func(t *testing.T) string {
				o := defaultOpts(testUUID)
				o.iss = "device:" + testUUID
				return buildTestTombstone(t, priv, kid, o)
			},
			lookup:    lookupFor(kid, pub),
			ownUUID:   testUUID,
			wantInErr: "iss",
		},
		{
			name: "unknown kid",
			b64: func(t *testing.T) string {
				return buildTestTombstone(t, otherPriv, otherKid, defaultOpts(testUUID))
			},
			lookup:    lookupFor(kid, pub),
			ownUUID:   testUUID,
			wantInErr: "kid lookup",
		},
		{
			name: "wrong kind",
			b64: func(t *testing.T) string {
				o := defaultOpts(testUUID)
				o.kind = "device_rebind"
				return buildTestTombstone(t, priv, kid, o)
			},
			lookup:    lookupFor(kid, pub),
			ownUUID:   testUUID,
			wantInErr: "kind",
		},
		{
			name: "wrong status",
			b64: func(t *testing.T) string {
				o := defaultOpts(testUUID)
				o.status = "DISABLED"
				return buildTestTombstone(t, priv, kid, o)
			},
			lookup:    lookupFor(kid, pub),
			ownUUID:   testUUID,
			wantInErr: "status",
		},
		{
			name: "unsupported envelope version",
			b64: func(t *testing.T) string {
				o := defaultOpts(testUUID)
				o.version = 99
				return buildTestTombstone(t, priv, kid, o)
			},
			lookup:    lookupFor(kid, pub),
			ownUUID:   testUUID,
			wantInErr: "schema version",
		},
		{
			name: "missing device_uuid header",
			b64: func(t *testing.T) string {
				o := defaultOpts(testUUID)
				o.omitDeviceHdr = true
				return buildTestTombstone(t, priv, kid, o)
			},
			lookup:    lookupFor(kid, pub),
			ownUUID:   testUUID,
			wantInErr: "missing required header field",
		},
		{
			name:      "empty tombstone",
			b64:       func(t *testing.T) string { return "" },
			lookup:    lookupFor(kid, pub),
			ownUUID:   testUUID,
			wantInErr: "missing",
		},
		{
			name:      "not base64",
			b64:       func(t *testing.T) string { return "!!!not base64!!!" },
			lookup:    lookupFor(kid, pub),
			ownUUID:   testUUID,
			wantInErr: "base64",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifyTombstone(tc.b64(t), tc.lookup, tc.ownUUID)
			if err == nil {
				t.Fatal("expected rejection, got nil error")
			}
			if !strings.Contains(err.Error(), tc.wantInErr) {
				t.Fatalf("error %q does not mention %q", err, tc.wantInErr)
			}
		})
	}
}

// A single flipped byte in the signed payload must fail the signature
// check, not slip through as a parse error.
func TestVerifyTombstone_TamperedPayload(t *testing.T) {
	pub, priv, _ := GenerateKeypair()
	kid := KidFromPubkey(pub)

	b64 := buildTestTombstone(t, priv, kid, defaultOpts(testUUID))
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Flip a byte inside the CBOR payload region (the JSON body sits in
	// the back half of the message, ahead of the signature).
	idx := len(raw) / 2
	raw[idx] ^= 0xFF

	_, err = VerifyTombstone(base64.StdEncoding.EncodeToString(raw), lookupFor(kid, pub), testUUID)
	if err == nil {
		t.Fatal("tampered tombstone verified")
	}
}

// tombstoneVector is the cross-module test vector NDManager publishes
// alongside the decommission contract. It is the only check that catches
// a wire-format divergence between the two sides — every other test here
// mints its own tombstone and would happily agree with itself.
//
// NDAGENT_TOMBSTONE_VECTOR overrides the path; the test skips when the
// file is absent rather than failing, so a checkout without it stays
// green.
type tombstoneVector struct {
	DeviceUUID   string `json:"device_uuid"`
	DeletedAt    string `json:"deleted_at"`
	Kid          string `json:"kid"`
	TombstoneB64 string `json:"tombstone_b64"`
	PublicKeyJWK struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		X   string `json:"x"`
	} `json:"public_key_jwk"`
}

func TestVerifyTombstone_NDManagerVector(t *testing.T) {
	path := os.Getenv("NDAGENT_TOMBSTONE_VECTOR")
	if path == "" {
		path = filepath.Join("testdata", "decommission-tombstone-vector.json")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("no NDManager tombstone vector at %s; skipping", path)
	}

	var v tombstoneVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vector: %v", err)
	}

	// JWK x is base64url without padding (RFC 7517 / RFC 8037); the
	// agent's own helpers speak standard base64, so decode it here.
	xRaw, err := base64.RawURLEncoding.DecodeString(v.PublicKeyJWK.X)
	if err != nil {
		t.Fatalf("decode jwk x: %v", err)
	}
	if len(xRaw) != ed25519.PublicKeySize {
		t.Fatalf("jwk x is %d bytes, want %d", len(xRaw), ed25519.PublicKeySize)
	}
	pub := ed25519.PublicKey(xRaw)

	// The kid the agent derives must match the one NDManager published,
	// or the agent would never resolve the key in its pinned table.
	kid := KidFromPubkey(pub)
	if got := hex.EncodeToString(kid); got != v.Kid {
		t.Fatalf("derived kid %s, vector says %s", got, v.Kid)
	}

	ts, err := VerifyTombstone(v.TombstoneB64, lookupFor(kid, pub), v.DeviceUUID)
	if err != nil {
		t.Fatalf("NDManager vector failed agent verification: %v", err)
	}
	if ts.DeviceUUID != v.DeviceUUID {
		t.Errorf("device_uuid = %q, want %q", ts.DeviceUUID, v.DeviceUUID)
	}
	if ts.DeletedAt != v.DeletedAt {
		t.Errorf("deleted_at = %q, want %q", ts.DeletedAt, v.DeletedAt)
	}

	// The same vector must be refused for any other device.
	if _, err := VerifyTombstone(v.TombstoneB64, lookupFor(kid, pub), testUUID); err == nil {
		t.Error("the vector verified against a different device_uuid")
	}
}
