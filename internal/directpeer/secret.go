package directpeer

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

// What both ends of a session derive its secret with. A change to any of
// them is another protocol number.
const (
	sealInfo        = "netdefense-connect-v1"
	labelServerNode = "netdefense-connect-v1 server-node-key"
	labelClientNode = "netdefense-connect-v1 client-node-key"
	labelPreshared  = "netdefense-connect-v1 preshared-key"

	// SealedMaxBytes bounds the sealed secret, before base64.
	SealedMaxBytes = 1024

	sealedVersion = 1
)

// Secret is what the client sealed to this device for one session: the seed
// its keys come from, and what the seed was made for. Only the device's
// identity key opens it, so the control plane that carried it never saw it.
type Secret struct {
	seed [32]byte

	ConnectID     string
	DeviceUUID    string
	ClientKey     [32]byte
	RelayHost     string
	RelayPort     uint64
	RelaySTUNPort uint64
	Exp           uint64
}

// A Secret prints without its seed, whatever the verb.
func (s *Secret) String() string   { return "directpeer.Secret{" + s.ConnectID + "}" }
func (s *Secret) GoString() string { return s.String() }

// Wipe forgets the seed.
func (s *Secret) Wipe() {
	if s != nil {
		clear(s.seed[:])
	}
}

// Unseal opens sealed, the base64 text of a task's payload, with the device's
// identity key, and reads the secret in it. Any error is the session's
// FailUnsealFailed; its text is for the log and names no value.
func Unseal(device ed25519.PrivateKey, sealed string) (*Secret, error) {
	if len(device) != ed25519.PrivateKeySize {
		return nil, errors.New("no device key")
	}
	if len(sealed) > base64.StdEncoding.EncodedLen(SealedMaxBytes) {
		return nil, errors.New("the sealed data is too long")
	}
	// The decoder passes over line breaks; the sealed text has one spelling.
	blob, err := base64.StdEncoding.Strict().DecodeString(sealed)
	if err != nil || strings.ContainsAny(sealed, "\r\n") {
		return nil, errors.New("the sealed data is not base64")
	}
	if len(blob) == 0 || len(blob) > SealedMaxBytes {
		return nil, errors.New("the sealed data has the wrong size")
	}

	// The device's X25519 key is the first half of the SHA-512 of its
	// Ed25519 seed: the private scalar of the same point the client seals to.
	digest := sha512.Sum512(device.Seed())
	defer clear(digest[:])
	recipient, err := hpke.DHKEM(ecdh.X25519()).NewPrivateKey(digest[:32])
	if err != nil {
		return nil, errors.New("the device key cannot open sealed data")
	}
	plaintext, err := hpke.Open(recipient, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), []byte(sealInfo), blob)
	if err != nil {
		return nil, errors.New("the sealed data does not open with this device's key")
	}
	defer clear(plaintext)
	return parseSecret(plaintext)
}

var secretDecMode = func() cbor.DecMode {
	mode, err := cbor.DecOptions{
		DupMapKey:   cbor.DupMapKeyEnforcedAPF,
		IndefLength: cbor.IndefLengthForbidden,
		TagsMd:      cbor.TagsForbidden,
		MaxMapPairs: 16,
	}.DecMode()
	if err != nil {
		panic(err)
	}
	return mode
}()

// CBOR major types, the top three bits of an item's first byte.
const (
	cborUnsigned = 0
	cborBytes    = 2
	cborText     = 3
	cborMap      = 5
)

// cborItem decodes raw into dst after checking that it is of the major type
// asked for. The decoder alone converts between types where Go allows it (an
// array of small numbers into a byte slice), and the secret's types are exact.
func cborItem(raw cbor.RawMessage, major byte, dst any) error {
	if len(raw) == 0 || raw[0]>>5 != major {
		return errors.New("wrong type")
	}
	return secretDecMode.Unmarshal(raw, dst)
}

// cborMapOf reads raw as a map with exactly the text keys named.
func cborMapOf(raw []byte, keys ...string) (map[string]cbor.RawMessage, error) {
	if len(raw) == 0 || raw[0]>>5 != cborMap {
		return nil, errors.New("not a map")
	}
	var fields map[string]cbor.RawMessage
	if err := secretDecMode.Unmarshal(raw, &fields); err != nil {
		return nil, errors.New("not a map of text keys")
	}
	if len(fields) != len(keys) {
		return nil, errors.New("wrong number of keys")
	}
	for _, key := range keys {
		if _, ok := fields[key]; !ok {
			return nil, fmt.Errorf("no %q", key)
		}
	}
	return fields, nil
}

// parseSecret reads the sealed plaintext: one map with exactly seven keys of
// exact types. A missing, extra or repeated key, a wrong type or anything
// after the map refuses it.
func parseSecret(plaintext []byte) (*Secret, error) {
	fields, err := cborMapOf(plaintext, "v", "seed", "connect_id", "device_uuid", "client_key", "relay", "exp")
	if err != nil {
		return nil, fmt.Errorf("the sealed data is malformed: %w", err)
	}
	// The decoder copied each value: the seed is in one of them.
	defer func() {
		for _, raw := range fields {
			clear(raw)
		}
	}()
	relay, err := cborMapOf(fields["relay"], "hostname", "derp_port", "stun_port")
	if err != nil {
		return nil, fmt.Errorf("the sealed relay is malformed: %w", err)
	}

	var (
		s         Secret
		version   uint64
		seed, key []byte
	)
	defer func() { clear(seed) }()
	for _, f := range []struct {
		name  string
		raw   cbor.RawMessage
		major byte
		dst   any
	}{
		{"v", fields["v"], cborUnsigned, &version},
		{"seed", fields["seed"], cborBytes, &seed},
		{"connect_id", fields["connect_id"], cborText, &s.ConnectID},
		{"device_uuid", fields["device_uuid"], cborText, &s.DeviceUUID},
		{"client_key", fields["client_key"], cborBytes, &key},
		{"exp", fields["exp"], cborUnsigned, &s.Exp},
		{"relay hostname", relay["hostname"], cborText, &s.RelayHost},
		{"relay derp_port", relay["derp_port"], cborUnsigned, &s.RelayPort},
		{"relay stun_port", relay["stun_port"], cborUnsigned, &s.RelaySTUNPort},
	} {
		if err := cborItem(f.raw, f.major, f.dst); err != nil {
			return nil, fmt.Errorf("the sealed data is malformed: %s has the wrong type", f.name)
		}
	}
	switch {
	case version != sealedVersion:
		return nil, errors.New("the sealed data is of a version this agent does not read")
	case len(seed) != len(s.seed):
		return nil, errors.New("the sealed data is malformed: the seed is not 32 bytes")
	case len(key) != len(s.ClientKey):
		return nil, errors.New("the sealed data is malformed: the client key is not 32 bytes")
	}
	copy(s.seed[:], seed)
	copy(s.ClientKey[:], key)
	return &s, nil
}

// Bindings are what a secret must have been sealed for: the values of the
// signed task that carried it and the device's own identity.
type Bindings struct {
	ConnectID  string
	DeviceUUID string
	// Exp is the signed task's expiry, in Unix seconds.
	Exp           int64
	RelayHost     string
	RelayPort     int
	RelaySTUNPort int
}

// CheckBindings refuses a secret sealed for another session, another device,
// another expiry or another relay: one lifted from the task it was made for
// and put into another. An error is the session's FailBindingMismatch and
// names the field, never its value.
func (s *Secret) CheckBindings(b Bindings) error {
	switch {
	case s.ConnectID == "" || s.ConnectID != b.ConnectID:
		return errors.New("sealed for another session id")
	case s.DeviceUUID == "" || s.DeviceUUID != b.DeviceUUID:
		return errors.New("sealed for another device")
	case b.Exp <= 0 || s.Exp != uint64(b.Exp):
		return errors.New("sealed with another expiry")
	case s.RelayHost == "" || s.RelayHost != b.RelayHost:
		return errors.New("sealed for another relay host")
	case b.RelayPort <= 0 || s.RelayPort != uint64(b.RelayPort):
		return errors.New("sealed for another relay port")
	case b.RelaySTUNPort <= 0 || s.RelaySTUNPort != uint64(b.RelaySTUNPort):
		return errors.New("sealed for another relay STUN port")
	}
	return nil
}

// clampNodeKey makes 32 bytes an X25519 private scalar in the one form both
// ends hand their tunnel. The tunnel derives a second key from these bytes as
// they are, so both ends clamp, here, right after the derivation.
func clampNodeKey(k *[32]byte) {
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
}

func nodePublic(private [32]byte) ([32]byte, error) {
	var public [32]byte
	key, err := ecdh.X25519().NewPrivateKey(private[:])
	if err != nil {
		return public, err
	}
	copy(public[:], key.PublicKey().Bytes())
	return public, nil
}

// Keys derives the session's keys from the seed and checks them against what
// the client sealed and what the control plane registered with the relay:
// admitServer and admitClient are the two node public keys of the signed
// task, 64 lowercase hex characters each. An error is the session's
// FailKeyMismatch: the client derived its keys another way, or the task names
// keys that are not this secret's, and the session would never pair.
func (s *Secret) Keys(admitServer, admitClient string) (Keys, error) {
	var (
		keys   Keys
		client [32]byte
	)
	defer clear(client[:])
	for _, d := range []struct {
		label string
		dst   *[32]byte
	}{
		{labelServerNode, &keys.Node},
		{labelClientNode, &client},
		{labelPreshared, &keys.PSK},
	} {
		out, err := hkdf.Key(sha256.New, s.seed[:], nil, d.label, len(d.dst))
		if err != nil {
			keys.Wipe()
			return Keys{}, errors.New("the session's keys could not be derived")
		}
		copy(d.dst[:], out)
		clear(out)
	}
	clampNodeKey(&keys.Node)
	clampNodeKey(&client)

	serverPublic, errServer := nodePublic(keys.Node)
	clientPublic, errClient := nodePublic(client)
	var problem string
	switch {
	case errServer != nil || errClient != nil:
		problem = "the session's keys could not be derived"
	case subtle.ConstantTimeCompare(clientPublic[:], s.ClientKey[:]) != 1:
		problem = "the sealed client key is not the one the seed gives"
	case !sameNodeKey(admitServer, serverPublic):
		problem = "the registered server key is not the one the seed gives"
	case !sameNodeKey(admitClient, clientPublic):
		problem = "the registered client key is not the one the seed gives"
	}
	if problem != "" {
		keys.Wipe()
		return Keys{}, errors.New(problem)
	}
	keys.Peer = clientPublic
	return keys, nil
}

// sameNodeKey compares a node public key in the contract's text form, 64
// lowercase hex characters, with key.
func sameNodeKey(text string, key [32]byte) bool {
	var want [64]byte
	hex.Encode(want[:], key[:])
	return len(text) == len(want) && subtle.ConstantTimeCompare([]byte(text), want[:]) == 1
}

// Wipe forgets the keys.
func (k *Keys) Wipe() {
	clear(k.Node[:])
	clear(k.Peer[:])
	clear(k.PSK[:])
}
