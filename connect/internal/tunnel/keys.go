package tunnel

import (
	"fmt"

	"go4.org/mem"
	"tailscale.com/types/key"
)

// NodeKey turns 32 bytes into this node's private key. It refuses bytes that
// are not a clamped Curve25519 scalar and never changes them: the library
// derives a second key, the one used to find a direct path, from these very
// bytes, and the peer derives the same key from its own copy. Clamping here
// would leave the handshake working and the two ends disagreeing about that
// second key, so the session would stay on the relay with no error anywhere.
// Whoever derives the key clamps it.
func NodeKey(raw [32]byte) (key.NodePrivate, error) {
	if raw[0]&7 != 0 || raw[31]&0x80 != 0 || raw[31]&0x40 == 0 {
		return key.NodePrivate{}, fmt.Errorf("%w: the node key is not a clamped scalar", ErrConfig)
	}
	return key.NodePrivateFromRaw32(mem.B(raw[:])), nil
}

// PeerKey turns 32 bytes into the peer's public key.
func PeerKey(raw [32]byte) key.NodePublic {
	return key.NodePublicFromRaw32(mem.B(raw[:]))
}
