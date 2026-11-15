package tunnel

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/tailscale/tailcat"
)

// The shared vector of the transport's cross-module contract is part of the
// agent's tree; its digest is pinned there.
const contractVectorPath = "../../../internal/directpeer/testdata/contract/connect-direct-peer-v1.json"

type contractSessionKeys struct {
	ServerNodeKeyHKDFOutputHex string `json:"server_node_key_hkdf_output_hex"`
	ServerNodePrivateHex       string `json:"server_node_private_hex"`
	ServerNodePublicHex        string `json:"server_node_public_hex"`
	ServerDiscoPublicHex       string `json:"server_disco_public_hex"`
	ClientNodeKeyHKDFOutputHex string `json:"client_node_key_hkdf_output_hex"`
	ClientNodePrivateHex       string `json:"client_node_private_hex"`
	ClientNodePublicHex        string `json:"client_node_public_hex"`
}

func contractKeys(t *testing.T) contractSessionKeys {
	t.Helper()
	data, err := os.ReadFile(contractVectorPath)
	if err != nil {
		t.Fatalf("the contract's vector is part of the agent's tree: %v", err)
	}
	var vector struct {
		SessionKeys contractSessionKeys `json:"session_keys"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	return vector.SessionKeys
}

func fromHex(t *testing.T, s string) [32]byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 32 {
		t.Fatalf("%q is not 32 bytes of hex", s)
	}
	return [32]byte(raw)
}

// The two ends of a session never exchange the server's keys: each derives
// them from the session seed. So the library, given the vector's clamped
// private keys, must arrive at the vector's public keys, and at its key for
// finding a direct path, which the library makes from the private key's bytes
// as they are. A library version that derives any of them differently cannot
// meet a peer built on the version the contract names.
func TestTheLibraryDerivesTheContractsKeys(t *testing.T) {
	keys := contractKeys(t)

	server, err := NodeKey(fromHex(t, keys.ServerNodePrivateHex))
	if err != nil {
		t.Fatalf("the vector's server key is refused: %v", err)
	}
	if got := server.Public().UntypedHexString(); got != keys.ServerNodePublicHex {
		t.Errorf("server public key = %s, the contract says %s", got, keys.ServerNodePublicHex)
	}
	disco, err := tailcat.DiscoPublicForNode(server).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(disco); got != keys.ServerDiscoPublicHex {
		t.Errorf("the server's path-discovery public key = %s, the contract says %s", got, keys.ServerDiscoPublicHex)
	}

	client, err := NodeKey(fromHex(t, keys.ClientNodePrivateHex))
	if err != nil {
		t.Fatalf("the vector's client key is refused: %v", err)
	}
	if got := client.Public().UntypedHexString(); got != keys.ClientNodePublicHex {
		t.Errorf("client public key = %s, the contract says %s", got, keys.ClientNodePublicHex)
	}
	if got := PeerKey(fromHex(t, keys.ClientNodePublicHex)); got != client.Public() {
		t.Errorf("PeerKey of the client's public key is %s", got.UntypedHexString())
	}
}

// The key as it comes out of the key derivation, before whoever derived it
// clamps it, is refused: used as it is, it would give the same public key and
// another path-discovery key than the peer expects.
func TestTheContractsUnclampedKeysAreRefused(t *testing.T) {
	keys := contractKeys(t)
	for name, unclamped := range map[string]string{
		"server": keys.ServerNodeKeyHKDFOutputHex,
		"client": keys.ClientNodeKeyHKDFOutputHex,
	} {
		raw := fromHex(t, unclamped)
		if _, err := NodeKey(raw); !errors.Is(err, ErrConfig) {
			t.Errorf("%s key before clamping: NodeKey = %v, want a refusal", name, err)
		}
	}

	// And it matters: the same bytes clamped by the library's own
	// constructor give the vector's public key and another discovery key.
	raw := fromHex(t, keys.ServerNodeKeyHKDFOutputHex)
	clamped := raw
	clamped[0] &= 248
	clamped[31] = (clamped[31] & 127) | 64
	if hex.EncodeToString(clamped[:]) != keys.ServerNodePrivateHex {
		t.Fatalf("clamping the vector's key derivation output does not give its private key")
	}
}
