package directpeer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// contractVectorPath is the shared vector of the transport's cross-module
// contract: one complete example of a session, the same bytes in every module
// that takes part in one.
const contractVectorPath = "testdata/contract/connect-direct-peer-v1.json"

// contractVectorDigest is its SHA-256, the same literal every copy is held to.
const contractVectorDigest = "b90ed4b4d8c768eba9639a52e5e11f138fbfdc33ed290c312a8d675de62e0897"

func TestTheContractVectorIsTheSharedOne(t *testing.T) {
	data, err := os.ReadFile(contractVectorPath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != contractVectorDigest {
		t.Fatalf("%s has digest %s, want %s: it is a copy and is never edited here", contractVectorPath, got, contractVectorDigest)
	}
}

// contractVector is the part of the vector this package is held to.
type contractVector struct {
	SessionKeys struct {
		ServerNodeKeyHKDFOutputHex string `json:"server_node_key_hkdf_output_hex"`
		ServerNodePrivateHex       string `json:"server_node_private_hex"`
		ClientNodePublicHex        string `json:"client_node_public_hex"`
		PresharedKeyHex            string `json:"preshared_key_hex"`
	} `json:"session_keys"`
	Payloads struct {
		Open struct {
			Protocol int `json:"protocol"`
			Relay    struct {
				ID       string `json:"id"`
				Hostname string `json:"hostname"`
				DERPPort int    `json:"derp_port"`
				STUNPort int    `json:"stun_port"`
			} `json:"relay"`
			Limits struct {
				MaxSeconds     int `json:"max_seconds"`
				IdleSeconds    int `json:"idle_seconds"`
				PairSeconds    int `json:"pair_seconds"`
				DeviceSessions int `json:"device_sessions"`
			} `json:"limits"`
		} `json:"open"`
	} `json:"payloads"`
	Lists struct {
		EndReasons     []string `json:"end_reasons"`
		FailureReasons []string `json:"failure_reasons"`
		Paths          []string `json:"paths"`
	} `json:"lists"`
}

func loadContractVector(t *testing.T) contractVector {
	t.Helper()
	data, err := os.ReadFile(contractVectorPath)
	if err != nil {
		t.Fatal(err)
	}
	var v contractVector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func hex32(t *testing.T, s string) [32]byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 32 {
		t.Fatalf("%q is not 32 bytes of hex", s)
	}
	return [32]byte(raw)
}
