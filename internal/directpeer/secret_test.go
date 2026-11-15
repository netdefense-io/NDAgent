package directpeer

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// secretVector is the part of the shared vector the session secret is held to.
type secretVector struct {
	DeviceKey struct {
		SeedB64 string `json:"ed25519_seed_b64"`
	} `json:"device_key"`
	SessionKeys struct {
		SeedHex          string `json:"seed_hex"`
		ServerPrivateHex string `json:"server_node_private_hex"`
		ServerPublicHex  string `json:"server_node_public_hex"`
		ClientPublicHex  string `json:"client_node_public_hex"`
		PresharedKeyHex  string `json:"preshared_key_hex"`
	} `json:"session_keys"`
	Labels struct {
		HPKEInfo      string `json:"hpke_info"`
		ServerNodeKey string `json:"server_node_key"`
		ClientNodeKey string `json:"client_node_key"`
		PresharedKey  string `json:"preshared_key"`
	} `json:"labels"`
	Sealed struct {
		Plaintext struct {
			V          uint64 `json:"v"`
			SeedHex    string `json:"seed_hex"`
			ConnectID  string `json:"connect_id"`
			DeviceUUID string `json:"device_uuid"`
			ClientKey  string `json:"client_key_hex"`
			Relay      struct {
				Hostname string `json:"hostname"`
				DERPPort uint64 `json:"derp_port"`
				STUNPort uint64 `json:"stun_port"`
			} `json:"relay"`
			Exp uint64 `json:"exp"`
		} `json:"plaintext"`
		PlaintextCBORHex string `json:"plaintext_cbor_hex"`
		SealedB64        string `json:"sealed_b64"`
		MustNotOpen      struct {
			AnotherInfoB64 string `json:"sealed_with_another_info_b64"`
			TamperedB64    string `json:"tampered_b64"`
		} `json:"must_not_open"`
	} `json:"sealed"`
	Payloads struct {
		Open struct {
			AdmitKeys struct {
				Server string `json:"server"`
				Client string `json:"client"`
			} `json:"admit_keys"`
		} `json:"open"`
	} `json:"payloads"`
}

func loadSecretVector(t *testing.T) secretVector {
	t.Helper()
	data, err := os.ReadFile(contractVectorPath)
	if err != nil {
		t.Fatal(err)
	}
	var v secretVector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func vectorDeviceKey(t *testing.T, v secretVector) ed25519.PrivateKey {
	t.Helper()
	seed, err := base64.StdEncoding.DecodeString(v.DeviceKey.SeedB64)
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.NewKeyFromSeed(seed)
}

// sealFor seals plaintext to device as a client does: to the X25519 form of
// the device's identity key.
func sealFor(t *testing.T, device ed25519.PrivateKey, info string, plaintext []byte) string {
	t.Helper()
	digest := sha512.Sum512(device.Seed())
	private, err := ecdh.X25519().NewPrivateKey(digest[:32])
	if err != nil {
		t.Fatal(err)
	}
	public, err := hpke.DHKEM(ecdh.X25519()).NewPublicKey(private.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := hpke.Seal(public, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), []byte(info), plaintext)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(sealed)
}

func vectorBindings(v secretVector) Bindings {
	p := v.Sealed.Plaintext
	return Bindings{
		ConnectID:     p.ConnectID,
		DeviceUUID:    p.DeviceUUID,
		Exp:           int64(p.Exp),
		RelayHost:     p.Relay.Hostname,
		RelayPort:     int(p.Relay.DERPPort),
		RelaySTUNPort: int(p.Relay.STUNPort),
	}
}

func TestUnsealOpensTheVectorAndDerivesItsKeys(t *testing.T) {
	v := loadSecretVector(t)
	secret, err := Unseal(vectorDeviceKey(t, v), v.Sealed.SealedB64)
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	p := v.Sealed.Plaintext
	if got := hex.EncodeToString(secret.seed[:]); got != p.SeedHex {
		t.Errorf("seed = %s, want %s", got, p.SeedHex)
	}
	if got := hex.EncodeToString(secret.ClientKey[:]); got != p.ClientKey {
		t.Errorf("client key = %s, want %s", got, p.ClientKey)
	}
	if secret.ConnectID != p.ConnectID || secret.DeviceUUID != p.DeviceUUID || secret.Exp != p.Exp ||
		secret.RelayHost != p.Relay.Hostname || secret.RelayPort != p.Relay.DERPPort || secret.RelaySTUNPort != p.Relay.STUNPort {
		t.Errorf("decoded %+v, want the vector's plaintext %+v", secret, p)
	}
	if err := secret.CheckBindings(vectorBindings(v)); err != nil {
		t.Errorf("CheckBindings: %v", err)
	}

	keys, err := secret.Keys(v.Payloads.Open.AdmitKeys.Server, v.Payloads.Open.AdmitKeys.Client)
	if err != nil {
		t.Fatalf("Keys: %v", err)
	}
	for _, c := range []struct {
		name string
		got  [32]byte
		want string
	}{
		{"server node private key (clamped)", keys.Node, v.SessionKeys.ServerPrivateHex},
		{"client node public key", keys.Peer, v.SessionKeys.ClientPublicHex},
		{"pre-shared key", keys.PSK, v.SessionKeys.PresharedKeyHex},
	} {
		if got := hex.EncodeToString(c.got[:]); got != c.want {
			t.Errorf("%s = %s, want %s", c.name, got, c.want)
		}
	}
	spec := Spec{Relay: Relay{ID: "eu", Host: p.Relay.Hostname}, Keys: keys}
	if err := spec.validate(); err != nil {
		t.Errorf("the derived keys are not ones a companion takes: %v", err)
	}
}

// The labels and the info string are the contract's, spelled out here: a
// constant changed to match its test would agree with it and be wrong.
func TestTheDerivationLabelsAreTheContracts(t *testing.T) {
	v := loadSecretVector(t)
	for _, c := range []struct{ name, got, vector, literal string }{
		{"info", sealInfo, v.Labels.HPKEInfo, "netdefense-connect-v1"},
		{"server", labelServerNode, v.Labels.ServerNodeKey, "netdefense-connect-v1 server-node-key"},
		{"client", labelClientNode, v.Labels.ClientNodeKey, "netdefense-connect-v1 client-node-key"},
		{"psk", labelPreshared, v.Labels.PresharedKey, "netdefense-connect-v1 preshared-key"},
	} {
		if c.got != c.literal || c.vector != c.literal {
			t.Errorf("%s label: code %q, vector %q, contract %q", c.name, c.got, c.vector, c.literal)
		}
	}
	if SealedMaxBytes != 1024 {
		t.Errorf("SealedMaxBytes = %d, want 1024", SealedMaxBytes)
	}
}

func TestUnsealRefusesWhatMustNotOpen(t *testing.T) {
	v := loadSecretVector(t)
	device := vectorDeviceKey(t, v)
	plaintext, err := hex.DecodeString(v.Sealed.PlaintextCBORHex)
	if err != nil {
		t.Fatal(err)
	}
	_, other, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	good := v.Sealed.SealedB64

	cases := map[string]struct {
		device ed25519.PrivateKey
		sealed string
	}{
		"sealed with another info (vector)": {device, v.Sealed.MustNotOpen.AnotherInfoB64},
		"tampered (vector)":                 {device, v.Sealed.MustNotOpen.TamperedB64},
		"sealed with another info":          {device, sealFor(t, device, "netdefense-connect-v2", plaintext)},
		"another device's key":              {other, good},
		"no device key":                     {nil, good},
		"empty":                             {device, ""},
		"not base64":                        {device, "!" + good[1:]},
		"base64 without padding":            {device, strings.TrimRight(base64.StdEncoding.EncodeToString(append(mustB64(t, good), 0)), "=")},
		"url-safe base64":                   {device, base64.URLEncoding.EncodeToString(mustB64(t, good))},
		"base64 with a line break":          {device, good[:8] + "\n" + good[8:]},
		"only an encapsulated key":          {device, base64.StdEncoding.EncodeToString(mustB64(t, good)[:32])},
		"truncated":                         {device, base64.StdEncoding.EncodeToString(mustB64(t, good)[:len(mustB64(t, good))-1])},
		"over the size bound":               {device, sealFor(t, device, sealInfo, bytes.Repeat([]byte{0}, SealedMaxBytes))},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if c.sealed == good && c.device != nil && c.device.Equal(device) {
				t.Fatal("the case is the good blob")
			}
			secret, err := Unseal(c.device, c.sealed)
			if err == nil {
				t.Fatalf("opened: %v", secret)
			}
		})
	}

	// The control: the same sealer with the right info opens.
	if _, err := Unseal(device, sealFor(t, device, sealInfo, plaintext)); err != nil {
		t.Fatalf("a blob sealed here with the contract's parameters does not open: %v", err)
	}
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// goodPlaintext is the vector's plaintext as a Go value a test can bend.
func goodPlaintext(v secretVector) map[string]any {
	p := v.Sealed.Plaintext
	seed, _ := hex.DecodeString(p.SeedHex)
	key, _ := hex.DecodeString(p.ClientKey)
	return map[string]any{
		"v":           p.V,
		"seed":        seed,
		"connect_id":  p.ConnectID,
		"device_uuid": p.DeviceUUID,
		"client_key":  key,
		"relay": map[string]any{
			"hostname":  p.Relay.Hostname,
			"derp_port": p.Relay.DERPPort,
			"stun_port": p.Relay.STUNPort,
		},
		"exp": p.Exp,
	}
}

func mustCBOR(t *testing.T, v any) []byte {
	t.Helper()
	out, err := cbor.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestTheSealedPlaintextIsReadExactly(t *testing.T) {
	v := loadSecretVector(t)
	device := vectorDeviceKey(t, v)

	bend := func(change func(m map[string]any)) []byte {
		m := goodPlaintext(v)
		change(m)
		return mustCBOR(t, m)
	}
	relay := func(m map[string]any) map[string]any { return m["relay"].(map[string]any) }
	good := mustCBOR(t, goodPlaintext(v))

	// A map of seven pairs whose last key repeats the first: the header says
	// seven, so only a decoder that looks at the keys refuses it.
	repeated := func() []byte {
		m := goodPlaintext(v)
		delete(m, "exp")
		six := mustCBOR(t, m)
		out := append([]byte{0xa7}, six[1:]...)
		return append(out, mustCBOR(t, "v")[0:]...)
	}()
	repeated = append(repeated, 0x01)

	// All seven keys and one of them a second time: seven different keys,
	// so only a decoder that refuses a repeated key refuses it.
	eight := append([]byte{0xa8}, good[1:]...)
	eight = append(append(eight, mustCBOR(t, "v")...), 0x01)

	// The same map with an indefinite length.
	indefinite := append(append([]byte{0xbf}, good[1:]...), 0xff)

	cases := map[string][]byte{
		"empty":                         {},
		"not a map":                     mustCBOR(t, []any{1, 2, 3}),
		"missing key":                   bend(func(m map[string]any) { delete(m, "exp") }),
		"extra key":                     bend(func(m map[string]any) { m["note"] = "x" }),
		"another key in place of one":   bend(func(m map[string]any) { delete(m, "exp"); m["expires"] = uint64(1) }),
		"repeated key":                  repeated,
		"repeated key beside all seven": eight,
		"indefinite-length map":         indefinite,
		"bytes after the map":           append(bytes.Clone(good), 0x00),
		"a tag around the map":          append([]byte{0xd8, 0x2a}, good...),
		"integer key":                   mustCBOR(t, map[any]any{1: 1, "seed": 1, "connect_id": 1, "device_uuid": 1, "client_key": 1, "relay": 1, "exp": 1}),
		"version 2":                     bend(func(m map[string]any) { m["v"] = uint64(2) }),
		"version 0":                     bend(func(m map[string]any) { m["v"] = uint64(0) }),
		"version as text":               bend(func(m map[string]any) { m["v"] = "1" }),
		"version negative":              bend(func(m map[string]any) { m["v"] = -1 }),
		"version as a float":            bend(func(m map[string]any) { m["v"] = 1.5 }),
		"seed as text":                  bend(func(m map[string]any) { m["seed"] = v.Sealed.Plaintext.SeedHex }),
		"seed as an array of numbers":   bend(func(m map[string]any) { m["seed"] = make([]int, 32) }),
		"seed of 31 bytes":              bend(func(m map[string]any) { m["seed"] = make([]byte, 31) }),
		"seed of 33 bytes":              bend(func(m map[string]any) { m["seed"] = make([]byte, 33) }),
		"seed empty":                    bend(func(m map[string]any) { m["seed"] = []byte{} }),
		"seed null":                     bend(func(m map[string]any) { m["seed"] = nil }),
		"client key of 31 bytes":        bend(func(m map[string]any) { m["client_key"] = make([]byte, 31) }),
		"client key as text":            bend(func(m map[string]any) { m["client_key"] = v.Sealed.Plaintext.ClientKey }),
		"connect_id as bytes":           bend(func(m map[string]any) { m["connect_id"] = []byte(v.Sealed.Plaintext.ConnectID) }),
		"connect_id as a number":        bend(func(m map[string]any) { m["connect_id"] = uint64(7) }),
		"device_uuid as bytes":          bend(func(m map[string]any) { m["device_uuid"] = []byte("x") }),
		"exp as text":                   bend(func(m map[string]any) { m["exp"] = "1794700800" }),
		"exp negative":                  bend(func(m map[string]any) { m["exp"] = -1794700800 }),
		"exp as a float":                bend(func(m map[string]any) { m["exp"] = 1794700800.0 }),
		"relay as text":                 bend(func(m map[string]any) { m["relay"] = "relay-eu.example.net" }),
		"relay as an array":             bend(func(m map[string]any) { m["relay"] = []any{"h", 443, 3478} }),
		"relay missing a key":           bend(func(m map[string]any) { delete(relay(m), "stun_port") }),
		"relay with an extra key":       bend(func(m map[string]any) { relay(m)["id"] = "eu" }),
		"relay hostname as bytes":       bend(func(m map[string]any) { relay(m)["hostname"] = []byte("h") }),
		"relay port as text":            bend(func(m map[string]any) { relay(m)["derp_port"] = "443" }),
		"relay STUN port negative":      bend(func(m map[string]any) { relay(m)["stun_port"] = -3478 }),
		"relay port as a float":         bend(func(m map[string]any) { relay(m)["derp_port"] = 443.0 }),
		"relay port beyond 64 bits": bend(func(m map[string]any) {
			relay(m)["derp_port"] = cbor.Tag{Number: 2, Content: bytes.Repeat([]byte{0xff}, 9)}
		}),
		"nested deeper than a session": bend(func(m map[string]any) { m["exp"] = map[string]any{"at": uint64(1)} }),
	}

	for name, plaintext := range cases {
		t.Run(name, func(t *testing.T) {
			if secret, err := parseSecret(plaintext); err == nil {
				t.Fatalf("parseSecret read it: %+v", secret)
			}
			if len(plaintext) == 0 {
				return
			}
			if secret, err := Unseal(device, sealFor(t, device, sealInfo, plaintext)); err == nil {
				t.Fatalf("Unseal read it: %+v", secret)
			}
		})
	}

	t.Run("the keys in another order are read", func(t *testing.T) {
		p := v.Sealed.Plaintext
		seed, _ := hex.DecodeString(p.SeedHex)
		key, _ := hex.DecodeString(p.ClientKey)
		type relayT struct {
			STUN uint64 `cbor:"stun_port"`
			Host string `cbor:"hostname"`
			DERP uint64 `cbor:"derp_port"`
		}
		reordered := mustCBOR(t, struct {
			Exp    uint64 `cbor:"exp"`
			Relay  relayT `cbor:"relay"`
			Key    []byte `cbor:"client_key"`
			Device string `cbor:"device_uuid"`
			ID     string `cbor:"connect_id"`
			Seed   []byte `cbor:"seed"`
			V      uint64 `cbor:"v"`
		}{p.Exp, relayT{p.Relay.STUNPort, p.Relay.Hostname, p.Relay.DERPPort}, key, p.DeviceUUID, p.ConnectID, seed, p.V})
		vectorBytes, _ := hex.DecodeString(v.Sealed.PlaintextCBORHex)
		if bytes.Equal(reordered, vectorBytes) {
			t.Fatal("the reordered plaintext is the vector's own bytes")
		}
		secret, err := Unseal(device, sealFor(t, device, sealInfo, reordered))
		if err != nil {
			t.Fatalf("Unseal: %v", err)
		}
		if err := secret.CheckBindings(vectorBindings(v)); err != nil {
			t.Fatalf("CheckBindings: %v", err)
		}
		if _, err := secret.Keys(v.Payloads.Open.AdmitKeys.Server, v.Payloads.Open.AdmitKeys.Client); err != nil {
			t.Fatalf("Keys: %v", err)
		}
	})
}

func TestCheckBindingsRefusesASecretMadeForSomethingElse(t *testing.T) {
	v := loadSecretVector(t)
	secret, err := Unseal(vectorDeviceKey(t, v), v.Sealed.SealedB64)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(b *Bindings){
		"another session id":       func(b *Bindings) { b.ConnectID = "eff97f3e3ad593d08e250b5a5e49244a" },
		"session id in upper case": func(b *Bindings) { b.ConnectID = strings.ToUpper(b.ConnectID) },
		"no session id":            func(b *Bindings) { b.ConnectID = "" },
		"another device":           func(b *Bindings) { b.DeviceUUID = "3f2b8c1e-6a4d-4e0b-9c57-d1a2b3c4e5f7" },
		"no device":                func(b *Bindings) { b.DeviceUUID = "" },
		"expiry one second later":  func(b *Bindings) { b.Exp++ },
		"expiry one second sooner": func(b *Bindings) { b.Exp-- },
		"no expiry":                func(b *Bindings) { b.Exp = 0 },
		"negative expiry":          func(b *Bindings) { b.Exp = -b.Exp },
		"another relay host":       func(b *Bindings) { b.RelayHost = "relay-us.example.net" },
		"relay host with a dot":    func(b *Bindings) { b.RelayHost += "." },
		"relay host in upper case": func(b *Bindings) { b.RelayHost = strings.ToUpper(b.RelayHost) },
		"another relay port":       func(b *Bindings) { b.RelayPort = 8443 },
		"no relay port":            func(b *Bindings) { b.RelayPort = 0 },
		"another STUN port":        func(b *Bindings) { b.RelaySTUNPort = 3479 },
		"no STUN port":             func(b *Bindings) { b.RelaySTUNPort = 0 },
		"the two ports swapped":    func(b *Bindings) { b.RelayPort, b.RelaySTUNPort = b.RelaySTUNPort, b.RelayPort },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			b := vectorBindings(v)
			change(&b)
			if err := secret.CheckBindings(b); err == nil {
				t.Fatal("accepted")
			}
		})
	}

	t.Run("an empty secret matches no empty bindings", func(t *testing.T) {
		if err := (&Secret{}).CheckBindings(Bindings{}); err == nil {
			t.Fatal("accepted")
		}
	})
}

func TestKeysRefusesKeysThatAreNotTheSeeds(t *testing.T) {
	v := loadSecretVector(t)
	device := vectorDeviceKey(t, v)
	server, client := v.Payloads.Open.AdmitKeys.Server, v.Payloads.Open.AdmitKeys.Client
	if server != v.SessionKeys.ServerPublicHex || client != v.SessionKeys.ClientPublicHex {
		t.Fatal("the vector's admit keys are not its session keys")
	}

	open := func(t *testing.T) *Secret {
		t.Helper()
		secret, err := Unseal(device, v.Sealed.SealedB64)
		if err != nil {
			t.Fatal(err)
		}
		return secret
	}
	cases := map[string]struct {
		change         func(s *Secret)
		server, client string
	}{
		"another server key registered": {nil, client, client},
		"another client key registered": {nil, server, server},
		"the two keys swapped":          {nil, client, server},
		"server key in upper case":      {nil, strings.ToUpper(server), client},
		"client key in upper case":      {nil, server, strings.ToUpper(client)},
		"server key with a prefix":      {nil, "nodekey:" + server, client},
		"no server key":                 {nil, "", client},
		"no client key":                 {nil, server, ""},
		"client key one character off":  {nil, server, client[:63] + flipHex(client[63])},
		"sealed client key is another":  {func(s *Secret) { s.ClientKey[0] ^= 1 }, server, client},
		"another seed":                  {func(s *Secret) { s.seed[0] ^= 1 }, server, client},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			secret := open(t)
			if c.change != nil {
				c.change(secret)
			}
			keys, err := secret.Keys(c.server, c.client)
			if err == nil {
				t.Fatal("accepted")
			}
			if keys != (Keys{}) {
				t.Fatal("a refusal returned key material")
			}
			if strings.Contains(err.Error(), server) || strings.Contains(err.Error(), client) {
				t.Fatalf("the error names a key: %v", err)
			}
		})
	}
}

func flipHex(c byte) string {
	if c == '0' {
		return "1"
	}
	return "0"
}

func TestWipeForgetsTheSecret(t *testing.T) {
	v := loadSecretVector(t)
	secret, err := Unseal(vectorDeviceKey(t, v), v.Sealed.SealedB64)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := secret.Keys(v.Payloads.Open.AdmitKeys.Server, v.Payloads.Open.AdmitKeys.Client)
	if err != nil {
		t.Fatal(err)
	}
	secret.Wipe()
	keys.Wipe()
	if secret.seed != ([32]byte{}) || keys != (Keys{}) {
		t.Fatal("something is left after Wipe")
	}
	(*Secret)(nil).Wipe()
}

func TestASecretPrintsWithoutItsSeed(t *testing.T) {
	v := loadSecretVector(t)
	secret, err := Unseal(vectorDeviceKey(t, v), v.Sealed.SealedB64)
	if err != nil {
		t.Fatal(err)
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		for _, value := range []any{secret, []*Secret{secret}} {
			out := fmt.Sprintf(verb, value)
			if strings.Contains(out, "178 187") || strings.Contains(out, "b2bb") || strings.Contains(out, "0xb2") {
				t.Errorf("%s prints the seed: %s", verb, out)
			}
		}
	}
}
