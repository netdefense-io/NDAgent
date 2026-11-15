// Package ipc is what the companion and the agent say to each other: one
// configuration message on the companion's stdin, then one JSON event per line
// on its stderr. Secrets travel only in the configuration message, never on
// the command line or in the environment.
//
// The agent's copy of these shapes is internal/directpeer in the parent
// module (the two modules share no code). Both are tested against the vectors
// in that package's testdata/ipc.
package ipc

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

const (
	// Version is the version of this exchange. Agent and companion are built
	// from one commit, so a difference means a mixed install.
	Version = 1

	// Protocol is the tunnel protocol number of this build: what the two ends
	// of a session must agree on. It changes when the pinned tunnel library
	// changes what it puts on the wire.
	Protocol = 1

	// RoleServer is the only role this companion has: it serves one port to
	// one peer.
	RoleServer = "server"

	// MaxConfigSize bounds the configuration message.
	MaxConfigSize = 64 << 10

	// DefaultStartTimeoutMS is how long the companion waits for the relay to
	// accept its connection when the configuration names no other bound.
	DefaultStartTimeoutMS = 8000

	minStartTimeoutMS = 1000
	maxStartTimeoutMS = 30000
)

// Key32 is 32 bytes of key material, base64 in JSON. It never prints itself.
type Key32 [32]byte

// IsZero reports whether k is all zero. Not constant time: a zero key is a
// configuration error, not a secret.
func (k Key32) IsZero() bool { return k == Key32{} }

func (k Key32) String() string   { return "[32 bytes]" }
func (k Key32) GoString() string { return "ipc.Key32{...}" }

func (k Key32) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.StdEncoding.EncodeToString(k[:]))
}

func (k *Key32) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return keyError("not a string")
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return keyError("not base64")
	}
	if len(raw) != len(k) {
		clear(raw)
		return keyError(fmt.Sprintf("%d bytes, want %d", len(raw), len(k)))
	}
	copy(k[:], raw)
	clear(raw)
	return nil
}

// keyError is what is wrong with a key field. It never holds the value.
type keyError string

func (e keyError) Error() string { return string(e) }

// Relay is the relay both ends of the session use.
type Relay struct {
	// ID is the relay's short name in the catalogue, e.g. "us".
	ID string `json:"id"`
	// RegionID is the number both ends give the relay. They must agree.
	RegionID int `json:"region_id"`
	// Host is the relay's hostname, which its TLS certificate must match.
	Host string `json:"host"`
	// Port is the relay's TLS port.
	Port int `json:"port"`
	// STUNPort is the relay's UDP port for address discovery.
	STUNPort int `json:"stun_port"`
}

// Config is the configuration message.
type Config struct {
	V        int    `json:"v"`
	Role     string `json:"role"`
	Protocol int    `json:"protocol"`
	Relay    Relay  `json:"relay"`
	// Port is the one TCP port served to the peer.
	Port int `json:"port"`
	// NodeKey is this session's own private key.
	NodeKey Key32 `json:"node_key"`
	// PeerKey is the public key of the one peer allowed to connect.
	PeerKey Key32 `json:"peer_key"`
	// PSK is the session's pre-shared key.
	PSK Key32 `json:"psk"`
	// StartTimeoutMS bounds the wait for the relay; 0 is DefaultStartTimeoutMS.
	StartTimeoutMS int `json:"start_timeout_ms,omitempty"`
	// Debug sends the tunnel library's own log lines as log events.
	Debug bool `json:"debug,omitempty"`
}

// Wipe zeroes the key material in c.
func (c *Config) Wipe() {
	clear(c.NodeKey[:])
	clear(c.PeerKey[:])
	clear(c.PSK[:])
}

var (
	relayIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	hostPattern    = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)
)

func validPort(p int) bool { return p >= 1 && p <= 65535 }

// Validate refuses a configuration with anything missing. Every check is
// here because the tunnel library fills in a value of its own for each thing
// left out: a new key, a new pre-shared key, every peer allowed, a relay
// looked up elsewhere, a port picked at random. The errors name fields, never
// values.
func (c *Config) Validate() error {
	switch {
	case c.V != Version:
		return fmt.Errorf("v: %d, this build speaks %d", c.V, Version)
	case c.Role != RoleServer:
		return errors.New("role: this companion only serves")
	case c.Protocol != Protocol:
		return fmt.Errorf("protocol: %d, this build speaks %d", c.Protocol, Protocol)
	case !relayIDPattern.MatchString(c.Relay.ID):
		return errors.New("relay.id: missing or malformed")
	case c.Relay.RegionID < 1 || c.Relay.RegionID > 65535:
		return errors.New("relay.region_id: must be 1 to 65535")
	case len(c.Relay.Host) > 253 || !hostPattern.MatchString(c.Relay.Host):
		return errors.New("relay.host: missing or not a hostname")
	case !validPort(c.Relay.Port):
		return errors.New("relay.port: must be 1 to 65535")
	case !validPort(c.Relay.STUNPort):
		return errors.New("relay.stun_port: must be 1 to 65535")
	case !validPort(c.Port):
		return errors.New("port: must be 1 to 65535")
	case c.NodeKey.IsZero():
		return errors.New("node_key: missing")
	case c.PeerKey.IsZero():
		return errors.New("peer_key: missing")
	case c.PSK.IsZero():
		return errors.New("psk: missing")
	case c.StartTimeoutMS != 0 && (c.StartTimeoutMS < minStartTimeoutMS || c.StartTimeoutMS > maxStartTimeoutMS):
		return fmt.Errorf("start_timeout_ms: must be %d to %d", minStartTimeoutMS, maxStartTimeoutMS)
	}
	return nil
}

// ErrNoConfig is ReadConfig's error when the stream ended before any
// configuration arrived: the parent went away.
var ErrNoConfig = errors.New("no configuration")

// ReadConfig reads the configuration message from r: a 4-byte big-endian
// length, then that many bytes of JSON. It reads nothing past the message, so
// what follows on r is the session. The result is validated.
func ReadConfig(r io.Reader) (*Config, error) {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, ErrNoConfig
		}
		return nil, errors.New("truncated length")
	}
	n := binary.BigEndian.Uint32(head[:])
	if n == 0 || n > MaxConfigSize {
		return nil, fmt.Errorf("length %d out of range", n)
	}
	body := make([]byte, n)
	defer clear(body)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, errors.New("truncated message")
	}

	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		c.Wipe()
		return nil, describeDecodeError(err)
	}
	if dec.More() {
		c.Wipe()
		return nil, errors.New("more than one JSON value")
	}
	if err := c.Validate(); err != nil {
		c.Wipe()
		return nil, err
	}
	return &c, nil
}

// describeDecodeError keeps a decoding error from quoting the message, which
// holds the keys: only the field and the kind of problem are named.
func describeDecodeError(err error) error {
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) && typeErr.Field != "" {
		return fmt.Errorf("%s: wrong type", typeErr.Field)
	}
	var keyErr keyError
	if errors.As(err, &keyErr) {
		return fmt.Errorf("a key field: %s", string(keyErr))
	}
	var syntaxErr *json.SyntaxError
	if errors.As(err, &syntaxErr) {
		return errors.New("not valid JSON")
	}
	if strings.HasPrefix(err.Error(), "json: unknown field ") {
		return errors.New("a field this build does not know")
	}
	return errors.New("not a configuration message")
}
