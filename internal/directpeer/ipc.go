package directpeer

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
)

// ipcVersion is the version of the exchange with the companion.
const ipcVersion = 1

// companionRole is the only role the device's companion has.
const companionRole = "server"

// maxConfigSize is the companion's bound on the configuration message.
const maxConfigSize = 64 << 10

// key32 is 32 bytes of key material, base64 in JSON. It never prints itself.
type key32 [32]byte

func (k key32) String() string   { return "[32 bytes]" }
func (k key32) GoString() string { return "directpeer.key32{...}" }

func (k key32) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.StdEncoding.EncodeToString(k[:]))
}

type relayConfig struct {
	ID       string `json:"id"`
	RegionID int    `json:"region_id"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	STUNPort int    `json:"stun_port"`
}

// companionConfig is the one message the agent writes to the companion's
// stdin before the session's frames. It is the only place a key travels.
type companionConfig struct {
	V              int         `json:"v"`
	Role           string      `json:"role"`
	Protocol       int         `json:"protocol"`
	Relay          relayConfig `json:"relay"`
	Port           int         `json:"port"`
	NodeKey        key32       `json:"node_key"`
	PeerKey        key32       `json:"peer_key"`
	PSK            key32       `json:"psk"`
	StartTimeoutMS int         `json:"start_timeout_ms,omitempty"`
	Debug          bool        `json:"debug,omitempty"`
}

// encode returns the message as the companion reads it: a 4-byte big-endian
// length, then the JSON. The caller wipes the result once it is written.
func (c *companionConfig) encode() ([]byte, error) {
	body, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	if len(body) > maxConfigSize {
		clear(body)
		return nil, fmt.Errorf("configuration message of %d bytes", len(body))
	}
	out := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(out, uint32(len(body)))
	copy(out[4:], body)
	clear(body)
	return out, nil
}

// Event names: one JSON object per line on the companion's stderr.
const (
	EventHello     = "hello"     // the companion's version, before it is given anything
	EventListening = "listening" // the relay accepted its connection; it can be reached
	EventConnected = "connected" // the client opened the session's connection
	EventPath      = "path"      // the session moved to a direct or a relayed path
	EventRelay     = "relay"     // the connection to the relay was lost or came back
	EventRefused   = "refused"   // a client with another key asked to connect
	EventClosed    = "closed"    // the session ended, and why
	EventError     = "error"     // the companion could not run, and why
	EventLog       = "log"       // a log line of the tunnel library (debug only)
)

// Paths.
const (
	PathDirect  = "direct"
	PathRelayed = "relayed"
)

// Relay states.
const (
	RelayConnected = "connected"
	RelayLost      = "lost"
)

// Reasons the companion gives.
const (
	// closed
	ReasonStdinClosed    = "stdin_closed"    // the agent ended the session
	ReasonPeerClosed     = "peer_closed"     // the client closed the connection
	ReasonConnectionLost = "connection_lost" // the connection to the client broke
	ReasonStdoutClosed   = "stdout_closed"   // the agent stopped reading
	ReasonTerminated     = "terminated"      // the companion was told to stop

	// error
	ReasonBadConfig        = "bad_config"
	ReasonNoConfig         = "no_config"
	ReasonRelayRefused     = "relay_refused"
	ReasonRelayUnreachable = "relay_unreachable"
	ReasonStartFailed      = "start_failed"
	ReasonInternal         = "internal" // the companion's own code failed

	// refused
	ReasonUnknownPeer = "unknown_peer"
)

// Event is one line of the companion's stderr. Only the fields of its kind
// are set.
type Event struct {
	Event string `json:"event"`

	// hello
	Version  string `json:"version,omitempty"`
	Commit   string `json:"commit,omitempty"`
	Protocol int    `json:"protocol,omitempty"`
	IPC      int    `json:"ipc,omitempty"`

	// path
	Path string `json:"path,omitempty"`

	// relay
	State string `json:"state,omitempty"`

	// refused, closed, error, relay lost
	Reason string `json:"reason,omitempty"`
	// Detail is for the log: the operating system's words for a network
	// failure, or which configuration field was refused.
	Detail string `json:"detail,omitempty"`

	// refused
	Peer  string `json:"peer,omitempty"`
	Count int    `json:"count,omitempty"`

	// log
	Msg string `json:"msg,omitempty"`
}

// parseEvent reads one stderr line. A line that is not an event (the Go
// runtime writes a crash there as plain text) is not one.
func parseEvent(line []byte) (Event, bool) {
	var e Event
	if err := json.Unmarshal(line, &e); err != nil || e.Event == "" {
		return Event{}, false
	}
	return e, true
}
