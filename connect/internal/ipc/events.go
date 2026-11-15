package ipc

import (
	"encoding/json"
	"io"
	"sync"
)

// Event names.
const (
	// EventHello is the first line the companion writes, before it reads its
	// configuration: its version, so the agent can refuse a companion of
	// another build before it hands it any key.
	EventHello = "hello"
	// EventListening: the relay accepted the companion's connection and the
	// port is being served. Nothing is reachable before it.
	EventListening = "listening"
	// EventConnected: the peer opened the session's connection.
	EventConnected = "connected"
	// EventPath: the session moved to a direct or a relayed path.
	EventPath = "path"
	// EventRelay: the connection to the relay was lost or came back.
	EventRelay = "relay"
	// EventRefused: a peer other than the allowed one asked to connect. The
	// tunnel library ignores such a peer without a word, which from the other
	// end looks like a dead network.
	EventRefused = "refused"
	// EventClosed is the last line of a session that ran: why it ended.
	EventClosed = "closed"
	// EventError is the last line of a companion that could not run.
	EventError = "error"
	// EventLog is one log line of the tunnel library (debug only).
	EventLog = "log"
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

// Reasons. They reach task results and device logs, so they name what
// happened in the product's own words.
const (
	// closed
	ReasonStdinClosed    = "stdin_closed"    // the agent ended the session
	ReasonPeerClosed     = "peer_closed"     // the peer closed the connection
	ReasonConnectionLost = "connection_lost" // the connection to the peer broke
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

// Event is one line on the companion's stderr. Only the fields of its kind
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
	// Detail is for the agent's log: the operating system's own words for a
	// network failure, or which configuration field was refused. Never a key.
	Detail string `json:"detail,omitempty"`

	// refused
	Peer  string `json:"peer,omitempty"`
	Count int    `json:"count,omitempty"`

	// log
	Msg string `json:"msg,omitempty"`
}

// Emitter writes events, one JSON object per line, each in a single write.
type Emitter struct {
	mu sync.Mutex
	w  io.Writer
}

func NewEmitter(w io.Writer) *Emitter { return &Emitter{w: w} }

// Emit writes e. A failed write is dropped: the reader is the agent, and when
// it is gone the companion is about to learn that from its stdin.
func (em *Emitter) Emit(e Event) {
	line, err := json.Marshal(e)
	if err != nil {
		return
	}
	line = append(line, '\n')
	em.mu.Lock()
	defer em.mu.Unlock()
	_, _ = em.w.Write(line)
}
