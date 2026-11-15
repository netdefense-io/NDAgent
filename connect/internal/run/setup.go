package run

import (
	"io"
	"log"
	"time"

	"github.com/netdefense-io/ndagent/connect/internal/tunnel"
)

// The agent and the client exchange keepalive frames of their own and give up
// on a peer that is silent for a minute; the companion never looks at frames.
// This is its own bound, for a connection on which nothing at all is in
// flight: after KeepaliveIdle without traffic the peer is probed every
// KeepaliveInterval, and the connection ends after nine unanswered probes,
// two minutes in all. The library's own default is over two hours.
const (
	KeepaliveIdle     = 30 * time.Second
	KeepaliveInterval = 10 * time.Second
)

// Setup prepares the process, once, before Run: nothing the tunnel library
// reads from the environment is left set, a connection to a vanished peer
// ends within minutes, nothing but events reaches stderr, and the process
// leaves no core file holding session keys. (That it prints no crash report
// holding them is the command's own check, on the environment it was started
// in.)
func Setup() {
	tunnel.ScrubEnvironment()
	tunnel.SetKeepalive(KeepaliveIdle, KeepaliveInterval)
	log.SetOutput(io.Discard)
	hardenProcess()
}
