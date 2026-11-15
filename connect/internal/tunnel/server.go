// Package tunnel serves one TCP port to one peer through one relay. It is the
// only package of the companion that touches the tunnel library.
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/tailscale/tailcat"
	"tailscale.com/envknob"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/filter"
)

// Paths a session's traffic can take.
const (
	PathDirect  = "direct"
	PathRelayed = "relayed"
)

// Relay failures.
const (
	// FailureRefused: the relay took the connection and closed it without a
	// word, which is how it turns away a key it was not told to admit.
	FailureRefused = "relay_refused"
	// FailureUnreachable: no connection to the relay could be made.
	FailureUnreachable = "relay_unreachable"
)

// Notice kinds.
const (
	// NoticeRelayConnected: the relay took the connection back after a loss.
	NoticeRelayConnected = iota + 1
	// NoticeRelayLost: the connection to the relay ended (Failure is empty),
	// or, while it is down, the relay refused or could not be reached for a
	// new one (Failure says which; each is reported once per loss). A relay
	// that refuses the reconnection no longer admits this session's key.
	NoticeRelayLost
	// NoticePeerRefused: a peer other than the allowed one asked to connect.
	NoticePeerRefused
)

// Notice is something the library reported while the server ran.
type Notice struct {
	Kind int
	// Failure and Detail say why no new relay connection could be made.
	Failure string
	Detail  string
	// Peer is the short form of a refused peer's public key.
	Peer string
}

// Config is everything the server needs. Nothing in it is optional except
// Notify and Logf: see validate.
type Config struct {
	NodeKey key.NodePrivate
	PeerKey key.NodePublic
	PSK     [32]byte
	Region  *tailcfg.DERPRegion
	Port    uint16

	// Notify, if set, is called for each Notice, from one goroutine, in
	// order. It may block; notices that pile up behind it are dropped.
	Notify func(Notice)
	// Logf, if set, receives the library's own log lines.
	Logf func(format string, args ...any)
}

// ErrConfig is the error of a configuration the server refuses.
var ErrConfig = errors.New("tunnel configuration refused")

// validate refuses a configuration with anything missing. The library has a
// default for each of these, and every default opens something: a zero key
// becomes a new key, a zero pre-shared key a new one, an empty allow list
// admits every peer, no region means the vendor's relay map is fetched, and
// port 0 is a port picked at random.
func (c *Config) validate() error {
	var zeroPSK [32]byte
	switch {
	case c.NodeKey.IsZero():
		return fmt.Errorf("%w: no node key", ErrConfig)
	case c.PeerKey.IsZero():
		return fmt.Errorf("%w: no peer key", ErrConfig)
	case c.PSK == zeroPSK:
		return fmt.Errorf("%w: no pre-shared key", ErrConfig)
	case c.Port == 0:
		return fmt.Errorf("%w: no port", ErrConfig)
	case c.Region == nil:
		return fmt.Errorf("%w: no relay", ErrConfig)
	case c.Region.RegionID < 1 || c.Region.RegionID > 65535:
		return fmt.Errorf("%w: relay region number out of range", ErrConfig)
	case len(c.Region.Nodes) != 1:
		return fmt.Errorf("%w: a relay is exactly one host", ErrConfig)
	}
	n := c.Region.Nodes[0]
	switch {
	case n == nil || n.HostName == "":
		return fmt.Errorf("%w: no relay host", ErrConfig)
	case n.RegionID != c.Region.RegionID:
		return fmt.Errorf("%w: relay host and region disagree", ErrConfig)
	case n.DERPPort < 1 || n.DERPPort > 65535:
		return fmt.Errorf("%w: no relay port", ErrConfig)
	case n.STUNPort < 1 || n.STUNPort > 65535:
		return fmt.Errorf("%w: no relay STUN port", ErrConfig)
	case c.NodeKey.Public() == c.PeerKey:
		return fmt.Errorf("%w: the peer key is this node's own", ErrConfig)
	}
	return nil
}

// NewRegion describes a relay to the library: one region holding one host.
// Every field the library would otherwise fill in is set here, because a
// region given to it directly skips that step, and both ends of a session
// must describe the relay the same way.
func NewRegion(id string, regionID int, host string, port, stunPort int) *tailcfg.DERPRegion {
	rid := tailcfg.DERPRegionID(regionID)
	return &tailcfg.DERPRegion{
		RegionID:   rid,
		RegionCode: id,
		RegionName: id,
		Nodes: []*tailcfg.DERPNode{{
			Name:     id + "-1",
			RegionID: rid,
			HostName: host,
			DERPPort: port,
			STUNPort: stunPort,
		}},
	}
}

// SetKeepalive sets, for the whole process, how soon a peer that vanished
// without closing its connection is noticed: after idle without traffic the
// connection is probed every interval, and it fails after the library's count
// of unanswered probes. The library's own default is over two hours. Call it
// before Start, from main: it is not safe once the library is running.
func SetKeepalive(idle, interval time.Duration) {
	envknob.Setenv("TS_NETSTACK_KEEPALIVE_IDLE", idle.String())
	envknob.Setenv("TS_NETSTACK_KEEPALIVE_INTERVAL", interval.String())
}

// StartError is why Start gave up waiting for the relay.
type StartError struct {
	Failure string // FailureRefused or FailureUnreachable
	Detail  string
}

func (e *StartError) Error() string {
	if e.Detail == "" {
		return e.Failure
	}
	return e.Failure + ": " + e.Detail
}

// refusalsBeforeGivingUp is how many times in a row the relay must close the
// connection, before it ever accepted one, for Start to stop waiting. Each
// attempt makes the relay ask whether this key is admitted, so a key that is
// not is not asked about for the whole wait.
const refusalsBeforeGivingUp = 4

// Server is a running tunnel endpoint.
type Server struct {
	cfg Config
	srv *tailcat.Server
	ln  net.Listener

	notices chan Notice
	done    chan struct{}
	wg      sync.WaitGroup

	mu                sync.Mutex
	everUp            bool
	up                bool
	refusedInRow      int
	lastFailure       StartError
	reportedWhileDown map[string]bool
	relayUp           chan struct{} // closed when the relay first accepts
	gaveUp            chan struct{} // closed when the relay refused refusalsBeforeGivingUp times in a row
	gaveUpOnce        sync.Once     // the library keeps trying, and reporting, while the server shuts down

	closeOnce sync.Once
}

// Start brings the endpoint up and returns once the relay has accepted its
// connection: only then can a peer reach it. It returns a *StartError when
// ctx ends first, or sooner when the relay keeps refusing.
func Start(ctx context.Context, cfg Config) (*Server, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	s := &Server{
		cfg:     cfg,
		notices: make(chan Notice, 64),
		done:    make(chan struct{}),
		relayUp: make(chan struct{}),
		gaveUp:  make(chan struct{}),
	}
	s.srv = &tailcat.Server{
		Key:            cfg.NodeKey,
		PresharedKey:   tailcat.PresharedKey(cfg.PSK),
		Logf:           s.logf,
		Region:         cfg.Region,
		AllowedClients: []key.NodePublic{cfg.PeerKey},
		ServedTCPPorts: []filter.PortRange{{First: cfg.Port, Last: cfg.Port}},
	}
	s.wg.Add(1)
	go s.deliver()

	ln, err := s.srv.Listen(ctx, "tcp", net.JoinHostPort("", strconv.Itoa(int(cfg.Port))))
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("listen: %w", err)
	}
	s.ln = ln

	select {
	case <-s.relayUp:
		return s, nil
	case <-s.gaveUp:
	case <-ctx.Done():
	}
	s.mu.Lock()
	failure := s.lastFailure
	s.mu.Unlock()
	if failure.Failure == "" {
		failure.Failure = FailureUnreachable
	}
	s.Close()
	return nil, &failure
}

// Accept waits for the peer's connection and returns it. A session is one
// connection: the port stops being served once it is made, so a second one is
// reset.
func (s *Server) Accept() (net.Conn, error) {
	conn, err := s.ln.Accept()
	if err != nil {
		return nil, err
	}
	_ = s.ln.Close()
	return conn, nil
}

// Path reports how traffic reaches the peer right now, or "" before the peer
// is known. The library names the peer's relay in its status whatever path is
// in use, so a direct path is read from the direct address alone.
func (s *Server) Path() string {
	st := s.srv.Status()
	if st == nil {
		return ""
	}
	ps, ok := st.Peer[s.cfg.PeerKey]
	if !ok || ps == nil {
		return ""
	}
	if ps.CurAddr != "" {
		return PathDirect
	}
	return PathRelayed
}

// Drain waits, within ctx, for the connections this end closed second to
// finish closing, so the process does not exit with its last segment unsent.
func (s *Server) Drain(ctx context.Context) {
	_ = s.srv.DrainTCP(ctx)
}

// Close shuts the endpoint down.
func (s *Server) Close() {
	s.closeOnce.Do(func() {
		if s.ln != nil {
			_ = s.ln.Close()
		}
		_ = s.srv.Close()
		close(s.done)
		s.wg.Wait()
	})
}

// deliver hands notices to Notify off the library's goroutines.
func (s *Server) deliver() {
	defer s.wg.Done()
	for {
		select {
		case n := <-s.notices:
			if s.cfg.Notify != nil {
				s.cfg.Notify(n)
			}
		case <-s.done:
			return
		}
	}
}

func (s *Server) notify(n Notice) {
	select {
	case s.notices <- n:
	default:
	}
}
