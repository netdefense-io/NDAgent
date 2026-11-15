package tunnel_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tailscale/tailcat"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"

	"github.com/netdefense-io/ndagent/connect/internal/tunnel"
	"github.com/netdefense-io/ndagent/connect/internal/tunneltest"
)

const (
	servedPort = 1
	// vanishingPeerEnv makes the test binary act as a peer that connects and
	// then does nothing, for TestAVanishedPeerIsNoticed to kill.
	vanishingPeerEnv = "NDAGENT_CONNECT_TEST_PEER_ADDR"
)

func TestMain(m *testing.M) {
	tunneltest.Hermetic()
	if addr := os.Getenv(vanishingPeerEnv); addr != "" {
		vanishingPeer(addr)
		return
	}
	os.Exit(m.Run())
}

// endpoint is a started server and what its peer needs to reach it.
type endpoint struct {
	srv       *tunnel.Server
	serverKey key.NodePrivate
	peerKey   key.NodePrivate
	psk       [32]byte
	region    *tailcfg.DERPRegion

	mu      sync.Mutex
	notices []tunnel.Notice
}

func (e *endpoint) notify(n tunnel.Notice) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.notices = append(e.notices, n)
}

// waitNotice waits for a notice match accepts and returns it.
func (e *endpoint) waitNotice(t *testing.T, what string, within time.Duration, match func(tunnel.Notice) bool) tunnel.Notice {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		e.mu.Lock()
		for _, n := range e.notices {
			if match(n) {
				e.mu.Unlock()
				return n
			}
		}
		seen := fmt.Sprintf("%+v", e.notices)
		e.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatalf("no %s within %v; notices so far: %s", what, within, seen)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (e *endpoint) config() tunnel.Config {
	return tunnel.Config{
		NodeKey: e.serverKey,
		PeerKey: e.peerKey.Public(),
		PSK:     e.psk,
		Region:  e.region,
		Port:    servedPort,
		Notify:  e.notify,
	}
}

func (e *endpoint) peer(t *testing.T) *tunneltest.Peer {
	return tunneltest.NewPeer(t, e.serverKey, e.psk, e.region, e.peerKey)
}

func newEndpoint(region *tailcfg.DERPRegion) *endpoint {
	return &endpoint{
		serverKey: key.NewNode(),
		peerKey:   key.NewNode(),
		psk:       tunneltest.NewPSK(),
		region:    region,
	}
}

func start(t *testing.T, region *tailcfg.DERPRegion) *endpoint {
	t.Helper()
	e := newEndpoint(region)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	srv, err := tunnel.Start(ctx, e.config())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	e.srv = srv
	t.Cleanup(srv.Close)
	return e
}

// A configuration with anything missing is refused before the library sees
// it, because the library fills each gap with a default that opens something.
func TestStartRefusesEveryMissingValue(t *testing.T) {
	relay := tunneltest.StartRelay(t)
	good := func() tunnel.Config { return newEndpoint(relay.Region.Clone()).config() }

	// The unmodified configuration starts: otherwise the refusals below would
	// prove nothing.
	start(t, relay.Region.Clone())

	cases := []struct {
		name   string
		mutate func(*tunnel.Config)
	}{
		{"no node key (the library would make one up)", func(c *tunnel.Config) { c.NodeKey = key.NodePrivate{} }},
		{"no peer key (the library would admit every peer)", func(c *tunnel.Config) { c.PeerKey = key.NodePublic{} }},
		{"no pre-shared key (the library would make one up)", func(c *tunnel.Config) { c.PSK = [32]byte{} }},
		{"no port (the library would pick one)", func(c *tunnel.Config) { c.Port = 0 }},
		{"no relay (the library would fetch the vendor's list)", func(c *tunnel.Config) { c.Region = nil }},
		{"relay region number 0", func(c *tunnel.Config) { c.Region.RegionID = 0 }},
		{"relay region number too large", func(c *tunnel.Config) { c.Region.RegionID = 70000 }},
		{"relay without a host entry", func(c *tunnel.Config) { c.Region.Nodes = nil }},
		{"relay with two hosts", func(c *tunnel.Config) { c.Region.Nodes = append(c.Region.Nodes, c.Region.Nodes[0]) }},
		{"relay host entry nil", func(c *tunnel.Config) { c.Region.Nodes[0] = nil }},
		{"relay without a hostname", func(c *tunnel.Config) { c.Region.Nodes[0].HostName = "" }},
		{"relay host in another region", func(c *tunnel.Config) { c.Region.Nodes[0].RegionID = 901 }},
		{"relay without a port (the library would use 443)", func(c *tunnel.Config) { c.Region.Nodes[0].DERPPort = 0 }},
		{"relay without a STUN port (the library would use 3478)", func(c *tunnel.Config) { c.Region.Nodes[0].STUNPort = 0 }},
		{"relay with STUN turned off", func(c *tunnel.Config) { c.Region.Nodes[0].STUNPort = -1 }},
		{"the peer key is the node's own", func(c *tunnel.Config) { c.PeerKey = c.NodeKey.Public() }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := good()
			tc.mutate(&cfg)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			began := time.Now()
			srv, err := tunnel.Start(ctx, cfg)
			if srv != nil {
				srv.Close()
			}
			if !errors.Is(err, tunnel.ErrConfig) {
				t.Fatalf("Start = %v, want a refused configuration", err)
			}
			if elapsed := time.Since(began); elapsed > time.Second {
				t.Errorf("the refusal took %v: it must come before anything is started", elapsed)
			}
		})
	}
}

// Start returns only once the relay has accepted the connection, so a peer
// can reach the server from that moment on.
func TestStartReturnsOnceTheRelayAccepted(t *testing.T) {
	relay := tunneltest.StartRelay(t)
	e := start(t, relay.Region)

	if !relay.Connected(e.serverKey.Public()) {
		t.Fatal("Start returned and the relay holds no connection from the server yet")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := e.peer(t).Ping(ctx); err != nil {
		t.Fatalf("the peer cannot reach the server right after Start returned: %v", err)
	}
}

// A relay that turns the key away is reported as refusing, and well before
// the wait is over: every attempt makes the relay ask about the key again.
func TestStartGivesUpOnARelayThatRefuses(t *testing.T) {
	relay := tunneltest.StartRefusingRelay(t)
	e := newEndpoint(relay.Region)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	began := time.Now()
	srv, err := tunnel.Start(ctx, e.config())
	elapsed := time.Since(began)
	if srv != nil {
		srv.Close()
		t.Fatal("Start succeeded against a relay that admits nobody")
	}
	var startErr *tunnel.StartError
	if !errors.As(err, &startErr) {
		t.Fatalf("Start = %v, want a *StartError", err)
	}
	if startErr.Failure != tunnel.FailureRefused {
		t.Errorf("failure = %q, want %q", startErr.Failure, tunnel.FailureRefused)
	}
	if elapsed > 15*time.Second {
		t.Errorf("Start took %v: it waited the wait out against a relay that refuses", elapsed)
	}
	if n := relay.Admissions(); n < 1 || n > 8 {
		t.Errorf("the relay asked about the key %d times, want a handful", n)
	}
}

// A relay nothing answers at is reported as unreachable when the wait ends,
// in the operating system's words and none of the library's.
func TestStartReportsAnUnreachableRelay(t *testing.T) {
	region := tunneltest.InsecureRegion("test", "127.0.0.1", tunneltest.UnusedPort(t), tunneltest.UnusedPort(t))
	e := newEndpoint(region)

	// The companion's own wait. The library looks at the network before its
	// first connection to the relay, so a much shorter wait can end before
	// any attempt was made, and with it any detail.
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	srv, err := tunnel.Start(ctx, e.config())
	if srv != nil {
		srv.Close()
		t.Fatal("Start succeeded with no relay")
	}
	var startErr *tunnel.StartError
	if !errors.As(err, &startErr) {
		t.Fatalf("Start = %v, want a *StartError", err)
	}
	if startErr.Failure != tunnel.FailureUnreachable {
		t.Errorf("failure = %q, want %q", startErr.Failure, tunnel.FailureUnreachable)
	}
	if !strings.Contains(startErr.Detail, "connection refused") {
		t.Errorf("detail = %q, want the dial error", startErr.Detail)
	}
	for _, word := range []string{"derp", "region", "magicsock", "tailscale", "tailcat"} {
		if strings.Contains(strings.ToLower(startErr.Detail), word) {
			t.Errorf("detail = %q names the library (%q)", startErr.Detail, word)
		}
	}
}

// A peer with another key gets no answer from the library, and the server
// says so.
func TestARefusedPeerIsReported(t *testing.T) {
	relay := tunneltest.StartRelay(t)
	e := start(t, relay.Region)

	strangerKey := key.NewNode()
	stranger := tunneltest.NewPeer(t, e.serverKey, e.psk, e.region, strangerKey)
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	if _, err := stranger.Ping(ctx); err == nil {
		t.Fatal("a peer the server does not allow got an answer")
	}

	want := strangerKey.Public().UntypedHexString()[:8]
	n := e.waitNotice(t, "refused-peer notice", 5*time.Second, func(n tunnel.Notice) bool { return n.Kind == tunnel.NoticePeerRefused })
	if n.Peer != want {
		t.Errorf("refused peer = %q, want %q (the start of its public key)", n.Peer, want)
	}
}

// One session: bytes both ways over the accepted connection, a direct path on
// the loopback interface, and no second connection.
func TestSessionCarriesBytesOverOneConnection(t *testing.T) {
	relay := tunneltest.StartRelay(t)
	e := start(t, relay.Region)
	peer := e.peer(t)

	if got := e.srv.Path(); got != "" {
		t.Errorf("path before any peer = %q, want none", got)
	}

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := e.srv.Accept()
		if err != nil {
			t.Errorf("Accept: %v", err)
			close(accepted)
			return
		}
		accepted <- conn
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	peerConn, err := peer.DialTCPPort(ctx, servedPort)
	if err != nil {
		t.Fatalf("the allowed peer cannot connect: %v", err)
	}
	defer peerConn.Close()
	serverConn := <-accepted
	if serverConn == nil {
		t.FailNow()
	}
	defer serverConn.Close()

	exchange := func(from, to net.Conn, text string) {
		t.Helper()
		if _, err := from.Write([]byte(text)); err != nil {
			t.Fatalf("write %q: %v", text, err)
		}
		got := make([]byte, len(text))
		_ = to.SetReadDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.ReadFull(to, got); err != nil || string(got) != text {
			t.Fatalf("read = %q, %v; want %q", got, err, text)
		}
	}
	exchange(peerConn, serverConn, "from the peer")
	exchange(serverConn, peerConn, "from the device")

	deadline := time.Now().Add(20 * time.Second)
	for e.srv.Path() != tunnel.PathDirect {
		if time.Now().After(deadline) {
			t.Fatalf("path = %q after 20 s on the loopback interface, want %q", e.srv.Path(), tunnel.PathDirect)
		}
		exchange(peerConn, serverConn, "x")
		time.Sleep(100 * time.Millisecond)
	}

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()
	if second, err := peer.DialTCPPort(dialCtx, servedPort); err == nil {
		second.Close()
		t.Fatal("a second connection to the served port was accepted")
	}
	exchange(peerConn, serverConn, "the first connection still works")
}

// Only the one port is reachable, and only with the session's pre-shared key.
func TestOnlyTheServedPortAndThePreSharedKeyGetIn(t *testing.T) {
	relay := tunneltest.StartRelay(t)
	e := start(t, relay.Region)
	go func() {
		for {
			conn, err := e.srv.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	t.Run("another port", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if conn, err := e.peer(t).DialTCPPort(ctx, servedPort+1); err == nil {
			conn.Close()
			t.Fatal("the peer reached a port that is not served")
		}
	})

	t.Run("another pre-shared key", func(t *testing.T) {
		wrong := e.psk
		wrong[0] ^= 0xff
		impostor := tunneltest.NewPeer(t, e.serverKey, wrong, e.region, e.peerKey)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if conn, err := impostor.DialTCPPort(ctx, servedPort); err == nil {
			conn.Close()
			t.Fatal("a peer with the right key and the wrong pre-shared key connected")
		}
	})
}

// A relay connection that ends is reported, and so is its return.
func TestRelayLossAndReturnAreReported(t *testing.T) {
	relay := tunneltest.StartRelay(t)
	e := start(t, relay.Region)

	relay.DropConnections()
	lost := e.waitNotice(t, "relay-lost notice", 10*time.Second, func(n tunnel.Notice) bool { return n.Kind == tunnel.NoticeRelayLost })
	if lost.Failure != "" {
		t.Errorf("the first notice of a loss says %q: it is the connection ending, not a failed reconnection", lost.Failure)
	}
	e.waitNotice(t, "relay-connected notice", 20*time.Second, func(n tunnel.Notice) bool { return n.Kind == tunnel.NoticeRelayConnected })
}

// vanishingPeer is the test binary acting as a peer: it connects, says so,
// and waits to be killed.
func vanishingPeer(addr string) {
	client := &tailcat.Client{Server: tailcat.Addr(addr), Logf: logger.Discard}
	var peerKey key.NodePrivate
	if err := peerKey.UnmarshalText([]byte(os.Getenv(vanishingPeerEnv + "_KEY"))); err != nil {
		fmt.Println("bad key:", err)
		os.Exit(1)
	}
	client.Key = peerKey
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := client.DialTCPPort(ctx, servedPort)
	if err != nil {
		fmt.Println("dial:", err)
		os.Exit(1)
	}
	if _, err := conn.Write([]byte("here")); err != nil {
		fmt.Println("write:", err)
		os.Exit(1)
	}
	fmt.Println("connected")
	select {}
}

// A peer that vanishes without closing (its process is killed, its network
// goes away) ends the connection on the server within the keepalive's bound.
// tunneltest.Hermetic sets that to one second idle and one second between
// probes, so about ten seconds here; the companion's own values make it two
// minutes. Without the keepalive setting the library waits over two hours.
func TestAVanishedPeerIsNoticed(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out the keepalive")
	}
	relay := tunneltest.StartRelay(t)
	e := start(t, relay.Region)

	info := tailcat.ConnInfo{
		ServerPublic:      tailcat.NodePublic{NodePublic: e.serverKey.Public()},
		ServerDiscoPublic: tailcat.DiscoPublicForNode(e.serverKey),
		PresharedKey:      tailcat.PresharedKey(e.psk),
		Region:            []*tailcfg.DERPRegion{e.region},
	}
	keyText, err := e.peerKey.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(os.Args[0])
	child.Env = append(os.Environ(), vanishingPeerEnv+"="+string(info.Addr()), vanishingPeerEnv+"_KEY="+string(keyText))
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = child.Process.Kill()
		_ = child.Wait()
	}()

	conn, err := e.srv.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer conn.Close()
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "connected" {
		t.Fatalf("the peer process said %q, %v", line, err)
	}
	greeting := make([]byte, 4)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		t.Fatalf("reading the peer's greeting: %v", err)
	}

	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	began := time.Now()
	readErr := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1))
		readErr <- err
	}()
	select {
	case err := <-readErr:
		if err == nil || errors.Is(err, io.EOF) {
			t.Fatalf("read after the peer was killed = %v, want a broken connection", err)
		}
		t.Logf("the vanished peer was noticed after %v: %v", time.Since(began).Round(time.Millisecond), err)
	case <-time.After(45 * time.Second):
		t.Fatal("the connection to a killed peer was still open after 45 s")
	}
}
