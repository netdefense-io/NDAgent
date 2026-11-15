package run

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/netdefense-io/ndagent/connect/internal/ipc"
	"github.com/netdefense-io/ndagent/connect/internal/tunnel"
	"github.com/netdefense-io/ndagent/connect/internal/tunneltest"
)

const servedPort = 1

func TestMain(m *testing.M) {
	tunneltest.Hermetic()
	pathPollInterval = 50 * time.Millisecond
	os.Exit(m.Run())
}

// companion is one Run with the test holding the other end of its pipes.
type companion struct {
	t *testing.T

	stdin  *io.PipeWriter
	stdout *io.PipeReader
	stop   chan struct{}
	exit   chan int

	mu     sync.Mutex
	events []ipc.Event
	raw    bytes.Buffer // everything written to stderr
	cursor int
}

// startCompanion runs the companion as the agent would: nothing is written to
// its stdin yet.
func startCompanion(t *testing.T) *companion {
	t.Helper()
	return startCompanionWith(t, nil)
}

// startCompanionWith is startCompanion with the options changed first.
func startCompanionWith(t *testing.T, change func(*Options)) *companion {
	t.Helper()
	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()
	stderrR, stderrW := io.Pipe()
	c := &companion{t: t, stdin: stdinW, stdout: stdoutR, stop: make(chan struct{}), exit: make(chan int, 1)}

	scanned := make(chan struct{})
	go func() {
		defer close(scanned)
		lines := bufio.NewScanner(stderrR)
		lines.Buffer(make([]byte, 0, 64<<10), 1<<20)
		for lines.Scan() {
			var e ipc.Event
			dec := json.NewDecoder(bytes.NewReader(lines.Bytes()))
			dec.DisallowUnknownFields()
			err := dec.Decode(&e)
			c.mu.Lock()
			c.raw.Write(lines.Bytes())
			c.raw.WriteByte('\n')
			if err != nil || e.Event == "" {
				t.Errorf("stderr carries a line that is not an event: %q", lines.Text())
			} else {
				c.events = append(c.events, e)
			}
			c.mu.Unlock()
		}
	}()
	options := Options{
		Stdin:   stdinR,
		Stdout:  stdoutW,
		Stderr:  stderrW,
		Version: "9.9.9",
		Commit:  "c0ffee1",
		Stop:    c.stop,
		regionFor: func(r ipc.Relay) *tailcfg.DERPRegion {
			return tunneltest.InsecureRegion(r.ID, r.Host, r.Port, r.STUNPort)
		},
	}
	if change != nil {
		change(&options)
	}
	go func() {
		code := Run(options)
		stdoutW.Close()
		stderrW.Close()
		<-scanned
		c.exit <- code
	}()
	t.Cleanup(func() {
		stdinW.Close()
		stdoutR.Close()
		select {
		case <-c.exit:
		case <-time.After(15 * time.Second):
			t.Error("the companion did not end when its pipes closed")
		}
	})
	return c
}

// next returns the next event named name, passing over the ones that come
// whenever they come (path, relay, log). Any other event in between fails the
// test: the order of the rest is the contract.
func (c *companion) next(name string, within time.Duration) ipc.Event {
	c.t.Helper()
	deadline := time.Now().Add(within)
	for {
		c.mu.Lock()
		for c.cursor < len(c.events) {
			e := c.events[c.cursor]
			c.cursor++
			if e.Event == name {
				c.mu.Unlock()
				return e
			}
			if e.Event != ipc.EventPath && e.Event != ipc.EventRelay && e.Event != ipc.EventLog {
				c.mu.Unlock()
				c.t.Fatalf("got event %+v while waiting for %q", e, name)
			}
		}
		c.mu.Unlock()
		if time.Now().After(deadline) {
			c.t.Fatalf("no %q event within %v; stderr so far:\n%s", name, within, c.stderr())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// all returns every event named name seen so far.
func (c *companion) all(name string) []ipc.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []ipc.Event
	for _, e := range c.events {
		if e.Event == name {
			out = append(out, e)
		}
	}
	return out
}

func (c *companion) stderr() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.raw.String()
}

// waitExit waits for the companion to end with status want. Its last line
// must be the one that says why: a closed or an error event, and nothing
// after it.
func (c *companion) waitExit(want int) {
	c.t.Helper()
	select {
	case code := <-c.exit:
		c.exit <- code
		if code != want {
			c.t.Errorf("exit status = %d, want %d; stderr:\n%s", code, want, c.stderr())
		}
	case <-time.After(15 * time.Second):
		c.t.Fatalf("the companion did not exit; stderr:\n%s", c.stderr())
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.events) == 0 {
		c.t.Fatal("the companion ended without a word")
	}
	if last := c.events[len(c.events)-1]; last.Event != ipc.EventClosed && last.Event != ipc.EventError {
		c.t.Errorf("the companion's last event is %+v, want closed or error; stderr:\n%s", last, c.raw.String())
	}
}

func (c *companion) send(body []byte) {
	c.t.Helper()
	var head [4]byte
	binary.BigEndian.PutUint32(head[:], uint32(len(body)))
	if _, err := c.stdin.Write(append(head[:], body...)); err != nil {
		c.t.Fatalf("writing the configuration: %v", err)
	}
}

// testSession is the keys and the relay of one session, as the agent would
// hold them after unsealing a task.
type testSession struct {
	serverKey key.NodePrivate
	peerKey   key.NodePrivate
	psk       [32]byte
	region    *tailcfg.DERPRegion
}

func newSession(region *tailcfg.DERPRegion) *testSession {
	return &testSession{serverKey: key.NewNode(), peerKey: key.NewNode(), psk: tunneltest.NewPSK(), region: region}
}

func (s *testSession) config(change func(*ipc.Config)) []byte {
	node := s.region.Nodes[0]
	cfg := ipc.Config{
		V:        ipc.Version,
		Role:     ipc.RoleServer,
		Protocol: ipc.Protocol,
		Relay:    ipc.Relay{ID: s.region.RegionCode, RegionID: int(s.region.RegionID), Host: node.HostName, Port: node.DERPPort, STUNPort: node.STUNPort},
		Port:     servedPort,
		NodeKey:  s.serverKey.Raw32(),
		PeerKey:  s.peerKey.Public().Raw32(),
		PSK:      s.psk,
	}
	if change != nil {
		change(&cfg)
	}
	body, err := json.Marshal(cfg)
	if err != nil {
		panic(err)
	}
	return body
}

func (s *testSession) secrets() []string {
	node, peer := s.serverKey.Raw32(), s.peerKey.Public().Raw32()
	return []string{
		base64.StdEncoding.EncodeToString(node[:]),
		base64.StdEncoding.EncodeToString(s.psk[:]),
		fmt.Sprintf("%x", node[:]),
		fmt.Sprintf("%x", s.psk[:]),
		base64.StdEncoding.EncodeToString(peer[:]),
	}
}

func (s *testSession) dial(t *testing.T) net.Conn {
	t.Helper()
	peer := tunneltest.NewPeer(t, s.serverKey, s.psk, s.region, s.peerKey)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := peer.DialTCPPort(ctx, servedPort)
	if err != nil {
		t.Fatalf("the peer cannot connect: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func readExactly(t *testing.T, r io.Reader, want string) {
	t.Helper()
	got := make([]byte, len(want))
	done := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(r, got)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil || string(got) != want {
			t.Fatalf("read %q, %v; want %q", got, err, want)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("nothing to read after 10 s; want %q", want)
	}
}

// The whole of a session, in the order the agent relies on: hello before the
// companion is given anything, listening once it can be reached, connected
// when the peer is there, the peer's bytes on stdout and the agent's to the
// peer, the path, and closed with the reason when the peer leaves.
func TestASessionFromHelloToClosed(t *testing.T) {
	relay := tunneltest.StartRelay(t)
	s := newSession(relay.Region)
	c := startCompanion(t)

	hello := c.next(ipc.EventHello, 5*time.Second)
	if hello != (ipc.Event{Event: "hello", Version: "9.9.9", Commit: "c0ffee1", Protocol: 1, IPC: 1}) {
		t.Errorf("hello = %+v", hello)
	}

	c.send(s.config(nil))
	c.next(ipc.EventListening, 15*time.Second)
	if !relay.Connected(s.serverKey.Public()) {
		t.Error("listening was sent and the relay holds no connection from the companion")
	}

	peer := s.dial(t)
	c.next(ipc.EventConnected, 10*time.Second)

	if _, err := peer.Write([]byte("from the peer")); err != nil {
		t.Fatal(err)
	}
	readExactly(t, c.stdout, "from the peer")
	if _, err := c.stdin.Write([]byte("from the agent")); err != nil {
		t.Fatal(err)
	}
	readExactly(t, peer, "from the agent")

	deadline := time.Now().Add(20 * time.Second)
	for {
		paths := c.all(ipc.EventPath)
		if len(paths) > 0 && paths[len(paths)-1].Path == ipc.PathDirect {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no direct path reported on the loopback interface; path events: %+v", paths)
		}
		if _, err := peer.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		readExactly(t, c.stdout, "x")
		time.Sleep(50 * time.Millisecond)
	}
	for i, p := range c.all(ipc.EventPath) {
		if p.Path != ipc.PathDirect && p.Path != ipc.PathRelayed {
			t.Errorf("path event %d = %+v", i, p)
		}
		if i > 0 && p.Path == c.all(ipc.EventPath)[i-1].Path {
			t.Errorf("path event %d repeats %q: it is for changes", i, p.Path)
		}
	}

	peer.Close()
	if closed := c.next(ipc.EventClosed, 10*time.Second); closed.Reason != ipc.ReasonPeerClosed {
		t.Errorf("closed = %+v, want reason %q", closed, ipc.ReasonPeerClosed)
	}
	c.waitExit(0)
	if rest, _ := io.ReadAll(c.stdout); len(rest) != 0 {
		t.Errorf("stdout carried %q after the peer's bytes: it is for the session alone", rest)
	}
	if logs := c.all(ipc.EventLog); len(logs) != 0 {
		t.Errorf("%d library log lines without debug, e.g. %q", len(logs), logs[0].Msg)
	}
	for _, secret := range s.secrets() {
		if strings.Contains(c.stderr(), secret) {
			t.Error("stderr shows key material")
		}
	}
}

// The agent ends a session by closing the companion's stdin. What it wrote
// before that still reaches the peer, which then sees the stream end: here
// four megabytes written just before the close, to a peer that only starts
// reading afterwards, so they are still on their way when stdin closes.
func TestTheAgentClosingStdinEndsTheSession(t *testing.T) {
	saved := closeGrace
	closeGrace = 20 * time.Second
	defer func() { closeGrace = saved }()

	relay := tunneltest.StartRelay(t)
	s := newSession(relay.Region)
	c := startCompanion(t)
	c.next(ipc.EventHello, 5*time.Second)
	c.send(s.config(nil))
	c.next(ipc.EventListening, 15*time.Second)
	peer := s.dial(t)
	c.next(ipc.EventConnected, 10*time.Second)

	sent := make([]byte, 4<<20)
	for i := range sent {
		sent[i] = byte(i * 7)
	}
	wrote := make(chan error, 1)
	go func() {
		_, err := c.stdin.Write(sent)
		c.stdin.Close()
		wrote <- err
	}()
	time.Sleep(300 * time.Millisecond)

	_ = peer.SetReadDeadline(time.Now().Add(30 * time.Second))
	got, err := io.ReadAll(peer)
	if err != nil {
		t.Errorf("the peer's read ended with %v, want the end of the stream", err)
	}
	if !bytes.Equal(got, sent) {
		t.Errorf("the peer read %d bytes, want the %d written before stdin closed", len(got), len(sent))
	}
	if err := <-wrote; err != nil {
		t.Errorf("writing to the companion: %v", err)
	}
	// A peer that reads the end of the stream closes its side, and the
	// companion does not wait its grace period out.
	peer.Close()
	began := time.Now()
	if closed := c.next(ipc.EventClosed, 10*time.Second); closed.Reason != ipc.ReasonStdinClosed {
		t.Errorf("closed = %+v, want reason %q", closed, ipc.ReasonStdinClosed)
	}
	if waited := time.Since(began); waited > 5*time.Second {
		t.Errorf("the companion took %v to end after the peer closed in answer", waited)
	}
	c.waitExit(0)
}

// A companion whose agent goes away before any peer came does not linger.
func TestStdinClosingBeforeAnyPeerEndsTheCompanion(t *testing.T) {
	relay := tunneltest.StartRelay(t)
	s := newSession(relay.Region)
	c := startCompanion(t)
	c.next(ipc.EventHello, 5*time.Second)
	c.send(s.config(nil))
	c.next(ipc.EventListening, 15*time.Second)

	c.stdin.Close()
	if closed := c.next(ipc.EventClosed, 5*time.Second); closed.Reason != ipc.ReasonStdinClosed {
		t.Errorf("closed = %+v, want reason %q", closed, ipc.ReasonStdinClosed)
	}
	c.waitExit(0)
	if relay.Connected(s.serverKey.Public()) {
		t.Error("the companion ended and the relay still holds its connection")
	}
}

func TestATerminationSignalEndsTheSession(t *testing.T) {
	relay := tunneltest.StartRelay(t)
	s := newSession(relay.Region)

	t.Run("before any peer", func(t *testing.T) {
		c := startCompanion(t)
		c.next(ipc.EventHello, 5*time.Second)
		c.send(s.config(nil))
		c.next(ipc.EventListening, 15*time.Second)
		close(c.stop)
		if closed := c.next(ipc.EventClosed, 5*time.Second); closed.Reason != ipc.ReasonTerminated {
			t.Errorf("closed = %+v, want reason %q", closed, ipc.ReasonTerminated)
		}
		c.waitExit(0)
	})

	t.Run("during a session", func(t *testing.T) {
		s := newSession(relay.Region)
		c := startCompanion(t)
		c.next(ipc.EventHello, 5*time.Second)
		c.send(s.config(nil))
		c.next(ipc.EventListening, 15*time.Second)
		peer := s.dial(t)
		c.next(ipc.EventConnected, 10*time.Second)
		close(c.stop)
		if closed := c.next(ipc.EventClosed, 10*time.Second); closed.Reason != ipc.ReasonTerminated {
			t.Errorf("closed = %+v, want reason %q", closed, ipc.ReasonTerminated)
		}
		c.waitExit(0)
		_ = peer.SetReadDeadline(time.Now().Add(10 * time.Second))
		if n, err := peer.Read(make([]byte, 1)); n != 0 || err != io.EOF {
			t.Errorf("the peer read %d bytes, %v; want the end of the stream", n, err)
		}
	})
}

// A companion that cannot run says why in one error event and exits 1,
// without ever saying it listens.
func TestACompanionThatCannotStartSaysWhy(t *testing.T) {
	relay := tunneltest.StartRelay(t)

	expectError := func(t *testing.T, c *companion, reason, detailPart string) ipc.Event {
		t.Helper()
		e := c.next(ipc.EventError, 15*time.Second)
		if e.Reason != reason {
			t.Errorf("error = %+v, want reason %q", e, reason)
		}
		if !strings.Contains(e.Detail, detailPart) {
			t.Errorf("error detail = %q, want it to hold %q", e.Detail, detailPart)
		}
		c.waitExit(1)
		if n := len(c.all(ipc.EventListening)); n != 0 {
			t.Errorf("listening was sent %d times by a companion that failed", n)
		}
		return e
	}

	t.Run("no configuration: the agent went away", func(t *testing.T) {
		c := startCompanion(t)
		c.next(ipc.EventHello, 5*time.Second)
		c.stdin.Close()
		expectError(t, c, ipc.ReasonNoConfig, "")
	})

	t.Run("a configuration that is not one", func(t *testing.T) {
		c := startCompanion(t)
		c.next(ipc.EventHello, 5*time.Second)
		c.send([]byte(`{"v":1}`))
		expectError(t, c, ipc.ReasonBadConfig, "role")
	})

	t.Run("a node key that is not clamped", func(t *testing.T) {
		s := newSession(relay.Region)
		c := startCompanion(t)
		c.next(ipc.EventHello, 5*time.Second)
		c.send(s.config(func(cfg *ipc.Config) { cfg.NodeKey[0] |= 1 }))
		expectError(t, c, ipc.ReasonBadConfig, "node_key")
		for _, secret := range s.secrets() {
			if strings.Contains(c.stderr(), secret) {
				t.Error("stderr shows key material")
			}
		}
	})

	t.Run("the peer key is the node's own", func(t *testing.T) {
		s := newSession(relay.Region)
		c := startCompanion(t)
		c.next(ipc.EventHello, 5*time.Second)
		c.send(s.config(func(cfg *ipc.Config) { cfg.PeerKey = s.serverKey.Public().Raw32() }))
		expectError(t, c, ipc.ReasonBadConfig, "peer key")
	})

	t.Run("a relay that does not admit the key", func(t *testing.T) {
		refusing := tunneltest.StartRefusingRelay(t)
		s := newSession(refusing.Region)
		c := startCompanion(t)
		c.next(ipc.EventHello, 5*time.Second)
		began := time.Now()
		c.send(s.config(nil))
		expectError(t, c, ipc.ReasonRelayRefused, "")
		if elapsed := time.Since(began); elapsed > 6*time.Second {
			t.Errorf("the refusal took %v, the whole wait: the agent waits only 10 s for listening", elapsed)
		}
	})

	// With the wait the companion has when the configuration names none: it
	// covers the library's own look at the network, which comes before its
	// first connection to the relay.
	t.Run("a relay nothing answers at", func(t *testing.T) {
		s := newSession(tunneltest.InsecureRegion("test", "127.0.0.1", tunneltest.UnusedPort(t), tunneltest.UnusedPort(t)))
		c := startCompanion(t)
		c.next(ipc.EventHello, 5*time.Second)
		began := time.Now()
		c.send(s.config(nil))
		e := c.next(ipc.EventError, 30*time.Second)
		if e.Reason != ipc.ReasonRelayUnreachable {
			t.Errorf("error = %+v, want reason %q", e, ipc.ReasonRelayUnreachable)
		}
		if !strings.Contains(e.Detail, "connection refused") {
			t.Errorf("error detail = %q, want the dial error", e.Detail)
		}
		c.waitExit(1)
		if elapsed := time.Since(began); elapsed < 7*time.Second {
			t.Errorf("gave up after %v, before the 8 s it has", elapsed)
		}
		if n := len(c.all(ipc.EventListening)); n != 0 {
			t.Errorf("listening was sent %d times by a companion that failed", n)
		}
	})
}

// A peer with another key is ignored by the tunnel library without a word.
// The companion reports it, once: such a peer asks again every second.
func TestARefusedPeerIsReportedOnce(t *testing.T) {
	relay := tunneltest.StartRelay(t)
	s := newSession(relay.Region)
	c := startCompanion(t)
	c.next(ipc.EventHello, 5*time.Second)
	c.send(s.config(nil))
	c.next(ipc.EventListening, 15*time.Second)

	strangerKey := key.NewNode()
	stranger := tunneltest.NewPeer(t, s.serverKey, s.psk, s.region, strangerKey)
	ctx, cancel := context.WithTimeout(context.Background(), 3500*time.Millisecond)
	defer cancel()
	if _, err := stranger.Ping(ctx); err == nil {
		t.Fatal("a peer the session does not allow got an answer")
	}

	refused := c.all(ipc.EventRefused)
	if len(refused) != 1 {
		t.Fatalf("%d refused events for one peer asking for 3.5 s, want 1: %+v", len(refused), refused)
	}
	want := ipc.Event{Event: "refused", Reason: "unknown_peer", Peer: strangerKey.Public().UntypedHexString()[:8], Count: 1}
	if refused[0] != want {
		t.Errorf("refused = %+v, want %+v", refused[0], want)
	}

	// The session still works for the peer it is for.
	peer := s.dial(t)
	c.next(ipc.EventRefused, time.Second)
	c.next(ipc.EventConnected, 10*time.Second)
	if _, err := peer.Write([]byte("still here")); err != nil {
		t.Fatal(err)
	}
	readExactly(t, c.stdout, "still here")
}

func TestRefusedPeersAreCountedBetweenReports(t *testing.T) {
	saved := refusedRepeat
	refusedRepeat = 200 * time.Millisecond
	defer func() { refusedRepeat = saved }()

	var out bytes.Buffer
	s := &session{em: ipc.NewEmitter(&out), refused: make(map[string]*refusedPeer)}
	for i := 0; i < 3; i++ {
		s.peerRefused("aaaaaaaa")
	}
	time.Sleep(250 * time.Millisecond)
	s.peerRefused("aaaaaaaa")
	s.peerRefused("bbbbbbbb")

	want := `{"event":"refused","reason":"unknown_peer","peer":"aaaaaaaa","count":1}
{"event":"refused","reason":"unknown_peer","peer":"aaaaaaaa","count":3}
{"event":"refused","reason":"unknown_peer","peer":"bbbbbbbb","count":1}
`
	if out.String() != want {
		t.Errorf("events:\n%s\nwant:\n%s", out.String(), want)
	}

	// Past the limit of peers told apart, the rest share one entry: the
	// table cannot be grown from outside.
	out.Reset()
	s = &session{em: ipc.NewEmitter(&out), refused: make(map[string]*refusedPeer)}
	for i := 0; i < maxRefusedPeers+40; i++ {
		s.peerRefused(fmt.Sprintf("%08x", i))
	}
	if len(s.refused) != maxRefusedPeers+1 {
		t.Errorf("%d peers tracked, want %d and one entry for the rest", len(s.refused), maxRefusedPeers)
	}
	if n := strings.Count(out.String(), "\n"); n != maxRefusedPeers+1 {
		t.Errorf("%d events, want %d", n, maxRefusedPeers+1)
	}
}

// With debug on, the tunnel library's own lines come as log events, never as
// bare text.
func TestDebugSendsTheLibrarysLogAsEvents(t *testing.T) {
	relay := tunneltest.StartRelay(t)
	s := newSession(relay.Region)
	c := startCompanion(t)
	c.next(ipc.EventHello, 5*time.Second)
	c.send(s.config(func(cfg *ipc.Config) { cfg.Debug = true }))
	c.next(ipc.EventListening, 15*time.Second)
	if len(c.all(ipc.EventLog)) == 0 {
		t.Error("no log events with debug on")
	}
	for _, secret := range s.secrets()[:4] {
		if strings.Contains(c.stderr(), secret) {
			t.Error("the library's log shows key material")
		}
	}
}

// An agent that ends a session closes both of the companion's pipes, and so
// does an agent that dies. Whichever the companion notices first, and
// whatever the peer is doing, the peer gets what the agent wrote last and
// then the end of the stream. Here the peer is sending without pause, so the
// companion's write to stdout fails at about the moment its stdin ends.
func TestEndingWhileThePeerSendsLosesNothing(t *testing.T) {
	relay := tunneltest.StartRelay(t)
	for round := 1; round <= 12; round++ {
		s := newSession(relay.Region)
		c := startCompanion(t)
		c.next(ipc.EventHello, 5*time.Second)
		c.send(s.config(nil))
		c.next(ipc.EventListening, 15*time.Second)
		peer := s.dial(t)
		c.next(ipc.EventConnected, 10*time.Second)

		stopSending := make(chan struct{})
		go func() {
			chunk := make([]byte, 1024)
			for {
				select {
				case <-stopSending:
					return
				default:
				}
				if _, err := peer.Write(chunk); err != nil {
					return
				}
			}
		}()
		go io.Copy(io.Discard, c.stdout) // the agent reads along, until it does not
		time.Sleep(20 * time.Millisecond)

		if _, err := c.stdin.Write([]byte("the last frame")); err != nil {
			t.Fatal(err)
		}
		c.stdin.Close()
		c.stdout.Close()

		_ = peer.SetReadDeadline(time.Now().Add(15 * time.Second))
		got, err := io.ReadAll(peer)
		close(stopSending)
		if err != nil || string(got) != "the last frame" {
			t.Fatalf("round %d: the peer read %q, %v; want the last frame and then the end of the stream", round, got, err)
		}
		peer.Close()
		if closed := c.next(ipc.EventClosed, 10*time.Second); closed.Reason != ipc.ReasonStdinClosed {
			t.Errorf("round %d: closed = %+v, want reason %q", round, closed, ipc.ReasonStdinClosed)
		}
		c.waitExit(0)
	}
}

// An agent that only stops reading: the session ends, and the peer still
// sees the end of the stream and not a broken connection.
func TestStdoutClosingEndsTheSessionInOrder(t *testing.T) {
	relay := tunneltest.StartRelay(t)
	s := newSession(relay.Region)
	c := startCompanion(t)
	c.next(ipc.EventHello, 5*time.Second)
	c.send(s.config(nil))
	c.next(ipc.EventListening, 15*time.Second)
	peer := s.dial(t)
	c.next(ipc.EventConnected, 10*time.Second)

	c.stdout.Close()
	if _, err := peer.Write([]byte("for nobody")); err != nil {
		t.Fatal(err)
	}
	_ = peer.SetReadDeadline(time.Now().Add(15 * time.Second))
	if got, err := io.ReadAll(peer); err != nil || len(got) != 0 {
		t.Errorf("the peer read %q, %v; want the end of the stream", got, err)
	}
	peer.Close()
	if closed := c.next(ipc.EventClosed, 10*time.Second); closed.Reason != ipc.ReasonStdoutClosed {
		t.Errorf("closed = %+v, want reason %q", closed, ipc.ReasonStdoutClosed)
	}
	c.waitExit(0)
}

// A companion that is started and never given a configuration does not stay.
func TestACompanionNobodySpeaksToEnds(t *testing.T) {
	saved := configWait
	configWait = 300 * time.Millisecond
	defer func() { configWait = saved }()

	c := startCompanion(t)
	c.next(ipc.EventHello, 5*time.Second)
	e := c.next(ipc.EventError, 10*time.Second)
	if e.Reason != ipc.ReasonNoConfig || e.Detail != "no configuration within 300ms" {
		t.Errorf("error = %+v", e)
	}
	c.waitExit(1)
}

// A panic where the tunnel is started is reported as an event that says
// where, and shows none of the values: the runtime's own report prints the
// arguments on the stack, and those are the session's keys.
func TestAPanicIsReportedWithoutTheKeys(t *testing.T) {
	relay := tunneltest.StartRelay(t)
	s := newSession(relay.Region)
	node := s.serverKey.Raw32()
	c := startCompanionWith(t, func(o *Options) {
		o.regionFor = func(ipc.Relay) *tailcfg.DERPRegion {
			panic(fmt.Sprintf("key %x and %#x went wrong", node[:], node[:8]))
		}
	})
	c.next(ipc.EventHello, 5*time.Second)
	c.send(s.config(nil))
	e := c.next(ipc.EventError, 10*time.Second)
	if e.Reason != ipc.ReasonInternal {
		t.Errorf("error = %+v, want reason %q", e, ipc.ReasonInternal)
	}
	if !strings.HasPrefix(e.Detail, "panic: key … and … went wrong in ") || !strings.Contains(e.Detail, "run.tunnelConfig (run.go:") {
		t.Errorf("detail = %q, want the panic's text without its numbers and the place it happened", e.Detail)
	}
	c.waitExit(1)
	for _, secret := range append(s.secrets(), fmt.Sprintf("%x", node[:8]), "0x") {
		if strings.Contains(c.stderr(), secret) {
			t.Errorf("stderr shows %q:\n%s", secret, c.stderr())
		}
	}
}

// What the tunnel reports in the instant before the companion says it
// listens is said after that, and nothing is said after its last event: the
// agent reads listening as the first word of a session and closed as the
// last.
func TestEventsKeepTheirOrder(t *testing.T) {
	var out bytes.Buffer
	s := &session{em: ipc.NewEmitter(&out), debug: true, refused: make(map[string]*refusedPeer)}

	s.notice(tunnel.Notice{Kind: tunnel.NoticePeerRefused, Peer: "aaaaaaaa"})
	s.notice(tunnel.Notice{Kind: tunnel.NoticeRelayLost})
	if out.Len() != 0 {
		t.Fatalf("said before listening: %s", out.String())
	}

	s.listening()
	s.listening() // only once
	s.notice(tunnel.Notice{Kind: tunnel.NoticeRelayConnected})
	s.last(ipc.Event{Event: ipc.EventClosed, Reason: ipc.ReasonPeerClosed})
	s.notice(tunnel.Notice{Kind: tunnel.NoticePeerRefused, Peer: "bbbbbbbb"})
	s.notice(tunnel.Notice{Kind: tunnel.NoticeRelayLost})
	s.libraryLog("a line %d", 1)
	s.last(ipc.Event{Event: ipc.EventError, Reason: ipc.ReasonInternal})

	want := `{"event":"listening"}
{"event":"refused","reason":"unknown_peer","peer":"aaaaaaaa","count":1}
{"event":"relay","state":"lost"}
{"event":"relay","state":"connected"}
{"event":"closed","reason":"peer_closed"}
`
	if out.String() != want {
		t.Errorf("events:\n%s\nwant:\n%s", out.String(), want)
	}

	// Held notices are bounded: a flood before listening cannot grow them.
	out.Reset()
	s = &session{em: ipc.NewEmitter(&out), refused: make(map[string]*refusedPeer)}
	for i := 0; i < maxHeldNotices+100; i++ {
		s.notice(tunnel.Notice{Kind: tunnel.NoticeRelayLost})
	}
	if len(s.held) != maxHeldNotices {
		t.Errorf("%d notices held, want at most %d", len(s.held), maxHeldNotices)
	}
}
