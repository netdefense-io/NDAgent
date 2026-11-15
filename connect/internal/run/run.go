// Package run is the companion's whole life: say hello, read the
// configuration, bring the tunnel up, carry one connection between the peer
// and the agent, say why it ended.
package run

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"tailscale.com/tailcfg"

	"github.com/netdefense-io/ndagent/connect/internal/ipc"
	"github.com/netdefense-io/ndagent/connect/internal/tunnel"
)

// Timings. Variables so tests can shorten them.
var (
	// configWait bounds the wait for the configuration message. The agent
	// writes it within moments of the hello; a companion nobody speaks to
	// does not stay.
	configWait = 30 * time.Second
	// pathPollInterval is how often the path to the peer is looked at.
	pathPollInterval = 2 * time.Second
	// closeGrace bounds each step of an orderly close: sending what the agent
	// already wrote, and waiting for the peer to close in answer.
	closeGrace = 2 * time.Second
	// bothPipesGrace is how long stdin has to show that it closed too, once
	// stdout has: an agent that ends a session, or dies, closes both.
	bothPipesGrace = 100 * time.Millisecond
	// refusedRepeat is the least time between two reports of the same
	// refused peer, which asks again every second.
	refusedRepeat = 30 * time.Second
)

const (
	// maxRefusedPeers bounds how many refused peers are told apart; the rest
	// are counted together.
	maxRefusedPeers = 16
	// maxHeldNotices bounds what is kept for after the listening event.
	maxHeldNotices = 32
)

// Options are the companion's three pipes and its identity.
type Options struct {
	// Stdin carries the configuration message, then the session's bytes
	// toward the peer. Its end is the agent ending the session.
	Stdin io.Reader
	// Stdout carries the session's bytes from the peer, and nothing else.
	Stdout io.Writer
	// Stderr carries the events.
	Stderr io.Writer

	Version string
	Commit  string

	// Stop, when closed, ends the companion as a termination signal does.
	Stop <-chan struct{}

	// regionFor describes the relay to the tunnel library. Nil in the
	// companion; a test replaces it to reach a relay that runs inside the
	// test, which no configuration message can ask for.
	regionFor func(ipc.Relay) *tailcfg.DERPRegion
}

// Run runs the companion and returns its exit status: 0 when it ended as
// told or a session ran to an end, 1 when it could not start.
func Run(o Options) (code int) {
	sess := &session{em: ipc.NewEmitter(o.Stderr), refused: make(map[string]*refusedPeer)}

	// A panic on this goroutine, where the tunnel library is started, is
	// reported as an event that says where it happened and none of the
	// values involved. The runtime's own crash report prints the arguments
	// of every call on the stack, and here those are the session's keys,
	// which is why the companion runs with that report turned off.
	defer func() {
		if r := recover(); r != nil {
			sess.last(ipc.Event{Event: ipc.EventError, Reason: ipc.ReasonInternal, Detail: describePanic(r)})
			code = 1
		}
	}()

	sess.em.Emit(ipc.Event{
		Event:    ipc.EventHello,
		Version:  o.Version,
		Commit:   o.Commit,
		Protocol: ipc.Protocol,
		IPC:      ipc.Version,
	})

	// Reading the configuration and starting the tunnel both wait on someone
	// else. A termination signal ends the companion during either.
	terminated := func() int {
		sess.last(ipc.Event{Event: ipc.EventClosed, Reason: ipc.ReasonTerminated})
		return 0
	}
	type readResult struct {
		cfg *ipc.Config
		err error
	}
	readc := make(chan readResult, 1)
	go func() {
		cfg, err := ipc.ReadConfig(o.Stdin)
		readc <- readResult{cfg, err}
	}()
	waited := time.NewTimer(configWait)
	defer waited.Stop()
	var cfg *ipc.Config
	select {
	case r := <-readc:
		if r.err != nil {
			reason := ipc.ReasonBadConfig
			if errors.Is(r.err, ipc.ErrNoConfig) {
				reason = ipc.ReasonNoConfig
			}
			sess.last(ipc.Event{Event: ipc.EventError, Reason: reason, Detail: r.err.Error()})
			return 1
		}
		cfg = r.cfg
	case <-waited.C:
		sess.last(ipc.Event{Event: ipc.EventError, Reason: ipc.ReasonNoConfig, Detail: fmt.Sprintf("no configuration within %v", configWait)})
		return 1
	case <-o.Stop:
		return terminated()
	}

	sess.debug = cfg.Debug
	tcfg, startTimeout, err := tunnelConfig(cfg, o.regionFor)
	cfg.Wipe()
	if err != nil {
		sess.last(ipc.Event{Event: ipc.EventError, Reason: ipc.ReasonBadConfig, Detail: err.Error()})
		return 1
	}
	tcfg.Notify = sess.notice
	if sess.debug {
		tcfg.Logf = sess.libraryLog
	}

	ctx, cancel := context.WithTimeout(context.Background(), startTimeout)
	started := make(chan struct{})
	go func() {
		select {
		case <-o.Stop:
			cancel()
		case <-started:
		}
	}()
	srv, err := tunnel.Start(ctx, tcfg)
	close(started)
	cancel()
	tcfg.PSK = [32]byte{}
	if err != nil {
		if stopped(o.Stop) {
			return terminated()
		}
		sess.last(sess.startFailure(err))
		return 1
	}
	defer srv.Close()
	// ended says why the companion ends, after the tunnel is down: nothing
	// the tunnel reports can follow the last event.
	ended := func(reason string) int {
		srv.Close()
		sess.last(ipc.Event{Event: ipc.EventClosed, Reason: reason})
		return 0
	}
	sess.listening()

	quit := make(chan struct{})
	defer close(quit)
	up := make(chan []byte)
	stdinDone := make(chan struct{})
	go readStdin(o.Stdin, up, stdinDone, quit)

	type accepted struct {
		conn net.Conn
		err  error
	}
	acceptc := make(chan accepted, 1)
	go func() {
		conn, err := srv.Accept()
		acceptc <- accepted{conn, err}
	}()

	var conn net.Conn
	select {
	case a := <-acceptc:
		if a.err != nil {
			srv.Close()
			sess.last(sess.startFailure(a.err))
			return 1
		}
		conn = a.conn
	case <-stdinDone:
		return ended(ipc.ReasonStdinClosed)
	case <-o.Stop:
		return ended(ipc.ReasonTerminated)
	}
	sess.em.Emit(ipc.Event{Event: ipc.EventConnected})

	stopPath := make(chan struct{})
	pathDone := make(chan struct{})
	go func() {
		defer close(pathDone)
		watchPath(srv, sess.em, stopPath)
	}()

	pumped := make(chan string, 2)
	downDone := make(chan struct{})
	go func() {
		defer close(downDone)
		pumped <- copyDown(o.Stdout, conn)
	}()
	upDone := make(chan struct{})
	go func() {
		defer close(upDone)
		for chunk := range up {
			if _, err := conn.Write(chunk); err != nil {
				pumped <- ipc.ReasonConnectionLost
				return
			}
		}
	}()

	var reason string
	select {
	case reason = <-pumped:
	case <-stdinDone:
		reason = ipc.ReasonStdinClosed
	case <-o.Stop:
		reason = ipc.ReasonTerminated
	}
	if reason == ipc.ReasonStdoutClosed {
		// The agent closes both pipes when it ends a session, and both close
		// when it dies. Which of the two this end notices first is chance,
		// and it is the same thing either way.
		grace := time.NewTimer(bothPipesGrace)
		select {
		case <-stdinDone:
			reason = ipc.ReasonStdinClosed
		case <-grace.C:
		}
		grace.Stop()
	}

	switch reason {
	case ipc.ReasonStdinClosed:
		closeTowardPeer(conn, upDone, downDone, true)
	case ipc.ReasonTerminated, ipc.ReasonStdoutClosed:
		closeTowardPeer(conn, upDone, downDone, false)
	case ipc.ReasonPeerClosed:
		// The peer closed first: close in answer and wait for that to be
		// acknowledged, or the peer keeps a half-closed connection.
		_ = conn.Close()
		drain, cancel := context.WithTimeout(context.Background(), closeGrace)
		srv.Drain(drain)
		cancel()
	default:
		_ = conn.Close()
	}

	// The path watcher reads the server's status, which must not outlive it.
	close(stopPath)
	<-pathDone
	return ended(reason)
}

// closeTowardPeer ends the connection from this end without losing what is
// on its way. With flush, what the agent wrote before it closed stdin is sent
// first. Then the peer is told the stream is over and gets a moment to close
// in answer. Its own bytes are read to the end meanwhile, by the copy to
// stdout while that runs and here once it has stopped: a connection closed
// with bytes unread is reset, and the peer would see an error, or nothing,
// where the end of the stream belongs.
func closeTowardPeer(conn net.Conn, upDone, downDone <-chan struct{}, flush bool) {
	if flush {
		waitFor(upDone, closeGrace)
	}
	if half, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = half.CloseWrite()
		grace := time.NewTimer(closeGrace)
		select {
		case <-downDone:
			_ = conn.SetReadDeadline(time.Now().Add(closeGrace))
			_, _ = io.Copy(io.Discard, conn)
		case <-grace.C:
		}
		grace.Stop()
	}
	_ = conn.Close()
	time.Sleep(50 * time.Millisecond)
}

// tunnelConfig turns the configuration message into the tunnel's own terms.
func tunnelConfig(cfg *ipc.Config, regionFor func(ipc.Relay) *tailcfg.DERPRegion) (tunnel.Config, time.Duration, error) {
	nodeKey, err := tunnel.NodeKey(cfg.NodeKey)
	if err != nil {
		return tunnel.Config{}, 0, errors.New("node_key: not a clamped key")
	}
	if regionFor == nil {
		regionFor = func(r ipc.Relay) *tailcfg.DERPRegion {
			return tunnel.NewRegion(r.ID, r.RegionID, r.Host, r.Port, r.STUNPort)
		}
	}
	timeoutMS := cfg.StartTimeoutMS
	if timeoutMS == 0 {
		timeoutMS = ipc.DefaultStartTimeoutMS
	}
	return tunnel.Config{
		NodeKey: nodeKey,
		PeerKey: tunnel.PeerKey(cfg.PeerKey),
		PSK:     cfg.PSK,
		Region:  regionFor(cfg.Relay),
		Port:    uint16(cfg.Port),
	}, time.Duration(timeoutMS) * time.Millisecond, nil
}

// readStdin hands what arrives on stdin to up, one read at a time, and closes
// up and then done when stdin ends.
//
// The end of stdin is seen only by reading up to it. While a chunk waits to
// be handed on (the peer has not connected yet, or has stopped taking data)
// nothing is read, and a stdin that closed behind that chunk goes unseen. The
// agent sends nothing before the peer is connected, and it ends a companion
// that has not ended by itself with a termination signal, which is noticed at
// any time.
func readStdin(r io.Reader, up chan<- []byte, done chan<- struct{}, quit <-chan struct{}) {
	defer close(done)
	defer close(up)
	buf := make([]byte, 64<<10)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			select {
			case up <- chunk:
			case <-quit:
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// copyDown copies the peer's bytes to stdout until either ends, and says
// which did.
func copyDown(stdout io.Writer, conn net.Conn) string {
	buf := make([]byte, 64<<10)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			if _, werr := stdout.Write(buf[:n]); werr != nil {
				return ipc.ReasonStdoutClosed
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return ipc.ReasonPeerClosed
			}
			return ipc.ReasonConnectionLost
		}
	}
}

// watchPath reports the path to the peer, once it is known and then each
// time it changes.
func watchPath(srv *tunnel.Server, em *ipc.Emitter, stop <-chan struct{}) {
	ticker := time.NewTicker(pathPollInterval)
	defer ticker.Stop()
	var last string
	for {
		if path := srv.Path(); path != "" && path != last {
			last = path
			em.Emit(ipc.Event{Event: ipc.EventPath, Path: path})
		}
		select {
		case <-ticker.C:
		case <-stop:
			return
		}
	}
}

func stopped(stop <-chan struct{}) bool {
	select {
	case <-stop:
		return true
	default:
		return false
	}
}

func waitFor(done <-chan struct{}, limit time.Duration) {
	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
	}
}

// A session's events come in three phases: before it listens, while it runs,
// and after its last event.
const (
	phaseStarting = iota
	phaseListening
	phaseEnded
)

// session turns what the tunnel reports into events, in an order the agent
// can rely on: nothing before the listening event but log lines, and nothing
// at all after the last one.
type session struct {
	em    *ipc.Emitter
	debug bool

	mu      sync.Mutex
	phase   int
	held    []tunnel.Notice // reported while starting, for after the listening event
	refused map[string]*refusedPeer
}

type refusedPeer struct {
	pending int
	last    time.Time
}

// listening says the companion listens, then what the tunnel reported in the
// instant before: a peer can knock the moment the relay has the connection.
func (s *session) listening() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase != phaseStarting {
		return
	}
	s.phase = phaseListening
	s.em.Emit(ipc.Event{Event: ipc.EventListening})
	for _, n := range s.held {
		s.report(n)
	}
	s.held = nil
}

// last emits the companion's final event. Whatever is reported afterwards is
// dropped.
func (s *session) last(e ipc.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase == phaseEnded {
		return
	}
	s.phase = phaseEnded
	s.em.Emit(e)
}

// notice takes what the tunnel reports. It is called from one goroutine.
func (s *session) notice(n tunnel.Notice) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch s.phase {
	case phaseStarting:
		if len(s.held) < maxHeldNotices {
			s.held = append(s.held, n)
		}
	case phaseListening:
		s.report(n)
	}
}

// report emits the event of a notice. s.mu is held.
func (s *session) report(n tunnel.Notice) {
	switch n.Kind {
	case tunnel.NoticeRelayConnected:
		s.em.Emit(ipc.Event{Event: ipc.EventRelay, State: ipc.RelayConnected})
	case tunnel.NoticeRelayLost:
		s.em.Emit(ipc.Event{Event: ipc.EventRelay, State: ipc.RelayLost, Reason: n.Failure, Detail: n.Detail})
	case tunnel.NoticePeerRefused:
		s.peerRefused(n.Peer)
	}
}

// peerRefused reports a refused peer when it is first seen and then at most
// every refusedRepeat, with how many times it asked since the last report.
// s.mu is held.
func (s *session) peerRefused(peer string) {
	p, known := s.refused[peer]
	if !known {
		if len(s.refused) >= maxRefusedPeers {
			peer = ""
			p, known = s.refused[peer]
		}
		if !known {
			p = &refusedPeer{}
			s.refused[peer] = p
		}
	}
	p.pending++
	now := time.Now()
	if !p.last.IsZero() && now.Sub(p.last) < refusedRepeat {
		return
	}
	s.em.Emit(ipc.Event{Event: ipc.EventRefused, Reason: ipc.ReasonUnknownPeer, Peer: peer, Count: p.pending})
	p.pending = 0
	p.last = now
}

// libraryLog passes one of the tunnel library's log lines on, in debug only.
func (s *session) libraryLog(format string, args ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase == phaseEnded {
		return
	}
	s.em.Emit(ipc.Event{Event: ipc.EventLog, Msg: fmt.Sprintf(format, args...)})
}

// startFailure is the error event for a tunnel that did not come up. The
// tunnel library's own error text is passed on only in debug mode.
func (s *session) startFailure(err error) ipc.Event {
	var startErr *tunnel.StartError
	if errors.As(err, &startErr) {
		return ipc.Event{Event: ipc.EventError, Reason: startErr.Failure, Detail: startErr.Detail}
	}
	e := ipc.Event{Event: ipc.EventError, Reason: ipc.ReasonStartFailed}
	if errors.Is(err, tunnel.ErrConfig) {
		e.Reason = ipc.ReasonBadConfig
		e.Detail = err.Error()
	} else if s.debug {
		e.Detail = err.Error()
	}
	return e
}

// numbers matches what could be key material in a panic's own text: hex
// literals and long runs of hex digits.
var numbers = regexp.MustCompile(`0[xX][0-9a-fA-F]+|[0-9a-fA-F]{16,}`)

const (
	maxPanicText   = 160
	maxPanicFrames = 6
)

// describePanic says what panicked and where: the panic's text, cut short and
// with anything that could be key material taken out, and the functions on
// the stack with their source lines. Never an argument: that is the part of a
// crash report that would show the session's keys.
func describePanic(r any) string {
	text := numbers.ReplaceAllString(fmt.Sprintf("panic: %v", r), "…")
	if len(text) > maxPanicText {
		text = text[:maxPanicText]
	}
	pcs := make([]uintptr, 32)
	frames := runtime.CallersFrames(pcs[:runtime.Callers(2, pcs)])
	var where []string
	for len(where) < maxPanicFrames {
		frame, more := frames.Next()
		if frame.Function != "" && !strings.HasPrefix(frame.Function, "runtime.") {
			where = append(where, fmt.Sprintf("%s (%s:%d)", frame.Function, filepath.Base(frame.File), frame.Line))
		}
		if !more {
			break
		}
	}
	if len(where) == 0 {
		return text
	}
	return text + " in " + strings.Join(where, " < ")
}
