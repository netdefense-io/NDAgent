package directpeer

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/netdefense-io/ndagent/internal/logging"
)

// Relay is the relay a session uses, as the control plane names it.
type Relay struct {
	// ID is its short name in the relay catalogue, e.g. "us".
	ID string
	// Host is its hostname.
	Host string
	// Port and STUNPort are its TLS and STUN ports; 0 is the default.
	Port     int
	STUNPort int
}

// Keys are one session's keys. They exist for that session only and are all
// the companion is ever given.
type Keys struct {
	// Node is this device's private key for the session, already clamped by
	// whoever derived it. The companion refuses one that is not and never
	// clamps it itself: the tunnel derives a second key from these bytes,
	// and the client derives the same from its own copy.
	Node [32]byte
	// Peer is the public key of the one client the session is for.
	Peer [32]byte
	// PSK is the session's pre-shared key.
	PSK [32]byte
}

// Spec is one session to carry.
type Spec struct {
	Relay Relay
	Keys  Keys
	// OnEvent, if set, is called for each event the companion sends about the
	// session (connected, path, relay, refused), in order, from a goroutine
	// of its own. The first call can come before Open has returned. A
	// callback that takes its time delays the ones after it and nothing
	// else; events that pile up behind one that never returns are dropped.
	OnEvent func(Event)
}

func (s *Spec) validate() error {
	var zero [32]byte
	switch {
	case s.Relay.ID == "":
		return errors.New("no relay")
	case s.Relay.Host == "":
		return errors.New("no relay host")
	case s.Keys.Node == zero:
		return errors.New("no node key")
	case s.Keys.Node[0]&7 != 0 || s.Keys.Node[31]&0x80 != 0 || s.Keys.Node[31]&0x40 == 0:
		return errors.New("the node key is not clamped")
	case s.Keys.Peer == zero:
		return errors.New("no client key")
	case s.Keys.PSK == zero:
		return errors.New("no pre-shared key")
	}
	return nil
}

// StartError is why a session could not start. Reason is one of the Fail
// reasons. The message is fit for a task result: it says what to do where
// there is something to do, and names no internal part.
type StartError struct {
	Reason string
	// Detail is for the log: the companion's own detail, or what it wrote
	// before it ended.
	Detail  string
	message string
}

func (e *StartError) Error() string { return e.message }

// companionStartTimeoutMS is how long the companion itself waits for the
// relay, inside the agent's own wait for it to listen.
const companionStartTimeoutMS = 8000

// companionEnv is the companion's whole environment. A Go program's report
// of a crash lists every call on every stack with the first words of its
// arguments, and in the companion those hold the session's keys. Only the
// environment a process starts in can turn the report off; the companion
// takes no session without it.
const companionEnv = "GOTRACEBACK=none"

// Starter starts companions.
type Starter struct {
	// Path is the companion's absolute path.
	Path string
	// Version is the agent's version. A companion that says another is not
	// given a session: package and agent were not installed together.
	Version string
	// RunAs is the user the companion runs as when the agent is root.
	RunAs string
	// Debug has the companion pass on the tunnel library's log lines, which
	// the agent writes to its own debug log.
	Debug bool

	// HelloTimeout bounds the wait for the companion's first line and
	// ListenTimeout the whole start, from the moment the process is started
	// until it listens. StopGrace is how long a companion whose stdin closed
	// has to end by itself, which covers its orderly close toward the client;
	// it is then sent a termination signal, and killed KillGrace later.
	HelloTimeout  time.Duration
	ListenTimeout time.Duration
	StopGrace     time.Duration
	KillGrace     time.Duration

	// Test seams. A stand-in companion is the test binary itself, told what
	// to play through extraEnv; companionWaitMS shortens the companion's own
	// wait for the relay.
	extraEnv        []string
	companionWaitMS int
	euid            func() int
	lookupUser      func(string) (*user.User, error)
}

// NewStarter returns a Starter for the companion the package installs.
func NewStarter(agentVersion string) *Starter {
	return &Starter{
		Path:          DefaultCompanionPath,
		Version:       agentVersion,
		RunAs:         DefaultRunAs,
		HelloTimeout:  5 * time.Second,
		ListenTimeout: 10 * time.Second,
		StopGrace:     5 * time.Second,
		KillGrace:     4 * time.Second,
	}
}

// process is a started companion and the agent's ends of its pipes.
type process struct {
	cmd      *exec.Cmd
	toPeer   *os.File // its stdin
	fromPeer *os.File // its stdout
	events   <-chan Event
	diag     *diagnostics
	began    time.Time
}

// kill removes a companion that never got to carry a session.
func (p *process) kill() {
	_ = p.cmd.Process.Kill()
	_ = p.toPeer.Close()
	_ = p.fromPeer.Close()
	for range p.events {
	}
	_ = p.cmd.Wait()
}

// Pending is a companion that has said which build it is and has been given
// nothing yet. Open hands it a session; Abort ends it.
type Pending struct {
	st   *Starter
	proc *process
	log  *zap.SugaredLogger
	once sync.Once
}

// Start starts a companion for spec and returns once it listens: Launch,
// then Open.
func (st *Starter) Start(ctx context.Context, spec Spec) (*Session, error) {
	p, err := st.Launch(ctx)
	if err != nil {
		return nil, err
	}
	return p.Open(ctx, spec)
}

// Launch starts the companion and checks that it is the build this agent
// came with, before the session's secret is even opened: a device without a
// usable companion says so, whatever else is wrong with the request. A
// companion that is missing, does not run, or is another build is
// FailCompanionUnavailable, and the message says to reinstall the package,
// which is the remedy for all three. The error is a *StartError, or ctx's
// error when ctx ended first; the companion is gone then.
//
// The check is against a package and an agent that were not installed
// together. It is not a check of the file: whoever can replace it can have it
// say the right version. What protects the file is where the package puts it.
//
// A Pending must be opened or aborted. One that is neither is ended by the
// companion itself, which waits half a minute for its configuration.
func (st *Starter) Launch(ctx context.Context) (*Pending, error) {
	unavailable := &StartError{
		Reason:  FailCompanionUnavailable,
		message: "the direct-peer companion (ndagent-connect) is not installed on this device; reinstall the NetDefense package",
	}
	broken := func(what string) *StartError {
		return &StartError{
			Reason:  FailCompanionUnavailable,
			message: "the direct-peer companion (ndagent-connect) on this device does not work (" + what + "); reinstall the NetDefense package",
		}
	}
	if !filepath.IsAbs(st.Path) {
		unavailable.Detail = fmt.Sprintf("%q is not an absolute path", st.Path)
		return nil, unavailable
	}
	if info, err := os.Stat(st.Path); err != nil || info.IsDir() {
		unavailable.Detail = fmt.Sprintf("%s: %v", st.Path, err)
		return nil, unavailable
	}

	attr, err := st.sysProcAttr()
	if err != nil {
		return nil, &StartError{
			Reason:  FailCompanionFailed,
			Detail:  err.Error(),
			message: "the direct-peer companion cannot be started without privileges on this device: " + err.Error(),
		}
	}

	cmd := exec.Command(st.Path)
	cmd.Env = append([]string{companionEnv}, st.extraEnv...)
	cmd.Dir = "/"
	cmd.SysProcAttr = attr

	pipes, err := newPipes()
	if err != nil {
		return nil, &StartError{Reason: FailCompanionFailed, Detail: err.Error(), message: "the direct-peer companion could not be started: " + err.Error()}
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = pipes.stdinR, pipes.stdoutW, pipes.stderrW
	began := time.Now()
	err = cmd.Start()
	pipes.closeChildEnds()
	if err != nil {
		pipes.closeParentEnds()
		if errors.Is(err, fs.ErrNotExist) {
			unavailable.Detail = err.Error()
			return nil, unavailable
		}
		e := broken("it cannot be run")
		e.Detail = err.Error()
		return nil, e
	}

	diag := &diagnostics{}
	events := make(chan Event, 16)
	go readEvents(pipes.stderrR, events, diag)
	proc := &process{cmd: cmd, toPeer: pipes.stdinW, fromPeer: pipes.stdoutR, events: events, diag: diag, began: began}

	fail := func(e *StartError) (*Pending, error) {
		proc.kill()
		if e.Detail == "" {
			e.Detail = diag.String()
		}
		return nil, e
	}

	// The companion speaks first: its version, before it is given anything.
	log := logging.Named("directpeer")
	hello, outcome := awaitEvent(ctx, events, EventHello, st.HelloTimeout, log, nil)
	switch outcome {
	case awaitCancelled:
		proc.kill()
		return nil, ctx.Err()
	case awaitTimeout:
		return fail(broken(fmt.Sprintf("it said nothing within %v", st.HelloTimeout)))
	case awaitEnded:
		return fail(broken("it ended at once"))
	case awaitOther:
		return fail(broken(fmt.Sprintf("its first word was %q", hello.Event)))
	}
	if hello.Version != st.Version || hello.IPC != ipcVersion || hello.Protocol != Protocol {
		return fail(&StartError{
			Reason:  FailCompanionUnavailable,
			Detail:  fmt.Sprintf("companion: version %q commit %q exchange %d protocol %d; agent: version %q exchange %d protocol %d", hello.Version, hello.Commit, hello.IPC, hello.Protocol, st.Version, ipcVersion, Protocol),
			message: fmt.Sprintf("the direct-peer companion on this device is version %s and the agent is version %s; reinstall the NetDefense package", orUnknown(hello.Version), orUnknown(st.Version)),
		})
	}
	return &Pending{st: st, proc: proc, log: log}, nil
}

// Abort ends a companion that will not be given a session. After Open it does
// nothing, also while Open is still waiting: an Open is given up through its
// context.
func (p *Pending) Abort() {
	p.once.Do(p.proc.kill)
}

// Open hands the companion the session and returns once it listens: the
// relay accepted its connection and the client can reach it. On any other
// outcome the companion is gone when Open returns, and the error is a
// *StartError (FailRelayRefused, FailRelayUnreachable, or FailCompanionFailed
// for a companion that did not get there), or ctx's error when ctx ended
// first. A Pending is opened once.
func (p *Pending) Open(ctx context.Context, spec Spec) (*Session, error) {
	opened := false
	p.once.Do(func() { opened = true })
	if !opened {
		return nil, &StartError{Reason: FailInternal, message: "the direct-peer companion was already given a session or ended"}
	}
	proc, st := p.proc, p.st

	fail := func(e *StartError) (*Session, error) {
		proc.kill()
		if e.Detail == "" {
			e.Detail = proc.diag.String()
		}
		return nil, e
	}
	if err := spec.validate(); err != nil {
		return fail(&StartError{Reason: FailInternal, Detail: err.Error(), message: "the session cannot be carried: " + err.Error()})
	}
	if err := writeConfig(proc.toPeer, st.config(spec)); err != nil {
		return fail(didNotStart("it did not take the session: " + err.Error()))
	}

	// A client can knock, and the relay connection can drop, in the instant
	// between the relay accepting the companion and the companion saying so.
	// What it reports of that is not a failed start: it is kept for the
	// session.
	var early []Event
	answer, outcome := awaitEvent(ctx, proc.events, EventListening, st.ListenTimeout-time.Since(proc.began), p.log, &early)
	switch outcome {
	case awaitCancelled:
		proc.kill()
		return nil, ctx.Err()
	case awaitTimeout:
		return fail(didNotStart(fmt.Sprintf("it was not listening within %v", st.ListenTimeout)))
	case awaitEnded:
		return fail(didNotStart("it ended before it was listening"))
	case awaitOther:
		if answer.Event != EventError {
			return fail(didNotStart(fmt.Sprintf("it said %q before it was listening", answer.Event)))
		}
		return fail(startErrorFor(answer))
	}

	s := &Session{
		ToPeer:      proc.toPeer,
		FromPeer:    proc.fromPeer,
		ListeningAt: time.Now(),
		cmd:         proc.cmd,
		events:      proc.events,
		early:       early,
		onEvent:     spec.OnEvent,
		stopGrace:   st.StopGrace,
		killGrace:   st.KillGrace,
		log:         p.log,
		diag:        proc.diag,
		connected:   make(chan struct{}),
		done:        make(chan struct{}),
	}
	p.log.Infow("Direct-peer companion is listening",
		"relay", spec.Relay.ID,
		"pid", proc.cmd.Process.Pid,
		"after", time.Since(proc.began).Round(time.Millisecond),
	)
	go s.run()
	return s, nil
}

func didNotStart(what string) *StartError {
	return &StartError{Reason: FailCompanionFailed, message: "the direct-peer companion did not start: " + what}
}

// startErrorFor turns the companion's own error event into a StartError.
func startErrorFor(e Event) *StartError {
	switch e.Reason {
	case ReasonRelayRefused:
		return &StartError{Reason: FailRelayRefused, Detail: e.Detail, message: "the relay refused the device's connection"}
	case ReasonRelayUnreachable:
		// Why it could not be reached is in the detail, for the log: the
		// message goes into a task result, which holds fixed words only.
		return &StartError{Reason: FailRelayUnreachable, Detail: e.Detail, message: "the relay could not be reached"}
	case ReasonBadConfig, ReasonNoConfig:
		return &StartError{Reason: FailInternal, Detail: e.Detail, message: "the session cannot be carried: the companion refused it (" + e.Detail + ")"}
	default:
		return &StartError{Reason: FailCompanionFailed, Detail: strings.TrimSpace(e.Reason + " " + e.Detail), message: "the direct-peer companion did not start"}
	}
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// config is the message for the companion. The caller wipes it.
func (st *Starter) config(spec Spec) *companionConfig {
	port, stunPort := spec.Relay.Port, spec.Relay.STUNPort
	if port == 0 {
		port = DefaultRelayPort
	}
	if stunPort == 0 {
		stunPort = DefaultRelaySTUNPort
	}
	waitMS := companionStartTimeoutMS
	if st.companionWaitMS != 0 {
		waitMS = st.companionWaitMS
	}
	return &companionConfig{
		V:        ipcVersion,
		Role:     companionRole,
		Protocol: Protocol,
		Relay: relayConfig{
			ID:       spec.Relay.ID,
			RegionID: RelayRegionID,
			Host:     spec.Relay.Host,
			Port:     port,
			STUNPort: stunPort,
		},
		Port:           ServedPort,
		NodeKey:        spec.Keys.Node,
		PeerKey:        spec.Keys.Peer,
		PSK:            spec.Keys.PSK,
		StartTimeoutMS: waitMS,
		Debug:          st.Debug,
	}
}

// writeConfig writes the configuration message, the one place a key travels,
// and wipes the copies it holds: the message and the keys in cfg. That is as
// far as it goes. Encoding the message makes strings of the keys, which
// cannot be wiped, and the caller's Spec still holds them: they are one
// session's keys, and the companion they are for holds them anyway.
func writeConfig(w *os.File, cfg *companionConfig) error {
	message, err := cfg.encode()
	clear(cfg.NodeKey[:])
	clear(cfg.PSK[:])
	if err != nil {
		return err
	}
	defer clear(message)
	_ = w.SetWriteDeadline(time.Now().Add(5 * time.Second))
	defer w.SetWriteDeadline(time.Time{})
	_, err = w.Write(message)
	return err
}

// Session is a running companion that listens for its client.
type Session struct {
	// ToPeer takes the session's frames for the client. Closing it ends the
	// session: the companion closes toward the client and exits.
	ToPeer *os.File
	// FromPeer gives the session's frames from the client. It ends when the
	// companion does.
	FromPeer *os.File
	// ListeningAt is when the companion said it listens: a session's
	// lifetime and its wait for the client are counted from it.
	ListeningAt time.Time

	cmd       *exec.Cmd
	events    <-chan Event
	early     []Event // said just before the companion listened
	onEvent   func(Event)
	stopGrace time.Duration
	killGrace time.Duration
	log       *zap.SugaredLogger
	diag      *diagnostics

	connected chan struct{}
	done      chan struct{}
	stopOnce  sync.Once

	mu          sync.Mutex
	connectedAt time.Time
	path        string
	exit        Exit
}

// Exit is how a companion ended.
type Exit struct {
	// Reason is the companion's own word when it gave one (a closed or an
	// error reason), else ExitUnexplained or ExitKilled.
	Reason string
	Detail string
	// Said reports whether the companion gave the reason itself.
	Said bool
	// Code is its exit status, or -1 when a signal ended it.
	Code int
}

// Exits the companion did not explain.
const (
	ExitUnexplained = "exited"
	ExitKilled      = "killed"
)

// Connected is closed once the client has opened the session's connection.
func (s *Session) Connected() <-chan struct{} { return s.connected }

// ConnectedAt is when the client connected; ok is false while it has not.
func (s *Session) ConnectedAt() (at time.Time, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connectedAt, !s.connectedAt.IsZero()
}

// Path is how traffic reaches the client now: PathDirect, PathRelayed, or ""
// before the companion has said.
func (s *Session) Path() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.path
}

// Done is closed once the companion is gone.
func (s *Session) Done() <-chan struct{} { return s.done }

// Exit is how the companion ended. Read it after Done.
func (s *Session) Exit() Exit {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.exit
}

// Stop ends the session and returns once the companion is gone. Closing its
// stdin is the request: it sends what it was given, closes toward the client
// and exits. One that is still there after the grace period has not read up
// to the end of its stdin (a client that takes no data holds back what was
// written before it), so it is sent a termination signal, which it notices at
// any time and answers with the same orderly close. One that ignores that too
// is killed.
func (s *Session) Stop() {
	s.stopOnce.Do(func() {
		_ = s.ToPeer.Close()
		if !s.endedWithin(s.stopGrace) {
			s.log.Warnw("Direct-peer companion did not end when its stdin closed; signalling it", "pid", s.cmd.Process.Pid)
			_ = s.cmd.Process.Signal(syscall.SIGTERM)
			if !s.endedWithin(s.killGrace) {
				s.log.Warnw("Direct-peer companion did not end when signalled; killing it", "pid", s.cmd.Process.Pid)
				_ = s.cmd.Process.Kill()
				<-s.done
			}
		}
		_ = s.FromPeer.Close()
	})
}

func (s *Session) endedWithin(d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-s.done:
		return true
	case <-timer.C:
		return false
	}
}

// maxQueuedCallbacks bounds the events waiting for OnEvent.
const maxQueuedCallbacks = 64

// run follows the companion from listening to its end.
func (s *Session) run() {
	// OnEvent runs on a goroutine of its own, so that a callback that blocks
	// cannot keep this one from seeing the companion end, which Stop waits
	// for.
	var callbacks chan Event
	if s.onEvent != nil {
		callbacks = make(chan Event, maxQueuedCallbacks)
		go func() {
			for e := range callbacks {
				s.onEvent(e)
			}
		}()
		defer close(callbacks)
	}

	var last Event
	said := false
	take := func(e Event) {
		switch e.Event {
		case EventLog:
			s.log.Debugw("Direct-peer companion", "line", e.Msg)
			return
		case EventClosed, EventError:
			if !said {
				last, said = e, true
			}
			return
		}
		if said {
			return // nothing follows the companion's last word
		}
		switch e.Event {
		case EventConnected:
			s.mu.Lock()
			first := s.connectedAt.IsZero()
			if first {
				s.connectedAt = time.Now()
			}
			s.mu.Unlock()
			if !first {
				return
			}
			close(s.connected)
			s.log.Infow("Direct-peer session: the client connected")
		case EventPath:
			s.mu.Lock()
			s.path = e.Path
			s.mu.Unlock()
			s.log.Infow("Direct-peer session path", "path", e.Path)
		case EventRelay:
			if e.State == RelayLost {
				s.log.Warnw("Direct-peer session: connection to the relay lost", "reason", e.Reason, "detail", e.Detail)
			} else {
				s.log.Infow("Direct-peer session: connected to the relay again")
			}
		case EventRefused:
			s.log.Warnw("Direct-peer session: a client with another key was refused", "client_key", e.Peer, "requests", e.Count)
		default:
			return
		}
		if callbacks != nil {
			select {
			case callbacks <- e:
			default:
				s.log.Warnw("Direct-peer session: an event was dropped, the ones before it are still being handled", "event", e.Event)
			}
		}
	}
	for _, e := range s.early {
		take(e)
	}
	s.early = nil
	for e := range s.events {
		take(e)
	}

	exit := Exit{Reason: ExitUnexplained}
	err := s.cmd.Wait()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		exit.Code = exitErr.ExitCode()
		if exit.Code < 0 {
			exit.Reason = ExitKilled
		}
	default:
		exit.Code = -1
	}
	if said {
		exit.Reason, exit.Detail, exit.Said = last.Reason, last.Detail, true
	} else if text := s.diag.String(); text != "" {
		exit.Detail = text
	}

	if exit.Said && last.Event == EventClosed {
		s.log.Infow("Direct-peer companion ended", "reason", exit.Reason)
	} else {
		s.log.Warnw("Direct-peer companion ended unexpectedly", "reason", exit.Reason, "exit_code", exit.Code, "detail", exit.Detail)
	}
	s.mu.Lock()
	s.exit = exit
	s.mu.Unlock()
	close(s.done)
}

// Outcomes of awaitEvent.
const (
	awaitGot = iota
	awaitOther
	awaitTimeout
	awaitEnded
	awaitCancelled
)

// awaitEvent waits for the event named. Log lines go to the debug log. With
// early, what the companion reports about a session before it says the event
// (a refused client, the relay, the path) is kept there and passed over;
// without it, any other event ends the wait. An event that is already there
// when the wait runs out counts: the companion said it in time.
func awaitEvent(ctx context.Context, events <-chan Event, name string, within time.Duration, log *zap.SugaredLogger, early *[]Event) (Event, int) {
	timer := time.NewTimer(max(within, 0))
	defer timer.Stop()
	// take says whether e ends the wait, and how.
	take := func(e Event, ok bool) (int, bool) {
		switch {
		case !ok:
			return awaitEnded, true
		case e.Event == EventLog:
			log.Debugw("Direct-peer companion", "line", e.Msg)
			return 0, false
		case e.Event == name:
			return awaitGot, true
		case early != nil && (e.Event == EventRefused || e.Event == EventRelay || e.Event == EventPath):
			*early = append(*early, e)
			return 0, false
		default:
			return awaitOther, true
		}
	}
	for {
		select {
		case e, ok := <-events:
			if outcome, done := take(e, ok); done {
				return e, outcome
			}
			continue
		default:
		}
		select {
		case e, ok := <-events:
			if outcome, done := take(e, ok); done {
				return e, outcome
			}
		case <-timer.C:
			return Event{}, awaitTimeout
		case <-ctx.Done():
			return Event{}, awaitCancelled
		}
	}
}

// pipes are the companion's three, each with the end the agent keeps.
type pipes struct {
	stdinR, stdinW   *os.File
	stdoutR, stdoutW *os.File
	stderrR, stderrW *os.File
}

func newPipes() (*pipes, error) {
	var p pipes
	var err error
	if p.stdinR, p.stdinW, err = os.Pipe(); err != nil {
		return nil, err
	}
	if p.stdoutR, p.stdoutW, err = os.Pipe(); err != nil {
		p.closeChildEnds()
		p.closeParentEnds()
		return nil, err
	}
	if p.stderrR, p.stderrW, err = os.Pipe(); err != nil {
		p.closeChildEnds()
		p.closeParentEnds()
		return nil, err
	}
	return &p, nil
}

func closeFiles(files ...*os.File) {
	for _, f := range files {
		if f != nil {
			_ = f.Close()
		}
	}
}

func (p *pipes) closeChildEnds()  { closeFiles(p.stdinR, p.stdoutW, p.stderrW) }
func (p *pipes) closeParentEnds() { closeFiles(p.stdinW, p.stdoutR, p.stderrR) }

const (
	maxEventLine    = 64 << 10
	maxDiagLines    = 20
	maxDiagLineSize = 300
)

// readEvents turns the companion's stderr into events until it ends, then
// closes events. Lines that are not events are kept as diagnostics: the Go
// runtime writes a crash there.
func readEvents(stderr *os.File, events chan<- Event, diag *diagnostics) {
	defer close(events)
	defer stderr.Close()
	r := bufio.NewReaderSize(stderr, maxEventLine)
	for {
		line, err := r.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			// A line longer than any event: keep its start, skip the rest.
			diag.add(line)
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = r.ReadSlice('\n')
			}
		} else if len(line) > 0 {
			if e, ok := parseEvent(line); ok {
				events <- e
			} else {
				diag.add(line)
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, os.ErrClosed) {
				diag.add([]byte("reading the companion's events: " + err.Error()))
			}
			return
		}
	}
}

// diagnostics keeps the last lines the companion wrote that were not events:
// what the Go runtime prints when a program dies. They end up in the agent's
// log, so nothing that could be key material stays in them. A crash report
// prints the first words of every call's arguments as hex numbers, and the
// companion's calls carry the session's keys; the companion turns that report
// off, and this holds whatever it prints.
type diagnostics struct {
	mu    sync.Mutex
	lines []string
}

// keyLike matches hex literals and long runs of hex digits.
var keyLike = regexp.MustCompile(`0[xX][0-9a-fA-F]+|[0-9a-fA-F]{16,}`)

func (d *diagnostics) add(line []byte) {
	text := keyLike.ReplaceAllString(strings.TrimSpace(string(line)), "…")
	if text == "" {
		return
	}
	if len(text) > maxDiagLineSize {
		text = text[:maxDiagLineSize]
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.lines = append(d.lines, text)
	if len(d.lines) > maxDiagLines {
		d.lines = d.lines[len(d.lines)-maxDiagLines:]
	}
}

func (d *diagnostics) String() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return strings.Join(d.lines, " | ")
}
