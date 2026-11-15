package directpeer

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/netdefense-io/ndagent/internal/logging"
)

func repeated(b byte) [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = b
	}
	return k
}

// vectorSpec is the session the shared configuration vector describes.
func vectorSpec() Spec {
	return Spec{
		Relay: Relay{ID: "us", Host: "relay-us.example.net"},
		Keys:  Keys{Node: repeated(0x40), Peer: repeated(0x02), PSK: repeated(0x03)},
	}
}

// fake is a Starter that runs the stand-in companion in a scenario, and the
// file the stand-in notes what it saw in.
type fake struct {
	*Starter
	out string
}

func newFake(t *testing.T, scenario string) *fake {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "seen")
	st := NewStarter(fakeVersion)
	st.Path = self
	// The stand-in runs as whoever runs the tests, also when that is root:
	// as another user it could not write its notes into the test's directory.
	st.euid = func() int { return 1000 }
	// GORACE: a binary built with the race detector waits a second before it
	// exits, and the stand-in is this test binary.
	st.extraEnv = []string{fakeScenarioEnv + "=" + scenario, fakeOutEnv + "=" + out, "GORACE=atexit_sleep_ms=0"}
	return &fake{Starter: st, out: out}
}

// seen returns the lines the stand-in noted.
func (f *fake) seen(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(f.out)
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
}

func (f *fake) seenValue(t *testing.T, key string) (string, bool) {
	t.Helper()
	for _, line := range f.seen(t) {
		if value, ok := strings.CutPrefix(line, key+"="); ok {
			return value, true
		}
	}
	return "", false
}

// gone reports whether the stand-in's process no longer exists.
func (f *fake) gone(t *testing.T) bool {
	t.Helper()
	value, ok := f.seenValue(t, "pid")
	if !ok {
		t.Fatal("the stand-in never started")
	}
	pid, err := strconv.Atoi(value)
	if err != nil {
		t.Fatal(err)
	}
	return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
}

func startError(t *testing.T, err error) *StartError {
	t.Helper()
	var startErr *StartError
	if !errors.As(err, &startErr) {
		t.Fatalf("Start = %v, want a *StartError", err)
	}
	return startErr
}

func waitClosed(t *testing.T, what string, c <-chan struct{}) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(10 * time.Second):
		t.Fatalf("%s: still waiting after 10 s", what)
	}
}

// The whole of a start and a session: the companion is given exactly the
// configuration the shared vector spells out, the session's bytes go through
// its stdin and stdout, and closing its stdin ends it.
func TestStartHandsTheSessionToTheCompanion(t *testing.T) {
	f := newFake(t, "ok")
	var mu sync.Mutex
	var events []Event
	spec := vectorSpec()
	spec.OnEvent = func(e Event) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, e)
	}

	s, err := f.Start(context.Background(), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Stop()

	want, err := os.ReadFile("testdata/ipc/config.json")
	if err != nil {
		t.Fatal(err)
	}
	got, ok := f.seenValue(t, "config")
	if !ok {
		t.Fatalf("the companion was given no configuration; it saw %q", f.seen(t))
	}
	if got != string(want) {
		t.Errorf("the companion was given\n%s\nwant the shared vector\n%s", got, want)
	}

	waitClosed(t, "the client connecting", s.Connected())
	deadline := time.Now().Add(5 * time.Second)
	for s.Path() != PathDirect {
		if time.Now().After(deadline) {
			t.Fatalf("path = %q, want %q", s.Path(), PathDirect)
		}
		time.Sleep(5 * time.Millisecond)
	}

	if _, err := s.ToPeer.Write([]byte("a frame")); err != nil {
		t.Fatal(err)
	}
	echoed := make([]byte, 7)
	_ = s.FromPeer.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(s.FromPeer, echoed); err != nil || string(echoed) != "a frame" {
		t.Fatalf("read %q, %v from the companion; want what was written to it", echoed, err)
	}

	select {
	case <-s.Done():
		t.Fatal("the companion ended while its stdin is open")
	default:
	}
	s.Stop()
	waitClosed(t, "the companion ending", s.Done())
	if end := s.Exit(); end != (Exit{Reason: ReasonStdinClosed, Said: true}) {
		t.Errorf("end = %+v, want the companion's own stdin_closed with status 0", end)
	}
	if !f.gone(t) {
		t.Error("the companion's process is still there after Stop")
	}

	mu.Lock()
	defer mu.Unlock()
	wantEvents := []Event{{Event: "connected"}, {Event: "path", Path: "relayed"}, {Event: "path", Path: "direct"}}
	if fmt.Sprint(events) != fmt.Sprint(wantEvents) {
		t.Errorf("events = %+v, want %+v", events, wantEvents)
	}
}

// A companion that is not the agent's own build is given nothing: not the
// session's keys, not a word.
func TestStartRefusesACompanionOfAnotherBuild(t *testing.T) {
	for _, scenario := range []string{"another-version", "another-exchange", "another-protocol"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFake(t, scenario)
			s, err := f.Start(context.Background(), vectorSpec())
			if s != nil {
				s.Stop()
				t.Fatal("a session was started")
			}
			startErr := startError(t, err)
			if startErr.Reason != FailCompanionUnavailable {
				t.Errorf("reason = %q, want %q", startErr.Reason, FailCompanionUnavailable)
			}
			if !strings.Contains(startErr.Error(), "reinstall the NetDefense package") {
				t.Errorf("message = %q, want it to say what to do", startErr.Error())
			}
			if _, given := f.seenValue(t, "config"); given {
				t.Error("the companion was given the session's configuration")
			}
			if !f.gone(t) {
				t.Error("the companion's process is still there")
			}
		})
	}

	f := newFake(t, "another-version")
	_, err := f.Start(context.Background(), vectorSpec())
	want := "the direct-peer companion on this device is version 9.9.9 and the agent is version 1.2.3; reinstall the NetDefense package"
	if err == nil || err.Error() != want {
		t.Errorf("message = %q\nwant      %q", err, want)
	}
}

// A companion that does not get as far as saying which build it is does not
// work: the reason is the one for a missing companion, and so is the remedy.
// One that said so and then does not get to listen failed to start.
func TestStartFailsWhenTheCompanionDoesNotComeUp(t *testing.T) {
	cases := []struct {
		scenario string
		reason   string
		message  string // part of it
		detail   string // part of it
		// The waits are shortened only where the test is the wait.
		hello, listen time.Duration
	}{
		{"says-nothing", FailCompanionUnavailable, "does not work (it said nothing within 300ms); reinstall the NetDefense package", "", 300 * time.Millisecond, 0},
		{"ends-at-once", FailCompanionUnavailable, "does not work (it ended at once); reinstall the NetDefense package", "", 0, 0},
		{"another-first-word", FailCompanionUnavailable, `does not work (its first word was "listening"); reinstall the NetDefense package`, "", 0, 0},
		{"never-listens", FailCompanionFailed, "it was not listening within 1s", "", 0, time.Second},
		{"crashes", FailCompanionFailed, "it ended before it was listening", "panic: boom", 0, 0},
		{"connected-before-listening", FailCompanionFailed, `it said "connected" before it was listening`, "", 0, 0},
		{"relay-refused", FailRelayRefused, "the relay refused the device's connection", "", 0, 0},
		{"relay-unreachable", FailRelayUnreachable, "the relay could not be reached", "dial tcp4 203.0.113.5:443: connect: connection refused", 0, 0},
		{"bad-config", FailInternal, "psk: missing", "psk: missing", 0, 0},
		{"start-failed", FailCompanionFailed, "the direct-peer companion did not start", "", 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.scenario, func(t *testing.T) {
			f := newFake(t, tc.scenario)
			if tc.hello != 0 {
				f.HelloTimeout = tc.hello
			}
			if tc.listen != 0 {
				f.ListenTimeout = tc.listen
			}
			s, err := f.Start(context.Background(), vectorSpec())
			if s != nil {
				s.Stop()
				t.Fatal("a session was started")
			}
			startErr := startError(t, err)
			if startErr.Reason != tc.reason {
				t.Errorf("reason = %q, want %q", startErr.Reason, tc.reason)
			}
			if !strings.Contains(startErr.Error(), tc.message) {
				t.Errorf("message = %q, want it to hold %q", startErr.Error(), tc.message)
			}
			if !strings.Contains(startErr.Detail, tc.detail) {
				t.Errorf("detail = %q, want it to hold %q", startErr.Detail, tc.detail)
			}
			for _, word := range []string{"NDManager", "NDBroker", "NDPathFinder", "tailcat", "Tailcat", "tailscale", "derp"} {
				if strings.Contains(startErr.Error(), word) {
					t.Errorf("message = %q names %q", startErr.Error(), word)
				}
			}
			if !f.gone(t) {
				t.Error("the companion's process is still there after Start failed")
			}
		})
	}
}

func TestStartEndsWithItsContext(t *testing.T) {
	f := newFake(t, "never-listens")
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	began := time.Now()
	s, err := f.Start(ctx, vectorSpec())
	if s != nil {
		s.Stop()
		t.Fatal("a session was started")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Start = %v, want context.Canceled", err)
	}
	if elapsed := time.Since(began); elapsed > 20*time.Second {
		t.Errorf("Start returned %v after its context ended", elapsed)
	}
	if !f.gone(t) {
		t.Error("the companion's process is still there")
	}
}

// A file that is there and cannot be run is a companion that does not work.
func TestStartWithACompanionThatCannotBeRunSaysToReinstall(t *testing.T) {
	notAProgram := filepath.Join(t.TempDir(), "ndagent-connect")
	if err := os.WriteFile(notAProgram, []byte("not a program\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	st := NewStarter(fakeVersion)
	st.Path = notAProgram
	st.euid = func() int { return 1000 }
	s, err := st.Start(context.Background(), vectorSpec())
	if s != nil {
		s.Stop()
		t.Fatal("a session was started")
	}
	startErr := startError(t, err)
	want := "the direct-peer companion (ndagent-connect) on this device does not work (it cannot be run); reinstall the NetDefense package"
	if startErr.Reason != FailCompanionUnavailable || startErr.Error() != want {
		t.Errorf("%q %q\nwant %q %q", startErr.Reason, startErr.Error(), FailCompanionUnavailable, want)
	}
}

func TestStartWithoutACompanionSaysToReinstall(t *testing.T) {
	want := "the direct-peer companion (ndagent-connect) is not installed on this device; reinstall the NetDefense package"
	for name, path := range map[string]string{
		"no such file":    filepath.Join(t.TempDir(), "ndagent-connect"),
		"a directory":     t.TempDir(),
		"a relative path": "ndagent-connect",
		"no path":         "",
	} {
		st := NewStarter(fakeVersion)
		st.Path = path
		s, err := st.Start(context.Background(), vectorSpec())
		if s != nil {
			s.Stop()
			t.Fatalf("%s: a session was started", name)
		}
		startErr := startError(t, err)
		if startErr.Reason != FailCompanionUnavailable || startErr.Error() != want {
			t.Errorf("%s: %q %q", name, startErr.Reason, startErr.Error())
		}
	}
}

// A session with anything missing is refused, and the companion is given
// nothing of it.
func TestStartRefusesASessionWithAnythingMissing(t *testing.T) {
	cases := map[string]func(*Spec){
		"no relay":                   func(s *Spec) { s.Relay.ID = "" },
		"no relay host":              func(s *Spec) { s.Relay.Host = "" },
		"no node key":                func(s *Spec) { s.Keys.Node = [32]byte{} },
		"a node key not clamped (1)": func(s *Spec) { s.Keys.Node[0] |= 1 },
		"a node key not clamped (2)": func(s *Spec) { s.Keys.Node[31] |= 0x80 },
		"a node key not clamped (3)": func(s *Spec) { s.Keys.Node[31] &^= 0x40 },
		"no client key":              func(s *Spec) { s.Keys.Peer = [32]byte{} },
		"no pre-shared key":          func(s *Spec) { s.Keys.PSK = [32]byte{} },
	}
	for name, change := range cases {
		f := newFake(t, "ok")
		spec := vectorSpec()
		change(&spec)
		s, err := f.Start(context.Background(), spec)
		if s != nil {
			s.Stop()
			t.Fatalf("%s: a session was started", name)
		}
		if startErr := startError(t, err); startErr.Reason != FailInternal {
			t.Errorf("%s: reason %q, want %q", name, startErr.Reason, FailInternal)
		}
		if _, given := f.seenValue(t, "config"); given {
			t.Errorf("%s: the companion was given the session", name)
		}
		if !f.gone(t) {
			t.Errorf("%s: the companion's process is still there", name)
		}
	}
}

// Lines that are not events, a line longer than any event, and log lines
// before the companion listens do not stop a start.
func TestStartToleratesNoiseOnStderr(t *testing.T) {
	f := newFake(t, "noisy-start")
	s, err := f.Start(context.Background(), vectorSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	s.Stop()
	if end := s.Exit(); end.Reason != ReasonStdinClosed {
		t.Errorf("end = %+v", end)
	}
}

// A companion that does not see its stdin close is asked with a termination
// signal, and ends in order: it says why. That is the state of a companion
// whose client takes no data, with bytes waiting in front of the end of its
// stdin.
func TestStopSignalsACompanionThatDoesNotSeeItsStdinClose(t *testing.T) {
	f := newFake(t, "needs-a-signal")
	f.StopGrace = 300 * time.Millisecond
	f.KillGrace = 30 * time.Second
	s, err := f.Start(context.Background(), vectorSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	began := time.Now()
	s.Stop()
	if elapsed := time.Since(began); elapsed < 250*time.Millisecond {
		t.Errorf("Stop took %v: the signal came before the companion had its 300 ms to end by itself", elapsed)
	}
	if !f.gone(t) {
		t.Fatal("the companion's process is still there after Stop")
	}
	if exit := s.Exit(); exit != (Exit{Reason: ReasonTerminated, Said: true}) {
		t.Errorf("exit = %+v, want the companion's own terminated with status 0: it was signalled, not killed", exit)
	}
}

// A companion that ends neither when its stdin closes nor when it is
// signalled is killed.
func TestStopKillsACompanionThatDoesNotEnd(t *testing.T) {
	f := newFake(t, "stubborn")
	f.StopGrace = 200 * time.Millisecond
	f.KillGrace = 300 * time.Millisecond
	s, err := f.Start(context.Background(), vectorSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	began := time.Now()
	s.Stop()
	if elapsed := time.Since(began); elapsed < 450*time.Millisecond {
		t.Errorf("Stop took %v with 200 ms to end by itself and 300 ms more after the signal", elapsed)
	}
	if !f.gone(t) {
		t.Fatal("the companion's process is still there after Stop")
	}
	if exit := s.Exit(); exit != (Exit{Reason: ExitKilled, Code: -1}) {
		t.Errorf("exit = %+v, want killed", exit)
	}
	s.Stop() // again: nothing to do
}

func TestTheCompanionEndingEndsTheSession(t *testing.T) {
	t.Run("the client leaves", func(t *testing.T) {
		f := newFake(t, "client-leaves")
		s, err := f.Start(context.Background(), vectorSpec())
		if err != nil {
			t.Fatalf("Start: %v", err)
		}
		defer s.Stop()
		waitClosed(t, "the companion ending", s.Done())
		if end := s.Exit(); end != (Exit{Reason: ReasonPeerClosed, Said: true}) {
			t.Errorf("end = %+v, want the companion's own peer_closed", end)
		}
		_ = s.FromPeer.SetReadDeadline(time.Now().Add(5 * time.Second))
		rest, err := io.ReadAll(s.FromPeer)
		if err != nil || string(rest) != "last bytes" {
			t.Errorf("read %q, %v; want the last bytes and then the end of the stream", rest, err)
		}
		select {
		case <-s.Connected():
		default:
			t.Error("Connected is not closed for a session whose client came and left")
		}
	})

	t.Run("it dies without a word", func(t *testing.T) {
		f := newFake(t, "dies-quietly")
		s, err := f.Start(context.Background(), vectorSpec())
		if err != nil {
			t.Fatalf("Start: %v", err)
		}
		defer s.Stop()
		waitClosed(t, "the companion ending", s.Done())
		if end := s.Exit(); end != (Exit{Reason: ExitUnexplained}) {
			t.Errorf("end = %+v, want exited with nothing said", end)
		}
	})

	t.Run("it crashes", func(t *testing.T) {
		f := newFake(t, "dies-loudly")
		s, err := f.Start(context.Background(), vectorSpec())
		if err != nil {
			t.Fatalf("Start: %v", err)
		}
		defer s.Stop()
		waitClosed(t, "the companion ending", s.Done())
		end := s.Exit()
		if end.Reason != ExitUnexplained || end.Said || end.Code != 2 || !strings.Contains(end.Detail, "fatal error: something broke") {
			t.Errorf("end = %+v, want exited with status 2 and what it wrote", end)
		}
	})
}

// Every event the companion can send while a session runs reaches OnEvent in
// order, except its log lines.
func TestSessionEventsReachTheCaller(t *testing.T) {
	f := newFake(t, "every-event")
	var mu sync.Mutex
	var events []Event
	spec := vectorSpec()
	spec.OnEvent = func(e Event) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, e)
	}
	s, err := f.Start(context.Background(), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitClosed(t, "the client connecting", s.Connected())
	s.Stop()

	mu.Lock()
	defer mu.Unlock()
	want := []Event{
		{Event: "relay", State: "lost"},
		{Event: "relay", State: "lost", Reason: "relay_refused"},
		{Event: "relay", State: "connected"},
		{Event: "refused", Reason: "unknown_peer", Peer: "0a1b2c3d", Count: 3},
		{Event: "connected"},
		{Event: "path", Path: "relayed"},
	}
	if fmt.Sprint(events) != fmt.Sprint(want) {
		t.Errorf("events = %+v\nwant     %+v", events, want)
	}
	if s.Path() != PathRelayed {
		t.Errorf("path = %q", s.Path())
	}
}

// The companion is started with one thing in its environment (the Go
// runtime's crash reports turned off, which only the environment can do), no
// arguments and the root directory as its own: what it needs comes on its
// stdin.
func TestTheCompanionIsStartedWithNothingButItsPipes(t *testing.T) {
	t.Setenv("TS_DEBUG_ALWAYS_USE_DERP", "1")
	t.Setenv("NDAGENT_SECRET_OF_THE_AGENT", "x")
	f := newFake(t, "reports-itself")
	s, err := f.Start(context.Background(), vectorSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	s.Stop()

	var env []string
	for _, line := range f.seen(t) {
		if name, ok := strings.CutPrefix(line, "env="); ok {
			env = append(env, name)
		}
	}
	if fmt.Sprint(env) != fmt.Sprint([]string{"GOTRACEBACK", fakeScenarioEnv, fakeOutEnv, "GORACE"}) {
		t.Errorf("the companion's environment holds %v, want GOTRACEBACK and what this test added", env)
	}
	if level, _ := f.seenValue(t, "gotraceback"); level != "none" {
		t.Errorf("GOTRACEBACK = %q in the companion, want none: its crash report would show the session's keys", level)
	}
	if cwd, _ := f.seenValue(t, "cwd"); cwd != "/" {
		t.Errorf("the companion's directory is %q, want /", cwd)
	}
	if args, _ := f.seenValue(t, "args"); args != "1" {
		t.Errorf("the companion was started with %s arguments, want its name alone", args)
	}
}

func TestCredentialForNeverRunsTheCompanionAsRoot(t *testing.T) {
	users := map[string]*user.User{
		"nobody":   {Uid: "65534", Gid: "65534"},
		"root":     {Uid: "0", Gid: "0"},
		"operator": {Uid: "2", Gid: "0"},
		"broken":   {Uid: "x", Gid: "5"},
		"broken2":  {Uid: "5", Gid: "y"},
	}
	lookup := func(name string) (*user.User, error) {
		if u, ok := users[name]; ok {
			return u, nil
		}
		return nil, user.UnknownUserError(name)
	}

	cred, err := credentialFor("nobody", 0, lookup)
	if err != nil {
		t.Fatalf("nobody: %v", err)
	}
	if cred.Uid != 65534 || cred.Gid != 65534 || len(cred.Groups) != 1 || cred.Groups[0] != 65534 || cred.NoSetGroups {
		t.Errorf("credential = %+v, want user and group 65534 and no other group", cred)
	}

	for _, name := range []string{"root", "operator", "broken", "broken2", "nosuchuser"} {
		if cred, err := credentialFor(name, 0, lookup); err == nil {
			t.Errorf("%s: credential %+v, want an error: a root agent must not start the companion under it", name, cred)
		}
	}

	// An agent that is not root cannot change user: the companion runs as
	// the agent does, whoever was asked for.
	for _, name := range []string{"nobody", "root", "nosuchuser"} {
		if cred, err := credentialFor(name, 501, lookup); cred != nil || err != nil {
			t.Errorf("not root, %s: %+v, %v; want no credential and no error", name, cred, err)
		}
	}
}

func TestARootAgentStartsTheCompanionAsTheUnprivilegedUser(t *testing.T) {
	st := NewStarter(fakeVersion)
	st.euid = func() int { return 0 }
	st.lookupUser = func(name string) (*user.User, error) {
		if name != "nobody" {
			t.Errorf("looked up %q, want nobody", name)
		}
		return &user.User{Uid: "65534", Gid: "65534"}, nil
	}
	attr, err := st.sysProcAttr()
	if err != nil {
		t.Fatal(err)
	}
	if attr.Credential == nil || attr.Credential.Uid != 65534 {
		t.Errorf("credential = %+v", attr.Credential)
	}
	if !attr.Setsid {
		t.Error("the companion shares the agent's session")
	}

	// A device without that user: no companion, and the error says why.
	st.lookupUser = func(name string) (*user.User, error) { return nil, user.UnknownUserError(name) }
	st.Path, _ = os.Executable()
	s, err := st.Start(context.Background(), vectorSpec())
	if s != nil {
		s.Stop()
		t.Fatal("a session was started")
	}
	if startErr := startError(t, err); startErr.Reason != FailCompanionFailed || !strings.Contains(startErr.Error(), "without privileges") {
		t.Errorf("error = %q %q", startErr.Reason, startErr.Error())
	}
}

// The agent's side of the exchange against the shared vectors: the
// configuration it writes, byte for byte, and every event line read.
func TestConfigurationMessageIsTheSharedVector(t *testing.T) {
	want, err := os.ReadFile("testdata/ipc/config.json")
	if err != nil {
		t.Fatal(err)
	}
	st := NewStarter(fakeVersion)
	cfg := st.config(vectorSpec())
	message, err := cfg.encode()
	if err != nil {
		t.Fatal(err)
	}
	if size := binary.BigEndian.Uint32(message[:4]); int(size) != len(want) {
		t.Errorf("length prefix = %d, want %d", size, len(want))
	}
	if !bytes.Equal(message[4:], want) {
		t.Errorf("message =\n%s\nwant the shared vector\n%s", message[4:], want)
	}

	printed := fmt.Sprintf("%v %+v %#v %s %x", *cfg, *cfg, *cfg, cfg.NodeKey, cfg.PSK)
	for _, secret := range []string{"QEBAQEBA", "AwMDAwMD", strings.Repeat("40", 8), strings.Repeat("03", 8), "64 64 64", "@@@@"} {
		if strings.Contains(printed, secret) {
			t.Errorf("a printed configuration shows key material (%q)", secret)
		}
	}

	st.Debug = true
	spec := vectorSpec()
	spec.Relay.Port, spec.Relay.STUNPort = 8443, 3479
	other := st.config(spec)
	if !other.Debug || other.Relay.Port != 8443 || other.Relay.STUNPort != 3479 {
		t.Errorf("debug and the relay's own ports are not passed on: %+v", other.Relay)
	}
}

func TestEveryEventOfTheSharedVectorsIsRead(t *testing.T) {
	data, err := os.ReadFile("testdata/ipc/events.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	want := []Event{
		{Event: "hello", Version: "1.2.3", Commit: "abc1234", Protocol: 1, IPC: 1},
		{Event: "listening"},
		{Event: "connected"},
		{Event: "path", Path: "relayed"},
		{Event: "path", Path: "direct"},
		{Event: "relay", State: "lost"},
		{Event: "relay", State: "lost", Reason: "relay_refused"},
		{Event: "relay", State: "lost", Reason: "relay_unreachable", Detail: "dial tcp4 203.0.113.5:443: connect: connection refused"},
		{Event: "relay", State: "connected"},
		{Event: "refused", Reason: "unknown_peer", Peer: "0a1b2c3d", Count: 3},
		{Event: "closed", Reason: "peer_closed"},
		{Event: "closed", Reason: "stdin_closed"},
		{Event: "closed", Reason: "connection_lost"},
		{Event: "closed", Reason: "stdout_closed"},
		{Event: "closed", Reason: "terminated"},
		{Event: "error", Reason: "bad_config", Detail: "psk: missing"},
		{Event: "error", Reason: "no_config", Detail: "no configuration"},
		{Event: "error", Reason: "relay_refused"},
		{Event: "error", Reason: "relay_unreachable", Detail: "lookup relay-us.example.net: no such host"},
		{Event: "error", Reason: "start_failed"},
		{Event: "error", Reason: "internal", Detail: "panic: boom in run.Run (run.go:1)"},
		{Event: "log", Msg: "a library log line"},
	}
	lines := bytes.Split(bytes.TrimSuffix(data, []byte("\n")), []byte("\n"))
	if len(lines) != len(want) {
		t.Fatalf("%d vector lines, %d expected here: a line added to the vectors needs its reading spelled out", len(lines), len(want))
	}
	for i, line := range lines {
		got, ok := parseEvent(line)
		if !ok || got != want[i] {
			t.Errorf("line %d %s: read as %+v (%v), want %+v", i+1, line, got, ok, want[i])
		}
	}

	for _, notAnEvent := range []string{"", "panic: boom", "{}", `{"event":""}`, `{"reason":"x"}`, "[1]", `"hello"`} {
		if e, ok := parseEvent([]byte(notAnEvent)); ok {
			t.Errorf("%q read as the event %+v", notAnEvent, e)
		}
	}

	// The names this package gives the companion's words are the vectors'.
	all := string(data)
	for _, word := range []string{
		EventHello, EventListening, EventConnected, EventPath, EventRelay, EventRefused, EventClosed, EventError, EventLog,
		PathDirect, PathRelayed, RelayConnected, RelayLost,
		ReasonStdinClosed, ReasonPeerClosed, ReasonConnectionLost, ReasonStdoutClosed, ReasonTerminated,
		ReasonBadConfig, ReasonNoConfig, ReasonRelayRefused, ReasonRelayUnreachable, ReasonStartFailed, ReasonInternal, ReasonUnknownPeer,
	} {
		if !strings.Contains(all, `"`+word+`"`) {
			t.Errorf("%q is in none of the vectors", word)
		}
	}
}

// What the other end of a session, the package and the control plane rely on,
// spelled out.
func TestTheNumbersOthersRelyOn(t *testing.T) {
	if Protocol != 1 || ServedPort != 1 || RelayRegionID != 900 || DefaultRelayPort != 443 || DefaultRelaySTUNPort != 3478 {
		t.Errorf("protocol %d, port %d, region %d, relay ports %d and %d", Protocol, ServedPort, RelayRegionID, DefaultRelayPort, DefaultRelaySTUNPort)
	}
	if DefaultCompanionPath != "/usr/local/libexec/ndagent-connect" || DefaultRunAs != "nobody" {
		t.Errorf("companion %q as %q", DefaultCompanionPath, DefaultRunAs)
	}
	if ipcVersion != 1 || companionRole != "server" || companionStartTimeoutMS != 8000 {
		t.Errorf("exchange %d, role %q, companion wait %d ms", ipcVersion, companionRole, companionStartTimeoutMS)
	}
	if companionEnv != "GOTRACEBACK=none" {
		t.Errorf("the companion's environment is %q, want GOTRACEBACK=none", companionEnv)
	}
	st := NewStarter("1.2.3")
	if st.Path != DefaultCompanionPath || st.RunAs != "nobody" || st.Version != "1.2.3" || st.Debug {
		t.Errorf("starter = %+v", st)
	}
	if st.HelloTimeout != 5*time.Second || st.ListenTimeout != 10*time.Second || st.StopGrace != 5*time.Second || st.KillGrace != 4*time.Second {
		t.Errorf("waits: hello %v, listening %v, stop %v, kill %v; want 5s, 10s, 5s, 4s", st.HelloTimeout, st.ListenTimeout, st.StopGrace, st.KillGrace)
	}
	if MaxDeviceSessions != 8 {
		t.Errorf("the agent's own maximum of sessions = %d, want 8", MaxDeviceSessions)
	}
	want := Limits{Pairing: 5 * time.Minute, Idle: 30 * time.Minute, Lifetime: 8 * time.Hour}
	if MaxLimits != want {
		t.Errorf("the agent's own limits = %+v, want %+v", MaxLimits, want)
	}
}

// The reasons the device gives, the paths it names and the limits of the
// contract's example are the contract's, read from its vector.
func TestReasonsAndLimitsAreTheContracts(t *testing.T) {
	vector := loadContractVector(t)
	if fmt.Sprint(FailureReasons) != fmt.Sprint(vector.Lists.FailureReasons) {
		t.Errorf("failure reasons = %v\nthe contract's = %v", FailureReasons, vector.Lists.FailureReasons)
	}
	if fmt.Sprint(EndReasons) != fmt.Sprint(vector.Lists.EndReasons) {
		t.Errorf("end reasons = %v\nthe contract's = %v", EndReasons, vector.Lists.EndReasons)
	}
	if fmt.Sprint(SessionPaths) != fmt.Sprint(vector.Lists.Paths) {
		t.Errorf("paths = %v\nthe contract's = %v", SessionPaths, vector.Lists.Paths)
	}

	open := vector.Payloads.Open
	if open.Protocol != Protocol {
		t.Errorf("the contract's example asks for protocol %d, this build is %d", open.Protocol, Protocol)
	}
	limits, ok := LimitsFor(open.Limits.PairSeconds, open.Limits.IdleSeconds, open.Limits.MaxSeconds)
	if !ok || limits != MaxLimits {
		t.Errorf("the contract's limits give %+v (%v), want the agent's own %+v", limits, ok, MaxLimits)
	}
	if open.Limits.DeviceSessions != 4 {
		t.Errorf("the contract's example allows %d sessions on a device", open.Limits.DeviceSessions)
	}

	// The session the contract's example describes is one the companion is
	// given as it stands: its relay, and its clamped server key.
	st := NewStarter(fakeVersion)
	cfg := st.config(Spec{
		Relay: Relay{ID: open.Relay.ID, Host: open.Relay.Hostname, Port: open.Relay.DERPPort, STUNPort: open.Relay.STUNPort},
		Keys: Keys{
			Node: hex32(t, vector.SessionKeys.ServerNodePrivateHex),
			Peer: hex32(t, vector.SessionKeys.ClientNodePublicHex),
			PSK:  hex32(t, vector.SessionKeys.PresharedKeyHex),
		},
	})
	if cfg.Relay != (relayConfig{ID: "eu", RegionID: 900, Host: "relay-eu.example.net", Port: 443, STUNPort: 3478}) || cfg.Port != 1 {
		t.Errorf("configuration for the contract's example: relay %+v, port %d", cfg.Relay, cfg.Port)
	}
	unclamped := Spec{
		Relay: Relay{ID: "eu", Host: "relay-eu.example.net"},
		Keys: Keys{
			Node: hex32(t, vector.SessionKeys.ServerNodeKeyHKDFOutputHex),
			Peer: hex32(t, vector.SessionKeys.ClientNodePublicHex),
			PSK:  hex32(t, vector.SessionKeys.PresharedKeyHex),
		},
	}
	if err := unclamped.validate(); err == nil {
		t.Error("the contract's key before clamping is accepted as a node key")
	}
}

// The companion is checked before the session's secret is opened, and is
// given the session only afterwards: between the two it holds nothing.
func TestLaunchChecksTheCompanionBeforeAnythingIsHandedOver(t *testing.T) {
	t.Run("abort", func(t *testing.T) {
		f := newFake(t, "ok")
		p, err := f.Launch(context.Background())
		if err != nil {
			t.Fatalf("Launch: %v", err)
		}
		if _, given := f.seenValue(t, "config"); given {
			t.Error("the companion was given a session by Launch")
		}
		p.Abort()
		p.Abort()
		if !f.gone(t) {
			t.Error("the companion's process is still there after Abort")
		}
		if _, given := f.seenValue(t, "config"); given {
			t.Error("the companion was given a session")
		}
		s, err := p.Open(context.Background(), vectorSpec())
		if s != nil {
			s.Stop()
			t.Fatal("a session was opened on a companion that was aborted")
		}
		if startErr := startError(t, err); startErr.Reason != FailInternal {
			t.Errorf("reason = %q, want %q", startErr.Reason, FailInternal)
		}
	})

	t.Run("open", func(t *testing.T) {
		f := newFake(t, "ok")
		p, err := f.Launch(context.Background())
		if err != nil {
			t.Fatalf("Launch: %v", err)
		}
		before := time.Now()
		s, err := p.Open(context.Background(), vectorSpec())
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer s.Stop()
		if s.ListeningAt.Before(before) || s.ListeningAt.After(time.Now()) {
			t.Errorf("ListeningAt = %v, want the moment Open returned", s.ListeningAt)
		}
		if at, ok := s.ConnectedAt(); ok && at.Before(s.ListeningAt) {
			t.Errorf("ConnectedAt = %v, before the companion listened", at)
		}
		waitClosed(t, "the client connecting", s.Connected())
		at, ok := s.ConnectedAt()
		if !ok || at.Before(s.ListeningAt) || at.After(time.Now()) {
			t.Errorf("ConnectedAt = %v, %v", at, ok)
		}

		p.Abort() // the session owns the companion now: nothing happens
		select {
		case <-s.Done():
			t.Fatal("Abort after Open ended the session")
		case <-time.After(100 * time.Millisecond):
		}
		if again, err := p.Open(context.Background(), vectorSpec()); again != nil || err == nil {
			t.Error("a companion was given a second session")
		}
	})

	t.Run("a session with something missing ends the companion", func(t *testing.T) {
		f := newFake(t, "ok")
		p, err := f.Launch(context.Background())
		if err != nil {
			t.Fatalf("Launch: %v", err)
		}
		spec := vectorSpec()
		spec.Keys.PSK = [32]byte{}
		s, err := p.Open(context.Background(), spec)
		if s != nil {
			s.Stop()
			t.Fatal("a session was opened")
		}
		if startErr := startError(t, err); startErr.Reason != FailInternal {
			t.Errorf("reason = %q, want %q", startErr.Reason, FailInternal)
		}
		if !f.gone(t) {
			t.Error("the companion's process is still there")
		}
		if _, given := f.seenValue(t, "config"); given {
			t.Error("the companion was given the session")
		}
	})
}

// startRaw starts the program at path on pipes and returns its events and a
// function that waits for it to end.
func startRaw(t *testing.T, path string, p *pipes) (<-chan Event, func()) {
	t.Helper()
	cmd := exec.Command(path)
	cmd.Env = []string{companionEnv}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = p.stdinR, p.stdoutW, p.stderrW
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p.closeChildEnds()
	events := make(chan Event, 16)
	go readEvents(p.stderrR, events, &diagnostics{})
	return events, func() {
		_ = p.stdinW.Close()
		for range events {
		}
		_ = cmd.Wait()
	}
}

// What the companion reports about the session in the instant before it says
// it listens (a client knocking, the relay dropping) is not a failed start,
// and is not lost: it comes first among the session's events.
func TestEventsBeforeListeningDoNotFailTheStart(t *testing.T) {
	f := newFake(t, "early-events")
	var mu sync.Mutex
	var events []Event
	spec := vectorSpec()
	spec.OnEvent = func(e Event) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, e)
	}
	s, err := f.Start(context.Background(), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitClosed(t, "the client connecting", s.Connected())
	s.Stop()

	want := []Event{
		{Event: "refused", Reason: "unknown_peer", Peer: "aaaaaaaa", Count: 1},
		{Event: "relay", State: "lost"},
		{Event: "path", Path: "relayed"},
		{Event: "connected"},
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		got := fmt.Sprint(events)
		mu.Unlock()
		if got == fmt.Sprint(want) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("events = %s\nwant     %v", got, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if s.Path() != PathRelayed {
		t.Errorf("path = %q, want what was said before listening", s.Path())
	}
}

// Nothing follows the companion's last word: what it writes after closed
// reaches nobody, and does not change why it ended.
func TestNothingFollowsTheCompanionsLastWord(t *testing.T) {
	f := newFake(t, "talks-after-closed")
	var mu sync.Mutex
	var events []Event
	spec := vectorSpec()
	spec.OnEvent = func(e Event) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, e)
	}
	s, err := f.Start(context.Background(), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Stop()
	waitClosed(t, "the companion ending", s.Done())
	if exit := s.Exit(); exit != (Exit{Reason: ReasonPeerClosed, Said: true}) {
		t.Errorf("exit = %+v, want its first last word, peer_closed", exit)
	}
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if fmt.Sprint(events) != fmt.Sprint([]Event{{Event: "connected"}}) {
		t.Errorf("events = %+v, want the connection and nothing said after closed", events)
	}
}

// A companion that dies writes a crash report, and the Go runtime prints the
// first words of every call's arguments in it. Those are the session's keys.
// Whatever the companion wrote, no number of it reaches the agent's log.
func TestACrashReportNeverShowsNumbers(t *testing.T) {
	f := newFake(t, "crashes-with-a-trace")
	s, err := f.Start(context.Background(), vectorSpec())
	if s != nil {
		s.Stop()
		t.Fatal("a session was started")
	}
	startErr := startError(t, err)
	if startErr.Reason != FailCompanionFailed {
		t.Errorf("reason = %q, want %q", startErr.Reason, FailCompanionFailed)
	}
	for _, kept := range []string{"panic: boom", "goroutine 1 [running]:", "internal/tunnel.Start(", "server.go:191"} {
		if !strings.Contains(startErr.Detail, kept) {
			t.Errorf("detail = %q, want it to keep %q: what happened and where", startErr.Detail, kept)
		}
	}
	for _, number := range []string{"0xa8", "0xa1", "0x1054f8e68", "a8a1a2a3", "0x"} {
		if strings.Contains(startErr.Detail, number) || strings.Contains(startErr.Error(), number) {
			t.Errorf("detail = %q shows %q", startErr.Detail, number)
		}
	}

	d := &diagnostics{}
	for line, want := range map[string]string{
		"main.f({0xa8, 0xa1, 0xa2}, 0x1400012c000)":         "main.f({…, …, …}, …)",
		"key=A8A1A2A3A4A5A6A7A8A9AAABACADAEAF and 0XFF":     "key=… and …",
		"/build/main.go:12 +0x1d":                           "/build/main.go:12 +…",
		"panic: runtime error: index out of range [5]":      "panic: runtime error: index out of range [5]",
		"exit status 2, fifteen hex digits abcdef012345678": "exit status 2, fifteen hex digits abcdef012345678",
	} {
		d.lines = nil
		d.add([]byte(line))
		if got := d.String(); got != want {
			t.Errorf("diagnostics of %q = %q, want %q", line, got, want)
		}
	}
}

// A callback that never returns holds back the callbacks after it, and
// nothing else: the session is still followed to its end, and Stop returns.
func TestABlockedCallbackDoesNotHoldTheSession(t *testing.T) {
	f := newFake(t, "every-event")
	release := make(chan struct{})
	defer close(release)
	called := make(chan struct{}, 16)
	spec := vectorSpec()
	spec.OnEvent = func(Event) {
		called <- struct{}{}
		<-release
	}
	s, err := f.Start(context.Background(), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	select {
	case <-called:
	case <-time.After(5 * time.Second):
		t.Fatal("OnEvent was not called")
	}
	waitClosed(t, "the client connecting, behind a callback that never returned", s.Connected())

	stopped := make(chan struct{})
	go func() {
		s.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("Stop did not return while a callback was blocked")
	}
	if exit := s.Exit(); exit != (Exit{Reason: ReasonStdinClosed, Said: true}) {
		t.Errorf("exit = %+v", exit)
	}
}

// With debug on, the tunnel library's lines from before the companion
// listens reach the agent's debug log too: they are what explains a start
// that failed.
func TestDebugLinesFromBeforeListeningAreLogged(t *testing.T) {
	core, logs := observer.New(zap.DebugLevel)
	restore := logging.SetForTest(zap.New(core))
	defer restore()

	f := newFake(t, "noisy-start")
	s, err := f.Start(context.Background(), vectorSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	s.Stop()

	var lines []string
	for _, entry := range logs.FilterMessage("Direct-peer companion").All() {
		if entry.Level != zap.DebugLevel {
			t.Errorf("a companion log line at level %v, want debug", entry.Level)
		}
		lines = append(lines, entry.ContextMap()["line"].(string))
	}
	if fmt.Sprint(lines) != fmt.Sprint([]string{"a library log line", "another library log line"}) {
		t.Errorf("logged lines = %q, want the two the companion wrote before it listened", lines)
	}
}
