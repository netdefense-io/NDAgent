package directpeer

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These tests run the agent's side against the companion itself, built from
// connect/ with another Go release than this module's:
//
//	make build-connect
//	NDAGENT_CONNECT_BIN=$PWD/bin/ndagent-connect NDAGENT_CONNECT_VERSION=$(cat VERSION) go test -run RealCompanion ./internal/directpeer/
//
// Without the two variables they are skipped. The companion reaches no relay
// here, so they cover what happens up to that point: the two builds know each
// other, and the companion takes the configuration the agent writes.
func realCompanion(t *testing.T) *Starter {
	t.Helper()
	path, version := os.Getenv("NDAGENT_CONNECT_BIN"), os.Getenv("NDAGENT_CONNECT_VERSION")
	if path == "" || version == "" {
		t.Skip("NDAGENT_CONNECT_BIN and NDAGENT_CONNECT_VERSION are not set: no companion to test against")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	st := NewStarter(version)
	st.Path = abs
	return st
}

func unusedLoopbackPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// The companion accepts the agent's hello check and its configuration, tries
// the relay it was given, and its report of a relay that is not there comes
// back as the agent's own error.
func TestRealCompanionTakesTheAgentsConfiguration(t *testing.T) {
	st := realCompanion(t)
	spec := vectorSpec()
	spec.Relay = Relay{ID: "test", Host: "127.0.0.1", Port: unusedLoopbackPort(t), STUNPort: unusedLoopbackPort(t)}

	began := time.Now()
	s, err := st.Start(context.Background(), spec)
	if s != nil {
		s.Stop()
		t.Fatal("a session was started with no relay")
	}
	startErr := startError(t, err)
	if startErr.Reason != FailRelayUnreachable {
		t.Fatalf("reason = %q (%s; detail %q), want %q: the companion did not get as far as the relay", startErr.Reason, startErr.Error(), startErr.Detail, FailRelayUnreachable)
	}
	if startErr.Error() != "the relay could not be reached" || !strings.Contains(startErr.Detail, "connection refused") {
		t.Errorf("message = %q, detail = %q; want the fixed message and the dial error as detail", startErr.Error(), startErr.Detail)
	}
	// The companion's own wait for the relay (8 s) ends inside the agent's
	// wait for it to listen (10 s), so the reason is the companion's.
	if elapsed := time.Since(began); elapsed > 9900*time.Millisecond {
		t.Errorf("Start took %v: the agent's own wait ended first", elapsed)
	}
}

func TestRealCompanionOfAnotherVersionIsRefused(t *testing.T) {
	st := realCompanion(t)
	companionVersion := st.Version
	st.Version = companionVersion + "-other"
	s, err := st.Start(context.Background(), vectorSpec())
	if s != nil {
		s.Stop()
		t.Fatal("a session was started")
	}
	startErr := startError(t, err)
	if startErr.Reason != FailCompanionUnavailable || !strings.Contains(startErr.Error(), "version "+companionVersion+" and the agent is version "+st.Version) {
		t.Errorf("error = %q %q", startErr.Reason, startErr.Error())
	}
}

// A companion that refuses the session says which field, and the agent passes
// that on: here a served port of 0, which Start never sends.
func TestRealCompanionRefusalNamesTheField(t *testing.T) {
	st := realCompanion(t)
	cfg := st.config(vectorSpec())
	cfg.Port = 0

	pipes, err := newPipes()
	if err != nil {
		t.Fatal(err)
	}
	defer pipes.closeParentEnds()
	// Drive the exchange by hand to send what Start never would.
	events, wait := startRaw(t, st.Path, pipes)
	if hello := <-events; hello.Event != EventHello {
		t.Fatalf("first event %+v", hello)
	}
	if err := writeConfig(pipes.stdinW, cfg); err != nil {
		t.Fatal(err)
	}
	e := <-events
	if e.Event != EventError || e.Reason != ReasonBadConfig || !strings.Contains(e.Detail, "port") {
		t.Errorf("event = %+v, want error bad_config naming the port", e)
	}
	if got := startErrorFor(e); got.Reason != FailInternal || !strings.Contains(got.Error(), "port") {
		t.Errorf("as the agent's error: %q %q", got.Reason, got.Error())
	}
	wait()
}
