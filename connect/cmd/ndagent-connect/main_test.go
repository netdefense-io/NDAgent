package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// These tests run the companion as the agent does: the binary itself, built
// with the release tags and a version stamped in, driven over its pipes.

var companionPath string

// panicHelperEnv makes the test binary panic at once, inside a call that
// carries a key in its arguments: the Go runtime's own behaviour, which the
// companion's handling of its keys relies on.
const panicHelperEnv = "NDAGENT_CONNECT_TEST_PANIC"

//go:noinline
func panicWithKeyOnTheStack(key [32]byte) {
	if key[0] != 0 {
		panic("boom")
	}
}

func TestMain(m *testing.M) {
	if os.Getenv(panicHelperEnv) != "" {
		var key [32]byte
		for i := range key {
			key[i] = 0xa0 + byte(i)
		}
		panicWithKeyOnTheStack(key)
		return
	}
	dir, err := os.MkdirTemp("", "ndagent-connect-test")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	tags, err := os.ReadFile("../../build-tags.txt")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	companionPath = filepath.Join(dir, "ndagent-connect")
	build := exec.Command("go", "build", "-trimpath",
		"-tags", strings.TrimSpace(string(tags)),
		"-ldflags", "-s -w -X main.version=7.7.7 -X main.commit=abc1234",
		"-o", companionPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "building the companion: %v\n%s", err, out)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type event map[string]any

// agentEnv is the whole environment ndagent starts the companion in.
func agentEnv() []string { return []string{"GOTRACEBACK=none"} }

// run starts the companion with an empty environment and returns it with its
// stdin open.
type process struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout bytes.Buffer
	lines  *bufio.Scanner
}

func start(t *testing.T, args ...string) *process {
	t.Helper()
	p := &process{cmd: exec.Command(companionPath, args...)}
	p.cmd.Env = agentEnv()
	p.cmd.Stdout = &p.stdout
	stdin, err := p.cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	p.stdin = stdin
	stderr, err := p.cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	p.lines = bufio.NewScanner(stderr)
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = p.cmd.Process.Kill()
		_, _ = p.cmd.Process.Wait()
	})
	return p
}

// next reads the next stderr line, which must be one JSON event.
func (p *process) next(t *testing.T) event {
	t.Helper()
	type result struct {
		line string
		ok   bool
	}
	got := make(chan result, 1)
	go func() {
		ok := p.lines.Scan()
		got <- result{p.lines.Text(), ok}
	}()
	select {
	case r := <-got:
		if !r.ok {
			t.Fatal("stderr ended")
		}
		var e event
		if err := json.Unmarshal([]byte(r.line), &e); err != nil {
			t.Fatalf("stderr line %q is not an event: %v", r.line, err)
		}
		return e
	case <-time.After(15 * time.Second):
		t.Fatal("no event within 15 s")
		return nil
	}
}

// end waits for the process and returns its exit status.
func (p *process) end(t *testing.T) int {
	t.Helper()
	for p.lines.Scan() {
		t.Errorf("stderr line after the last event: %q", p.lines.Text())
	}
	done := make(chan error, 1)
	go func() { done <- p.cmd.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			return 0
		}
		if exit, ok := err.(*exec.ExitError); ok && exit.Exited() {
			return exit.ExitCode()
		}
		t.Fatalf("the companion ended abnormally: %v", err)
	case <-time.After(15 * time.Second):
		t.Fatal("the companion did not exit")
	}
	return -1
}

func wantHello(t *testing.T, e event) {
	t.Helper()
	want := event{"event": "hello", "version": "7.7.7", "commit": "abc1234", "protocol": float64(1), "ipc": float64(1)}
	if fmt.Sprint(e) != fmt.Sprint(want) {
		t.Errorf("first event = %v, want %v", e, want)
	}
}

func TestVersionFlag(t *testing.T) {
	cmd := exec.Command(companionPath, "--version")
	cmd.Env = []string{}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("--version: %v", err)
	}
	if stdout.String() != "ndagent-connect 7.7.7 (protocol 1)\n" || stderr.Len() != 0 {
		t.Errorf("stdout %q, stderr %q", stdout.String(), stderr.String())
	}
}

func TestAnyOtherArgumentIsRefused(t *testing.T) {
	for _, args := range [][]string{{"serve"}, {"--version", "x"}, {"--key=abc"}} {
		cmd := exec.Command(companionPath, args...)
		cmd.Env = []string{}
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		exit, ok := err.(*exec.ExitError)
		if !ok || exit.ExitCode() != 2 {
			t.Errorf("%v: %v, want exit status 2", args, err)
		}
		if stdout.Len() != 0 || !strings.HasPrefix(stderr.String(), "usage: ndagent-connect") {
			t.Errorf("%v: stdout %q, stderr %q", args, stdout.String(), stderr.String())
		}
	}
}

// With nothing in its environment and nothing on its stdin, the companion
// says who it is and that it was given no configuration, and nothing else on
// either stream.
func TestHelloThenNoConfiguration(t *testing.T) {
	p := start(t)
	wantHello(t, p.next(t))
	p.stdin.Close()
	if e := p.next(t); e["event"] != "error" || e["reason"] != "no_config" {
		t.Errorf("event = %v, want error no_config", e)
	}
	if code := p.end(t); code != 1 {
		t.Errorf("exit status %d, want 1", code)
	}
	if p.stdout.Len() != 0 {
		t.Errorf("stdout = %q, want nothing", p.stdout.String())
	}
}

func unusedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func configMessage(t *testing.T, relayPort, stunPort int) []byte {
	t.Helper()
	key := func(b byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)) }
	body, err := json.Marshal(map[string]any{
		"v": 1, "role": "server", "protocol": 1,
		"relay":    map[string]any{"id": "test", "region_id": 900, "host": "127.0.0.1", "port": relayPort, "stun_port": stunPort},
		"port":     1,
		"node_key": key(0x40),
		"peer_key": key(0x02),
		"psk":      key(0x03),
	})
	if err != nil {
		t.Fatal(err)
	}
	var head [4]byte
	binary.BigEndian.PutUint32(head[:], uint32(len(body)))
	return append(head[:], body...)
}

// The real binary, the relay description it builds for itself and a relay
// that is not there: one error event with the reason, in the operating
// system's words, and nothing on stdout.
func TestARelayThatIsNotThere(t *testing.T) {
	p := start(t)
	wantHello(t, p.next(t))
	if _, err := p.stdin.Write(configMessage(t, unusedPort(t), unusedPort(t))); err != nil {
		t.Fatal(err)
	}
	e := p.next(t) // after the companion's own wait of 8 s
	if e["event"] != "error" || e["reason"] != "relay_unreachable" {
		t.Fatalf("event = %v, want error relay_unreachable", e)
	}
	if detail, _ := e["detail"].(string); !strings.Contains(detail, "connection refused") {
		t.Errorf("detail = %q, want the dial error", detail)
	}
	p.stdin.Close()
	if code := p.end(t); code != 1 {
		t.Errorf("exit status %d, want 1", code)
	}
	if p.stdout.Len() != 0 {
		t.Errorf("stdout = %q, want nothing", p.stdout.String())
	}
}

// A termination signal ends the companion whatever it is waiting for, here
// its configuration, with a closed event and status 0.
func TestSIGTERMEndsTheCompanion(t *testing.T) {
	p := start(t)
	wantHello(t, p.next(t))
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if e := p.next(t); e["event"] != "closed" || e["reason"] != "terminated" {
		t.Errorf("event = %v, want closed terminated", e)
	}
	if code := p.end(t); code != 0 {
		t.Errorf("exit status %d, want 0", code)
	}
}

// Writing to a pipe whose reader is gone must not kill the companion with a
// signal, which is what the runtime does for stdout and stderr unless told
// otherwise: it would end with no reason given. Here the reader of its events
// goes away, and its next event (no configuration) has nowhere to go.
func TestAClosedPipeIsAnErrorNotASignal(t *testing.T) {
	cmd := exec.Command(companionPath)
	cmd.Env = agentEnv()
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = stderrW
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	stderrW.Close()
	hello, err := bufio.NewReader(stderrR).ReadString('\n')
	if err != nil || !strings.Contains(hello, `"event":"hello"`) {
		t.Fatalf("first line %q, %v", hello, err)
	}
	stderrR.Close()
	stdin.Close()

	err = cmd.Wait()
	exit, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("the companion ended with %v, want exit status 1", err)
	}
	if status, isUnix := exit.Sys().(syscall.WaitStatus); isUnix && status.Signaled() {
		t.Fatalf("the companion was killed by %v", status.Signal())
	}
	if exit.ExitCode() != 1 {
		t.Errorf("exit status %d, want 1 (no configuration)", exit.ExitCode())
	}
}

// The Go runtime's report of a crash lists every call on every stack with
// the first words of its arguments, and the session's keys are among them.
// Only the environment a process starts in can turn that report off, so the
// companion takes no session unless it was started that way.
func TestWithoutCrashReportsOffTheCompanionDoesNotRun(t *testing.T) {
	for name, env := range map[string][]string{
		"nothing set":     {},
		"reports for one": {"GOTRACEBACK=single"},
		"reports for all": {"GOTRACEBACK=all"},
	} {
		cmd := exec.Command(companionPath)
		cmd.Env = env
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		exit, ok := err.(*exec.ExitError)
		if !ok || exit.ExitCode() != 2 {
			t.Errorf("%s: %v, want exit status 2", name, err)
		}
		if strings.Contains(stderr.String(), `"event"`) || stdout.Len() != 0 || !strings.Contains(stderr.String(), "GOTRACEBACK=none") {
			t.Errorf("%s: stdout %q, stderr %q; want no event and the reason", name, stdout.String(), stderr.String())
		}
	}
}

// What the companion's handling of its keys relies on in the Go runtime: a
// panic's report lists the calls on the stack with the first words of their
// arguments, and GOTRACEBACK=none in the environment the process starts in
// leaves the panic's message alone. A Go release that changes either fails
// here.
func TestAPanicUnderGOTRACEBACKNoneShowsNoArguments(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	crash := func(env ...string) string {
		cmd := exec.Command(self)
		cmd.Env = append([]string{panicHelperEnv + "=1"}, env...)
		out, _ := cmd.CombinedOutput()
		return string(out)
	}

	// The control: with the report on, the key's first bytes are in it.
	loud := crash("GOTRACEBACK=single")
	if !strings.Contains(loud, "panicWithKeyOnTheStack(") || !strings.Contains(loud, "0xa0, 0xa1") {
		t.Fatalf("with crash reports on, the report does not show the key on the stack; this test shows nothing:\n%s", loud)
	}

	quiet := crash("GOTRACEBACK=none")
	if !strings.Contains(quiet, "panic: boom") {
		t.Errorf("with crash reports off, the panic's own message is gone too:\n%s", quiet)
	}
	for _, shown := range []string{"0xa0", "goroutine ", "panicWithKeyOnTheStack", ".go:"} {
		if strings.Contains(quiet, shown) {
			t.Errorf("with crash reports off, the output still holds %q:\n%s", shown, quiet)
		}
	}
}

// SIGQUIT makes the runtime print every goroutine's stack, arguments
// included, whatever GOTRACEBACK says. The companion ignores it.
func TestSIGQUITPrintsNothing(t *testing.T) {
	p := start(t)
	wantHello(t, p.next(t))
	if err := p.cmd.Process.Signal(syscall.SIGQUIT); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	// The next line is the companion's own last word, not a dump.
	if e := p.next(t); e["event"] != "closed" || e["reason"] != "terminated" {
		t.Errorf("event = %v, want closed terminated", e)
	}
	if code := p.end(t); code != 0 {
		t.Errorf("exit status %d, want 0", code)
	}
}
