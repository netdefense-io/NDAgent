package directpeer

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The stand-in companion is this test binary, started by the Starter under
// test with fakeScenarioEnv set. It speaks the companion's side of the
// exchange as the vectors in testdata/ipc spell it, so the agent's side is
// tested without the tunnel library or its Go release.
const (
	fakeScenarioEnv = "NDAGENT_FAKE_COMPANION"
	fakeVersionEnv  = "NDAGENT_FAKE_VERSION"
	// fakeOutEnv names a file where the stand-in writes what it saw: its
	// process id, then the configuration it was given.
	fakeOutEnv = "NDAGENT_FAKE_OUT"

	fakeVersion = "1.2.3"
)

func TestMain(m *testing.M) {
	if scenario := os.Getenv(fakeScenarioEnv); scenario != "" {
		fakeCompanion(scenario)
		return
	}
	os.Exit(m.Run())
}

func fakeSay(event string, fields ...any) {
	line := map[string]any{"event": event}
	for i := 0; i+1 < len(fields); i += 2 {
		line[fields[i].(string)] = fields[i+1]
	}
	out, _ := json.Marshal(line)
	fmt.Fprintf(os.Stderr, "%s\n", out)
}

func fakeNote(format string, args ...any) {
	path := os.Getenv(fakeOutEnv)
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, format+"\n", args...)
}

func fakeHello() {
	version := os.Getenv(fakeVersionEnv)
	if version == "" {
		version = fakeVersion
	}
	fakeSay("hello", "version", version, "commit", "abc1234", "protocol", 1, "ipc", 1)
}

// fakeReadConfig reads the configuration message and notes it. It notes
// "no-config" when stdin ends first.
func fakeReadConfig() bool {
	var head [4]byte
	if _, err := io.ReadFull(os.Stdin, head[:]); err != nil {
		fakeNote("no-config")
		return false
	}
	body := make([]byte, binary.BigEndian.Uint32(head[:]))
	if _, err := io.ReadFull(os.Stdin, body); err != nil {
		fakeNote("truncated-config")
		return false
	}
	fakeNote("config=%s", body)
	return true
}

// fakeForever waits without end. Not select {}: with no other goroutine the
// runtime calls that a deadlock and ends the process.
func fakeForever() {
	for {
		time.Sleep(time.Hour)
	}
}

func fakeCompanion(scenario string) {
	fakeNote("pid=%d", os.Getpid())
	echoUntilStdinCloses := func() {
		_, _ = io.Copy(os.Stdout, os.Stdin)
		fakeSay("closed", "reason", "stdin_closed")
		os.Exit(0)
	}

	switch scenario {
	case "ok":
		fakeHello()
		if !fakeReadConfig() {
			os.Exit(1)
		}
		fakeSay("listening")
		time.Sleep(30 * time.Millisecond)
		fakeSay("connected")
		fakeSay("path", "path", "relayed")
		fakeSay("path", "path", "direct")
		echoUntilStdinCloses()

	case "another-version":
		fakeSay("hello", "version", "9.9.9", "commit", "fffffff", "protocol", 1, "ipc", 1)
		fakeReadConfig()
		os.Exit(1)
	case "another-exchange":
		fakeSay("hello", "version", fakeVersion, "commit", "abc1234", "protocol", 1, "ipc", 2)
		fakeReadConfig()
		os.Exit(1)
	case "another-protocol":
		fakeSay("hello", "version", fakeVersion, "commit", "abc1234", "protocol", 2, "ipc", 1)
		fakeReadConfig()
		os.Exit(1)

	case "says-nothing":
		fakeForever()
	case "ends-at-once":
		os.Exit(3)
	case "another-first-word":
		fakeSay("listening")
		fakeForever()

	case "relay-refused":
		fakeHello()
		fakeReadConfig()
		fakeSay("error", "reason", "relay_refused")
		os.Exit(1)
	case "relay-unreachable":
		fakeHello()
		fakeReadConfig()
		fakeSay("error", "reason", "relay_unreachable", "detail", "dial tcp4 203.0.113.5:443: connect: connection refused")
		os.Exit(1)
	case "bad-config":
		fakeHello()
		fakeReadConfig()
		fakeSay("error", "reason", "bad_config", "detail", "psk: missing")
		os.Exit(1)
	case "start-failed":
		fakeHello()
		fakeReadConfig()
		fakeSay("error", "reason", "start_failed")
		os.Exit(1)

	case "never-listens":
		fakeHello()
		fakeReadConfig()
		fakeForever()
	case "crashes":
		fakeHello()
		fakeReadConfig()
		fmt.Fprint(os.Stderr, "panic: boom\n\ngoroutine 1 [running]:\nmain.main()\n\t/build/main.go:12 +0x1d\n")
		os.Exit(2)
	case "connected-before-listening":
		fakeHello()
		fakeReadConfig()
		fakeSay("connected")
		fakeForever()

	case "noisy-start":
		fmt.Fprintln(os.Stderr, "a line that is not an event")
		fmt.Fprintln(os.Stderr, strings.Repeat("x", 200<<10))
		fakeHello()
		fakeSay("log", "msg", "a library log line")
		if !fakeReadConfig() {
			os.Exit(1)
		}
		fakeSay("log", "msg", "another library log line")
		fakeSay("listening")
		echoUntilStdinCloses()

	case "stubborn":
		signal.Ignore(syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
		fakeHello()
		fakeReadConfig()
		fakeSay("listening")
		fakeForever()

	case "needs-a-signal":
		// Never reads its stdin again, as a companion whose client takes no
		// data: it ends on a termination signal only.
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGTERM)
		fakeHello()
		fakeReadConfig()
		fakeSay("listening")
		<-signals
		fakeSay("closed", "reason", "terminated")
		os.Exit(0)

	case "early-events":
		fakeHello()
		fakeReadConfig()
		fakeSay("refused", "reason", "unknown_peer", "peer", "aaaaaaaa", "count", 1)
		fakeSay("relay", "state", "lost")
		fakeSay("path", "path", "relayed")
		fakeSay("listening")
		fakeSay("connected")
		echoUntilStdinCloses()

	case "talks-after-closed":
		fakeHello()
		fakeReadConfig()
		fakeSay("listening")
		fakeSay("connected")
		fakeSay("closed", "reason", "peer_closed")
		fakeSay("refused", "reason", "unknown_peer", "peer", "bbbbbbbb", "count", 1)
		fakeSay("relay", "state", "lost")
		fakeSay("error", "reason", "internal")
		os.Exit(0)

	case "crashes-with-a-trace":
		// What the Go runtime prints for a panic while the tunnel starts,
		// with the first words of the node key among the arguments.
		fakeHello()
		fakeReadConfig()
		fmt.Fprint(os.Stderr, "panic: boom\n\ngoroutine 1 [running]:\n"+
			"github.com/netdefense-io/ndagent/connect/internal/tunnel.Start({0x1054f8e68, 0x14000126000}, {{{}, {0xa8, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, ...}}, ...})\n"+
			"\t/build/connect/internal/tunnel/server.go:191 +0x1d\n"+
			"key a8a1a2a3a4a5a6a7a8a9aaabacadaeaf\n")
		os.Exit(2)

	case "slow-start":
		fakeHello()
		fakeReadConfig()
		time.Sleep(700 * time.Millisecond)
		fakeSay("listening")
		echoUntilStdinCloses()
	case "waits-for-a-client":
		fakeHello()
		fakeReadConfig()
		fakeSay("listening")
		echoUntilStdinCloses()
	case "connection-lost":
		fakeHello()
		fakeReadConfig()
		fakeSay("listening")
		fakeSay("connected")
		fakeSay("path", "path", "relayed")
		fakeSay("closed", "reason", "connection_lost")
		os.Exit(0)

	case "client-leaves":
		fakeHello()
		fakeReadConfig()
		fakeSay("listening")
		fakeSay("connected")
		fmt.Fprint(os.Stdout, "last bytes")
		fakeSay("closed", "reason", "peer_closed")
		os.Exit(0)
	case "dies-quietly":
		fakeHello()
		fakeReadConfig()
		fakeSay("listening")
		os.Exit(0)
	case "dies-loudly":
		fakeHello()
		fakeReadConfig()
		fakeSay("listening")
		fmt.Fprint(os.Stderr, "fatal error: something broke\n")
		os.Exit(2)

	case "every-event":
		fakeHello()
		fakeReadConfig()
		fakeSay("listening")
		fakeSay("relay", "state", "lost")
		fakeSay("relay", "state", "lost", "reason", "relay_refused")
		fakeSay("relay", "state", "connected")
		fakeSay("refused", "reason", "unknown_peer", "peer", "0a1b2c3d", "count", 3)
		fakeSay("log", "msg", "a library log line")
		fakeSay("connected")
		fakeSay("path", "path", "relayed")
		echoUntilStdinCloses()

	case "reports-itself":
		cwd, _ := os.Getwd()
		fakeNote("cwd=%s", cwd)
		fakeNote("args=%d", len(os.Args))
		for _, entry := range os.Environ() {
			name, _, _ := strings.Cut(entry, "=")
			fakeNote("env=%s", name)
		}
		fakeNote("gotraceback=%s", os.Getenv("GOTRACEBACK"))
		fakeHello()
		fakeReadConfig()
		fakeSay("listening")
		echoUntilStdinCloses()

	default:
		fmt.Fprintf(os.Stderr, "unknown stand-in scenario %q\n", scenario)
		os.Exit(64)
	}
}
