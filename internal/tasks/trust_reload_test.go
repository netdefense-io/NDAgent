package tasks

import (
	"context"
	"encoding/base64"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/config"
	"github.com/netdefense-io/ndagent/internal/network"
	"github.com/netdefense-io/ndagent/internal/signing"
	"github.com/netdefense-io/ndagent/internal/state"
	"github.com/netdefense-io/ndagent/internal/testbroker"
)

// newTestRestarter is a restarter whose restart runs until release is closed,
// with short ceilings.
func newTestRestarter(startErr error) (w *webGUIRestarter, release chan struct{}, started *atomic.Int32) {
	release = make(chan struct{})
	started = &atomic.Int32{}
	w = &webGUIRestarter{
		start: func() (func() error, error) {
			started.Add(1)
			if startErr != nil {
				return nil, startErr
			}
			return func() error { <-release; return nil }, nil
		},
		restartCeiling: time.Second,
		probeCeiling:   time.Second,
		probeTimeout:   200 * time.Millisecond,
		probeInterval:  10 * time.Millisecond,
	}
	return w, release, started
}

// A probe gives up fast: a request in flight while lighttpd shuts down hangs
// until its own timeout, so each probe carries a deadline of at most two
// seconds, whatever the ceiling of the whole wait.
func TestWebGUIRestart_ProbesGiveUpFast(t *testing.T) {
	if webGUIRestart.probeTimeout <= 0 || webGUIRestart.probeTimeout > 2*time.Second {
		t.Fatalf("probe timeout = %v, want at most 2s", webGUIRestart.probeTimeout)
	}
	w, release, _ := newTestRestarter(nil)
	close(release)
	var deadlines []time.Duration
	var mu sync.Mutex
	w.schedule(func(ctx context.Context) error {
		deadline, ok := ctx.Deadline()
		mu.Lock()
		defer mu.Unlock()
		if !ok {
			deadlines = append(deadlines, -1)
		} else {
			deadlines = append(deadlines, time.Until(deadline))
		}
		if len(deadlines) < 3 {
			return errors.New("connection refused")
		}
		return nil
	})
	assertWaitEndsWithin(t, w, context.Background(), 5*time.Second)
	mu.Lock()
	defer mu.Unlock()
	if len(deadlines) != 3 {
		t.Fatalf("probed %d times, want 3", len(deadlines))
	}
	for i, d := range deadlines {
		if d <= 0 || d > w.probeTimeout {
			t.Errorf("probe %d had %v left, want a deadline within %v", i, d, w.probeTimeout)
		}
	}
}

// The next SYNC waits while the restart runs and until the API answers again,
// then goes on; with nothing scheduled it does not wait at all.
func TestWebGUIRestart_NextSyncWaitsForTheAPI(t *testing.T) {
	w, release, started := newTestRestarter(nil)
	w.wait(context.Background())

	var probes atomic.Int32
	w.schedule(func(context.Context) error {
		if probes.Add(1) < 3 {
			return errors.New("connection refused")
		}
		return nil
	})

	waited := make(chan struct{})
	go func() {
		w.wait(context.Background())
		close(waited)
	}()
	select {
	case <-waited:
		t.Fatal("the wait ended while the restart was still running")
	case <-time.After(100 * time.Millisecond):
	}
	if probes.Load() != 0 {
		t.Fatal("the API was probed before the restart had run")
	}

	close(release)
	select {
	case <-waited:
	case <-time.After(5 * time.Second):
		t.Fatal("the wait did not end once the API answered")
	}
	if started.Load() != 1 || probes.Load() != 3 {
		t.Errorf("helper started %d time(s), probed %d time(s); want 1 and 3", started.Load(), probes.Load())
	}

	done := make(chan struct{})
	go func() { w.wait(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("a second wait blocked after the restart was over")
	}
}

// The wait is bounded: an API that never answers ends it after the probe
// ceiling, a helper that never exits after the restart ceiling, and the
// caller's context ends it at once.
func TestWebGUIRestart_WaitIsBounded(t *testing.T) {
	t.Run("the API never answers", func(t *testing.T) {
		w, release, _ := newTestRestarter(nil)
		close(release)
		w.schedule(func(context.Context) error { return errors.New("down") })
		assertWaitEndsWithin(t, w, context.Background(), 5*time.Second)
	})
	t.Run("the helper never exits", func(t *testing.T) {
		w, release, _ := newTestRestarter(nil)
		t.Cleanup(func() { close(release) })
		w.schedule(func(context.Context) error { return nil })
		assertWaitEndsWithin(t, w, context.Background(), 5*time.Second)
	})
	t.Run("the helper does not start", func(t *testing.T) {
		w, _, _ := newTestRestarter(errors.New("no /bin/sh"))
		w.schedule(func(context.Context) error { t.Error("probed without a restart"); return nil })
		assertWaitEndsWithin(t, w, context.Background(), time.Second)
	})
	t.Run("the caller gives up", func(t *testing.T) {
		w, release, _ := newTestRestarter(nil)
		w.restartCeiling = time.Hour
		t.Cleanup(func() { close(release) })
		w.schedule(func(context.Context) error { return nil })
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		assertWaitEndsWithin(t, w, ctx, time.Second)
	})
}

func assertWaitEndsWithin(t *testing.T, w *webGUIRestarter, ctx context.Context, limit time.Duration) {
	t.Helper()
	done := make(chan struct{})
	go func() { w.wait(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(limit):
		t.Fatalf("the wait did not end within %v", limit)
	}
}

// Two restarts scheduled back to back run one after the other.
func TestWebGUIRestart_RestartsDoNotOverlap(t *testing.T) {
	w, _, _ := newTestRestarter(nil)
	var mu sync.Mutex
	running, maxRunning := 0, 0
	w.start = func() (func() error, error) {
		mu.Lock()
		running++
		if running > maxRunning {
			maxRunning = running
		}
		mu.Unlock()
		return func() error {
			time.Sleep(20 * time.Millisecond)
			mu.Lock()
			running--
			mu.Unlock()
			return nil
		}, nil
	}

	w.schedule(func(context.Context) error { return nil })
	w.schedule(func(context.Context) error { return nil })
	assertWaitEndsWithin(t, w, context.Background(), 5*time.Second)
	if maxRunning != 1 {
		t.Fatalf("%d restarts ran at once", maxRunning)
	}
}

func TestConfigdReportedError(t *testing.T) {
	for answer, want := range map[string]bool{
		"OK":                            false,
		"":                              false,
		"Execute error":                 true,
		"Action not allowed or missing": true,
		"Action not found":              true,
		"OK\nExecute error on script":   true,
	} {
		if got := configdReportedError(answer); got != want {
			t.Errorf("configdReportedError(%q) = %v, want %v", answer, got, want)
		}
	}
}

// Each kind of service is its own unit: changing one changes what runs for it
// and nothing else.
func TestTrustReloadUnits_AreSwappable(t *testing.T) {
	calls := recordConfigctl(t)
	prev := trustReloadUnits["ipsec"]
	trustReloadUnits["ipsec"] = trustReloadUnit{Verb: "ipsec restart", Steps: [][]string{{"ipsec", "restart"}}}
	t.Cleanup(func() { trustReloadUnits["ipsec"] = prev })

	run := &trustRun{ctx: context.Background(), renewedCerts: []renewedTrust{{RefID: "r", Name: "fw1"}}}
	run.config, run.configRead = newTrustConfig(mustParseTree(t, `<opnsense><OPNsense><Swanctl><locals><local uuid="u"><description>HQ</description><certs>r</certs></local></locals></Swanctl></OPNsense></opnsense>`)), true
	run.reload()
	if !reflect.DeepEqual(*calls, []string{"ipsec restart"}) {
		t.Fatalf("configctl calls = %q", *calls)
	}
	if got := itemsOf(run.result); !reflect.DeepEqual(got, []string{"trust_reload HQ ipsec restart success"}) {
		t.Fatalf("items = %q", got)
	}
}

func mustParseTree(t *testing.T, body string) *xmlNode {
	t.Helper()
	root, err := parseXMLTree(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// The web GUI restart starts only after the SYNC result has gone out: the
// broker holds the response by the time the restart is asked for.
func TestSendSyncResult_RestartRunsAfterTheResponse(t *testing.T) {
	b := testbroker.New(t)
	_, priv, err := signing.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	stateStore, err := state.New(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	ws := network.NewWebSocketClient(&config.Config{
		ServerURIWS:   b.URL(),
		DeviceUUID:    "3a1e88a3-0000-4000-8000-0000000000aa",
		Token:         "00000000-0000-4000-8000-000000000000",
		DevicePrivKey: base64.StdEncoding.EncodeToString(signing.SeedFromPrivateKey(priv)),
	}, stateStore, nil, LifecycleFor, b.NDMKeys())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = ws.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	b.WaitForHeartbeats(1, 5*time.Second)

	var responsesWhenRestarted int
	err = sendSyncResult(ws, "4242", TaskResult{Success: true, Message: "Trust certificates ~1"}, func() {
		b.WaitFor("the SYNC response", 5*time.Second, func() bool { return len(b.TaskResponses()) == 1 })
		responsesWhenRestarted = len(b.TaskResponses())
	})
	if err != nil {
		t.Fatal(err)
	}
	if responsesWhenRestarted != 1 {
		t.Fatalf("the broker held %d responses when the restart ran, want the SYNC's", responsesWhenRestarted)
	}
	if r := b.TaskResponses()[0]; r.TaskID != 4242 || r.Status != "COMPLETED" {
		t.Fatalf("response = %+v", r)
	}
}

// Syslog is started again after a stop, even when the stop failed, and a
// failure of either says logging may be stopped.
func TestTrustReload_SyslogIsStartedAgain(t *testing.T) {
	for _, tc := range []struct {
		name string
		fail []string
		ok   bool
	}{
		{"both succeed", nil, true},
		{"the stop fails", []string{"syslog stop"}, false},
		{"the start fails", []string{"syslog start"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := recordConfigctl(t, tc.fail...)
			err := runTrustReloadUnit(context.Background(), trustReloadUnits["syslog"])
			if (err == nil) != tc.ok {
				t.Errorf("err = %v", err)
			}
			if want := []string{"syslog stop", "syslog start"}; !reflect.DeepEqual(*calls, want) {
				t.Errorf("configctl calls = %q, want %q", *calls, want)
			}
		})
	}
	if text := trustReloadUnits["syslog"].IfFailed; !strings.Contains(text, "logging may have been left stopped") || !strings.Contains(text, "configctl syslog stop, then configctl syslog start") {
		t.Errorf("IfFailed = %q", text)
	}
}

// configctl's own deadline, or a cancelled context, is reported as such, so a
// reload that did not finish is told from one that failed.
func TestRunConfigctl_ReportsAContextThatEnded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runConfigctl(ctx, "openvpn", "configure"); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want it to wrap context.Canceled", err)
	}
}

// The restart is recorded as started only once the helper has started.
func TestWebGUIRestart_RecordsTheStart(t *testing.T) {
	for _, tc := range []struct {
		name     string
		startErr error
		want     int32
	}{{"started", nil, 1}, {"not started", errors.New("fork failed"), 0}} {
		t.Run(tc.name, func(t *testing.T) {
			w, release, _ := newTestRestarter(tc.startErr)
			close(release)
			var started atomic.Int32
			w.started = func() { started.Add(1) }
			w.schedule(func(context.Context) error { return nil })
			assertWaitEndsWithin(t, w, context.Background(), 5*time.Second)
			if got := started.Load(); got != tc.want {
				t.Errorf("started = %d, want %d", got, tc.want)
			}
		})
	}
	if webGUIRestart.started == nil {
		t.Error("the agent's restarter does not record the start")
	}
}
