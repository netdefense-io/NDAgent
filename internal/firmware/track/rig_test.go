package track

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/netdefense-io/ndagent/internal/firmware"
	"github.com/netdefense-io/ndagent/internal/logging"
)

func fastTiming() Timing {
	return Timing{
		Poll:          time.Millisecond,
		ReadyWait:     40 * time.Millisecond,
		CheckTimeout:  400 * time.Millisecond,
		CheckIdleDrop: 15 * time.Millisecond,
		StartWindow:   80 * time.Millisecond,
		StartPoll:     time.Millisecond,
		Settle:        time.Millisecond,
		ProbeCacheTTL: time.Minute,
		APIWait:       25 * time.Millisecond,
	}
}

// rig is an engine over a simulated device and a record in a temp directory.
type rig struct {
	t     *testing.T
	dev   *simDevice
	store *StateStore
	eng   *Engine
	jobs  []Job
	msgs  []string
	// clock is set by simulateTime: the tasks the rig runs are then taken up by it.
	clock *fakeClock
}

func newRig(t *testing.T, tweak ...func(*simDevice)) *rig {
	t.Helper()
	firmware.ResetGuardForTest()
	t.Cleanup(firmware.ResetGuardForTest)
	dev := newSim(t)
	for _, f := range tweak {
		f(dev)
	}
	r := &rig{t: t, dev: dev, store: NewStateStore(filepath.Join(t.TempDir(), "firmware-track.json"))}
	r.eng = r.newEngine()
	return r
}

func (r *rig) newEngine(opts ...Option) *Engine {
	base := []Option{
		WithTiming(fastTiming()),
		WithJitter(func(time.Duration) time.Duration { return 0 }),
		WithUptime(func() time.Duration { return time.Hour }),
		WithBootTime(r.dev.BootTime),
	}
	return New(r.dev, r.store, nil, append(base, opts...)...)
}

func enrollPayload(track string) Payload {
	return Payload{Action: ActionEnroll, Track: track, Reboot: true, Approved: map[string]string{}}
}

func unenrollPayload(track string) Payload {
	return Payload{Action: ActionUnenroll, Track: track, Reboot: true, Approved: map[string]string{}}
}

func advancePayload(track string, reboot bool, approved map[string]string) Payload {
	return Payload{Action: ActionAdvance, Track: track, Reboot: reboot, Approved: approved}
}

// run runs a task to its end. A step that waits for a reboot nobody simulates would
// otherwise hold the suite until its own timeout: the context ends the wait, the
// outcome is Aborted, and the test that expected an answer fails at once.
func (r *rig) run(p Payload) *Outcome {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return r.runCtx(ctx, p)
}

// execute runs an input a test built itself, bounded as run is.
func (r *rig) execute(in Input) *Outcome {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return r.eng.Execute(ctx, in)
}

func (r *rig) runCtx(ctx context.Context, p Payload) *Outcome {
	r.t.Helper()
	out := r.eng.Execute(ctx, Input{
		TaskID:   "101",
		Payload:  p,
		Started:  r.now(),
		Save:     func(j Job) { r.jobs = append(r.jobs, j) },
		Progress: func(m string) { r.msgs = append(r.msgs, m) },
	})
	r.checkOutcome(p, out)
	return out
}

// runInTestMode runs a task for an agent whose test_mode is on.
func (r *rig) runInTestMode(ctx context.Context, p Payload) *Outcome {
	r.t.Helper()
	out := r.eng.Execute(ctx, Input{TaskID: "102", Payload: p, Started: time.Now(), TestMode: true})
	r.checkOutcome(p, out)
	return out
}

// checkOutcome holds every outcome to the contract: a result passes the
// validator the control plane runs, with the payload it dispatched, and a
// failure's side-channel is a valid one.
func (r *rig) checkOutcome(p Payload, out *Outcome) {
	r.t.Helper()
	switch {
	case out.Result != nil:
		if out.Failure != "" || out.Aborted {
			r.t.Fatalf("an outcome that is a result and something else: %+v", out)
		}
		if f := ValidateResult(out.Message, &Expect{Action: p.Action, Track: p.Track, Approved: p.Approved, Major: p.Major}); f != nil {
			r.t.Fatalf("the result %s is refused by the contract: %v", out.Message, f)
		}
	case out.Failure != "":
		if strings.HasPrefix(strings.TrimSpace(out.Failure), "{") {
			r.t.Fatalf("a failure's message is plain text, not JSON: %q", out.Failure)
		}
		if m := out.Detail.Map(); m != nil {
			if f := ValidateFailureDetail(m, &Expect{Action: p.Action, Track: p.Track, Approved: p.Approved, Major: p.Major}); f != nil {
				r.t.Fatalf("the failure detail %v is refused: %v", m, f)
			}
		}
	}
}

func (r *rig) state() *State {
	r.t.Helper()
	st, err := r.store.Load()
	if err != nil {
		r.t.Fatalf("load the record: %v", err)
	}
	return st
}

// wantResult asserts a COMPLETED outcome and returns its result.
func wantResult(t *testing.T, out *Outcome, outcome, reason string) *Result {
	t.Helper()
	if out.Result == nil {
		t.Fatalf("want %s/%s, got %+v", outcome, reason, out)
	}
	if out.Result.Outcome != outcome || out.Result.Reason != reason {
		t.Fatalf("want %s/%s, got %s/%s (%s)", outcome, reason, out.Result.Outcome, out.Result.Reason, out.Message)
	}
	return out.Result
}

func wantVersions(t *testing.T, r *Result, from, to, target, pinned string) {
	t.Helper()
	if r.FromVersion != from || r.ToVersion != to || r.TargetVersion != target || r.PinnedVersion != pinned {
		t.Fatalf("versions from=%q to=%q target=%q pinned=%q; want %q %q %q %q",
			r.FromVersion, r.ToVersion, r.TargetVersion, r.PinnedVersion, from, to, target, pinned)
	}
}

// writes are the flavours the device was told to take, in order.
func (d *simDevice) writes() []string {
	var out []string
	for _, c := range d.Calls() {
		if strings.HasPrefix(c, "set ") {
			out = append(out, strings.TrimPrefix(c, "set "))
		}
	}
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// captureLogs sends everything the engine logs to an observer. It has to be
// called before the rig is built: an engine takes its logger when it is made.
func captureLogs(t *testing.T) *observer.ObservedLogs {
	t.Helper()
	core, logs := observer.New(zapcore.DebugLevel)
	t.Cleanup(logging.SetForTest(zap.New(core)))
	return logs
}

// panics is how many panics the engine contained.
func panics(logs *observer.ObservedLogs) int { return logs.FilterMessage(panicMessage).Len() }

// now is when the rig takes a task up: the simulated clock's, or the real one.
func (r *rig) now() time.Time {
	if r.clock != nil {
		return r.clock.Now()
	}
	return time.Now()
}

// Sleep is a wait that costs no time: it moves the clock by d, so what a wait is
// bounded by (a count of polls, a deadline) is the same on every machine.
func (c *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.Advance(d)
	return nil
}

// simulateTime gives the rig an engine whose waits move a clock instead of
// sleeping. The clock starts at the real time, because the deadlines the engine
// hands to contexts are real ones.
func (r *rig) simulateTime(opts ...Option) *fakeClock {
	clock := &fakeClock{t: time.Now()}
	r.clock = clock
	r.eng = r.newEngine(append([]Option{WithClock(clock.Now), WithSleep(clock.Sleep)}, opts...)...)
	return clock
}

// onClock gives the rig an engine on a clock the test moves.
func (r *rig) onClock() *fakeClock {
	clock := &fakeClock{t: time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)}
	r.clock = clock // the tasks the rig runs are taken up by it
	r.eng = r.newEngine(WithClock(clock.Now))
	return clock
}
