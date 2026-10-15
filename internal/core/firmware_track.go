package core

// firmware_track.go — the process-level half of the firmware tracks.
//
// A device in a track is held at one release by OPNsense's own firmware flavour
// setting, and the invariant is that outside a running track task it always is.
// Tasks (internal/tasks) move the pin in windows; two things have to keep it true
// between them, and both outlive any WebSocket phase:
//
//   - trackSupervisor runs track.Engine.Tick at agent start and on a timer: the
//     reconcile of a pin that was changed outside NetDefense, the repair of an
//     operation that did not end, and the 30-day dead-man. A DISABLED device
//     waits in the registration phase and still has to release its pin, so this
//     is started with the process, not with the WebSocket phase.
//   - trackRowReconciler decides the FIRMWARE_TRACK rows a handler left behind
//     (the connection dropped, or the box rebooted for the update) from the
//     device. It is bound to the WebSocket phase, like the FIRMWARE_UPGRADE one.

import (
	"context"
	"math/rand"
	"sync"
	"time"

	"github.com/netdefense-io/ndagent/internal/config"
	"github.com/netdefense-io/ndagent/internal/firmware"
	"github.com/netdefense-io/ndagent/internal/firmware/track"
	"github.com/netdefense-io/ndagent/internal/network"
	"github.com/netdefense-io/ndagent/internal/opnapi"
	"github.com/netdefense-io/ndagent/internal/tasks"
	"github.com/netdefense-io/ndagent/internal/taskstore"
)

const (
	// trackTickInterval is how often the engine looks at the pin. A round with
	// nothing to do is a read of the record and, for a pinned device, two local
	// reads (the firmware settings, the version file).
	trackTickInterval = 5 * time.Minute
	// trackSweepInterval is how often the row reconciler looks at its rows.
	trackSweepInterval = 15 * time.Second
	// trackSweepTimeout bounds one sweep of the ticker.
	trackSweepTimeout = 2 * time.Minute
)

// The start order. A firmware check is a write when the catalog it reads carries a
// newer pkg, so the first one of a process must not run before the firmware pin has
// been put right: the supervisor's first round runs as soon as the firmware API
// answers (the web GUI and configd may not be up yet after a boot, so it retries
// every trackSettlePoll) instead of after a fixed delay, and closes the gate the
// heavy-telemetry collector's checks wait behind (Settled) when a round has been able
// to read the device, whatever it then did, or at trackSettleBound after the
// process started, so that a device whose API never answers is not kept from
// checking for ever. Variables so that tests do not sit through them.
var (
	trackSettlePoll  = 3 * time.Second
	trackSettleBound = 5 * time.Minute
)

// trackSupervisor owns the process's engine, its contact tracker and the loop.
type trackSupervisor struct {
	engine  *track.Engine
	contact *track.Contact

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}

	// The gate: closed, once, when the start order allows the first firmware check.
	gateMu     sync.Mutex
	settledCh  chan struct{}
	settleOnce sync.Once

	// now and sleep are the supervisor's clock and wait; nil is the real ones.
	now   func() time.Time
	sleep func(ctx context.Context, d time.Duration) error
}

// Settled is the gate of the start order: it is closed when a round of the engine
// has been able to read the device and decide about the pin (re-pinned it, found it
// right, found no record or no pin), or at trackSettleBound after the supervisor
// started. The heavy-telemetry collector holds its firmware checks until then.
func (s *trackSupervisor) Settled() <-chan struct{} { return s.gate() }

func (s *trackSupervisor) gate() chan struct{} {
	s.gateMu.Lock()
	defer s.gateMu.Unlock()
	if s.settledCh == nil {
		s.settledCh = make(chan struct{})
	}
	return s.settledCh
}

// settle closes the gate; closing it again is nothing.
func (s *trackSupervisor) settle() { s.settleOnce.Do(func() { close(s.gate()) }) }

func (s *trackSupervisor) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func (s *trackSupervisor) wait(ctx context.Context, d time.Duration) error {
	if s.sleep != nil {
		return s.sleep(ctx, d)
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

// newTrackSupervisor builds the engine over the real device. Without OPNsense
// API credentials there is no supervisor: nothing can be read or written, and no
// pin can have been written either.
func newTrackSupervisor(cfg *config.Config) *trackSupervisor {
	client := opnapi.NewClient(cfg.OPNsenseAPIURL, cfg.APIKey, cfg.APISecret, true)
	contact := &track.Contact{}
	engine := track.New(track.NewSystemDevice(client), track.NewStateStore(track.DefaultStatePath), contact,
		track.WithHelperRelease(tasks.ReleaseFirmwarePin))
	return &trackSupervisor{engine: engine, contact: contact}
}

// start runs the loop until ctx ends or stop is called. A second call does nothing.
func (s *trackSupervisor) start(ctx context.Context, logf func(string, ...interface{})) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		return
	}
	loopCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.done = make(chan struct{})
	go func() {
		defer close(s.done)
		s.loop(loopCtx, trackTickInterval, logf)
	}()
}

// stop ends the loop and waits for the round in progress. The decommission calls
// it first: the sequence takes the pin off itself, and a round that pinned again
// meanwhile would undo it.
func (s *trackSupervisor) stop() {
	s.mu.Lock()
	cancel, done := s.cancel, s.done
	s.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	<-done
}

func (s *trackSupervisor) loop(ctx context.Context, every time.Duration, logf func(string, ...interface{})) {
	s.startup(ctx, logf)
	wait := every + time.Duration(rand.Int63n(int64(every/10)+1))
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		s.engine.Tick(ctx)
		// Spread the fleet's rounds a little: a mirror problem should not be asked
		// about by every device in the same second.
		wait = every + time.Duration(rand.Int63n(int64(every/10)+1))
	}
}

// startup runs the engine's rounds until one has settled the pin, then closes the
// gate. The first round is not put off: it is made at once, and again every
// trackSettlePoll while the firmware API does not answer, the backend is busy, a
// task or another firmware job holds the slot, or an update the agent requested
// before it restarted has not been settled by its row (a series upgrade's pin is
// re-written by that row's finish). The gate closes in any case when this returns:
// at trackSettleBound, or when the supervisor is stopped.
func (s *trackSupervisor) startup(ctx context.Context, logf func(string, ...interface{})) {
	defer s.settle()
	deadline := s.clock().Add(trackSettleBound)
	for {
		if s.engine.Reconcile(ctx) == track.TickSettled {
			return
		}
		if ctx.Err() != nil {
			return
		}
		if !s.clock().Before(deadline) {
			logf("firmware-track: the pin could not be reconciled within %s of the start; the firmware checks are let go", trackSettleBound)
			return
		}
		if err := s.wait(ctx, trackSettlePoll); err != nil {
			return
		}
	}
}

// trackRowReconciler decides the FIRMWARE_TRACK rows nothing in this process
// owns any more. Like the FIRMWARE_UPGRADE reconciler it never touches a row
// whose handler is alive, resolves through a compare-and-set so a row goes out
// once, and keeps other firmware jobs out (firmware.WatchTracks) while a row
// waits for the device.
type trackRowReconciler struct {
	store  *taskstore.Store
	engine *track.Engine
	isLive func(taskID string) bool
	// resolve records a terminal outcome for a task and delivers it, with the
	// extra keys of the signed response. It returns whether this call was the one
	// that resolved the task.
	resolve func(taskID, status, message string, data map[string]interface{}) (bool, error)
	now     func() time.Time
	uptime  func() time.Duration
	logf    func(format string, args ...interface{})

	mu       sync.Mutex
	lastNote map[string]string
}

func newTrackRowReconciler(
	store *taskstore.Store,
	engine *track.Engine,
	isLive func(taskID string) bool,
	resolve func(taskID, status, message string, data map[string]interface{}) (bool, error),
	logf func(format string, args ...interface{}),
) *trackRowReconciler {
	return &trackRowReconciler{
		store: store, engine: engine, isLive: isLive, resolve: resolve,
		now: time.Now, uptime: firmware.Uptime, logf: logf,
		lastNote: make(map[string]string),
	}
}

// startTrackRowReconciler is what a WebSocket phase does with it: it decides the
// rows on every connect and every interval for as long as ctx lives (ctx is the
// phase's: when it ends, so does the loop).
//
// The connect only starts the sweep. Deciding a row can write the pin back, make
// a forced check and probe the mirror, which is tens of seconds of work that no
// bound of the connect's hook limits (it is detached from it on purpose, so a
// pin is not left half restored), and the heartbeat loop starts only when the
// hook returns. The drain leaves the type alone, so it needs no row decided
// before it runs; a decided row is sent by the sweep itself.
func startTrackRowReconciler(
	ctx context.Context,
	ws *network.WebSocketClient,
	store *taskstore.Store,
	engine *track.Engine,
	logf func(format string, args ...interface{}),
	interval time.Duration,
) *trackRowReconciler {
	r := newTrackRowReconciler(store, engine, ws.GetDispatcher().IsTaskLive, ws.CompleteInProgressTaskWithData, logf)
	ws.AddPreDrainHook(func(context.Context) { go r.sweepWithin(ctx, trackSweepTimeout) })
	go r.Run(ctx, interval)
	return r
}

// Run sweeps every interval until ctx ends.
func (r *trackRowReconciler) Run(ctx context.Context, interval time.Duration) {
	defer firmware.WatchTracks(0)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.sweepWithin(ctx, trackSweepTimeout)
		}
	}
}

// sweepWithin is Sweep under a deadline of its own.
func (r *trackRowReconciler) sweepWithin(ctx context.Context, limit time.Duration) {
	sweepCtx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	r.Sweep(sweepCtx)
}

// Sweep resolves every FIRMWARE_TRACK row that is IN_PROGRESS and not owned by a
// handler in this process, and leaves the ones the device has no answer for yet.
func (r *trackRowReconciler) Sweep(ctx context.Context) {
	if !r.mu.TryLock() {
		return
	}
	defer r.mu.Unlock()

	rows, err := r.store.InProgressByType(network.TaskTypeFirmwareTrack)
	if err != nil {
		r.logf("firmware-track-reconcile: query in-progress rows failed: %v", err)
		return
	}
	if len(rows) == 0 {
		firmware.WatchTracks(0)
		clear(r.lastNote)
		return
	}
	r.watch(rows)
	defer func() {
		if left, err := r.store.InProgressByType(network.TaskTypeFirmwareTrack); err == nil {
			r.watch(left)
		}
	}()

	seen := make(map[string]struct{}, len(rows))
	for _, row := range rows {
		seen[row.TaskID] = struct{}{}
		if ctx.Err() != nil {
			return
		}
		if r.isLive(row.TaskID) {
			continue
		}
		var job track.Job
		found, err := r.store.GetTaskMeta(row.TaskID, &job)
		if err != nil {
			r.logf("firmware-track-reconcile: task %s: reading its record failed: %v", row.TaskID, err)
			continue
		}
		if !found || job.Action == "" {
			r.unrecorded(row)
			continue
		}
		out, done := r.engine.Resolve(ctx, job, track.Row{TaskID: row.TaskID, StartedAt: row.StartedAt})
		if !done {
			r.note(row.TaskID, "wait", "firmware-track-reconcile: task %s stays IN_PROGRESS", row.TaskID)
			continue
		}
		r.finish(row.TaskID, out)
	}
	for id := range r.lastNote {
		if _, ok := seen[id]; !ok {
			delete(r.lastNote, id)
		}
	}
}

// unrecorded handles a row that carries no record of what the task was: the
// agent stopped between taking the task up and writing it. Nothing can be
// echoed (not even the action, so no hold can be answered), so it is failed once
// its time is up, with no release named, and left until then. The control plane
// counts a failed advance that names none against the release it was sending.
func (r *trackRowReconciler) unrecorded(row taskstore.Record) {
	// There is no payload to read, so the longer budget is taken on purpose: a lost
	// series-upgrade step must never be failed here while the broker still waits for
	// it (a lost minor step is failed by the broker's own expiry long before, and a
	// late answer is dropped).
	if r.now().Before(firmware.Deadline(row.StartedAt.Add(track.MajorAdvanceTTL))) || r.uptime() <= firmware.Grace {
		r.note(row.TaskID, "unrecorded", "firmware-track-reconcile: task %s has no record of what it was; waiting for its time to run out", row.TaskID)
		return
	}
	r.finish(row.TaskID, &track.Outcome{Failure: "The firmware track task was lost when the agent stopped, before it recorded what it was. Nothing was applied by this task."})
}

// finish delivers an outcome. An aborted one is not an outcome.
func (r *trackRowReconciler) finish(taskID string, out *track.Outcome) {
	var (
		status  = taskstore.StatusFailed
		message = out.Failure
		data    map[string]interface{}
	)
	switch {
	case out.Aborted:
		return
	case out.Result != nil:
		status, message = taskstore.StatusCompleted, out.Message
	default:
		if detail := out.Detail.Map(); detail != nil {
			data = map[string]interface{}{track.FailureKey: detail}
		}
	}
	won, err := r.resolve(taskID, status, message, data)
	switch {
	case !won && err != nil:
		r.logf("firmware-track-reconcile: task %s: could not record %s: %v", taskID, status, err)
	case !won:
		r.logf("firmware-track-reconcile: task %s was already resolved; leaving its outcome alone", taskID)
	case err != nil:
		r.logf("firmware-track-reconcile: task %s resolved %s; delivery failed and will be replayed on the next connect: %v", taskID, status, err)
	default:
		r.logf("firmware-track-reconcile: task %s resolved %s", taskID, status)
	}
	delete(r.lastNote, taskID)
}

// watch tells firmware.Busy how many of the rows nothing in this process owns.
func (r *trackRowReconciler) watch(rows []taskstore.Record) {
	waiting := 0
	for _, row := range rows {
		if !r.isLive(row.TaskID) {
			waiting++
		}
	}
	firmware.WatchTracks(waiting)
}

func (r *trackRowReconciler) note(taskID, key, format string, args ...interface{}) {
	if r.lastNote[taskID] == key {
		return
	}
	r.lastNote[taskID] = key
	r.logf(format, args...)
}
