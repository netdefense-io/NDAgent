package core

import (
	"context"
	"sync"
	"time"

	"github.com/netdefense-io/ndagent/internal/firmware"
	"github.com/netdefense-io/ndagent/internal/network"
	"github.com/netdefense-io/ndagent/internal/opnapi"
	"github.com/netdefense-io/ndagent/internal/taskstore"
)

// firmwareSweepInterval is how often the reconciler looks at its rows while the
// WebSocket phase runs. Each sweep of an idle store is one local query.
const firmwareSweepInterval = 15 * time.Second

// firmwareSweepTimeout bounds one sweep of the ticker. The connect hook gets its
// own, tighter bound from the connect; this one is what keeps a read that cannot
// finish (the package database behind a long install, an API that hangs) from
// holding the sweep, and with it every later one, for as long as it lasts.
const firmwareSweepTimeout = 2 * time.Minute

// firmwareReconciler decides the outcome of FIRMWARE_UPGRADE rows that nothing
// in this process owns any more.
//
// A firmware update outlives the handler that started it: OPNsense runs it in a
// detached process tree, the agent may be restarted by the very package the
// update replaces, and the box reboots. The row is then left IN_PROGRESS, the
// connect-time drain skips the type, and this reconciler resolves it once the
// device shows how the update ended (firmware.Evaluate). It runs on every
// connect and on a ticker for the life of the WebSocket phase, and it is bound
// to that phase: its sender is the phase's client, so a phase that ended takes
// the loop with it instead of leaving one that resolves through a dead client.
//
// It never touches a row whose handler is alive in this process, and it
// resolves through a compare-and-set, so a second sweep, or the handler, can
// never produce a second outcome for the same task.
type firmwareReconciler struct {
	store *taskstore.Store
	// probes read the device.
	probes firmware.Probes
	// isLive reports whether this process still owns a task (its handler is
	// running or queued).
	isLive func(taskID string) bool
	// resolve records a terminal outcome for a task and delivers it. It returns
	// whether this call was the one that resolved the task.
	resolve func(taskID, status, message string) (bool, error)
	// now and uptime are the clock and how long this process has run;
	// overridable in tests.
	now    func() time.Time
	uptime func() time.Duration
	logf   func(format string, args ...interface{})
	// sweepTimeout bounds each sweep the ticker starts.
	sweepTimeout time.Duration

	// mu keeps sweeps from overlapping: the connect hook and the ticker can both
	// fire. A sweep that finds another under way returns rather than waits.
	mu sync.Mutex
	// lastNote holds the last thing logged per task, so a row that waits for
	// twenty minutes is logged when it starts waiting and when that changes, not
	// every sweep.
	lastNote map[string]string
}

// firmwareProbes reads the device through the OPNsense API client, or without
// one for a device that has no API credentials. The check is on the concrete
// type: a nil *opnapi.Client stored in the firmware.API interface is not a nil
// interface, and the probes would call through it.
func firmwareProbes(client *opnapi.Client) firmware.Probes {
	var api firmware.API
	if client != nil {
		api = client
	}
	return firmware.NewProbes(api)
}

// startFirmwareReconciler is what a WebSocket phase does with the reconciler: it
// decides the rows the drain leaves to it on every connect (the client's
// pre-drain hook, so it has decided before the drain replays anything) and every
// interval for as long as ctx lives. ctx is the phase's: when the phase ends, so
// does the loop, instead of one that resolves through a dead client. The
// reconciler never touches a row whose handler is alive (the dispatcher says
// which), and resolves through the client's compare-and-set, so a row goes out
// once.
func startFirmwareReconciler(
	ctx context.Context,
	ws *network.WebSocketClient,
	store *taskstore.Store,
	probes firmware.Probes,
	logf func(format string, args ...interface{}),
	interval time.Duration,
) *firmwareReconciler {
	reconciler := newFirmwareReconciler(store, probes, ws.GetDispatcher().IsTaskLive, ws.CompleteInProgressTask, logf)
	ws.SetPreDrainHook(reconciler.Sweep)
	go reconciler.Run(ctx, interval)
	return reconciler
}

func newFirmwareReconciler(
	store *taskstore.Store,
	probes firmware.Probes,
	isLive func(taskID string) bool,
	resolve func(taskID, status, message string) (bool, error),
	logf func(format string, args ...interface{}),
) *firmwareReconciler {
	return &firmwareReconciler{
		store:        store,
		probes:       probes,
		isLive:       isLive,
		resolve:      resolve,
		now:          time.Now,
		uptime:       firmware.Uptime,
		logf:         logf,
		sweepTimeout: firmwareSweepTimeout,
		lastNote:     make(map[string]string),
	}
}

// Run sweeps every interval until ctx ends.
func (r *firmwareReconciler) Run(ctx context.Context, interval time.Duration) {
	// What the loop was waiting on is not something it can still answer for.
	defer firmware.Watch(0)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.sweepWithin(ctx, r.sweepTimeout)
		}
	}
}

// sweepWithin is Sweep under a deadline of its own.
func (r *firmwareReconciler) sweepWithin(ctx context.Context, limit time.Duration) {
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	r.Sweep(ctx)
}

// Sweep evaluates every FIRMWARE_UPGRADE row that is IN_PROGRESS and not owned
// by a handler in this process, and resolves the ones the device has an answer
// for. A row that cannot be resolved yet is left as it is.
//
// The connect hook runs it inside the connect, where nothing else happens (no
// heartbeat, no command) until it returns, and it gets a context that bounds it.
// A sweep already under way, the ticker's, is deciding the same rows and will
// finish on its own, so this one does not queue behind it: the next tick, or the
// next connect, looks again.
func (r *firmwareReconciler) Sweep(ctx context.Context) {
	if !r.mu.TryLock() {
		return
	}
	defer r.mu.Unlock()

	rows, err := r.store.InProgressByType(network.TaskTypeFirmwareUpgrade)
	if err != nil {
		r.logf("firmware-reconcile: query in-progress rows failed: %v", err)
		return
	}
	if len(rows) == 0 {
		firmware.Watch(0)
		clear(r.lastNote)
		return
	}
	// While rows are waiting on the device the agent must not start firmware
	// checks of its own: see firmware.Busy. A row whose handler is alive is
	// covered by the handler's own hold.
	r.watch(rows)
	// However the sweep ends (a context that ran out included), what is left is
	// what the agent has to keep out of the way of.
	defer func() {
		if left, err := r.store.InProgressByType(network.TaskTypeFirmwareUpgrade); err == nil {
			r.watch(left)
		}
	}()

	// Rows of one sweep are about one device: read each source once.
	probes := r.probes.Once()
	seen := make(map[string]struct{}, len(rows))
	for _, row := range rows {
		seen[row.TaskID] = struct{}{}
		if ctx.Err() != nil {
			return
		}
		if r.isLive(row.TaskID) {
			continue
		}
		in := firmware.Input{
			RowStartedAt:  row.StartedAt,
			ProcessUptime: r.uptime(),
			Now:           r.now(),
		}
		meta, err := r.recordedRun(row.TaskID)
		if err != nil {
			r.logf("firmware-reconcile: task %s: reading its metadata failed: %v", row.TaskID, err)
			continue
		}
		in.Meta = meta
		r.apply(row, meta, firmware.Evaluate(ctx, in, probes))
	}
	for id := range r.lastNote {
		if _, ok := seen[id]; !ok {
			delete(r.lastNote, id)
		}
	}
}

// watch tells firmware.Busy how many of the rows nothing in this process owns.
func (r *firmwareReconciler) watch(rows []taskstore.Record) {
	waiting := 0
	for _, row := range rows {
		if !r.isLive(row.TaskID) {
			waiting++
		}
	}
	firmware.Watch(waiting)
}

// recordedRun is what the handler recorded about the run, or nil for a row that
// has none: one written by an agent that recorded nothing (an older one; this one
// records a marker as soon as it takes a task up, before it waits for its turn,
// so a task that never triggered anything is not mistaken for one of those).
func (r *firmwareReconciler) recordedRun(taskID string) (*firmware.Meta, error) {
	var meta firmware.Meta
	found, err := r.store.GetTaskMeta(taskID, &meta)
	if err != nil || !found || meta.Mode == "" {
		return nil, err
	}
	return &meta, nil
}

// apply acts on a row's verdict. meta is what the handler recorded about the
// run, nil for a row an older agent wrote.
func (r *firmwareReconciler) apply(row taskstore.Record, meta *firmware.Meta, v firmware.Verdict) {
	// A row with no record may have been a run that applied something.
	triggered := meta == nil || meta.Triggered()
	switch v.Action {
	case firmware.Wait:
		r.note(row.TaskID, "wait:"+v.Reason,
			"firmware-reconcile: task %s stays IN_PROGRESS: %s", row.TaskID, v.Message)
	case firmware.Complete:
		r.finish(row.TaskID, taskstore.StatusCompleted, v, triggered)
	case firmware.Fail:
		r.finish(row.TaskID, taskstore.StatusFailed, v, triggered)
	}
}

// finish resolves a row. triggered says whether its run asked OPNsense to
// apply something: only then does the outcome ask for a firmware check.
func (r *firmwareReconciler) finish(taskID, status string, v firmware.Verdict, triggered bool) {
	won, err := r.resolve(taskID, status, v.Message)
	switch {
	case !won && err != nil:
		r.logf("firmware-reconcile: task %s: could not record %s: %v", taskID, status, err)
	case !won:
		r.logf("firmware-reconcile: task %s was already resolved; leaving its outcome alone", taskID)
	case err != nil:
		r.logf("firmware-reconcile: task %s resolved %s (%s); delivery failed and will be replayed on the next connect: %v",
			taskID, status, v.Reason, err)
	default:
		r.logf("firmware-reconcile: task %s resolved %s (%s)", taskID, status, v.Reason)
	}
	if won && triggered {
		firmware.NoteOutcome()
	}
	delete(r.lastNote, taskID)
}

func (r *firmwareReconciler) note(taskID, key, format string, args ...interface{}) {
	if r.lastNote[taskID] == key {
		return
	}
	r.lastNote[taskID] = key
	r.logf(format, args...)
}
