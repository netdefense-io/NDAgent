package network

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/signing"
	"github.com/netdefense-io/ndagent/internal/state"
	"github.com/netdefense-io/ndagent/internal/taskstore"
)

// errDispatchReplay is the sentinel wrapped by checkDispatchReplayBarrier
// when an envelope is rejected as a replay (as opposed to a state-persist
// failure) — callers use errors.Is to pick the right log level.
var errDispatchReplay = errors.New("dispatch replay rejected")

// LifecycleResolver maps a task_type string to its taskstore Lifecycle
// category. The dispatcher uses it at Begin time so the boot-time drain
// knows how to react to rows left IN_PROGRESS. Implemented in
// internal/tasks/register.go (LifecycleFor); passed in via constructor
// to avoid an import cycle (tasks → network → tasks).
type LifecycleResolver func(taskType string) taskstore.Lifecycle

// Task type constants
const (
	TaskTypePing            = "PING"
	TaskTypeShutdown        = "SHUTDOWN"
	TaskTypeReboot          = "REBOOT"
	TaskTypeRestart         = "RESTART"
	TaskTypePull            = "PULL"
	TaskTypeSync            = "SYNC"
	TaskTypeBackup          = "BACKUP"
	TaskTypeConnect         = "CONNECT"
	TaskTypePluginInstall   = "PLUGIN_INSTALL"
	TaskTypeFirmwareUpgrade = "FIRMWARE_UPGRADE"
)

// TaskHandler is a function that handles a specific task type.
// It receives the WebSocket client, command, and context.
// It should send appropriate responses via the WebSocket.
type TaskHandler func(ctx context.Context, ws *WebSocketClient, cmd Command) error

// syncQueueCapacity is the SYNC-only FIFO's buffer size. Generous on
// purpose: reaching it means dozens of SYNCs are
// already backlogged behind one still running, at which point failing the
// newest arrival fast (SYNC_QUEUE_FULL) is more useful than growing the
// queue further — the next trigger simply re-syncs.
const syncQueueCapacity = 64

// CommandDispatcher handles command dispatching to task handlers.
type CommandDispatcher struct {
	handlers    map[string]TaskHandler
	activeTasks sync.Map // map[string]context.CancelFunc
	mu          sync.Mutex
	taskCount   int

	// State store for replay barrier (per-NDM monotonic task_id).
	state *state.Store
	// Task-state registry: per-task IN_PROGRESS / terminal / delivered
	// rows persisted across restarts. The dispatcher writes the Begin
	// row; SendTaskResponse on the WebSocketClient writes the terminal
	// + delivered markers. nil-tolerant for tests that don't need it.
	taskStore *taskstore.Store
	// Maps task_type → Lifecycle. nil-tolerant — falls back to
	// LifecycleSynchronous, which is the right default for any unknown
	// task type.
	lifecycleFor LifecycleResolver
	// Static NDM pubkey table (primary + emergency) — populated from
	// the agent's conf at startup.
	ndmKeys map[string]ed25519.PublicKey // hex(kid) -> pubkey
	// The agent's own UUID, bound into envelope verification.
	deviceUUID string

	// syncQueue and syncWorkerCtx implement the per-agent SYNC FIFO:
	// every OTHER task type still runs in its
	// own goroutine via dispatchCommand, but a SYNC command is enqueued
	// here and a single worker drains it, so overlapping SYNCs can never
	// finish out of dispatch order (the replay barrier already makes
	// arrival order == dispatch_seq order — the FIFO just makes
	// EXECUTION order match arrival order too).
	//
	// The CommandDispatcher itself is created exactly ONCE per process —
	// by NewWebSocketClient, inside the constructor — and is reused across
	// every ordinary WebSocket reconnect: WebSocketClient.Run loops on
	// w.connect internally and keeps the same *CommandDispatcher for the
	// life of the process; only a full return to Phase 1 (a permanent
	// refusal) and a brand-new LifecycleManager.runWebSocketPhase call
	// would ever construct a new one. Each call to
	// ReceiveCommands, though, DOES get its own fresh loopCtx (built in
	// runCommunicationLoop), which is cancelled when that connection ends.
	// ensureSyncWorker must therefore be able to start a NEW worker bound
	// to the NEW loopCtx once the OLD one's context is done — a plain
	// sync.Once (which fires at most once for the dispatcher's entire
	// lifetime) would leave the queue with no consumer at all after the
	// first reconnect, silently wedging every SYNC behind it until the
	// process restarts.
	syncQueue     chan Command
	syncWorkerMu  sync.Mutex
	syncWorkerCtx context.Context // ctx of the currently-live worker; nil or Done() means none is running
}

// NewCommandDispatcher creates a new command dispatcher.
//
// `ndmKeys` maps lowercase-hex kid → pubkey for the NDManager primary
// and emergency keys (loaded from the agent conf). `stateStore`
// persists the `last_executed_task_id` replay barrier across restarts.
// `taskStore` and `lifecycleFor` are optional — pass nil to disable
// per-task persistence (tests, or environments without /var/db/ndagent
// write access). When taskStore is set, lifecycleFor MUST be too.
func NewCommandDispatcher(stateStore *state.Store, taskStore *taskstore.Store, lifecycleFor LifecycleResolver, ndmKeys map[string]ed25519.PublicKey, deviceUUID string) *CommandDispatcher {
	d := &CommandDispatcher{
		handlers:     make(map[string]TaskHandler),
		state:        stateStore,
		taskStore:    taskStore,
		lifecycleFor: lifecycleFor,
		ndmKeys:      ndmKeys,
		deviceUUID:   deviceUUID,
		syncQueue:    make(chan Command, syncQueueCapacity),
	}

	// Note: Task handlers are registered by tasks.RegisterHandlers()

	return d
}

// RegisterHandler registers a handler for a specific task type.
func (d *CommandDispatcher) RegisterHandler(taskType string, handler TaskHandler) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.handlers[taskType] = handler
}

// ReceiveCommands reads and dispatches commands from the WebSocket.
//
// Each frame goes through envelope verification before reaching the handler:
//  1. Decode the outer frame (envelope must be present — there is no
//     fallthrough for unsigned dispatches).
//  2. Verify the COSE_Sign1 envelope against the agent's DISPATCH key set
//     ONLY (primary). Emergency is loaded into a separate map for rotation
//     directives and is never consulted here.
//  3. Validate header bindings: v=2, iss=ndmanager, device_uuid matches
//     own UUID, signed exp not yet expired, then the replay barrier: if
//     the envelope carries a signed dispatch_seq (HdrDispatchSeq), that
//     per-device monotonic counter gates it (strictly greater than
//     last_dispatch_seq); otherwise fall back to the legacy task_id
//     barrier (strictly greater than last_executed_task_id). Never both
//     — see the barrier block below for why.
//  4. Persist the new last_dispatch_seq (or last_executed_task_id, in the
//     fallback case) BEFORE dispatching the handler so a mid-handler
//     crash + replay is rejected.
//  5. Reconstruct the verified Command using the SIGNED task_type
//     (decoded.Type), never the raw outer frame field. Payload comes
//     from the verified envelope; pathfinder_session for CONNECT lives
//     inside the signed payload (NDManager seals it at task creation).
func (d *CommandDispatcher) ReceiveCommands(ctx context.Context, ws *WebSocketClient) error {
	log := logging.Named("dispatcher")

	for {
		// Check for cancellation
		select {
		case <-ctx.Done():
			log.Info("Command receiver cancelled")
			return ctx.Err()
		default:
		}

		// Read message
		_, message, err := ws.ReadMessage()
		if err != nil {
			log.Errorw("Error reading WebSocket message",
				"error", err,
			)
			return err
		}

		// Parse outer frame
		var raw rawCommandFrame
		if err := json.Unmarshal(message, &raw); err != nil {
			log.Errorw("Error parsing command JSON", "error", err)
			continue
		}

		outerTaskIDStr := taskIDToString(raw.TaskID)

		if raw.Envelope == "" {
			log.Errorw("Refusing unsigned dispatch — closed beta requires envelope",
				"task_id", outerTaskIDStr,
			)
			continue
		}

		envelopeBytes, err := base64.StdEncoding.DecodeString(raw.Envelope)
		if err != nil {
			log.Errorw("Envelope base64 malformed", "task_id", outerTaskIDStr, "error", err)
			continue
		}

		decoded, err := signing.VerifyDispatchEnvelope(envelopeBytes, d.lookupNDMKey)
		if err != nil {
			log.Errorw("Envelope signature verification failed",
				"task_id", outerTaskIDStr,
				"error", err,
			)
			continue
		}

		// Header binding checks:
		// - signed exp must not have passed (replaces an iat skew check)
		// - signed type must be present (we route from it, not from the
		//   unsigned outer frame field)
		if decoded.Iss != "ndmanager" {
			log.Errorw("Envelope iss mismatch",
				"task_id", outerTaskIDStr, "iss", decoded.Iss)
			continue
		}
		if decoded.DeviceUUID != d.deviceUUID {
			log.Errorw("Envelope device_uuid mismatch",
				"task_id", outerTaskIDStr, "envelope_device", decoded.DeviceUUID, "agent_device", d.deviceUUID)
			continue
		}
		if outerTaskIDStr != "" {
			outerInt, parseErr := strconv.ParseInt(outerTaskIDStr, 10, 64)
			if parseErr != nil || outerInt != decoded.TaskID {
				log.Errorw("Outer/inner task_id mismatch",
					"outer", outerTaskIDStr, "inner", decoded.TaskID)
				continue
			}
		}
		if decoded.Type == "" {
			log.Errorw("Envelope missing signed task_type", "task_id", decoded.TaskID)
			continue
		}
		if decoded.Exp == 0 {
			log.Errorw("Envelope missing signed exp", "task_id", decoded.TaskID)
			continue
		}
		nowSec := time.Now().Unix()
		if nowSec > decoded.Exp {
			log.Warnw("Envelope expired before dispatch",
				"task_id", decoded.TaskID, "exp", decoded.Exp, "now", nowSec)
			continue
		}

		// Replay barrier (dispatch-side). See checkDispatchReplayBarrier
		// for the per-envelope either/or rule (dispatch_seq when present,
		// else the legacy task_id barrier — never both).
		if err := d.checkDispatchReplayBarrier(decoded); err != nil {
			if errors.Is(err, errDispatchReplay) {
				log.Warnw("Envelope replay rejected",
					"task_id", decoded.TaskID,
					"has_dispatch_seq", decoded.HasDispatchSeq,
					"dispatch_seq", decoded.DispatchSeq,
					"error", err,
				)
			} else {
				log.Errorw("Failed to persist dispatch replay barrier",
					"task_id", decoded.TaskID,
					"has_dispatch_seq", decoded.HasDispatchSeq,
					"dispatch_seq", decoded.DispatchSeq,
					"error", err,
				)
			}
			continue
		}

		// Reconstruct verified Command. TaskType is from the SIGNED envelope,
		// not the unsigned outer frame field. pathfinder_session for CONNECT
		// lives inside the signed payload; pulled out below if present.
		cmd := Command{
			TaskID:   fmt.Sprintf("%d", decoded.TaskID),
			TaskType: decoded.Type,
		}
		if len(decoded.Payload) > 0 {
			if err := json.Unmarshal(decoded.Payload, &cmd.Payload); err != nil {
				log.Errorw("Verified payload not a JSON object",
					"task_id", cmd.TaskID, "error", err)
				continue
			}
			if pfRaw, ok := cmd.Payload["pathfinder_session"]; ok {
				if pfStr, isStr := pfRaw.(string); isStr {
					cmd.PathfinderSession = pfStr
				}
			}
		}

		log.Infow("Received signed command",
			"task_id", cmd.TaskID,
			"task_type", cmd.TaskType,
			"kid", hex.EncodeToString(decoded.Kid),
		)

		// SYNC commands go through the per-agent
		// FIFO instead of their own goroutine, so an older SYNC can never
		// finish after a newer one and win. Every other task type is
		// unaffected — dispatchCommand still runs in its own goroutine.
		if cmd.TaskType == TaskTypeSync {
			// Record IN_PROGRESS at ENQUEUE time, not when the worker
			// eventually dequeues it. A SYNC can sit behind up to
			// syncQueueCapacity-1 others; without this, a crash while
			// this one is still queued (never yet reached
			// dispatchCommand's own Begin call) leaves no row at all for
			// the boot-time drain to find, so it can never send a
			// terminal response for a task_id the broker is still
			// waiting on. dispatchCommand's own Begin call right before
			// the handler runs is idempotent against an already
			// IN_PROGRESS row, so this is safe to do twice.
			d.beginTaskState(cmd)

			d.ensureSyncWorker(ctx, ws)
			if !d.trySyncEnqueue(cmd) {
				log.Warnw("SYNC queue full; failing this SYNC (the next trigger will re-sync)",
					"task_id", cmd.TaskID, "capacity", syncQueueCapacity)
				if err := ws.SendTaskResponse(cmd.TaskID, TaskStatusFailed,
					"SYNC_QUEUE_FULL: a previous SYNC is still running and the queue is full; the next scheduled sync will retry", nil); err != nil {
					log.Errorw("Failed to send SYNC_QUEUE_FULL response", "error", err)
				}
			}
			continue
		}

		// Dispatch command in a goroutine
		go d.dispatchCommand(ctx, ws, cmd)
	}
}

// trySyncEnqueue attempts a non-blocking enqueue onto the SYNC FIFO.
// Returns false when the queue is full (capacity syncQueueCapacity) — the
// caller is responsible for reporting SYNC_QUEUE_FULL; this method touches
// nothing but the channel, so it is testable without a WebSocketClient.
func (d *CommandDispatcher) trySyncEnqueue(cmd Command) bool {
	select {
	case d.syncQueue <- cmd:
		return true
	default:
		return false
	}
}

// ensureSyncWorker starts the single SYNC-draining goroutine bound to ctx,
// unless a worker already started under a still-live ctx is running. It is
// called on every SYNC command ReceiveCommands sees (once per connection's
// loopCtx), so it must both (a) never start a second concurrent worker for
// the current connection, and (b) be able to start a fresh worker once the
// previous connection's worker has stopped — see the syncWorkerCtx doc
// comment on CommandDispatcher for why a one-shot sync.Once cannot do this
// across a WebSocket reconnect. The worker calls dispatchCommand
// SYNCHRONOUSLY (not in its own goroutine, unlike every other task type):
// that is the FIFO — the next queued SYNC is not even started until
// dispatchCommand returns from the previous one.
//
// The worker's own select loop gives workerCtx.Done() priority over the
// queue (see the doc comment inside the goroutine below) — this function
// decides "the previous worker is gone" purely from workerCtx.Err(), with
// no synchronization against that worker's goroutine actually having
// exited, so the two must agree that a done context always wins.
func (d *CommandDispatcher) ensureSyncWorker(ctx context.Context, ws *WebSocketClient) {
	d.syncWorkerMu.Lock()
	defer d.syncWorkerMu.Unlock()

	if d.syncWorkerCtx != nil && d.syncWorkerCtx.Err() == nil {
		// A worker is already running for the current connection — this is
		// the common case, since ensureSyncWorker is called on every SYNC
		// command, not just the first.
		return
	}

	d.syncWorkerCtx = ctx
	go func(workerCtx context.Context) {
		for {
			// Check workerCtx.Done() with priority, via its own
			// non-blocking select, before ever racing it against the
			// queue. A single two-case `select { <-Done(); <-queue }`
			// picks pseudo-randomly between them when BOTH are already
			// ready — which they both are on every iteration after the
			// connection this worker belongs to has ended (Done() does
			// not merely become ready at some point; it STAYS ready).
			// Without this, a worker whose connection already ended can
			// keep winning that coin flip and go on dequeuing SYNCs
			// under an already-cancelled context — precisely while
			// ensureSyncWorker (above) is deciding, from the very same
			// workerCtx.Err() != nil, that THIS worker is gone and a
			// replacement is needed. Two workers draining d.syncQueue at
			// once is exactly what the FIFO exists to prevent. A
			// `default:` branch makes this check non-blocking, so a
			// worker that still has nothing to do falls through to the
			// real (blocking) select below exactly as before.
			select {
			case <-workerCtx.Done():
				return
			default:
			}
			select {
			case <-workerCtx.Done():
				return
			case cmd, ok := <-d.syncQueue:
				if !ok {
					return
				}
				d.dispatchCommand(workerCtx, ws, cmd)
			}
		}
	}(ctx)
}

// checkDispatchReplayBarrier enforces the dispatch-side replay barrier and
// advances the winning counter, persisted BEFORE the caller dispatches the
// handler goroutine (conservative against duplicate execution on a
// mid-handler crash — see SetLastDispatchSeq / SetLastExecutedTaskID).
//
// Per-envelope either/or — NEVER both barriers on the same envelope:
//   - If decoded carries a signed dispatch_seq (HasDispatchSeq==true, i.e.
//     NDManager minted signing.HdrDispatchSeq into the protected header),
//     that per-device monotonic counter is authoritative and the legacy
//     task_id barrier is skipped entirely for this envelope. This is the
//     XM-12 fix: task_id is the GLOBAL autoincrement row id, so a
//     scheduled task activated later can legitimately carry a lower
//     task_id than an already-executed immediate task; gating on task_id
//     in that case would silently drop a valid dispatch. Running both
//     barriers on the same envelope would reintroduce exactly that drop
//     whenever a valid dispatch_seq arrives alongside a stale task_id, so
//     the fallback below must never also run in this branch.
//   - Absent (an un-upgraded NDManager that hasn't started minting
//     dispatch_seq yet) falls back to the legacy task_id barrier,
//     unchanged from pre-XM-12 behavior. This is what makes the fix safe
//     to ship ahead of the NDManager/NDBroker side.
//
// Both barriers use strict `>` (gap-tolerant — a dropped or reordered-then-
// caught-up sequence number is fine; only non-increasing is rejected).
//
// Returns an error wrapping errDispatchReplay when the envelope must be
// dropped as a replay (caller: log.Warnw + continue); any other error is a
// state-persist failure (caller: log.Errorw + continue). Returns nil only
// when the winning counter was successfully advanced and persisted.
func (d *CommandDispatcher) checkDispatchReplayBarrier(decoded *signing.DecodedEnvelope) error {
	if decoded.HasDispatchSeq {
		last := d.state.LastDispatchSeq()
		if decoded.DispatchSeq <= last {
			return fmt.Errorf("%w: dispatch_seq %d <= last_dispatch_seq %d", errDispatchReplay, decoded.DispatchSeq, last)
		}
		if err := d.state.SetLastDispatchSeq(decoded.DispatchSeq); err != nil {
			return fmt.Errorf("persist last_dispatch_seq: %w", err)
		}
		return nil
	}

	last := d.state.LastExecutedTaskID()
	if decoded.TaskID <= last {
		return fmt.Errorf("%w: task_id %d <= last_executed_task_id %d", errDispatchReplay, decoded.TaskID, last)
	}
	if err := d.state.SetLastExecutedTaskID(decoded.TaskID); err != nil {
		return fmt.Errorf("persist last_executed_task_id: %w", err)
	}
	return nil
}

func (d *CommandDispatcher) lookupNDMKey(kid []byte) (ed25519.PublicKey, error) {
	pub, ok := d.ndmKeys[hex.EncodeToString(kid)]
	if !ok {
		return nil, fmt.Errorf("kid %s not in NDM key table", hex.EncodeToString(kid))
	}
	return pub, nil
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

// beginTaskState records cmd as IN_PROGRESS in the local task registry,
// nil-tolerant (tests, or environments without /var/db/ndagent write
// access) and idempotent against an already-IN_PROGRESS row (taskstore.Begin
// itself treats that as a no-op re-Begin) — safe to call more than once for
// the same task_id, which is exactly what happens for a SYNC command: once
// at enqueue time (ReceiveCommands) and again right before the handler
// actually runs (dispatchCommand).
func (d *CommandDispatcher) beginTaskState(cmd Command) {
	if d.taskStore == nil || d.lifecycleFor == nil {
		return
	}
	log := logging.Named("dispatcher")
	if err := d.taskStore.Begin(cmd.TaskID, cmd.TaskType, d.lifecycleFor(cmd.TaskType)); err != nil {
		// Don't block dispatch — the handler can still send a response;
		// we just lose crash-recovery coverage for this one task.
		// ErrAlreadyTerminal is expected if the broker redispatched a
		// task we already finished; log at INFO so it's not noise.
		log.Infow("taskstore.Begin failed",
			"task_id", cmd.TaskID,
			"task_type", cmd.TaskType,
			"error", err,
		)
	}
}

// dispatchCommand dispatches a command to the appropriate handler.
func (d *CommandDispatcher) dispatchCommand(ctx context.Context, ws *WebSocketClient, cmd Command) {
	log := logging.Named("dispatcher")

	// Create a cancellable context for this task
	taskCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Track the task
	d.activeTasks.Store(cmd.TaskID, cancel)
	d.mu.Lock()
	d.taskCount++
	d.mu.Unlock()

	defer func() {
		d.activeTasks.Delete(cmd.TaskID)
		d.mu.Lock()
		d.taskCount--
		d.mu.Unlock()
	}()

	// Get handler
	d.mu.Lock()
	handler, exists := d.handlers[cmd.TaskType]
	d.mu.Unlock()

	if !exists {
		log.Errorw("Unknown command type",
			"task_type", cmd.TaskType,
			"task_id", cmd.TaskID,
		)
		// Send error response
		if err := ws.SendTaskResponse(cmd.TaskID, TaskStatusFailed, "Unknown command type: "+cmd.TaskType, nil); err != nil {
			log.Errorw("Failed to send error response",
				"error", err,
			)
		}
		return
	}

	// Record the task as IN_PROGRESS in the local registry before the
	// handler runs (idempotent — beginTaskState may already have done
	// this at enqueue time for a SYNC command). The lifecycle category
	// drives boot-time drain behavior if the agent dies before the
	// handler can send a final task_response (see internal/taskstore).
	d.beginTaskState(cmd)

	// Execute handler
	if err := handler(taskCtx, ws, cmd); err != nil {
		// Check if it was cancelled
		if taskCtx.Err() != nil {
			log.Infow("Task cancelled",
				"task_id", cmd.TaskID,
				"task_type", cmd.TaskType,
			)
			// Try to send cancellation response
			if sendErr := ws.SendTaskResponse(cmd.TaskID, TaskStatusFailed, cmd.TaskType+" task was cancelled", nil); sendErr != nil {
				log.Errorw("Failed to send cancellation response",
					"error", sendErr,
				)
			}
			return
		}

		log.Errorw("Task handler error",
			"task_id", cmd.TaskID,
			"task_type", cmd.TaskType,
			"error", err,
		)
	}
}

// CancelTask cancels a specific task by ID.
func (d *CommandDispatcher) CancelTask(taskID string) bool {
	if cancelFn, ok := d.activeTasks.Load(taskID); ok {
		cancelFn.(context.CancelFunc)()
		return true
	}
	return false
}

// CleanupTasks cancels all active tasks.
func (d *CommandDispatcher) CleanupTasks() {
	log := logging.Named("dispatcher")

	count := 0
	d.activeTasks.Range(func(key, value interface{}) bool {
		cancel := value.(context.CancelFunc)
		cancel()
		count++
		return true
	})

	if count > 0 {
		log.Infow("Cancelled active tasks",
			"count", count,
		)
	}
}

// ActiveTaskCount returns the number of currently active tasks.
func (d *CommandDispatcher) ActiveTaskCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.taskCount
}

// placeholderHandler is a temporary handler that sends a "not implemented" response.
// Used for tasks not yet implemented.
func (d *CommandDispatcher) placeholderHandler(ctx context.Context, ws *WebSocketClient, cmd Command) error {
	log := logging.Named("dispatcher")

	log.Warnw("Task handler not yet implemented",
		"task_type", cmd.TaskType,
		"task_id", cmd.TaskID,
	)

	// Send "not implemented" response
	return ws.SendTaskResponse(
		cmd.TaskID,
		TaskStatusFailed,
		cmd.TaskType+" handler not yet implemented",
		nil,
	)
}

// GetDispatcher returns the command dispatcher.
func (w *WebSocketClient) GetDispatcher() *CommandDispatcher {
	return w.dispatcher
}
