package track

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"runtime/debug"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/netdefense-io/ndagent/internal/firmware"
	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/opnapi"
	"github.com/netdefense-io/ndagent/internal/util"
)

// Time budgets of the task. NDManager gives an advance 20 minutes (the 15 of a
// minor update and 5 of grace) and an enroll or unenroll 5; the lab measured an
// advance at 196 to 263 seconds and an enroll at one check of about 17. A step that
// carries `major` gets MajorAdvanceTTL, from the moment the step is created: the
// series upgrade reboots three times (four after a reset at the start of stage B),
// downloads 1244208 KB and was measured at 230 to 275 seconds from the request to
// the agent's own authentication on a fast lab link. 120 minutes is the chosen
// value, above the 90-minute floor of four times the longest measurement.
const (
	AdvanceTTL      = firmware.MinorTTL + firmware.Grace
	EnrollTTL       = 5 * time.Minute
	MajorAdvanceTTL = 120 * time.Minute
)

// Timing is every wait the engine makes, as a value so tests do not sit through
// them.
type Timing struct {
	// Poll is the time between reads of the firmware backend.
	Poll time.Duration
	// ReadyWait bounds the wait for the backend to be free before the engine
	// touches it: a request that finds OPNsense's lock held is dropped without a
	// word, so nothing is asked of a busy backend.
	ReadyWait time.Duration
	// CheckTimeout bounds one check; a healthy one takes about 15 seconds.
	CheckTimeout time.Duration
	// CheckIdleDrop is how long the backend may read idle after a check was
	// requested without a fresh result before the request counts as dropped.
	CheckIdleDrop time.Duration
	// StartWindow is how long OPNsense gets to show that an update it accepted
	// started.
	StartWindow time.Duration
	StartPoll   time.Duration
	// Settle is the time between evaluations of a run that has ended but cannot
	// be judged yet.
	Settle time.Duration
	// Jitter is the most a task waits before its first request to the mirror:
	// the windows of a track fire for all its devices together.
	Jitter time.Duration
	// ProbeCacheTTL is how long an answer of the mirror is reused.
	ProbeCacheTTL time.Duration
	// APIWait bounds the wait for OPNsense's firmware API to answer when the
	// engine needs it and it does not: the agent starts before the web GUI and
	// configd after a boot, and the API can still be settling after the update's
	// reboot. Zero: no wait.
	APIWait time.Duration
}

// DefaultTiming is the production timing.
func DefaultTiming() Timing {
	return Timing{
		Poll:          3 * time.Second,
		ReadyWait:     5 * time.Minute,
		CheckTimeout:  3 * time.Minute,
		CheckIdleDrop: 20 * time.Second,
		StartWindow:   15 * time.Second,
		StartPoll:     time.Second,
		Settle:        5 * time.Second,
		Jitter:        20 * time.Second,
		ProbeCacheTTL: 10 * time.Minute,
		APIWait:       2 * time.Minute,
	}
}

// Phases of a job, in the order a task passes them. What a restarted agent does
// with a task it finds left over depends on how far it got.
const (
	// PhaseStarted: the task was taken up and nothing on the device changed.
	PhaseStarted = "started"
	// PhaseMoved: the firmware flavour was written; the update, if any, not requested.
	PhaseMoved = "moved"
	// PhaseTriggered: an update was requested; the device decides how it ended.
	PhaseTriggered = "triggered"
)

// Job is what a task records about itself on its row, before it changes
// anything, so whoever decides its outcome later (the handler in-session, or the
// reconciler once the handler is gone) can judge it against where it began and
// can name the action and track the result must echo.
type Job struct {
	Action   string            `json:"action"`
	Track    string            `json:"track"`
	Approved map[string]string `json:"approved,omitempty"`
	// Revisions are the payload's, kept so the answer after a restart still names
	// the revision the dispatch asked for.
	Revisions map[string]string `json:"revisions,omitempty"`
	Reboot    bool              `json:"reboot"`
	Phase     string            `json:"phase"`

	// From is the installed release when the task began, Target the release the
	// payload approves for its series ("" when none).
	From   string `json:"from,omitempty"`
	Target string `json:"target,omitempty"`

	// PrevFlavour is the flavour before the task wrote one, NewFlavour what it
	// wrote.
	PrevFlavour string `json:"prev_flavour,omitempty"`
	NewFlavour  string `json:"new_flavour,omitempty"`

	Drift      bool `json:"drift,omitempty"`
	Reinstalls int  `json:"reinstalls,omitempty"`

	StartedAt int64 `json:"started_at"`
	ExpiresAt int64 `json:"expires_at"`

	// Upgrade is the update's own record, which firmware.Evaluate judges the end
	// of the run by. Set when the update is requested.
	Upgrade *firmware.Meta `json:"upgrade,omitempty"`

	// Major is the series the payload asked for ("" for a step without one). It is
	// the payload's, copied the moment the task is taken up, so that whoever settles
	// the row after a restart can restore the dispatch it must answer.
	Major string `json:"major,omitempty"`
	// FromBase, FromKernel and FromPkgs are what `opnsense-update -vb`, `-vk` and
	// `-vp` read when the series upgrade was requested, beside From (the core):
	// the four versions the abort classification compares, because the pkgs marker
	// of an image can sit below the core and "unchanged" means equal to what was
	// recorded. Set with Upgrade, by a series upgrade only.
	FromBase   string `json:"from_base,omitempty"`
	FromKernel string `json:"from_kernel,omitempty"`
	FromPkgs   string `json:"from_pkgs,omitempty"`
	// Notes are the tokens of A4.3, A4.8 and A4.10 (the audit of repositories and
	// packages and the boot-environment decision), which the final answer carries
	// across the reboots. BootEnvironment is the environment the step made.
	Notes           []string             `json:"notes,omitempty"`
	BootEnvironment *MadeBootEnvironment `json:"boot_environment,omitempty"`
}

// MadeBootEnvironment is the environment a series upgrade made before it started:
// the agent never removes it, and the record is what lets a person find it.
type MadeBootEnvironment struct {
	Name string `json:"name"`
	UUID string `json:"uuid,omitempty"`
}

// isHop reports whether the job is a series upgrade that was requested: the
// hop's answers carry kind major, the series and the notes (the answer rule). A
// step that carried `major` and ran the ordinary minor update is not one, and
// neither is one that held before it recorded the run.
func (j Job) isHop() bool {
	return j.Major != "" && j.Phase == PhaseTriggered && j.Upgrade != nil && j.Upgrade.Mode == "major"
}

// Outcome is how a task ended. Exactly one of Result, Failure and Aborted is set.
type Outcome struct {
	// Result is a COMPLETED task's result and Message its JSON text.
	Result  *Result
	Message string

	// Failure is a FAILED task's plain text (never JSON: NDCLI renders a JSON
	// message without `applied` as a dry-run preview) and Detail the signed
	// side-channel naming what the failed step was moving to.
	Failure string
	Detail  FailureDetail

	// Aborted says the task is left as it is, IN_PROGRESS, for whoever finds it:
	// the context ended (the connection dropped, the agent is stopping, the box is
	// rebooting for the update), or an update that completed cannot be recorded
	// yet because its release or the agent's record cannot be read (finishApplied),
	// and the row's reconciler asks again.
	Aborted bool
}

// Input is a task the engine runs.
type Input struct {
	TaskID  string
	Payload Payload
	// Started is when the handler took the task up and Expires when NDManager
	// stops waiting for it (the signed dispatch expiry). A zero Expires is the
	// action's own lifetime from Started.
	Started time.Time
	Expires time.Time
	// TestMode holds an advance (held_test_mode): the device refuses an update and
	// a reboot. Enroll and unenroll run.
	TestMode bool
	// Progress sends an IN_PROGRESS message. Optional.
	Progress func(message string)
	// Save records the job on the task's row. Optional.
	Save func(Job)
	// Persist is Save for the records that must be on disk before the request that
	// follows them is made: it returns once the job is durable, and an error says it
	// may not be. A lost record is a hold, never a false success, and nothing is
	// requested on a record that may be lost. Optional: without it Save is used.
	Persist func(Job) error
}

// Engine is the pin lifecycle of one device.
type Engine struct {
	dev     Device
	store   *StateStore
	contact *Contact
	timing  Timing
	log     *zap.SugaredLogger

	now      func() time.Time
	sleeper  func(ctx context.Context, d time.Duration) error
	mono     func() time.Duration
	uptime   func() time.Duration
	bootTime func() (int64, error)
	jitter   func(max time.Duration) time.Duration

	// mu serializes everything the engine does to the device. A task holds it for
	// as long as it runs (an advance can wait for a reboot), so the periodic work
	// takes it with TryLock and skips a round.
	mu sync.Mutex

	probeMu sync.Mutex
	probes  map[string]probeEntry

	// armedAt is when the dead-man first saw the silence due, on the monotonic
	// clock, and armedWall the wall clock then: a release needs the silence to
	// persist and the wall clock to have moved as the monotonic one did.
	armedAt   time.Duration
	armedWall time.Time
	armed     bool

	// silent says the last round found the saved contact older than 30 days by the
	// time the connection that is up (or was) began, and left it where it was: the
	// device came back to a control plane that has dropped it, which the dead-man
	// acts on although the connection is live. Worked out again every round from
	// the saved contact, so a restart cannot lose it and a clock that is set right
	// clears it.
	silent bool
	// silentLogged keeps the round from saying it every five minutes.
	silentLogged bool

	// repinAfter is when the periodic reconcile tries again a pin it could not
	// write, or one that keeps being changed from outside.
	repinAfter time.Time

	// driftStreak counts the pins the periodic reconcile wrote again because
	// something outside NetDefense changed the flavour, and driftLast when it last
	// did: see noteDriftRepin.
	driftStreak int
	driftLast   time.Time

	// helperRelease takes the pin off through the plugin's PHP instead of the REST
	// API, for the dead-man when the API cannot. Nil: no fallback.
	helperRelease func(ctx context.Context) error
}

type probeEntry struct {
	result ProbeResult
	at     time.Time
}

// wallClock is the engine's time: the wall clock alone. Round(0) drops the
// monotonic reading, because two times that carry one subtract on it, and every
// wall-clock comparison the dead-man makes (did the clock step while it was
// confirming?) would then compare the monotonic clock with itself.
func wallClock() time.Time { return time.Now().Round(0) }

// Option configures an Engine.
type Option func(*Engine)

// WithTiming sets the waits.
func WithTiming(t Timing) Option { return func(e *Engine) { e.timing = t } }

// WithClock sets the wall clock and, with it, the monotonic one the dead-man
// compares it against. Tests use it to move time.
func WithClock(now func() time.Time) Option {
	return func(e *Engine) {
		e.now = now
		start := now()
		e.mono = func() time.Duration { return now().Sub(start) }
	}
}

// WithSleep sets how the engine waits. A test passes a wait that moves its clock
// by the time asked instead of sitting through it, so that what a wait is bounded
// by (a count of polls, a deadline) does not depend on how fast the machine is.
func WithSleep(sleep func(ctx context.Context, d time.Duration) error) Option {
	return func(e *Engine) { e.sleeper = sleep }
}

// WithMonotonic sets the monotonic clock alone, to let a test step the wall
// clock behind the engine's back.
func WithMonotonic(mono func() time.Duration) Option { return func(e *Engine) { e.mono = mono } }

// WithUptime sets how long the process has run.
func WithUptime(uptime func() time.Duration) Option { return func(e *Engine) { e.uptime = uptime } }

// WithBootTime sets how the boot time is read.
func WithBootTime(boot func() (int64, error)) Option { return func(e *Engine) { e.bootTime = boot } }

// WithHelperRelease sets the fallback the dead-man uses when the REST API cannot
// restore the setting: the plugin's PHP helper, which edits the firmware setting
// itself and needs neither the API user nor the web server.
func WithHelperRelease(fn func(ctx context.Context) error) Option {
	return func(e *Engine) { e.helperRelease = fn }
}

// WithJitter sets how the first probe's delay is chosen.
func WithJitter(j func(max time.Duration) time.Duration) Option {
	return func(e *Engine) { e.jitter = j }
}

// New returns the engine of a device. contact may be nil (then the dead-man has
// nothing to measure from but the state file).
func New(dev Device, store *StateStore, contact *Contact, opts ...Option) *Engine {
	processStart := time.Now()
	e := &Engine{
		dev:      dev,
		store:    store,
		contact:  contact,
		timing:   DefaultTiming(),
		log:      logging.Named("firmware-track"),
		now:      wallClock,
		sleeper:  util.ShutdownAwareSleep,
		mono:     func() time.Duration { return time.Since(processStart) },
		uptime:   firmware.Uptime,
		bootTime: firmware.BootTime,
		jitter: func(max time.Duration) time.Duration {
			if max <= 0 {
				return 0
			}
			return time.Duration(rand.Int63n(int64(max)))
		},
		probes: make(map[string]probeEntry),
	}
	if contact == nil {
		e.contact = &Contact{}
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// Execute runs one task. The firmware slot (firmware.Acquire) is the caller's to
// hold for the whole call.
func (e *Engine) Execute(ctx context.Context, in Input) (out *Outcome) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var o *op
	defer func() {
		if r := recover(); r != nil {
			out = e.panicked(o, in.Payload, r)
		}
	}()

	if in.Started.IsZero() {
		in.Started = e.now()
	}
	if in.Expires.IsZero() {
		in.Expires = DefaultExpiry(in.Payload, in.Started)
	}
	o = &op{
		in: in,
		job: Job{
			Action: in.Payload.Action, Track: in.Payload.Track, Approved: in.Payload.Approved, Revisions: in.Payload.Revisions, Reboot: in.Payload.Reboot,
			Phase: PhaseStarted, StartedAt: in.Started.Unix(), ExpiresAt: in.Expires.Unix(), Major: in.Payload.Major,
		},
	}
	o.saveJob()

	switch in.Payload.Action {
	case ActionEnroll:
		return e.enroll(ctx, o)
	case ActionAdvance:
		return e.advance(ctx, o)
	default:
		return e.unenroll(ctx, o)
	}
}

// op is a task in progress: its input, its job record and what it has learned
// about the device, which is what the result is made of.
type op struct {
	in  Input
	job Job

	st        *State
	settings  opnapi.FirmwareSettings
	installed string

	// The versions a result names. Empty is omitted.
	from, to, target, pinned string

	drift      bool
	reinstalls int

	// jittered says the task already delayed its first request to the mirror, and
	// repinned that it wrote the pin itself (so its folder was just probed).
	jittered, repinned bool

	// kind is KindMajor from the moment the step chooses the series upgrade (A3):
	// the answer rule. From then on target is the series, not the approved minor,
	// and every answer, a hold included, carries kind, target_version and notes, so
	// no row has to remember them. notes are the tokens found so far. A step that
	// carried `major` and took the minor path has neither.
	kind  string
	notes []string

	// revision is the fingerprint of the folder content the task read from the
	// device's catalog; the answer names it when the dispatch carried revisions.
	revision string

	// noPin says the answer reports no pin: the agent holds none it can vouch for
	// (the gone-record rule), so the result carries no pinned_version.
	noPin bool
}

func (o *op) saveJob() {
	o.job.Drift, o.job.Reinstalls = o.drift, o.reinstalls
	if o.in.Save != nil {
		o.in.Save(o.job)
	}
}

// persistJob is saveJob for a record that must be on disk before the request that
// follows it.
func (o *op) persistJob() error {
	o.job.Drift, o.job.Reinstalls = o.drift, o.reinstalls
	switch {
	case o.in.Persist != nil:
		return o.in.Persist(o.job)
	case o.in.Save != nil:
		o.in.Save(o.job)
	}
	return nil
}

// note adds a token to the notes the answer carries, once.
func (o *op) note(token string) {
	o.notes = addNote(o.notes, token)
	o.job.Notes = append([]string(nil), o.notes...)
}

// asHop makes the step the series upgrade's: from here every answer carries kind
// major, the series as its target_version and the notes found so far.
func (o *op) asHop(major string) {
	o.kind, o.target, o.notes = KindMajor, major, nil
}

// wanted is the revision the dispatch holds the task's series to, "" for a series
// the track has not fixed one for.
func (o *op) wanted() string {
	series, _ := SeriesOf(o.installed)
	return o.in.Payload.Revisions[series]
}

// namesRevision says whether the answer carries the revision the task read: only
// for an advance whose dispatch carried revisions, only for the answers that are
// about the content (the update applied, nothing newer on offer, a folder that is
// not the approved revision), and never for a series upgrade's.
func (o *op) namesRevision(outcome, reason string) bool {
	if o.revision == "" || len(o.in.Payload.Revisions) == 0 || o.kind != "" {
		return false
	}
	return outcome == OutcomeSuccess || reason == ReasonAtOrAboveTarget || reason == ReasonPinDrift || reason == ReasonHeldRevisionMismatch
}

func (o *op) progress(message string) {
	if o.in.Progress != nil {
		o.in.Progress(message)
	}
}

// result builds the COMPLETED outcome with the versions the task has so far.
func (e *Engine) result(o *op, outcome, reason string) *Outcome {
	r := Result{
		Action: o.in.Payload.Action, Track: o.in.Payload.Track, Outcome: outcome, Reason: reason,
		Drift: o.drift, ReinstallEntries: o.reinstalls,
		FromVersion: o.from, ToVersion: o.to, TargetVersion: o.target, PinnedVersion: o.pinned,
		Kind: o.kind, Notes: append([]string(nil), o.notes...),
	}
	if o.noPin {
		r.PinnedVersion = ""
	}
	if o.namesRevision(outcome, reason) {
		r.Revision = o.revision
	}
	message, err := r.MessageFor(o.in.Payload)
	if err != nil {
		// A result the contract refuses is a bug here, and the one thing worse
		// than a failed task is a malformed answer.
		e.log.Errorw("Built a result the contract refuses", "error", err, "action", r.Action, "reason", reason)
		return &Outcome{Failure: "internal error: the agent built a firmware track result the contract refuses (" + err.Error() + ")"}
	}
	e.log.Infow("Firmware track task ended",
		"task_id", o.in.TaskID, "action", r.Action, "track", r.Track, "outcome", outcome, "reason", reason,
		"kind", o.kind, "notes", o.notes,
		"from", o.from, "to", o.to, "target", o.target, "pinned", o.pinned, "drift", o.drift)
	return &Outcome{Result: &r, Message: message}
}

// hold is a COMPLETED task that declined, before it changed anything that stays
// changed, because a precondition was not met. A hold costs one window; a FAILED
// stops a release for the whole organization, so an agent that can name the
// precondition holds.
func (e *Engine) hold(o *op, reason string) *Outcome {
	return e.result(o, OutcomeHeld, reason)
}

// fail is a FAILED task: an operation that started and did not finish, or whose
// result cannot be trusted. The side-channel names the release it was moving to,
// and the control plane counts the failure against it for the whole organization.
func (e *Engine) fail(o *op, format string, args ...interface{}) *Outcome {
	text := fmt.Sprintf(format, args...)
	e.log.Warnw("Firmware track task failed", "task_id", o.in.TaskID, "action", o.in.Payload.Action, "error", text)
	detail := FailureDetail{PinnedVersion: o.pinned}
	if o.in.Payload.Action == ActionAdvance {
		detail.Target = o.target
		if o.kind == KindMajor {
			// The series upgrade is the irreversible operation: its failure counts
			// against the series, and blocks it in the tracks after this one, and not
			// against the final minor; the notes keep the board's warnings and the
			// boot environment of the attempt that failed.
			detail.Kind = KindMajor
			detail.Notes = append([]string(nil), o.notes...)
		}
	}
	return &Outcome{Failure: text, Detail: detail}
}

func aborted() *Outcome { return &Outcome{Aborted: true} }

// sleep waits d or until ctx ends.
func (e *Engine) sleep(ctx context.Context, d time.Duration) error {
	return e.sleeper(ctx, d)
}

var (
	errBackendBusy  = errors.New("OPNsense's firmware backend stayed busy")
	errCheckDropped = errors.New("OPNsense did not run the firmware check it was asked for")
	errCheckTimeout = errors.New("the firmware check did not finish in time")
)

// NewJob is the record a task leaves on its row the moment it is taken up,
// before it waits for its turn: if the agent stops now, whoever finds the row
// knows which action and track the answer must echo, and that nothing has changed.
func NewJob(p Payload, started, expires time.Time) Job {
	return Job{
		Action: p.Action, Track: p.Track, Approved: p.Approved, Revisions: p.Revisions, Reboot: p.Reboot, Major: p.Major,
		Phase: PhaseStarted, StartedAt: started.Unix(), ExpiresAt: expires.Unix(),
	}
}

// panicMessage is what the engine logs when it contains a panic.
const panicMessage = "The firmware track engine panicked; the pin is repaired by the next round"

// logPanic records a panic the engine contained, with the stack. A panic that
// reaches the top of a goroutine ends the process, which daemon(8) starts again
// only after its restart delay and with the task in hand lost, and the pin this
// engine holds is something it has to go on repairing.
func (e *Engine) logPanic(what string, recovered interface{}) {
	e.log.Errorw(panicMessage, "in", what, "panic", fmt.Sprint(recovered), "stack", string(debug.Stack()))
}

// panicked turns a panic in a task into its answer. The record of an operation
// that did not end is repaired by the next round, so the answer is a hold, and a
// failure for an unenroll, which the control plane has to ask again.
//
// Once the update has been requested (the job's phase is triggered) it answers
// nothing: a hold is a COMPLETED row, the update runs on without the agent, and
// nothing would then settle how it ended, so the row stays IN_PROGRESS for Resolve.
// The same rule serves a minor update after its request. A panic before the request
// still holds, with the ordinary step's answer: it has no op to ask, so a series
// upgrade held by a panic carries no kind and no notes, as an attempt that ends
// before it has recorded the run does.
func (e *Engine) panicked(o *op, p Payload, recovered interface{}) *Outcome {
	e.logPanic("task", recovered)
	if p.Action == ActionUnenroll {
		return &Outcome{Failure: "The agent hit an internal error while restoring the firmware setting; it will repair the pin and be asked again"}
	}
	if o != nil && o.job.Phase == PhaseTriggered {
		return aborted()
	}
	return Held(p, ReasonHeldCheckFailed)
}

// Held is the outcome of a task that declined before it touched the device, for
// the callers that never reach the engine: there is no engine to ask (the device
// has no API credentials), or the task's time ran out waiting for its turn.
func Held(p Payload, reason string) *Outcome {
	r := Result{Action: p.Action, Track: p.Track, Outcome: OutcomeHeld, Reason: reason}
	message, err := r.MessageFor(p)
	if err != nil {
		return &Outcome{Failure: "internal error: " + err.Error()}
	}
	return &Outcome{Result: &r, Message: message}
}

// DefaultExpiry is when NDManager stops waiting for a task that carries no
// signed expiry: the action's own lifetime from when it was taken up, and for an
// advance that carries `major` the longer lifetime of a series upgrade.
func DefaultExpiry(p Payload, started time.Time) time.Time {
	switch {
	case p.Action != ActionAdvance:
		return started.Add(EnrollTTL)
	case p.Major != "":
		return started.Add(MajorAdvanceTTL)
	}
	return started.Add(AdvanceTTL)
}
