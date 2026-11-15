package directpeer

import (
	"context"
	"errors"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/netdefense-io/ndagent/internal/logging"
)

// ErrClientSilent is what a Carrier's Run returns when the client sent
// nothing at all for the receive timeout.
var ErrClientSilent = errors.New("the client sent nothing for the receive timeout")

// Carrier speaks a session's frames over a companion's pipes and serves the
// streams the client opens. The agent's stream services are its
// implementation; this package only needs to run it and to end it.
type Carrier interface {
	// Run carries the session until the stream of frames ends, and returns
	// why: nil when the other end closed it or Close was called,
	// ErrClientSilent, or another error of the transport.
	Run(ctx context.Context, connected <-chan struct{}) error
	// LastActivity is when the last frame other than a keepalive went either
	// way, or the zero time before any.
	LastActivity() time.Time
	// Close ends every stream and what serves it, and closes the writing
	// side toward the companion, which is the request to end the session.
	Close()
}

// Reporter records and sends what the device answers about a session. The
// agent's control connection is its implementation.
type Reporter interface {
	// ReportConnectResult returns an error only when the result is not on
	// record; one that is recorded and not sent yet is no error.
	ReportConnectResult(taskID string, result Result) error
	// ResendConnectResult sends the session result on record for the task
	// again, and reports whether there was one.
	ResendConnectResult(taskID string) bool
}

// OpenRequest is a verified task that asks for a session.
type OpenRequest struct {
	TaskID string
	// Exp is the task's signed expiry, in Unix seconds.
	Exp       int64
	ConnectID string
	Protocol  int
	Relay     Relay
	// Sealed is the session's secret as the task carries it.
	Sealed string
	// AdmitServer and AdmitClient are the node public keys registered with
	// the relay for the session.
	AdmitServer, AdmitClient string
	// The session's limits in seconds, and how many sessions the device may
	// carry at once.
	PairSeconds, IdleSeconds, MaxSeconds, DeviceSessions int

	// Unseal opens Sealed with the device's identity key, which never leaves
	// its holder.
	Unseal func(sealed string) (*Secret, error)
	// Carry makes the Carrier of the session once it listens.
	Carry func(s *Session) Carrier
}

type liveSession struct {
	connectID string
	taskID    string
	closeOnce sync.Once
	closeReq  chan struct{}
}

func (l *liveSession) requestClose() { l.closeOnce.Do(func() { close(l.closeReq) }) }

type queuedReport struct {
	taskID string
	result Result
	// recorded runs once the result is on record.
	recorded func()
}

// Manager carries the device's sessions. There is one per agent process: a
// session outlives the control connection its task arrived on, and its end
// is reported on whichever connection is there then.
type Manager struct {
	starter    *Starter
	ledger     *Ledger
	deviceUUID string
	log        *zap.SugaredLogger
	sessions   Sessions

	mu       sync.Mutex
	live     map[string]*liveSession // by session id, from the replay check on
	starting map[string]struct{}     // tasks being opened
	stopped  bool
	stopping chan struct{}
	wg       sync.WaitGroup

	repMu    sync.Mutex
	reporter Reporter
	queue    []queuedReport

	touchEvery time.Duration
}

// NewManager returns the manager of this process's sessions. The sessions
// the previous process left open are reported as ended as soon as a Reporter
// is set.
func NewManager(starter *Starter, ledger *Ledger, deviceUUID string) *Manager {
	m := &Manager{
		starter:    starter,
		ledger:     ledger,
		deviceUUID: deviceUUID,
		log:        logging.Named("directpeer"),
		live:       make(map[string]*liveSession),
		starting:   make(map[string]struct{}),
		stopping:   make(chan struct{}),
		touchEvery: time.Minute,
	}
	for _, o := range ledger.Orphans() {
		end := SessionEnd{Reason: o.EndReason, Duration: o.EndedAt.Sub(o.ListeningAt), Path: o.Path}
		if o.EndReason == "" {
			// The process died with the session open, and its companion with it.
			end.Reason, end.Duration = EndError, o.LastSeen.Sub(o.ListeningAt)
		}
		if !o.ConnectedAt.IsZero() {
			end.Paired, end.PairedAfter = true, o.ConnectedAt.Sub(o.ListeningAt)
		}
		m.log.Warnw("A remote session of the previous agent process is reported as ended",
			"connect_id", o.ConnectID, "task_id", o.TaskID, "reason", end.Reason)
		connectID := o.ConnectID
		m.queue = append(m.queue, queuedReport{
			taskID:   o.TaskID,
			result:   SessionEndResult(connectID, end),
			recorded: func() { m.sessionRecorded(connectID) },
		})
	}
	return m
}

func (m *Manager) sessionRecorded(connectID string) {
	if err := m.ledger.Ended(connectID); err != nil {
		m.log.Warnw("Cannot note that a remote session's end is on record; it will be reported again after a restart",
			"connect_id", connectID, "error", err)
	}
}

// SetReporter names where results go from now on, and hands it the ones
// that waited for one. Call it for each control connection before that
// connection replays what its task store holds.
func (m *Manager) SetReporter(r Reporter) {
	m.repMu.Lock()
	defer m.repMu.Unlock()
	m.reporter = r
	m.flushLocked()
}

// maxQueuedResults bounds the results that wait for a Reporter. A device
// carries at most MaxDeviceSessions sessions and each waits with two results
// at most, so only refusals made with no connection to report them could
// fill it, and the oldest of those is the one to lose.
const maxQueuedResults = 256

func (m *Manager) flushLocked() {
	for len(m.queue) > 0 && m.reporter != nil {
		q := m.queue[0]
		err := m.reporter.ReportConnectResult(q.taskID, q.result)
		switch {
		case errors.Is(err, ErrNotAResult):
			// It will never be recorded: keeping it would hold back every
			// result behind it, of every session.
			m.log.Errorw("A remote session result the contract refuses was dropped", "task_id", q.taskID, "status", q.result.Status)
			m.queue = m.queue[1:]
			continue
		case err != nil:
			m.log.Warnw("A remote session result cannot be recorded yet", "task_id", q.taskID, "error", err)
			return
		}
		m.queue = m.queue[1:]
		if q.recorded != nil {
			q.recorded()
		}
	}
}

// report records and sends a result, in the order results were made. One
// that cannot be recorded now waits for the next result or Reporter.
func (m *Manager) report(taskID string, result Result, recorded func()) {
	if _, valid := CleanResult(result.Status, result.Connect); !valid {
		m.log.Errorw("A remote session result the contract refuses was not reported", "task_id", taskID, "status", result.Status)
		return
	}
	m.repMu.Lock()
	defer m.repMu.Unlock()
	if len(m.queue) >= maxQueuedResults {
		m.log.Errorw("Too many remote session results wait to be recorded; the oldest is dropped", "task_id", m.queue[0].taskID)
		m.queue = m.queue[1:]
	}
	m.queue = append(m.queue, queuedReport{taskID: taskID, result: result, recorded: recorded})
	m.flushLocked()
}

func (m *Manager) resend(taskID string) bool {
	m.repMu.Lock()
	defer m.repMu.Unlock()
	for _, q := range m.queue {
		if q.taskID == taskID {
			return true // its answer is waiting to be recorded
		}
	}
	return m.reporter != nil && m.reporter.ResendConnectResult(taskID)
}

// Refuse answers an open task the caller turned away before it got here. A
// task that already has an answer keeps it: delivered again after the device's
// policy changed, or while the agent stops, it must not turn a session that
// is running into a refused one.
func (m *Manager) Refuse(taskID, connectID, reason string) {
	if m.resend(taskID) {
		m.log.Infow("The open task was delivered again; its answer is sent again", "task_id", taskID, "connect_id", connectID)
		return
	}
	m.log.Warnw("Remote session refused", "task_id", taskID, "connect_id", connectID, "reason", reason)
	m.report(taskID, FailedResult(connectID, reason), nil)
}

// Sessions is how many sessions the device carries now.
func (m *Manager) Sessions() int { return m.sessions.Open() }

// Open runs the checks a session must pass, in the contract's order from the
// companion on, starts the session and answers the task: ready, or refused
// and why. It returns once that answer is made; a session that started then
// runs on by itself, whatever happens to ctx, until something ends it, and
// answers the task a second time.
//
// ctx bounds the start only. A start it cuts short opens nothing.
func (m *Manager) Open(ctx context.Context, req OpenRequest) {
	log := m.log.With("task_id", req.TaskID, "connect_id", req.ConnectID)

	m.mu.Lock()
	if _, busy := m.starting[req.TaskID]; busy {
		m.mu.Unlock()
		log.Infow("The open task was delivered again while it is being answered")
		return
	}
	stopped := m.stopped
	if !stopped {
		m.starting[req.TaskID] = struct{}{}
	}
	m.mu.Unlock()
	if stopped {
		m.Refuse(req.TaskID, req.ConnectID, FailInternal)
		return
	}
	defer func() {
		m.mu.Lock()
		delete(m.starting, req.TaskID)
		m.mu.Unlock()
	}()

	// The same task again is not a new request and not a replay: the control
	// plane did not get the answer. It gets the one on record, and nothing
	// starts. A refusal here would end a session that is running.
	if m.resend(req.TaskID) {
		log.Infow("The open task was delivered again; its answer is sent again")
		return
	}
	if task, known := m.ledger.Lookup(req.ConnectID); known && task == req.TaskID {
		m.mu.Lock()
		_, running := m.live[req.ConnectID]
		m.mu.Unlock()
		if running {
			log.Infow("The open task of a running session was delivered again; it is told again that the session is ready")
			m.report(req.TaskID, ListeningResult(req.ConnectID), nil)
		} else {
			log.Infow("The open task of a session that is over was delivered again; nothing starts")
		}
		return
	}

	refuse := func(reason, detail string) {
		log.Warnw("Remote session refused", "reason", reason, "detail", detail)
		m.report(req.TaskID, FailedResult(req.ConnectID, reason), nil)
	}
	startFailure := func(err error) {
		var start *StartError
		if errors.As(err, &start) {
			refuse(start.Reason, start.Error()+" "+start.Detail)
			return
		}
		refuse(FailInternal, "the start was cut short: "+err.Error())
	}

	// The companion: there, the agent's build, and of the protocol asked for.
	pending, err := m.starter.Launch(ctx)
	if err != nil {
		startFailure(err)
		return
	}
	opened := false
	defer func() {
		if !opened {
			pending.Abort()
		}
	}()
	if req.Protocol != Protocol {
		refuse(FailProtocolMismatch, "")
		return
	}

	// A place among the device's sessions.
	limits, ok := LimitsFor(req.PairSeconds, req.IdleSeconds, req.MaxSeconds)
	if !ok || req.DeviceSessions <= 0 {
		refuse(FailUnsupportedAction, "a limit is not above zero")
		return
	}
	release, ok := m.sessions.Acquire(req.DeviceSessions)
	if !ok {
		refuse(FailTooManySessions, "")
		return
	}
	started := false
	defer func() {
		if !started {
			release()
		}
	}()

	// The secret: opens with this device's key, and was made for this task.
	if req.Unseal == nil || req.Carry == nil {
		refuse(FailInternal, "the request is incomplete")
		return
	}
	secret, err := req.Unseal(req.Sealed)
	if err != nil {
		refuse(FailUnsealFailed, err.Error())
		return
	}
	defer secret.Wipe()
	if err := secret.CheckBindings(Bindings{
		ConnectID:     req.ConnectID,
		DeviceUUID:    m.deviceUUID,
		Exp:           req.Exp,
		RelayHost:     req.Relay.Host,
		RelayPort:     req.Relay.Port,
		RelaySTUNPort: req.Relay.STUNPort,
	}); err != nil {
		refuse(FailBindingMismatch, err.Error())
		return
	}

	// The id: never used. It is on disk before the companion is given a key.
	// Accepting the id and making the session known to a close instruction
	// are one step: a close finds the session, or its id is remembered first
	// and the open is refused.
	live := &liveSession{connectID: req.ConnectID, taskID: req.TaskID, closeReq: make(chan struct{})}
	m.mu.Lock()
	accepted, err := m.ledger.Accept(req.ConnectID, req.TaskID, req.Exp)
	if err == nil && accepted == AcceptedNew {
		m.live[req.ConnectID] = live
	}
	m.mu.Unlock()
	switch {
	case err != nil:
		refuse(FailInternal, "the session id cannot be checked: "+err.Error())
		return
	case accepted == AcceptedReplayed:
		refuse(FailReplayed, "")
		return
	case accepted == AcceptedSameTask:
		log.Infow("The open task was delivered again; nothing starts")
		return
	}
	defer func() {
		if !started {
			m.forget(live)
		}
	}()

	// The keys: the ones the client sealed and the relay admits.
	keys, err := secret.Keys(req.AdmitServer, req.AdmitClient)
	if err != nil {
		refuse(FailKeyMismatch, err.Error())
		return
	}
	secret.Wipe()

	spec := Spec{Relay: req.Relay, Keys: keys, OnEvent: func(e Event) { m.noteEvent(req.ConnectID, e) }}
	opened = true
	sess, err := pending.Open(ctx, spec)
	keys.Wipe()
	spec.Keys.Wipe()
	if err != nil {
		startFailure(err)
		return
	}

	if err := m.ledger.Listening(req.ConnectID, Protocol, sess.ListeningAt); err != nil {
		log.Warnw("Cannot record that the session listens; if the agent stops unexpectedly its end will not be reported", "error", err)
	}
	log.Infow("Remote session ready", "relay", req.Relay.ID,
		"pairing", limits.Pairing.String(), "idle", limits.Idle.String(), "lifetime", limits.Lifetime.String())
	m.report(req.TaskID, ListeningResult(req.ConnectID), nil)

	started = true
	carrier := req.Carry(sess)
	m.mu.Lock()
	stopped = m.stopped
	if !stopped {
		m.wg.Add(1)
	}
	m.mu.Unlock()
	if stopped {
		// The agent began to stop while the session started: it ends at once.
		m.run(live, sess, limits, carrier, release)
		return
	}
	go func() {
		defer m.wg.Done()
		m.run(live, sess, limits, carrier, release)
	}()
}

func (m *Manager) forget(live *liveSession) {
	m.mu.Lock()
	if m.live[live.connectID] == live {
		delete(m.live, live.connectID)
	}
	m.mu.Unlock()
}

// noteEvent keeps on disk what a session's end will report, for the process
// that finds the session open after this one died.
func (m *Manager) noteEvent(connectID string, e Event) {
	var err error
	switch e.Event {
	case EventConnected:
		err = m.ledger.Connected(connectID, time.Now())
	case EventPath:
		err = m.ledger.Path(connectID, e.Path)
	}
	if err != nil {
		m.log.Debugw("Cannot record a session event", "connect_id", connectID, "event", e.Event, "error", err)
	}
}

// run carries a session that listens until something ends it, and reports
// its end, once.
func (m *Manager) run(live *liveSession, sess *Session, limits Limits, carrier Carrier, release func()) {
	defer release()
	log := m.log.With("task_id", live.taskID, "connect_id", live.connectID)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	transport := make(chan error, 1)
	go func() { transport <- carrier.Run(ctx, sess.Connected()) }()
	limit := make(chan string, 1)
	go func() {
		if reason := limits.Watch(ctx, sess.ListeningAt, sess.Connected(), carrier.LastActivity); reason != "" {
			limit <- reason
		}
	}()
	touch := time.NewTicker(m.touchEvery)
	defer touch.Stop()

	// The first cause is the session's end; whatever follows from ending it
	// (the companion exits, the frames stop) is not another.
	var (
		reason         string
		transportErr   error
		transportEnded bool
	)
wait:
	for {
		select {
		case reason = <-limit:
		case <-live.closeReq:
			reason = EndClosed
		case <-m.stopping:
			reason = EndAgentShutdown
		case transportErr = <-transport:
			transportEnded = true
		case <-sess.Done():
		case <-touch.C:
			m.ledger.Touch()
			continue
		}
		break wait
	}
	endedAt := time.Now()

	carrier.Close()
	sess.Stop()
	cancel()
	if !transportEnded {
		transportErr = <-transport
	}
	if reason == "" {
		reason = endReason(transportErr, sess.Exit())
	}

	end := SessionEnd{Reason: reason, Duration: endedAt.Sub(sess.ListeningAt), Path: sess.Path()}
	if at, ok := sess.ConnectedAt(); ok {
		end.Paired, end.PairedAfter = true, at.Sub(sess.ListeningAt)
	}
	log.Infow("Remote session ended", "reason", reason,
		"duration", end.Duration.Round(time.Second).String(), "client_connected", end.Paired, "path", end.Path)

	if err := m.ledger.Ending(live.connectID, reason, endedAt); err != nil {
		log.Warnw("Cannot record how the session ended", "error", err)
	}
	m.forget(live)
	connectID := live.connectID
	m.report(live.taskID, SessionEndResult(connectID, end), func() { m.sessionRecorded(connectID) })
}

// endReason is why a session ended that nothing on this side ended: the
// frames stopped or the companion exited. The companion's own word is the
// authority; the transport's error only tells a silent client from the rest.
func endReason(transportErr error, exit Exit) string {
	switch {
	case errors.Is(transportErr, ErrClientSilent):
		return EndClientTimeout
	case exit.Said && exit.Reason == ReasonPeerClosed:
		return EndClientClosed
	case exit.Said && exit.Reason == ReasonConnectionLost:
		return EndClientTimeout
	case !exit.Said:
		return EndCompanionExited
	default:
		return EndError
	}
}

// Close is the close instruction for the session connectID, which expires at
// exp (Unix seconds): the session ends, and the id can start nothing until
// then. It answers the instruction's task.
func (m *Manager) Close(taskID, connectID string, exp int64) {
	m.mu.Lock()
	if err := m.ledger.RememberClosed(connectID, exp); err != nil {
		m.log.Errorw("Cannot record a close instruction; an open with this id that arrives later could start", "connect_id", connectID, "error", err)
	}
	live, found := m.live[connectID]
	m.mu.Unlock()
	if found {
		live.requestClose()
	}
	m.log.Infow("Close instruction for a remote session", "task_id", taskID, "connect_id", connectID, "found", found)
	m.report(taskID, ClosedResult(connectID, found), nil)
}

// Shutdown ends every session because the agent stops, and waits up to wait
// for their ends to be recorded. No session starts after it.
func (m *Manager) Shutdown(wait time.Duration) {
	m.mu.Lock()
	if !m.stopped {
		m.stopped = true
		close(m.stopping)
	}
	m.mu.Unlock()

	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		m.log.Warnw("Remote sessions were still ending when the agent stopped")
	}
}
