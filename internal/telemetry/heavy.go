package telemetry

import (
	"context"
	"math/rand"
	"sync"
	"time"

	"github.com/netdefense-io/ndagent/internal/firmware"
	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/opnapi"
	"github.com/netdefense-io/ndagent/internal/util"
	"go.uber.org/zap"
)

// HeavySnapshot bundles the OPNsense-API-derived fields that are too
// expensive to probe on every 60 s heartbeat. The collector refreshes them
// in a background goroutine; the heartbeat sender embeds the latest cached
// pointer, or nothing while there is none.
//
// Each block carries its own `as_of`, the agent-clock time it was collected.
// A block whose probe failed is carried over with its original stamp, and a
// snapshot restored after a restart keeps the stamps it was saved with.
// `collected_at` is when the refresh that collected the newest block began.
type HeavySnapshot struct {
	Services    *ServicesBlock `json:"services,omitempty"`
	Updates     *UpdatesBlock  `json:"updates,omitempty"`
	Certs       *CertsBlock    `json:"certs,omitempty"`
	CollectedAt float64        `json:"collected_at"`
}

// Each block's collectedAt is the as_of it was collected with, set only when
// restamp has moved AsOf: the moved stamp lives in memory, and saving puts the
// collected one back (asCollected).

type ServicesBlock struct {
	Items       []opnapi.ServiceEntry `json:"items"`
	AsOf        float64               `json:"as_of"`
	collectedAt float64
}

type UpdatesBlock struct {
	*opnapi.FirmwareStatus
	AsOf        float64 `json:"as_of"`
	collectedAt float64
}

type CertsBlock struct {
	Items       []opnapi.CertEntry `json:"items"`
	AsOf        float64            `json:"as_of"`
	collectedAt float64
}

const (
	// heavyRefreshInterval is how often services, certificates and the
	// firmware status are read. Reading the status starts no check.
	heavyRefreshInterval = 15 * time.Minute

	// firmwareCheckInterval is how often the agent makes OPNsense check for
	// updates. A check refetches the changelog and every repository catalog,
	// about 0.5 MB, nearly all from pkg.opnsense.org, a single host that is
	// not ours, so it runs a few times a day, each interval moved by up to
	// firmwareCheckJitter either way, plus when something calls for one.
	firmwareCheckInterval = 6 * time.Hour
	firmwareCheckJitter   = 25 * time.Minute

	// firmwareCheckStagger spreads the check a start calls for over the
	// first minute, so a fleet that reconnects together does not hit the
	// mirror together.
	firmwareCheckStagger = time.Minute

	// firmwareCheckRetry is when a check that a busy OPNsense turned away is
	// tried again.
	firmwareCheckRetry = 2 * time.Minute

	// A probe that fails keeps its previous block while that block is at most
	// this old: 15 minutes past its next refresh for services and
	// certificates, a day for the update reading.
	servicesMaxAge = heavyRefreshInterval + 15*time.Minute
	certsMaxAge    = servicesMaxAge
	updatesMaxAge  = 24 * time.Hour

	// clockAhead is how far after the clock a stamp may be and still be taken
	// as written. One further ahead was written by a clock that was ahead (a
	// fast clock, or one stepped back since), or the clock is behind now (a
	// dead or local-time RTC before NTP): in memory its block is stamped now,
	// so its bound runs from here and not from a moment that may be days
	// away, and what is saved keeps the stamp it was collected with.
	clockAhead = 5 * time.Minute

	// bootSettle is how long after a boot a service that is not running may
	// still be starting: the agent starts while rc runs the start scripts, so
	// its first reading can catch a service a second before it is up. Within
	// it such a reading does not replace the services block in hand, and the
	// services are read again servicesRecheck later.
	bootSettle      = 5 * time.Minute
	servicesRecheck = time.Minute
)

// firstGatherRetries is how soon a gather is retried after a start until one
// has had every probe answer: after a boot the web GUI the API runs behind
// may not be up yet.
var firstGatherRetries = []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute}

// failedCheckRetries is how soon a check whose result was a failure (the
// mirror could not be used) is tried again, one step per failure in a row;
// past the last step the regular interval applies.
var failedCheckRetries = []time.Duration{10 * time.Minute, 30 * time.Minute, time.Hour}

// Variables so tests do not sit through them: how a check is waited for, and
// the most a check is put off after an update or upgrade ended, so the devices
// a scheduled task updated together do not all check in the same seconds.
var (
	firmwareCheckPoll    = 3 * time.Second
	firmwareCheckTimeout = 120 * time.Second
	firmwareOutcomeDelay = 2 * time.Minute
)

// HeavyCollector owns the cache. There is one per agent process: lifecycle.go
// creates it at start and every WebSocket phase wires the same one, so the
// cache survives reconnects and returns to the registration phase.
type HeavyCollector struct {
	client    *opnapi.Client
	cachePath string
	log       *zap.SugaredLogger

	// now, random, installedVersion and bootTime are the clock, the source of
	// stagger and jitter (uniform in [0, n)), the installed release ("" when
	// it cannot be read) and the device's boot time in unix seconds; tests
	// replace them.
	now              func() time.Time
	random           func(n time.Duration) time.Duration
	installedVersion func() string
	bootTime         func() (int64, error)

	mu    sync.RWMutex
	cache *HeavySnapshot

	// Only Run's goroutine touches these.
	sched heavySchedule
	// installed is the release the last gather or check saw.
	installed string
	// reading is the latest completed reading of the installed release seen
	// (restored, read or checked), clean or not: it decides whether a start
	// has a fresh reading, which the update block cannot when it carries a
	// good reading over a failed check.
	reading *opnapi.FirmwareStatus
	// noResult: the last firmware status read found no check result on the
	// device, which is what OPNsense has after a boot until a check runs.
	noResult bool
}

// NewHeavyCollector returns a collector reading OPNsense through client and
// keeping its snapshot at cachePath between processes ("" keeps none).
func NewHeavyCollector(client *opnapi.Client, cachePath string) *HeavyCollector {
	return &HeavyCollector{
		client:           client,
		cachePath:        cachePath,
		log:              logging.Named("heavy-telemetry"),
		now:              time.Now,
		random:           randomDuration,
		installedVersion: localInstalledVersion,
		bootTime:         firmware.BootTime,
	}
}

// booted is when the device booted, zero when that cannot be read.
func (h *HeavyCollector) booted() time.Time {
	at, err := h.bootTime()
	if err != nil || at <= 0 {
		return time.Time{}
	}
	return time.Unix(at, 0)
}

// settling reports whether the device booted less than bootSettle before now.
func (h *HeavyCollector) settling(now time.Time) bool {
	booted := h.booted()
	return !booted.IsZero() && now.Sub(booted) < bootSettle
}

func randomDuration(n time.Duration) time.Duration {
	if n <= 0 {
		return 0
	}
	return time.Duration(rand.Int63n(int64(n)))
}

// localInstalledVersion reads the installed release from the local version
// file, which needs neither the API nor its web server.
func localInstalledVersion() string {
	release, err := opnapi.InstalledReleaseFromFile()
	if err != nil {
		return ""
	}
	return release.Raw
}

// Run blocks until ctx is cancelled. It gathers services, certificates and
// the firmware status at once and then every heavyRefreshInterval, sooner
// while a start's first gather has not had every probe answer
// (firstGatherRetries) or right after a boot a service was not running yet
// (servicesRecheck). A firmware check runs one firmwareCheckInterval
// (jittered) after the previous one, sooner after a failed one
// (failedCheckRetries), and when something calls for it: a start without a
// fresh reading of the installed release, which a boot always is (after a
// random stagger), a change of the installed release, or the end of an
// update or upgrade (after a random delay).
func (h *HeavyCollector) Run(ctx context.Context) error {
	h.log.Infow("heavy-telemetry started",
		"refresh_interval", heavyRefreshInterval.String(),
		"firmware_check_interval", firmwareCheckInterval.String(),
	)

	h.start(ctx)
	h.log.Infow("heavy-telemetry: first firmware check planned",
		"in", h.sched.nextCheck.Sub(h.now()).Round(time.Second).String())

	for {
		timer := time.NewTimer(h.sched.next().Sub(h.now()))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-firmware.Outcomes():
			timer.Stop()
			delay := h.random(firmwareOutcomeDelay)
			h.log.Infow("heavy-telemetry: a firmware update ended; checking for updates",
				"in", delay.Round(time.Second).String())
			h.sched.checkBy(h.now().Add(delay))
		case <-timer.C:
		}

		if ctx.Err() == nil && !h.now().Before(h.sched.nextGather) {
			h.sched.gathered(h.now(), h.gather(ctx))
		}
		if ctx.Err() == nil && !h.now().Before(h.sched.nextCheck) {
			h.sched.checked(h.now(), h.check(ctx), h.jitter())
		}
	}
}

// start is what Run does before its loop: the first gather, and the plan for
// the first check.
func (h *HeavyCollector) start(ctx context.Context) {
	h.sched.gathered(h.now(), h.gather(ctx))
	h.sched.planFirstCheck(h.now(), h.startReading(), h.random(firmwareCheckStagger), h.jitter())
}

// startReading is the reading a start may count as fresh, or nil. OPNsense
// clears its check result at boot, so after a boot the reading in hand is not
// one the device still has, and the boot gets a check of its own: nil when
// the reading was made before the device booted, or when the device answered
// that it holds no result within bootSettle of the boot. Later the answer
// means a check somebody else started is running, and the next status read
// picks its result up. A start later in the same boot finds the result of the
// boot's check. Without the boot time a start is taken for a restart.
func (h *HeavyCollector) startReading() *opnapi.FirmwareStatus {
	booted := h.booted()
	switch {
	case h.reading == nil:
		return nil
	case booted.IsZero():
		return h.reading
	case time.Unix(h.reading.LastCheckUnix, 0).Before(booted):
		return nil
	case h.noResult && h.now().Sub(booted) < bootSettle:
		return nil
	}
	return h.reading
}

// jitter is uniform in [-firmwareCheckJitter, firmwareCheckJitter).
func (h *HeavyCollector) jitter() time.Duration {
	return h.random(2*firmwareCheckJitter) - firmwareCheckJitter
}

// Snapshot returns the most recent cached snapshot: nil while there is no
// block to send, which the heartbeat sender treats as "omit the `heavy`
// field".
func (h *HeavyCollector) Snapshot() *HeavySnapshot {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.cache
}

// gather reads services, certificates and the firmware status, and reports
// whether every probe answered. A probe that failed keeps its previous block
// while that block is young enough, and so does a status without a usable
// result: no check has completed, or the one that did ran against another
// release. Neither ever turns into an empty reading, and a failed check does
// not replace a good one (updatesFrom).
func (h *HeavyCollector) gather(ctx context.Context) bool {
	start := h.now()
	prev := restamp(h.Snapshot(), start)
	next := &HeavySnapshot{}
	allOK := true
	services, certs, updates := blockFresh, blockFresh, blockFresh
	// While a start's quick retries last, a block is kept whatever its age,
	// so the snapshot restored at start stays until the API answers.
	grace := h.sched.starting()

	if items, err := h.client.ListServices(ctx); err != nil {
		allOK = false
		h.log.Warnw("heavy-telemetry: service list failed", "error", err)
		next.Services = keptServices(prev, start, grace)
		services = carried(next.Services != nil)
	} else if stopped := stoppedServices(items); len(stopped) > 0 && h.settling(start) {
		// They may still be starting: read them again soon, and until then
		// keep the block in hand, if any, rather than report them down.
		h.sched.gatherBy = h.now().Add(servicesRecheck)
		h.log.Infow("heavy-telemetry: services not running this soon after the boot; reading them again shortly",
			"not_running", stopped, "in", servicesRecheck.String())
		if prev != nil && prev.Services != nil {
			next.Services, services = prev.Services, blockKept
		} else {
			next.Services = &ServicesBlock{Items: items, AsOf: unixSeconds(h.now())}
		}
	} else {
		next.Services = &ServicesBlock{Items: items, AsOf: unixSeconds(h.now())}
	}

	if items, err := h.client.ListCerts(ctx); err != nil {
		allOK = false
		h.log.Warnw("heavy-telemetry: cert list failed", "error", err)
		next.Certs = keptCerts(prev, start, grace)
		certs = carried(next.Certs != nil)
	} else {
		next.Certs = &CertsBlock{Items: items, AsOf: unixSeconds(h.now())}
	}

	installed := h.installedVersion()
	st, err := h.client.GetFirmwareStatus(ctx)
	if err == nil {
		h.noResult = !st.Completed()
	}
	switch {
	case err != nil:
		allOK = false
		h.log.Warnw("heavy-telemetry: firmware status read failed", "error", err)
	case st.Completed() && !st.Stale():
		h.reading = st
		next.Updates = updatesFrom(st, prev, h.now())
	}
	if installed == "" && st != nil {
		installed = st.OPNsenseVersion
	}
	switch {
	case next.Updates == nil:
		next.Updates = keptUpdates(prev, installed, start, grace)
		updates = carried(next.Updates != nil)
	case prev != nil && next.Updates == prev.Updates:
		updates = blockKept
	}
	if h.reading != nil && installed != "" && h.reading.OPNsenseVersion != installed {
		h.reading = nil
	}
	h.noteInstalled(installed, start)

	fresh := services == blockFresh || certs == blockFresh || updates == blockFresh
	h.publish(next, prev, start, fresh)
	h.log.Infow("heavy-telemetry refresh complete",
		"duration_ms", h.now().Sub(start).Milliseconds(),
		"services", services,
		"updates", updates,
		"certs", certs,
	)
	return allOK
}

// What a refresh did with a block, as logged.
const (
	blockFresh = "fresh"
	blockKept  = "kept"
	blockNone  = "none"
)

// stoppedServices names the services that are not running.
func stoppedServices(items []opnapi.ServiceEntry) []string {
	var stopped []string
	for _, item := range items {
		if !item.Running {
			stopped = append(stopped, item.Name)
		}
	}
	return stopped
}

func carried(kept bool) string {
	if kept {
		return blockKept
	}
	return blockNone
}

// noteInstalled remembers the installed release and makes a check due when
// it changed: what is pending is not the same for another release.
func (h *HeavyCollector) noteInstalled(installed string, now time.Time) {
	if installed == "" {
		return
	}
	if h.installed != "" && installed != h.installed {
		h.log.Infow("heavy-telemetry: the installed release changed; checking for updates",
			"from", h.installed, "to", installed)
		h.sched.checkBy(now)
	}
	h.installed = installed
}

// publish installs next as the cache, or nil when it holds no block. A
// snapshot with something freshly collected is stamped with at and saved for
// the next process; one that only carries blocks over keeps the previous
// stamp.
func (h *HeavyCollector) publish(next, prev *HeavySnapshot, at time.Time, fresh bool) {
	switch {
	case next.Services == nil && next.Updates == nil && next.Certs == nil:
		next = nil
	case fresh || prev == nil:
		next.CollectedAt = unixSeconds(at)
	default:
		next.CollectedAt = prev.CollectedAt
	}

	h.mu.Lock()
	h.cache = next
	h.mu.Unlock()

	if fresh && next != nil {
		h.save(next)
	}
}

// checkResult is how a firmware check attempt ended.
type checkResult int

const (
	// checkBusy: no check ran because a firmware job holds OPNsense (an
	// update in progress, a check somebody else started, a request of ours
	// that was dropped). It is tried again soon.
	checkBusy checkResult = iota
	// checkUnreachable: no check ran because the API did not answer. It is
	// tried again with the next gather.
	checkUnreachable
	// checkDone: the check finished and its result was read.
	checkDone
	// checkFailed: the check finished, and could not use the mirror. It is
	// tried again sooner than the regular interval (failedCheckRetries).
	checkFailed
	// checkUnfinished: the check was still running when the wait ended; a
	// later gather reads its result.
	checkUnfinished
)

// check makes OPNsense check for updates and reads the result. It starts
// none while a firmware update is in progress, as far as this process knows
// (firmware.Busy) or OPNsense says (/running): a check takes the lock the
// update needs and truncates the progress log the update is judged by. It
// waits on /running rather than for a fixed time, and takes a result only
// when its last_check differs from the one before the request: OPNsense
// drops a request that finds its lock held, and the old result stays.
func (h *HeavyCollector) check(ctx context.Context) checkResult {
	if firmware.Busy() {
		h.log.Debugw("heavy-telemetry: a firmware update is in progress; the firmware check waits")
		return checkBusy
	}
	running, err := h.client.GetFirmwareRunning(ctx)
	if err != nil || running == nil {
		h.log.Debugw("heavy-telemetry: the firmware backend cannot be read; the firmware check waits", "error", err)
		return checkUnreachable
	}
	if running.Status != "ready" {
		h.log.Debugw("heavy-telemetry: the firmware backend is busy; the firmware check waits", "backend", running.Status)
		return checkBusy
	}
	before, err := h.client.GetFirmwareStatus(ctx)
	if err != nil {
		h.log.Debugw("heavy-telemetry: the firmware status cannot be read; the firmware check waits", "error", err)
		return checkUnreachable
	}

	started := h.now()
	if err := h.client.TriggerFirmwareCheck(ctx); err != nil {
		h.log.Warnw("heavy-telemetry: firmware check trigger failed", "error", err)
		return checkUnreachable
	}

	st, ran := h.awaitCheck(ctx, before.LastCheck)
	switch {
	case st != nil:
		return h.acceptCheck(st, started)
	case ran:
		h.log.Infow("heavy-telemetry: the firmware check is still running; a later refresh reads its result",
			"waited", firmwareCheckTimeout.String())
		return checkUnfinished
	default:
		if ctx.Err() == nil {
			h.log.Infow("heavy-telemetry: OPNsense did not run the firmware check; it is tried again soon")
		}
		return checkBusy
	}
}

// awaitCheck polls /running until the check is over and returns its result,
// or nil when none arrived within firmwareCheckTimeout. ran says whether the
// check was seen running.
func (h *HeavyCollector) awaitCheck(ctx context.Context, before string) (*opnapi.FirmwareStatus, bool) {
	ran := false
	deadline := time.Now().Add(firmwareCheckTimeout)
	for {
		if util.ShutdownAwareSleep(ctx, firmwareCheckPoll) != nil {
			return nil, ran
		}
		running, err := h.client.GetFirmwareRunning(ctx)
		switch {
		case err != nil || running == nil:
		case running.Status != "ready":
			ran = true
		default:
			if st, err := h.client.GetFirmwareStatus(ctx); err == nil && st.Completed() && st.LastCheck != before {
				return st, true
			}
		}
		if time.Now().After(deadline) {
			return nil, ran
		}
	}
}

// acceptCheck takes a check's result and reports how the check went. The
// result becomes the update block (updatesFrom), unless it names another
// release than the installed one.
func (h *HeavyCollector) acceptCheck(st *opnapi.FirmwareStatus, started time.Time) checkResult {
	if st.Stale() {
		h.log.Warnw("heavy-telemetry: the firmware check's result names another release than the installed one; not using it",
			"checked", st.CheckedVersion, "installed", st.OPNsenseVersion)
		return checkDone
	}
	h.reading = st
	if st.OPNsenseVersion != "" {
		h.installed = st.OPNsenseVersion
	}
	now := h.now()
	prev := restamp(h.Snapshot(), now)
	block := updatesFrom(st, prev, now)
	kept := prev != nil && block == prev.Updates
	if !kept {
		next := &HeavySnapshot{Updates: block}
		if prev != nil {
			next.Services, next.Certs = prev.Services, prev.Certs
		}
		h.publish(next, prev, started, true)
	}
	if !st.Clean() {
		h.log.Warnw("heavy-telemetry: the firmware check could not use the mirror",
			"status", st.Status,
			"connection", st.Connection,
			"repository", st.Repository,
			"previous_reading_kept", kept,
		)
		return checkFailed
	}
	h.log.Infow("heavy-telemetry: firmware check complete",
		"duration_ms", now.Sub(started).Milliseconds(),
		"status", st.Status,
		"opnsense_version", st.OPNsenseVersion,
		"opnsense_latest", st.OPNsenseLatest,
		"upgrade_major_version", st.UpgradeMajorVersion,
	)
	return checkDone
}

// updatesFrom is the update block a completed reading of the installed
// release gives: the reading itself, unless it is a check that failed while a
// good reading young enough to keep is in hand, which stays with its as_of. A
// failed reading is sent only when there is no good one.
func updatesFrom(st *opnapi.FirmwareStatus, prev *HeavySnapshot, now time.Time) *UpdatesBlock {
	if !st.Clean() {
		if good := goodUpdates(prev, st.OPNsenseVersion, now); good != nil {
			return good
		}
	}
	return &UpdatesBlock{FirmwareStatus: st, AsOf: unixSeconds(now)}
}

// goodUpdates is the previous update block when it is a clean reading of the
// given release, at most updatesMaxAge old.
func goodUpdates(prev *HeavySnapshot, release string, now time.Time) *UpdatesBlock {
	if prev == nil || !describes(prev.Updates, release) || !prev.Updates.Clean() ||
		!young(prev.Updates.AsOf, updatesMaxAge, now) {
		return nil
	}
	return prev.Updates
}

// keptServices is the previous services block while it is young enough, or
// of any age during the start's grace.
func keptServices(prev *HeavySnapshot, now time.Time, grace bool) *ServicesBlock {
	if prev == nil || prev.Services == nil || !(grace || young(prev.Services.AsOf, servicesMaxAge, now)) {
		return nil
	}
	return prev.Services
}

// keptCerts is the previous certificates block while it is young enough, or
// of any age during the start's grace.
func keptCerts(prev *HeavySnapshot, now time.Time, grace bool) *CertsBlock {
	if prev == nil || prev.Certs == nil || !(grace || young(prev.Certs.AsOf, certsMaxAge, now)) {
		return nil
	}
	return prev.Certs
}

// keptUpdates is the previous update reading while it describes the installed
// release and is young enough, or of any age during the start's grace.
func keptUpdates(prev *HeavySnapshot, installed string, now time.Time, grace bool) *UpdatesBlock {
	if prev == nil || !describes(prev.Updates, installed) || !(grace || young(prev.Updates.AsOf, updatesMaxAge, now)) {
		return nil
	}
	return prev.Updates
}

// describes reports whether an update reading is one of the installed
// release, which must be known: a reading of another release says nothing
// about what this one has pending.
func describes(u *UpdatesBlock, installed string) bool {
	return u != nil && u.FirmwareStatus != nil && installed != "" && u.OPNsenseVersion == installed
}

// young reports whether a block stamped asOf is at most maxAge old. A stamp
// after now counts as young: restamp leaves none more than clockAhead after
// it.
func young(asOf float64, maxAge time.Duration, now time.Time) bool {
	return now.Sub(time.Unix(int64(asOf), 0)) <= maxAge
}

// restamp returns snap, or a copy of it in which every block stamped more
// than clockAhead after now is stamped now, remembering the stamp it was
// collected with.
func restamp(snap *HeavySnapshot, now time.Time) *HeavySnapshot {
	if snap == nil {
		return nil
	}
	limit := now.Add(clockAhead)
	ahead := func(asOf float64) bool { return time.Unix(int64(asOf), 0).After(limit) }
	collected := func(at, kept float64) float64 {
		if kept != 0 {
			return kept
		}
		return at
	}
	out := *snap
	changed := false
	if b := snap.Services; b != nil && ahead(b.AsOf) {
		c := *b
		c.collectedAt, c.AsOf = collected(b.AsOf, b.collectedAt), unixSeconds(now)
		out.Services, changed = &c, true
	}
	if b := snap.Updates; b != nil && ahead(b.AsOf) {
		c := *b
		c.collectedAt, c.AsOf = collected(b.AsOf, b.collectedAt), unixSeconds(now)
		out.Updates, changed = &c, true
	}
	if b := snap.Certs; b != nil && ahead(b.AsOf) {
		c := *b
		c.collectedAt, c.AsOf = collected(b.AsOf, b.collectedAt), unixSeconds(now)
		out.Certs, changed = &c, true
	}
	if !changed {
		return snap
	}
	return &out
}

// asCollected returns snap, or a copy of it in which every block restamp has
// moved carries the stamp it was collected with again: what is saved.
func asCollected(snap *HeavySnapshot) *HeavySnapshot {
	out := *snap
	changed := false
	if b := snap.Services; b != nil && b.collectedAt != 0 {
		c := *b
		c.AsOf, c.collectedAt = b.collectedAt, 0
		out.Services, changed = &c, true
	}
	if b := snap.Updates; b != nil && b.collectedAt != 0 {
		c := *b
		c.AsOf, c.collectedAt = b.collectedAt, 0
		out.Updates, changed = &c, true
	}
	if b := snap.Certs; b != nil && b.collectedAt != 0 {
		c := *b
		c.AsOf, c.collectedAt = b.collectedAt, 0
		out.Certs, changed = &c, true
	}
	if !changed {
		return snap
	}
	return &out
}

func unixSeconds(t time.Time) float64 {
	return float64(t.Unix())
}

// heavySchedule is when Run next gathers and next checks.
type heavySchedule struct {
	nextGather time.Time
	nextCheck  time.Time
	// failed counts the gathers since the start in which a probe failed, until
	// settled is set by the first in which every probe answered.
	failed  int
	settled bool
	// failedChecks counts the checks in a row that could not use the mirror.
	failedChecks int
	// gatherBy, when set, is the latest the next gather may come: a gather
	// sets it when its services reading has to be repeated soon.
	gatherBy time.Time
}

// starting reports whether the gather about to run is the start's first or
// one of its quick retries.
func (s *heavySchedule) starting() bool {
	return !s.settled && s.failed <= len(firstGatherRetries)
}

func (s *heavySchedule) next() time.Time {
	if s.nextCheck.Before(s.nextGather) {
		return s.nextCheck
	}
	return s.nextGather
}

// gathered plans the next gather after one that ended at now.
func (s *heavySchedule) gathered(now time.Time, allOK bool) {
	if allOK {
		s.settled = true
	}
	switch {
	case s.settled:
		s.nextGather = now.Add(heavyRefreshInterval)
	case s.failed < len(firstGatherRetries):
		s.nextGather = now.Add(firstGatherRetries[s.failed])
		s.failed++
	default:
		s.failed++
		s.nextGather = now.Add(heavyRefreshInterval)
	}
	if !s.gatherBy.IsZero() {
		if s.gatherBy.Before(s.nextGather) {
			s.nextGather = s.gatherBy
		}
		s.gatherBy = time.Time{}
	}
}

// planFirstCheck plans the check a start calls for: after the stagger when
// there is no fresh reading of the installed release (reading, nil when the
// start has none: a failed check is never fresh), otherwise one interval
// after that reading's check, and never later than one interval from now.
func (s *heavySchedule) planFirstCheck(now time.Time, reading *opnapi.FirmwareStatus, stagger, jitter time.Duration) {
	earliest := now.Add(stagger)
	if reading == nil || !reading.Clean() || reading.LastCheckUnix <= 0 {
		s.nextCheck = earliest
		return
	}
	checked := time.Unix(reading.LastCheckUnix, 0)
	if now.Sub(checked) >= firmwareCheckInterval {
		s.nextCheck = earliest
		return
	}
	due := checked.Add(firmwareCheckInterval + jitter)
	latest := now.Add(firmwareCheckInterval + jitter)
	switch {
	case due.Before(earliest):
		s.nextCheck = earliest
	case due.After(latest):
		s.nextCheck = latest
	default:
		s.nextCheck = due
	}
}

// checked plans the next check after an attempt that ended at now. A check
// that never ran comes back soon, and one that could not use the mirror after
// failedCheckRetries; one that ran past the wait loaded the mirror, and is
// followed by the regular interval like a good one.
func (s *heavySchedule) checked(now time.Time, result checkResult, jitter time.Duration) {
	switch result {
	case checkBusy:
		s.nextCheck = now.Add(firmwareCheckRetry)
	case checkUnreachable:
		s.nextCheck = s.nextGather
	case checkFailed:
		if s.failedChecks < len(failedCheckRetries) {
			s.nextCheck = now.Add(failedCheckRetries[s.failedChecks])
			s.failedChecks++
			return
		}
		s.nextCheck = now.Add(firmwareCheckInterval + jitter)
	case checkDone:
		s.failedChecks = 0
		s.nextCheck = now.Add(firmwareCheckInterval + jitter)
	default:
		s.nextCheck = now.Add(firmwareCheckInterval + jitter)
	}
}

// checkBy makes a check due no later than at.
func (s *heavySchedule) checkBy(at time.Time) {
	if at.Before(s.nextCheck) {
		s.nextCheck = at
	}
}
