package telemetry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/firmware"
	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// fakeOPNsense answers the endpoints the collector reads and remembers which it
// was asked for. A check it is asked for runs for `checkPolls` reads of
// /running, during which /status has no result, and then leaves a result with a
// new last_check, as OPNsense's check.sh does.
type fakeOPNsense struct {
	srv *httptest.Server

	mu   sync.Mutex
	hits map[string]int

	servicesDown, certsDown, statusDown, runningDown bool
	// cronStopped makes the service list show cron not running, as a reading
	// taken while rc is still starting it does.
	cronStopped bool
	// running is what /running answers when no check of ours runs.
	running string
	// installed is the release the version file holds; checked the one the
	// last result was made for ("" = installed); lastCheck that result's
	// stamp ("" = no result); latest the core package's candidate.
	installed, checked, lastCheck, latest string
	checkPolls                            int
	// dropChecks makes a check request vanish, as one that finds the lock
	// held does. checkedAs, when set, is the release a check's result names.
	// failChecks makes a check's result one that could not use the mirror,
	// and failedResult says the result in place is one.
	dropChecks   bool
	checkedAs    string
	failChecks   bool
	failedResult bool

	busyLeft int
	checks   int
}

func newFakeOPNsense(t *testing.T) *fakeOPNsense {
	t.Helper()
	f := &fakeOPNsense{
		hits:       map[string]int{},
		running:    "ready",
		installed:  "26.7",
		lastCheck:  "Sun Oct  4 01:00:00 UTC 2026",
		latest:     "26.7.5",
		checkPolls: 2,
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeOPNsense) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hits[r.Method+" "+r.URL.Path]++
	w.Header().Set("Content-Type", "application/json")

	unavailable := func() { http.Error(w, "unavailable", http.StatusServiceUnavailable) }
	switch r.URL.Path {
	case "/core/service/search":
		if f.servicesDown {
			unavailable()
			return
		}
		cron := 1
		if f.cronStopped {
			cron = 0
		}
		_, _ = fmt.Fprintf(w, `{"rows":[{"name":"unbound","description":"DNS","running":1},`+
			`{"name":"cron","description":"Cron","running":%d}]}`, cron)
	case "/trust/cert/search":
		if f.certsDown {
			unavailable()
			return
		}
		_, _ = w.Write([]byte(`{"rows":[{"descr":"Web GUI","valid_to":"1798761600","in_use":"1","crt":"x"}]}`))
	case "/core/firmware/check":
		f.checks++
		if !f.dropChecks {
			f.busyLeft = f.checkPolls
			f.lastCheck = fmt.Sprintf("Sun Oct  4 02:%02d:00 UTC 2026", f.checks)
			f.checked = f.checkedAs
			f.failedResult = f.failChecks
		}
		_, _ = w.Write([]byte(`{"status":"ok","msg_uuid":"x"}`))
	case "/core/firmware/running":
		if f.runningDown {
			unavailable()
			return
		}
		status := f.running
		if f.busyLeft > 0 {
			f.busyLeft--
			status = "busy"
		}
		_, _ = fmt.Fprintf(w, `{"status":%q}`, status)
	case "/core/firmware/status":
		if f.statusDown {
			unavailable()
			return
		}
		_, _ = w.Write(f.statusBody())
	default:
		http.NotFound(w, r)
	}
}

// statusBody is /status as OPNsense builds it. The fake's lock is held.
func (f *fakeOPNsense) statusBody() []byte {
	product := map[string]any{"product_version": f.installed, "product_id": "opnsense", "product_latest": "26.7.2"}
	if f.busyLeft > 0 || f.lastCheck == "" {
		body, _ := json.Marshal(map[string]any{"status": "none", "product": product})
		return body
	}
	checked := f.checked
	if checked == "" {
		checked = f.installed
	}
	if f.failedResult { // a mirror that cannot be resolved
		body, _ := json.Marshal(map[string]any{
			"status": "error", "last_check": f.lastCheck, "connection": "unresolved", "repository": "error",
			"product_version": checked, "product_id": "opnsense", "upgrade_packages": []any{}, "product": product,
		})
		return body
	}
	upgrades := []any{map[string]any{"name": "curl", "current_version": "8.21.0", "new_version": "8.22.0"}}
	if f.latest != "" {
		upgrades = append(upgrades, map[string]any{"name": "opnsense", "current_version": checked, "new_version": f.latest})
	}
	body, _ := json.Marshal(map[string]any{
		"status": "update", "last_check": f.lastCheck, "connection": "ok", "repository": "ok",
		"product_version": checked, "product_id": "opnsense", "upgrade_packages": upgrades,
		"needs_reboot": "1", "product": product,
	})
	return body
}

func (f *fakeOPNsense) set(fn func(*fakeOPNsense)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *fakeOPNsense) count(endpoint string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[endpoint]
}

func (f *fakeOPNsense) version() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.installed
}

// testClock is the collector's clock, moved by hand.
type testClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

var testStart = time.Date(2026, 10, 4, 3, 0, 0, 0, time.UTC)

// newCollector reads f, keeps its snapshot at cachePath ("" none), reads the
// installed release from f, and draws every random duration at its midpoint:
// a 30 s stagger and no jitter.
func newCollector(t *testing.T, f *fakeOPNsense, cachePath string) (*HeavyCollector, *testClock) {
	t.Helper()
	prevPoll, prevTimeout := firmwareCheckPoll, firmwareCheckTimeout
	firmwareCheckPoll, firmwareCheckTimeout = time.Millisecond, 500*time.Millisecond
	t.Cleanup(func() { firmwareCheckPoll, firmwareCheckTimeout = prevPoll, prevTimeout })
	t.Cleanup(func() { firmware.Watch(0) })

	clock := &testClock{at: testStart}
	h := NewHeavyCollector(opnapi.NewClient(f.srv.URL, "key", "secret", true), cachePath)
	h.now = clock.now
	h.random = func(n time.Duration) time.Duration { return n / 2 }
	h.installedVersion = f.version
	h.bootTime = bootedAt(testStart.Add(-30 * 24 * time.Hour)) // a box up for a month
	return h, clock
}

// bootedAt is a bootTime that answers t.
func bootedAt(t time.Time) func() (int64, error) {
	return func() (int64, error) { return t.Unix(), nil }
}

func asOf(t time.Time) float64 { return float64(t.Unix()) }

// refresh is one gather as Run makes it, with the schedule told how it went.
func refresh(h *HeavyCollector, clock *testClock) bool {
	ok := h.gather(context.Background())
	h.sched.gathered(clock.now(), ok)
	return ok
}

// ─── The firmware check ──────────────────────────────────────────────────────

// The firmware check takes the lock a running update needs and truncates the
// progress log the update is judged by, so the collector does not start one
// while a FIRMWARE_UPGRADE is in progress in this process.
func TestCheck_SkipsWhileAnUpdateIsInProgress(t *testing.T) {
	f := newFakeOPNsense(t)
	h, _ := newCollector(t, f, "")

	release, err := firmware.Acquire(context.Background(), nil) // a FIRMWARE_UPGRADE task holds the slot
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer release()

	if got := h.check(context.Background()); got != checkBusy {
		t.Fatalf("check = %v, want busy", got)
	}
	if n := f.count("POST /core/firmware/check"); n != 0 {
		t.Fatalf("requested a firmware check %d times during an update", n)
	}
	if !h.gather(context.Background()) || f.count("GET /core/service/search") == 0 {
		t.Fatal("the rest of the refresh must still run")
	}
}

// The same holds while the reconciler waits for an update the previous process
// started.
func TestCheck_SkipsWhileTheReconcilerWaits(t *testing.T) {
	f := newFakeOPNsense(t)
	h, _ := newCollector(t, f, "")

	firmware.Watch(1)
	if got := h.check(context.Background()); got != checkBusy {
		t.Fatalf("check = %v, want busy", got)
	}
	if n := f.count("POST /core/firmware/check"); n != 0 {
		t.Fatalf("requested a firmware check %d times while the reconciler waits", n)
	}
}

// A job somebody else started (an update or a check from the web GUI) holds
// OPNsense's lock too, and only /running shows it: the check is not requested,
// and the reading in hand stays.
func TestCheck_SkipsWhileOPNsenseIsBusy(t *testing.T) {
	f := newFakeOPNsense(t)
	h, _ := newCollector(t, f, "")
	h.gather(context.Background())
	before := h.Snapshot().Updates

	f.set(func(f *fakeOPNsense) { f.running = "busy" })
	if got := h.check(context.Background()); got != checkBusy {
		t.Fatalf("check = %v, want busy", got)
	}
	if n := f.count("POST /core/firmware/check"); n != 0 {
		t.Fatalf("requested a firmware check %d times while OPNsense was busy", n)
	}
	if h.Snapshot().Updates != before {
		t.Fatal("the reading in hand was replaced while the check was skipped")
	}
}

// An API that does not answer is not a busy OPNsense: the check waits for the
// next gather instead of asking again every couple of minutes.
func TestCheck_AnAPIThatDoesNotAnswerWaitsForTheNextGather(t *testing.T) {
	f := newFakeOPNsense(t)
	h, _ := newCollector(t, f, "")

	f.set(func(f *fakeOPNsense) { f.runningDown = true })
	if got := h.check(context.Background()); got != checkUnreachable {
		t.Fatalf("check = %v with /running down, want unreachable", got)
	}
	f.set(func(f *fakeOPNsense) { f.runningDown, f.statusDown = false, true })
	if got := h.check(context.Background()); got != checkUnreachable {
		t.Fatalf("check = %v with /status down, want unreachable", got)
	}
	if n := f.count("POST /core/firmware/check"); n != 0 {
		t.Fatalf("requested %d checks without a readable baseline", n)
	}
}

// What the dashboard showed stays up instead of turning "unavailable" for the
// length of the update, with its own as_of.
func TestCheck_KeepsThePreviousReadingWhileItSkips(t *testing.T) {
	f := newFakeOPNsense(t)
	h, clock := newCollector(t, f, "")

	if got := h.check(context.Background()); got != checkDone {
		t.Fatalf("first check = %v, want done", got)
	}
	before := h.Snapshot()
	if before == nil || before.Updates == nil || before.Updates.OPNsenseVersion != "26.7" {
		t.Fatalf("the first check did not read the firmware status: %+v", before)
	}

	clock.advance(firmwareCheckInterval)
	firmware.Watch(1)
	h.check(context.Background())
	after := h.Snapshot()
	if after == nil || after.Updates == nil || after.Updates.AsOf != before.Updates.AsOf {
		t.Fatalf("the update reading was dropped or restamped while the check was skipped: %+v", after)
	}
}

// The check is waited for on /running, however long it takes within the
// bound, and its result is read once: no fixed settle, and no "none" read in
// the middle of it.
func TestCheck_WaitsOnRunningAndReadsTheNewResult(t *testing.T) {
	f := newFakeOPNsense(t)
	f.set(func(f *fakeOPNsense) { f.checkPolls = 5 })
	h, _ := newCollector(t, f, "")

	if got := h.check(context.Background()); got != checkDone {
		t.Fatalf("check = %v, want done", got)
	}
	if f.count("POST /core/firmware/check") != 1 {
		t.Fatalf("%d checks requested, want 1", f.count("POST /core/firmware/check"))
	}
	if n := f.count("GET /core/firmware/running"); n < 6 {
		t.Fatalf("/running read %d times, want the 5 busy answers and the ready one", n)
	}
	u := h.Snapshot().Updates
	if u == nil || u.Status != "update" || u.LastCheck != "Sun Oct  4 02:01:00 UTC 2026" {
		t.Fatalf("updates = %+v, want the new check's result", u)
	}
	if u.OPNsenseLatest != "26.7.5" || u.OPNsensePackage != "opnsense" {
		t.Fatalf("latest = %q, package = %q; want the catalog's 26.7.5 for opnsense", u.OPNsenseLatest, u.OPNsensePackage)
	}
}

// A request OPNsense drops (its lock was taken in between) leaves the old
// result in place: that is not the check's result, and since nothing ran it is
// tried again soon.
func TestCheck_ADroppedRequestIsNotTakenForAResult(t *testing.T) {
	f := newFakeOPNsense(t)
	h, _ := newCollector(t, f, "")
	h.gather(context.Background())
	before := h.Snapshot().Updates

	f.set(func(f *fakeOPNsense) { f.dropChecks = true })
	if got := h.check(context.Background()); got != checkBusy {
		t.Fatalf("check = %v, want busy", got)
	}
	if h.Snapshot().Updates != before {
		t.Fatal("the old result was taken for the new check's")
	}
}

// A check still running when the wait ends loaded the mirror already: it is
// not requested again soon, and the gather that follows reads its result.
func TestCheck_ALongCheckIsLeftToALaterGather(t *testing.T) {
	f := newFakeOPNsense(t)
	f.set(func(f *fakeOPNsense) { f.checkPolls = 1_000_000 })
	h, _ := newCollector(t, f, "")

	if got := h.check(context.Background()); got != checkUnfinished {
		t.Fatalf("check = %v, want unfinished", got)
	}
	f.set(func(f *fakeOPNsense) { f.busyLeft = 0 })
	h.gather(context.Background())
	if u := h.Snapshot().Updates; u == nil || u.LastCheck != "Sun Oct  4 02:01:00 UTC 2026" {
		t.Fatalf("updates = %+v, want the long check's result", u)
	}
}

// A result made for another release than the installed one is not the check's
// to give: the reading in hand stays.
func TestCheck_AStaleResultIsNotUsed(t *testing.T) {
	f := newFakeOPNsense(t)
	h, _ := newCollector(t, f, "")
	h.gather(context.Background())
	before := h.Snapshot().Updates

	// The release moved while the check ran: OPNsense's result names the old one.
	f.set(func(f *fakeOPNsense) { f.checkedAs = "26.7.4" })
	if got := h.check(context.Background()); got != checkDone {
		t.Fatalf("check = %v, want done", got)
	}
	if h.Snapshot().Updates != before {
		t.Fatalf("a result for 26.7.4 replaced the 26.7 reading: %+v", h.Snapshot().Updates)
	}
}

// A check that ran but could not use the mirror (a DNS blip) never replaces a
// good reading: the good one stays with its as_of, the failure counts for the
// schedule, and it is not a fresh reading for the next start.
func TestCheck_AFailedCheckKeepsTheGoodReading(t *testing.T) {
	f := newFakeOPNsense(t)
	h, _ := newCollector(t, f, "")
	h.gather(context.Background())
	good := h.Snapshot().Updates

	f.set(func(f *fakeOPNsense) { f.failChecks = true })
	if got := h.check(context.Background()); got != checkFailed {
		t.Fatalf("check = %v, want failed", got)
	}
	if u := h.Snapshot().Updates; u != good {
		t.Fatalf("a failed check replaced the good reading: %+v", u)
	}
	if h.reading == nil || h.reading.Clean() || h.reading.Connection != "unresolved" {
		t.Fatalf("the reading for the schedule = %+v, want the failed check", h.reading)
	}
	var s heavySchedule
	s.planFirstCheck(testStart, h.reading, 20*time.Second, 0)
	if !s.nextCheck.Equal(testStart.Add(20 * time.Second)) {
		t.Fatal("a failed check counted as a fresh reading")
	}
}

// Without a good reading to keep, the failed one is what there is to say.
func TestCheck_AFailedCheckIsSentWhenThereIsNoGoodReading(t *testing.T) {
	f := newFakeOPNsense(t)
	f.set(func(f *fakeOPNsense) { f.lastCheck, f.failChecks = "", true })
	h, _ := newCollector(t, f, "")

	if got := h.check(context.Background()); got != checkFailed {
		t.Fatalf("check = %v, want failed", got)
	}
	u := h.Snapshot().Updates
	if u == nil || u.Status != "error" || u.Connection != "unresolved" || u.OPNsenseLatest != "" {
		t.Fatalf("updates = %+v, want the failed reading without opnsense_latest", u)
	}
}

// ─── Gathers and carry-over ──────────────────────────────────────────────────

// A failed result the gather reads (a check somebody else ran) does not replace
// the good reading either, until that one is older than a day.
func TestGather_AFailedResultGivesWayOnlyWhenTheGoodReadingIsOld(t *testing.T) {
	f := newFakeOPNsense(t)
	h, clock := newCollector(t, f, "")
	refresh(h, clock)
	good := h.Snapshot().Updates

	clock.advance(heavyRefreshInterval)
	f.set(func(f *fakeOPNsense) { f.failedResult, f.lastCheck = true, "Sun Oct  4 03:20:00 UTC 2026" })
	refresh(h, clock)
	if u := h.Snapshot().Updates; u != good {
		t.Fatalf("a failed result replaced the good reading: %+v", u)
	}

	clock.advance(updatesMaxAge)
	refresh(h, clock)
	if u := h.Snapshot().Updates; u == nil || u.Clean() || u.Status != "error" {
		t.Fatalf("updates = %+v a day later, want the failed reading", u)
	}
}

// A block stamped by a clock that was ahead is stamped now when it is carried
// over, so its bound runs from here: a clock stepped back two days does not keep
// a block for two days more.
func TestGather_AStampFromTheFutureDoesNotOutliveItsBound(t *testing.T) {
	f := newFakeOPNsense(t)
	h, clock := newCollector(t, f, "")
	refresh(h, clock)

	clock.advance(-48 * time.Hour) // NTP corrects a clock that ran two days fast
	f.set(func(f *fakeOPNsense) { f.servicesDown = true })
	refresh(h, clock)
	kept := h.Snapshot().Services
	if kept == nil || kept.AsOf != asOf(clock.now()) {
		t.Fatalf("services = %+v, want the block carried over and stamped now (%v)", kept, asOf(clock.now()))
	}

	clock.advance(servicesMaxAge + time.Second)
	refresh(h, clock)
	if snap := h.Snapshot(); snap != nil && snap.Services != nil {
		t.Fatalf("services stamped from the future were still sent past their bound: %+v", snap.Services)
	}
}

// restamp moves only what is too far ahead, in a copy, and keeps the stamp it
// was collected with for asCollected, which is what is saved.
func TestRestamp(t *testing.T) {
	now := testStart
	written := asOf(now.Add(72 * time.Hour))
	snap := &HeavySnapshot{
		Services:    &ServicesBlock{AsOf: asOf(now.Add(clockAhead))}, // within the tolerance
		Updates:     &UpdatesBlock{FirmwareStatus: &opnapi.FirmwareStatus{}, AsOf: written},
		Certs:       &CertsBlock{AsOf: asOf(now.Add(-time.Hour))},
		CollectedAt: written,
	}
	got := restamp(snap, now)
	if got == snap || got.Services != snap.Services || got.Certs != snap.Certs {
		t.Fatal("restamp must copy only the blocks it changes")
	}
	if got.Updates.AsOf != asOf(now) || got.Updates.FirmwareStatus != snap.Updates.FirmwareStatus || got.CollectedAt != written {
		t.Fatalf("restamped = %+v", got)
	}
	if snap.Updates.AsOf != written {
		t.Fatal("restamp changed the snapshot it was given")
	}
	if same := restamp(got, now); same != got {
		t.Fatal("restamp copied a snapshot with nothing to change")
	}

	// Moved again by a clock an hour further behind, a block keeps the stamp
	// it was collected with, and what was never moved is saved as it is.
	again := restamp(got, now.Add(-time.Hour))
	saved := asCollected(again)
	if saved.Updates.AsOf != written || saved.Services.AsOf != asOf(now.Add(clockAhead)) || saved.Certs != again.Certs {
		t.Fatalf("saved = %+v, want every block with the stamp it was collected with", saved)
	}
	if again.Updates.AsOf != asOf(now.Add(-time.Hour)) {
		t.Fatal("asCollected changed the snapshot in memory")
	}
	if same := asCollected(snap); same != snap {
		t.Fatal("asCollected copied a snapshot nothing moved")
	}
}

// The status a gather reads is the result of the last check, whoever ran it;
// reading it starts none.
func TestGather_ReadsTheLastResultWithoutChecking(t *testing.T) {
	f := newFakeOPNsense(t)
	h, _ := newCollector(t, f, "")

	if !h.gather(context.Background()) {
		t.Fatal("gather reported a failed probe")
	}
	if n := f.count("POST /core/firmware/check"); n != 0 {
		t.Fatalf("a gather requested %d firmware checks", n)
	}
	snap := h.Snapshot()
	if snap.Services == nil || snap.Certs == nil || snap.Updates == nil {
		t.Fatalf("snapshot = %+v, want every block", snap)
	}
	if snap.Updates.LastCheck != "Sun Oct  4 01:00:00 UTC 2026" || snap.Updates.AsOf != asOf(testStart) {
		t.Fatalf("updates = %+v", snap.Updates)
	}
}

// A probe that fails keeps the previous block, with its own as_of, for a
// bounded time; the other blocks are refreshed.
func TestGather_KeepsTheBlockOfAFailedProbeForABoundedTime(t *testing.T) {
	f := newFakeOPNsense(t)
	h, clock := newCollector(t, f, "")
	refresh(h, clock)
	first := h.Snapshot()

	clock.advance(heavyRefreshInterval)
	f.set(func(f *fakeOPNsense) { f.servicesDown, f.certsDown, f.statusDown = true, true, true })
	if refresh(h, clock) {
		t.Fatal("gather reported success with every probe down")
	}
	kept := h.Snapshot()
	if kept == nil || kept.Services != first.Services || kept.Certs != first.Certs || kept.Updates != first.Updates {
		t.Fatalf("a failed refresh dropped good blocks: %+v", kept)
	}
	if kept.CollectedAt != first.CollectedAt {
		t.Fatal("a refresh that collected nothing moved collected_at")
	}

	clock.advance(servicesMaxAge - heavyRefreshInterval + time.Second)
	refresh(h, clock)
	old := h.Snapshot()
	if old == nil || old.Services != nil || old.Certs != nil {
		t.Fatalf("services and certificates older than %s were still sent: %+v", servicesMaxAge, old)
	}
	if old.Updates != first.Updates {
		t.Fatal("the update reading was dropped long before a day")
	}

	clock.advance(updatesMaxAge)
	refresh(h, clock)
	if snap := h.Snapshot(); snap != nil {
		t.Fatalf("snapshot = %+v after a day of failures, want none", snap)
	}
}

// After a start the API may not answer yet (a boot). What the previous process
// saved is kept, whatever its age, through the first gather and its quick
// retries; after them the usual bounds apply.
func TestGather_KeepsTheRestoredSnapshotThroughTheStartRetries(t *testing.T) {
	f := newFakeOPNsense(t)
	path := filepath.Join(t.TempDir(), "heavy.json")
	prev, _ := newCollector(t, f, path)
	refresh(prev, &testClock{at: testStart})

	h, clock := newCollector(t, f, path)
	clock.advance(3 * time.Hour) // the box was off
	h.Restore()
	restored := h.Snapshot()
	f.set(func(f *fakeOPNsense) { f.servicesDown, f.certsDown, f.statusDown = true, true, true })

	for i := 0; i <= len(firstGatherRetries); i++ {
		refresh(h, clock)
		if snap := h.Snapshot(); snap == nil || snap.Services != restored.Services || snap.Certs != restored.Certs ||
			snap.Updates != restored.Updates {
			t.Fatalf("gather %d of the start dropped restored blocks: %+v", i+1, snap)
		}
		clock.advance(h.sched.nextGather.Sub(clock.now()))
	}

	refresh(h, clock)
	if snap := h.Snapshot(); snap == nil || snap.Services != nil || snap.Certs != nil || snap.Updates != restored.Updates {
		t.Fatalf("after the start's retries the bounds apply: %+v", snap)
	}
}

// While a check runs, and after a boot before any has, OPNsense answers "none"
// with zero counts and no last_check. That is no reading: the last good one is
// carried over, or nothing is sent, never a fresh-looking "none".
func TestGather_NeverSendsAStatusWithoutACheckAsAReading(t *testing.T) {
	f := newFakeOPNsense(t)
	f.set(func(f *fakeOPNsense) { f.lastCheck = "" })
	h, clock := newCollector(t, f, "")

	h.gather(context.Background())
	if u := h.Snapshot().Updates; u != nil {
		t.Fatalf("updates = %+v without any check, want none", u)
	}

	f.set(func(f *fakeOPNsense) { f.lastCheck = "Sun Oct  4 01:00:00 UTC 2026" })
	h.gather(context.Background())
	good := h.Snapshot().Updates

	clock.advance(heavyRefreshInterval)
	f.set(func(f *fakeOPNsense) { f.busyLeft = 1_000_000 }) // a check somebody else started
	h.gather(context.Background())
	if u := h.Snapshot().Updates; u != good {
		t.Fatalf("updates = %+v while a check ran, want the previous reading", u)
	}
}

// After an update the result describes the release that was replaced. It is not
// sent, the reading of the old release is dropped, and a check is due at once.
func TestGather_AChangedReleaseDropsTheReadingAndCallsForACheck(t *testing.T) {
	f := newFakeOPNsense(t)
	h, clock := newCollector(t, f, "")
	h.gather(context.Background())
	h.sched.nextCheck = testStart.Add(firmwareCheckInterval)

	clock.advance(heavyRefreshInterval)
	f.set(func(f *fakeOPNsense) { f.checked, f.installed = "26.7", "26.7.5" })
	h.gather(context.Background())

	if u := h.Snapshot().Updates; u != nil {
		t.Fatalf("updates = %+v after the release changed, want none until a check", u)
	}
	if !h.sched.nextCheck.Equal(clock.now()) {
		t.Fatalf("next check at %v, want now (%v)", h.sched.nextCheck, clock.now())
	}
	if got := h.check(context.Background()); got != checkDone {
		t.Fatalf("check = %v", got)
	}
	if u := h.Snapshot().Updates; u == nil || u.OPNsenseVersion != "26.7.5" {
		t.Fatalf("updates = %+v, want the new release's reading", u)
	}
}

// ─── After a boot ────────────────────────────────────────────────────────────

func running(t *testing.T, b *ServicesBlock, name string) bool {
	t.Helper()
	for _, item := range b.Items {
		if item.Name == name {
			return item.Running
		}
	}
	t.Fatalf("no %q in %+v", name, b.Items)
	return false
}

// restoredAfter returns a collector that restored what a previous process
// saved, on a device that booted at booted.
func restoredAfter(t *testing.T, f *fakeOPNsense, booted time.Time) (*HeavyCollector, *testClock) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "heavy.json")
	prev, _ := newCollector(t, f, path)
	prev.now = func() time.Time { return testStart.Add(-4 * time.Minute) }
	prev.gather(context.Background())

	h, clock := newCollector(t, f, path)
	h.bootTime = bootedAt(booted)
	h.Restore()
	return h, clock
}

// A service rc has not started yet when the first gather after a boot runs
// is not reported down: the restored block stays, the services are read again
// a minute later, and that reading is taken.
func TestGather_AServiceStillStartingAfterABootKeepsTheRestoredBlock(t *testing.T) {
	f := newFakeOPNsense(t)
	h, clock := restoredAfter(t, f, testStart.Add(-17*time.Second))
	restored := h.Snapshot().Services
	f.set(func(f *fakeOPNsense) { f.cronStopped = true })

	refresh(h, clock)
	if got := h.Snapshot().Services; got != restored {
		t.Fatalf("services = %+v right after the boot, want the restored block", got)
	}
	if got := h.sched.nextGather.Sub(clock.now()); got != servicesRecheck {
		t.Fatalf("next gather in %v, want %v", got, servicesRecheck)
	}

	f.set(func(f *fakeOPNsense) { f.cronStopped = false })
	clock.advance(servicesRecheck)
	refresh(h, clock)
	got := h.Snapshot().Services
	if got == restored || !running(t, got, "cron") || got.AsOf != asOf(clock.now()) {
		t.Fatalf("services = %+v a minute later, want a fresh reading with cron running", got)
	}
	if next := h.sched.nextGather.Sub(clock.now()); next != heavyRefreshInterval {
		t.Fatalf("next gather in %v, want the regular %v", next, heavyRefreshInterval)
	}
}

// A service still not running once the boot has settled is down, and is
// reported so.
func TestGather_AServiceDownPastTheBootWindowIsReported(t *testing.T) {
	f := newFakeOPNsense(t)
	h, clock := restoredAfter(t, f, testStart.Add(-bootSettle+30*time.Second))
	f.set(func(f *fakeOPNsense) { f.cronStopped = true })

	refresh(h, clock) // 4.5 min after the boot: read again soon
	clock.advance(h.sched.nextGather.Sub(clock.now()))
	refresh(h, clock) // 5.5 min after the boot
	if got := h.Snapshot().Services; running(t, got, "cron") || got.AsOf != asOf(clock.now()) {
		t.Fatalf("services = %+v past the boot window, want cron reported down", got)
	}
}

// After a plain restart the services had time to start long ago: one that is
// not running is down, and is reported at once.
func TestGather_AServiceDownAfterAPlainRestartIsReportedAtOnce(t *testing.T) {
	f := newFakeOPNsense(t)
	h, clock := restoredAfter(t, f, testStart.Add(-30*24*time.Hour))
	f.set(func(f *fakeOPNsense) { f.cronStopped = true })

	refresh(h, clock)
	if got := h.Snapshot().Services; running(t, got, "cron") || got.AsOf != asOf(clock.now()) {
		t.Fatalf("services = %+v after a restart, want cron reported down at once", got)
	}
	if got := h.sched.nextGather.Sub(clock.now()); got != heavyRefreshInterval {
		t.Fatalf("next gather in %v, want the regular %v", got, heavyRefreshInterval)
	}
}

// Without the boot time there is no telling a boot from a restart, and a
// service that is not running is reported at once.
func TestGather_AServiceDownWithAnUnreadableBootTimeIsReportedAtOnce(t *testing.T) {
	f := newFakeOPNsense(t)
	h, clock := restoredAfter(t, f, testStart.Add(-17*time.Second))
	h.bootTime = func() (int64, error) { return 0, errors.New("sysctl kern.boottime: unavailable") }
	f.set(func(f *fakeOPNsense) { f.cronStopped = true })

	refresh(h, clock)
	if got := h.Snapshot().Services; running(t, got, "cron") || got.AsOf != asOf(clock.now()) {
		t.Fatalf("services = %+v, want cron reported down at once", got)
	}
	if got := h.sched.nextGather.Sub(clock.now()); got != heavyRefreshInterval {
		t.Fatalf("next gather in %v, want the regular %v", got, heavyRefreshInterval)
	}
}

// Without a saved block a boot's first reading is all there is: it is sent at
// once, and corrected by the reading a minute later.
func TestGather_WithoutACacheTheFirstBootReadingIsSentAtOnce(t *testing.T) {
	f := newFakeOPNsense(t)
	f.set(func(f *fakeOPNsense) { f.cronStopped = true })
	h, clock := newCollector(t, f, "")
	h.bootTime = bootedAt(testStart.Add(-17 * time.Second))

	refresh(h, clock)
	if got := h.Snapshot().Services; got == nil || running(t, got, "cron") {
		t.Fatalf("services = %+v, want the first reading sent as it is", got)
	}
	if got := h.sched.nextGather.Sub(clock.now()); got != servicesRecheck {
		t.Fatalf("next gather in %v, want %v", got, servicesRecheck)
	}
}

// OPNsense clears its check result at boot. The first start after a boot
// checks once, after the stagger, whatever the age of the reading it restored;
// a plain restart, or a start in the same boot after that check, keeps the
// rule for a fresh reading.
func TestStart_ABootChecksAndARestartDoesNot(t *testing.T) {
	stagger := firmwareCheckStagger / 2 // newCollector draws every random duration at its midpoint
	lastCheck := time.Date(2026, 10, 4, 1, 0, 0, 0, time.UTC)

	t.Run("boot", func(t *testing.T) {
		f := newFakeOPNsense(t)
		h, clock := restoredAfter(t, f, testStart.Add(-17*time.Second))
		f.set(func(f *fakeOPNsense) { f.lastCheck = "" }) // /tmp was cleared
		h.start(context.Background())
		if got := h.sched.nextCheck; !got.Equal(clock.now().Add(stagger)) {
			t.Fatalf("first check at %v, want after the stagger (%v)", got, clock.now().Add(stagger))
		}
		if u := h.Snapshot().Updates; u == nil || u.LastCheck != "Sun Oct  4 01:00:00 UTC 2026" {
			t.Fatalf("updates = %+v, want the restored reading until the check", u)
		}
	})

	t.Run("plain restart", func(t *testing.T) {
		f := newFakeOPNsense(t)
		h, _ := restoredAfter(t, f, testStart.Add(-30*24*time.Hour))
		h.start(context.Background())
		if got := h.sched.nextCheck; !got.Equal(lastCheck.Add(firmwareCheckInterval)) {
			t.Fatalf("first check at %v, want one interval after the last one (%v)", got, lastCheck.Add(firmwareCheckInterval))
		}
	})

	t.Run("restart after the boot's check", func(t *testing.T) {
		f := newFakeOPNsense(t)
		h, _ := restoredAfter(t, f, lastCheck.Add(-time.Minute))
		h.start(context.Background())
		if got := h.sched.nextCheck; !got.Equal(lastCheck.Add(firmwareCheckInterval)) {
			t.Fatalf("first check at %v, want one interval after the boot's check (%v)", got, lastCheck.Add(firmwareCheckInterval))
		}
	})

	// A clock 3 h behind until NTP sets it reads the boot time 3 h early too,
	// so the reading made before the boot looks newer than the boot. The
	// device answering, this soon after the boot, that it holds no result is
	// what tells the boot apart.
	t.Run("boot with the clock behind", func(t *testing.T) {
		f := newFakeOPNsense(t)
		path := filepath.Join(t.TempDir(), "heavy.json")
		prev, _ := newCollector(t, f, path)
		prev.now = func() time.Time { return testStart.Add(-4 * time.Minute) }
		prev.gather(context.Background())

		h, clock := newCollector(t, f, path)
		clock.advance(-3 * time.Hour)
		h.bootTime = bootedAt(clock.now().Add(-17 * time.Second))
		h.Restore()
		f.set(func(f *fakeOPNsense) { f.lastCheck = "" })
		h.start(context.Background())
		if got := h.sched.nextCheck; !got.Equal(clock.now().Add(stagger)) {
			t.Fatalf("first check at %v, want after the stagger (%v)", got, clock.now().Add(stagger))
		}
	})

	// While a check somebody else started runs, OPNsense has no result
	// either. Long after the boot that is no boot: the restart keeps the 6 h
	// rule, and the next status read picks the result up.
	t.Run("plain restart during a running check", func(t *testing.T) {
		f := newFakeOPNsense(t)
		h, _ := restoredAfter(t, f, testStart.Add(-30*24*time.Hour))
		f.set(func(f *fakeOPNsense) { f.busyLeft = 1_000_000 })
		h.start(context.Background())
		if got := h.sched.nextCheck; !got.Equal(lastCheck.Add(firmwareCheckInterval)) {
			t.Fatalf("first check at %v, want one interval after the last one (%v)", got, lastCheck.Add(firmwareCheckInterval))
		}
	})

	// Without the boot time a start is taken for a restart: the device's
	// missing result alone does not make it a boot.
	t.Run("boot time unreadable", func(t *testing.T) {
		f := newFakeOPNsense(t)
		h, _ := restoredAfter(t, f, testStart.Add(-17*time.Second))
		h.bootTime = func() (int64, error) { return 0, errors.New("sysctl kern.boottime: unavailable") }
		f.set(func(f *fakeOPNsense) { f.lastCheck = "" })
		h.start(context.Background())
		if got := h.sched.nextCheck; !got.Equal(lastCheck.Add(firmwareCheckInterval)) {
			t.Fatalf("first check at %v, want one interval after the last one (%v)", got, lastCheck.Add(firmwareCheckInterval))
		}
	})

	// The API not answering yet says nothing about the device's result: the
	// boot time decides, and a boot still checks once the API answers.
	t.Run("boot with the API not up yet", func(t *testing.T) {
		f := newFakeOPNsense(t)
		h, clock := restoredAfter(t, f, testStart.Add(-17*time.Second))
		f.set(func(f *fakeOPNsense) { f.statusDown = true })
		h.start(context.Background())
		if got := h.sched.nextCheck; !got.Equal(clock.now().Add(stagger)) {
			t.Fatalf("first check at %v, want after the stagger (%v)", got, clock.now().Add(stagger))
		}
		f.set(func(f *fakeOPNsense) { f.statusDown = false })
		clock.advance(stagger)
		if got := h.check(context.Background()); got != checkDone {
			t.Fatalf("the boot's check = %v once the API answered, want done", got)
		}
	})
}

// ─── Schedule ────────────────────────────────────────────────────────────────

// A first gather that fails is retried after 30 s, 60 s and 2 min, then on the
// regular cadence. Once a gather had every probe answer, a later failure waits
// for the regular cadence.
func TestSchedule_RetriesAFailedFirstGatherQuickly(t *testing.T) {
	var s heavySchedule
	now := testStart
	for i, want := range []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, heavyRefreshInterval, heavyRefreshInterval} {
		if starting := i <= len(firstGatherRetries); s.starting() != starting {
			t.Fatalf("gather %d: starting = %v, want %v", i+1, s.starting(), starting)
		}
		s.gathered(now, false)
		if got := s.nextGather.Sub(now); got != want {
			t.Fatalf("after a failed gather the next is in %v, want %v", got, want)
		}
		now = s.nextGather
	}

	var t2 heavySchedule
	t2.gathered(testStart, false)
	t2.gathered(testStart.Add(30*time.Second), true)
	if t2.starting() {
		t.Fatal("still starting after a gather in which every probe answered")
	}
	t2.gathered(testStart.Add(time.Hour), false)
	if got := t2.nextGather.Sub(testStart.Add(time.Hour)); got != heavyRefreshInterval {
		t.Fatalf("a failure after a good gather waits %v, want %v", got, heavyRefreshInterval)
	}
}

func TestSchedule_FirstCheck(t *testing.T) {
	stagger, jitter := 20*time.Second, 10*time.Minute
	// reading is a clean check made checkedAgo before testStart, changed by set.
	reading := func(checkedAgo time.Duration, set ...func(*opnapi.FirmwareStatus)) *opnapi.FirmwareStatus {
		st := &opnapi.FirmwareStatus{Status: "update", LastCheck: "x", Connection: "ok", Repository: "ok",
			LastCheckUnix: testStart.Add(-checkedAgo).Unix()}
		for _, f := range set {
			f(st)
		}
		return st
	}
	cases := []struct {
		name    string
		reading *opnapi.FirmwareStatus
		want    time.Time
	}{
		{"no reading at all", nil, testStart.Add(stagger)},
		{"a reading whose time is unknown", reading(0, func(st *opnapi.FirmwareStatus) { st.LastCheckUnix = 0 }),
			testStart.Add(stagger)},
		{"a reading older than the interval", reading(7 * time.Hour), testStart.Add(stagger)},
		{"a fresh reading", reading(2 * time.Hour), testStart.Add(4*time.Hour + jitter)},
		{"a reading due within the stagger", reading(firmwareCheckInterval + jitter - time.Second), testStart.Add(stagger)},
		{"a reading stamped in the future", reading(-3 * time.Hour), testStart.Add(firmwareCheckInterval + jitter)},
		{"a recent check that could not resolve the mirror", reading(time.Hour, func(st *opnapi.FirmwareStatus) {
			st.Status, st.Connection = "error", "unresolved"
		}), testStart.Add(stagger)},
		{"a recent check the repository refused", reading(time.Hour, func(st *opnapi.FirmwareStatus) {
			st.Status, st.Repository = "error", "forbidden"
		}), testStart.Add(stagger)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var s heavySchedule
			s.planFirstCheck(testStart, tc.reading, stagger, jitter)
			if !s.nextCheck.Equal(tc.want) {
				t.Fatalf("first check at %v, want %v", s.nextCheck, tc.want)
			}
		})
	}
}

// A gather whose services reading has to be repeated pulls the next gather
// forward once; it never puts it off.
func TestSchedule_AServicesRecheckBringsTheNextGatherForward(t *testing.T) {
	var s heavySchedule
	s.gatherBy = testStart.Add(servicesRecheck)
	s.gathered(testStart, true)
	if !s.nextGather.Equal(testStart.Add(servicesRecheck)) || !s.gatherBy.IsZero() {
		t.Fatalf("next gather %v (gatherBy %v), want in %v and the request used up", s.nextGather, s.gatherBy, servicesRecheck)
	}
	s.gathered(testStart.Add(servicesRecheck), true)
	if got := s.nextGather.Sub(testStart.Add(servicesRecheck)); got != heavyRefreshInterval {
		t.Fatalf("the gather after it came in %v, want %v", got, heavyRefreshInterval)
	}

	q := heavySchedule{gatherBy: testStart.Add(time.Hour)}
	q.gathered(testStart, false)
	if got := q.nextGather.Sub(testStart); got != firstGatherRetries[0] {
		t.Fatalf("a later recheck put the quick retry off to %v", got)
	}
}

// A check that never ran comes back soon, and one that could not use the
// mirror after 10, 30 and 60 minutes; one that ran, finished or not, is
// followed by the regular interval, so a slow mirror is not checked back to
// back.
func TestSchedule_AfterACheck(t *testing.T) {
	jitter := -7 * time.Minute
	for result, want := range map[checkResult]time.Duration{
		checkBusy:        firmwareCheckRetry,
		checkUnreachable: heavyRefreshInterval, // with the next gather
		checkDone:        firmwareCheckInterval + jitter,
		checkUnfinished:  firmwareCheckInterval + jitter,
		checkFailed:      10 * time.Minute,
	} {
		s := heavySchedule{nextGather: testStart.Add(heavyRefreshInterval)}
		s.checked(testStart, result, jitter)
		if got := s.nextCheck.Sub(testStart); got != want {
			t.Errorf("after result %d the next check is in %v, want %v", result, got, want)
		}
	}

	var s heavySchedule
	s.checked(testStart, checkDone, 0)
	s.checkBy(testStart.Add(time.Minute))
	if !s.nextCheck.Equal(testStart.Add(time.Minute)) {
		t.Fatalf("checkBy left the next check at %v", s.nextCheck)
	}
	s.checkBy(testStart.Add(time.Hour))
	if !s.nextCheck.Equal(testStart.Add(time.Minute)) {
		t.Fatalf("checkBy put the next check off to %v", s.nextCheck)
	}
}

// Failed checks in a row back off 10, 30 and 60 minutes, then the regular
// interval; a busy OPNsense or an unreachable API in between neither counts nor
// resets; a good check starts the backoff over.
func TestSchedule_AFailingCheckBacksOff(t *testing.T) {
	jitter := 3 * time.Minute
	s := heavySchedule{nextGather: testStart.Add(heavyRefreshInterval)}
	now := testStart
	for i, want := range []time.Duration{10 * time.Minute, 30 * time.Minute, time.Hour, firmwareCheckInterval + jitter, firmwareCheckInterval + jitter} {
		s.checked(now, checkFailed, jitter)
		if got := s.nextCheck.Sub(now); got != want {
			t.Fatalf("failed check %d: next in %v, want %v", i+1, got, want)
		}
		if i == 0 {
			s.checked(now, checkBusy, jitter)
			s.checked(now, checkUnreachable, jitter)
		}
		now = now.Add(time.Hour)
	}

	s.checked(now, checkDone, jitter)
	s.checked(now, checkFailed, jitter)
	if got := s.nextCheck.Sub(now); got != 10*time.Minute {
		t.Fatalf("a failure after a good check: next in %v, want 10m0s", got)
	}
}

// ─── Run ─────────────────────────────────────────────────────────────────────

func drainOutcomes() {
	for {
		select {
		case <-firmware.Outcomes():
		default:
			return
		}
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// A start gathers services, certificates and the status at once; the check a
// start without a fresh reading calls for keeps its stagger. The outcome of a
// FIRMWARE_UPGRADE task brings the check forward.
func TestRun_GathersAtOnceAndChecksAfterAFirmwareTask(t *testing.T) {
	drainOutcomes()
	prevDelay := firmwareOutcomeDelay
	firmwareOutcomeDelay = 10 * time.Millisecond
	t.Cleanup(func() { firmwareOutcomeDelay = prevDelay })
	f := newFakeOPNsense(t)
	f.set(func(f *fakeOPNsense) { f.lastCheck = "" })
	h, _ := newCollector(t, f, "")
	h.now = time.Now

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = h.Run(ctx)
	}()
	defer func() {
		cancel()
		<-done
	}()

	waitFor(t, "the first gather", func() bool { return h.Snapshot() != nil })
	if n := f.count("POST /core/firmware/check"); n != 0 {
		t.Fatalf("%d checks requested before the stagger", n)
	}

	firmware.NoteOutcome()
	waitFor(t, "the check after the firmware task", func() bool {
		snap := h.Snapshot()
		return snap != nil && snap.Updates != nil
	})
	if n := f.count("POST /core/firmware/check"); n != 1 {
		t.Fatalf("%d checks requested, want 1", n)
	}
}

// ─── The snapshot on disk ────────────────────────────────────────────────────

// What a process saved, the next restores, every stamp as it was.
func TestRestore_RoundTrip(t *testing.T) {
	f := newFakeOPNsense(t)
	path := filepath.Join(t.TempDir(), "heavy.json")
	h, _ := newCollector(t, f, path)
	h.gather(context.Background())
	saved := h.Snapshot()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("nothing saved: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("saved with mode %v, want 0600", info.Mode().Perm())
	}
	if leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".*")); len(leftovers) != 0 {
		t.Fatalf("temporary files left behind: %v", leftovers)
	}

	next, clock := newCollector(t, f, path)
	clock.advance(time.Hour)
	next.Restore()
	got := next.Snapshot()
	if got == nil {
		t.Fatal("nothing restored")
	}
	want, _ := json.Marshal(saved)
	have, _ := json.Marshal(got)
	if string(want) != string(have) {
		t.Fatalf("restored %s\nwant     %s", have, want)
	}
}

// After an update the saved reading describes the release that was replaced:
// it is dropped, and the rest is restored.
func TestRestore_DropsTheUpdateReadingOfAnotherRelease(t *testing.T) {
	f := newFakeOPNsense(t)
	path := filepath.Join(t.TempDir(), "heavy.json")
	h, _ := newCollector(t, f, path)
	h.gather(context.Background())

	f.set(func(f *fakeOPNsense) { f.installed = "26.7.5" })
	next, _ := newCollector(t, f, path)
	next.Restore()
	got := next.Snapshot()
	if got == nil || got.Services == nil || got.Certs == nil {
		t.Fatalf("restored %+v, want services and certificates", got)
	}
	if got.Updates != nil {
		t.Fatalf("restored the 26.7 reading on a 26.7.5 device: %+v", got.Updates)
	}

	unknown, _ := newCollector(t, f, path)
	unknown.installedVersion = func() string { return "" }
	unknown.Restore()
	if u := unknown.Snapshot().Updates; u != nil {
		t.Fatalf("restored an update reading without knowing the installed release: %+v", u)
	}
}

func TestRestore_DropsAnUpdateReadingOlderThanADay(t *testing.T) {
	f := newFakeOPNsense(t)
	path := filepath.Join(t.TempDir(), "heavy.json")
	h, _ := newCollector(t, f, path)
	h.gather(context.Background())

	next, clock := newCollector(t, f, path)
	clock.advance(updatesMaxAge + time.Second)
	next.Restore()
	if got := next.Snapshot(); got == nil || got.Updates != nil || got.Services == nil {
		t.Fatalf("restored %+v, want everything but the day-old update reading", got)
	}

	// A clock behind the stamps (not yet set after a boot) is not a reason.
	behind, clock := newCollector(t, f, path)
	clock.advance(-time.Hour)
	behind.Restore()
	if got := behind.Snapshot(); got == nil || got.Updates == nil {
		t.Fatalf("restored %+v with the clock behind, want the update reading", got)
	}
}

// The reviewer's case: a restored good reading, then a check the mirror cannot
// answer. The good reading stays, the next check comes in 10 minutes, and the
// cache still holds the good reading.
func TestRestore_AGoodReadingSurvivesAFailedCheck(t *testing.T) {
	f := newFakeOPNsense(t)
	path := filepath.Join(t.TempDir(), "heavy.json")
	prev, _ := newCollector(t, f, path)
	prev.gather(context.Background())

	h, clock := newCollector(t, f, path)
	h.Restore()
	good := h.Snapshot().Updates
	f.set(func(f *fakeOPNsense) { f.failChecks = true })
	h.sched.checked(clock.now(), h.check(context.Background()), 0)

	if u := h.Snapshot().Updates; u != good {
		t.Fatalf("updates = %+v, want the restored good reading", u)
	}
	if got := h.sched.nextCheck.Sub(clock.now()); got != 10*time.Minute {
		t.Fatalf("next check in %v, want 10m0s", got)
	}
	next, _ := newCollector(t, f, path)
	next.Restore()
	if u := next.Snapshot().Updates; u == nil || !u.Clean() {
		t.Fatalf("the cache holds %+v, want the good reading", u)
	}
}

// A failed reading saved because there was no good one is restored as the
// last known state, and is not a fresh reading: the start checks again.
func TestRestore_AFailedReadingIsNotFresh(t *testing.T) {
	f := newFakeOPNsense(t)
	f.set(func(f *fakeOPNsense) { f.lastCheck, f.failChecks = "", true })
	path := filepath.Join(t.TempDir(), "heavy.json")
	prev, _ := newCollector(t, f, path)
	prev.check(context.Background())

	h, clock := newCollector(t, f, path)
	h.Restore()
	if u := h.Snapshot().Updates; u == nil || u.Status != "error" {
		t.Fatalf("restored %+v, want the failed reading", u)
	}
	h.sched.planFirstCheck(clock.now(), h.startReading(), 20*time.Second, 0)
	if !h.sched.nextCheck.Equal(clock.now().Add(20 * time.Second)) {
		t.Fatalf("first check at %v: a restored failed reading counted as fresh", h.sched.nextCheck)
	}
}

// A restored block stamped from the future (a clock three days fast wrote it)
// is stamped now in memory, so the bounds count from this start, not from a
// moment days away.
func TestRestore_RestampsAStampFromTheFuture(t *testing.T) {
	f := newFakeOPNsense(t)
	path := filepath.Join(t.TempDir(), "heavy.json")
	ahead, _ := newCollector(t, f, path)
	ahead.now = func() time.Time { return testStart.Add(72 * time.Hour) }
	ahead.gather(context.Background())

	h, clock := newCollector(t, f, path)
	h.Restore()
	snap := h.Snapshot()
	if snap == nil || snap.Services == nil || snap.Updates == nil || snap.Certs == nil ||
		snap.Services.AsOf != asOf(clock.now()) || snap.Updates.AsOf != asOf(clock.now()) || snap.Certs.AsOf != asOf(clock.now()) {
		t.Fatalf("restored %+v, want every block stamped now", snap)
	}

	h.sched.gathered(clock.now(), true) // past the start's grace
	clock.advance(servicesMaxAge + time.Second)
	f.set(func(f *fakeOPNsense) { f.servicesDown, f.certsDown = true, true })
	h.gather(context.Background())
	if snap := h.Snapshot(); snap.Services != nil || snap.Certs != nil {
		t.Fatalf("restored blocks from the future outlived their bound: %+v", snap)
	}
}

// A clock behind at boot (a dead RTC, or one kept in local time) makes the
// true stamps of the saved snapshot look like the future. They are moved to
// that wrong "now" in memory only: the file keeps the stamps the blocks were
// collected with, through the restore and through the saves that follow, so
// they are right again once NTP has set the clock.
func TestRestore_AClockBehindDoesNotRewriteTheStamps(t *testing.T) {
	f := newFakeOPNsense(t)
	path := filepath.Join(t.TempDir(), "heavy.json")
	prev, _ := newCollector(t, f, path)
	prev.gather(context.Background())
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	h, clock := newCollector(t, f, path)
	clock.advance(-3 * time.Hour)
	h.Restore()
	if after, err := os.Stat(path); err != nil || !os.SameFile(before, after) {
		t.Fatalf("the restore rewrote the file (%v)", err)
	}
	if u := h.Snapshot().Updates; u == nil || u.AsOf != asOf(clock.now()) {
		t.Fatalf("updates = %+v, want the stamp moved to now in memory", u)
	}

	// After a boot OPNsense has no check result: the restored reading is
	// carried, and the first gather saves it with what it collected.
	f.set(func(f *fakeOPNsense) { f.lastCheck = "" })
	h.gather(context.Background())
	var saved heavyCacheFile
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &saved); err != nil || saved.Heavy == nil || saved.Heavy.Updates == nil {
		t.Fatalf("saved %s (%v)", data, err)
	}
	if got := saved.Heavy.Updates.AsOf; got != asOf(testStart) {
		t.Fatalf("the carried update reading was saved with as_of %v, want the stamp it was collected with (%v)",
			got, asOf(testStart))
	}
}

func TestRestore_IgnoresAFileItCannotUse(t *testing.T) {
	f := newFakeOPNsense(t)
	for name, content := range map[string]string{
		"corrupt":         `{"v":1,"heavy":`,
		"another version": `{"v":2,"heavy":{"services":{"items":[],"as_of":1},"collected_at":1}}`,
		"no snapshot":     `{"v":1}`,
		"no block":        `{"v":1,"heavy":{"collected_at":1}}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "heavy.json")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			h, _ := newCollector(t, f, path)
			h.Restore()
			if snap := h.Snapshot(); snap != nil {
				t.Fatalf("restored %+v", snap)
			}
		})
	}
}

// The state directory is not recreated: once a decommission removed it,
// nothing is written back.
func TestSave_DoesNotCreateTheStateDirectory(t *testing.T) {
	f := newFakeOPNsense(t)
	dir := filepath.Join(t.TempDir(), "ndagent")
	h, _ := newCollector(t, f, filepath.Join(dir, "heavy.json"))
	h.gather(context.Background())
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("the state directory was created: %v", err)
	}
}

func TestRemoveCache(t *testing.T) {
	f := newFakeOPNsense(t)
	path := filepath.Join(t.TempDir(), "heavy.json")
	h, _ := newCollector(t, f, path)
	h.gather(context.Background())
	if err := h.RemoveCache(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("the snapshot survived: %v", err)
	}
	if err := h.RemoveCache(); err != nil {
		t.Fatalf("removing an absent snapshot: %v", err)
	}
}

// The wire shape of the update reading after a check, as NDBroker receives it.
func TestUpdatesBlockWireShape(t *testing.T) {
	f := newFakeOPNsense(t)
	h, _ := newCollector(t, f, "")
	h.check(context.Background())
	raw, err := json.Marshal(h.Snapshot().Updates)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"opnsense_version":"26.7"`, `"opnsense_latest":"26.7.5"`, `"opnsense_package":"opnsense"`, `"last_check_unix":`, `"as_of":`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("%s missing from %s", want, raw)
		}
	}
}
