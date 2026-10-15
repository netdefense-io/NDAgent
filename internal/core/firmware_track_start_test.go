package core

import (
	"context"
	"fmt"
	"go/ast"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/firmware"
	"github.com/netdefense-io/ndagent/internal/firmware/track"
	"github.com/netdefense-io/ndagent/internal/opnapi"
	"github.com/netdefense-io/ndagent/internal/telemetry"
)

// The start order. A firmware check is a write when the catalog it reads carries a
// newer pkg (core check.sh upgrades pkg itself), so the first check of a process
// must not run before the firmware pin has been put right: on a live url a check
// made first would upgrade the package manager against an unpinned catalog, and the
// re-pin cannot undo it. The supervisor's first round runs as soon as the firmware
// API answers, and the heavy-telemetry collector's checks wait behind the gate it
// closes.

// eventLog is the order in which the device and the collector were asked things.
type eventLog struct {
	mu     sync.Mutex
	events []string
}

func (l *eventLog) add(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, fmt.Sprintf(format, args...))
}

func (l *eventLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.events...)
}

func (l *eventLog) index(prefix string) int {
	for i, e := range l.snapshot() {
		if strings.HasPrefix(e, prefix) {
			return i
		}
	}
	return -1
}

// orderedDevice is a pinnedDevice that tells the log when its pin is written, and
// whose firmware API can be made not to answer.
type orderedDevice struct {
	*pinnedDevice
	log *eventLog

	apiMu   sync.Mutex
	apiDown bool
}

func (d *orderedDevice) setAPIDown(down bool) {
	d.apiMu.Lock()
	defer d.apiMu.Unlock()
	d.apiDown = down
}

func (d *orderedDevice) down() bool {
	d.apiMu.Lock()
	defer d.apiMu.Unlock()
	return d.apiDown
}

func (d *orderedDevice) Settings(ctx context.Context) (opnapi.FirmwareSettings, error) {
	if d.down() {
		return opnapi.FirmwareSettings{}, fmt.Errorf("the firmware API does not answer yet")
	}
	return d.pinnedDevice.Settings(ctx)
}

func (d *orderedDevice) SetFlavour(ctx context.Context, f string) error {
	d.log.add("set %s", f)
	return d.pinnedDevice.SetFlavour(ctx, f)
}

func (d *orderedDevice) flavourNow() string {
	d.pinnedDevice.mu.Lock()
	defer d.pinnedDevice.mu.Unlock()
	return d.pinnedDevice.flavour
}

// fakeOPNsenseAPI answers what the collector reads over REST, and tells the log
// when a firmware check is asked for and which flavour the box held then.
func fakeOPNsenseAPI(t *testing.T, log *eventLog, dev *orderedDevice) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	checked := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/core/service/search":
			_, _ = w.Write([]byte(`{"rows":[{"name":"unbound","description":"DNS","running":1}]}`))
		case "/trust/cert/search":
			_, _ = w.Write([]byte(`{"rows":[]}`))
		case "/core/firmware/check":
			log.add("collector check, flavour %s", dev.flavourNow())
			mu.Lock()
			checked = true
			mu.Unlock()
			_, _ = w.Write([]byte(`{"status":"ok","msg_uuid":"x"}`))
		case "/core/firmware/running":
			_, _ = w.Write([]byte(`{"status":"ready"}`))
		case "/core/firmware/status":
			mu.Lock()
			done := checked
			mu.Unlock()
			if !done {
				_, _ = w.Write([]byte(`{"status":"none","product":{"product_version":"26.7.1_1"}}`))
				return
			}
			_, _ = w.Write([]byte(`{"status":"none","last_check":"Mon Oct 12 20:12:37 UTC 2026","connection":"ok","repository":"ok",` +
				`"product_version":"26.7.1_1","upgrade_packages":[],"product":{"product_version":"26.7.1_1","product_id":"opnsense"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// startCollector runs a real collector, over the fake API, whose first check is
// planned for the moment it starts.
func startCollector(t *testing.T, srv *httptest.Server, gate <-chan struct{}) {
	t.Helper()
	firmware.ResetGuardForTest()
	t.Cleanup(firmware.ResetGuardForTest)
	h := telemetry.NewHeavyCollector(opnapi.NewClient(srv.URL, "k", "s", true), "")
	telemetry.SetScheduleForTest(h, time.Now, func(time.Duration) time.Duration { return time.Millisecond },
		time.Millisecond, 2*time.Second, 5*time.Millisecond)
	telemetry.SetInstalledVersionForTest(h, func() string { return "26.7.1_1" })
	telemetry.SetBootTimeForTest(h, func() (int64, error) { return time.Now().Add(-time.Minute).Unix(), nil })
	if gate != nil {
		h.SetCheckGate(gate)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = h.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
		firmware.Watch(0)
	})
}

// quickStart makes the supervisor poll in milliseconds and give up on the API after
// a bound the test can reach.
func quickStart(t *testing.T, bound time.Duration) {
	t.Helper()
	prevPoll, prevBound := trackSettlePoll, trackSettleBound
	trackSettlePoll, trackSettleBound = 5*time.Millisecond, bound
	t.Cleanup(func() { trackSettlePoll, trackSettleBound = prevPoll, prevBound })
}

// A device that landed from a series upgrade (or whose pin was reset) holds a pin
// that names another series than the one installed, on a box whose firmware API is
// not up yet when the agent starts. The collector's first check is planned a
// millisecond after the start. The pin is written first, and the check follows.
func TestFirstFirmwareCheckWaitsForTheReconcile(t *testing.T) {
	quickStart(t, time.Minute)
	log := &eventLog{}
	dev := &orderedDevice{pinnedDevice: &pinnedDevice{flavour: "26.1/MINT/26.1.11/latest", installed: "26.7.1_1"}, log: log}
	dev.setAPIDown(true)
	engine, st := newTrackEngine(t, dev)
	if err := st.Save(&track.State{Pinned: true, Track: "fast", PinnedFlavour: "26.1/MINT/26.1.11/latest", PinnedVersion: "26.1.11_10"}); err != nil {
		t.Fatal(err)
	}
	srv := fakeOPNsenseAPI(t, log, dev)
	s := &trackSupervisor{engine: engine, contact: &track.Contact{}}

	startCollector(t, srv, s.Settled())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.loop(ctx, time.Hour, func(string, ...interface{}) {})
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	// The collector is ready to check at once and the API is down: the check waits.
	time.Sleep(150 * time.Millisecond)
	if i := log.index("collector check"); i >= 0 {
		t.Fatalf("the collector checked before the pin was put right: %v", log.snapshot())
	}
	select {
	case <-s.Settled():
		t.Fatal("the gate is closed before a round could read the device")
	default:
	}

	dev.setAPIDown(false) // the web GUI and configd come up
	deadline := time.Now().Add(10 * time.Second)
	for log.index("collector check") < 0 {
		if time.Now().After(deadline) {
			t.Fatalf("the collector never checked: %v", log.snapshot())
		}
		time.Sleep(5 * time.Millisecond)
	}
	events := log.snapshot()
	set, check := log.index("set 26.7/MINT/"), log.index("collector check")
	if set < 0 || check < set {
		t.Fatalf("events %v: the pin must be re-written before the first check", events)
	}
	if !strings.Contains(events[check], "flavour 26.7/MINT/") {
		t.Errorf("the check was made on %q: the box still held the old series' pin", events[check])
	}
}

// With no record there is no pin to put right and no gate: the first check runs on
// its schedule, not after the bound.
func TestFirstFirmwareCheckHasNoGateWhenThereIsNoRecord(t *testing.T) {
	quickStart(t, time.Hour)
	log := &eventLog{}
	dev := &orderedDevice{pinnedDevice: &pinnedDevice{installed: "26.7.1_1"}, log: log}
	dev.setAPIDown(true) // nothing needs the API when there is no record
	engine, _ := newTrackEngine(t, dev)
	srv := fakeOPNsenseAPI(t, log, dev)
	s := &trackSupervisor{engine: engine, contact: &track.Contact{}}

	startCollector(t, srv, s.Settled())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.loop(ctx, time.Hour, func(string, ...interface{}) {})
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	deadline := time.Now().Add(10 * time.Second)
	for log.index("collector check") < 0 {
		if time.Now().After(deadline) {
			t.Fatalf("the collector never checked, with no record to wait for: %v", log.snapshot())
		}
		time.Sleep(5 * time.Millisecond)
	}
	select {
	case <-s.Settled():
	default:
		t.Error("the gate stays closed on a device with no record")
	}
}

// A firmware API that never answers does not keep the device from checking for
// ever: the gate opens at the bound after the start.
func TestFirstFirmwareCheckIsReleasedAtTheBoundWhenTheAPINeverAnswers(t *testing.T) {
	quickStart(t, 300*time.Millisecond)
	log := &eventLog{}
	dev := &orderedDevice{pinnedDevice: &pinnedDevice{flavour: "26.1/MINT/26.1.11/latest", installed: "26.7.1_1"}, log: log}
	dev.setAPIDown(true)
	engine, st := newTrackEngine(t, dev)
	if err := st.Save(&track.State{Pinned: true, Track: "fast", PinnedFlavour: "26.1/MINT/26.1.11/latest", PinnedVersion: "26.1.11_10"}); err != nil {
		t.Fatal(err)
	}
	srv := fakeOPNsenseAPI(t, log, dev)
	s := &trackSupervisor{engine: engine, contact: &track.Contact{}}

	startCollector(t, srv, s.Settled())
	var logged []string
	var logMu sync.Mutex
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	started := time.Now()
	go func() {
		defer close(done)
		s.loop(ctx, time.Hour, func(format string, args ...interface{}) {
			logMu.Lock()
			logged = append(logged, fmt.Sprintf(format, args...))
			logMu.Unlock()
		})
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	deadline := time.Now().Add(10 * time.Second)
	for log.index("collector check") < 0 {
		if time.Now().After(deadline) {
			t.Fatalf("the gate was never released: %v", log.snapshot())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if took := time.Since(started); took < 250*time.Millisecond {
		t.Errorf("the check ran after %v, before the bound", took)
	}
	if dev.flavourNow() != "26.1/MINT/26.1.11/latest" {
		t.Errorf("flavour %q: the pin could not be written with the API down", dev.flavourNow())
	}
	logMu.Lock()
	defer logMu.Unlock()
	if len(logged) == 0 {
		t.Error("the bound was passed in silence")
	}
}

// The gate is the supervisor's own, closed once, whatever ended the start-up, and
// a process that is stopped does not hold the collector.
func TestTrackSupervisor_TheGateClosesWhenTheSupervisorIsStopped(t *testing.T) {
	quickStart(t, time.Hour)
	dev := &orderedDevice{pinnedDevice: &pinnedDevice{flavour: trackPrev, installed: "26.7.3_11"}, log: &eventLog{}}
	dev.setAPIDown(true)
	engine, st := newTrackEngine(t, dev)
	if err := st.Save(&track.State{Pinned: true, Track: "fast", PinnedFlavour: trackPrev, PinnedVersion: "26.7.3_11"}); err != nil {
		t.Fatal(err)
	}
	s := &trackSupervisor{engine: engine, contact: &track.Contact{}}
	ctx, cancel := context.WithCancel(context.Background())
	s.start(ctx, func(string, ...interface{}) {})
	select {
	case <-s.Settled():
		t.Fatal("closed before a round could read the device")
	case <-time.After(60 * time.Millisecond):
	}
	s.stop()
	select {
	case <-s.Settled():
	default:
		t.Error("a stopped supervisor leaves the collector waiting")
	}
	cancel()
}

// The lifecycle hands the supervisor's gate to the collector; nothing ties them at
// compile time and a missed call is silent (the first check would then run on
// whatever pin the box has).
func TestLifecycleGatesTheFirstFirmwareCheck(t *testing.T) {
	files := parseCorePackage(t)
	fn := funcDecl(files, "NewLifecycleManager")
	if fn == nil {
		t.Fatal("NewLifecycleManager not found")
	}
	gated := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if _, ok := isCall(n, "SetCheckGate"); ok {
			gated = true
		}
		return true
	})
	if !gated {
		t.Error("NewLifecycleManager does not give the collector the tracks' gate: the first firmware check would not wait for the pin")
	}
}

// A series upgrade that was requested and has not been settled by its row owns the
// pin: the round leaves it alone, so the gate stays closed until the row's finish
// has re-pinned the box and cleared the pending move. (On a same-ABI landing the old
// pin still answers, and a check made before the re-pin is the exposure the gate
// exists for.)
func TestTrackSupervisor_AnUnsettledUpgradeKeepsTheGateClosedUntilItsRowIsSettled(t *testing.T) {
	quickStart(t, time.Hour)
	dev := &orderedDevice{pinnedDevice: &pinnedDevice{flavour: "26.1/MINT/26.1.11/latest", installed: "26.7.1_1"}, log: &eventLog{}}
	engine, st := newTrackEngine(t, dev)
	if err := st.Save(&track.State{
		Pinned: true, Track: "fast", PinnedFlavour: "26.1/MINT/26.1.11/latest", PinnedVersion: "26.1.11_10",
		Pending: &track.Pending{Op: track.ActionAdvance, TaskID: "101", FromFlavour: "26.1/MINT/26.1.11/latest",
			ToFlavour: "26.1/MINT/26.1.11/latest", Triggered: true, Major: "26.7", StartedAt: time.Now().Unix()},
	}); err != nil {
		t.Fatal(err)
	}
	s := &trackSupervisor{engine: engine, contact: &track.Contact{}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.loop(ctx, time.Hour, func(string, ...interface{}) {})
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	select {
	case <-s.Settled():
		t.Fatal("the gate closed while the upgrade's row was unsettled")
	case <-time.After(100 * time.Millisecond):
	}
	if flavour := dev.flavourNow(); flavour != "26.1/MINT/26.1.11/latest" {
		t.Errorf("flavour %q: the round wrote under a requested upgrade", flavour)
	}

	// The row's finish: the pin on the new series, the pending move gone.
	dev.SetFlavour(context.Background(), "26.7/MINT/26.7.1/latest")
	if _, err := st.Update(func(s *track.State) {
		s.PinnedFlavour, s.PinnedVersion, s.Pending = "26.7/MINT/26.7.1/latest", "26.7.1_1", nil
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.Settled():
	case <-time.After(5 * time.Second):
		t.Fatal("the gate stayed closed after the row was settled")
	}
}
