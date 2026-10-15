package track

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/firmware"
)

func TestTick_PutsBackAResetFlavourAndFlagsTheDriftForTheNextResult(t *testing.T) {
	r := enrolledRig(t)
	r.dev.do(func(d *simDevice) { d.flavour = "" })

	r.eng.Tick(context.Background())

	if r.dev.Flavour() != "26.7/MINT/26.7.3/latest" {
		t.Fatalf("flavour %q", r.dev.Flavour())
	}
	if st := r.state(); !st.DriftPending || st.PinnedFlavour != "26.7/MINT/26.7.3/latest" || st.Pending != nil {
		t.Fatalf("record %+v", st)
	}
	// The re-pin is followed by a forced check.
	if r.dev.count("check") != 1 {
		t.Errorf("checks %d", r.dev.count("check"))
	}

	// The drift the reconcile repaired is still reported, once.
	res := wantResult(t, r.run(advancePayload(TrackFast, true, map[string]string{"26.7": "26.7.3"})), OutcomeNoop, ReasonPinDrift)
	if !res.Drift {
		t.Error("the repaired drift was not reported")
	}
	res = wantResult(t, r.run(advancePayload(TrackFast, true, map[string]string{"26.7": "26.7.3"})), OutcomeNoop, ReasonAtOrAboveTarget)
	if res.Drift {
		t.Error("the drift was reported twice")
	}
}

// The repository file is generated from the pin, so after a major upgrade made
// outside NetDefense it still names the old series: the series to pin is the
// installed release's, and the periodic round must manage it all the same.
func TestTick_RePinsOnTheNewSeriesAfterAMajorMadeOutsideNetDefense(t *testing.T) {
	r := enrolledRig(t)
	r.dev.do(afterAGUIMajor)

	r.eng.Tick(context.Background())

	if got := r.dev.Flavour(); got != "27.1/MINT/27.1/latest" {
		t.Fatalf("flavour %q", got)
	}
	if st := r.state(); !st.Pinned || st.PinnedFlavour != "27.1/MINT/27.1/latest" || st.PinnedVersion != "27.1" || !st.DriftPending || st.Pending != nil {
		t.Fatalf("record %+v", st)
	}
	if r.dev.count("check") != 1 {
		t.Errorf("checks %d: the re-pin is followed by a forced check", r.dev.count("check"))
	}
}

// A flavour that is reset every few minutes (a tool that saves the firmware form
// with it empty) costs two config revisions and a catalog refetch each time: the
// round backs off, and a quiet day starts it over.
func TestTick_AFlavourResetOverAndOverIsPutBackWithGrowingWaits(t *testing.T) {
	r := enrolledRig(t)
	clock := r.onClock()
	start := clock.Now()
	var rePins []time.Duration
	round := func() {
		r.dev.do(func(d *simDevice) { d.flavour = "" })
		before := len(r.dev.writes())
		r.eng.Tick(context.Background())
		if len(r.dev.writes()) > before {
			rePins = append(rePins, clock.Now().Sub(start))
		}
	}
	for i := 0; i < 72; i++ { // six hours of rounds, every five minutes
		round()
		clock.Advance(5 * time.Minute)
	}
	if len(rePins) < 4 || len(rePins) > 9 {
		t.Fatalf("%d re-pins in six hours at %v, want a handful", len(rePins), rePins)
	}
	for i := 2; i < len(rePins); i++ {
		if rePins[i]-rePins[i-1] < rePins[i-1]-rePins[i-2] {
			t.Errorf("the wait shrank: re-pins at %v", rePins)
		}
	}
	if gap := rePins[1] - rePins[0]; gap != 5*time.Minute {
		t.Errorf("the second re-pin came %v after the first: the first is never held back", gap)
	}
	if st := r.state(); !st.DriftPending {
		t.Errorf("record %+v: the drift is still to be reported", st)
	}

	// A day with no re-pin ends the streak.
	clock.Advance(25 * time.Hour)
	rePins = nil
	for i := 0; i < 2; i++ {
		round()
		clock.Advance(5 * time.Minute)
	}
	if len(rePins) != 2 {
		t.Errorf("re-pins after a quiet day: %v, want both rounds to write", rePins)
	}
}

func TestTick_DoesNothingForADeviceWithoutAPin(t *testing.T) {
	r := newRig(t)
	r.eng.Tick(context.Background())
	if len(r.dev.Calls()) != 0 {
		t.Errorf("calls %v", r.dev.Calls())
	}
}

func TestTick_LeavesAFineDeviceAlone(t *testing.T) {
	r := enrolledRig(t)
	r.eng.Tick(context.Background())
	if r.dev.count("set") != 0 || r.dev.count("check") != 0 || r.dev.count("probe") != 0 {
		t.Errorf("calls %v: a pin that is right needs no write, no check, no probe", r.dev.Calls())
	}
}

func TestTick_HealsARepositoryFileThatDivergedFromTheSetting(t *testing.T) {
	r := enrolledRig(t)
	r.dev.do(func(d *simDevice) { d.repoDiverged = true }) // opnsense-update -sd rewrote the file alone

	r.eng.Tick(context.Background())

	if got := r.dev.writes(); !equal(got, []string{"26.7/MINT/26.7.3/latest"}) {
		t.Fatalf("writes %v: the setting is written again so OPNsense replays it into the files", got)
	}
	if r.dev.repoDiverged {
		t.Error("the file still diverges")
	}
	if st := r.state(); !st.DriftPending {
		t.Errorf("record %+v", st)
	}
}

func TestTick_NeverPinsBelowTheInstalledRelease(t *testing.T) {
	r := enrolledRig(t)
	r.dev.do(func(d *simDevice) { // updated outside NetDefense, and the flavour reset
		d.flavour = ""
		d.core, d.updatePkg, d.sets = "26.7.5", "26.7.4_1", "26.7.4"
		d.pkgs["opnsense"] = "26.7.5"
	})
	r.eng.Tick(context.Background())
	if got := r.dev.writes(); !equal(got, []string{"26.7/MINT/26.7.5/latest"}) {
		t.Errorf("writes %v", got)
	}
}

func TestTick_DoesNotTouchADeviceThatGainedASubscription(t *testing.T) {
	r := enrolledRig(t)
	r.dev.do(func(d *simDevice) { d.subscription, d.flavour = true, "" })
	r.eng.Tick(context.Background())
	if len(r.dev.writes()) != 0 {
		t.Errorf("writes %v", r.dev.writes())
	}
}

func TestTick_BacksOffAfterAPinItCouldNotWrite(t *testing.T) {
	r := enrolledRig(t)
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	r.eng = r.newEngine(WithClock(func() time.Time { return now }))
	r.dev.do(func(d *simDevice) {
		d.flavour = ""
		delete(d.folders, "26.7.3")
	})
	r.eng.Tick(context.Background())
	probes := r.dev.count("probe")
	if probes == 0 || len(r.dev.writes()) != 0 {
		t.Fatalf("calls %v", r.dev.Calls())
	}
	r.eng.Tick(context.Background())
	if r.dev.count("probe") != probes {
		t.Errorf("the mirror was asked again within the back-off: %v", r.dev.Calls())
	}
	now = now.Add(repinBackoff + time.Minute)
	r.eng.forgetProbes()
	r.eng.Tick(context.Background())
	if r.dev.count("probe") == probes {
		t.Errorf("the mirror was not asked again after the back-off")
	}
}

func TestTick_SkipsWhileAFirmwareJobHoldsTheSlot(t *testing.T) {
	r := enrolledRig(t)
	r.dev.do(func(d *simDevice) { d.flavour = "" })
	release, err := firmware.Acquire(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	r.eng.Tick(context.Background())
	release()
	if len(r.dev.Calls()) != 0 {
		t.Errorf("calls %v: the periodic work must not queue behind an update", r.dev.Calls())
	}
}

// A check, an update started from the GUI, one that outlived its task: the round
// does not write the flavour under it.
func TestTick_DoesNotWriteUnderARunningFirmwareJob(t *testing.T) {
	r := enrolledRig(t)
	r.dev.do(func(d *simDevice) { d.flavour = ""; d.alwaysBusy = true })
	r.eng.Tick(context.Background())
	if len(r.dev.writes()) != 0 {
		t.Fatalf("writes %v", r.dev.writes())
	}
	r.dev.do(func(d *simDevice) { d.alwaysBusy = false; d.pkgToolsBusy = true }) // a package tool, with the lock free
	r.eng.Tick(context.Background())
	if len(r.dev.writes()) != 0 {
		t.Fatalf("writes %v: pkg was running", r.dev.writes())
	}
	r.dev.do(func(d *simDevice) { d.pkgToolsBusy = false })
	r.eng.Tick(context.Background())
	if len(r.dev.writes()) != 1 {
		t.Fatalf("writes %v: once the box is idle the pin is put back", r.dev.writes())
	}
}

func TestTick_RepairsAnInterruptedOperationOnlyOnceTheBoxIsIdle(t *testing.T) {
	r := enrolledRig(t)
	prev, next := "26.7/MINT/26.7.3/latest", "26.7/MINT/26.7.5/latest"
	r.dev.do(func(d *simDevice) { d.flavour = next; d.alwaysBusy = true })
	if _, err := r.store.Update(func(s *State) {
		s.Pending = &Pending{Op: ActionAdvance, FromFlavour: prev, ToFlavour: next, StartedAt: time.Now().Unix()}
	}); err != nil {
		t.Fatal(err)
	}
	r.eng.Tick(context.Background())
	if r.dev.Flavour() != next || r.state().Pending == nil {
		t.Fatalf("repaired under a running job: flavour %q, record %+v", r.dev.Flavour(), r.state())
	}
	r.dev.do(func(d *simDevice) { d.alwaysBusy = false })
	r.eng.Tick(context.Background())
	if r.dev.Flavour() != prev || r.state().Pending != nil {
		t.Fatalf("flavour %q, record %+v", r.dev.Flavour(), r.state())
	}
}

func TestTick_SkipsWhileATaskRuns(t *testing.T) {
	r := enrolledRig(t)
	r.dev.do(func(d *simDevice) { d.flavour = "" })
	r.eng.mu.Lock()
	r.eng.Tick(context.Background())
	r.eng.mu.Unlock()
	if len(r.dev.Calls()) != 0 {
		t.Errorf("calls %v", r.dev.Calls())
	}
}

// --- an operation that did not end ------------------------------------------------

func TestTick_RollsBackAnEnrollmentThatDiedAfterWritingTheFlavour(t *testing.T) {
	r := newRig(t)
	pin := "26.7/MINT/26.7.3/latest"
	r.dev.do(func(d *simDevice) { d.flavour = pin })
	if err := r.store.Save(&State{Pending: &Pending{Op: ActionEnroll, FromFlavour: "", ToFlavour: pin, StartedAt: time.Now().Unix()}}); err != nil {
		t.Fatal(err)
	}
	r.eng.Tick(context.Background())
	if r.dev.Flavour() != "" {
		t.Errorf("flavour %q", r.dev.Flavour())
	}
	if st := r.state(); st != nil {
		t.Errorf("record %+v", st)
	}
}

func TestTick_PutsBackAnAdvanceThatDiedBeforeRequestingTheUpdate(t *testing.T) {
	r := enrolledRig(t)
	prev, next := "26.7/MINT/26.7.3/latest", "26.7/MINT/26.7.5/latest"
	r.dev.do(func(d *simDevice) { d.flavour = next })
	if _, err := r.store.Update(func(s *State) {
		s.Pending = &Pending{Op: ActionAdvance, FromFlavour: prev, ToFlavour: next, StartedAt: time.Now().Unix()}
	}); err != nil {
		t.Fatal(err)
	}
	r.eng.Tick(context.Background())
	if r.dev.Flavour() != prev {
		t.Errorf("flavour %q", r.dev.Flavour())
	}
	if st := r.state(); st.Pending != nil || !st.Pinned || st.PinnedFlavour != prev {
		t.Errorf("record %+v", st)
	}
}

func TestTick_LeavesARequestedUpdateToItsRow(t *testing.T) {
	r := enrolledRig(t)
	prev, next := "26.7/MINT/26.7.3/latest", "26.7/MINT/26.7.5/latest"
	r.dev.do(func(d *simDevice) { d.flavour = next })
	if _, err := r.store.Update(func(s *State) {
		s.Pending = &Pending{Op: ActionAdvance, FromFlavour: prev, ToFlavour: next, Triggered: true, StartedAt: time.Now().Unix()}
	}); err != nil {
		t.Fatal(err)
	}
	r.eng.Tick(context.Background())
	if r.dev.Flavour() != next || r.state().Pending == nil {
		t.Errorf("a requested update is the row reconciler's: flavour %q, record %+v", r.dev.Flavour(), r.state())
	}
}

func TestTick_FinishesAnUnenrollThatDied(t *testing.T) {
	r := enrolledRig(t)
	if _, err := r.store.Update(func(s *State) {
		s.Pending = &Pending{Op: ActionUnenroll, FromFlavour: s.PinnedFlavour, ToFlavour: "", StartedAt: time.Now().Unix()}
	}); err != nil {
		t.Fatal(err)
	}
	r.eng.Tick(context.Background())
	if r.dev.Flavour() != "" || r.state() != nil {
		t.Errorf("flavour %q, record %+v", r.dev.Flavour(), r.state())
	}
}

func TestTick_RollsAnInterruptedRePinForwardWhenItsWriteTookEffect(t *testing.T) {
	r := enrolledRig(t)
	newPin := "26.7/MINT/26.7.5/latest"
	r.dev.do(func(d *simDevice) {
		d.flavour = newPin
		d.core, d.updatePkg, d.sets = "26.7.5", "26.7.4_1", "26.7.4"
		d.pkgs["opnsense"] = "26.7.5"
	})
	if _, err := r.store.Update(func(s *State) {
		s.Pending = &Pending{Op: "repin", FromFlavour: s.PinnedFlavour, ToFlavour: newPin, StartedAt: time.Now().Unix()}
	}); err != nil {
		t.Fatal(err)
	}
	r.eng.Tick(context.Background())
	if st := r.state(); st.PinnedFlavour != newPin || st.Pending != nil {
		t.Errorf("record %+v", st)
	}
	if len(r.dev.writes()) != 0 {
		t.Errorf("writes %v", r.dev.writes())
	}
}

func TestTask_RepairsAnInterruptedOperationBeforeItActs(t *testing.T) {
	r := enrolledRig(t, onlyHotfixes, func(d *simDevice) {
		d.core = "26.7.3_8"
		d.pkgs["opnsense"] = "26.7.3_8"
	})
	prev, next := "26.7/MINT/26.7.3/latest", "26.7/MINT/26.7.5/latest"
	r.dev.do(func(d *simDevice) { d.flavour = next })
	_, _ = r.store.Update(func(s *State) {
		s.Pending = &Pending{Op: ActionAdvance, FromFlavour: prev, ToFlavour: next, StartedAt: time.Now().Unix()}
	})
	out := r.run(advancePayload(TrackFast, true, map[string]string{"26.7": "26.7.3"}))
	wantResult(t, out, OutcomeSuccess, ReasonApplied)
	if got := r.dev.writes(); len(got) == 0 || got[0] != prev {
		t.Errorf("writes %v: the pin should have been put back first", got)
	}
}

// --- the dead-man -----------------------------------------------------------------

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

var day = 24 * time.Hour

// deadManRig is a device enrolled at a fixed time, an engine on a clock the test
// moves, and a contact tracker the test drives.
func deadManRig(t *testing.T) (*rig, *fakeClock, *Contact) {
	t.Helper()
	clock := &fakeClock{t: time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)}
	r := newRig(t)
	r.clock = clock // the tasks the rig runs are taken up by it
	contact := &Contact{}
	r.eng = New(r.dev, r.store, contact,
		WithTiming(fastTiming()), WithJitter(func(time.Duration) time.Duration { return 0 }),
		WithUptime(func() time.Duration { return time.Hour }), WithBootTime(r.dev.BootTime), WithClock(clock.Now))
	enrolled(t, r)
	return r, clock, contact
}

func TestDeadMan_ReleasesThePinAfterThirtyDaysOfSilence(t *testing.T) {
	r, clock, _ := deadManRig(t)

	clock.Advance(29 * day)
	r.eng.Tick(context.Background())
	if r.dev.Flavour() == "" {
		t.Fatal("released after 29 days")
	}

	clock.Advance(day) // exactly 30 days: the rule is "at least"
	r.eng.Tick(context.Background())
	if r.dev.Flavour() == "" {
		t.Fatal("released at the first sighting: it has to be confirmed")
	}
	clock.Advance(deadManConfirm - time.Minute)
	r.eng.Tick(context.Background())
	if r.dev.Flavour() == "" {
		t.Fatal("released before the confirmation time")
	}

	clock.Advance(2 * time.Minute)
	r.eng.Tick(context.Background())
	if r.dev.Flavour() != "" {
		t.Fatalf("flavour %q: the pin should be released", r.dev.Flavour())
	}
	st := r.state()
	if st == nil || st.Pinned || st.PinnedFlavour != "" || st.Released == nil || st.Released.Reason != "dead_man" {
		t.Fatalf("record %+v", st)
	}
	// The restore is followed by a forced check.
	if r.dev.count("check") != 1 {
		t.Errorf("checks %d", r.dev.count("check"))
	}

	// The tombstone keeps the periodic reconcile from pinning the device again.
	r.dev.calls = nil
	clock.Advance(day)
	r.eng.Tick(context.Background())
	if len(r.dev.Calls()) != 0 {
		t.Errorf("calls after the release: %v", r.dev.Calls())
	}
}

func TestDeadMan_AnAuthenticatedContactResetsTheClock(t *testing.T) {
	r, clock, contact := deadManRig(t)
	clock.Advance(20 * day)
	contact.SessionStarted(clock.Now())
	for i := 0; i < 100; i++ { // a connection that stays up for 100 days
		clock.Advance(day)
		contact.SessionAlive(clock.Now())
		r.eng.Tick(context.Background())
		clock.Advance(deadManConfirm + time.Minute)
		r.eng.Tick(context.Background())
	}
	if r.dev.Flavour() == "" {
		t.Fatal("a device whose connection is up was released")
	}
	if st := r.state(); st.LastContact == 0 {
		t.Errorf("the contact was not saved: %+v", st)
	}
}

func TestDeadMan_TheSilenceCountsFromTheEndOfTheLastConnection(t *testing.T) {
	r, clock, contact := deadManRig(t)
	contact.SessionStarted(clock.Now())
	clock.Advance(10 * day)
	contact.SessionEnded(clock.Now()) // the device is disabled from here on

	clock.Advance(29 * day) // 29 days since the contact, 39 since the enrollment
	r.eng.Tick(context.Background())
	clock.Advance(deadManConfirm + time.Minute)
	r.eng.Tick(context.Background())
	if r.dev.Flavour() == "" {
		t.Fatal("released 29 days after the last contact")
	}

	clock.Advance(day)
	r.eng.Tick(context.Background())
	clock.Advance(deadManConfirm + time.Minute)
	r.eng.Tick(context.Background())
	if r.dev.Flavour() != "" {
		t.Fatal("not released 30 days after the last contact")
	}
}

// A clock that jumped forward at boot, before NTP set it, reads as a month of
// silence for a few minutes. It has to hold on the monotonic clock too.
func TestDeadMan_AClockThatSteppedIsNotSilence(t *testing.T) {
	clock := &fakeClock{t: time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)}
	r := newRig(t)
	var mono time.Duration
	r.eng = New(r.dev, r.store, &Contact{},
		WithTiming(fastTiming()), WithJitter(func(time.Duration) time.Duration { return 0 }),
		WithUptime(func() time.Duration { return time.Hour }), WithBootTime(r.dev.BootTime),
		WithClock(clock.Now), WithMonotonic(func() time.Duration { return mono }))
	enrolled(t, r)

	clock.Advance(40 * day) // the wall clock jumps; the monotonic one did not move
	r.eng.Tick(context.Background())
	mono += deadManConfirm + time.Minute
	clock.Advance(deadManConfirm + time.Minute)
	clock.Advance(-40 * day) // NTP sets it right again
	r.eng.Tick(context.Background())
	if r.dev.Flavour() == "" {
		t.Fatal("released on a clock that stepped back")
	}
}

func TestDeadMan_WaitsForTheSlotAndRetries(t *testing.T) {
	r, clock, _ := deadManRig(t)
	clock.Advance(31 * day)
	r.eng.Tick(context.Background())
	clock.Advance(deadManConfirm + time.Minute)

	release, err := firmware.Acquire(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	r.eng.Tick(context.Background())
	release()
	if r.dev.Flavour() == "" {
		t.Fatal("released while another firmware job held the slot")
	}
	r.eng.Tick(context.Background())
	if r.dev.Flavour() != "" {
		t.Fatal("not released once the slot was free")
	}
}

func TestDeadMan_ARestoreThatFailsLeavesThePinForTheNextRound(t *testing.T) {
	r, clock, _ := deadManRig(t)
	clock.Advance(31 * day)
	r.eng.Tick(context.Background())
	clock.Advance(deadManConfirm + time.Minute)
	r.dev.do(func(d *simDevice) { d.setErr = errSim })
	r.eng.Tick(context.Background())
	if st := r.state(); !st.Pinned || st.Released != nil {
		t.Fatalf("record %+v: a pin that is still in force is not released", st)
	}
	r.dev.do(func(d *simDevice) { d.setErr = nil })
	r.eng.Tick(context.Background())
	if r.dev.Flavour() != "" {
		t.Fatal("not released once the restore could be made")
	}
}

func TestDeadMan_AFlavourSomebodyElseSetIsLeftAlone(t *testing.T) {
	r, clock, _ := deadManRig(t)
	r.dev.do(func(d *simDevice) { d.flavour = "26.7/MINT/26.7.1/latest" })
	r.eng.repinAfter = clock.Now().Add(365 * day) // the reconcile cannot put it back (its mirror is out of reach)
	clock.Advance(31 * day)
	r.eng.Tick(context.Background())
	clock.Advance(deadManConfirm + time.Minute)
	r.eng.Tick(context.Background())
	if r.dev.Flavour() != "26.7/MINT/26.7.1/latest" {
		t.Errorf("flavour %q", r.dev.Flavour())
	}
	if st := r.state(); st == nil || st.Pinned || st.Released == nil {
		t.Errorf("record %+v", st)
	}
}

// After a release by the dead-man the agent holds no pin. Only the control plane
// can ask it for one again: an enroll does, and an advance (the control plane
// still has the device) pins it first and says it did.
func TestDeadMan_AfterTheReleaseOnlyATaskPinsTheDeviceAgain(t *testing.T) {
	r, clock, _ := deadManRig(t)
	clock.Advance(31 * day)
	r.eng.Tick(context.Background())
	clock.Advance(deadManConfirm + time.Minute)
	r.eng.Tick(context.Background())
	if r.dev.Flavour() != "" {
		t.Fatal("not released")
	}

	res := wantResult(t, r.run(enrollPayload(TrackFast)), OutcomeSuccess, ReasonEnrolled)
	if res.Drift {
		t.Error("an enroll after a release is a plain enrollment")
	}
	if st := r.state(); !st.Pinned || st.Released != nil {
		t.Errorf("record %+v", st)
	}
}

func TestDeadMan_AnAdvanceAfterTheReleasePinsFirstAndFlagsIt(t *testing.T) {
	r, clock, _ := deadManRig(t)
	clock.Advance(31 * day)
	r.eng.Tick(context.Background())
	clock.Advance(deadManConfirm + time.Minute)
	r.eng.Tick(context.Background())

	res := wantResult(t, r.run(advancePayload(TrackFast, true, map[string]string{"26.7": "26.7.3"})), OutcomeNoop, ReasonPinDrift)
	if !res.Drift {
		t.Error("not flagged")
	}
	if r.dev.Flavour() != "26.7/MINT/26.7.3/latest" {
		t.Errorf("flavour %q", r.dev.Flavour())
	}
}

func TestDeadMan_AnUnenrollAfterTheReleaseIsANoop(t *testing.T) {
	r, clock, _ := deadManRig(t)
	clock.Advance(31 * day)
	r.eng.Tick(context.Background())
	clock.Advance(deadManConfirm + time.Minute)
	r.eng.Tick(context.Background())
	wantResult(t, r.run(unenrollPayload(TrackFast)), OutcomeNoop, ReasonUnenrolled)
	if r.state() != nil {
		t.Errorf("the tombstone survived: %+v", r.state())
	}
}

func TestContact_FollowsTheConnection(t *testing.T) {
	var c Contact
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	if last, live := c.Last(); !last.IsZero() || live {
		t.Fatal("a fresh tracker has no contact")
	}
	c.SessionAlive(t0) // a heartbeat with no accepted connection is not a contact
	if last, _ := c.Last(); !last.IsZero() {
		t.Fatal("a heartbeat counted without a session")
	}
	if !c.Started().IsZero() {
		t.Fatal("a fresh tracker has no connection that began")
	}
	c.SessionStarted(t0)
	c.SessionAlive(t0.Add(time.Minute))
	if last, live := c.Last(); !live || !last.Equal(t0.Add(time.Minute)) {
		t.Fatalf("last=%v live=%v", last, live)
	}
	if got := c.Started(); !got.Equal(t0) {
		t.Fatalf("started %v: a heartbeat does not start a connection", got)
	}
	c.SessionEnded(t0.Add(2 * time.Minute))
	c.SessionEnded(t0.Add(time.Hour)) // a second end changes nothing
	if last, live := c.Last(); live || !last.Equal(t0.Add(2*time.Minute)) {
		t.Fatalf("last=%v live=%v", last, live)
	}
	if got := c.Started(); !got.Equal(t0) {
		t.Fatalf("started %v: the end of a connection keeps when it began", got)
	}
	c.SessionStarted(t0.Add(3 * time.Hour))
	if got := c.Started(); !got.Equal(t0.Add(3 * time.Hour)) {
		t.Fatalf("started %v: a new connection began", got)
	}
}

// While confirming, the wall clock must have moved as the monotonic one did: a
// step in the middle (NTP setting the clock after a boot on a wrong one) starts
// the confirmation over.
func TestDeadMan_AWallClockThatSteppedWhileConfirmingStartsOver(t *testing.T) {
	clock := &fakeClock{t: time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)}
	r := newRig(t)
	var mono time.Duration
	r.eng = New(r.dev, r.store, &Contact{},
		WithTiming(fastTiming()), WithJitter(func(time.Duration) time.Duration { return 0 }),
		WithUptime(func() time.Duration { return time.Hour }), WithBootTime(r.dev.BootTime),
		WithClock(clock.Now), WithMonotonic(func() time.Duration { return mono }))
	enrolled(t, r)

	clock.Advance(31 * day)
	r.eng.Tick(context.Background()) // armed
	mono += deadManConfirm + time.Minute
	clock.Advance(deadManConfirm + time.Minute + 10*day) // the wall clock stepped forward as well
	r.eng.Tick(context.Background())
	if r.dev.Flavour() == "" {
		t.Fatal("released although the clocks disagree about how long the silence lasted")
	}

	mono += deadManConfirm + time.Minute
	clock.Advance(deadManConfirm + time.Minute)
	r.eng.Tick(context.Background())
	if r.dev.Flavour() != "" {
		t.Fatal("not released once the clocks agree for the whole confirmation")
	}
}

// An enrollment that died after writing the flavour left a value that is the
// agent's: the enroll that follows must roll it back and pin afresh, not hold
// because "the device has a flavour of its own".
func TestEnroll_FindsItsOwnLeftoverPinAndStartsOver(t *testing.T) {
	r := newRig(t)
	pin := "26.7/MINT/26.7.3/latest"
	r.dev.do(func(d *simDevice) { d.flavour = pin })
	if err := r.store.Save(&State{Pending: &Pending{Op: ActionEnroll, FromFlavour: "", ToFlavour: pin, StartedAt: time.Now().Unix()}}); err != nil {
		t.Fatal(err)
	}
	wantResult(t, r.run(enrollPayload(TrackFast)), OutcomeSuccess, ReasonEnrolled)
	if st := r.state(); !st.Pinned || st.Pending != nil || st.PinnedFlavour != pin {
		t.Errorf("record %+v", st)
	}
}

// An update that was requested and not settled owns the setting: a new advance
// does not run over it.
func TestAdvance_HoldsWhileAnEarlierUpdateIsUnsettled(t *testing.T) {
	r := enrolledRig(t)
	prev, next := "26.7/MINT/26.7.3/latest", "26.7/MINT/26.7.5/latest"
	r.dev.do(func(d *simDevice) { d.flavour = next })
	_, _ = r.store.Update(func(s *State) {
		s.Pending = &Pending{Op: ActionAdvance, TaskID: "100", FromFlavour: prev, ToFlavour: next, Triggered: true, StartedAt: time.Now().Unix()}
	})
	wantResult(t, r.run(advancePayload(TrackFast, true, approve575)), OutcomeHeld, ReasonHeldFirmwareBusy)
	if r.dev.Flavour() != next || len(r.dev.writes()) != 0 {
		t.Errorf("flavour %q writes %v", r.dev.Flavour(), r.dev.writes())
	}
}

// The release must not depend on the REST API alone: with the API user gone or
// the web server down, the plugin's PHP takes the pin off.
func TestDeadMan_FallsBackToThePluginHelperWhenTheAPICannotRestore(t *testing.T) {
	clock := &fakeClock{t: time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)}
	r := newRig(t)
	helperCalls := 0
	r.eng = New(r.dev, r.store, &Contact{},
		WithTiming(fastTiming()), WithJitter(func(time.Duration) time.Duration { return 0 }),
		WithUptime(func() time.Duration { return time.Hour }), WithBootTime(r.dev.BootTime), WithClock(clock.Now),
		WithHelperRelease(func(context.Context) error {
			helperCalls++
			r.dev.do(func(d *simDevice) { d.flavour = "" }) // what the PHP does to config.xml
			return nil
		}))
	enrolled(t, r)
	r.dev.do(func(d *simDevice) { d.setErr = errSim }) // the REST API cannot write

	clock.Advance(31 * day)
	r.eng.Tick(context.Background())
	clock.Advance(deadManConfirm + time.Minute)
	r.eng.Tick(context.Background())

	if helperCalls != 1 || r.dev.Flavour() != "" {
		t.Fatalf("helper called %d times, flavour %q", helperCalls, r.dev.Flavour())
	}
	if st := r.state(); st == nil || st.Pinned || st.Released == nil || st.Released.Reason != "dead_man" {
		t.Errorf("record %+v", st)
	}
}

// Without a tombstone the next round would find a record that says the agent
// holds a pin the setting no longer has, and put one back: no record says the same
// thing.
func TestDeadMan_AReleaseThatCannotSaveItsTombstoneLeavesNoRecord(t *testing.T) {
	r, clock, _ := deadManRig(t)
	clock.Advance(31 * day)
	r.eng.Tick(context.Background())
	clock.Advance(deadManConfirm + time.Minute)
	r.store.write = func(string, []byte) error { return errSim }

	r.eng.Tick(context.Background())
	if r.dev.Flavour() != "" || r.state() != nil {
		t.Fatalf("flavour %q, record %+v", r.dev.Flavour(), r.state())
	}
	r.dev.calls = nil
	clock.Advance(day)
	r.eng.Tick(context.Background())
	if len(r.dev.Calls()) != 0 {
		t.Errorf("calls after the release: %v", r.dev.Calls())
	}
}

func TestDeadMan_ARemainingPinAfterTheHelperIsNotARelease(t *testing.T) {
	for name, helper := range map[string]func(context.Context) error{
		"a helper that fails":                        func(context.Context) error { return errSim },
		"a helper that succeeds and changes nothing": func(context.Context) error { return nil },
	} {
		clock := &fakeClock{t: time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)}
		r := newRig(t)
		r.eng = New(r.dev, r.store, &Contact{},
			WithTiming(fastTiming()), WithJitter(func(time.Duration) time.Duration { return 0 }),
			WithUptime(func() time.Duration { return time.Hour }), WithBootTime(r.dev.BootTime), WithClock(clock.Now),
			WithHelperRelease(helper))
		enrolled(t, r)
		r.dev.do(func(d *simDevice) { d.setErr = errSim })
		clock.Advance(31 * day)
		r.eng.Tick(context.Background())
		clock.Advance(deadManConfirm + time.Minute)
		r.eng.Tick(context.Background())
		if st := r.state(); st == nil || !st.Pinned || st.Released != nil {
			t.Errorf("%s: record %+v: a pin that is still on the device is not released", name, st)
		}
		if r.dev.Flavour() != "26.7/MINT/26.7.3/latest" {
			t.Errorf("%s: flavour %q", name, r.dev.Flavour())
		}
	}
}

// --- the dead-man across a restart and a reconnect -------------------------------
//
// A device that was off for a month comes back with its connection up. Its saved
// contact is the old one until a round saves the new, and the round that saves it
// used to erase the silence it was about to judge.

// comeBack is the agent starting after the box was off for gap: the clock moved
// with nothing running, the broker accepts the connection a few seconds in, and
// the first round runs half a minute after the start.
func comeBack(clock *fakeClock, contact *Contact, gap time.Duration) {
	clock.Advance(gap)
	clock.Advance(5 * time.Second)
	contact.SessionStarted(clock.Now())
	clock.Advance(30 * time.Second)
}

// round advances the clock by d with the connection up and runs one round.
func (r *rig) round(clock *fakeClock, contact *Contact, d time.Duration) {
	clock.Advance(d)
	contact.SessionAlive(clock.Now())
	r.eng.Tick(context.Background())
}

func TestDeadMan_AReturnAfterThirtyDaysReleasesThePinWithTheConnectionUp(t *testing.T) {
	r, clock, contact := deadManRig(t)
	enrolledAt := r.state().LastContact

	comeBack(clock, contact, 45*day)
	r.eng.Tick(context.Background())
	if r.dev.Flavour() == "" {
		t.Fatal("released at the first sighting: it has to be confirmed")
	}
	if got := r.state().LastContact; got != enrolledAt {
		t.Fatalf("the contact that ended 45 days of silence erased it: saved %d, was %d", got, enrolledAt)
	}

	for i := 0; i < 5; i++ { // the connection stays up the whole time
		r.round(clock, contact, 5*time.Minute)
	}
	if r.dev.Flavour() == "" {
		t.Fatal("released before the confirmation time")
	}
	r.round(clock, contact, 5*time.Minute)
	if r.dev.Flavour() != "" {
		t.Fatalf("flavour %q: a device that came back after 45 days must not keep the pin", r.dev.Flavour())
	}
	st := r.state()
	if st == nil || st.Pinned || st.Released == nil || st.Released.Reason != "dead_man" {
		t.Fatalf("record %+v", st)
	}
	if r.dev.count("check") != 1 {
		t.Errorf("checks %d: the restore is followed by a forced check", r.dev.count("check"))
	}
}

// Whoever resets the Flavour in the GUI after the release, or while it is being
// confirmed, is not put back: the round writes nothing for a device whose silence
// is due.
func TestDeadMan_NothingIsPinnedAgainWhileTheReleaseIsConfirmedOrAfterIt(t *testing.T) {
	r, clock, contact := deadManRig(t)
	comeBack(clock, contact, 45*day)
	r.eng.Tick(context.Background())

	r.dev.do(func(d *simDevice) { d.flavour = "" }) // reset in the GUI during the confirmation
	r.dev.calls = nil
	for i := 0; i < 7; i++ {
		r.round(clock, contact, 5*time.Minute)
	}
	if got := r.dev.writes(); len(got) != 0 {
		t.Fatalf("writes %v: the pin was put back over a reset", got)
	}
	if st := r.state(); st == nil || st.Pinned || st.Released == nil {
		t.Fatalf("record %+v", st)
	}

	r.dev.do(func(d *simDevice) { d.flavour = "" }) // and again after the release
	r.dev.calls = nil
	for i := 0; i < 4; i++ {
		r.round(clock, contact, 5*time.Minute)
	}
	if len(r.dev.Calls()) != 0 {
		t.Errorf("calls after the release: %v", r.dev.Calls())
	}
}

func TestDeadMan_AReturnJustInsideThirtyDaysKeepsThePin(t *testing.T) {
	r, clock, contact := deadManRig(t)
	enrolledAt := r.state().LastContact

	comeBack(clock, contact, 29*day+23*time.Hour)
	r.eng.Tick(context.Background())
	for i := 0; i < 8; i++ {
		r.round(clock, contact, 5*time.Minute)
	}
	if r.dev.Flavour() != "26.7/MINT/26.7.3/latest" {
		t.Fatalf("flavour %q: a device back after 29 days 23 hours keeps its pin", r.dev.Flavour())
	}
	st := r.state()
	if !st.Pinned || st.Released != nil {
		t.Fatalf("record %+v", st)
	}
	if st.LastContact <= enrolledAt {
		t.Errorf("the contact was not saved: %d", st.LastContact)
	}
}

func TestDeadMan_AReconnectAfterADayIsNotSilence(t *testing.T) {
	r, clock, contact := deadManRig(t)
	contact.SessionStarted(clock.Now())
	clock.Advance(day)
	contact.SessionEnded(clock.Now())
	clock.Advance(day)
	contact.SessionStarted(clock.Now())
	clock.Advance(30 * time.Second)
	r.eng.Tick(context.Background())
	for i := 0; i < 8; i++ {
		r.round(clock, contact, 5*time.Minute)
	}
	if r.dev.Flavour() == "" || r.state().Released != nil {
		t.Fatalf("flavour %q, record %+v", r.dev.Flavour(), r.state())
	}
}

// An agent that stays up while its connection is down for a month sees the
// silence become due, and the connection may come back inside the confirmation:
// the control plane dropped the row at day 30 all the same.
func TestDeadMan_AConnectionThatReturnsWhileTheReleaseIsConfirmedDoesNotCancelIt(t *testing.T) {
	r, clock, contact := deadManRig(t)
	clock.Advance(30 * day)
	r.eng.Tick(context.Background()) // due by the clock: confirming
	if r.dev.Flavour() == "" {
		t.Fatal("released at the first sighting")
	}

	clock.Advance(10 * time.Minute)
	contact.SessionStarted(clock.Now()) // it reconnects, inside the confirmation
	r.round(clock, contact, time.Minute)
	if r.dev.Flavour() == "" {
		t.Fatal("released before the confirmation time")
	}
	r.round(clock, contact, 25*time.Minute)
	if r.dev.Flavour() != "" {
		t.Fatalf("flavour %q: the reconnect must not erase a silence that was already due", r.dev.Flavour())
	}
}

// A signed task is the control plane saying it still holds the device: whatever
// silence came before is over, and the release is called off.
func TestDeadMan_ASignedTaskTheControlPlaneSendsCallsTheReleaseOff(t *testing.T) {
	r, clock, contact := deadManRig(t)
	comeBack(clock, contact, 45*day)
	r.eng.Tick(context.Background())
	r.round(clock, contact, 5*time.Minute)

	res := wantResult(t, r.run(enrollPayload(TrackFast)), OutcomeNoop, ReasonEnrolled)
	if res.Drift {
		t.Error("an enroll for a pin in force is a plain confirmation")
	}
	for i := 0; i < 12; i++ {
		r.round(clock, contact, 5*time.Minute)
	}
	if r.dev.Flavour() != "26.7/MINT/26.7.3/latest" {
		t.Fatalf("flavour %q: the control plane showed it holds the device", r.dev.Flavour())
	}
	if st := r.state(); !st.Pinned || st.Released != nil || st.LastContact < clock.Now().Unix()-int64(time.Hour/time.Second) {
		t.Fatalf("record %+v", st)
	}
}

// The wall clock was wrong when the connection began (it jumped forward at boot,
// before NTP set it). Once it is right the gap is a day, not 40.
func TestDeadMan_AClockThatWasWrongWhenTheConnectionBeganIsNotAFortyDaySilence(t *testing.T) {
	r, clock, contact := deadManRig(t)
	enrolledAt := r.state().LastContact

	clock.Advance(40 * day) // the clock reads a month and more ahead
	contact.SessionStarted(clock.Now())
	clock.Advance(30 * time.Second)
	r.eng.Tick(context.Background()) // confirming, on a clock that is wrong

	clock.Advance(-40 * day) // NTP sets it right
	clock.Advance(2 * time.Hour)
	for i := 0; i < 8; i++ {
		r.round(clock, contact, 5*time.Minute)
	}
	if r.dev.Flavour() == "" || r.state().Released != nil {
		t.Fatalf("released on a clock that was wrong: flavour %q, record %+v", r.dev.Flavour(), r.state())
	}
	if st := r.state(); st.LastContact <= enrolledAt {
		t.Errorf("a live connection on a right clock saves its contact: %+v", st)
	}
	// And it stays kept as the connection goes on.
	for i := 0; i < 400; i++ {
		r.round(clock, contact, 2*time.Hour)
	}
	if r.dev.Flavour() == "" {
		t.Fatal("a connection that has been up for a month was released")
	}
}

// A box with a dead RTC battery boots at the time its disk was last written, and
// the connection begins before NTP sets the clock: what the first rounds save looks
// recent, and the month shows only once the clock is right.
func TestDeadMan_AClockBehindWhenTheConnectionBeganIsSetRightWhileItIsUp(t *testing.T) {
	for name, setBeforeTheFirstRound := range map[string]bool{
		"after a round saved a contact": false,
		"before the first round":        true,
	} {
		t.Run(name, func(t *testing.T) {
			r, clock, contact := deadManRig(t)
			clock.Advance(10 * time.Minute) // booted on the clock the disk was last written with
			contact.SessionStarted(clock.Now())
			clock.Advance(30 * time.Second)
			if !setBeforeTheFirstRound {
				r.eng.Tick(context.Background())
			}

			clock.Advance(45 * day) // NTP sets the real date
			r.round(clock, contact, 2*time.Minute)
			if r.dev.Flavour() == "" {
				t.Fatal("released at the first sighting")
			}
			for i := 0; i < 5; i++ {
				r.round(clock, contact, 5*time.Minute)
			}
			if r.dev.Flavour() == "" {
				t.Fatal("released before the confirmation time")
			}
			r.round(clock, contact, 5*time.Minute)
			if r.dev.Flavour() != "" {
				t.Fatalf("flavour %q: the device was off for 45 days and the clock hid it", r.dev.Flavour())
			}
		})
	}
}

// A restart in the middle of the confirmation must not forget the silence: the
// saved contact is still the old one.
func TestDeadMan_ARestartWhileTheReleaseIsConfirmedDoesNotLoseIt(t *testing.T) {
	r, clock, contact := deadManRig(t)
	comeBack(clock, contact, 45*day)
	r.eng.Tick(context.Background())
	r.round(clock, contact, 10*time.Minute)

	// The agent restarts (an upgrade of the package, say): a new engine on the same
	// record, a new tracker, the connection comes back.
	contact = &Contact{}
	r.eng = New(r.dev, r.store, contact,
		WithTiming(fastTiming()), WithJitter(func(time.Duration) time.Duration { return 0 }),
		WithUptime(func() time.Duration { return time.Hour }), WithBootTime(r.dev.BootTime), WithClock(clock.Now))
	clock.Advance(10 * time.Second)
	contact.SessionStarted(clock.Now())
	clock.Advance(30 * time.Second)
	r.eng.Tick(context.Background())
	if r.dev.Flavour() == "" {
		t.Fatal("released at the first sighting after the restart")
	}
	for i := 0; i < 7; i++ {
		r.round(clock, contact, 5*time.Minute)
	}
	if r.dev.Flavour() != "" {
		t.Fatalf("flavour %q: the restart lost the silence", r.dev.Flavour())
	}
}

// A package removal restores the flavour and keeps the record. Put back after a
// month, the agent finds a record for a device the control plane dropped.
func TestDeadMan_AReinstallAfterAMonthDoesNotPinTheDeviceAgain(t *testing.T) {
	r, clock, contact := deadManRig(t)
	r.dev.do(func(d *simDevice) { d.flavour = "" }) // what the pre-deinstall hook did
	r.dev.calls = nil

	comeBack(clock, contact, 45*day)
	for i := 0; i < 8; i++ {
		r.round(clock, contact, 5*time.Minute)
	}
	if got := r.dev.writes(); len(got) != 0 {
		t.Fatalf("writes %v: a device the control plane dropped was pinned again", got)
	}
	if st := r.state(); st == nil || st.Pinned || st.Released == nil {
		t.Fatalf("record %+v: the stale record should have become a tombstone", st)
	}
}

// Inside the month the control plane still holds the device, and the reinstall
// puts the pin back, flagged.
func TestDeadMan_AReinstallInsideAMonthPinsTheDeviceAgain(t *testing.T) {
	r, clock, contact := deadManRig(t)
	r.dev.do(func(d *simDevice) { d.flavour = "" })

	comeBack(clock, contact, 3*day)
	r.eng.Tick(context.Background())
	if r.dev.Flavour() != "26.7/MINT/26.7.3/latest" {
		t.Fatalf("flavour %q", r.dev.Flavour())
	}
	if st := r.state(); !st.DriftPending {
		t.Errorf("record %+v", st)
	}
}

func TestEngineClockIsTheWallClockAlone(t *testing.T) {
	e := New(newSim(t), NewStateStore(filepath.Join(t.TempDir(), "x.json")), nil)
	if s := e.now().String(); strings.Contains(s, "m=") {
		t.Fatalf("the engine's time %q carries a monotonic reading: subtracting two of them never sees a step of the wall clock", s)
	}
	a := e.now()
	if got := wallElapsed(a, a.Add(time.Hour)); got != time.Hour {
		t.Fatalf("elapsed %v", got)
	}
	// Whatever the two readings carry, the elapsed time is the wall clock's.
	mono := time.Now()
	if got := wallElapsed(mono, mono.Add(3*time.Hour)); got != 3*time.Hour {
		t.Fatalf("elapsed %v", got)
	}
}
