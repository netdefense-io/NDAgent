package track

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// The landing (finishMajor): majorLanded, then the re-pin, then one catalog
// refresh. No check is made before the re-pin, and none is read.

// The two real check results of a landed box hold nothing: the agent's record of the
// old ABI and the core's "Vital flag changed" entry are same-version reinstalls, which
// are counted and never judged, even though the status reads "update" for them.
func TestLanding_TheCheckResultsOfALandedBoxEndNothingNewerWithTheEntriesCounted(t *testing.T) {
	for file, reinstalls := range map[string]int{"hop-a-check.json": 1, "hop-b-check.json": 2} {
		t.Run(file, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", "landing", file))
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(raw) }))
			defer server.Close()
			st, err := opnapi.NewClient(server.URL, "k", "s", true).GetFirmwareUpgradeStatus(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			plan := NewPlan(st)
			if plan.ReinstallEntries() != reinstalls {
				t.Errorf("reinstall entries %d, want %d", plan.ReinstallEntries(), reinstalls)
			}
			kind, h, _ := plan.forAdvance("26.7.1_1", "26.7.1", false)
			if kind != planNothingNewer || h != nil {
				t.Fatalf("plan %v held %+v: the landed box has nothing to do", kind, h)
			}
			if k, h := plan.forMajor("26.7"); k != majorNoOffer || h != nil {
				t.Errorf("a landed box offers no series upgrade: %v %+v", k, h)
			}
		})
	}
}

// The re-pin is the first act after the landing is proved, the refresh of the catalog
// follows it, and the finish makes no check at all: the first check on the old pin of
// a cross-ABI hop reads "repository error", and a check is a write when its catalog
// carries a newer pkg.
func TestLanding_TheRePinComesFirstThenOneRefreshAndNoCheckIsMade(t *testing.T) {
	r := hopRig(t)
	p := hopPayload(approveFinalHotfix)
	job := hopRebootedJob(t, r, p)
	mark := len(r.dev.Calls())

	out, done := r.agentBack(job)
	if !done {
		t.Fatal("not resolved")
	}
	wantHop(t, wantResult(t, out, OutcomeSuccess, ReasonApplied), NoteBootEnvironmentMade)

	calls := r.dev.Calls()[mark:]
	set, refresh := orderOf(calls, "set ", 0), orderOf(calls, "refresh-catalog", 0)
	if set < 0 || refresh < 0 || set > refresh {
		t.Errorf("calls %v: the pin is written, then the catalog refreshed", calls)
	}
	for _, c := range calls {
		if c == "check" || orderOf([]string{c}, "exec", 0) == 0 {
			t.Errorf("call %q: the landing makes no check and runs no package command", c)
		}
	}
	if n := orderOf(calls, "set ", set+1); n >= 0 {
		t.Errorf("calls %v: the pin is written once", calls)
	}
}

// sameABI makes the hop table's pair keep its ABI, the shape measured on a real box
// (25.1.12 to 25.7, FreeBSD:14 on both sides): after the landing the old pin still
// resolves. The shipped table has no such pair; this is the engine's input for the day
// a schema release adds one.
func sameABI(t *testing.T) func(*simDevice) {
	t.Helper()
	saved := hops
	t.Cleanup(func() { hops = saved })
	hops = []Hop{{Source: "26.1", Target: "26.7", SourceABI: "FreeBSD:14:amd64", TargetABI: "FreeBSD:14:amd64"}}
	return func(d *simDevice) {
		// The core lands on the release itself, and the mirror holds two directories
		// whose catalogs are equal, the release's and its first hotfix's: the pin is the
		// installed core's own name, never the one a catalog comparison would pick.
		d.hop.landABI, d.hop.landCore = "FreeBSD:14:amd64", "26.7.1"
		c := simCatalog{core: "26.7.1", update: "26.7", pkgs: map[string]string{"curl": "8.22.0", "pkg": "2.3.1_1"}, abi: "FreeBSD:14:amd64"}
		d.folders["26.7.1"], d.folders["26.7.1_1"] = c, c
	}
}

func TestLanding_AHopThatKeepsItsABILandsFromTheBoxWhileTheOldPinStillAnswers(t *testing.T) {
	r := hopRig(t, sameABI(t))
	p := hopPayload(approveFinalHotfix)
	job := hopRebootedJob(t, r, p)
	if r.dev.Flavour() != "26.1/MINT/26.1.11/latest" {
		t.Fatalf("flavour %q", r.dev.Flavour())
	}

	// The premise: on the old pin the landed box reads a clean "none", not the
	// cross-ABI hop's "repository error", so the landing is never recognised by a
	// failing first reading.
	r.dev.do(func(d *simDevice) {
		d.publishCheck()
		if st := d.checked; st == nil || st.Repository != "ok" || st.Connection != "ok" || st.Status != "none" ||
			len(st.UpgradePackages) != 0 || len(st.ReinstallPackages) != 0 || st.UpgradeMajorVersion != "" {
			t.Fatalf("the first reading on the old pin: %+v", st)
		}
		d.checked = nil
	})
	mark := len(r.dev.Calls())

	out, done := r.agentBack(job)
	if !done {
		t.Fatal("not resolved")
	}
	r.checkOutcome(p, out)
	res := wantResult(t, out, OutcomeSuccess, ReasonApplied)
	wantHop(t, res, NoteBootEnvironmentMade)
	wantVersions(t, res, "26.1.11_10", "26.7.1", "26.7", "26.7.1")

	if got := r.dev.Flavour(); got != "26.7/MINT/26.7.1/latest" {
		t.Errorf("flavour %q: the installed core's own directory, with two equal ones", got)
	}
	for _, c := range r.dev.Calls()[mark:] {
		if c == "check" {
			t.Errorf("calls %v: a landing reading is the version files, never a check", r.dev.Calls()[mark:])
		}
	}
}

func TestLanding_AHopThatKeepsItsABIAndEndedShortIsStillAFailedStage(t *testing.T) {
	r := hopRig(t, sameABI(t))
	p := hopPayload(approveFinalHotfix)
	job := hopRebootedJob(t, r, p)
	// The core is at the series, the packages marker is short of it and left, and the
	// landing left no .update.log.
	r.dev.do(func(d *simDevice) {
		d.hop.pkgs = "26.1.6_2"
		d.hop.markers = Markers{Pkgs: true}
		d.hop.updateLog = LogFile{}
	})
	out, done := r.agentBack(job)
	if !done || out.Failure == "" {
		t.Fatalf("want a failure, got done=%v %+v", done, out)
	}
	r.checkOutcome(p, out)
	if st := r.state(); st.Landing == nil {
		t.Errorf("record %+v: no landing note", st)
	}
	// And the old pin, which still answers, is left alone: nothing re-pins a mixed system.
	if got := r.eng.Reconcile(context.Background()); got != TickSettled {
		t.Errorf("round %v", got)
	}
	if got := r.dev.Flavour(); got != "26.1/MINT/26.1.11/latest" {
		t.Errorf("flavour %q", got)
	}
}

// The status the proof's 26.1.11_10 device answered with the 26.7 offer shown, read
// as the engine reads it: a usable check whose offer is the major and its three sets,
// nothing else pending, and nothing for the minor step to do.
func TestPlanForMajor_TheMeasuredOffer(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "opnapi", "testdata", "firmware-status-offer-26.1.11_10.json"))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(raw) }))
	defer server.Close()
	st, err := opnapi.NewClient(server.URL, "k", "s", true).GetFirmwareUpgradeStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := usable(st); err != nil {
		t.Fatalf("the measured check is not usable: %v", err)
	}
	plan := NewPlan(st)
	if kind, h := plan.forMajor("26.7"); kind != majorOffered || h != nil {
		t.Fatalf("the measured offer: %v %+v", kind, h)
	}
	if got := needBytes(plan.MajorSets); got != 3328<<20 {
		t.Errorf("need %d: the sizes of the measured offer come to 2.75 GiB and the floor of 3.25 GiB wins", got)
	}
	if kind, h, _ := plan.forAdvance("26.1.11_10", "26.1.11_10", false); kind != planNothingNewer || h != nil {
		t.Errorf("the minor step on the measured check: %v %+v", kind, h)
	}
	if _, ok := HopBetween("26.1", plan.Major); !ok {
		t.Errorf("the offered series %q is no row of the hop table", plan.Major)
	}
}

// --- a box with no packages marker ----------------------------------------------------------

// An image, or a box installed from one, never ran stage P: it has no packages
// marker (`opnsense-update -vp` prints an empty line), and that is normal. It must not
// block the upgrade; the marker stage P writes when its pkg upgrade succeeds is what
// proves the landing.
func TestLanding_ABoxWithNoPackagesMarkerHopsAndLands(t *testing.T) {
	r := hopRig(t, func(d *simDevice) { d.hop.pkgsAbsent = true })
	p := hopPayload(approveFinalHotfix)
	job := hopRebootedJob(t, r, p)

	if r.dev.posts() != 1 {
		t.Fatalf("%d requests: an absent packages marker is no reason to hold the upgrade", r.dev.posts())
	}
	if job.FromBase != "26.1.11" || job.FromKernel != "26.1.11" || job.FromPkgs != "" {
		t.Errorf("the four versions recorded at the request: %+v", job)
	}

	out, done := r.agentBack(job)
	if !done {
		t.Fatal("not resolved")
	}
	r.checkOutcome(p, out)
	res := wantResult(t, out, OutcomeSuccess, ReasonApplied)
	wantHop(t, res, NoteBootEnvironmentMade)
	wantVersions(t, res, "26.1.11_10", "26.7.1_1", "26.7", "26.7.1_1")
	if got := r.dev.Flavour(); got != "26.7/MINT/26.7.1/latest" {
		t.Errorf("flavour %q", got)
	}
}

// With no marker before and none after, nothing changed: an abort of stage 0 is told
// from a landing the same way it is on a box that has one.
func TestLanding_AStage0AbortOnABoxWithNoPackagesMarkerIsHeldAsAborted(t *testing.T) {
	r := hopRig(t, stage0Aborts, func(d *simDevice) { d.hop.pkgsAbsent = true })
	r.simulateTime()
	r.hopWants(t, ReasonHeldUpgradeAborted, NoteBootEnvironmentMade)
	if r.streak() != 1 {
		t.Errorf("streak %d", r.streak())
	}
}

// Stage P consumes its pending marker first and writes the packages marker only when
// its pkg upgrade succeeded. On a box that had none, a stage P that failed leaves the
// base and the kernel at the series and the marker still absent: a stage that did
// not finish, FAILED with the landing note, never taken for a landing.
func TestLanding_AFailedStagePOnABoxWithNoPackagesMarkerIsFailedAndLeavesTheLandingNote(t *testing.T) {
	r := hopRig(t, func(d *simDevice) { d.hop.pkgsAbsent = true })
	p := hopPayload(approveFinalHotfix)
	job := hopRebootedJob(t, r, p)
	r.dev.do(func(d *simDevice) { d.hop.pkgsAbsent, d.hop.markers = true, Markers{} })

	out, done := r.agentBack(job)
	if !done || out.Failure == "" {
		t.Fatalf("want a failure, got done=%v %+v", done, out)
	}
	r.checkOutcome(p, out)
	if out.Detail.Kind != KindMajor || out.Detail.Target != "26.7" || !equal(out.Detail.Notes, []string{NoteBootEnvironmentMade}) {
		t.Errorf("detail %+v", out.Detail)
	}
	if st := r.state(); st.Landing == nil || st.Landing.Series != "26.7" || st.Pending != nil {
		t.Fatalf("record %+v: the failure leaves the landing note", st)
	}

	// The round does not re-pin it, and the next window holds.
	if got := r.eng.Reconcile(context.Background()); got != TickSettled {
		t.Errorf("round %v", got)
	}
	if got := r.dev.Flavour(); got != "26.1/MINT/26.1.11/latest" || len(r.dev.writes()) != 0 {
		t.Errorf("flavour %q, writes %v: a mixed system is not re-pinned", got, r.dev.writes())
	}
	next := advancePayload(TrackFast, true, map[string]string{"26.7": "26.7.1"})
	wantOrdinary(t, wantResult(t, r.run(next), OutcomeHeld, ReasonHeldUnexpectedPlan))
}

// The setting should hold, at the landing, the pin the task relied on (the dead pin of
// the old series). When something changed it while the box was upgrading, the answer
// says drift, as the answer of a minor update does, and the pin is written at the
// installed release all the same.
func TestLanding_ASettingChangedWhileTheBoxUpgradedIsAnsweredAsDriftAndPutRight(t *testing.T) {
	for name, flavour := range map[string]string{
		"the operator reset it to the default":       "",
		"somebody set a path of their own":           "custom/mirror/path",
		"it names another release of the old series": "26.1/MINT/26.1.9/latest",
	} {
		t.Run(name, func(t *testing.T) {
			r := hopRig(t)
			p := hopPayload(approveFinalHotfix)
			job := hopRebootedJob(t, r, p)
			r.dev.do(func(d *simDevice) { d.flavour = flavour })

			out, done := r.agentBack(job)
			if !done {
				t.Fatal("not resolved")
			}
			r.checkOutcome(p, out)
			res := wantResult(t, out, OutcomeSuccess, ReasonApplied)
			wantHop(t, res, NoteBootEnvironmentMade)
			if !res.Drift {
				t.Error("the setting was changed under the hop and the answer does not say drift")
			}
			if res.PinnedVersion != "26.7.1_1" || r.dev.Flavour() != "26.7/MINT/26.7.1/latest" {
				t.Errorf("pinned %q flavour %q: the pin is written at the installed release", res.PinnedVersion, r.dev.Flavour())
			}
		})
	}
}
