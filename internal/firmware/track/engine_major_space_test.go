package track

import (
	"context"
	"fmt"
	"testing"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// Space and the boot environment (A4.8 and A4.10).

func TestNeedBytes_TheFormulaAndTheFloor(t *testing.T) {
	sets := func(packages, kernel, base int64) []opnapi.FirmwareUpgradeSet {
		return []opnapi.FirmwareUpgradeSet{
			{Name: "packages", Size: packages}, {Name: "kernel", Size: kernel}, {Name: "base", Size: base},
		}
	}
	const floor = 3328 << 20 // 3.25 GiB
	for name, tc := range map[string]struct {
		sets []opnapi.FirmwareUpgradeSet
		want int64
	}{
		// 2 x 1142865408 + 33428352 + 98926556 + 512 MiB = 2.75 GiB, below the floor.
		"today's payload: the floor wins": {sets(1142865408, 33428352, 98926556), floor},
		// The packages are on disk twice (the tar and its extraction).
		"a payload twice as large: the formula takes over": {sets(2285730816, 66856704, 197853112), 2*2285730816 + 66856704 + 197853112 + 512<<20},
		"nothing in the offer":                             {nil, floor},
		"a set with no readable size":                      {sets(-1, 33428352, 98926556), floor},
	} {
		if got := needBytes(tc.sets); got != tc.want {
			t.Errorf("%s: need %d, want %d", name, got, tc.want)
		}
	}
	if needBytes(sets(1142865408, 33428352, 98926556)) != floor || floor != 3489660928 {
		t.Error("the floor is 3.25 GiB, the smallest budget that completed the proof's hop (2.75 GiB) plus 512 MiB")
	}
}

// The decision on the space, and on the boot environment, is made once and never
// holds on the environment: a pool with room for the upgrade and not for the
// environment skips it and says so.
func TestMajorSpace_TheSpaceAndTheBootEnvironmentDecision(t *testing.T) {
	const (
		need   = int64(3328 << 20)
		beCost = int64(1339559936)
	)
	type tc struct {
		name     string
		tweak    func(*simDevice)
		payload  func(*Payload)
		reason   string
		notes    []string
		made     bool
		asksAPI  bool // the snapshots API is asked whether it is supported
		noRecord bool // the step ends before the request
	}
	cases := []tc{
		{name: "the cache's filesystem has less than the upgrade needs", reason: ReasonHeldInsufficientSpace,
			tweak: func(d *simDevice) { d.hop.disk.CacheFree = need - 1 }},
		{name: "the root has less than 1 GiB on a split layout", reason: ReasonHeldInsufficientSpace,
			tweak: func(d *simDevice) { d.hop.disk.SplitRoot, d.hop.disk.RootFree = true, 1<<30-1 }},
		{name: "the root is another filesystem with room", reason: ReasonHeldUpgradeAborted,
			tweak: func(d *simDevice) { d.hop.disk.SplitRoot, d.hop.disk.RootFree = true, 1<<30 },
			notes: []string{NoteBootEnvironmentMade}, made: true, asksAPI: true},
		{name: "the root is short but is the cache's own filesystem", reason: ReasonHeldUpgradeAborted,
			tweak: func(d *simDevice) { d.hop.disk.SplitRoot, d.hop.disk.RootFree = false, 1 },
			notes: []string{NoteBootEnvironmentMade}, made: true, asksAPI: true},
		{name: "exactly the space the upgrade needs, in a pool with room for the environment", reason: ReasonHeldUpgradeAborted,
			tweak: func(d *simDevice) { d.hop.disk.CacheFree = need },
			notes: []string{NoteBootEnvironmentMade}, made: true, asksAPI: true},
		{name: "a pool at exactly the upgrade plus the environment", reason: ReasonHeldUpgradeAborted,
			tweak: func(d *simDevice) { d.hop.disk.PoolFree = need + beCost },
			notes: []string{NoteBootEnvironmentMade}, made: true, asksAPI: true},
		{name: "a pool one byte short of the upgrade plus the environment", reason: ReasonHeldUpgradeAborted,
			tweak: func(d *simDevice) { d.hop.disk.PoolFree = need + beCost - 1 },
			notes: []string{NoteBootEnvironmentSkippedNoRoom}, asksAPI: true},
		{name: "a pool with room for the upgrade and none for the environment", reason: ReasonHeldUpgradeAborted,
			tweak: func(d *simDevice) { d.hop.disk.PoolFree = need },
			notes: []string{NoteBootEnvironmentSkippedNoRoom}, asksAPI: true},
		{name: "the device's setting is off", reason: ReasonHeldUpgradeAborted,
			payload: func(p *Payload) { p.BootEnvironmentOff = true },
			notes:   []string{NoteBootEnvironmentOff}},
		{name: "a box without ZFS", reason: ReasonHeldUpgradeAborted,
			tweak: func(d *simDevice) { d.hop.disk.ZFS = false },
			notes: []string{NoteBootEnvironmentUnavailable}},
		{name: "a ZFS box whose boot dataset is unknown", reason: ReasonHeldUpgradeAborted,
			tweak: func(d *simDevice) { d.hop.disk.BootDataset = "" },
			notes: []string{NoteBootEnvironmentUnavailable}},
		{name: "the snapshots API says no", reason: ReasonHeldUpgradeAborted,
			tweak: func(d *simDevice) { d.hop.snapshots = false },
			notes: []string{NoteBootEnvironmentUnavailable}, asksAPI: true},
		{name: "the snapshots API cannot be asked", reason: ReasonHeldUpgradeAborted,
			tweak: func(d *simDevice) { d.hop.snapshotsErr = errSim },
			notes: []string{NoteBootEnvironmentUnavailable}, asksAPI: true},
		{name: "the add is refused", reason: ReasonHeldUpgradeAborted,
			tweak: func(d *simDevice) { d.hop.beAddErr = errSim },
			notes: []string{NoteBootEnvironmentUnavailable}, asksAPI: true},
		{name: "the add worked and the listing cannot be read", reason: ReasonHeldUpgradeAborted,
			tweak: func(d *simDevice) { d.hop.beFindErr = errSim },
			notes: []string{NoteBootEnvironmentMade}, made: true, asksAPI: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := hopRig(t, stage0Aborts)
			if c.tweak != nil {
				r.dev.do(c.tweak)
			}
			p := hopPayload(approveFinalHotfix)
			if c.payload != nil {
				c.payload(&p)
			}
			out := r.run(p)
			res := wantResult(t, out, OutcomeHeld, c.reason)
			wantHop(t, res, c.notes...)

			if asked := r.dev.count("snapshot-supported") > 0; asked != c.asksAPI {
				t.Errorf("the snapshots API asked: %v, want %v", asked, c.asksAPI)
			}
			var names []string
			r.dev.do(func(d *simDevice) {
				for _, be := range d.hop.bes {
					names = append(names, be.Name)
				}
			})
			if made := len(names) > 0; made != c.made {
				t.Errorf("boot environments %v, made: %v", names, c.made)
			}
			if c.made {
				if job := r.jobs[len(r.jobs)-1]; job.BootEnvironment == nil || job.BootEnvironment.Name != "ndagent-pre-26.7" {
					t.Errorf("the job does not name the environment it made: %+v", job.BootEnvironment)
				}
			}
			if c.reason == ReasonHeldInsufficientSpace && r.dev.posts() != 0 {
				t.Error("the upgrade was requested without the space for it")
			}
		})
	}
}

// A name that is taken gets the next one, up to a bound; the add, the search and the
// uuid of the environment are recorded in the job.
func TestMajorSpace_TheBootEnvironmentTakesTheNextFreeName(t *testing.T) {
	t.Run("two names are taken", func(t *testing.T) {
		r := hopRig(t, stage0Aborts, func(d *simDevice) {
			d.hop.bes = []BootEnvironment{{Name: "ndagent-pre-26.7", UUID: "a"}, {Name: "ndagent-pre-26.7-2", UUID: "b"}}
		})
		wantHop(t, wantResult(t, r.run(hopPayload(approveFinalHotfix)), OutcomeHeld, ReasonHeldUpgradeAborted), NoteBootEnvironmentMade)
		job := r.jobs[len(r.jobs)-1]
		if job.BootEnvironment == nil || job.BootEnvironment.Name != "ndagent-pre-26.7-3" || job.BootEnvironment.UUID != "uuid-ndagent-pre-26.7-3" {
			t.Errorf("the environment the job names: %+v", job.BootEnvironment)
		}
		r.dev.do(func(d *simDevice) {
			if len(d.hop.bes) != 3 {
				t.Errorf("environments %+v: the agent never removes one", d.hop.bes)
			}
		})
	})
	t.Run("every name is taken", func(t *testing.T) {
		r := hopRig(t, stage0Aborts, func(d *simDevice) {
			d.hop.bes = []BootEnvironment{{Name: "ndagent-pre-26.7", UUID: "x"}}
			for n := 2; n <= bootEnvironmentTries; n++ {
				d.hop.bes = append(d.hop.bes, BootEnvironment{Name: fmt.Sprintf("ndagent-pre-26.7-%d", n), UUID: "x"})
			}
		})
		wantHop(t, wantResult(t, r.run(hopPayload(approveFinalHotfix)), OutcomeHeld, ReasonHeldUpgradeAborted), NoteBootEnvironmentUnavailable)
	})
}

// The notes the attempt found are in the job the row keeps, so that an agent that
// comes back after the reboots answers with them.
func TestMajorSpace_TheNotesSurviveARestartOfTheAgent(t *testing.T) {
	r := hopRig(t, func(d *simDevice) {
		d.hop.audit = RepoAudit{Repositories: []string{"Foreign"}, Packages: []string{"foo"}}
		d.hop.disk.PoolFree = 3328 << 20 // room for the upgrade and none for the environment
	})
	p := hopPayload(approveFinalHotfix)
	job := hopRebootedJob(t, r, p)
	want := []string{NoteThirdPartyRepository, NoteThirdPartyPackage, NoteBootEnvironmentSkippedNoRoom}
	if !equal(job.Notes, want) {
		t.Fatalf("job notes %v, want %v", job.Notes, want)
	}
	out, done := r.agentBack(job)
	if !done {
		t.Fatal("not resolved")
	}
	wantHop(t, wantResult(t, out, OutcomeSuccess, ReasonApplied), want...)
}

// A stale work directory of an earlier attempt is cleared before the space is
// measured, and only when nothing can be harmed by it: no job runs, no marker is
// left, and the agent has no operation of its own in flight (opnsense-update -es
// removes the markers too).
func TestMajorSpace_AStaleWorkDirectoryIsClearedOnlyWhenNothingRunsAndNothingIsPending(t *testing.T) {
	stale := func(d *simDevice) {
		d.hop.workDirLeft, d.hop.workDirBytes = true, 1244208<<10
		d.hop.disk.CacheFree = 3328<<20 + 1<<20 // room for the upgrade only once the leftover is gone
	}

	t.Run("the leftover is cleared first and the space is measured after it", func(t *testing.T) {
		r := hopRig(t, stage0Aborts, stale)
		wantHop(t, wantResult(t, r.run(hopPayload(approveFinalHotfix)), OutcomeHeld, ReasonHeldUpgradeAborted), NoteBootEnvironmentMade)
		calls := r.dev.Calls()
		clean, measure := orderOf(calls, "clear-stale", 0), orderOf(calls, "disk-free", 0)
		if clean < 0 || measure < 0 || clean > measure {
			t.Errorf("calls %v: the leftover is cleared before the space is read", calls)
		}
	})

	t.Run("the leftover, left in place, is a short disk", func(t *testing.T) {
		r := hopRig(t, stale)
		r.dev.do(func(d *simDevice) { d.hop.clearStaleErr = errSim })
		wantHop(t, wantResult(t, r.run(hopPayload(approveFinalHotfix)), OutcomeHeld, ReasonHeldInsufficientSpace))
	})

	t.Run("the agent is stopped while it clears the leftover", func(t *testing.T) {
		r := hopRig(t, stale)
		r.dev.do(func(d *simDevice) { d.hop.clearStaleErr = errSim })
		hopCutAt(t, r, hopPayload(approveFinalHotfix), "clear-stale")
		if r.dev.count("disk-free") != 0 {
			t.Error("the space was measured after the agent was stopped")
		}
	})

	t.Run("a marker is left: the step holds before anything is cleared", func(t *testing.T) {
		r := hopRig(t, stale, func(d *simDevice) { d.hop.markers = Markers{Pkgs: true} })
		wantHop(t, wantResult(t, r.run(hopPayload(approveFinalHotfix)), OutcomeHeld, ReasonHeldRebootPending))
		if r.dev.count("clear-stale") != 0 || r.dev.count("clear-cache") != 0 {
			t.Errorf("calls %v: a marker is what a reboot would resume, and the cleanup removes it", r.dev.Calls())
		}
	})

	t.Run("an operation of the agent's is in flight", func(t *testing.T) {
		r := hopRig(t, stale)
		if _, err := r.store.Update(func(s *State) { s.Pending = &Pending{Op: "repin", TaskID: "7"} }); err != nil {
			t.Fatal(err)
		}
		o := &op{in: Input{Payload: hopPayload(approveFinalHotfix)}, st: r.state()}
		_, out := r.eng.majorSpace(context.Background(), o, Plan{MajorSets: offerSets("26.7")})
		if out == nil || out.Result == nil || out.Result.Reason != ReasonHeldInsufficientSpace {
			t.Fatalf("outcome %+v: the leftover stays and the disk is short", out)
		}
		if r.dev.count("clear-stale") != 0 {
			t.Error("the leftover was cleared under an operation of the agent's")
		}
	})

	t.Run("a firmware job runs", func(t *testing.T) {
		r := hopRig(t, stale)
		r.dev.do(func(d *simDevice) { d.alwaysBusy = true })
		o := &op{in: Input{Payload: hopPayload(approveFinalHotfix)}, st: r.state()}
		_, _ = r.eng.majorSpace(context.Background(), o, Plan{MajorSets: offerSets("26.7")})
		if r.dev.count("clear-stale") != 0 {
			t.Error("the leftover was cleared under a running firmware job")
		}
	})
}
