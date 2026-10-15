package track

import (
	"context"
	"testing"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// The proof's hop, end to end in the simulator: a device at the final build of
// 26.1, pinned there, offered the 26.7 upgrade, asked for it by a window.
func TestMajor_TheHopLandsAndTheAgentThatComesBackAnswersAndRepins(t *testing.T) {
	for name, approved := range map[string]map[string]string{
		"the target is the pin's directory":        approveFinal,
		"the target is the final build's own name": approveFinalHotfix,
	} {
		t.Run(name, func(t *testing.T) {
			r := hopRig(t)
			p := hopPayload(approved)
			job := hopRebootedJob(t, r, p)

			// What was recorded before the request is what decides the row later.
			if job.Phase != PhaseTriggered || job.Major != "26.7" || job.Upgrade == nil || job.Upgrade.Mode != "major" ||
				!job.Upgrade.Reboot || job.Upgrade.TriggeredAt == 0 || !job.Upgrade.RebootSeen {
				t.Fatalf("job %+v", job)
			}
			if job.From != "26.1.11_10" || job.FromBase != "26.1.11" || job.FromKernel != "26.1.11" || job.FromPkgs != "26.1.6_2" {
				t.Errorf("the four versions were not recorded: %+v", job)
			}
			if job.PrevFlavour != "26.1/MINT/26.1.11/latest" || job.NewFlavour != job.PrevFlavour {
				t.Errorf("the pin in force was not recorded as both flavours: %q %q", job.PrevFlavour, job.NewFlavour)
			}
			if r.dev.posts() != 1 {
				t.Errorf("%d requests", r.dev.posts())
			}
			// The hop wrote nothing; the box is on the new ABI with the dead pin.
			if got := r.dev.writes(); len(got) != 0 {
				t.Errorf("writes %v: the hop writes the pin once, after it landed", got)
			}
			if st := r.state(); st.Pending == nil || !st.Pending.Triggered || st.Pending.Major != "26.7" ||
				st.Pending.FromFlavour != st.Pending.ToFlavour {
				t.Fatalf("pending %+v", st.Pending)
			}

			// The agent that comes back after boot 3 settles the row from the device.
			out, done := r.newEngine().Resolve(context.Background(), job, startedRow())
			if !done {
				t.Fatalf("not resolved: %+v", out)
			}
			r.checkOutcome(p, out)
			res := wantResult(t, out, OutcomeSuccess, ReasonApplied)
			wantHop(t, res, NoteBootEnvironmentMade)
			wantVersions(t, res, "26.1.11_10", "26.7.1_1", "26.7", "26.7.1_1")
			if res.Drift {
				t.Error("a track-driven hop is the expected case: it is not flagged as drift")
			}
			if got := r.dev.Flavour(); got != "26.7/MINT/26.7.1/latest" {
				t.Errorf("flavour %q: the pin follows the installed release on the new series", got)
			}
			if st := r.state(); !st.Pinned || st.PinnedFlavour != "26.7/MINT/26.7.1/latest" || st.PinnedVersion != "26.7.1_1" || st.Pending != nil {
				t.Errorf("record %+v", st)
			}
			if r.dev.count("refresh-catalog") != 1 {
				t.Errorf("calls %v: one scoped catalog refresh after the re-pin", r.dev.Calls())
			}
		})
	}
}

// --- the offer check -------------------------------------------------------------------
//
// On core 26.1.9, which has no offer, `POST /upgrade` printed "No known packages set
// to fetch was specified.", passed the sanity hook, wrote ***REBOOT*** and rebooted
// the box: its upgrade.sh cannot see opnsense-update refuse. The endpoint is no
// probe. Two things stand between a mistaken `major` and that reboot: the control
// plane seals one only for a device at the series' final build, and the agent makes
// no request unless the same task's forced check showed the offer.

// below26111 is a 26.1.9 box, below the final build, with no offer, pinned at its own
// release: a track that has not approved the final build yet sends it a step with
// `major` (it should not, but the agent does not rely on it).
func below26111(d *simDevice) {
	finalBuild26(d)
	d.core, d.updatePkg, d.sets = "26.1.9", "26.1.9", "26.1.9"
	d.pkgs["opnsense"], d.pkgs["opnsense-update"] = "26.1.9", "26.1.9"
	d.folders = map[string]simCatalog{
		"26.1.9": {core: "26.1.9", update: "26.1.9", pkgs: map[string]string{"curl": "8.20.0", "pkg": "2.3.1_1"}, abi: "FreeBSD:14:amd64"},
	}
	d.latest = d.folders["26.1.9"]
	d.majorOffered = ""
	d.hop.base, d.hop.kernel, d.hop.pkgs = "26.1.9", "26.1.9", "26.1.9"
}

func TestMajorOnASubFinalDeviceAnswersNoopAndNeverPostsUpgrade(t *testing.T) {
	r := hopRig(t, below26111)
	boot := r.dev.boot

	out := r.run(hopPayload(map[string]string{"26.1": "26.1.9"}))

	res := wantResult(t, out, OutcomeNoop, ReasonTargetNotYetOffered)
	wantHop(t, res)
	wantVersions(t, res, "26.1.9", "26.1.9", "26.7", "26.1.9")
	if n := r.dev.posts(); n != 0 || r.dev.count("upgrade") != 0 {
		t.Fatalf("POST /upgrade was made %d times on a device the check showed no offer for: it reboots a 26.1.9 box", n)
	}
	if r.dev.boot != boot {
		t.Error("the box was rebooted")
	}
	if got := r.dev.writes(); len(got) != 0 {
		t.Errorf("writes %v: a noop writes nothing", got)
	}
	if st := r.state(); st.Pending != nil || !st.Pinned || st.PinnedFlavour != "26.1/MINT/26.1.9/latest" {
		t.Errorf("record %+v", st)
	}
	if len(r.jobs) == 0 || r.jobs[len(r.jobs)-1].Phase == PhaseTriggered {
		t.Errorf("the run was recorded as requested: %+v", r.jobs[len(r.jobs)-1])
	}
}

// A check whose only entry is a same-version reinstall of the agent's own package
// reads "update" while the major is still offered: the offer is the major version and
// the sets, never the status.
func TestOfferReadUnderStatusUpdateStillStartsTheHop(t *testing.T) {
	r := hopRig(t, func(d *simDevice) { d.hop.reinstallAgent = true })
	p := hopPayload(approveFinalHotfix)

	job := hopRebootedJob(t, r, p)

	if r.dev.posts() != 1 {
		t.Fatalf("%d requests: an offer shown under the status update was not read", r.dev.posts())
	}
	if job.Phase != PhaseTriggered || job.Upgrade == nil || job.Upgrade.Mode != "major" {
		t.Errorf("job %+v", job)
	}
	if reinstalls := job.Reinstalls; reinstalls != 1 {
		t.Errorf("reinstall entries %d: the agent's record is counted, never held on", reinstalls)
	}
}

// No fresh, clean, current check, no request.
func TestNoMajorRequestWithoutAFreshCleanCheck(t *testing.T) {
	for name, tweak := range map[string]func(*simDevice){
		"no result at all: every check request is dropped": func(d *simDevice) { d.dropChecks = 100 },
		"a check that could not use the mirror":            func(d *simDevice) { d.checkFailsAs = "repository" },
		"a result made for another release":                func(d *simDevice) { d.hop.staleCheck = "26.1.9" },
	} {
		t.Run(name, func(t *testing.T) {
			r := hopRig(t)
			r.dev.do(tweak) // after the enrollment, which needs a clean check of its own
			res := wantResult(t, r.run(hopPayload(approveFinalHotfix)), OutcomeHeld, ReasonHeldCheckFailed)
			wantHop(t, res)
			if r.dev.posts() != 0 {
				t.Errorf("the request was made without a usable check: %v", r.dev.Calls())
			}
			if st := r.state(); st.Pending != nil {
				t.Errorf("pending %+v", st.Pending)
			}
		})
	}
}

// The offer is read again right before the request. The waits of the steps between
// (the free space, the boot environment) can see the check replaced under them.
func TestOfferIsReReadRightBeforeThePost(t *testing.T) {
	for name, tc := range map[string]struct {
		change  func(*simDevice)
		outcome string
		reason  string
	}{
		"the offer is gone": {func(d *simDevice) {
			d.checked.UpgradeMajorVersion, d.checked.UpgradeSets = "", nil
		}, OutcomeNoop, ReasonTargetNotYetOffered},
		"another check ran": {func(d *simDevice) { d.checked.LastCheck = "Mon Oct 12 23:59:59 UTC 2026" },
			OutcomeHeld, ReasonHeldCheckFailed},
		"the result was flushed": {func(d *simDevice) { d.checked = nil }, OutcomeHeld, ReasonHeldCheckFailed},
		"the sets changed": {func(d *simDevice) {
			d.checked.UpgradeSets = d.checked.UpgradeSets[:2]
		}, OutcomeHeld, ReasonHeldUnexpectedPlan},
		"a hotfix is pending": {func(d *simDevice) {
			d.checked.UpgradePackages = append(d.checked.UpgradePackages,
				opnapi.FirmwarePackageEntry{Name: "curl", Repository: "OPNsense", CurrentVersion: "8.20.0", NewVersionAlt: "8.21.0"})
		}, OutcomeHeld, ReasonHeldUnexpectedPlan},
	} {
		t.Run(name, func(t *testing.T) {
			r := hopRig(t)
			// disk-free is the last read before the record: a change here is one the waits
			// of the steps in between could have let happen.
			r.dev.onCall("disk-free", tc.change)
			res := wantResult(t, r.run(hopPayload(approveFinalHotfix)), tc.outcome, tc.reason)
			// The boot environment was made before the re-read, and the agent never removes
			// one: the answer says so, so the board does.
			wantHop(t, res, NoteBootEnvironmentMade)
			if r.dev.posts() != 0 {
				t.Errorf("the request was made on an offer that was no longer there: %v", r.dev.Calls())
			}
			if st := r.state(); st.Pending != nil {
				t.Errorf("pending %+v: nothing is recorded when the step ends here", st.Pending)
			}
			for _, j := range r.jobs {
				if j.Phase == PhaseTriggered {
					t.Errorf("the run was recorded as requested: %+v", j)
				}
			}
		})
	}
}

// A real upgrade entry in the plan is a hold even though the offer is there: the
// minor step should have taken it.
func TestAPlanWithARealUpgradeEntryHoldsEvenThoughTheOfferIsThere(t *testing.T) {
	r := hopRig(t)
	// The directory gets a newer curl after the minor path judged the plan.
	r.dev.onCall("stage-state", func(d *simDevice) {
		c := d.folders["26.1.11"]
		c.pkgs = map[string]string{"curl": "8.21.0", "pkg": "2.3.1_1"}
		d.folders["26.1.11"] = c
	})
	res := wantResult(t, r.run(hopPayload(approveFinalHotfix)), OutcomeHeld, ReasonHeldUnexpectedPlan)
	wantHop(t, res)
	if r.dev.posts() != 0 {
		t.Error("the upgrade was requested over a pending update")
	}
}
