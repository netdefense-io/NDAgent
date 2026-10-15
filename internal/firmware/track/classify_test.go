package track

import (
	"strings"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/firmware"
)

// The abort classification of a series upgrade that has been requested: what the
// upgrade was, from the four versions against what the job recorded, the markers,
// the boot time and the text of the logs. No size is a test.

var classifyTrigger = time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC)

// atTheStart is the device as the job recorded it at the request: a community
// 26.1.11_10, whose pkgs marker sits below the core (an image's).
func atTheStart(mut ...func(*hopEvidence)) hopEvidence {
	ev := hopEvidence{
		Job:  Job{Major: "26.7", From: "26.1.11_10", FromBase: "26.1.11", FromKernel: "26.1.11", FromPkgs: "26.1.6_2"},
		Meta: firmware.Meta{TriggeredAt: classifyTrigger.Unix()},
		State: StageState{
			Core: "26.1.11_10", Base: "26.1.11", Kernel: "26.1.11", Pkgs: "26.1.6_2",
			SetsPendingEmpty: true, RunningKernel: "14.3-RELEASE-p16", Userland: "14.3-RELEASE-p16",
		},
		BootKnown: true,
	}
	for _, m := range mut {
		m(&ev)
	}
	return ev
}

func progress(text string) func(*hopEvidence) { return func(ev *hopEvidence) { ev.Progress = text } }
func bootMoved(ev *hopEvidence)               { ev.BootMoved = true }
func bootUnknown(ev *hopEvidence)             { ev.BootKnown, ev.BootMoved = false, false }
func setsPendingLeft(ev *hopEvidence)         { ev.State.SetsPendingEmpty = false }
func markers(m Markers) func(*hopEvidence)    { return func(ev *hopEvidence) { ev.State.Markers = m } }
func updateLog(at time.Time, text string) func(*hopEvidence) {
	return func(ev *hopEvidence) { ev.State.UpdateLog = LogFile{Exists: true, ModTime: at, Text: text} }
}
func upgradeLog(at time.Time, text string) func(*hopEvidence) {
	return func(ev *hopEvidence) { ev.State.UpgradeLog = LogFile{Exists: true, ModTime: at, Text: text} }
}
func versions(core, base, kernel, pkgs string) func(*hopEvidence) {
	return func(ev *hopEvidence) {
		ev.State.Core, ev.State.Base, ev.State.Kernel, ev.State.Pkgs = core, base, kernel, pkgs
	}
}

const (
	afterTheRequest  = 10 * time.Minute
	beforeTheRequest = -48 * time.Hour
)

func TestClassifyHop_TheRowsOfTheTable(t *testing.T) {
	after, before := classifyTrigger.Add(afterTheRequest), classifyTrigger.Add(beforeTheRequest)
	cases := []struct {
		name   string
		ev     hopEvidence
		action hopAction
		reason string
		abort  bool // counts in the back-off
		clean  bool // the cache is emptied once every log was read
		mixed  bool // the landing note
	}{
		// Row 4: the disk was full. The lab produced EDQUOT; ENOSPC is matched by its text.
		{name: "row 4: the fetch ran out of disk (EDQUOT)",
			ev:     atTheStart(progress("failed, no update found\nDisc quota exceeded\n***DONE***")),
			action: hopHold, reason: ReasonHeldInsufficientSpace, clean: true},
		{name: "row 4: the extraction ran out of disk (ENOSPC), the .update.log rewrite lost (71b)",
			ev: atTheStart(progress("tar: Error exit delayed from previous errors.\nNo space left on device\n***DONE***"),
				updateLog(after, "")),
			action: hopHold, reason: ReasonHeldInsufficientSpace, clean: true},
		{name: "row 4: the text only in the .update.log written after the request",
			ev:     atTheStart(progress("***DONE***"), updateLog(after, "pkg: No space left on device")),
			action: hopHold, reason: ReasonHeldInsufficientSpace, clean: true},
		{name: "row 4: the text only in the .upgrade.log written after the request",
			ev:     atTheStart(upgradeLog(after, "Disc quota exceeded")),
			action: hopHold, reason: ReasonHeldInsufficientSpace, clean: true},
		{name: "row 4: the box restarted, whatever the boot time says",
			ev:     atTheStart(progress("Disc quota exceeded"), bootMoved),
			action: hopHold, reason: ReasonHeldInsufficientSpace, clean: true},
		{name: "row 4: a partial .sets.pending of any size changes nothing",
			ev:     atTheStart(progress("Disc quota exceeded"), setsPendingLeft),
			action: hopHold, reason: ReasonHeldInsufficientSpace, clean: true},

		// Row 5: anything else that left the box as it was.
		{name: "row 5: the script's own abort line",
			ev:     atTheStart(progress("The upgrade was aborted due to an error.\n***DONE***")),
			action: hopHold, reason: ReasonHeldUpgradeAborted, abort: true, clean: true},
		{name: "row 5: a power cut in the download: the box restarted and no log says anything",
			ev:     atTheStart(bootMoved),
			action: hopHold, reason: ReasonHeldUpgradeAborted, abort: true, clean: true},
		{name: "row 5: a reset after the extraction, the markers lost, a partial .sets.pending",
			ev:     atTheStart(bootMoved, setsPendingLeft, updateLog(before, "the previous update")),
			action: hopHold, reason: ReasonHeldUpgradeAborted, abort: true, clean: true},
		{name: "row 5: the refused stage P (wrong architecture) leaves its text in the .upgrade.log",
			ev: atTheStart(bootMoved, setsPendingLeft,
				upgradeLog(after, "pkg: wrong architecture: FreeBSD:15:amd64 instead of FreeBSD:14:amd64")),
			action: hopHold, reason: ReasonHeldUpgradeAborted, abort: true, clean: true},
		{name: "row 5: a disk text in an .update.log from before the request is an earlier run's",
			ev:     atTheStart(updateLog(before, "Disc quota exceeded"), upgradeLog(before, "No space left on device")),
			action: hopHold, reason: ReasonHeldUpgradeAborted, abort: true, clean: true},
		{name: "row 5: a boot time that cannot be read changes nothing when the versions are unchanged",
			ev:     atTheStart(bootUnknown),
			action: hopHold, reason: ReasonHeldUpgradeAborted, abort: true, clean: true},
		{name: "row 5: the progress log is read even when the logs on disk are not there",
			ev:     atTheStart(progress("No space left on device")),
			action: hopHold, reason: ReasonHeldInsufficientSpace, clean: true},

		// Row 6: staged and waiting for a reboot, which will resume it.
		{name: "row 6: the three markers, the boot time unchanged",
			ev:     atTheStart(markers(Markers{Kernel: true, Base: true, Pkgs: true})),
			action: hopHold, reason: ReasonHeldRebootPending},
		{name: "row 6: one marker left",
			ev:     atTheStart(markers(Markers{Pkgs: true})),
			action: hopHold, reason: ReasonHeldRebootPending},

		// Row 3: some at the series, some not, the box restarted.
		{name: "row 3: the core at the series with the packages marker short of it",
			ev:     atTheStart(versions("26.7.1_1", "26.7", "26.7", "26.1.6_2"), bootMoved, markers(Markers{Pkgs: true})),
			action: hopFail, mixed: true},
		{name: "row 3: the base and the kernel at the series, the core and the packages short",
			ev:     atTheStart(versions("26.1.11_10", "26.7", "26.7", "26.1.6_2"), bootMoved),
			action: hopFail, mixed: true},
		{name: "row 3: the kernel alone at the series",
			ev:     atTheStart(versions("26.1.11_10", "26.1.11", "26.7", "26.1.6_2"), bootMoved),
			action: hopFail, mixed: true},
		{name: "row 3: a boot time that cannot be read: the versions prove what it cannot",
			ev:     atTheStart(versions("26.7.1_1", "26.7", "26.1.11", "26.1.6_2"), bootUnknown),
			action: hopFail, mixed: true},

		// Row 7: anything else waits.
		{name: "row 7: markers left and the box restarted",
			ev:     atTheStart(markers(Markers{Pkgs: true}), bootMoved),
			action: hopWait},
		{name: "row 7: markers left and the boot time unreadable",
			ev:     atTheStart(markers(Markers{Base: true, Pkgs: true}), bootUnknown),
			action: hopWait},
		{name: "row 7: a version moved inside the old series and nothing is at the new one",
			ev:     atTheStart(versions("26.1.12", "26.1.11", "26.1.11", "26.1.6_2"), bootMoved),
			action: hopWait},
		{name: "row 7: some at the series and the box has not restarted",
			ev:     atTheStart(versions("26.1.11_10", "26.1.11", "26.7", "26.1.6_2")),
			action: hopWait},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := classifyHop(tc.ev)
			if v.action != tc.action || v.reason != tc.reason || v.abort != tc.abort || v.clean != tc.clean || v.mixed != tc.mixed {
				t.Fatalf("verdict %+v, want action %d reason %q abort %v clean %v mixed %v",
					v, tc.action, tc.reason, tc.abort, tc.clean, tc.mixed)
			}
			if tc.action == hopFail && !strings.Contains(v.why, "26.7") {
				t.Errorf("the failure text %q does not name the series", v.why)
			}
		})
	}
}

// The four versions are compared with what the job recorded, not with each other:
// an image's pkgs marker sits below its core, and that is "unchanged".
func TestClassifyHop_UnchangedMeansEqualToWhatTheJobRecorded(t *testing.T) {
	ev := atTheStart(progress("The upgrade was aborted due to an error.\n***DONE***"))
	if ev.State.Pkgs == ev.State.Core {
		t.Fatal("the fixture must keep its pkgs marker below the core")
	}
	if v := classifyHop(ev); v.reason != ReasonHeldUpgradeAborted {
		t.Fatalf("verdict %+v: a pkgs marker below the core is no change", v)
	}
	ev.Job.FromPkgs = "26.1.11" // recorded differently from what is read now
	if v := classifyHop(ev); v.action == hopHold {
		t.Fatalf("verdict %+v: a version that differs from the recorded one is not an unchanged box", v)
	}
}

func TestMajorLanded_TheBoxIsWholeAtTheSeries(t *testing.T) {
	whole := StageState{
		Core: "26.7.1_1", Base: "26.7", Kernel: "26.7", Pkgs: "26.7", SetsPendingEmpty: true,
		RunningKernel: "15.1-RELEASE-p1", Userland: "15.1-RELEASE-p1",
	}
	if !majorLanded(whole, "26.7") {
		t.Fatal("a whole box was not taken for landed")
	}
	cases := map[string]func(*StageState){
		"the core is short":                  func(s *StageState) { s.Core = "26.1.11_10" },
		"the core is another series":         func(s *StageState) { s.Core = "27.1.1" },
		"the base is short":                  func(s *StageState) { s.Base = "26.1.11" },
		"the kernel is short":                func(s *StageState) { s.Kernel = "26.1.11" },
		"the packages marker is short":       func(s *StageState) { s.Pkgs = "26.1.6_2" },
		"a version cannot be read":           func(s *StageState) { s.Pkgs = "" },
		"the kernel marker is left":          func(s *StageState) { s.Markers = Markers{Kernel: true} },
		"the base marker is left":            func(s *StageState) { s.Markers = Markers{Base: true} },
		"the packages marker is left":        func(s *StageState) { s.Markers = Markers{Pkgs: true} },
		"the extracted sets are still there": func(s *StageState) { s.SetsPendingEmpty = false },
		"the running kernel is not the userland": func(s *StageState) {
			s.RunningKernel = "14.3-RELEASE-p16"
		},
		"the running kernel cannot be read": func(s *StageState) { s.RunningKernel = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			st := whole
			mutate(&st)
			if majorLanded(st, "26.7") {
				t.Fatalf("%+v was taken for landed", st)
			}
		})
	}
	if majorLanded(whole, "27.1") {
		t.Error("a box at 26.7 landed on 27.1")
	}
}

// A landing is told from the box and never from a log: the log files are not an
// input of majorLanded.
func TestMajorLanded_ReadsNoLogAndNoRepository(t *testing.T) {
	whole := StageState{
		Core: "26.7.1_1", Base: "26.7", Kernel: "26.7", Pkgs: "26.7", SetsPendingEmpty: true,
		RunningKernel: "15.1-RELEASE-p1", Userland: "15.1-RELEASE-p1",
		UpdateLog: LogFile{Exists: true, ModTime: classifyTrigger, Text: "Partial update failure detected\n***DONE***"},
	}
	if !majorLanded(whole, "26.7") {
		t.Fatal("a failure text in a log (an operator's click on the dead pin writes one) failed a landed box")
	}
	whole.UpdateLog = LogFile{}
	if !majorLanded(whole, "26.7") {
		t.Fatal("a landing that leaves no .update.log is still a landing (Part 9's left none)")
	}
}
