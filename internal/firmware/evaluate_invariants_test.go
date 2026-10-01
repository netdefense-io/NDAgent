package firmware

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestEvaluate_Invariants walks every combination of what the device can show
// for every kind of row, and holds each verdict to the rules the contract states
// as "never": an update is not reported done while it is still running, with
// proof it failed, without the reboot it needed or with a planned package
// missing, whatever else is edited. The rules are written from the contract, not
// from the code; a state that breaks one is printed whole.
func TestEvaluate_Invariants(t *testing.T) {
	type row struct {
		name string
		meta *Meta
	}
	rows := []row{
		{"weekly (reboot, base+kernel)", metaPtr(weeklyMeta())},
		{"weekly, no boot time recorded", metaPtr(weeklyMeta().withoutBoot())},
		{"nightly (no reboot)", metaPtr(nightlyMeta())},
		{"nightly, from an older release", metaPtr(nightlyMeta().fromRelease(fromV))},
		{"own upgrade (reboot, one package)", metaPtr(func() Meta {
			m := weeklyMeta()
			m.FromVersion = toV
			m.Packages = []Package{{Name: "os-netdefense", Version: "1.19.5"}}
			return m
		}())},
		{"major", metaPtr(majorMeta())},
		{"never triggered", metaPtr(weeklyMeta().untriggered())},
		{"legacy (no metadata)", nil},
	}

	runStates := []struct {
		name  string
		state RunState
		err   error
	}{
		{"ready", RunReady, nil}, {"busy", RunBusy, nil}, {"unknown", RunUnknown, nil}, {"error", RunUnknown, errors.New("refused")},
	}
	locks := []struct {
		held bool
		err  error
	}{{false, nil}, {true, nil}, {false, errors.New("no flock")}}
	releases := []struct {
		v   string
		err error
	}{{fromV, nil}, {toV, nil}, {"", errors.New("no version file")}}
	boots := []struct {
		v   int64
		err error
	}{{bootBefore, nil}, {bootBefore + 3600, nil}, {0, errors.New("sysctl")}}
	installs := []struct {
		name string
		m    map[string]string
		err  error
	}{
		{"all", map[string]string{"opnsense": toV, "os-netdefense": "1.19.5", "curl": "8.9.1_1", "libfoo": "2.0"}, nil},
		{"one missing", map[string]string{"opnsense": toV, "os-netdefense": "1.19.5", "libfoo": "2.0"}, nil},
		{"unreadable", nil, errors.New("read lock")},
	}
	tools := []struct {
		running bool
		err     error
	}{{false, nil}, {true, nil}, {false, errors.New("pgrep failed")}}
	evidences := []string{"", PartialFailureMarker}
	sentinels := []string{"", "done"}
	bounds := []time.Duration{2 * time.Minute, MajorTTL + Grace + time.Second}

	checked := 0
	for _, r := range rows {
		for _, rs := range runStates {
			for _, lk := range locks {
				for _, rel := range releases {
					for _, bt := range boots {
						for _, in := range installs {
							for _, tl := range tools {
								for _, ev := range evidences {
									for _, sentinel := range sentinels {
										for _, at := range bounds {
											dev := device{
												state: rs.state, runErr: rs.err, locked: lk.held, lockedErr: lk.err,
												release: rel.v, releaseErr: rel.err, boot: bt.v, bootErr: bt.err,
												installed: in.m, installErr: in.err, updating: tl.running, updateErr: tl.err,
												evidence: ev,
											}
											input := Input{Meta: r.meta, RowStartedAt: t0, ProcessUptime: time.Hour, Now: t0.Add(at), Sentinel: sentinel}
											v := Evaluate(context.Background(), input, dev.probes())
											checked++
											if msg := violation(r.meta, dev, input, v, at > MinorTTL+Grace); msg != "" {
												t.Fatalf("%s\nrow: %s\nverdict: action %v reason %q message %q\ndevice: %+v\nsentinel %q, %v into the task",
													msg, r.name, v.Action, v.Reason, v.Message, dev, sentinel, at)
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	t.Logf("%d states checked", checked)
}

// violation names the rule a verdict breaks, or "" when it breaks none.
func violation(meta *Meta, d device, in Input, v Verdict, pastBound bool) string {
	usesLauncher := meta == nil || meta.Reboot
	busy := d.state != RunReady || d.runErr != nil || d.locked
	toolsUnknownOrRunning := d.updating || d.updateErr != nil
	pastDeadline := pastBound && in.ProcessUptime > Grace && in.Now.After(Deadline(expiryOf(meta, in)))

	if v.Action == Fail && strings.HasPrefix(v.Message, "{") {
		return "a failure must be plain text: NDCLI shows a JSON message without applied as a dry-run preview"
	}

	if meta != nil && !meta.Triggered() {
		if v.Action != Fail || v.Reason != "not-started" {
			return "a task that never triggered anything must be failed as not started, whatever the device shows"
		}
		return ""
	}

	if v.Action == Complete {
		switch {
		case usesLauncher && busy:
			return "completed while OPNsense was busy or could not be read"
		case usesLauncher && d.evidence != "":
			return "completed although OPNsense's log shows the run failed"
		case (meta == nil || !meta.Reboot) && toolsUnknownOrRunning:
			return "completed while package tools were running or could not be probed"
		case meta != nil && !meta.Reboot && missingPlanned(meta, d):
			return "a run that does not reboot was completed with a planned package not installed"
		case meta != nil && meta.RebootExpected() && meta.BootTime > 0 && !movedBoot(meta, d):
			return "completed a run that needed a reboot the boot time does not show"
		case meta != nil && meta.RebootExpected() && meta.BootTime == 0 && d.release == meta.FromVersion:
			return "completed a run that needed a reboot, whose start boot time is unknown, with the release unchanged"
		case meta != nil && d.releaseErr != nil:
			return "completed without being able to read the release"
		case meta != nil && meta.Mode == "major" && d.release == meta.FromVersion:
			return "completed a series upgrade that did not change the release"
		}
		return ""
	}

	if v.Action == Fail && !pastDeadline {
		// Before the bound a row is failed only on positive evidence.
		switch v.Reason {
		case "partial-failure":
			if !usesLauncher || d.evidence == "" || busy {
				return "failed on evidence that was not there, or before the backend was idle"
			}
		case "no-reboot":
			if in.Sentinel != "done" {
				return "failed a missing reboot without the end marker, before the bound"
			}
		case "unchanged":
			if in.Sentinel != "done" {
				return "failed a series upgrade that has not changed the release, without the end marker, before the bound"
			}
		case "packages-missing":
			if toolsUnknownOrRunning || d.installErr != nil {
				return "failed for missing packages while package tools ran or the database could not be read"
			}
			if len(v.Missing) == 0 {
				return "a missing-packages failure that names none"
			}
		default:
			return fmt.Sprintf("failed before the bound with %q, which is not positive evidence", v.Reason)
		}
	}
	return ""
}

func expiryOf(meta *Meta, in Input) time.Time {
	if meta == nil {
		return in.RowStartedAt.Add(MajorTTL)
	}
	return meta.Expiry()
}

func movedBoot(meta *Meta, d device) bool {
	return d.bootErr == nil && time.Unix(d.boot, 0).After(time.Unix(meta.BootTime, 0).Add(BootMargin))
}

// missingPlanned reports whether a planned package is not installed at its
// planned version, or the database could not say.
func missingPlanned(meta *Meta, d device) bool {
	if d.installErr != nil {
		return true
	}
	for _, p := range meta.checkable() {
		if !AtLeast(d.installed[p.Name], p.Version) {
			return true
		}
	}
	return false
}
