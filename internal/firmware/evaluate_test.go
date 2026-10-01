package firmware

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// t0 is when the update was triggered in every scenario.
var t0 = time.Date(2026, 9, 22, 9, 0, 0, 0, time.UTC)

const (
	bootBefore = int64(1_780_000_000) // the box's boot time when the update was triggered
	fromV      = "26.7.3_8"
	toV        = "26.7.4_1"
)

// device is everything Evaluate can read, as one scenario sees it.
type device struct {
	state      RunState
	runErr     error
	locked     bool
	lockedErr  error
	release    string
	releaseErr error
	boot       int64
	bootErr    error
	installed  map[string]string
	installErr error
	updating   bool
	updateErr  error
	evidence   string
}

func (d device) probes() Probes {
	return Probes{
		Running: func(context.Context) (RunState, error) { return d.state, d.runErr },
		Locked:  func(context.Context) (bool, error) { return d.locked, d.lockedErr },
		Release: func(context.Context) (string, error) { return d.release, d.releaseErr },
		BootTime: func() (int64, error) {
			return d.boot, d.bootErr
		},
		Installed: func(context.Context) (map[string]string, error) { return d.installed, d.installErr },
		Updating:  func(context.Context) (bool, error) { return d.updating, d.updateErr },
		Evidence:  func(context.Context, time.Time) (string, error) { return d.evidence, nil },
	}
}

// idleDevice is the box after a clean update that rebooted: idle, the new
// release, a boot time an hour later, the planned packages installed.
func idleDevice() device {
	return device{
		state:   RunReady,
		release: toV,
		boot:    bootBefore + 3600,
		installed: map[string]string{
			"opnsense": toV, "os-netdefense": "1.19.5", "curl": "8.9.1_1", "libfoo": "2.0",
		},
	}
}

// weeklyMeta is a minor reboot=true run whose plan includes base and kernel.
func weeklyMeta() Meta {
	return Meta{
		Mode: "minor", Reboot: true, FromVersion: fromV, NeedsReboot: true,
		BootTime: bootBefore, StartedAt: t0.Unix(), TriggeredAt: t0.Unix(), ExpiresAt: t0.Add(MinorTTL).Unix(),
		Packages: []Package{
			{Name: "opnsense", Version: toV},
			{Name: "os-netdefense", Version: "1.19.5"},
			{Name: "curl", Version: "8.9.1_1"},
			{Name: "base", Version: "26.7.4"},
			{Name: "kernel", Version: "26.7.4"},
		},
	}
}

// nightlyMeta is a minor reboot=false run: packages only, base and kernel
// deferred, so the release may not change.
func nightlyMeta() Meta {
	return Meta{
		Mode: "minor", Reboot: false, FromVersion: toV, NeedsReboot: true,
		BootTime: bootBefore, StartedAt: t0.Unix(), TriggeredAt: t0.Unix(), ExpiresAt: t0.Add(MinorTTL).Unix(),
		Packages: []Package{
			{Name: "os-netdefense", Version: "1.19.5"},
			{Name: "curl", Version: "8.9.1_1"},
			{Name: "base", Version: "26.7.4"},
		},
	}
}

func majorMeta() Meta {
	return Meta{
		Mode: "major", Reboot: true, FromVersion: "26.1.9", NeedsReboot: true,
		BootTime: bootBefore, StartedAt: t0.Unix(), TriggeredAt: t0.Unix(), ExpiresAt: t0.Add(MajorTTL).Unix(),
	}
}

func inputAt(m *Meta, offset time.Duration) Input {
	return Input{Meta: m, RowStartedAt: t0, ProcessUptime: time.Hour, Now: t0.Add(offset)}
}

func metaPtr(m Meta) *Meta { return &m }

func (d device) with(f func(*device)) device { f(&d); return d }

type want struct {
	action  Action
	reason  string
	contain []string // substrings of the message
}

func TestEvaluate(t *testing.T) {
	soon := 2 * time.Minute
	afterDeadline := MinorTTL + Grace + time.Second

	cases := []struct {
		name string
		in   Input
		dev  device
		want want
	}{
		// ── never resolve while OPNsense is busy ─────────────────────────────────
		{
			name: "busy while the release has already advanced defers",
			in:   inputAt(metaPtr(weeklyMeta()), soon),
			dev:  idleDevice().with(func(d *device) { d.state = RunBusy }),
			want: want{Wait, "busy", nil},
		},
		{
			name: "busy with the release still the old one defers",
			in:   inputAt(metaPtr(weeklyMeta()), soon),
			dev:  idleDevice().with(func(d *device) { d.state = RunBusy; d.release = fromV }),
			want: want{Wait, "busy", nil},
		},
		{
			name: "the API answers ready but the lock is held: busy",
			in:   inputAt(metaPtr(weeklyMeta()), soon),
			dev:  idleDevice().with(func(d *device) { d.locked = true }),
			want: want{Wait, "busy", nil},
		},
		{
			name: "an unreadable lock probe changes nothing",
			in:   inputAt(metaPtr(weeklyMeta()), soon),
			dev:  idleDevice().with(func(d *device) { d.lockedErr = errors.New("no flock") }),
			want: want{Complete, "advanced", nil},
		},
		{
			name: "API error is unknown, not ready",
			in:   inputAt(metaPtr(weeklyMeta()), soon),
			dev:  idleDevice().with(func(d *device) { d.runErr = errors.New("connection refused") }),
			want: want{Wait, "unreachable", nil},
		},
		{
			name: "an empty answer is unknown, not ready",
			in:   inputAt(metaPtr(weeklyMeta()), soon),
			dev:  idleDevice().with(func(d *device) { d.state = RunUnknown }),
			want: want{Wait, "busy", nil},
		},
		{
			name: "busy past the deadline fails and says why",
			in:   inputAt(metaPtr(weeklyMeta()), afterDeadline),
			dev:  idleDevice().with(func(d *device) { d.state = RunBusy }),
			want: want{Fail, "busy-past-deadline", []string{"still running a firmware job"}},
		},
		{
			name: "unreachable past the deadline fails and says why",
			in:   inputAt(metaPtr(weeklyMeta()), afterDeadline),
			dev:  idleDevice().with(func(d *device) { d.runErr = errors.New("connection refused") }),
			want: want{Fail, "unreachable-past-deadline", []string{"could not be read", "connection refused"}},
		},

		// ── the release advanced ─────────────────────────────────────────────────
		{
			name: "ready, release advanced, rebooted: completed",
			in:   inputAt(metaPtr(weeklyMeta()), soon),
			dev:  idleDevice(),
			want: want{Complete, "advanced", nil},
		},
		{
			name: "release advanced but the reboot the plan needed has not happened: not completed",
			in:   inputAt(metaPtr(weeklyMeta()), soon),
			dev:  idleDevice().with(func(d *device) { d.boot = bootBefore }),
			want: want{Wait, "no-reboot", []string{"has not restarted"}},
		},
		{
			name: "a boot time that moved by less than the NTP margin is not a reboot",
			in:   inputAt(metaPtr(weeklyMeta()), soon),
			dev:  idleDevice().with(func(d *device) { d.boot = bootBefore + 90 }),
			want: want{Wait, "no-reboot", nil},
		},
		{
			name: "a boot time that moved by more than the margin is a reboot",
			in:   inputAt(metaPtr(weeklyMeta()), soon),
			dev:  idleDevice().with(func(d *device) { d.boot = bootBefore + 121 }),
			want: want{Complete, "advanced", nil},
		},
		{
			name: "no reboot past the deadline fails",
			in:   inputAt(metaPtr(weeklyMeta()), afterDeadline),
			dev:  idleDevice().with(func(d *device) { d.boot = bootBefore }),
			want: want{Fail, "no-reboot-past-deadline", []string{"has not restarted"}},
		},
		{
			name: "the boot time cannot be read while a reboot is required: wait",
			in:   inputAt(metaPtr(weeklyMeta()), soon),
			dev:  idleDevice().with(func(d *device) { d.bootErr = errors.New("sysctl failed") }),
			want: want{Wait, "boot-time", nil},
		},
		{
			name: "no boot time recorded at trigger: the reboot cannot be checked, the rest decides",
			in:   inputAt(metaPtr(weeklyMeta().withoutBoot()), soon),
			dev:  idleDevice().with(func(d *device) { d.boot = bootBefore }),
			want: want{Complete, "advanced", nil},
		},
		{
			name: "release unreadable: wait",
			in:   inputAt(metaPtr(weeklyMeta()), soon),
			dev:  idleDevice().with(func(d *device) { d.releaseErr = errors.New("no version file") }),
			want: want{Wait, "release-unreadable", nil},
		},

		// ── packages only: the release does not change ───────────────────────────
		{
			name: "packages-only run: every planned package installed is a completed run",
			in:   inputAt(metaPtr(nightlyMeta()), soon),
			dev: idleDevice().with(func(d *device) {
				d.release = toV
				d.boot = bootBefore
			}),
			want: want{Complete, "packages-applied", nil},
		},
		{
			name: "the agent's own upgrade keeps the release and completes",
			in: inputAt(metaPtr(func() Meta {
				m := weeklyMeta()
				m.Packages = []Package{{Name: "os-netdefense", Version: "1.19.5"}}
				m.FromVersion = toV
				m.Reboot = true
				return m
			}()), soon),
			dev:  idleDevice(),
			want: want{Complete, "packages-applied", nil},
		},
		{
			name: "one planned package missing fails and names it",
			in:   inputAt(metaPtr(nightlyMeta()), soon),
			dev: idleDevice().with(func(d *device) {
				d.boot = bootBefore
				d.installed["os-netdefense"] = "1.19.4"
			}),
			want: want{Fail, "packages-missing", []string{"os-netdefense", "not at the planned version"}},
		},
		{
			name: "a package installed at a newer version than planned counts",
			in:   inputAt(metaPtr(nightlyMeta()), soon),
			dev: idleDevice().with(func(d *device) {
				d.boot = bootBefore
				d.installed["curl"] = "8.9.2"
			}),
			want: want{Complete, "packages-applied", nil},
		},
		{
			name: "a revision bump of the planned version counts",
			in:   inputAt(metaPtr(nightlyMeta()), soon),
			dev: idleDevice().with(func(d *device) {
				d.boot = bootBefore
				d.installed["curl"] = "8.9.1_2"
			}),
			want: want{Complete, "packages-applied", nil},
		},
		{
			name: "a new package that is not installed is missing",
			in: inputAt(metaPtr(func() Meta {
				m := nightlyMeta()
				m.Packages = append(m.Packages, Package{Name: "py311-newdep", Version: "1.0"})
				return m
			}()), soon),
			dev:  idleDevice().with(func(d *device) { d.boot = bootBefore }),
			want: want{Fail, "packages-missing", []string{"py311-newdep"}},
		},
		{
			name: "missing packages while package tools still run: wait",
			in:   inputAt(metaPtr(nightlyMeta()), soon),
			dev: idleDevice().with(func(d *device) {
				d.boot = bootBefore
				d.installed["curl"] = "8.9.0"
				d.updating = true
			}),
			want: want{Wait, "packages-updating", nil},
		},
		{
			name: "missing packages and the tools cannot be probed: wait",
			in:   inputAt(metaPtr(nightlyMeta()), soon),
			dev: idleDevice().with(func(d *device) {
				d.boot = bootBefore
				d.installed["curl"] = "8.9.0"
				d.updateErr = errors.New("pgrep failed")
			}),
			want: want{Wait, "packages-updating", nil},
		},
		{
			name: "a package query that fails is not 'not installed': wait",
			in:   inputAt(metaPtr(nightlyMeta()), soon),
			dev: idleDevice().with(func(d *device) {
				d.boot = bootBefore
				d.installed = nil
				d.installErr = errors.New("Cannot get a read lock on a database")
			}),
			want: want{Wait, "pkg-query", []string{"read lock"}},
		},
		{
			name: "a package query that keeps failing past the deadline fails",
			in:   inputAt(metaPtr(nightlyMeta()), afterDeadline),
			dev: idleDevice().with(func(d *device) {
				d.installed = nil
				d.installErr = errors.New("Cannot get a read lock on a database")
			}),
			want: want{Fail, "pkg-query-past-deadline", nil},
		},
		{
			name: "only base and kernel planned, the box rebooted: completed",
			in: inputAt(metaPtr(func() Meta {
				m := weeklyMeta()
				m.Packages = []Package{{Name: "base", Version: "26.7.4"}, {Name: "kernel", Version: "26.7.4"}}
				return m
			}()), soon),
			dev:  idleDevice().with(func(d *device) { d.release = fromV }),
			want: want{Complete, "nothing-to-verify", nil},
		},

		// ── reboot=false: the agent's own child, no launcher lock ────────────────
		{
			name: "reboot=false ignores a busy backend and checks the plan",
			in:   inputAt(metaPtr(nightlyMeta()), soon),
			dev: idleDevice().with(func(d *device) {
				d.state = RunBusy
				d.runErr = errors.New("api down")
				d.boot = bootBefore
			}),
			want: want{Complete, "packages-applied", nil},
		},
		{
			name: "reboot=false does not require a reboot for the deferred base and kernel",
			in:   inputAt(metaPtr(nightlyMeta()), soon),
			dev:  idleDevice().with(func(d *device) { d.boot = bootBefore }),
			want: want{Complete, "packages-applied", nil},
		},
		{
			name: "reboot=false with a package missing fails",
			in:   inputAt(metaPtr(nightlyMeta()), soon),
			dev: idleDevice().with(func(d *device) {
				d.boot = bootBefore
				delete(d.installed, "curl")
			}),
			want: want{Fail, "packages-missing", []string{"curl"}},
		},

		// ── reboot=false: the release moves first, the packages follow ───────────
		{
			name: "reboot=false, the release advanced but pkg is still installing the rest: wait",
			in:   inputAt(metaPtr(nightlyMeta().fromRelease(fromV)), soon),
			dev: idleDevice().with(func(d *device) {
				d.boot = bootBefore
				d.updating = true
				d.installed = map[string]string{"opnsense": toV}
			}),
			want: want{Wait, "packages-updating", nil},
		},
		{
			name: "reboot=false, the release advanced and the tools cannot be probed: wait",
			in:   inputAt(metaPtr(nightlyMeta().fromRelease(fromV)), soon),
			dev: idleDevice().with(func(d *device) {
				d.boot = bootBefore
				d.updateErr = errors.New("pgrep failed")
			}),
			want: want{Wait, "packages-updating", nil},
		},
		{
			name: "reboot=false, the release advanced, pkg idle, a planned package missing: failed",
			in:   inputAt(metaPtr(nightlyMeta().fromRelease(fromV)), soon),
			dev: idleDevice().with(func(d *device) {
				d.boot = bootBefore
				d.installed = map[string]string{"opnsense": toV, "os-netdefense": "1.19.5"}
			}),
			want: want{Fail, "packages-missing", []string{"curl"}},
		},
		{
			name: "reboot=false, the release advanced, pkg idle, every package installed: completed",
			in:   inputAt(metaPtr(nightlyMeta().fromRelease(fromV)), soon),
			dev:  idleDevice().with(func(d *device) { d.boot = bootBefore }),
			want: want{Complete, "advanced", nil},
		},
		{
			name: "reboot=false, nothing planned can be checked and pkg is running: wait",
			in: inputAt(metaPtr(func() Meta {
				m := nightlyMeta()
				m.Packages = []Package{{Name: "base", Version: "26.7.4"}}
				return m
			}()), soon),
			dev:  idleDevice().with(func(d *device) { d.boot = bootBefore; d.updating = true }),
			want: want{Wait, "packages-updating", nil},
		},

		// ── a run that never triggered anything ──────────────────────────────────
		{
			name: "a task that never triggered the update fails at once, whatever the device shows",
			in:   inputAt(metaPtr(weeklyMeta().untriggered()), soon),
			dev:  idleDevice(),
			want: want{Fail, "not-started", []string{"was not started", "Nothing was applied by this task"}},
		},
		{
			name: "a task that never triggered the update fails at once, also while OPNsense is busy",
			in:   inputAt(metaPtr(weeklyMeta().untriggered()), soon),
			dev:  idleDevice().with(func(d *device) { d.state = RunBusy }),
			want: want{Fail, "not-started", nil},
		},
		{
			name: "a task that never triggered the update fails at once, also when nothing can be read",
			in:   inputAt(metaPtr(nightlyMeta().untriggered()), soon),
			dev:  device{runErr: errors.New("connection refused"), releaseErr: errors.New("x"), installErr: errors.New("y")},
			want: want{Fail, "not-started", nil},
		},

		// ── a reboot that cannot be confirmed ────────────────────────────────────
		{
			name: "no boot time at trigger, only base and kernel planned, the release unchanged: not completed",
			in: inputAt(metaPtr(func() Meta {
				m := weeklyMeta().withoutBoot()
				m.Packages = []Package{{Name: "base", Version: "26.7.4"}, {Name: "kernel", Version: "26.7.4"}}
				return m
			}()), soon),
			dev:  idleDevice().with(func(d *device) { d.release = fromV }),
			want: want{Wait, "boot-time-unknown", []string{"restart cannot be confirmed"}},
		},
		{
			name: "no boot time at trigger, packages installed but the release unchanged and a reboot needed: not completed",
			in: inputAt(metaPtr(func() Meta {
				m := weeklyMeta().withoutBoot()
				m.Packages = []Package{{Name: "os-netdefense", Version: "1.19.5"}, {Name: "base", Version: "26.7.4"}}
				return m
			}()), soon),
			dev:  idleDevice().with(func(d *device) { d.release = fromV }),
			want: want{Wait, "boot-time-unknown", nil},
		},
		{
			name: "no boot time at trigger, still unconfirmed past the deadline: failed",
			in: inputAt(metaPtr(func() Meta {
				m := weeklyMeta().withoutBoot()
				m.Packages = []Package{{Name: "base", Version: "26.7.4"}}
				return m
			}()), afterDeadline),
			dev:  idleDevice().with(func(d *device) { d.release = fromV }),
			want: want{Fail, "boot-time-unknown-past-deadline", nil},
		},

		// ── series upgrade ───────────────────────────────────────────────────────
		{
			name: "major: the release moved and the box rebooted: completed",
			in:   inputAt(metaPtr(majorMeta()), soon),
			dev:  idleDevice().with(func(d *device) { d.release = "26.7" }),
			want: want{Complete, "advanced", nil},
		},
		{
			name: "major between its reboots: the release has not moved yet, wait",
			in:   inputAt(metaPtr(majorMeta()), soon),
			dev:  idleDevice().with(func(d *device) { d.release = "26.1.9" }),
			want: want{Wait, "major-in-progress", nil},
		},
		{
			name: "major that never changed the release fails at the deadline",
			in:   inputAt(metaPtr(majorMeta()), MajorTTL+Grace+time.Second),
			dev:  idleDevice().with(func(d *device) { d.release = "26.1.9" }),
			want: want{Fail, "major-in-progress-past-deadline", []string{"has not changed", "26.1.9"}},
		},

		// ── proof of failure ─────────────────────────────────────────────────────
		{
			name: "a partial failure in OPNsense's log fails a run whose release advanced",
			in:   inputAt(metaPtr(weeklyMeta()), soon),
			dev:  idleDevice().with(func(d *device) { d.evidence = "Partial update failure detected" }),
			want: want{Fail, "partial-failure", []string{"Partial update failure detected"}},
		},

		// ── rows nothing was recorded for (written by an older agent) ────────────
		{
			name: "no metadata, busy: wait",
			in:   inputAt(nil, soon),
			dev:  idleDevice().with(func(d *device) { d.state = RunBusy }),
			want: want{Wait, "busy", nil},
		},
		{
			name: "no metadata, ready and reachable: completed as before",
			in:   inputAt(nil, soon),
			dev:  idleDevice(),
			want: want{Complete, "returned", []string{"Firmware upgrade completed; device returned with product_version " + toV}},
		},
		{
			name: "no metadata, ready, release unreadable: completed",
			in:   inputAt(nil, soon),
			dev:  idleDevice().with(func(d *device) { d.releaseErr = errors.New("x") }),
			want: want{Complete, "returned", []string{"Device returned after restart"}},
		},
		{
			name: "no metadata, ready, but package tools are running (an older agent's reboot=false run): wait",
			in:   inputAt(nil, soon),
			dev:  idleDevice().with(func(d *device) { d.updating = true }),
			want: want{Wait, "packages-updating", nil},
		},
		{
			name: "no metadata, ready, and the tools cannot be probed: wait",
			in:   inputAt(nil, soon),
			dev:  idleDevice().with(func(d *device) { d.updateErr = errors.New("pgrep failed") }),
			want: want{Wait, "packages-updating", nil},
		},
		{
			name: "no metadata, package tools still running past the longest task lifetime: failed",
			in:   inputAt(nil, MajorTTL+Grace+time.Second),
			dev:  idleDevice().with(func(d *device) { d.updating = true }),
			want: want{Fail, "packages-updating-past-deadline", nil},
		},
		{
			name: "no metadata, positive evidence of a partial failure: failed",
			in:   inputAt(nil, soon),
			dev:  idleDevice().with(func(d *device) { d.evidence = "Partial update failure detected" }),
			want: want{Fail, "partial-failure", nil},
		},
		{
			name: "no metadata, busy past the longest task lifetime: failed",
			in:   inputAt(nil, MajorTTL+Grace+time.Second),
			dev:  idleDevice().with(func(d *device) { d.state = RunBusy }),
			want: want{Fail, "busy-past-deadline", nil},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := Evaluate(context.Background(), tc.in, tc.dev.probes())
			if v.Action != tc.want.action || v.Reason != tc.want.reason {
				t.Fatalf("Evaluate = action %v reason %q (%q); want action %v reason %q",
					v.Action, v.Reason, v.Message, tc.want.action, tc.want.reason)
			}
			for _, sub := range tc.want.contain {
				if !strings.Contains(v.Message, sub) {
					t.Errorf("message %q does not contain %q", v.Message, sub)
				}
			}
			if v.Action == Fail && strings.HasPrefix(v.Message, "{") {
				t.Errorf("a failure must be plain text: NDCLI shows a JSON message without applied as a dry-run preview; got %q", v.Message)
			}
		})
	}
}

func (m Meta) withoutBoot() Meta { m.BootTime = 0; return m }

// untriggered is a run that was recorded but never triggered.
func (m Meta) untriggered() Meta { m.TriggeredAt = 0; return m }

// fromRelease is the same run started from another release.
func (m Meta) fromRelease(v string) Meta { m.FromVersion = v; return m }

// A COMPLETED run's message is the JSON NDCLI and NDWeb render. The values are
// the contract's, asserted literally.
func TestEvaluate_CompletedResultShape(t *testing.T) {
	v := Evaluate(context.Background(), inputAt(metaPtr(weeklyMeta()), 2*time.Minute), idleDevice().probes())
	if v.Action != Complete {
		t.Fatalf("Evaluate = %+v", v)
	}
	var got map[string]interface{}
	if err := json.Unmarshal([]byte(v.Message), &got); err != nil {
		t.Fatalf("the message is not JSON: %v\n%s", err, v.Message)
	}
	for k, want := range map[string]interface{}{
		"resolved_mode":    "minor",
		"from_version":     "26.7.3_8",
		"to_version":       "26.7.4_1",
		"applied":          true,
		"no_update":        false,
		"reboot_performed": true,
		"reboots_expected": float64(1),
		"packages_applied": float64(3), // opnsense, os-netdefense, curl: base and kernel are a reboot
		"mixed_state":      false,
		"reconciled":       true,
	} {
		if got[k] != want {
			t.Errorf("%s = %v (%T), want %v", k, got[k], got[k], want)
		}
	}
	if _, present := got["status_sentinel"]; present {
		t.Error("a reconciled result must not claim a sentinel the handler never saw")
	}
}

func TestEvaluate_PackagesOnlyResultKeepsTheRelease(t *testing.T) {
	dev := idleDevice().with(func(d *device) { d.boot = bootBefore })
	v := Evaluate(context.Background(), inputAt(metaPtr(nightlyMeta()), 2*time.Minute), dev.probes())
	if v.Action != Complete {
		t.Fatalf("Evaluate = %+v", v)
	}
	var got map[string]interface{}
	if err := json.Unmarshal([]byte(v.Message), &got); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	for k, want := range map[string]interface{}{
		"from_version":     toV,
		"to_version":       toV,
		"applied":          true,
		"reboot_performed": false,
		"reboots_expected": float64(0),
		"mixed_state":      true, // base was deferred
		"packages_applied": float64(2),
	} {
		if got[k] != want {
			t.Errorf("%s = %v, want %v", k, got[k], want)
		}
	}
}

// The handler evaluating its own run adds what it saw and does not call the
// result reconciled.
func TestEvaluate_InSessionResultCarriesTheSentinel(t *testing.T) {
	in := inputAt(metaPtr(weeklyMeta()), 2*time.Minute)
	in.Sentinel = "done"
	dev := idleDevice()
	v := Evaluate(context.Background(), in, dev.probes())
	if v.Action != Complete {
		t.Fatalf("Evaluate = %+v", v)
	}
	var got map[string]interface{}
	if err := json.Unmarshal([]byte(v.Message), &got); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if got["status_sentinel"] != "done" {
		t.Errorf("status_sentinel = %v, want done", got["status_sentinel"])
	}
	if _, present := got["reconciled"]; present {
		t.Error("an in-session result must not be marked reconciled")
	}
}

// OPNsense prints ***DONE*** after a partial failure and when it finishes
// without the reboot it needed, so the marker alone proves nothing.
func TestEvaluate_TheDoneMarkerIsNotTrusted(t *testing.T) {
	in := inputAt(metaPtr(weeklyMeta()), 2*time.Minute)
	in.Sentinel = "done"

	t.Run("done without the reboot the plan needed fails at once", func(t *testing.T) {
		dev := idleDevice().with(func(d *device) { d.boot = bootBefore })
		v := Evaluate(context.Background(), in, dev.probes())
		if v.Action != Fail || v.Reason != "no-reboot" {
			t.Fatalf("Evaluate = %+v", v)
		}
	})
	t.Run("done after a partial failure fails", func(t *testing.T) {
		dev := idleDevice().with(func(d *device) { d.evidence = "Partial update failure detected" })
		v := Evaluate(context.Background(), in, dev.probes())
		if v.Action != Fail || v.Reason != "partial-failure" {
			t.Fatalf("Evaluate = %+v", v)
		}
	})
	t.Run("done with packages missing fails", func(t *testing.T) {
		n := inputAt(metaPtr(nightlyMeta()), 2*time.Minute)
		n.Sentinel = "done"
		dev := idleDevice().with(func(d *device) { d.boot = bootBefore; delete(d.installed, "curl") })
		v := Evaluate(context.Background(), n, dev.probes())
		if v.Action != Fail || v.Reason != "packages-missing" {
			t.Fatalf("Evaluate = %+v", v)
		}
	})
	t.Run("done on a series upgrade that changed nothing fails", func(t *testing.T) {
		m := inputAt(metaPtr(majorMeta()), 2*time.Minute)
		m.Sentinel = "done"
		dev := idleDevice().with(func(d *device) { d.release = "26.1.9" })
		v := Evaluate(context.Background(), m, dev.probes())
		if v.Action != Fail || v.Reason != "unchanged" {
			t.Fatalf("Evaluate = %+v", v)
		}
	})
}

// A series upgrade whose end marker was seen while its start boot time is unknown
// is still failed at once: the unknown boot time only matters to a run that has
// no other way of showing it did nothing.
func TestEvaluate_ASeriesUpgradeThatEndedUnchangedFailsAtOnceWithoutABootTime(t *testing.T) {
	m := majorMeta()
	m.BootTime = 0
	in := inputAt(&m, 2*time.Minute)
	in.Sentinel = "done"
	dev := idleDevice().with(func(d *device) { d.release = "26.1.9" })
	if v := Evaluate(context.Background(), in, dev.probes()); v.Action != Fail || v.Reason != "unchanged" {
		t.Fatalf("Evaluate = %+v, want the series upgrade failed as unchanged", v)
	}
}

func TestEvaluate_FailureNamesMissingPackagesAndCapsTheList(t *testing.T) {
	m := nightlyMeta()
	m.Packages = nil
	for _, n := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"} {
		m.Packages = append(m.Packages, Package{Name: n, Version: "2"})
	}
	dev := idleDevice().with(func(d *device) { d.boot = bootBefore; d.installed = map[string]string{"a": "1"} })
	v := Evaluate(context.Background(), inputAt(metaPtr(m), 2*time.Minute), dev.probes())
	if v.Action != Fail || len(v.Missing) != 10 {
		t.Fatalf("Evaluate = %+v", v)
	}
	if !strings.Contains(v.Message, "10 packages (a, b, c, d, e, f, g, h and 2 more) are not at the planned version") {
		t.Errorf("message = %q", v.Message)
	}
}

// After a reboot the agent process is young: the row's own deadline is long
// gone, but the first sweeps must still read the outcome, not fail the row. The
// grace is counted in process uptime, which a step of the wall clock cannot move.
func TestEvaluate_TheDeadlineWaitsForTheProcessToHaveBeenUpForTheGrace(t *testing.T) {
	m := weeklyMeta()
	late := t0.Add(2 * time.Hour)
	dev := idleDevice().with(func(d *device) { d.runErr = errors.New("api not up yet") })

	in := Input{Meta: &m, RowStartedAt: t0, ProcessUptime: time.Minute, Now: late}
	if v := Evaluate(context.Background(), in, dev.probes()); v.Action != Wait {
		t.Fatalf("a row was failed a minute after the agent started: %+v", v)
	}

	in.ProcessUptime = Grace
	if v := Evaluate(context.Background(), in, dev.probes()); v.Action != Wait {
		t.Fatalf("a row was failed exactly at the grace: %+v", v)
	}

	in.ProcessUptime = Grace + time.Second
	if v := Evaluate(context.Background(), in, dev.probes()); v.Action != Fail {
		t.Fatalf("a row that stayed unreadable past the grace was not failed: %+v", v)
	}
}

// A process that has been up for ages does not push a row's deadline out: the
// row's own expiry plus the grace is what bounds it.
func TestEvaluate_AnOldProcessDoesNotExtendTheDeadline(t *testing.T) {
	m := weeklyMeta()
	dev := idleDevice().with(func(d *device) { d.runErr = errors.New("api down") })
	in := Input{Meta: &m, RowStartedAt: t0, ProcessUptime: 100 * time.Hour, Now: t0.Add(MinorTTL + Grace)}
	if v := Evaluate(context.Background(), in, dev.probes()); v.Action != Wait {
		t.Fatalf("failed at the deadline itself: %+v", v)
	}
	in.Now = t0.Add(MinorTTL + Grace + time.Second)
	if v := Evaluate(context.Background(), in, dev.probes()); v.Action != Fail {
		t.Fatalf("not failed just past the deadline: %+v", v)
	}
}

// A device without some probe still evaluates: the missing source is unreadable.
func TestEvaluate_NilProbesAreUnreadableSources(t *testing.T) {
	// A run that does not reboot is judged by the package tools first.
	m := nightlyMeta()
	v := Evaluate(context.Background(), inputAt(&m, 2*time.Minute), Probes{
		Release: func(context.Context) (string, error) { return toV, nil },
	})
	if v.Action != Wait || v.Reason != "packages-updating" {
		t.Fatalf("Evaluate = %+v, want a wait on the package tools", v)
	}

	// A packages-only run through the launcher needs the package database.
	own := weeklyMeta()
	own.FromVersion = toV
	own.Packages = []Package{{Name: "os-netdefense", Version: "1.19.5"}}
	v = Evaluate(context.Background(), inputAt(&own, 2*time.Minute), Probes{
		Running:  func(context.Context) (RunState, error) { return RunReady, nil },
		Release:  func(context.Context) (string, error) { return toV, nil },
		BootTime: func() (int64, error) { return bootBefore + 3600, nil },
	})
	if v.Action != Wait || v.Reason != "pkg-query" {
		t.Fatalf("Evaluate = %+v, want a wait on the package database", v)
	}

	w := weeklyMeta()
	v = Evaluate(context.Background(), inputAt(&w, 2*time.Minute), Probes{})
	if v.Action != Wait {
		t.Fatalf("Evaluate = %+v, want a wait with no API at all", v)
	}
}

// The failure text OPNsense keeps is looked for from the moment this run was
// triggered, not from when its task was taken up: a log an earlier run left, while
// this one waited for its turn, is not this run's.
func TestEvaluate_EvidenceIsLookedForFromTheTrigger(t *testing.T) {
	m := weeklyMeta()
	m.StartedAt = t0.Add(-10 * time.Minute).Unix()
	m.TriggeredAt = t0.Add(-2 * time.Minute).Unix()

	var since time.Time
	dev := idleDevice()
	probes := dev.probes()
	probes.Evidence = func(_ context.Context, s time.Time) (string, error) { since = s; return "", nil }
	if v := Evaluate(context.Background(), inputAt(&m, 2*time.Minute), probes); v.Action != Complete {
		t.Fatalf("Evaluate = %+v", v)
	}
	if !since.Equal(time.Unix(m.TriggeredAt, 0)) {
		t.Fatalf("evidence asked from %v, want the trigger time %v", since, time.Unix(m.TriggeredAt, 0))
	}

	// A row an older agent wrote is looked at from when the task row began.
	since = time.Time{}
	if v := Evaluate(context.Background(), inputAt(nil, 2*time.Minute), probes); v.Action != Complete {
		t.Fatalf("Evaluate = %+v", v)
	}
	if !since.Equal(t0) {
		t.Fatalf("evidence asked from %v for a row with no metadata, want the row's start %v", since, t0)
	}
}
