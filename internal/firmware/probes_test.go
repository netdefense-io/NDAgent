package firmware

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

type stubAPI struct {
	running     *opnapi.FirmwareRunning
	runningErr  error
	progress    *opnapi.FirmwareProgressStatus
	progressErr error
	release     opnapi.ProductRelease
	releaseErr  error
}

func (s stubAPI) GetFirmwareRunning(context.Context) (*opnapi.FirmwareRunning, error) {
	return s.running, s.runningErr
}
func (s stubAPI) GetFirmwareUpgradeProgress(context.Context) (*opnapi.FirmwareProgressStatus, error) {
	return s.progress, s.progressErr
}
func (s stubAPI) InstalledRelease(context.Context) (opnapi.ProductRelease, error) {
	return s.release, s.releaseErr
}

// exitStatus returns the error a command that exits with code produces.
func exitStatus(t *testing.T, code string) error {
	t.Helper()
	err := exec.Command("sh", "-c", "exit "+code).Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected an ExitError, got %v", err)
	}
	return err
}

// /running is read literally: "ready" is ready, "busy" is busy, and an empty or
// unexpected status is not evidence of anything.
func TestNewProbes_RunningStates(t *testing.T) {
	cases := []struct {
		name    string
		api     API
		want    RunState
		wantErr bool
	}{
		{"ready", stubAPI{running: &opnapi.FirmwareRunning{Status: "ready"}}, RunReady, false},
		{"busy", stubAPI{running: &opnapi.FirmwareRunning{Status: "busy"}}, RunBusy, false},
		{"empty", stubAPI{running: &opnapi.FirmwareRunning{Status: ""}}, RunUnknown, false},
		{"unexpected", stubAPI{running: &opnapi.FirmwareRunning{Status: "running"}}, RunUnknown, false},
		{"nil response", stubAPI{}, RunUnknown, false},
		{"error", stubAPI{runningErr: errors.New("boom")}, RunUnknown, true},
		{"no api client", nil, RunUnknown, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NewProbes(tc.api).Running(context.Background())
			if got != tc.want || (err != nil) != tc.wantErr {
				t.Fatalf("Running = %v, %v; want %v, error=%v", got, err, tc.want, tc.wantErr)
			}
		})
	}
}

func TestNewProbes_ReleaseIsTheRawInstalledVersion(t *testing.T) {
	api := stubAPI{release: opnapi.ProductRelease{Raw: "26.7.4_1", Major: 26, Minor: 7}}
	got, err := NewProbes(api).Release(context.Background())
	if err != nil || got != "26.7.4_1" {
		t.Fatalf("Release = %q, %v; want 26.7.4_1", got, err)
	}
	if _, err := NewProbes(stubAPI{releaseErr: errors.New("boom")}).Release(context.Background()); err == nil {
		t.Fatal("a release error was swallowed")
	}
}

func TestProbesOnce_ReadsEachSourceOnce(t *testing.T) {
	var running, locked, release, boot, installed, updating int
	p := Probes{
		Running:   func(context.Context) (RunState, error) { running++; return RunReady, nil },
		Locked:    func(context.Context) (bool, error) { locked++; return false, nil },
		Release:   func(context.Context) (string, error) { release++; return "26.7", nil },
		BootTime:  func() (int64, error) { boot++; return 7, nil },
		Installed: func(context.Context) (map[string]string, error) { installed++; return map[string]string{"a": "1"}, nil },
		Updating:  func(context.Context) (bool, error) { updating++; return false, nil },
	}.Once()

	for i := 0; i < 3; i++ {
		_, _ = p.Running(context.Background())
		_, _ = p.Locked(context.Background())
		_, _ = p.Release(context.Background())
		_, _ = p.BootTime()
		_, _ = p.Installed(context.Background())
		_, _ = p.Updating(context.Background())
	}
	for name, n := range map[string]int{"Running": running, "Locked": locked, "Release": release, "BootTime": boot, "Installed": installed, "Updating": updating} {
		if n != 1 {
			t.Errorf("%s read %d times, want once", name, n)
		}
	}
}

func TestProbesOnce_RemembersAnErrorAndLeavesNilProbesNil(t *testing.T) {
	calls := 0
	p := Probes{
		Running: func(context.Context) (RunState, error) { calls++; return RunUnknown, errors.New("down") },
	}.Once()
	for i := 0; i < 2; i++ {
		if _, err := p.Running(context.Background()); err == nil {
			t.Fatal("the error was lost")
		}
	}
	if calls != 1 {
		t.Fatalf("the failing read ran %d times, want once", calls)
	}
	if p.Release != nil || p.Installed != nil || p.Locked != nil || p.BootTime != nil || p.Updating != nil {
		t.Fatal("Once must not invent probes the caller did not have")
	}
}

func TestPackageToolsRunning(t *testing.T) {
	prev := pgrep
	t.Cleanup(func() { pgrep = prev })

	pgrep = func(_ context.Context, pattern string) error {
		if pattern != updateToolsPattern {
			t.Errorf("pattern = %q", pattern)
		}
		return nil
	}
	if busy, err := packageToolsRunning(context.Background()); !busy || err != nil {
		t.Fatalf("a matching process: busy=%v err=%v, want true,nil", busy, err)
	}

	pgrep = func(context.Context, string) error { return exitStatus(t, "1") }
	if busy, err := packageToolsRunning(context.Background()); busy || err != nil {
		t.Fatalf("no match (exit 1): busy=%v err=%v, want false,nil", busy, err)
	}

	pgrep = func(context.Context, string) error { return exitStatus(t, "3") }
	if _, err := packageToolsRunning(context.Background()); err == nil {
		t.Fatal("a pgrep failure (exit 3) must be an error, not 'nothing running'")
	}
}

// The pattern is what decides which processes count, so it is pinned against the
// command lines of the tools it must catch and of the ones it must not.
func TestUpdateToolsPattern(t *testing.T) {
	re := mustCompileERE(t, updateToolsPattern)
	for _, line := range []string{
		"pkg upgrade -y",
		"/usr/sbin/pkg upgrade -y",
		"/usr/local/sbin/pkg-static upgrade -f",
		"/bin/sh /usr/local/sbin/opnsense-update -pt opnsense",
		"opnsense-update",
	} {
		if !re.MatchString(line) {
			t.Errorf("%q must count as package tooling running", line)
		}
	}
	for _, line := range []string{
		"/usr/local/bin/ndagent -c /usr/local/etc/ndagent.conf",
		"vi /usr/local/etc/pkg/repos/NetDefense.conf",
		"tail -f /var/log/pkg.log",
		"/usr/local/sbin/pkg-config --libs",
		"sshd: root@pts/0",
	} {
		if re.MatchString(line) {
			t.Errorf("%q must not count as package tooling running", line)
		}
	}
}

func TestFirmwareLockHeld(t *testing.T) {
	prev := flock
	t.Cleanup(func() { flock = prev })

	flock = func(context.Context) error { return nil }
	if held, err := firmwareLockHeld(context.Background()); held || err != nil {
		t.Fatalf("lock taken: held=%v err=%v, want false,nil", held, err)
	}
	flock = func(context.Context) error { return exitStatus(t, "1") }
	if held, err := firmwareLockHeld(context.Background()); !held || err != nil {
		t.Fatalf("contended (exit 1): held=%v err=%v, want true,nil", held, err)
	}
	// Any other failure says nothing about the lock.
	flock = func(context.Context) error { return exitStatus(t, "64") }
	if held, err := firmwareLockHeld(context.Background()); held || err == nil {
		t.Fatalf("usage error: held=%v err=%v, want false and an error", held, err)
	}
	flock = func(context.Context) error { return errors.New("flock: not found") }
	if held, err := firmwareLockHeld(context.Background()); held || err == nil {
		t.Fatalf("missing binary: held=%v err=%v, want false and an error", held, err)
	}
}

func TestBootTime(t *testing.T) {
	prev := bootTimeFunc
	t.Cleanup(func() { bootTimeFunc = prev })

	bootTimeFunc = func() (uint64, error) { return 1_780_000_000, nil }
	if got, err := BootTime(); got != 1_780_000_000 || err != nil {
		t.Fatalf("BootTime = %d, %v", got, err)
	}
	bootTimeFunc = func() (uint64, error) { return 0, errors.New("sysctl") }
	if _, err := BootTime(); err == nil {
		t.Fatal("a boot time error was swallowed")
	}
}

// writeUpdateLog points the evidence probe at a log with the given text and age.
func writeUpdateLog(t *testing.T, text string, age time.Duration) {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".update.log")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}
	when := time.Now().Add(-age)
	if err := os.Chtimes(path, when, when); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	prev := updateLogPath
	updateLogPath = path
	t.Cleanup(func() { updateLogPath = prev })
}

func TestPartialFailureEvidence(t *testing.T) {
	since := time.Now().Add(-10 * time.Minute)
	failed := "Fetching...\n" + PartialFailureMarker + "\n***DONE***\n"

	t.Run("the last update's log on disk, from this run", func(t *testing.T) {
		writeUpdateLog(t, failed, 5*time.Minute)
		got, err := partialFailureEvidence(nil)(context.Background(), since)
		if err != nil || got != PartialFailureMarker {
			t.Fatalf("evidence = %q, %v", got, err)
		}
	})
	t.Run("a log older than the run is not this run's", func(t *testing.T) {
		writeUpdateLog(t, failed, 3*time.Hour)
		if got, _ := partialFailureEvidence(nil)(context.Background(), since); got != "" {
			t.Fatalf("evidence = %q from a log that predates the run", got)
		}
	})
	// Two tasks of one device run back to back: the second's trigger is seconds
	// after the first's failure, and what the first left is not the second's.
	t.Run("a log written a moment before the trigger is not this run's either", func(t *testing.T) {
		writeUpdateLog(t, failed, 10*time.Minute+30*time.Second)
		if got, _ := partialFailureEvidence(nil)(context.Background(), since); got != "" {
			t.Fatalf("evidence = %q from a log written before the run was triggered", got)
		}
	})
	t.Run("a series upgrade that was aborted", func(t *testing.T) {
		writeUpdateLog(t, "Fetching...\n"+UpgradeAbortedMarker+"\n***DONE***\n", time.Minute)
		got, err := partialFailureEvidence(nil)(context.Background(), since)
		if err != nil || got != UpgradeAbortedMarker {
			t.Fatalf("evidence = %q, %v", got, err)
		}
	})
	t.Run("the abort text in the live progress log", func(t *testing.T) {
		writeUpdateLog(t, "", 3*time.Hour)
		api := stubAPI{progress: &opnapi.FirmwareProgressStatus{Status: "done", Log: UpgradeAbortedMarker + "\n***DONE***"}}
		got, err := partialFailureEvidence(api)(context.Background(), since)
		if err != nil || got != UpgradeAbortedMarker {
			t.Fatalf("evidence = %q, %v", got, err)
		}
	})
	t.Run("a clean log is no evidence", func(t *testing.T) {
		writeUpdateLog(t, "Fetching...\n***DONE***\n", time.Minute)
		if got, _ := partialFailureEvidence(nil)(context.Background(), since); got != "" {
			t.Fatalf("evidence = %q from a clean log", got)
		}
	})
	t.Run("the live progress log the API serves", func(t *testing.T) {
		writeUpdateLog(t, "", 3*time.Hour) // nothing usable on disk
		api := stubAPI{progress: &opnapi.FirmwareProgressStatus{Status: "done", Log: failed}}
		got, err := partialFailureEvidence(api)(context.Background(), since)
		if err != nil || got != PartialFailureMarker {
			t.Fatalf("evidence = %q, %v", got, err)
		}
	})
	t.Run("an API that cannot answer is no evidence", func(t *testing.T) {
		writeUpdateLog(t, "", 3*time.Hour)
		api := stubAPI{progressErr: errors.New("boom")}
		if got, err := partialFailureEvidence(api)(context.Background(), since); got != "" || err != nil {
			t.Fatalf("evidence = %q, %v", got, err)
		}
	})
	t.Run("no log at all", func(t *testing.T) {
		prev := updateLogPath
		updateLogPath = filepath.Join(t.TempDir(), "missing")
		t.Cleanup(func() { updateLogPath = prev })
		if got, err := partialFailureEvidence(nil)(context.Background(), since); got != "" || err != nil {
			t.Fatalf("evidence = %q, %v", got, err)
		}
	})
}

func TestReadTail_OnlyTheEndOfALargeFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	if err := os.WriteFile(path, []byte(strings.Repeat("a", 100)+"END"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readTail(path, 10)
	if err != nil || got != strings.Repeat("a", 7)+"END" {
		t.Fatalf("readTail = %q, %v", got, err)
	}
	got, err = readTail(path, 1000)
	if err != nil || len(got) != 103 {
		t.Fatalf("readTail of a small file = %d bytes, %v", len(got), err)
	}
}

// mustCompileERE compiles a POSIX-style pattern with Go's regexp, for tests of
// patterns that pgrep(1) evaluates. The pattern uses only what both accept.
func mustCompileERE(t *testing.T, pattern string) *regexp.Regexp {
	t.Helper()
	re, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatalf("compile %q: %v", pattern, err)
	}
	return re
}

func TestInstalledSets(t *testing.T) {
	defer func(prev func(context.Context, string) (string, error)) { setVersion = prev }(setVersion)

	versions := map[string]string{"-vb": "26.7.4", "-vk": "26.7.4"}
	setVersion = func(_ context.Context, flag string) (string, error) { return versions[flag], nil }
	base, kernel, err := NewProbes(nil).Sets(context.Background())
	if err != nil || base != "26.7.4" || kernel != "26.7.4" {
		t.Fatalf("got %q %q, %v", base, kernel, err)
	}

	// Anything that is not a version is no reading: a usage text, nothing at all.
	for name, out := range map[string]string{
		"empty":      "",
		"usage":      "Usage: opnsense-update [-bdefGgikmnPpRrSsTUuVv] [-A abi]",
		"with space": "26.7 4",
	} {
		versions["-vb"] = out
		if _, _, err := installedSets(context.Background()); err == nil {
			t.Errorf("%s: %q was taken for a version", name, out)
		}
	}

	versions["-vb"] = "26.7.4"
	setVersion = func(_ context.Context, flag string) (string, error) {
		if flag == "-vk" {
			return "", errors.New("exit status 1")
		}
		return versions[flag], nil
	}
	if _, _, err := installedSets(context.Background()); err == nil {
		t.Error("an unreadable kernel version was accepted")
	}
}

// A series upgrade's landing is judged from the version of the base, the kernel and
// the packages. The packages marker is written by stage P only when its pkg upgrade
// succeeded, so a box that never ran stage P (an image, a box installed from one) has
// none, and `opnsense-update -vp` prints an empty line: that is no version, and no
// failure to read. Base and kernel are always there, and an empty answer for either
// is an error.
func TestSetVersion_AnAbsentPackagesMarkerReadsEmptyAndTheOtherSetsAreStrict(t *testing.T) {
	defer func(prev func(context.Context, string) (string, error)) { setVersion = prev }(setVersion)
	answers := map[string]string{"-vb": "26.1.11", "-vk": "26.1.11", "-vp": ""}
	var asked []string
	setVersion = func(_ context.Context, flag string) (string, error) {
		asked = append(asked, flag)
		return answers[flag], nil
	}
	ctx := context.Background()

	for which, want := range map[string]string{"base": "26.1.11", "kernel": "26.1.11", "pkgs": ""} {
		got, err := SetVersion(ctx, which)
		if err != nil || got != want {
			t.Errorf("%s: %q, %v; want %q", which, got, err, want)
		}
	}
	if !reflect.DeepEqual(sortedStrings(asked), []string{"-vb", "-vk", "-vp"}) {
		t.Errorf("opnsense-update was run with %v", asked)
	}

	answers["-vp"] = "26.1.6_2"
	if got, err := SetVersion(ctx, "pkgs"); err != nil || got != "26.1.6_2" {
		t.Errorf("a marker that is there: %q, %v", got, err)
	}

	// Base and kernel are strict: nothing, a usage text, or a line with a space is
	// no reading.
	for _, which := range []string{"base", "kernel"} {
		flag := map[string]string{"base": "-vb", "kernel": "-vk"}[which]
		for name, out := range map[string]string{
			"empty": "", "usage": "Usage: opnsense-update [-bdefGgikmnPpRrSsTUuVv] [-A abi]", "with a space": "26.7 4",
		} {
			answers[flag] = out
			if got, err := SetVersion(ctx, which); err == nil {
				t.Errorf("%s, %s: %q was taken for a version", which, name, got)
			}
		}
		answers[flag] = "26.1.11"
	}

	// The packages marker is tolerant of an empty line only: a usage text or a line
	// with a space is still no reading, and a command that fails cannot be read.
	for name, out := range map[string]string{"usage": "Usage: opnsense-update [-bdefGgikmnPpRrSsTUuVv]", "with a space": "26.7 4"} {
		answers["-vp"] = out
		if got, err := SetVersion(ctx, "pkgs"); err == nil {
			t.Errorf("pkgs, %s: %q was taken for a version", name, got)
		}
	}
	setVersion = func(context.Context, string) (string, error) { return "", errors.New("exit status 1") }
	if got, err := SetVersion(ctx, "pkgs"); err == nil {
		t.Errorf("pkgs, a command that failed: %q was taken for a reading", got)
	}
	if _, err := SetVersion(ctx, "firmware"); err == nil {
		t.Error("a set that does not exist was read")
	}
}

func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
