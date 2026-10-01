package firmware

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/host"

	"github.com/netdefense-io/ndagent/internal/opnapi"
	"github.com/netdefense-io/ndagent/internal/pkgmgr"
	"github.com/netdefense-io/ndagent/internal/util"
)

// Probes are the reads Evaluate makes. Each is a function so a caller can
// substitute the device. A nil probe is a source the caller does not have and is
// treated as unreadable.
type Probes struct {
	// Running reads the firmware backend's state. An error means "cannot tell".
	Running func(ctx context.Context) (RunState, error)
	// Locked reports whether the lock the firmware backend's state is read from is
	// held, asking the lock itself rather than the API.
	Locked func(ctx context.Context) (bool, error)
	// Release reads the installed OPNsense release as OPNsense spells it
	// ("26.7.4_1"), from the local version file rather than a firmware check.
	Release func(ctx context.Context) (string, error)
	// BootTime is the box's boot time in unix seconds.
	BootTime func() (int64, error)
	// Installed reads the version of every installed package in one query, and
	// fails rather than answering "nothing installed" when it cannot read.
	Installed func(ctx context.Context) (map[string]string, error)
	// Updating reports whether package tooling (pkg, opnsense-update) is running
	// on the box.
	Updating func(ctx context.Context) (bool, error)
	// Evidence returns a line proving the run failed part-way, or "" when there is
	// none. since is when the run started.
	Evidence func(ctx context.Context, since time.Time) (string, error)
}

// Once returns Probes that read Running, Locked, Release, BootTime, Installed
// and Updating at most once, for a caller that evaluates several rows against the
// same device in one pass. It is not safe for concurrent use.
func (p Probes) Once() Probes {
	q := p
	if p.Running != nil {
		q.Running = memo(p.Running)
	}
	if p.Release != nil {
		q.Release = memo(p.Release)
	}
	if p.Locked != nil {
		q.Locked = memo(p.Locked)
	}
	if p.Installed != nil {
		q.Installed = memo(p.Installed)
	}
	if p.Updating != nil {
		q.Updating = memo(p.Updating)
	}
	if p.BootTime != nil {
		boot := p.BootTime
		var (
			done bool
			val  int64
			err  error
		)
		q.BootTime = func() (int64, error) {
			if !done {
				val, err = boot()
				done = true
			}
			return val, err
		}
	}
	return q
}

func memo[T any](read func(context.Context) (T, error)) func(context.Context) (T, error) {
	var (
		done bool
		val  T
		err  error
	)
	return func(ctx context.Context) (T, error) {
		if !done {
			val, err = read(ctx)
			done = true
		}
		return val, err
	}
}

// API is the part of the OPNsense client the production probes read.
type API interface {
	GetFirmwareRunning(ctx context.Context) (*opnapi.FirmwareRunning, error)
	GetFirmwareUpgradeProgress(ctx context.Context) (*opnapi.FirmwareProgressStatus, error)
	InstalledRelease(ctx context.Context) (opnapi.ProductRelease, error)
}

var (
	errNoAPI   = errors.New("OPNsense API client not configured")
	errNoProbe = errors.New("no way to read whether package tools are running")
)

// NewProbes reads the device through api. A nil api is a device without API
// credentials: the release still comes from local sources, but the firmware
// backend cannot be read, so nothing resolves until the deadline.
func NewProbes(api API) Probes {
	return Probes{
		Running: func(ctx context.Context) (RunState, error) {
			if api == nil {
				return RunUnknown, errNoAPI
			}
			running, err := api.GetFirmwareRunning(ctx)
			if err != nil {
				return RunUnknown, err
			}
			return runStateOf(running), nil
		},
		Release: func(ctx context.Context) (string, error) {
			var (
				release opnapi.ProductRelease
				err     error
			)
			if api != nil {
				release, err = api.InstalledRelease(ctx)
			} else {
				release, err = (*opnapi.Client)(nil).InstalledRelease(ctx)
			}
			if err != nil {
				return "", err
			}
			return release.Raw, nil
		},
		Locked:    firmwareLockHeld,
		BootTime:  bootTime,
		Installed: pkgmgr.InstalledVersions,
		Updating:  packageToolsRunning,
		Evidence:  partialFailureEvidence(api),
	}
}

func runStateOf(r *opnapi.FirmwareRunning) RunState {
	switch {
	case r == nil:
		return RunUnknown
	case r.Status == "ready":
		return RunReady
	case r.Status == "busy":
		return RunBusy
	default:
		return RunUnknown
	}
}

// firmwareLockFile is the file OPNsense's launcher holds an flock on for as long
// as a firmware job runs, and the one /api/core/firmware/running tests.
const firmwareLockFile = "/tmp/pkg_upgrade.progress"

// flock tries to take the lock without waiting; tests replace it. It returns nil
// when the lock was free and an *exec.ExitError with code 1 when it is held.
var flock = func(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "/usr/local/bin/flock", "-n", firmwareLockFile, "/usr/bin/true")
	cmd.Env = util.DeviceExecEnv()
	return cmd.Run()
}

func firmwareLockHeld(ctx context.Context) (bool, error) {
	err := flock(ctx)
	if err == nil {
		return false, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return true, nil
	}
	return false, err
}

// BootTime reads the box's boot time in unix seconds.
func BootTime() (int64, error) { return bootTime() }

// bootTimeFunc is what reads it; tests replace it.
var bootTimeFunc = func() (uint64, error) { return host.BootTime() }

func bootTime() (int64, error) {
	t, err := bootTimeFunc()
	if err != nil {
		return 0, err
	}
	return int64(t), nil
}

// updateToolsPattern matches the command lines of the tools that change
// packages: pkg (also as pkg-static) and the opnsense-update script that drives
// it.
const updateToolsPattern = `(^|[ /])(pkg|pkg-static|opnsense-update)( |$)`

// pgrep runs `pgrep -f pattern`; tests replace it. It returns nil when a process
// matched and an *exec.ExitError with code 1 when none did.
var pgrep = func(ctx context.Context, pattern string) error {
	cmd := exec.CommandContext(ctx, "pgrep", "-f", pattern)
	cmd.Env = util.DeviceExecEnv()
	return cmd.Run()
}

func packageToolsRunning(ctx context.Context) (bool, error) {
	err := pgrep(ctx, updateToolsPattern)
	if err == nil {
		return true, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return false, nil
	}
	return false, err
}

// The lines OPNsense's update and upgrade scripts print when a run failed
// part-way. Both then print ***DONE*** all the same, so a finished log does not
// mean a finished update.
const (
	// PartialFailureMarker is update.sh's line for a package step that failed.
	PartialFailureMarker = "Partial update failure detected"
	// UpgradeAbortedMarker is upgrade.sh's line for a series upgrade that failed
	// after its packages were fetched.
	UpgradeAbortedMarker = "The upgrade was aborted due to an error."
)

// failureMarkers is every line that proves a run failed.
var failureMarkers = []string{PartialFailureMarker, UpgradeAbortedMarker}

var (
	// updateLogPath is where OPNsense keeps the log of the last update, which
	// survives a reboot (the live progress log in /tmp does not).
	updateLogPath = "/var/cache/opnsense-update/.update.log"
	// updateLogMaxBytes bounds how much of it is read.
	updateLogMaxBytes int64 = 4 << 20
)

// failureIn returns the failure marker the text carries, if any.
func failureIn(text string) string {
	for _, marker := range failureMarkers {
		if strings.Contains(text, marker) {
			return marker
		}
	}
	return ""
}

// partialFailureEvidence looks for a failure marker in the last update's log on
// disk, if that log was written after the run was triggered, and in the live
// progress log the API serves. The script writes the log when a run ends, so a
// log older than the trigger is an earlier run's, however recent; without that
// bound a run that succeeds right after one that failed would be failed for it.
// Either is a best-effort read: no answer is no evidence.
func partialFailureEvidence(api API) func(ctx context.Context, since time.Time) (string, error) {
	return func(ctx context.Context, since time.Time) (string, error) {
		if info, err := os.Stat(updateLogPath); err == nil && !info.ModTime().Before(since) {
			if logged, err := readTail(updateLogPath, updateLogMaxBytes); err == nil {
				if marker := failureIn(logged); marker != "" {
					return marker, nil
				}
			}
		}
		if api != nil {
			if progress, err := api.GetFirmwareUpgradeProgress(ctx); err == nil && progress != nil {
				if marker := failureIn(progress.Log); marker != "" {
					return marker, nil
				}
			}
		}
		return "", nil
	}
}

// readTail reads up to max bytes from the end of the file.
func readTail(path string, max int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if info.Size() > max {
		if _, err := f.Seek(-max, io.SeekEnd); err != nil {
			return "", err
		}
	}
	b, err := io.ReadAll(io.LimitReader(f, max))
	return string(b), err
}
