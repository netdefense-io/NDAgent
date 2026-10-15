package track

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/netdefense-io/ndagent/internal/firmware"
	"github.com/netdefense-io/ndagent/internal/opnapi"
	"github.com/netdefense-io/ndagent/internal/util"
)

// Device is the box as the engine sees it. The production one is SystemDevice;
// tests stand a simulated OPNsense in its place.
type Device interface {
	// Settings reads the firmware settings, the subscription redacted.
	Settings(ctx context.Context) (opnapi.FirmwareSettings, error)
	// SetFlavour writes the firmware flavour and no other setting.
	SetFlavour(ctx context.Context, flavour string) error
	// Installed is the installed release as the local version file has it
	// (26.7.3_11), never the cached result of a check.
	Installed(ctx context.Context) (string, error)

	// RepoBase is the device's own mirror, read from its generated repository file.
	RepoBase(ctx context.Context) (RepoBase, error)
	// RepoPath is the path that file's url holds after the ABI, which the flavour
	// replaces; "" with an error when the file cannot be read.
	RepoPath(ctx context.Context) (string, error)
	// Probe asks the mirror whether a release directory is there.
	Probe(ctx context.Context, url string) ProbeResult

	// Running reads the firmware backend: ready, busy or unknown.
	Running(ctx context.Context) (firmware.RunState, error)
	TriggerCheck(ctx context.Context) error
	Status(ctx context.Context) (*opnapi.FirmwareUpgradeStatus, error)

	// TriggerUpdate asks OPNsense to run its update (packages, base and kernel,
	// then a reboot when they need one). It answers the status OPNsense gave.
	TriggerUpdate(ctx context.Context) (string, error)
	Progress(ctx context.Context) (*opnapi.FirmwareProgressStatus, error)
	// ApplyPackagesOnly runs `opnsense-update -pt opnsense`: the userland
	// packages, with base and kernel left for a later update.
	ApplyPackagesOnly(ctx context.Context) (ExecResult, error)

	// The rest is what a series upgrade asks of the box (device_major.go).

	// HAMember reports whether the box is a member of an HA pair.
	HAMember(ctx context.Context) (bool, error)
	// RepoAudit lists the repositories and packages from outside OPNsense and
	// NetDefense.
	RepoAudit(ctx context.Context) (RepoAudit, error)
	// DiskFree reads the free space; on ZFS every figure follows a `zpool sync`.
	DiskFree(ctx context.Context) (Disk, error)
	// ClearStaleWork empties the upgrade's cache before the space is measured.
	ClearStaleWork(ctx context.Context) error
	// AgentRepoProbe checks the NetDefense repository for the ABI the box moves to.
	AgentRepoProbe(ctx context.Context, abi string) (AgentRepo, error)
	// RefreshCatalog runs `pkg update -f -r OPNsense`: the catalog of OPNsense's own
	// repository alone, which is the first update a box that has just landed on a new
	// series needs before its local catalog can be read.
	RefreshCatalog(ctx context.Context) error
	// TriggerUpgrade asks OPNsense for the series upgrade (POST /upgrade). It
	// answers the status OPNsense gave.
	TriggerUpgrade(ctx context.Context) (string, error)
	// StageState reads what the upgrade has left on the box. It only reads.
	StageState(ctx context.Context) (StageState, error)
	// ClearUpgradeCache is the cleanup of an aborted upgrade, after every log was
	// read.
	ClearUpgradeCache(ctx context.Context) error
	// SnapshotSupported, CreateBootEnvironment and FindBootEnvironment make and find
	// the boot environment a series upgrade can be preceded by.
	SnapshotSupported(ctx context.Context) (bool, error)
	CreateBootEnvironment(ctx context.Context, name, note string) error
	FindBootEnvironment(ctx context.Context, name string) (BootEnvironment, bool, error)

	// Probes are the reads firmware.Evaluate makes to decide how an update ended.
	Probes() firmware.Probes
}

// ExecResult is the end of a command the agent ran itself.
type ExecResult struct {
	ExitCode int
	// Tail is the last lines of its output.
	Tail string
}

// SystemDevice is the real box: OPNsense's REST API for the firmware backend and
// its settings, the local files and commands for the rest.
type SystemDevice struct {
	client *opnapi.Client
	probes firmware.Probes
}

// NewSystemDevice reads and drives the box through client.
func NewSystemDevice(client *opnapi.Client) *SystemDevice {
	return &SystemDevice{client: client, probes: firmware.NewProbes(client)}
}

func (d *SystemDevice) Settings(ctx context.Context) (opnapi.FirmwareSettings, error) {
	s, err := d.client.GetFirmwareSettings(ctx)
	if err != nil {
		return opnapi.FirmwareSettings{}, err
	}
	return *s, nil
}

func (d *SystemDevice) SetFlavour(ctx context.Context, flavour string) error {
	return d.client.SetFirmwareFlavour(ctx, flavour)
}

func (d *SystemDevice) Installed(ctx context.Context) (string, error) {
	release, err := d.client.InstalledRelease(ctx)
	if err != nil {
		return "", err
	}
	if release.Raw == "" {
		return "", errors.New("no product version")
	}
	return release.Raw, nil
}

func (d *SystemDevice) Running(ctx context.Context) (firmware.RunState, error) {
	return d.probes.Running(ctx)
}

func (d *SystemDevice) TriggerCheck(ctx context.Context) error {
	return d.client.TriggerFirmwareCheck(ctx)
}

func (d *SystemDevice) Status(ctx context.Context) (*opnapi.FirmwareUpgradeStatus, error) {
	return d.client.GetFirmwareUpgradeStatus(ctx)
}

func (d *SystemDevice) TriggerUpdate(ctx context.Context) (string, error) {
	resp, err := d.client.TriggerFirmwareUpdate(ctx)
	if err != nil {
		return "", err
	}
	return resp.Status, nil
}

func (d *SystemDevice) Progress(ctx context.Context) (*opnapi.FirmwareProgressStatus, error) {
	return d.client.GetFirmwareUpgradeProgress(ctx)
}

func (d *SystemDevice) Probes() firmware.Probes { return d.probes }

// Commands the device runs, as variables so tests do not run them.
var (
	// repoConfPath is the generated repository file.
	repoConfPath = RepoConfPath

	// pkgABIFunc reads pkg's ABI (FreeBSD:15:amd64).
	pkgABIFunc = func(ctx context.Context) (string, error) {
		cmd := exec.CommandContext(ctx, "/usr/sbin/pkg", "config", "ABI")
		cmd.Env = util.DeviceExecEnv()
		out, err := cmd.Output()
		return strings.TrimSpace(string(out)), err
	}

	// fetchFunc runs fetch(1) the way OPNsense's own firmware scripts do (it is
	// what pkg uses: the same trust store and proxy handling). With -s it asks
	// for the size only, so nothing is downloaded.
	fetchFunc = func(ctx context.Context, rawURL string) (exitCode int, output string, err error) {
		cmd := exec.CommandContext(ctx, "/usr/bin/fetch", "-s", "-T", "20", rawURL)
		cmd.Env = util.DeviceExecEnv()
		cmd.WaitDelay = 2 * time.Second
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out
		err = cmd.Run()
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode(), out.String(), nil
		}
		return 0, out.String(), err
	}

	// packagesOnlyFunc runs the update of the userland packages. The core
	// package is `opnsense`: a device with a type of its own (business, devel)
	// is never enrolled, so there is no suffix to read.
	packagesOnlyFunc = func(ctx context.Context) (ExecResult, error) {
		cmd := exec.CommandContext(ctx, "/usr/local/sbin/opnsense-update", "-pt", "opnsense")
		cmd.Env = util.DeviceExecEnv()
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out
		err := cmd.Run()
		var exitErr *exec.ExitError
		switch {
		case err == nil:
			return ExecResult{Tail: tailLines(out.String(), 50)}, nil
		case errors.As(err, &exitErr):
			return ExecResult{ExitCode: exitErr.ExitCode(), Tail: tailLines(out.String(), 50)}, nil
		default:
			return ExecResult{}, err
		}
	}
)

func tailLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// fetchSaysNotFound reads fetch(1)'s message for an HTTP 404, "fetch: <url>:
// Not Found", and not the resolver's ("Unknown host", "No address record",
// "Host not found"). Only the message after the URL is looked at: the URL may
// hold any word, a mirror's host or path named "host" or "address" included.
func fetchSaysNotFound(output string) bool {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if i := strings.LastIndex(line, ": "); i >= 0 && strings.EqualFold(strings.TrimSpace(line[i+2:]), "not found") {
			return true
		}
	}
	return false
}

func (d *SystemDevice) ApplyPackagesOnly(ctx context.Context) (ExecResult, error) {
	return packagesOnlyFunc(ctx)
}

// RepoBase reads the mirror the repository file points at and pkg's ABI.
func (d *SystemDevice) RepoBase(ctx context.Context) (RepoBase, error) {
	conf, err := os.ReadFile(repoConfPath)
	if err != nil {
		return RepoBase{}, fmt.Errorf("read the repository file: %w", err)
	}
	abi, err := pkgABIFunc(ctx)
	if err != nil {
		return RepoBase{}, fmt.Errorf("read pkg's ABI: %w", err)
	}
	return ParseRepoConf(string(conf), abi)
}

// RepoPath reads the path the generated repository file points at.
func (d *SystemDevice) RepoPath(ctx context.Context) (string, error) {
	conf, err := os.ReadFile(repoConfPath)
	if err != nil {
		return "", fmt.Errorf("read the repository file: %w", err)
	}
	return RepoPath(string(conf))
}

// Probe asks the mirror for url with fetch(1). 404 is "missing"; anything else
// that is not a clean answer is "unreachable", never "missing": a directory is
// only reported gone when the mirror said so.
func (d *SystemDevice) Probe(ctx context.Context, rawURL string) ProbeResult {
	ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	code, output, err := fetchFunc(ctx, rawURL)
	switch {
	case err != nil:
		return ProbeUnreachable
	case code == 0:
		return ProbeFound
	case fetchSaysNotFound(output):
		return ProbeMissing
	default:
		return ProbeUnreachable
	}
}
