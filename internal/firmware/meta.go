package firmware

import (
	"sort"
	"strings"
	"time"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// MaxPlannedPackages caps how many packages of the plan are stored per task. A
// pending update is normally tens of packages and can be a few hundred; the cap
// keeps the row small, and a plan that was cut is still verified for the
// packages it holds.
const MaxPlannedPackages = 200

// Package is one package of the plan an update started from: its name and the
// version the update was going to install.
type Package struct {
	Name    string `json:"name"`
	Version string `json:"new_version,omitempty"`
}

// Meta is what the handler records, before it triggers an update, about the run
// it is about to start. The row's outcome is decided later, possibly by another
// process (the agent restarts mid-update, and the box reboots), and the
// question then is what changed since this point, so this is everything that
// answer needs.
type Meta struct {
	Mode   string `json:"mode"`   // "minor" or "major"
	Reboot bool   `json:"reboot"` // the payload's reboot flag
	// FromVersion is the installed release when the update was triggered, read
	// from the local version file (never from the cached result of a check).
	FromVersion string `json:"from_version"`
	// Packages is the plan, capped at MaxPlannedPackages; PackagesTotal is the
	// real count when it was cut.
	Packages      []Package `json:"packages,omitempty"`
	PackagesTotal int       `json:"packages_total,omitempty"`
	// NeedsReboot is /status's needs_reboot flag, kept for the record.
	NeedsReboot bool `json:"needs_reboot"`
	// BootTime is the boot time (unix seconds) when the update was triggered; a
	// later one means the box rebooted since.
	BootTime int64 `json:"boot_time,omitempty"`
	// StartedAt is when the handler took the task up, ExpiresAt when NDManager
	// gives up on it.
	StartedAt int64 `json:"started_at"`
	ExpiresAt int64 `json:"expires_at"`
	// TriggeredAt is when the handler asked OPNsense to apply the update (or ran
	// it itself), 0 for a task that has not got that far. A row that is left
	// without it never touched the device.
	TriggeredAt int64 `json:"triggered_at,omitempty"`
	// RebootSeen is set once the handler has seen OPNsense announce the reboot.
	RebootSeen bool `json:"reboot_seen,omitempty"`
}

// Triggered reports whether the update was requested.
func (m Meta) Triggered() bool { return m.TriggeredAt > 0 }

// TTL is how long NDManager keeps a task of the given mode open.
func TTL(mode string) time.Duration {
	if mode == "major" {
		return MajorTTL
	}
	return MinorTTL
}

// isBaseOrKernel reports whether name is one of the two pseudo-packages OPNsense
// lists for the base system and the kernel, which are installed by a reboot and
// are not in the package database.
func isBaseOrKernel(name string) bool { return name == "base" || name == "kernel" }

// PlannedPackages is what an update was going to install: the upgrades and the
// new packages they pull in.
func PlannedPackages(st *opnapi.FirmwareUpgradeStatus) []Package {
	if st == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(st.UpgradePackages)+len(st.NewPackages))
	var plan []Package
	for _, list := range [][]opnapi.FirmwarePackageEntry{st.UpgradePackages, st.NewPackages} {
		for _, e := range list {
			if e.Name == "" {
				continue
			}
			if _, dup := seen[e.Name]; dup {
				continue
			}
			seen[e.Name] = struct{}{}
			plan = append(plan, Package{Name: e.Name, Version: e.VersionString()})
		}
	}
	return plan
}

// CoreVersion is the version the plan installs for OPNsense's own package, or ""
// when the plan does not touch it. It is the release the update reaches, and it
// is read from the plan because the status's product_latest is derived from the
// installed changelog and does not move with the update.
func CoreVersion(plan []Package) string {
	for _, p := range plan {
		if opnapi.IsCorePackage(p.Name) {
			return p.Version
		}
	}
	return ""
}

// PackagesApplied is how many packages of the plan an update installs, not
// counting the base system and kernel, which a reboot installs. New packages
// count: an update installs them too.
func PackagesApplied(plan []Package) int {
	n := 0
	for _, p := range plan {
		if !isBaseOrKernel(p.Name) {
			n++
		}
	}
	return n
}

// HasBaseOrKernel reports whether the plan includes the base system or kernel.
func HasBaseOrKernel(plan []Package) bool {
	for _, p := range plan {
		if isBaseOrKernel(p.Name) {
			return true
		}
	}
	return false
}

// NewMarker records a task the handler has taken up and that has triggered
// nothing yet. If the agent stops before the run is recorded in full (the task
// is waiting for its turn), this is what tells the reconciler the row never
// touched the device, as opposed to a row an older agent wrote that recorded
// nothing at all.
func NewMarker(mode string, reboot bool, started, expires time.Time) Meta {
	return Meta{Mode: mode, Reboot: reboot, StartedAt: started.Unix(), ExpiresAt: expires.Unix()}
}

// NewMeta records an update about to be triggered. bootTime is 0 when it could
// not be read.
func NewMeta(mode string, reboot bool, fromVersion string, st *opnapi.FirmwareUpgradeStatus, bootTime int64, started, expires time.Time) Meta {
	plan := PlannedPackages(st)
	total := len(plan)
	if total > MaxPlannedPackages {
		// Keep what matters most if the plan has to be cut: the release itself,
		// the base system and kernel, and the agent's own package, whose upgrade
		// restarts the agent under the update.
		sort.SliceStable(plan, func(i, j int) bool { return keepFirst(plan[i].Name) && !keepFirst(plan[j].Name) })
		plan = plan[:MaxPlannedPackages]
	} else {
		total = 0
	}
	m := Meta{
		Mode:          mode,
		Reboot:        reboot,
		FromVersion:   fromVersion,
		Packages:      plan,
		PackagesTotal: total,
		BootTime:      bootTime,
		StartedAt:     started.Unix(),
		ExpiresAt:     expires.Unix(),
	}
	if st != nil {
		m.NeedsReboot = st.NeedsReboot
	}
	return m
}

func keepFirst(name string) bool {
	return opnapi.IsCorePackage(name) || isBaseOrKernel(name) || strings.HasPrefix(name, "os-netdefense")
}

// Expiry is when NDManager gives up on the task.
func (m Meta) Expiry() time.Time {
	if m.ExpiresAt > 0 {
		return time.Unix(m.ExpiresAt, 0)
	}
	return time.Unix(m.StartedAt, 0).Add(TTL(m.Mode))
}

// RebootExpected reports whether the run is going to restart the box: a major
// upgrade always does, a run that includes the base system or kernel does, and so
// does one OPNsense has announced. A run that does not reboot by design
// (reboot=false) never expects one, whatever its plan holds: it defers those.
func (m Meta) RebootExpected() bool {
	return m.Reboot && (m.Mode == "major" || m.RebootSeen || HasBaseOrKernel(m.Packages))
}

// ExpectedReboots is how many restarts the run may cause, for the result.
func (m Meta) ExpectedReboots() int {
	switch {
	case !m.Reboot:
		return 0
	case m.Mode == "major":
		return 2
	default:
		return 1
	}
}

// checkable is the part of the plan the package database can confirm: every
// package but the base system and kernel, whose installation is a reboot.
func (m Meta) checkable() []Package {
	var out []Package
	for _, p := range m.Packages {
		if !isBaseOrKernel(p.Name) {
			out = append(out, p)
		}
	}
	return out
}
