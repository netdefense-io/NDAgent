// Package firmware decides, from the device's own state, how a FIRMWARE_UPGRADE
// ended.
//
// The update itself is not the agent's: OPNsense runs it as a detached process
// tree (launcher.sh under flock, then update.sh) that the agent only polls, and
// that outlives the agent whenever a package in the run replaces the agent's
// own or the box reboots. So "the agent came back" says nothing about the
// update, and the agent's own progress polling can end for reasons unrelated to
// it. The one signal that survives both is /api/core/firmware/running, which
// reads "busy" for exactly as long as that process tree holds its lock, up to
// the reboot. Evaluate is the single place that turns that signal, the
// installed release and the local package database into an outcome; the handler
// (in-session) and the reconciler (after the handler is gone) both call it.
package firmware

import "time"

// Per-mode task lifetimes, mirroring NDManager's run_service.py. NDManager
// fails a task at its expiry regardless of what the agent does, so these bound
// how long the agent keeps trying to give a truthful outcome.
const (
	MinorTTL = 15 * time.Minute
	MajorTTL = 60 * time.Minute
)

// Grace is how long past its expiry a row is still evaluated before it is
// failed for being unresolvable. A row is failed only when its expiry plus Grace
// has passed and this process has been up for at least Grace as well: an update
// that outlives its task's lifetime usually ends in a reboot, and the first
// sweeps of the process that comes back must get a real chance to read the
// outcome before the bound can fail the row on the spot.
const Grace = 5 * time.Minute

// processStart is set when the package is first loaded, which for the agent is
// process start.
var processStart = time.Now()

// Uptime is how long this agent process has been running. It is measured on the
// monotonic clock: a box that steps its wall clock after booting (it may boot
// with a wrong one) does not change it, where a start time compared with the
// wall clock would.
func Uptime() time.Duration { return time.Since(processStart) }

// Deadline is when a row's outcome has to be settled: its expiry plus Grace.
func Deadline(expires time.Time) time.Time { return expires.Add(Grace) }

// RunState is what /api/core/firmware/running says about OPNsense's firmware
// backend.
type RunState int

const (
	// RunUnknown: the API did not answer, or answered with nothing usable.
	// Never treated as ready.
	RunUnknown RunState = iota
	// RunReady: no firmware job holds OPNsense's lock.
	RunReady
	// RunBusy: a firmware job (an update, or just a check) holds the lock.
	RunBusy
)
