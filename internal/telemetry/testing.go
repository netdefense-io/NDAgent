package telemetry

import "time"

// Test-only helpers, exported so that tests in sibling packages (internal/core)
// can drive the collector's schedule without sitting through a minute-long stagger
// and a three-second poll. Production code never calls them. Each returns a restore
// func.

// SetScheduleForTest makes the collector draw its random durations (the first
// check's stagger, the jitter) with random, and wait for a check as the arguments
// say. gateRecheck is how soon a check held by the start order looks at the gate
// again.
func SetScheduleForTest(h *HeavyCollector, now func() time.Time, random func(n time.Duration) time.Duration,
	checkPoll, checkTimeout, gateRecheck time.Duration) (restore func()) {
	prevPoll, prevTimeout, prevRecheck := firmwareCheckPoll, firmwareCheckTimeout, checkGateRecheck
	prevNow, prevRandom := h.now, h.random
	if now != nil {
		h.now = now
	}
	if random != nil {
		h.random = random
	}
	firmwareCheckPoll, firmwareCheckTimeout, checkGateRecheck = checkPoll, checkTimeout, gateRecheck
	return func() {
		firmwareCheckPoll, firmwareCheckTimeout, checkGateRecheck = prevPoll, prevTimeout, prevRecheck
		h.now, h.random = prevNow, prevRandom
	}
}

// SetInstalledVersionForTest and SetBootTimeForTest replace how the collector reads
// the installed release and the boot time (the real ones read the box's files).
func SetInstalledVersionForTest(h *HeavyCollector, installed func() string) {
	h.installedVersion = installed
}
func SetBootTimeForTest(h *HeavyCollector, boot func() (int64, error)) { h.bootTime = boot }
