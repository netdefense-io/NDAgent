package firmware

import "context"

// ResetGuardForTest puts the in-process firmware guard back to idle: no slot
// held, no run triggered, no rows watched. Tests in other packages share the
// guard's process-wide state, and one that left a count behind would fail the
// next test that needs the slot for a reason that has nothing to do with it.
// Production code never calls it.
func ResetGuardForTest() {
	guardMu.Lock()
	defer guardMu.Unlock()
	taken, triggered = false, false
	watching, watchingTracks = 0, 0
	wake()
}

// SetVersionCommandForTest replaces how `opnsense-update -v<set>` is run and returns
// the function that puts the real one back: the tests of a series upgrade read the
// state of the box through the real SetVersion over a command that prints what the
// lab's boxes printed. Production code never calls it.
func SetVersionCommandForTest(fn func(ctx context.Context, flag string) (string, error)) (restore func()) {
	prev := setVersion
	setVersion = fn
	return func() { setVersion = prev }
}
