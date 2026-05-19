package pkgmgr

import "context"

// Test-only swap helpers. They're exported so handler tests in sibling
// packages (e.g. internal/tasks) can substitute the pkg(8) call paths
// without shelling out. Keep them out of the public API mental model —
// production code never calls these; their existence is purely for tests.

// SetInstallFunc replaces the Install backend and returns the previous one
// so the caller can restore it on cleanup.
func SetInstallFunc(f func(context.Context, string) MutateOutcome) func(context.Context, string) MutateOutcome {
	prev := installFunc
	installFunc = f
	return prev
}

// SetRemoveFunc — same pattern for Delete.
func SetRemoveFunc(f func(context.Context, string) MutateOutcome) func(context.Context, string) MutateOutcome {
	prev := removeFunc
	removeFunc = f
	return prev
}

// SetUpdateFunc — same pattern for Update.
func SetUpdateFunc(f func(context.Context) error) func(context.Context) error {
	prev := updateFunc
	updateFunc = f
	return prev
}

// SetIsInstalledFunc — same pattern for IsInstalled.
func SetIsInstalledFunc(f func(context.Context, string) (bool, error)) func(context.Context, string) (bool, error) {
	prev := isInstalledFunc
	isInstalledFunc = f
	return prev
}

// SetQueryFunc — same pattern for Query (read-only side).
func SetQueryFunc(f func(context.Context, []string) ([]Status, error)) func(context.Context, []string) ([]Status, error) {
	prev := queryFunc
	queryFunc = f
	return prev
}
