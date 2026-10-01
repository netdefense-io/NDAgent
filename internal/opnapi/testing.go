package opnapi

import "os/exec"

// Test-only helpers, exported so tests in sibling packages (internal/tasks)
// can keep InstalledRelease off the real device. Production code never calls
// them. Each returns a restore func.

// SetVersionFileForTest points the local release reader at path.
func SetVersionFileForTest(path string) (restore func()) {
	prev := versionFilePath
	versionFilePath = path
	return func() { versionFilePath = prev }
}

// SetCommandOutputForTest replaces how `opnsense-version` is run. f receives
// the prepared command and returns what its stdout would have been.
func SetCommandOutputForTest(f func(*exec.Cmd) ([]byte, error)) (restore func()) {
	prev := commandOutput
	commandOutput = f
	return func() { commandOutput = prev }
}
