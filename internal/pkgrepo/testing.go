package pkgrepo

import "path/filepath"

// Test-only helper, mirroring internal/pkgmgr/testing.go: retarget the device
// paths at a temp root so tests exercise the real write/prune logic without
// touching a live /usr/local/etc/pkg. Production code never calls this.
//
// Returns a restore func rather than mutating globally forever, so a test that
// forgets cleanup cannot leak into the next one.
func SetRootForTest(root string) func() {
	prevRepos, prevFP, prevKeys := reposDir, fingerprintsIn, keysDir
	reposDir = filepath.Join(root, "usr/local/etc/pkg/repos")
	fingerprintsIn = filepath.Join(root, "usr/local/etc/pkg/fingerprints")
	keysDir = filepath.Join(root, "usr/local/etc/pkg/keys")
	return func() {
		reposDir, fingerprintsIn, keysDir = prevRepos, prevFP, prevKeys
	}
}

// ReposDirForTest exposes the (possibly retargeted) repos directory so tests
// can plant a foreign config file the way an administrator would.
func ReposDirForTest() string { return reposDir }
