// Package version provides version information for the NDAgent application.
package version

// These variables are set at build time via ldflags.
var (
	// Version is the semantic version of the application.
	Version = "dev"

	// BuildTime is the UTC timestamp of when the binary was built.
	BuildTime = "unknown"

	// GitCommit is the short git commit hash of the build.
	GitCommit = "unknown"
)

// Info returns a formatted version string with all version information.
func Info() string {
	return Version
}

// Full returns complete version information including build time and commit.
func Full() string {
	return "ndagent version " + Version + " (built " + BuildTime + ", commit " + GitCommit + ")"
}
