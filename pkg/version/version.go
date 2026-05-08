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

	// PackageName is the FreeBSD pkg name this build was packaged under
	// (os-netdefense / os-netdefense-qa / os-netdefense-dev). Used by the
	// PLUGIN_INSTALL handler to invoke `pkg install` against the correct
	// channel; the agent never accepts a channel override from the wire.
	PackageName = "unknown"
)

// Info returns a formatted version string with all version information.
func Info() string {
	return Version
}

// Full returns complete version information including build time and commit.
func Full() string {
	return "ndagent version " + Version + " (built " + BuildTime + ", commit " + GitCommit + ")"
}
