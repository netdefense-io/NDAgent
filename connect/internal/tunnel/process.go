package tunnel

import (
	"os"
	"strings"

	"tailscale.com/envknob"
)

// envPrefixes are the names under which the tunnel library reads settings
// from the environment: debugging switches that change which relay it talks
// to, what it logs and what it trusts.
var envPrefixes = []string{"TS_", "TAILSCALE_", "TAILCAT_"}

// ScrubEnvironment empties every such setting, so the companion behaves the
// same whatever environment it was started in. The agent starts it with a
// minimal one; this covers a companion started by hand. Call it first thing
// in main: the library reads some settings when it starts.
func ScrubEnvironment() {
	scrubEnvironment(os.Environ(), envknob.Setenv)
}

func scrubEnvironment(environ []string, set func(name, value string)) {
	for _, entry := range environ {
		name, value, _ := strings.Cut(entry, "=")
		if value != "" && (name == "IN_TS_TEST" || hasAnyPrefix(name, envPrefixes)) {
			set(name, "")
		}
	}
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
