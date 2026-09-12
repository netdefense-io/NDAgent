package main

// main_test.go — argument handling.
//
// The bug this guards: every positional argument used to start the daemon.
// `ndagent version` — the natural guess for anyone used to subcommand CLIs —
// booted a second agent in the foreground, which then held the device's
// WebSocket slot. A freshly installed agent failed auth with close 1008
// "Device already connected" while `pkg info`, `ndagent --version`,
// `service ndagent status` and the control plane's device record all looked
// correct. Two such strays nearly invalidated a lab E2E run.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/netdefense-io/ndagent/pkg/version"
)

// resetFlags restores flag state between runs.
//
// rootCmd is a package-level value, and pflag values PERSIST across
// Execute calls. Without resetting them, a test that runs `--version`
// leaves cobra's version flag set to true, and every later Execute prints
// the version and returns nil before argument validation ever runs — which
// looks exactly like "the guard does not work" while the real binary
// rejects the same input. Reset before each run so the tests are
// order-independent and measure the command, not leftover state.
func resetFlags(t *testing.T) {
	t.Helper()

	// Ensure cobra's implicit --version/--help flags exist before resetting.
	rootCmd.InitDefaultVersionFlag()
	rootCmd.InitDefaultHelpFlag()

	reset := func(fs *pflag.FlagSet) {
		fs.VisitAll(func(f *pflag.Flag) {
			if err := f.Value.Set(f.DefValue); err != nil {
				t.Fatalf("resetting flag --%s: %v", f.Name, err)
			}
			f.Changed = false
		})
	}
	reset(rootCmd.Flags())
	reset(rootCmd.PersistentFlags())
	for _, c := range rootCmd.Commands() {
		reset(c.Flags())
	}
}

// execute runs the real root command with the given args, capturing output
// and returning it with any error. It never reaches `run` in these tests:
// every case either resolves to the version subcommand or is rejected during
// argument validation, which is exactly the property under test.
func execute(t *testing.T, args ...string) (string, error) {
	t.Helper()

	resetFlags(t)

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetArgs(args)
	t.Cleanup(func() {
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		rootCmd.SetArgs(nil)
	})

	err := rootCmd.Execute()
	return out.String(), err
}

// TestPositionalVersionPrintsAndExits is the footgun itself: `ndagent
// version` must print the version, not start the daemon.
func TestPositionalVersionPrintsAndExits(t *testing.T) {
	out, err := execute(t, "version")
	if err != nil {
		t.Fatalf("`ndagent version` returned an error: %v", err)
	}
	if !strings.Contains(out, version.Full()) {
		t.Errorf("output %q does not contain the version string %q", out, version.Full())
	}
}

// TestVersionFormsAreIdentical pins that the positional and flag forms print
// the same thing. They diverged before: the version template prepended
// {{.Name}} to a string that already began with the binary name, so
// `--version` printed "ndagent ndagent version ...". A version surface that
// prints something subtly odd is one an operator stops trusting, and during
// the incident these were among the checks that "looked correct".
func TestVersionFormsAreIdentical(t *testing.T) {
	positional, err := execute(t, "version")
	if err != nil {
		t.Fatalf("version subcommand: %v", err)
	}
	flag, err := execute(t, "--version")
	if err != nil {
		t.Fatalf("--version: %v", err)
	}

	if strings.TrimSpace(positional) != strings.TrimSpace(flag) {
		t.Errorf("`version` printed %q but `--version` printed %q; the two must agree",
			strings.TrimSpace(positional), strings.TrimSpace(flag))
	}
	if strings.Contains(flag, "ndagent ndagent") {
		t.Errorf("--version output %q repeats the binary name", strings.TrimSpace(flag))
	}
}

// TestUnknownPositionalIsRejected covers the general case: anything that is
// not a known subcommand must be a usage error, never a daemon start.
func TestUnknownPositionalIsRejected(t *testing.T) {
	for _, arg := range []string{"bogus", "status", "start", "daemon"} {
		t.Run(arg, func(t *testing.T) {
			out, err := execute(t, arg)
			if err == nil {
				t.Fatalf("`ndagent %s` was accepted; an unknown positional must be a usage error, not a daemon start", arg)
			}
			if !strings.Contains(out, "Usage:") {
				t.Errorf("output %q should include usage", out)
			}
		})
	}
}

// TestVersionSubcommandRejectsExtraArgs keeps the subcommand from becoming a
// new way in: `ndagent version --foreground extra` must not start anything.
func TestVersionSubcommandRejectsExtraArgs(t *testing.T) {
	if _, err := execute(t, "version", "extra"); err == nil {
		t.Error("`ndagent version extra` was accepted; it must be a usage error")
	}
}

// TestRootRejectsArgsButKeepsFlags pins that the guard is on POSITIONALS
// only. The rc.d script runs the daemon as `ndagent --config <path>` (the
// `-f -p` in command_args belong to daemon(8), not to us), so flags must
// keep working or the service will not start.
func TestRootRejectsArgsButKeepsFlags(t *testing.T) {
	if rootCmd.Args == nil {
		t.Fatal("rootCmd.Args is nil: any positional would start the daemon again")
	}

	// NoArgs accepts an empty positional list — the service's invocation.
	if err := rootCmd.Args(rootCmd, []string{}); err != nil {
		t.Errorf("no positionals must be accepted (this is how the service starts): %v", err)
	}
	if err := rootCmd.Args(rootCmd, []string{"version"}); err == nil {
		t.Error("rootCmd.Args accepted a positional; it must reject them (subcommands are routed before Args runs)")
	}

	// The flags the rc.d script and the Makefile rely on must still exist.
	for _, name := range []string{"config", "foreground"} {
		if rootCmd.Flags().Lookup(name) == nil {
			t.Errorf("flag --%s is missing; the service invocation depends on it", name)
		}
	}
}

// TestVersionSubcommandIsRegistered guards the wiring rather than the
// behaviour, so removing AddCommand fails here even if cobra would then
// silently treat "version" as an unknown positional.
func TestVersionSubcommandIsRegistered(t *testing.T) {
	var found bool
	for _, c := range rootCmd.Commands() {
		if c.Name() == "version" {
			found = true
			if _, ok := interface{}(c.Args).(cobra.PositionalArgs); !ok && c.Args == nil {
				t.Error("version subcommand has no Args validator")
			}
		}
	}
	if !found {
		t.Error("version subcommand is not registered on rootCmd")
	}
}
