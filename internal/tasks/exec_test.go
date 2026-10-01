package tasks

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// devicePATHLiteral is the PATH on-device children are documented to get,
// written out so the tests do not agree with util.DevicePATH by construction.
const devicePATHLiteral = "/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin"

// rcdPATH is what the agent inherits from rc.d.
const rcdPATH = "/sbin:/bin:/usr/sbin:/usr/bin"

// assertDetachedHelperCmd checks everything a helper the agent outlives must
// have, for the command as built (nothing is started).
func assertDetachedHelperCmd(t *testing.T, cmd *exec.Cmd, wantPath string, wantArgs []string) {
	t.Helper()

	if cmd.Path != wantPath {
		t.Errorf("Path = %q, want %q", cmd.Path, wantPath)
	}
	if !reflect.DeepEqual(cmd.Args, append([]string{wantPath}, wantArgs...)) {
		t.Errorf("Args = %q, want %q", cmd.Args, append([]string{wantPath}, wantArgs...))
	}

	// A nil Env would hand the child the agent's own environment, and with it
	// the stripped rc.d PATH.
	if cmd.Env == nil {
		t.Fatal("Env is nil: the helper would inherit the agent's stripped PATH")
	}
	var paths []string
	for _, kv := range cmd.Env {
		if strings.HasPrefix(kv, "PATH=") {
			paths = append(paths, kv)
		}
	}
	if len(paths) != 1 || paths[0] != "PATH="+devicePATHLiteral {
		t.Errorf("PATH entries = %q, want exactly [PATH=%s]", paths, devicePATHLiteral)
	}

	if cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setsid {
		t.Errorf("SysProcAttr = %+v, want Setsid: pkg's `rc.d ndagent stop` would take the helper down with the agent", cmd.SysProcAttr)
	}
	if cmd.Stdin != nil || cmd.Stdout != nil || cmd.Stderr != nil {
		t.Errorf("stdio must be nil so the helper inherits no agent descriptors; got in=%v out=%v err=%v", cmd.Stdin, cmd.Stdout, cmd.Stderr)
	}
}

func TestNewDetachedHelperCmd(t *testing.T) {
	t.Setenv("PATH", rcdPATH)

	cmd := newDetachedHelperCmd("/opt/x/helper.sh", "os-netdefense-dev", "", "task-1")

	assertDetachedHelperCmd(t, cmd, "/opt/x/helper.sh", []string{"os-netdefense-dev", "", "task-1"})
}

func TestNewDetachedHelperCmd_KeepsTheRestOfTheEnvironment(t *testing.T) {
	t.Setenv("PATH", rcdPATH)
	t.Setenv("NDAGENT_TEST_MARKER", "kept")

	cmd := newDetachedHelperCmd("/opt/x/helper.sh")

	found := false
	for _, kv := range cmd.Env {
		if kv == "NDAGENT_TEST_MARKER=kept" {
			found = true
		}
	}
	if !found {
		t.Errorf("Env dropped an inherited variable: %q", cmd.Env)
	}
}

// The child, not just the struct: a script started the way the agent starts
// the helper, under the agent's rc.d PATH, must see the device PATH.
func TestNewDetachedHelperCmd_ChildSeesDevicePATH(t *testing.T) {
	t.Setenv("PATH", rcdPATH)

	dir := t.TempDir()
	out := filepath.Join(dir, "path.out")
	script := filepath.Join(dir, "helper.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s' \"$PATH\" > \"$1\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := newDetachedHelperCmd(script, out).Run(); err != nil {
		t.Fatalf("run helper: %v", err)
	}

	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != devicePATHLiteral {
		t.Errorf("helper saw PATH=%q, want %q", got, devicePATHLiteral)
	}
}
