//go:build freebsd

package run

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const denyTracingChildEnv = "NDAGENT_CONNECT_TEST_DENY_TRACING"

// In a child of its own: turning tracing off is for the life of the process,
// and the test binary would take every later test with it.
func TestDenyTracingTurnsTracingOff(t *testing.T) {
	if os.Getenv(denyTracingChildEnv) == "1" {
		before := int32(99)
		if err := procctlSelf(procTraceStatus, &before); err != nil {
			t.Fatalf("status before: %v", err)
		}
		if before != 0 {
			t.Fatalf("status before = %d, want 0 (tracing on, no tracer)", before)
		}
		if err := DenyTracing(); err != nil {
			t.Fatalf("DenyTracing: %v", err)
		}
		after := int32(99)
		if err := procctlSelf(procTraceStatus, &after); err != nil || after != traceStatusDisabled {
			t.Fatalf("status after = %d (%v), want %d", after, err, traceStatusDisabled)
		}
		// A tracer of the same user is turned away. Root's is not (the
		// setting is against other processes of an unprivileged user), and a
		// process root traces cannot ask again, so as root the probe is left
		// out. ktrace gets a file of this test's own: it removes the file it
		// is given before it writes it, and as root that removes a device
		// node too.
		if os.Geteuid() != 0 {
			trace := filepath.Join(t.TempDir(), "ktrace.out")
			out, err := exec.Command("/usr/bin/ktrace", "-f", trace, "-p", strconv.Itoa(os.Getpid())).CombinedOutput()
			if err == nil {
				_ = exec.Command("/usr/bin/ktrace", "-c", "-f", trace, "-p", strconv.Itoa(os.Getpid())).Run()
				t.Fatalf("ktrace by the same user attached to a process that turned tracing off: %s", out)
			}
			if !strings.Contains(string(out), "Operation not permitted") {
				t.Fatalf("ktrace failed for another reason than the setting: %s", out)
			}
		}
		// Asked twice, it still holds.
		if err := DenyTracing(); err != nil {
			t.Fatalf("DenyTracing a second time: %v", err)
		}
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run", "^TestDenyTracingTurnsTracingOff$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), denyTracingChildEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "--- PASS: TestDenyTracingTurnsTracingOff") {
		t.Fatalf("the child failed: %v\n%s", err, out)
	}
}
