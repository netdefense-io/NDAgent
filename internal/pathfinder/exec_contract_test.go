package pathfinder

// exec_contract_test.go — tests for wire-contract items that had no coverage.
//
// These assert against the CONTRACT documented in exec.go's package comment,
// not against whatever the code happens to do today. Where the two disagree
// these tests must fail: that disagreement is exactly what the exec-timeout
// bug was (the comment claimed a process-group kill the code did not perform,
// and nothing asserted it either way), and what item 9's HOME=/root claim was
// (true of the interactive shell path, never of the exec path).
//
// Every test here must pass both on a CI runner and on the device, WITHOUT
// depending on being root — the /root case is precisely where an environment
// assumption hides.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/util"
)

// contractDevicePATH is the PATH string wire-contract item 9 documents,
// written out literally rather than referenced from util.DevicePATH. Taking
// it from the constant would make the test agree with the code by
// construction and assert nothing; spelling it out means a change to the
// constant fails here until the contract comment is updated to match.
const contractDevicePATH = "/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin"

// ---------------------------------------------------------------------------
// Item 9: privilege / environment
// ---------------------------------------------------------------------------

// TestContract_DevicePATHConstantMatchesContract pins the constant against the
// documented string. If someone edits DevicePATH, this fails and forces the
// contract comment (which NDCLI reads) to be updated in the same change.
func TestContract_DevicePATHConstantMatchesContract(t *testing.T) {
	if util.DevicePATH != contractDevicePATH {
		t.Errorf("util.DevicePATH = %q, but wire-contract item 9 documents %q; update the contract comment in exec.go and this constant together",
			util.DevicePATH, contractDevicePATH)
	}
}

// TestContract_CommandSeesDevicePATH runs a command and checks the PATH it
// actually observes. Nothing previously asserted the command's environment at
// all — only its output — which is why the /root working-directory bug
// survived until CI ran the suite as a non-root user.
func TestContract_CommandSeesDevicePATH(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping shell exec test in short mode")
	}

	resps := runOne(t, ExecRequest{ID: "path", Command: `printf %s "$PATH"`, TimeoutSeconds: 10})

	if got := lastResult(t, resps).ExitCode; got != 0 {
		t.Fatalf("exit_code = %d, want 0", got)
	}
	if got := decodeAll(t, resps, "stdout"); got != contractDevicePATH {
		t.Errorf("command PATH = %q, want %q", got, contractDevicePATH)
	}
}

// TestContract_CommandInheritsHome pins the corrected half of item 9: the exec
// path inherits HOME from the agent process rather than forcing HOME=/root.
// Forcing it is the interactive shell path's behaviour (shell.go), and the
// contract comment used to claim it for this path too.
//
// Runner- and device-safe: it compares against this process's own HOME
// whatever that is, and skips if the environment has none.
func TestContract_CommandInheritsHome(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping shell exec test in short mode")
	}

	want, ok := os.LookupEnv("HOME")
	if !ok {
		t.Skip("no HOME in the test process environment; nothing to inherit")
	}
	// If the inherited value already IS /root — running as root, e.g. on the
	// device — then "inherited" and "forced to /root" produce the same answer
	// and this test cannot tell them apart. Skip rather than report a green
	// that distinguishes nothing; that false confidence is the failure mode
	// this whole file exists to avoid.
	if want == deviceHomeDir {
		t.Skipf("HOME is already %s: inherited and forced are indistinguishable here", deviceHomeDir)
	}

	resps := runOne(t, ExecRequest{ID: "home", Command: `printf %s "$HOME"`, TimeoutSeconds: 10})

	if got := lastResult(t, resps).ExitCode; got != 0 {
		t.Fatalf("exit_code = %d, want 0", got)
	}
	if got := decodeAll(t, resps, "stdout"); got != want {
		t.Errorf("command HOME = %q, want the inherited %q (the exec path must not force HOME=/root; that is shell.go's behaviour)", got, want)
	}
}

// TestContract_WorkingDirectory checks the working directory a command
// actually runs in, asserting both documented branches of item 9: /root on a
// host where it can be entered, the agent's own directory where it cannot.
//
// Deliberately not "assert /root" — that would pass only as root and would
// enshrine the very existence-vs-usability confusion that broke every exec
// command on the first CI run.
func TestContract_WorkingDirectory(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping shell exec test in short mode")
	}

	resps := runOne(t, ExecRequest{ID: "cwd", Command: "pwd", TimeoutSeconds: 10})
	if got := lastResult(t, resps).ExitCode; got != 0 {
		t.Fatalf("exit_code = %d, want 0 (a command that cannot chdir reports -1 with no output)", got)
	}
	got := strings.TrimSpace(decodeAll(t, resps, "stdout"))

	want := usableWorkingDir(deviceHomeDir)
	if want == "" {
		// Inherited: compare against this process's own directory.
		wd, err := os.Getwd()
		if err != nil {
			t.Fatalf("os.Getwd: %v", err)
		}
		want = wd
	}

	// Compare with symlinks resolved on both sides: on macOS the temp and
	// working directories reach through /private, and `pwd` and os.Getwd can
	// disagree on the spelling of the same directory.
	if resolve(t, got) != resolve(t, want) {
		t.Errorf("working directory = %q, want %q", got, want)
	}
}

func resolve(t *testing.T, path string) string {
	t.Helper()
	if p, err := filepath.EvalSymlinks(path); err == nil {
		return p
	}
	return path
}

// ---------------------------------------------------------------------------
// usableWorkingDir: the decision the /root bug got wrong
// ---------------------------------------------------------------------------

func TestUsableWorkingDir_ReturnsEnterableDirectory(t *testing.T) {
	dir := t.TempDir()
	if got := usableWorkingDir(dir); got != dir {
		t.Errorf("usableWorkingDir(%q) = %q, want %q", dir, got, dir)
	}
}

func TestUsableWorkingDir_RejectsMissingDirectory(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-dir")
	if got := usableWorkingDir(missing); got != "" {
		t.Errorf("usableWorkingDir(%q) = %q, want \"\"", missing, got)
	}
}

// TestUsableWorkingDir_RejectsUnenterableDirectory is the regression test for
// the bug itself: a directory that EXISTS but cannot be entered must be
// rejected. An os.Stat-based check passes here and the exec then dies with a
// chdir error before the command runs.
//
// Skipped when running as root, which bypasses permission checks entirely —
// so this asserts nothing on the device, by design, rather than failing there.
func TestUsableWorkingDir_RejectsUnenterableDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission bits are bypassed, so this case cannot be exercised")
	}

	dir := filepath.Join(t.TempDir(), "locked")
	if err := os.Mkdir(dir, 0o000); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if got := usableWorkingDir(dir); got != "" {
		t.Errorf("usableWorkingDir(%q) = %q, want \"\" (the directory exists but cannot be entered)", dir, got)
	}
}

// ---------------------------------------------------------------------------
// Item 5: signal exit codes
// ---------------------------------------------------------------------------

// TestContract_SignalExitCodeIs128PlusSignum pins item 5: a process killed by
// a signal reports 128+signal_number, so SIGKILL (9) is 137. The literal 137
// is the documented value; it is not derived from the code.
//
// `kill -9 $$` makes the shell kill itself, which works identically on
// FreeBSD, Linux and macOS and needs no privileges.
func TestContract_SignalExitCodeIs128PlusSignum(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping shell exec test in short mode")
	}

	resps := runOne(t, ExecRequest{ID: "sig", Command: "kill -9 $$", TimeoutSeconds: 10})

	const wantSIGKILL = 137 // 128 + 9, per wire-contract item 5
	if got := lastResult(t, resps).ExitCode; got != wantSIGKILL {
		t.Errorf("exit_code = %d, want %d (128 + SIGKILL)", got, wantSIGKILL)
	}
}

// ---------------------------------------------------------------------------
// Item 4: the timeout kills the process GROUP
// ---------------------------------------------------------------------------

// TestContract_TimeoutKillsSurvivingDescendants is the regression test whose
// absence let the timeout bug ship. The existing timeout test uses `sleep 60`
// — a lone simple command, which the shell execs into, leaving no descendant
// — so a kill aimed at the direct child alone happened to work and the
// process-group claim in item 4 went unverified on every host it ran on.
//
// A compound command forks a descendant that survives a single-PID kill and
// keeps the inherited stdout pipe open, so cmd.Wait cannot return. Measured
// on macOS before the fix: 45s elapsed against a 1s deadline, and on the lab
// OPNsense two survivors after killing only the shell PID. The reported
// exit_code was 124 throughout — the caller was told "timed out" on schedule
// while the command ran on, which is why an elapsed-time assertion and not
// just an exit-code assertion is the thing that catches this.
func TestContract_TimeoutKillsSurvivingDescendants(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping shell exec test in short mode")
	}

	start := time.Now()
	resps := runOne(t, ExecRequest{
		ID:             "pgroup",
		Command:        "sleep 30 & sleep 30",
		TimeoutSeconds: 1,
	})
	elapsed := time.Since(start)

	if elapsed > 5*time.Second {
		t.Errorf("a descendant survived the timeout kill: elapsed %v for a 1s deadline (the kill must target the process group, and WaitDelay must bound the wait on the inherited pipe)", elapsed)
	}
	if got := lastResult(t, resps).ExitCode; got != ExecTimeoutExitCode {
		t.Errorf("exit_code = %d, want %d", got, ExecTimeoutExitCode)
	}
}

// ---------------------------------------------------------------------------
// Item 7: serialisation — one command at a time
// ---------------------------------------------------------------------------

// TestContract_CommandsQueueRatherThanInterleave pins item 7: the agent holds
// a mutex across the FULL lifecycle of each command, so a second request
// queues behind the first rather than running alongside it.
//
// The pre-existing serialisation test pushes two instantaneous `echo`s and
// checks that two result frames come back. That passes whether or not the
// mutex exists — it demonstrates completion, not exclusion. This one makes
// each command record when it starts and finishes, so overlap is visible:
// serialised execution writes s1,e1,s2,e2 and interleaved execution writes
// s1,s2,e1,e2.
//
// Why the property matters beyond tidiness: a command that overruns blocks
// the next one. Before the process-group fix, a command reported as timed out
// at 124 could hold this queue for another 45 s while the caller believed it
// was finished — the queue is what turned a late kill into a stalled session.
func TestContract_CommandsQueueRatherThanInterleave(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping shell exec test in short mode")
	}

	marks := filepath.Join(t.TempDir(), "marks")
	tc := newTestCapture()
	em := NewExecManager()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		em.HandleExecStream(ctx, tc.stream)
	}()

	// Each command brackets a sleep with a start and an end marker. The sleep
	// is long enough that genuine concurrency would interleave the markers.
	mark := func(id string) string {
		return "printf '" + id + "-start\\n' >> " + marks +
			"; sleep 0.4; printf '" + id + "-end\\n' >> " + marks
	}
	tc.pushBytes(encodeReq("q1", mark("q1"), 10))
	tc.pushBytes(encodeReq("q2", mark("q2"), 10))

	waitForResults(t, tc, 2, 20*time.Second)
	tc.closeInput()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("HandleExecStream did not exit after stream close")
	}

	raw, err := os.ReadFile(marks)
	if err != nil {
		t.Fatalf("reading markers: %v", err)
	}
	got := strings.Fields(string(raw))
	want := []string{"q1-start", "q1-end", "q2-start", "q2-end"}

	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("command markers = %v, want %v\nthe second command must not start until the first has finished (item 7: one command at a time)", got, want)
	}
}

// waitForResults blocks until the capture holds at least n result frames.
func waitForResults(t *testing.T, tc *testCapture, n int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		count := 0
		for _, r := range tc.responses() {
			if r.Type == "result" {
				count++
			}
		}
		if count >= n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d result frames", n)
}

// ---------------------------------------------------------------------------
// Item 4: the descendants are actually dead, not merely no longer blocking us
// ---------------------------------------------------------------------------

// TestContract_TimeoutReapsDescendantProcesses asserts what item 4 actually
// promises — "the agent kills the entire process group" — rather than the
// weaker thing a timing assertion can show.
//
// TestContract_TimeoutKillsSurvivingDescendants proves the parent stopped
// blocking. That is a different claim from the process group having died, and
// the bug lived precisely in the gap between them: a stray `sleep` left
// running on the device is invisible to any elapsed-time check. Verified on
// the lab OPNsense (FreeBSD 14.3) that killing only the shell PID leaves two
// survivors, so this is the shape worth pinning.
//
// The command records its background child's PID where the test can read it,
// and the test then waits for that PID to disappear.
func TestContract_TimeoutReapsDescendantProcesses(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping shell exec test in short mode")
	}

	pidFile := filepath.Join(t.TempDir(), "child.pid")

	// `sleep 30 &` backgrounds a child; a non-interactive shell has job
	// control off, so it stays in the process group Setpgid created — which
	// is exactly the group the timeout must kill. The trailing sleep keeps
	// the shell itself alive until the deadline.
	command := "sleep 30 & printf %s \"$!\" > " + pidFile + "; sleep 30"

	resps := runOne(t, ExecRequest{ID: "reap", Command: command, TimeoutSeconds: 1})

	if got := lastResult(t, resps).ExitCode; got != ExecTimeoutExitCode {
		t.Fatalf("exit_code = %d, want %d", got, ExecTimeoutExitCode)
	}

	raw, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("reading child pid: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid <= 0 {
		t.Fatalf("bad child pid %q: %v", raw, err)
	}

	// Poll rather than check once: SIGKILL makes the process a zombie until
	// its new parent (init, after the shell died) reaps it, and kill(pid, 0)
	// still succeeds against a zombie.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if processGone(pid) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Do not leave a stray process behind if the assertion fails.
	_ = syscall.Kill(pid, syscall.SIGKILL)
	t.Errorf("backgrounded descendant (pid %d) was still alive after the timeout: the kill must target the process group, not just the direct child", pid)
}

// processGone reports whether pid no longer exists. Signal 0 performs the
// permission and existence checks without delivering anything.
func processGone(pid int) bool {
	err := syscall.Kill(pid, 0)
	return errors.Is(err, syscall.ESRCH)
}

// ---------------------------------------------------------------------------
// Items 4 and 5 pinned against each other, in both directions
// ---------------------------------------------------------------------------

// TestContract_TimeoutIs124AndSignalIs137 pins the two exit-code rules so
// neither can drift into the other.
//
// They are easy to conflate because a timeout kills the process with SIGKILL,
// so the "128 + signum" rule would give 137 — but item 4 says a timeout
// reports 124, and resolveExitCode gives the timeout flag priority for that
// reason. Asserting only one direction would let a later change "unify" the
// two and still pass. This fails if a timeout ever starts reporting 137, and
// equally if a signalled command starts reporting 124.
func TestContract_TimeoutIs124AndSignalIs137(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping shell exec test in short mode")
	}

	const (
		wantTimeout = 124 // item 4, literal
		wantSignal  = 137 // item 5: 128 + SIGKILL(9), literal
	)

	t.Run("timeout reports 124 and not 137", func(t *testing.T) {
		resps := runOne(t, ExecRequest{ID: "to", Command: "sleep 30", TimeoutSeconds: 1})
		got := lastResult(t, resps).ExitCode
		if got == wantSignal {
			t.Fatalf("exit_code = %d: a timed-out command must report %d (item 4), not the 128+SIGKILL value", got, wantTimeout)
		}
		if got != wantTimeout {
			t.Errorf("exit_code = %d, want %d", got, wantTimeout)
		}
	})

	t.Run("signal reports 137 and not 124", func(t *testing.T) {
		resps := runOne(t, ExecRequest{ID: "sg", Command: "kill -9 $$", TimeoutSeconds: 10})
		got := lastResult(t, resps).ExitCode
		if got == wantTimeout {
			t.Fatalf("exit_code = %d: a signalled command must report %d (item 5), not the timeout value", got, wantSignal)
		}
		if got != wantSignal {
			t.Errorf("exit_code = %d, want %d", got, wantSignal)
		}
	})
}

// ---------------------------------------------------------------------------
// Item 6: the output cap trims stdout first, then stderr fills the remainder
// ---------------------------------------------------------------------------

// TestContract_OutputCapTrimsStderrToTheRemainder pins the ordering half of
// item 6. The existing cap test only checks truncated=true and that stdout
// stays under the cap, which holds under any trimming policy — including one
// that dropped stdout to make room for stderr.
//
// With stdout under the cap on its own, the contract says stdout survives
// whole and stderr is trimmed to exactly the bytes left over.
func TestContract_OutputCapTrimsStderrToTheRemainder(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping shell exec test in short mode")
	}

	// 600 KiB on each stream: 1200 KiB combined, over the 1 MiB cap, while
	// stdout alone stays comfortably under it.
	const eachKiB = 600
	each := eachKiB * 1024

	command := "dd if=/dev/zero bs=1024 count=" + strconv.Itoa(eachKiB) + " 2>/dev/null | tr '\\0' 'A'; " +
		"dd if=/dev/zero bs=1024 count=" + strconv.Itoa(eachKiB) + " 2>/dev/null | tr '\\0' 'B' >&2"

	resps := runOne(t, ExecRequest{ID: "cap", Command: command, TimeoutSeconds: 60})

	result := lastResult(t, resps)
	if !result.Truncated {
		t.Error("truncated = false, want true when combined output exceeds the cap")
	}

	stdout := decodeAll(t, resps, "stdout")
	stderr := decodeAll(t, resps, "stderr")

	if len(stdout) != each {
		t.Errorf("stdout = %d bytes, want %d untouched (stdout is under the cap on its own, so item 6 keeps it whole)", len(stdout), each)
	}
	if want := execOutputCap - each; len(stderr) != want {
		t.Errorf("stderr = %d bytes, want %d (the remainder of the %d-byte cap after stdout)", len(stderr), want, execOutputCap)
	}
	if total := len(stdout) + len(stderr); total != execOutputCap {
		t.Errorf("combined output = %d bytes, want exactly the cap %d", total, execOutputCap)
	}
}

// ---------------------------------------------------------------------------
// Item 3: timeout default and clamp
// ---------------------------------------------------------------------------

// TestContract_ResolveExecTimeout pins item 3's two rules, neither of which
// was exercised before: timeout_seconds absent or <=0 means the 60 s default,
// and anything above the 3600 s cap is silently clamped to it.
//
// Only the CONSTANTS were checked previously. The one test that looked like
// it covered the default — TestRunCommand_DefaultTimeoutIsUsedWhenZero — runs
// `echo fast` and asserts exit_code 0, which is true for any timeout value
// whatsoever, including a broken one; it asserts nothing about timeouts at
// all. Driving these branches through a live command would mean waiting out a
// 60 s default or a 3600 s cap, which is why the resolution is extracted.
//
// Expected values are written literally rather than taken from
// defaultExecTimeout/maxExecTimeout, so redefining a constant fails here
// instead of moving the goalposts with the code.
func TestContract_ResolveExecTimeout(t *testing.T) {
	const (
		contractDefault = 60 * time.Second   // item 3
		contractMax     = 3600 * time.Second // item 3
	)

	cases := []struct {
		name    string
		seconds int
		want    time.Duration
	}{
		{"absent (zero value) uses the default", 0, contractDefault},
		{"negative uses the default", -1, contractDefault},
		{"large negative uses the default", -3600, contractDefault},
		{"one second is honoured", 1, time.Second},
		{"an ordinary value passes through", 30, 30 * time.Second},
		{"the cap itself is not clamped", 3600, contractMax},
		{"one second over the cap is clamped", 3601, contractMax},
		{"far over the cap is clamped", 86400, contractMax},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveExecTimeout(tc.seconds); got != tc.want {
				t.Errorf("resolveExecTimeout(%d) = %v, want %v", tc.seconds, got, tc.want)
			}
		})
	}
}

// TestContract_NonPositiveTimeoutStillRunsTheCommand guards the boundary the
// unit test above cannot see: <=0 must mean "use the default", never "deadline
// already passed". If the <=0 branch regressed to a zero duration, the context
// would expire immediately and every such command would return 124 without
// running — so this asserts a real command still executes and succeeds.
func TestContract_NonPositiveTimeoutStillRunsTheCommand(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping shell exec test in short mode")
	}

	for _, seconds := range []int{0, -1} {
		resps := runOne(t, ExecRequest{ID: "nz", Command: "printf ran", TimeoutSeconds: seconds})
		result := lastResult(t, resps)
		if result.ExitCode != 0 {
			t.Errorf("timeout_seconds=%d: exit_code = %d, want 0 (a non-positive timeout means the default, not an expired deadline)", seconds, result.ExitCode)
		}
		if got := decodeAll(t, resps, "stdout"); got != "ran" {
			t.Errorf("timeout_seconds=%d: stdout = %q, want %q", seconds, got, "ran")
		}
	}
}
