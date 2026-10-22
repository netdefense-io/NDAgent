package core

import (
	"go/ast"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

// withSupervisorParent makes parent the agent's parent pid and records the
// pids the agent signals instead of signalling them.
func withSupervisorParent(t *testing.T, parent int) *[]int {
	t.Helper()
	var signalled []int
	origParent, origSignal := supervisorParentPID, signalSupervisor
	supervisorParentPID = func() int { return parent }
	signalSupervisor = func(pid int) error {
		signalled = append(signalled, pid)
		return nil
	}
	t.Cleanup(func() { supervisorParentPID, signalSupervisor = origParent, origSignal })
	return &signalled
}

func writeSupervisorPidfile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ndagent.daemon.pid")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// withForceExit records the forced exits instead of making them.
func withForceExit(t *testing.T) *[]int {
	t.Helper()
	var codes []int
	orig := forceExit
	forceExit = func(code int) { codes = append(codes, code) }
	t.Cleanup(func() { forceExit = orig })
	return &codes
}

// The rc.d script names the variable; the agent reads it.
func TestSupervisorPidfileEnvIsTheOneTheRCScriptSets(t *testing.T) {
	if SupervisorPidfileEnv != "NDAGENT_SUPERVISOR_PIDFILE" {
		t.Fatalf("SupervisorPidfileEnv = %q", SupervisorPidfileEnv)
	}
	src, err := os.ReadFile("../../plugin/src/usr/local/etc/rc.d/ndagent")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "NDAGENT_SUPERVISOR_PIDFILE=${ndagent_supervisor_pidfile}") {
		t.Fatal("the rc.d script does not pass the supervisor pidfile in NDAGENT_SUPERVISOR_PIDFILE")
	}
}

func TestEndSupervisionSignalsTheParentThePidfileNames(t *testing.T) {
	signalled := withSupervisorParent(t, 4241)
	t.Setenv(SupervisorPidfileEnv, writeSupervisorPidfile(t, "4241\n"))

	asked, err := endSupervision()
	if err != nil || !asked {
		t.Fatalf("endSupervision = %v, %v; want true, nil", asked, err)
	}
	if !reflect.DeepEqual(*signalled, []int{4241}) {
		t.Fatalf("signalled %v, want [4241]", *signalled)
	}
}

// An agent started by hand, or by an earlier package's rc.d script, has no
// supervisor to ask.
func TestEndSupervisionWithoutASupervisorSignalsNothing(t *testing.T) {
	signalled := withSupervisorParent(t, 4241)
	t.Setenv(SupervisorPidfileEnv, "")

	asked, err := endSupervision()
	if err != nil || asked || len(*signalled) != 0 {
		t.Fatalf("endSupervision = %v, %v, signalled %v; want false, nil, nothing", asked, err, *signalled)
	}
}

func TestEndSupervisionSignalsNothingButTheAgentsParent(t *testing.T) {
	for name, tc := range map[string]struct {
		content string
		parent  int
	}{
		"another process":                         {"777\n", 4241},
		"the supervisor gone, the agent orphaned": {"4241\n", 1},
		"an empty pidfile":                        {"", 4241},
		"no pid in the pidfile":                   {"daemon\n", 4241},
		"init":                                    {"1\n", 1},
	} {
		t.Run(name, func(t *testing.T) {
			signalled := withSupervisorParent(t, tc.parent)
			t.Setenv(SupervisorPidfileEnv, writeSupervisorPidfile(t, tc.content))

			asked, err := endSupervision()
			if err == nil || asked || len(*signalled) != 0 {
				t.Fatalf("endSupervision = %v, %v, signalled %v; want an error and nothing signalled", asked, err, *signalled)
			}
		})
	}

	t.Run("no pidfile", func(t *testing.T) {
		signalled := withSupervisorParent(t, 4241)
		t.Setenv(SupervisorPidfileEnv, filepath.Join(t.TempDir(), "missing.pid"))
		if asked, err := endSupervision(); err == nil || asked || len(*signalled) != 0 {
			t.Fatalf("endSupervision = %v, %v, signalled %v; want an error and nothing signalled", asked, err, *signalled)
		}
	})
}

func TestStopAsksTheSupervisorAndShutsDown(t *testing.T) {
	signalled := withSupervisorParent(t, 4241)
	t.Setenv(SupervisorPidfileEnv, writeSupervisorPidfile(t, "4241\n"))

	s := NewShutdownCoordinator()
	s.Stop()
	if !reflect.DeepEqual(*signalled, []int{4241}) {
		t.Fatalf("signalled %v, want the supervisor", *signalled)
	}
	if !s.IsShutdownRequested() || s.Context().Err() == nil {
		t.Fatal("Stop did not shut the agent down")
	}
}

// The supervisor forwards the SIGTERM it gets from Stop to the agent, which is
// already shutting down: that must not count as a second signal.
func TestASignalDuringARequestedShutdownDoesNotForceTheExit(t *testing.T) {
	exits := withForceExit(t)
	s := NewShutdownCoordinator()
	s.RequestShutdown()

	s.onSignal(syscall.SIGTERM)
	if len(*exits) != 0 {
		t.Fatalf("the forwarded SIGTERM forced the exit (%v)", *exits)
	}
	s.onSignal(syscall.SIGTERM)
	if !reflect.DeepEqual(*exits, []int{1}) {
		t.Fatalf("forced exits %v after a second signal, want [1]", *exits)
	}
}

func TestTheFirstSignalShutsDownAndTheSecondForcesTheExit(t *testing.T) {
	exits := withForceExit(t)
	s := NewShutdownCoordinator()

	s.onSignal(syscall.SIGTERM)
	if len(*exits) != 0 || s.Context().Err() == nil {
		t.Fatalf("first signal: exits %v, context %v; want a graceful shutdown", *exits, s.Context().Err())
	}
	s.onSignal(syscall.SIGINT)
	if !reflect.DeepEqual(*exits, []int{1}) {
		t.Fatalf("forced exits %v, want [1]", *exits)
	}
}

// methodDecl finds the method name of the type recv.
func methodDecl(files []*ast.File, recv, name string) *ast.FuncDecl {
	for _, file := range files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name != name || fn.Recv == nil || len(fn.Recv.List) != 1 {
				continue
			}
			typ := fn.Recv.List[0].Type
			if star, ok := typ.(*ast.StarExpr); ok {
				typ = star.X
			}
			if ident, ok := typ.(*ast.Ident); ok && ident.Name == recv {
				return fn
			}
		}
	}
	return nil
}

// containsCall reports whether the body calls something named sel.
func containsCall(body ast.Node, sel string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if _, ok := isCall(n, sel); ok {
			found = true
		}
		return true
	})
	return found
}

// The exits the agent makes on purpose end the supervision; anything else
// leaves the supervisor to start the agent again.
func TestDeliberateExitsEndTheSupervision(t *testing.T) {
	files := parseCorePackage(t)

	phase := funcDecl(files, "runWebSocketPhase")
	if phase == nil {
		t.Fatal("runWebSocketPhase not found")
	}
	var callback *ast.FuncLit
	ast.Inspect(phase.Body, func(n ast.Node) bool {
		if call, ok := isCall(n, "SetShutdownCallback"); ok && len(call.Args) == 1 {
			callback, _ = call.Args[0].(*ast.FuncLit)
		}
		return true
	})
	if callback == nil {
		t.Fatal("runWebSocketPhase sets no shutdown callback")
	}
	if !containsCall(callback.Body, "Stop") || containsCall(callback.Body, "RequestShutdown") {
		t.Error("the shutdown callback of RESTART and PLUGIN_INSTALL must call Stop, not RequestShutdown")
	}

	decommission := funcDecl(files, "runDecommission")
	if decommission == nil {
		t.Fatal("runDecommission not found")
	}
	passesStop := false
	ast.Inspect(decommission.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if fn, ok := call.Fun.(*ast.Ident); !ok || fn.Name != "decommissionRunner" {
			return true
		}
		for _, arg := range call.Args {
			if sel, ok := arg.(*ast.SelectorExpr); ok && sel.Sel.Name == "Stop" {
				passesStop = true
			}
		}
		return true
	})
	if !passesStop {
		t.Error("the decommission must shut the agent down with Stop")
	}

	run := methodDecl(files, "LifecycleManager", "Run")
	if run == nil {
		t.Fatal("LifecycleManager.Run not found")
	}
	if !containsCall(run.Body, "EndSupervision") {
		t.Error("Run must end the supervision before a deleted device stops")
	}
}
