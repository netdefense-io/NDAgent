package core

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/opnapi"
	"github.com/netdefense-io/ndagent/internal/telemetry"
)

// parseCorePackage parses the package's non-test files.
func parseCorePackage(t *testing.T) []*ast.File {
	t.Helper()
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", path, err)
		}
		files = append(files, file)
	}
	return files
}

func funcDecl(files []*ast.File, name string) *ast.FuncDecl {
	for _, file := range files {
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == name {
				return fn
			}
		}
	}
	return nil
}

// isCall reports whether n calls something named sel, as x.sel(...).
func isCall(n ast.Node, sel string) (*ast.CallExpr, bool) {
	call, ok := n.(*ast.CallExpr)
	if !ok {
		return nil, false
	}
	s, ok := call.Fun.(*ast.SelectorExpr)
	return call, ok && s.Sel.Name == sel
}

// One heavy-telemetry collector per process. It used to be built inside
// runWebSocketPhase and run on the process context: every return to the
// registration phase added a collector with a firmware check schedule of its
// own that nothing ever stopped, and each began with an empty cache. Now
// NewLifecycleManager, which runs once per process, is the only place that
// builds one, and every phase starts it through a sync.Once and wires it.
func TestHeavyCollectorIsBuiltOncePerProcess(t *testing.T) {
	files := parseCorePackage(t)

	builtIn := map[string]int{}
	for _, file := range files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				if _, ok := isCall(n, "NewHeavyCollector"); ok {
					builtIn[fn.Name.Name]++
				}
				return true
			})
		}
	}
	if len(builtIn) != 1 || builtIn["NewLifecycleManager"] != 1 {
		t.Fatalf("telemetry.NewHeavyCollector is called in %v, want once, in NewLifecycleManager", builtIn)
	}

	phase := funcDecl(files, "runWebSocketPhase")
	if phase == nil {
		t.Fatal("runWebSocketPhase not found")
	}
	starts := false
	ast.Inspect(phase.Body, func(n ast.Node) bool {
		if _, ok := n.(*ast.GoStmt); ok {
			t.Errorf("runWebSocketPhase starts a goroutine of its own; what outlives a phase belongs to the process")
		}
		if _, ok := isCall(n, "startHeavyTelemetry"); ok {
			starts = true
		}
		return true
	})
	if !starts {
		t.Error("runWebSocketPhase does not call startHeavyTelemetry: the collector would never run")
	}

	start := funcDecl(files, "startHeavyTelemetry")
	if start == nil {
		t.Fatal("startHeavyTelemetry not found")
	}
	runsOnce := false
	ast.Inspect(start.Body, func(n ast.Node) bool {
		call, ok := isCall(n, "Do")
		if !ok {
			return true
		}
		ast.Inspect(call, func(m ast.Node) bool {
			if _, ok := isCall(m, "Run"); ok {
				runsOnce = true
			}
			return true
		})
		return true
	})
	if !runsOnce {
		t.Error("startHeavyTelemetry does not run the collector inside a sync.Once")
	}
}

// The decommission stops the collector before it dismantles the API and
// removes the snapshot the collector keeps on disk.
func TestDecommissionStopsTheHeavyCollector(t *testing.T) {
	files := parseCorePackage(t)
	decommission := funcDecl(files, "runDecommission")
	if decommission == nil {
		t.Fatal("runDecommission not found")
	}
	stopped := false
	ast.Inspect(decommission.Body, func(n ast.Node) bool {
		if _, ok := isCall(n, "stopHeavyTelemetry"); ok {
			stopped = true
		}
		return true
	})
	if !stopped {
		t.Fatal("runDecommission does not call stopHeavyTelemetry")
	}

	stop := funcDecl(files, "stopHeavyTelemetry")
	removes := false
	ast.Inspect(stop.Body, func(n ast.Node) bool {
		if _, ok := isCall(n, "RemoveCache"); ok {
			removes = true
		}
		return true
	})
	if !removes {
		t.Fatal("stopHeavyTelemetry does not remove the saved snapshot")
	}
}

// fakeHeavyAPI answers what the collector reads and counts the service reads,
// one per gather.
type fakeHeavyAPI struct {
	srv      *httptest.Server
	services atomic.Int32
}

func newFakeHeavyAPI(t *testing.T) *fakeHeavyAPI {
	t.Helper()
	f := &fakeHeavyAPI{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/core/service/search":
			f.services.Add(1)
			_, _ = w.Write([]byte(`{"rows":[{"name":"unbound","description":"DNS","running":1}]}`))
		case "/trust/cert/search":
			_, _ = w.Write([]byte(`{"rows":[]}`))
		case "/core/firmware/running":
			_, _ = w.Write([]byte(`{"status":"busy"}`))
		case "/core/firmware/status":
			_, _ = w.Write([]byte(`{"status":"none","product":{"product_version":"26.7"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// Starting the collector from a second phase does not start a second one, and
// stopping it waits for it and removes what it saved.
func TestHeavyTelemetryStartsOnceAndStopsWithItsSnapshot(t *testing.T) {
	api := newFakeHeavyAPI(t)
	cache := filepath.Join(t.TempDir(), "heavy.json")
	l := &LifecycleManager{
		shutdown: NewShutdownCoordinator(),
		heavy:    telemetry.NewHeavyCollector(opnapi.NewClient(api.srv.URL, "key", "secret", true), cache),
	}

	l.startHeavyTelemetry()
	l.startHeavyTelemetry() // the next phase
	deadline := time.Now().Add(5 * time.Second)
	for l.heavy.Snapshot() == nil {
		if time.Now().After(deadline) {
			t.Fatal("the collector never gathered")
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	if n := api.services.Load(); n != 1 {
		t.Fatalf("%d gathers at start, want 1: a second collector is running", n)
	}
	if _, err := os.Stat(cache); err != nil {
		t.Fatalf("the gather saved nothing: %v", err)
	}

	stopped := make(chan struct{})
	go func() {
		l.stopHeavyTelemetry()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("stopHeavyTelemetry did not return")
	}
	if _, err := os.Stat(cache); !os.IsNotExist(err) {
		t.Fatalf("the saved snapshot survived the stop: %v", err)
	}
}
