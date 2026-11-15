package core

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/config"
	"github.com/netdefense-io/ndagent/internal/network"
	"github.com/netdefense-io/ndagent/internal/signing"
	"github.com/netdefense-io/ndagent/internal/state"
	"github.com/netdefense-io/ndagent/internal/tasks"
	"github.com/netdefense-io/ndagent/internal/testbroker"
)

// The agent died with a remote session open. The next process finds it in
// the record and, wired as runWebSocketPhase wires it, reports its end over
// the first connection: recorded before the connect, sent by its drain.
func TestDirectPeerManagerReportsOverThePhasesConnection(t *testing.T) {
	const connectID = "eff97f3e3ad593d08e250b5a5e492449"
	ledgerPath := filepath.Join(t.TempDir(), "connect-sessions.json")
	listening := time.Now().Add(-10 * time.Minute).Unix()
	record := fmt.Sprintf(`{"v":1,"entries":[{"connect_id":%q,"task_id":"4711","until":%d,"listening_at":%d,"connected_at":%d,"path":"direct","protocol":1}]}`,
		connectID, listening+90, listening, listening+4)
	if err := os.WriteFile(ledgerPath, []byte(record), 0o600); err != nil {
		t.Fatal(err)
	}

	manager := newDirectPeerManager("3a1e88a3-0000-4000-8000-0000000000aa", ledgerPath)
	defer manager.Shutdown(time.Second)

	b := testbroker.New(t)
	store := openStore(t)
	_, priv, err := signing.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	stateStore, err := state.New(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	ws := network.NewWebSocketClient(&config.Config{
		ServerURIWS:   b.URL(),
		DeviceUUID:    "3a1e88a3-0000-4000-8000-0000000000aa",
		Token:         "00000000-0000-4000-8000-000000000000",
		DevicePrivKey: base64.StdEncoding.EncodeToString(signing.SeedFromPrivateKey(priv)),
	}, stateStore, store, tasks.LifecycleFor, b.NDMKeys())

	// Before the phase has a connection, nothing is on record.
	if _, found, _ := store.Get("4711"); found {
		t.Fatal("the end was recorded before a connection was named")
	}
	manager.SetReporter(ws)
	rec, found, err := store.Get("4711")
	if err != nil || !found || rec.Status != "COMPLETED" || rec.Delivered {
		t.Fatalf("after SetReporter, before the connect: row %+v found %v err %v; want COMPLETED, undelivered", rec, found, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = ws.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	b.WaitFor("the session's end", 10*time.Second, func() bool { return len(b.TaskResponses()) >= 1 })
	got := b.TaskResponses()[0]
	var connect map[string]interface{}
	_ = json.Unmarshal(got.Inner["connect"], &connect)
	if got.TaskID != 4711 || got.Status != "COMPLETED" || connect["event"] != "session-end" || connect["reason"] != "error" ||
		connect["connect_id"] != connectID || connect["path"] != "direct" || connect["paired_after_seconds"] != 4.0 {
		t.Fatalf("the broker got %+v with %v", got, connect)
	}

	// Reported once: the record no longer holds the session.
	again := newDirectPeerManager("3a1e88a3-0000-4000-8000-0000000000aa", ledgerPath)
	defer again.Shutdown(time.Second)
	again.SetReporter(ws)
	time.Sleep(200 * time.Millisecond)
	if n := len(b.TaskResponses()); n != 1 {
		t.Fatalf("%d answers after the next process started, want the 1", n)
	}
}

// A device that is never sent a direct-peer task has no record file: building
// the manager writes nothing.
func TestDirectPeerManagerWritesNothingByItself(t *testing.T) {
	dir := t.TempDir()
	manager := newDirectPeerManager("3a1e88a3-0000-4000-8000-0000000000aa", filepath.Join(dir, "connect-sessions.json"))
	manager.Shutdown(time.Second)
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("files after building and stopping the manager: %v (%v)", entries, err)
	}
	if manager.Sessions() != 0 {
		t.Fatal("sessions counted")
	}
}

// phaseCalls returns the calls in runWebSocketPhase, in source order, as
// printed expressions of what is called.
func phaseCalls(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "lifecycle.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing lifecycle.go: %v", err)
	}
	var calls []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "runWebSocketPhase" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			// What a deferred function does happens when the phase ends.
			if _, deferred := n.(*ast.DeferStmt); deferred {
				return false
			}
			if call, ok := n.(*ast.CallExpr); ok {
				text := exprString(call.Fun)
				if len(call.Args) == 1 {
					text += "(" + exprString(call.Args[0]) + ")"
				}
				calls = append(calls, text)
			}
			return true
		})
	}
	if len(calls) == 0 {
		t.Fatal("runWebSocketPhase not found in lifecycle.go")
	}
	return calls
}

// Each WebSocket phase names its connection to the manager, and does so
// before the connection runs: a result has to be in the task store when the
// first connect replays what the store holds. Without the call every answer
// about a session waits forever and nothing fails.
func TestRunWebSocketPhaseNamesItsConnectionToTheDirectPeerManager(t *testing.T) {
	named, ran := -1, -1
	for i, call := range phaseCalls(t) {
		switch call {
		case "l.directPeer.SetReporter(wsClient)":
			named = i
		case "wsClient.Run(phaseCtx)":
			ran = i
		}
	}
	if ran < 0 {
		t.Fatal("runWebSocketPhase no longer calls wsClient.Run(phaseCtx): this test needs another anchor")
	}
	if named < 0 {
		t.Fatal("runWebSocketPhase does not call l.directPeer.SetReporter(wsClient): no answer about a remote session would ever be sent")
	}
	if named > ran {
		t.Fatal("l.directPeer.SetReporter(wsClient) comes after wsClient.Run: it must be named before the connection runs")
	}
}

// The manager is the process's one: NewLifecycleManager builds it and hands
// it to the task handlers, and the lifecycle's Run ends its sessions.
func TestTheLifecycleOwnsTheDirectPeerManager(t *testing.T) {
	src, err := os.ReadFile("lifecycle.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"directPeer := newDirectPeerManager(cfg.DeviceUUID, directpeer.DefaultLedgerPath)",
		"tasks.SetDirectPeerManager(directPeer)",
		"defer l.directPeer.Shutdown(directPeerShutdownWait)",
	} {
		if !strings.Contains(string(src), want) {
			t.Errorf("lifecycle.go no longer has %q", want)
		}
	}
}
