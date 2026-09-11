package tasks

// connect_stream_lifetime_test.go — pins the CONNECT session-lifetime wiring.
//
// Follows the precedent of plugin/tests/RemoteAccessPolicyTest.php: assert a
// cross-file link that nothing ties together at compile time, because the
// alternative is a guarantee held by a comment.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestConnectDoesNotRegisterOnAllStreamsClosed pins the decision that makes
// the webadmin tunnel survivable: CONNECT session lifetime is tied to the
// PathFinder relay connection, NOT to the open-stream count.
//
// Webadmin rides one short-lived stream per HTTP request, so the count
// legitimately returns to zero between requests and after a terminal stream
// closes. Registering an all-streams-closed teardown here cancels the session
// at the first such moment — which broke the tunnel mid-session and made
// read-only (terminal-less) sessions unusable with "connection refused". That
// was found and fixed once already; this test is what makes re-introducing it
// fail in CI rather than in an operator's browser.
//
// internal/pathfinder/stream_lifetime_test.go already covers the other side:
// that the StreamManager tears nothing down when no callback is registered,
// with a positive control proving the mechanism still fires when one is. What
// nothing asserted until now is that THIS package keeps declining to register
// one — that linkage lived in a comment on the test ("matching connect.go"),
// which a change to connect.go would not disturb.
//
// Deliberately an AST check rather than a string search: a future comment or
// log line mentioning OnAllStreamsClosed must not trip it, and only a real
// call should. It scans every non-test file in the package rather than
// connect.go alone, so moving the call into a helper does not evade it.
func TestConnectDoesNotRegisterOnAllStreamsClosed(t *testing.T) {
	const forbidden = "OnAllStreamsClosed"

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading package directory: %v", err)
	}

	fset := token.NewFileSet()
	scanned := 0

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}

		file, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		scanned++

		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel == nil || sel.Sel.Name != forbidden {
				return true
			}
			t.Errorf("%s calls %s at %s.\n\n"+
				"CONNECT session lifetime is relay-tied, not stream-count-tied. Webadmin opens and "+
				"closes one stream per HTTP request, so the open-stream count reaching zero is normal "+
				"and must not cancel the session — registering this teardown kills the tunnel "+
				"mid-session and makes read-only sessions fail with \"connection refused\". "+
				"See internal/pathfinder/stream_lifetime_test.go for the StreamManager side.",
				name, forbidden, fset.Position(call.Pos()))
			return true
		})
	}

	// Guard against the check silently becoming vacuous — a package layout
	// change that leaves nothing to scan would otherwise read as a pass.
	if scanned == 0 {
		t.Fatal("scanned no non-test Go files; this assertion would pass vacuously")
	}
	if _, err := os.Stat(filepath.Join(".", "connect.go")); err != nil {
		t.Fatalf("connect.go not found in this package (%v); the file this assertion exists to guard has moved, so update it deliberately rather than letting it pass", err)
	}
}
