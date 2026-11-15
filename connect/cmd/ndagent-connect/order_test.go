package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// The companion turns tracing off before it does anything else with the
// session, and takes none when that fails. The call does something on
// FreeBSD only, where no CI job runs: without this test, taking it out of
// main leaves every suite green.
func TestMainTurnsTracingOffBeforeAnythingIsRead(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	var body *ast.BlockStmt
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "main" && fn.Recv == nil {
			body = fn.Body
		}
	}
	if body == nil {
		t.Fatal("main.go has no func main")
	}

	isRunCall := func(n ast.Node, name string) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return false
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != name {
			return false
		}
		pkg, ok := sel.X.(*ast.Ident)
		return ok && pkg.Name == "run"
	}
	position := func(name string) token.Pos {
		var at token.Pos
		ast.Inspect(body, func(n ast.Node) bool {
			if at == token.NoPos && n != nil && isRunCall(n, name) {
				at = n.Pos()
			}
			return true
		})
		return at
	}
	deny, setup, run := position("DenyTracing"), position("Setup"), position("Run")
	if deny == token.NoPos {
		t.Fatal("main does not call run.DenyTracing: another process of the companion's user could read a session's keys out of it")
	}
	if setup == token.NoPos || run == token.NoPos {
		t.Fatal("main no longer calls run.Setup and run.Run: this test needs other anchors")
	}
	if !(deny < setup && setup < run) {
		t.Fatal("run.DenyTracing must come before run.Setup and run.Run, which reads the session's keys")
	}

	// Its failure ends the process: no session is taken.
	exits := false
	for _, stmt := range body.List {
		ifStmt, ok := stmt.(*ast.IfStmt)
		if !ok || ifStmt.Init == nil {
			continue
		}
		denies := false
		ast.Inspect(ifStmt.Init, func(n ast.Node) bool {
			if n != nil && isRunCall(n, "DenyTracing") {
				denies = true
			}
			return true
		})
		if !denies {
			continue
		}
		ast.Inspect(ifStmt.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Exit" {
				if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "os" {
					exits = true
				}
			}
			return true
		})
	}
	if !exits {
		t.Fatal("a failed run.DenyTracing must end the process (os.Exit) before any session is taken")
	}
}
