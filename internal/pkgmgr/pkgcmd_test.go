package pkgmgr

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The PATH pkg's children are documented to get, written out so the test does
// not agree with util.DevicePATH by construction.
const devicePATHLiteral = "/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin"

func TestPkgCmdCarriesTheDevicePATH(t *testing.T) {
	t.Setenv("PATH", "/sbin:/bin:/usr/sbin:/usr/bin")
	t.Setenv("NDAGENT_TEST_KEEP", "kept")

	cmd := pkgCmd(context.Background(), "install", "-y", "os-example")

	if filepath.Base(cmd.Path) != "pkg" || strings.Join(cmd.Args[1:], " ") != "install -y os-example" {
		t.Errorf("command %q %q", cmd.Path, cmd.Args)
	}
	var paths []string
	kept := false
	for _, kv := range cmd.Env {
		if strings.HasPrefix(kv, "PATH=") {
			paths = append(paths, kv)
		}
		kept = kept || kv == "NDAGENT_TEST_KEEP=kept"
	}
	if len(paths) != 1 || paths[0] != "PATH="+devicePATHLiteral {
		t.Errorf("PATH entries %q, want exactly [PATH=%s]: pkg's scripts run with pkg's environment", paths, devicePATHLiteral)
	}
	if !kept {
		t.Error("the rest of the environment was not passed on")
	}
}

// Every pkg(8) spawn of the package goes through pkgCmd, so none of them hands
// the package scripts the agent's stripped PATH.
func TestEveryPkgSpawnUsesPkgCmd(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	found := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "exec" || !strings.HasPrefix(sel.Sel.Name, "Command") {
					return true
				}
				found++
				if fn.Name.Name != "pkgCmd" {
					t.Errorf("%s: %s builds a command with exec.%s; use pkgCmd", fset.Position(call.Pos()), fn.Name.Name, sel.Sel.Name)
				}
				return true
			})
		}
	}
	if found == 0 {
		t.Fatal("no exec.Command call found: the scan looked in the wrong place")
	}
}
