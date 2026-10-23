package tasks

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// standInPHP makes RunPHPConfigHelper run a shell script in place of PHP. The
// script records its arguments in argsFile before body runs.
func standInPHP(t *testing.T, body string) (script, argsFile string) {
	t.Helper()
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args")
	script = filepath.Join(dir, "helper.sh")
	src := "#!/bin/sh\necho \"$@\" > '" + argsFile + "'\n" + body
	if err := os.WriteFile(script, []byte(src), 0o755); err != nil {
		t.Fatal(err)
	}
	prev := phpConfigHelperInterpreter
	phpConfigHelperInterpreter = "/bin/sh"
	t.Cleanup(func() { phpConfigHelperInterpreter = prev })
	return script, argsFile
}

func TestRunPHPConfigHelper_ReturnsTheResultItReports(t *testing.T) {
	script, args := standInPHP(t, `echo 'a line before the report'; echo '{"result":"ok","cleared":true}'`+"\n")
	result, err := RunPHPConfigHelper(context.Background(), script, "--json")
	if err != nil || result != "ok" {
		t.Fatalf("result %q, error %v", result, err)
	}
	if got, _ := os.ReadFile(args); strings.TrimSpace(string(got)) != "--json" {
		t.Errorf("arguments %q", got)
	}
}

func TestRunPHPConfigHelper_ANonZeroExitIsAnErrorThatCarriesTheReport(t *testing.T) {
	script, _ := standInPHP(t, `echo '{"result":"failed","message":"the config lock was not available within 30 seconds"}'; exit 22`+"\n")
	result, err := RunPHPConfigHelper(context.Background(), script, "--json")
	if err == nil || !strings.Contains(err.Error(), "helper.sh exited 22: failed the config lock was not available") {
		t.Fatalf("error %v", err)
	}
	if result != "failed" {
		t.Errorf("result %q", result)
	}
}

// A script that dies before its report (a PHP fatal error, printed on stdout on
// OPNsense) says why in the error, without the stack trace, whose frames can
// carry call arguments.
func TestRunPHPConfigHelper_AFailureWithoutAReportSaysWhatTheScriptSaid(t *testing.T) {
	script, _ := standInPHP(t, `printf '\nFatal error: Uncaught Error: Class "OPNsense\\NetDefense\\ConfigTransaction" not found in /usr/local/opnsense/scripts/OPNsense/NetDefense/configure.php:54\nStack trace:\n#0 /x.php(9): f('"'"'argument-in-a-frame'"'"')\n#1 {main}\n  thrown in /x.php on line 54\n'; exit 255`+"\n")
	result, err := RunPHPConfigHelper(context.Background(), script, "--json")
	if err == nil {
		t.Fatal("a script that exited 255 was not an error")
	}
	msg := err.Error()
	for _, want := range []string{"helper.sh exited 255 without a report", `Class "OPNsense\NetDefense\ConfigTransaction" not found`, "configure.php:54"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q, want it to contain %q", msg, want)
		}
	}
	for _, unwanted := range []string{"Stack trace", "argument-in-a-frame", "\n"} {
		if strings.Contains(msg, unwanted) {
			t.Errorf("error %q contains %q", msg, unwanted)
		}
	}
	if result != "" {
		t.Errorf("result %q from a script that printed no report", result)
	}
}

func TestHelperOutputReason(t *testing.T) {
	cases := []struct{ out, want string }{
		{"", "no output"},
		{"\n  \n", "no output"},
		{"PHP Warning:  x\n\tin y\n", "PHP Warning: x in y"},
		{"bad \x1b[31mcolour\x00\n", "bad [31mcolour"},
	}
	for _, tc := range cases {
		if got := helperOutputReason([]byte(tc.out)); got != tc.want {
			t.Errorf("helperOutputReason(%q) = %q, want %q", tc.out, got, tc.want)
		}
	}

	// A long output keeps its end, cut at a character boundary.
	got := helperOutputReason([]byte(strings.Repeat("é", 400) + " the end"))
	kept := strings.TrimPrefix(got, "...")
	if !strings.HasPrefix(got, "...") || !strings.HasSuffix(got, " the end") || !utf8.ValidString(got) ||
		len(kept) > helperReasonMax || len(kept) < helperReasonMax-utf8.UTFMax {
		t.Errorf("a long output gave %q (%d bytes kept), want its last %d bytes or so, whole characters", got, len(kept), helperReasonMax)
	}
}

func TestRunPHPConfigHelper_ADoneContextKeepsItFromStarting(t *testing.T) {
	script, args := standInPHP(t, `echo '{"result":"ok"}'`+"\n")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := RunPHPConfigHelper(ctx, script, "--json"); !errors.Is(err, context.Canceled) {
		t.Fatalf("error %v, want context.Canceled", err)
	}
	if _, err := os.Stat(args); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the script ran under a context that was already done: %v", err)
	}
}

// The script may be in the middle of Config::save() when the context ends:
// killing it there leaves config.xml cut short.
func TestRunPHPConfigHelper_AContextThatEndsWhileItRunsDoesNotReachIt(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "finished")
	script, _ := standInPHP(t, "sleep 0.5\ntouch '"+marker+"'\necho '{\"result\":\"ok\"}'\n")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	result, err := RunPHPConfigHelper(ctx, script, "--json")
	if err != nil || result != "ok" {
		t.Fatalf("result %q, error %v: the script was stopped when the context ended", result, err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("the script did not run to its end: %v", err)
	}
}

func standInConfigure(t *testing.T, body string) (argsFile string) {
	t.Helper()
	script, args := standInPHP(t, body)
	prev := configureScript
	configureScript = script
	t.Cleanup(func() { configureScript = prev })
	return args
}

// The decommission passes the agent's shutdown context; a stop while
// configure.php removes the accounts must not kill it.
func TestDeprovisionLocalAccounts_SurvivesAStopWhileItRuns(t *testing.T) {
	args := standInConfigure(t, "sleep 0.5\necho '{\"result\":\"ok\",\"removed\":true}'\n")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := deprovisionLocalAccounts(ctx); err != nil {
		t.Fatalf("error %v", err)
	}
	if got, _ := os.ReadFile(args); strings.TrimSpace(string(got)) != "--deprovision-accounts --json" {
		t.Errorf("arguments %q", got)
	}
}

func TestResetPluginIdentity_AFailureIsReportedWithTheHelpersMessage(t *testing.T) {
	args := standInConfigure(t, `echo '{"result":"failed","message":"config lock unavailable"}'; exit 22`+"\n")
	err := resetPluginIdentity(context.Background())
	if err == nil || !strings.Contains(err.Error(), "exited 22: failed config lock unavailable") {
		t.Fatalf("error %v", err)
	}
	if got, _ := os.ReadFile(args); strings.TrimSpace(string(got)) != "--reset-identity --json" {
		t.Errorf("arguments %q", got)
	}
}

// TestPHPScriptsAreNeverStartedWithExecCommand keeps the plugin's PHP out of
// exec.Command and exec.CommandContext anywhere in the agent. Those kill
// with SIGKILL when their context ends, and a kill during Config::save()
// leaves config.xml cut short; a PHP script runs under runHelperSubprocess
// (RunPHPConfigHelper, runPHPHelper). An argument counts as PHP when it is a
// string naming a .php file or the PHP binary, a name declared as one, or a
// name that says php.
func TestPHPScriptsAreNeverStartedWithExecCommand(t *testing.T) {
	fset := token.NewFileSet()
	var files []*ast.File
	for _, root := range []string{"..", filepath.Join("..", "..", "cmd")} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			files = append(files, f)
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", root, err)
		}
	}

	isPHPString := func(e ast.Expr) bool {
		lit, ok := e.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return false
		}
		v, err := strconv.Unquote(lit.Value)
		return err == nil && (strings.HasSuffix(v, ".php") || strings.HasSuffix(v, "/bin/php"))
	}

	// Names declared as a PHP path, directly or through another such name.
	phpNames := map[string]bool{}
	for grew := true; grew; {
		grew = false
		for _, f := range files {
			ast.Inspect(f, func(n ast.Node) bool {
				spec, ok := n.(*ast.ValueSpec)
				if !ok {
					return true
				}
				for i, name := range spec.Names {
					if i >= len(spec.Values) || phpNames[name.Name] {
						continue
					}
					v := spec.Values[i]
					if id, ok := v.(*ast.Ident); isPHPString(v) || (ok && phpNames[id.Name]) {
						phpNames[name.Name] = true
						grew = true
					}
				}
				return true
			})
		}
	}
	if !phpNames["phpInterpreter"] || !phpNames["configureScript"] {
		t.Fatalf("the scan did not resolve the known PHP names (got %v): it would find nothing", phpNames)
	}

	execCalls := 0
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "exec" || (sel.Sel.Name != "Command" && sel.Sel.Name != "CommandContext") {
				return true
			}
			execCalls++
			for _, arg := range call.Args {
				id, isIdent := arg.(*ast.Ident)
				if isPHPString(arg) || (isIdent && (phpNames[id.Name] || strings.Contains(strings.ToLower(id.Name), "php"))) {
					t.Errorf("%s starts PHP with exec.%s; run it with RunPHPConfigHelper (or runPHPHelper) instead",
						fset.Position(call.Pos()), sel.Sel.Name)
					break
				}
			}
			return true
		})
	}
	if execCalls == 0 {
		t.Fatal("no exec.Command call found at all: the scan looked in the wrong place")
	}
}
