package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// useApplyRecord points the record at a file in a temporary directory that owes
// the given services (none when empty), for the rest of the test.
func useApplyRecord(t *testing.T, owed ...applyService) {
	t.Helper()
	useNoApplyRecord(t)
	f := applyOwedFile{V: applyOwedVersion, Owed: map[applyService]string{}}
	for _, s := range owed {
		f.Owed[s] = "2026-11-13T00:00:00Z"
	}
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(applyOwedPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// useNoApplyRecord points the record at a file that does not exist yet.
func useNoApplyRecord(t *testing.T) {
	t.Helper()
	prev := applyOwedPath
	applyOwedPath = filepath.Join(t.TempDir(), "apply-owed.json")
	t.Cleanup(func() { applyOwedPath = prev })
}

// syncCtx is what HandleSyncAPI gives the executors: the record, loaded for
// this SYNC.
func syncCtx() context.Context {
	return loadApplyOwed().attach(context.Background())
}

// recordOwes reads the services the record on disk owes.
func recordOwes(t *testing.T) map[applyService]bool {
	t.Helper()
	owes, err := readRecordOwes()
	if err != nil {
		t.Fatal(err)
	}
	return owes
}

func readRecordOwes() (map[applyService]bool, error) {
	data, err := os.ReadFile(applyOwedPath)
	if err != nil {
		return nil, fmt.Errorf("read the record: %w", err)
	}
	var f applyOwedFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("decode the record: %w", err)
	}
	owes := map[applyService]bool{}
	for s := range f.Owed {
		owes[s] = true
	}
	return owes, nil
}

func applyItemOf(results []SyncAPIItemResult, itemType string) *SyncAPIItemResult {
	for i := range results {
		if results[i].Type == itemType && results[i].Action == "apply" {
			return &results[i]
		}
	}
	return nil
}

// A record that says nothing about what came before owes every service: the
// apply an earlier agent or an earlier SYNC left owed is never lost.
func TestApplyOwed_ARecordThatSaysNothingOwesEveryService(t *testing.T) {
	for name, content := range map[string]string{
		"missing":       "",
		"not JSON":      "{",
		"other version": `{"v":2,"owed":{}}`,
	} {
		t.Run(name, func(t *testing.T) {
			useNoApplyRecord(t)
			if content != "" {
				if err := os.WriteFile(applyOwedPath, []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			a := loadApplyOwed()
			for _, s := range applyServices {
				if apply, owedOnly := a.due(s); !apply || !owedOnly {
					t.Errorf("%s: due = %v, %v; want applied as owed", s, apply, owedOnly)
				}
			}
			if content == "" {
				return
			}
			// An unreadable record is replaced at once, with its guesses.
			if owes := recordOwes(t); len(owes) != len(applyServices) {
				t.Errorf("the replaced record owes %v, want every service", owes)
			}
			if next := loadApplyOwed(); !next.guessed[applyZabbix] {
				t.Error("the replaced record does not keep its entries as guesses")
			}
		})
	}
}

// Every API path the client sends under a module whose writes owe an apply
// maps to its service, or is one that owes nothing: a write endpoint added
// under a new controller would otherwise be left unapplied without anyone
// noticing.
func TestApplyOwed_EveryPathOfAnAppliedModuleIsMapped(t *testing.T) {
	owesNothing := map[string]bool{
		"/firewall/alias/reconfigure":      true,
		"/firewall/filter/apply":           true,
		"/firewall/group/search_item":      true, // a read
		"/unbound/service/reconfigure":     true,
		"/unbound/service/status":          true, // a read
		"/zabbixagent/service/reconfigure": true,
		"/zabbixagent/service/status":      true, // a read
		"/wireguard/service/reconfigure":   true,
	}
	dir := filepath.Join("..", "opnapi")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			path, err := strconv.Unquote(lit.Value)
			if err != nil || !strings.HasPrefix(path, "/") {
				return true
			}
			switch module, _, _ := strings.Cut(strings.TrimPrefix(path, "/"), "/"); module {
			case "firewall", "unbound", "zabbixagent", "wireguard":
			default:
				return true
			}
			if i := strings.IndexAny(path, "%?"); i >= 0 {
				path = path[:i]
			}
			found++
			if applyServiceOf(path) == "" && !owesNothing[path] {
				t.Errorf("%s: %s maps to no service; add its prefix to applyWritePrefixes, or to this test's list if it owes no apply", name, path)
			}
			return true
		})
	}
	if found < 40 {
		t.Fatalf("found %d paths; this check would pass vacuously", found)
	}
}

func TestApplyOwed_AnEmptyRecordOwesNothing(t *testing.T) {
	useApplyRecord(t)
	a := loadApplyOwed()
	for _, s := range applyServices {
		if apply, _ := a.due(s); apply {
			t.Errorf("%s is due on a record that owes nothing", s)
		}
	}
}

// Without a record (the executors called on their own) every service is
// applied, as before the record existed.
func TestApplyOwed_WithoutARecordEverythingIsApplied(t *testing.T) {
	var a *applyOwed
	if apply, owedOnly := a.due(applyUnbound); !apply || owedOnly {
		t.Errorf("due = %v, %v; want applied, not as owed", apply, owedOnly)
	}
	a.applied(applyUnbound)
	a.gone(applyZabbix)
}

func TestApplyOwed_WritesOweTheirServiceAndNothingElseDoes(t *testing.T) {
	for path, want := range map[string]applyService{
		"/firewall/alias/setItem/x":             applyFirewallAliases,
		"/firewall/alias/delItem/x":             applyFirewallAliases,
		"/firewall/filter/setRule/x":            applyFirewallRules,
		"/firewall/filter/toggleRule/x?enabled": applyFirewallRules,
		"/unbound/settings/addHostOverride":     applyUnbound,
		"/unbound/settings/delAcl/x":            applyUnbound,
		"/zabbixagent/settings/set":             applyZabbix,
		"/zabbixagent/settings/delAlias/x":      applyZabbix,
		"/wireguard/general/set":                applyWireGuard,
		"/wireguard/server/add_server":          applyWireGuard,
		"/wireguard/client/del_client/x":        applyWireGuard,
		"/firewall/alias/reconfigure":           "",
		"/firewall/filter/apply":                "",
		"/unbound/service/reconfigure":          "",
		"/zabbixagent/service/reconfigure":      "",
		"/wireguard/service/reconfigure":        "",
		"/crowdsec/general/set":                 "",
		"/auth/user/set/x":                      "",
		"/trust/cert/add":                       "",
	} {
		if got := applyServiceOf(path); got != want {
			t.Errorf("%s owes %q, want %q", path, got, want)
		}
	}
}

// The entry is on disk when the write reaches the device, so an agent that
// stops before the apply leaves it owed. A read and the apply itself enter
// nothing.
func TestApplyOwed_AWriteIsRecordedBeforeItIsSent(t *testing.T) {
	useApplyRecord(t)
	var seen []map[applyService]bool
	var readErr error
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		owes, err := readRecordOwes()
		if err != nil && readErr == nil {
			readErr = err
		}
		seen = append(seen, owes)
		_, _ = w.Write([]byte(`{"result":"deleted","status":"ok","rows":[]}`))
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	client := opnapi.NewClient(server.URL, "key", "secret", true)
	ctx := syncCtx()

	_, _ = client.ListAllHostOverrides(ctx)
	_ = client.ReconfigureUnbound(ctx)
	if len(seen) != 2 || len(seen[0]) != 0 || len(seen[1]) != 0 {
		t.Fatalf("a search and an apply entered %v", seen)
	}
	seen = nil
	_ = client.DeleteHostOverride(ctx, "x")
	_ = client.DeleteRule(ctx, "x")
	_ = client.DeleteZabbixAlias(ctx, "x")
	if readErr != nil {
		t.Fatal(readErr)
	}
	for i, want := range []applyService{applyUnbound, applyFirewallRules, applyZabbix} {
		if i >= len(seen) || !seen[i][want] {
			t.Errorf("write %d reached the device with the record %v, want %s in it", i, seen, want)
		}
	}
}

// An entry that cannot be saved does not stop the write, and the SYNC still
// applies what it wrote.
func TestApplyOwed_AnUnsavableRecordStillApplies(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	prev := applyOwedPath
	applyOwedPath = filepath.Join(blocker, "apply-owed.json")
	t.Cleanup(func() { applyOwedPath = prev })
	a := newApplyOwed()

	a.noteWrite("POST", "/unbound/settings/setAcl/x")

	if apply, owedOnly := a.due(applyUnbound); !apply || owedOnly {
		t.Errorf("due = %v, %v; want applied for the write", apply, owedOnly)
	}
}

func TestApplyOwed_AppliedAndGoneClearTheEntry(t *testing.T) {
	useApplyRecord(t, applyUnbound, applyZabbix, applyWireGuard)
	a := loadApplyOwed()
	a.applied(applyUnbound)
	a.gone(applyZabbix)
	if owes := recordOwes(t); len(owes) != 1 || !owes[applyWireGuard] {
		t.Errorf("record owes %v, want wireguard only", owes)
	}
	if apply, _ := a.due(applyUnbound); apply {
		t.Error("an applied service is still due")
	}
}

// The first SYNC after the record is gone applies everything once and leaves
// a record that owes nothing.
func TestApplyOwed_AMissingRecordIsWrittenAsItIsCaughtUp(t *testing.T) {
	useNoApplyRecord(t)
	a := loadApplyOwed()
	for _, s := range applyServices {
		a.applied(s)
	}
	if owes := recordOwes(t); len(owes) != 0 {
		t.Errorf("record owes %v after every service was applied", owes)
	}
}

// The alias reconfigure (a filter reload, the alias tables, a cron restart)
// runs only after an alias was written and the filter apply only after a rule
// was, and a SYNC with nothing new runs neither. A failed filter apply is
// retried by the next SYNC (NDAgent-go#248).
func TestExecuteSyncAPI_AppliesOnlyWhatItWrote(t *testing.T) {
	useApplyRecord(t)
	device := newFakeRuleDevice(t, ruleTemplate(t), nil)
	aliases := func(content string) []APIAliasPayload {
		return []APIAliasPayload{desiredAlias(t, "hosts", `{"uuid":"`+testAliasUUID+`","name":"hosts","type":"host","content":"`+content+`"}`)}
	}
	rules := func(action string) []APIRulePayload {
		return []APIRulePayload{desiredRule(t, "r", RulePositionPrepend, 100, `{"uuid":"`+ruleA+`","action":"`+action+`","interface":"lan"}`)}
	}
	ruleApplies := func() int {
		n := 0
		for _, w := range device.writes {
			if w == "apply" {
				n++
			}
		}
		return n
	}
	pass := func(name string, a []APIAliasPayload, r []APIRulePayload, wantAlias, wantRule int) SyncAPIResult {
		t.Helper()
		alias0, rule0 := device.aliasApplies, ruleApplies()
		result := executeSyncAPI(syncCtx(), device.client, a, r)
		if gotAlias, gotRule := device.aliasApplies-alias0, ruleApplies()-rule0; gotAlias != wantAlias || gotRule != wantRule {
			t.Errorf("%s: alias reconfigures %d, filter applies %d; want %d and %d", name, gotAlias, gotRule, wantAlias, wantRule)
		}
		return result
	}

	first := pass("first", aliases("192.0.2.1"), rules("pass"), 1, 1)
	if !first.Success {
		t.Fatalf("first sync failed: %v", first.Errors)
	}
	for _, itemType := range []string{"alias_apply", "rule_apply"} {
		if item := applyItemOf(first.Results, itemType); item == nil || item.Status != "success" || item.Code != "" {
			t.Errorf("%s item = %+v, want a success without a code", itemType, item)
		}
	}
	noop := pass("nothing new", aliases("192.0.2.1"), rules("pass"), 0, 0)
	if applyItemOf(noop.Results, "alias_apply") != nil || applyItemOf(noop.Results, "rule_apply") != nil {
		t.Errorf("a SYNC with nothing new reported an apply: %+v", noop.Results)
	}
	pass("alias changed", aliases("192.0.2.2"), rules("pass"), 1, 0)
	pass("rule changed", aliases("192.0.2.2"), rules("block"), 0, 1)

	device.ruleApplyFails = true
	failed := pass("apply fails", aliases("192.0.2.2"), rules("pass"), 0, 1)
	if failed.Success || !recordOwes(t)[applyFirewallRules] {
		t.Fatalf("a failed filter apply: success=%v, record %v", failed.Success, recordOwes(t))
	}
	device.ruleApplyFails = false
	retry := pass("after the failed apply", aliases("192.0.2.2"), rules("pass"), 0, 1)
	if item := applyItemOf(retry.Results, "rule_apply"); item == nil || item.Code != codeApplyOwed {
		t.Errorf("rule_apply item = %+v, want code %s", item, codeApplyOwed)
	}
	pass("after the retry", aliases("192.0.2.2"), rules("pass"), 0, 0)
}

// A plugin that is not installed has nothing to apply: an apply its service
// owes is dropped instead of being tried on every SYNC.
func TestApplyOwed_APluginThatIsNotInstalledOwesNothing(t *testing.T) {
	useApplyRecord(t, applyZabbix, applyWireGuard)
	server := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(server.Close)
	client := opnapi.NewClient(server.URL, "key", "secret", true)
	ctx := syncCtx()

	executeSyncZabbix(ctx, client, nil, nil, nil, false)
	executeSyncVPN(ctx, client, nil)

	if owes := recordOwes(t); len(owes) != 0 {
		t.Errorf("record owes %v for plugins that are not installed", owes)
	}
}

// WireGuard is reconfigured only after a write: a SYNC of networks the device
// already holds leaves it alone.
func TestExecuteSyncVPN_ReconfiguresOnlyAfterAWrite(t *testing.T) {
	useApplyRecord(t)
	store, client := newWireGuardStore(t)
	networks := testVPNNetworks()

	first := executeSyncVPN(syncCtx(), client, networks)
	if !first.Success || store.reconfigures != 1 {
		t.Fatalf("first sync: success=%v reconfigures=%d errors=%v", first.Success, store.reconfigures, first.Errors)
	}
	second := executeSyncVPN(syncCtx(), client, networks)
	if !second.Success || store.reconfigures != 1 {
		t.Errorf("a SYNC with nothing new: success=%v reconfigures=%d", second.Success, store.reconfigures)
	}
	if item := applyItemOf(second.Results, "wg_apply"); item != nil {
		t.Errorf("a skipped apply was reported: %+v", item)
	}
}

// A missing record owes only the services in which NetDefense has something:
// a Zabbix agent or an Unbound the device runs without any managed object, and
// that the SYNC wants nothing in, is not restarted by the first SYNC of this
// version, nor failed on every SYNC when its restart fails.
func TestApplyOwed_AMissingRecordSparesWhatNetDefenseHoldsNothingIn(t *testing.T) {
	useNoApplyRecord(t)
	zabbix := newZabbixNoopServer(t, nil, nil, nil)
	executeSyncZabbix(syncCtx(), zabbix.client, nil, nil, nil, false)
	if zabbix.reconfigs != 0 {
		t.Errorf("a Zabbix agent with nothing managed was reconfigured %d times", zabbix.reconfigs)
	}
	if owes := recordOwes(t); owes[applyZabbix] {
		t.Errorf("record still owes %v", owes)
	}

	useNoApplyRecord(t)
	device := newFakeRuleDevice(t, ruleTemplate(t), nil)
	executeSyncAPI(syncCtx(), device.client, nil, nil)
	if device.aliasApplies != 0 || len(device.writes) != 0 {
		t.Errorf("a firewall with nothing managed: alias reconfigures %d, writes %v", device.aliasApplies, device.writes)
	}
	if owes := recordOwes(t); owes[applyFirewallAliases] || owes[applyFirewallRules] {
		t.Errorf("record still owes %v", owes)
	}

	useNoApplyRecord(t)
	wireguard, wgClient := newWireGuardStore(t)
	executeSyncVPN(syncCtx(), wgClient, nil)
	if wireguard.reconfigures != 0 {
		t.Errorf("a WireGuard with nothing managed was reconfigured %d times", wireguard.reconfigures)
	}
	if owes := recordOwes(t); owes[applyWireGuard] {
		t.Errorf("record still owes %v", owes)
	}

	useNoApplyRecord(t)
	unbound := newUnboundStoreAt(t)
	runUnbound(unbound, unboundSnippets{})
	if n := unbound.takeReconfigures(); n != 0 {
		t.Errorf("an Unbound with nothing managed was reconfigured %d times", n)
	}
	if owes := recordOwes(t); owes[applyUnbound] {
		t.Errorf("record still owes %v", owes)
	}

	snippets := noopUnboundSnippets(t, `["192.168.1.0/24"]`)
	runUnbound(unbound, snippets)
	unbound.takeWrites()
	unbound.takeReconfigures()
	useNoApplyRecord(t)
	result := runUnbound(unbound, snippets)
	if got := unbound.takeWrites(); len(got) != 0 {
		t.Fatalf("wrote %v to a device that holds what the SYNC wants", got)
	}
	if n := unbound.takeReconfigures(); n != 1 {
		t.Errorf("an Unbound holding managed rows was reconfigured %d times, want once", n)
	}
	if item := applyItemOf(result.Results, "unbound_apply"); item == nil || item.Code != codeApplyOwed {
		t.Errorf("apply item = %+v, want code %s", item, codeApplyOwed)
	}
}

// A SYNC cut short after the record was written from a missing one leaves its
// guesses as guesses: the next SYNC still spares a service NetDefense holds
// nothing in, and still applies the write the cut SYNC made.
func TestApplyOwed_ASYNCCutShortKeepsItsGuessesAsGuesses(t *testing.T) {
	useNoApplyRecord(t)
	cut := loadApplyOwed()
	cut.noteWrite("POST", "/firewall/alias/setItem/x")

	next := loadApplyOwed()
	next.unused(applyZabbix)
	next.unused(applyFirewallAliases)
	if apply, _ := next.due(applyZabbix); apply {
		t.Error("a guess the cut SYNC saved became an entry the agent recorded")
	}
	if apply, owedOnly := next.due(applyFirewallAliases); !apply || !owedOnly {
		t.Errorf("the alias write of the cut SYNC: due = %v, %v; want applied as owed", apply, owedOnly)
	}
	if owes := recordOwes(t); owes[applyZabbix] || !owes[applyFirewallAliases] {
		t.Errorf("record owes %v", owes)
	}
}

// An entry this agent recorded is applied even when nothing is managed any
// more: the SYNC that deleted the last row and failed its reconfigure left
// the row in the running service.
func TestApplyOwed_ARecordedEntryIsAppliedWhenNothingIsLeft(t *testing.T) {
	unbound := newUnboundStore(t)
	useApplyRecord(t, applyUnbound)
	result := runUnbound(unbound, unboundSnippets{})
	if n := unbound.takeReconfigures(); n != 1 {
		t.Errorf("reconfigured %d times, want once", n)
	}
	if item := applyItemOf(result.Results, "unbound_apply"); item == nil || item.Code != codeApplyOwed {
		t.Errorf("apply item = %+v, want code %s", item, codeApplyOwed)
	}
}

// The record never creates the agent's directory, which a decommission
// removes.
func TestApplyOwed_ASaveDoesNotCreateTheDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ndagent")
	prev := applyOwedPath
	applyOwedPath = filepath.Join(dir, "apply-owed.json")
	t.Cleanup(func() { applyOwedPath = prev })
	a := newApplyOwed()

	a.noteWrite("POST", "/unbound/settings/setAcl/x")

	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("the directory exists after a save: %v", err)
	}
}

// HandleSyncAPI and the decommission give their executors the record before
// the first of them runs; without it every service is applied on every SYNC
// again, and no executor test would notice. An AST check, as
// connect_stream_lifetime_test.go: the link is between files.
func TestApplyOwed_TheRecordIsAttachedBeforeTheExecutorsRun(t *testing.T) {
	for _, tc := range []struct{ file, function, firstRun string }{
		{"sync_api.go", "HandleSyncAPI", "executeSyncTrust"},
		{"decommission.go", "Run", "reconcileFamily"},
	} {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, tc.file, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", tc.file, err)
		}
		attached, firstRun := token.NoPos, token.NoPos
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name != tc.function || fn.Body == nil {
				continue
			}
			// The attach must be a statement of the function itself, not of a
			// branch some SYNCs skip.
			for _, stmt := range fn.Body.List {
				if n, ok := stmt.(*ast.AssignStmt); ok && len(n.Lhs) == 1 && len(n.Rhs) == 1 &&
					isIdent(n.Lhs[0], "ctx") && isAttachOfLoad(n.Rhs[0]) && attached == token.NoPos {
					attached = n.Pos()
				}
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok && calledName(call) == tc.firstRun && firstRun == token.NoPos {
					firstRun = call.Pos()
				}
				return true
			})
		}
		switch {
		case attached == token.NoPos:
			t.Errorf("%s: %s does not assign ctx = loadApplyOwed().attach(ctx) in its own body", tc.file, tc.function)
		case firstRun == token.NoPos:
			t.Errorf("%s: %s does not call %s", tc.file, tc.function, tc.firstRun)
		case attached > firstRun:
			t.Errorf("%s: %s attaches the record at %s, after %s at %s", tc.file, tc.function, fset.Position(attached), tc.firstRun, fset.Position(firstRun))
		}
	}
}

func isIdent(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}

func calledName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		return fn.Sel.Name
	}
	return ""
}

// isAttachOfLoad matches loadApplyOwed().attach(ctx).
func isAttachOfLoad(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 || !isIdent(call.Args[0], "ctx") {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "attach" {
		return false
	}
	inner, ok := sel.X.(*ast.CallExpr)
	return ok && calledName(inner) == "loadApplyOwed"
}
