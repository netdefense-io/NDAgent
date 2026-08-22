package tasks

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/netdefense-io/ndagent/internal/pkgmgr"
	"github.com/netdefense-io/ndagent/internal/pkgrepo"
)

// orderLog records the order pkg operations were attempted in. The execution
// order is a documented contract, not an implementation detail, so it is
// asserted directly rather than inferred from side effects.
type orderLog struct {
	mu    sync.Mutex
	calls []string
}

func (c *orderLog) add(s string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, s)
}

func (c *orderLog) all() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.calls...)
}

func (c *orderLog) indexOf(prefix string) int {
	for i, s := range c.all() {
		if strings.HasPrefix(s, prefix) {
			return i
		}
	}
	return -1
}

// stubPkg wires every pkg entry point to the log and returns a cleanup.
func stubPkg(t *testing.T, log *orderLog, installed map[string]bool) {
	t.Helper()
	if installed == nil {
		installed = map[string]bool{}
	}
	prevUpdate := pkgmgr.SetUpdateFunc(func(ctx context.Context) error {
		log.add("update")
		return nil
	})
	prevIs := pkgmgr.SetIsInstalledFunc(func(ctx context.Context, name string) (bool, error) {
		return installed[name], nil
	})
	prevInstall := pkgmgr.SetInstallFunc(func(ctx context.Context, name string) pkgmgr.MutateOutcome {
		log.add("install:" + name)
		return pkgmgr.MutateOutcome{Action: pkgmgr.ActionInstalled}
	})
	prevRemove := pkgmgr.SetRemoveFunc(func(ctx context.Context, name string) pkgmgr.MutateOutcome {
		log.add("delete:" + name)
		return pkgmgr.MutateOutcome{Action: pkgmgr.ActionRemoved}
	})
	prevAdd := pkgmgr.SetAddURLFunc(func(ctx context.Context, url string, force bool) pkgmgr.MutateOutcome {
		log.add("addurl:" + url)
		return pkgmgr.MutateOutcome{Action: pkgmgr.ActionInstalled}
	})
	prevOffered := pkgmgr.SetOfferedByFunc(func(ctx context.Context, name string) ([]string, error) {
		log.add("offeredby:" + name)
		return []string{"OPNsense"}, nil
	})
	t.Cleanup(func() {
		pkgmgr.SetUpdateFunc(prevUpdate)
		pkgmgr.SetIsInstalledFunc(prevIs)
		pkgmgr.SetInstallFunc(prevInstall)
		pkgmgr.SetRemoveFunc(prevRemove)
		pkgmgr.SetAddURLFunc(prevAdd)
		pkgmgr.SetOfferedByFunc(prevOffered)
	})
	t.Cleanup(pkgrepo.SetRootForTest(t.TempDir()))
}

func payloadWith(t *testing.T, body string) *softwarePayload {
	t.Helper()
	var outer map[string]interface{}
	if err := json.Unmarshal([]byte(body), &outer); err != nil {
		t.Fatalf("bad test payload: %v", err)
	}
	sp, err := parseSoftwarePayload(outer)
	if err != nil {
		t.Fatalf("parseSoftwarePayload: %v", err)
	}
	return sp
}

const repoJSON = `{
  "name": "mimugmail",
  "url": "https://opn-repo.example/repo/${ABI}",
  "priority": 5,
  "enabled": true,
  "signature": {"type": "fingerprints",
                "fingerprints": [{"function": "sha256", "fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}
}`

// The documented six-phase order. Repo work brackets the existing sequence;
// it does not reorder it.
func TestExecutionOrderIsScanReconcileUpdateAbsentPresentExternal(t *testing.T) {
	log := &orderLog{}
	stubPkg(t, log, map[string]bool{"old-pkg": true})

	sp := payloadWith(t, `{"software":{
		"present":["new-pkg"],
		"absent":["old-pkg"],
		"repositories":[`+repoJSON+`],
		"external":[{"name":"ext","version":"1.0","url":"https://x.example/ext-1.0.pkg","force":false}],
		"allow_unverified":false}}`)

	res := executeSyncSoftware(context.Background(), sp)
	if !res.Success {
		t.Fatalf("expected success, errors=%v", res.Errors)
	}

	order := []string{"update", "delete:old-pkg", "install:new-pkg", "addurl:https://x.example/ext-1.0.pkg"}
	idx := make([]int, len(order))
	for i, want := range order {
		idx[i] = log.indexOf(want)
		if idx[i] < 0 {
			t.Fatalf("%q never happened; calls=%v", want, log.all())
		}
	}
	for i := 1; i < len(idx); i++ {
		if idx[i] < idx[i-1] {
			t.Fatalf("%q ran before %q; calls=%v", order[i], order[i-1], log.all())
		}
	}

	// Repo config must be on disk before the catalog refresh, or the refresh
	// would not see the repository the policy just declared.
	if _, err := readConf(t, "mimugmail"); err != nil {
		t.Fatalf("repo config not written: %v", err)
	}
}

func readConf(t *testing.T, name string) (string, error) {
	t.Helper()
	b, err := osReadFile(pkgrepo.ConfPath(name))
	return string(b), err
}

// A foreign definition must stop the task before any pkg mutation happens.
func TestForeignConflictFailsBeforeAnyMutation(t *testing.T) {
	log := &orderLog{}
	stubPkg(t, log, nil)

	// An administrator's own file, no marker.
	if err := osMkdirAll(pkgrepo.ReposDirForTest()); err != nil {
		t.Fatal(err)
	}
	if err := osWriteFile(pkgrepo.ReposDirForTest()+"/mimugmail.conf",
		"mimugmail: {\n  url: \"https://elsewhere.example\"\n}\n"); err != nil {
		t.Fatal(err)
	}

	sp := payloadWith(t, `{"software":{
		"present":["new-pkg"],"absent":[],
		"repositories":[`+repoJSON+`],
		"allow_unverified":false}}`)

	res := executeSyncSoftware(context.Background(), sp)
	if res.Success {
		t.Fatal("a foreign duplicate must fail the task")
	}
	if calls := log.all(); len(calls) != 0 {
		t.Fatalf("no pkg mutation should have run, got %v", calls)
	}
	joined := strings.Join(res.Errors, " ")
	if !strings.Contains(joined, "mimugmail") || !strings.Contains(joined, "mimugmail.conf") {
		t.Errorf("error should name the repository and the offending file: %v", res.Errors)
	}
	if findAction(res, string(pkgmgr.ActionRepoConflict)) == nil {
		t.Errorf("expected a REPO_CONFLICT item, got %+v", res.Results)
	}
}

// The pre-existing contract, unchanged. This mirrors the assertion in
// sync_software_test.go and exists here to catch a reordering introduced by
// the repository work specifically.
func TestAbsentStillRunsBeforePresent(t *testing.T) {
	log := &orderLog{}
	stubPkg(t, log, map[string]bool{"old-pkg": true})

	sp := payloadWith(t, `{"software":{"present":["new-pkg"],"absent":["old-pkg"]}}`)
	res := executeSyncSoftware(context.Background(), sp)
	if !res.Success {
		t.Fatalf("errors=%v", res.Errors)
	}
	if d, i := log.indexOf("delete:old-pkg"), log.indexOf("install:new-pkg"); d < 0 || i < 0 || d > i {
		t.Fatalf("absent must precede present; calls=%v", log.all())
	}
}

// A payload with neither new key must behave exactly as before.
func TestPayloadWithoutNewKeysIsUnchanged(t *testing.T) {
	log := &orderLog{}
	stubPkg(t, log, nil)

	sp := payloadWith(t, `{"software":{"present":["p"],"absent":[]}}`)
	res := executeSyncSoftware(context.Background(), sp)
	if !res.Success {
		t.Fatalf("errors=%v", res.Errors)
	}
	if n := strings.Count(strings.Join(log.all(), " "), "update"); n != 1 {
		t.Errorf("expected exactly one catalog refresh, calls=%v", log.all())
	}
	for _, c := range log.all() {
		if strings.HasPrefix(c, "addurl:") {
			t.Errorf("no external work should happen: %v", log.all())
		}
	}
}

// Everything already satisfied: no mutation at all, and the task completes.
// The no-work-is-a-no-op rule.
func TestFullySatisfiedPolicyPerformsNoMutations(t *testing.T) {
	log := &orderLog{}
	stubPkg(t, log, map[string]bool{"p": true, "ext-1.0": true})

	sp := payloadWith(t, `{"software":{
		"present":["p"],"absent":[],
		"external":[{"name":"ext","version":"1.0","url":"https://x.example/ext-1.0.pkg","force":false}],
		"allow_unverified":false}}`)

	res := executeSyncSoftware(context.Background(), sp)
	if !res.Success {
		t.Fatalf("errors=%v", res.Errors)
	}
	for _, c := range log.all() {
		if strings.HasPrefix(c, "install:") || strings.HasPrefix(c, "delete:") || strings.HasPrefix(c, "addurl:") {
			t.Errorf("settled device should mutate nothing, got %v", log.all())
		}
	}
}

func TestExternalAlreadyAtVersionSkipsDownload(t *testing.T) {
	log := &orderLog{}
	stubPkg(t, log, map[string]bool{"ext-1.0": true})

	sp := payloadWith(t, `{"software":{"present":[],"absent":[],
		"external":[{"name":"ext","version":"1.0","url":"https://x.example/ext-1.0.pkg","force":false}]}}`)

	res := executeSyncSoftware(context.Background(), sp)
	if !res.Success {
		t.Fatalf("errors=%v", res.Errors)
	}
	if log.indexOf("addurl:") >= 0 {
		t.Errorf("no download expected when already at the declared version: %v", log.all())
	}
	if it := findAction(res, string(pkgmgr.ActionAlreadyPresent)); it == nil {
		t.Errorf("expected ALREADY_PRESENT for the satisfied external entry: %+v", res.Results)
	}
}

func TestExternalForceReinstallsEvenWhenPresent(t *testing.T) {
	log := &orderLog{}
	stubPkg(t, log, map[string]bool{"ext-1.0": true})

	sp := payloadWith(t, `{"software":{"present":[],"absent":[],
		"external":[{"name":"ext","version":"1.0","url":"https://x.example/ext-1.0.pkg","force":true}]}}`)

	if res := executeSyncSoftware(context.Background(), sp); !res.Success {
		t.Fatalf("errors=%v", res.Errors)
	}
	if log.indexOf("addurl:") < 0 {
		t.Errorf("force should reinstall: %v", log.all())
	}
}

// The shadow check refuses rather than letting pkg pick a winner.
func TestShadowedPackageFailsRatherThanInstalling(t *testing.T) {
	log := &orderLog{}
	stubPkg(t, log, nil)
	prev := pkgmgr.SetOfferedByFunc(func(ctx context.Context, name string) ([]string, error) {
		return []string{"OPNsense", "mimugmail"}, nil
	})
	t.Cleanup(func() { pkgmgr.SetOfferedByFunc(prev) })

	sp := payloadWith(t, `{"software":{"present":["os-haproxy"],"absent":[]}}`)
	res := executeSyncSoftware(context.Background(), sp)

	if res.Success {
		t.Fatal("an ambiguous install must fail the task")
	}
	if log.indexOf("install:os-haproxy") >= 0 {
		t.Errorf("shadowed package must not be installed: %v", log.all())
	}
	if findAction(res, string(pkgmgr.ActionShadowed)) == nil {
		t.Errorf("expected a SHADOWED item: %+v", res.Results)
	}
	joined := strings.Join(res.Errors, " ")
	if !strings.Contains(joined, "OPNsense") || !strings.Contains(joined, "mimugmail") {
		t.Errorf("error should name both repositories: %v", res.Errors)
	}
}

// Already-installed packages are not shadow-checked: CONSERVATIVE_UPGRADE
// governs their upgrade path, and re-checking would cost a query per package
// on every settled sync.
func TestShadowCheckOnlyRunsForPackagesBeingInstalled(t *testing.T) {
	log := &orderLog{}
	stubPkg(t, log, map[string]bool{"already": true})

	sp := payloadWith(t, `{"software":{"present":["already"],"absent":[]}}`)
	if res := executeSyncSoftware(context.Background(), sp); !res.Success {
		t.Fatalf("errors=%v", res.Errors)
	}
	if log.indexOf("offeredby:already") >= 0 {
		t.Errorf("settled package should not be shadow-checked: %v", log.all())
	}
}

func TestUnsignedRepoRefusedWhenOrgDidNotOptIn(t *testing.T) {
	log := &orderLog{}
	stubPkg(t, log, nil)

	sp := payloadWith(t, `{"software":{"present":[],"absent":[],
		"repositories":[{"name":"r","url":"https://x.example/repo","priority":1,"enabled":true,
		                 "signature":{"type":"none"}}],
		"allow_unverified":false}}`)

	res := executeSyncSoftware(context.Background(), sp)
	if res.Success {
		t.Fatal("unsigned repository must be refused without the org opt-in")
	}
	if log.indexOf("update") >= 0 {
		t.Errorf("nothing should have run after the refusal: %v", log.all())
	}
}

func TestUnsignedRepoAllowedWhenOrgOptedIn(t *testing.T) {
	log := &orderLog{}
	stubPkg(t, log, nil)

	sp := payloadWith(t, `{"software":{"present":[],"absent":[],
		"repositories":[{"name":"r","url":"https://x.example/repo","priority":1,"enabled":true,
		                 "signature":{"type":"none"}}],
		"allow_unverified":true}}`)

	if res := executeSyncSoftware(context.Background(), sp); !res.Success {
		t.Fatalf("should be permitted when the org opted in: %v", res.Errors)
	}
}

func findAction(res SyncAPIResult, action string) *SyncAPIItemResult {
	for i := range res.Results {
		if res.Results[i].Action == action {
			return &res.Results[i]
		}
	}
	return nil
}

// Small os shims so the test file states its intent without importing os
// everywhere; kept at the bottom because they are scaffolding, not subject.
func osReadFile(p string) ([]byte, error) { return os.ReadFile(p) }
func osMkdirAll(p string) error           { return os.MkdirAll(p, 0o755) }
func osWriteFile(p, body string) error    { return os.WriteFile(p, []byte(body), 0o644) }
