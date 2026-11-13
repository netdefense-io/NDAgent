package tasks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
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
		// A real add installs the archive's own name-version; the test URLs
		// name the file after it.
		installed[strings.TrimSuffix(path.Base(url), ".pkg")] = true
		return pkgmgr.MutateOutcome{Action: pkgmgr.ActionInstalled}
	})
	// The installed version of a name is read from a "<name>-<version>" key, as
	// pkg's database would answer it.
	prevVersion := pkgmgr.SetInstalledVersionFunc(func(ctx context.Context, name string) (string, error) {
		for key, ok := range installed {
			if ok && strings.HasPrefix(key, name+"-") {
				return strings.TrimPrefix(key, name+"-"), nil
			}
		}
		return "", nil
	})
	// An archive holds the name-version its file is named after.
	prevArchive := readExternalArchive
	readExternalArchive = func(ctx context.Context, url string) (string, string, error) {
		log.add("fetch:" + url)
		base := strings.TrimSuffix(path.Base(url), ".pkg")
		i := strings.LastIndex(base, "-")
		if i < 0 {
			// pkg query -F always answers a version; a file named without
			// one is an archive that cannot be read.
			return "", "", fmt.Errorf("%s: no version in the file name", base)
		}
		return base[:i], base[i+1:], nil
	}
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
		pkgmgr.SetInstalledVersionFunc(prevVersion)
		readExternalArchive = prevArchive
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

	res := executeSyncSoftware(context.Background(), sp, "")
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

	res := executeSyncSoftware(context.Background(), sp, "")
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
	res := executeSyncSoftware(context.Background(), sp, "")
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
	res := executeSyncSoftware(context.Background(), sp, "")
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

	res := executeSyncSoftware(context.Background(), sp, "")
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

	res := executeSyncSoftware(context.Background(), sp, "")
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

	if res := executeSyncSoftware(context.Background(), sp, ""); !res.Success {
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
	res := executeSyncSoftware(context.Background(), sp, "")

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
	if res := executeSyncSoftware(context.Background(), sp, ""); !res.Success {
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

	res := executeSyncSoftware(context.Background(), sp, "")
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

	if res := executeSyncSoftware(context.Background(), sp, ""); !res.Success {
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

// The regression this exists for: a policy that once configured a repository
// and is then emptied must remove it from the device. Before the fix the
// empty payload collapsed to nil, executeSyncSoftware returned immediately,
// Prune never ran, and the managed file stayed on disk forever.
func TestEmptiedPolicyPrunesManagedRepositories(t *testing.T) {
	defer pkgrepo.SetRootForTest(t.TempDir())()

	// A repository this agent manages is already on the device.
	configured := pkgrepo.Repository{
		Name:      "feature-check",
		URL:       "https://example.invalid/repo",
		Priority:  9,
		Enabled:   enabledAs(false),
		Signature: pkgrepo.Signature{Type: pkgrepo.SignatureNone},
	}
	if _, err := pkgrepo.Apply([]pkgrepo.Repository{configured}, true); err != nil {
		t.Fatalf("seeding the device state: %v", err)
	}
	confPath := pkgrepo.ConfPath("feature-check")
	if _, err := os.Stat(confPath); err != nil {
		t.Fatalf("fixture did not write the conf: %v", err)
	}

	// The policy is emptied: present, absent and repositories all gone.
	sp, err := parseSoftwarePayload(mustPayload(t, `{"software":{"present":[],"absent":[]}}`))
	if err != nil {
		t.Fatalf("parseSoftwarePayload: %v", err)
	}
	if sp == nil {
		t.Fatal("an emptied policy must still reconcile; nil skips the prune entirely")
	}

	var result SyncAPIResult
	if _, ok := reconcileRepositories(context.Background(), sp, &result); !ok {
		t.Fatalf("reconcile refused: %+v", result.Errors)
	}

	if _, err := os.Stat(confPath); !os.IsNotExist(err) {
		t.Error("the managed repository file survived an emptied policy")
	}
	var removed bool
	for _, r := range result.Results {
		if r.Type == "REPOSITORY" && r.Name == "feature-check" && r.Action == "REPO_REMOVED" {
			removed = true
		}
	}
	if !removed {
		t.Errorf("removal must be reported, got %+v", result.Results)
	}
}

// The keep-list is built from the payload's repositories, and NDManager has
// already merged every policy reaching the device through every template/OU
// association into that one list. So the prune must keep ALL of them and
// remove only what no policy contributes — dropping one because it arrived
// via a different template would uninstall a live repository on every sync.
func TestPruneKeepsEveryRepositoryInTheMergedPayload(t *testing.T) {
	defer pkgrepo.SetRootForTest(t.TempDir())()

	// Three managed repositories already on the device.
	seed := []pkgrepo.Repository{
		{Name: "alpha", URL: "https://example.invalid/a", Priority: 1, Enabled: enabledAs(true),
			Signature: pkgrepo.Signature{Type: pkgrepo.SignatureNone}},
		{Name: "bravo", URL: "https://example.invalid/b", Priority: 2, Enabled: enabledAs(true),
			Signature: pkgrepo.Signature{Type: pkgrepo.SignatureNone}},
		{Name: "stale", URL: "https://example.invalid/s", Priority: 3, Enabled: enabledAs(true),
			Signature: pkgrepo.Signature{Type: pkgrepo.SignatureNone}},
	}
	if _, err := pkgrepo.Apply(seed, true); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	// The merged payload still carries alpha and bravo — they come from two
	// different policies — but no longer carries stale.
	sp, err := parseSoftwarePayload(mustPayload(t, `{"software":{"present":[],"absent":[],"allow_unverified":true,"repositories":[
		{"name":"alpha","url":"https://example.invalid/a","priority":1,"enabled":true,"signature":{"type":"none"}},
		{"name":"bravo","url":"https://example.invalid/b","priority":2,"enabled":true,"signature":{"type":"none"}}]}}`))
	if err != nil {
		t.Fatalf("parseSoftwarePayload: %v", err)
	}

	var result SyncAPIResult
	if _, ok := reconcileRepositories(context.Background(), sp, &result); !ok {
		t.Fatalf("reconcile refused: %+v", result.Errors)
	}

	for _, keep := range []string{"alpha", "bravo"} {
		if _, err := os.Stat(pkgrepo.ConfPath(keep)); err != nil {
			t.Errorf("repository %q is still in the merged payload but was pruned: %v", keep, err)
		}
	}
	if _, err := os.Stat(pkgrepo.ConfPath("stale")); !os.IsNotExist(err) {
		t.Error("a repository no policy contributes should have been removed")
	}
}

// An external package is installed with `pkg add` and no repository signature
// over it: without the organization's opt-in only an https URL is fetched, and
// a refused entry fails the task without stopping its siblings.
func TestExternalPackageNeedsHTTPSWithoutTheOptIn(t *testing.T) {
	for _, u := range []string{"http://x.example/ext-1.0.pkg", "HTTP://x.example/ext-1.0.pkg", "HTTPS://x.example/ext-1.0.pkg", "Https://x.example/ext-1.0.pkg", " https://x.example/ext-1.0.pkg", "ftp://x.example/ext-1.0.pkg", "/tmp/ext-1.0.pkg", "file:///tmp/ext-1.0.pkg", "https:/ext-1.0.pkg", "x.example/ext-1.0.pkg"} {
		t.Run(u, func(t *testing.T) {
			log := &orderLog{}
			stubPkg(t, log, nil)
			sp := payloadWith(t, `{"software":{"present":["p"],"absent":[],
				"external":[{"name":"ext","version":"1.0","url":"`+u+`","force":false},
				            {"name":"ok","version":"2.0","url":"https://x.example/ok-2.0.pkg","force":true}],
				"allow_unverified":false}}`)

			res := executeSyncSoftware(context.Background(), sp, "")
			if res.Success {
				t.Fatal("an external package from a non-https URL was accepted without the opt-in")
			}
			if log.indexOf("addurl:"+u) >= 0 {
				t.Errorf("pkg add ran for the refused URL: %v", log.all())
			}
			if log.indexOf("addurl:https://x.example/ok-2.0.pkg") < 0 || log.indexOf("install:p") < 0 {
				t.Errorf("the rest of the policy should still apply: %v", log.all())
			}
			if item := findAction(res, "refused"); item == nil || item.Name != "ext" || !strings.Contains(item.Error, u) {
				t.Errorf("want a refused item for ext naming the URL: %+v", res.Results)
			}
		})
	}

	// A URL that pkg would read as an option is refused whatever the opt-in.
	for _, allow := range []bool{false, true} {
		log := &orderLog{}
		stubPkg(t, log, nil)
		sp := payloadWith(t, `{"software":{"present":[],"absent":[],
			"external":[{"name":"ext","version":"1.0","url":"-f","force":false}],
			"allow_unverified":`+fmt.Sprint(allow)+`}}`)
		res := executeSyncSoftware(context.Background(), sp, "")
		if res.Success || log.indexOf("addurl:-f") >= 0 {
			t.Errorf("allow_unverified %v: an option-like URL was accepted or fetched: %v", allow, log.all())
		}
		if item := findAction(res, "refused"); item == nil || !strings.Contains(item.Error, "read as an option") {
			t.Errorf("allow_unverified %v: want a refused item saying why: %+v", allow, res.Results)
		}
	}

	for _, tc := range []struct {
		name      string
		installed bool
		force     bool
	}{{"already installed", true, false}, {"forced", false, true}, {"already installed and forced", true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			log := &orderLog{}
			stubPkg(t, log, map[string]bool{"ext-1.0": tc.installed})
			sp := payloadWith(t, fmt.Sprintf(`{"software":{"present":[],"absent":[],
				"external":[{"name":"ext","version":"1.0","url":"http://x.example/ext-1.0.pkg","force":%v}],
				"allow_unverified":false}}`, tc.force))
			res := executeSyncSoftware(context.Background(), sp, "")
			if res.Success || findAction(res, "refused") == nil || log.indexOf("addurl:http://x.example/ext-1.0.pkg") >= 0 {
				t.Errorf("want the entry refused before the installed check and force: %+v %v", res.Results, log.all())
			}
		})
	}

	t.Run("permitted when the org opted in", func(t *testing.T) {
		log := &orderLog{}
		stubPkg(t, log, nil)
		sp := payloadWith(t, `{"software":{"present":[],"absent":[],
			"external":[{"name":"ext","version":"1.0","url":"http://x.example/ext-1.0.pkg","force":false}],
			"allow_unverified":true}}`)
		if res := executeSyncSoftware(context.Background(), sp, ""); !res.Success || log.indexOf("addurl:http://x.example/ext-1.0.pkg") < 0 {
			t.Fatalf("should be installed when the org opted in: %v %v", res.Errors, log.all())
		}
	})
}

// An external package's version is a pkg version and nothing else: `pkg info
// name-version` matches a glob, so "*" would read any installed build as the
// one asked for and skip the add. A bad version refuses that entry only; the
// rest of the policy applies.
func TestExternalPackage_TheVersionIsAPkgVersion(t *testing.T) {
	for _, v := range []string{"1.0", "2.3.1_1", "1.2.3_1,1", "0.9.0.a1", "26.1.11+git", "latest", strings.Repeat("1", 100)} {
		if err := externalPermitted(externalPackage{Name: "ext", Version: v, URL: "https://x.example/ext.pkg"}, false); err != nil {
			t.Errorf("%q: %v", v, err)
		}
	}
	for _, v := range []string{"*", "1.*", "1.[0-9]", "1.0?", "1.{0,1}", "1.0 2.0", "-1.0", ".1", "1.0-2", strings.Repeat("1", 101)} {
		log := &orderLog{}
		stubPkg(t, log, nil)
		sp := payloadWith(t, `{"software":{"present":["p"],"absent":[],
			"external":[{"name":"ext","version":"`+v+`","url":"https://x.example/ext.pkg","force":false}],
			"allow_unverified":false}}`)
		res := executeSyncSoftware(context.Background(), sp, "")
		if res.Success || log.indexOf("addurl:https://x.example/ext.pkg") >= 0 {
			t.Errorf("%q: accepted or fetched: %v", v, log.all())
		}
		if item := findAction(res, "refused"); item == nil || !strings.Contains(item.Error, "not a package version") {
			t.Errorf("%q: want a refused item naming the version: %+v", v, res.Results)
		}
		if log.indexOf("install:p") < 0 {
			t.Errorf("%q: the rest of the policy should still apply: %v", v, log.all())
		}
	}
}

// externalCase runs one external entry against a device that has the given
// version of "ext" installed ("" for none) and an archive at the URL that holds
// archive (name-version). A pkg add installs what addInstalls says, "" being
// pkg 2.3.1's "already installed" that installs nothing.
func externalCase(t *testing.T, installed, archive, addInstalls, version string, force bool, readErr error) (SyncAPIResult, *orderLog) {
	t.Helper()
	log := &orderLog{}
	stubPkg(t, log, nil)
	current := installed
	prevVersion := pkgmgr.SetInstalledVersionFunc(func(ctx context.Context, name string) (string, error) {
		log.add("query:" + name)
		if readErr != nil && log.indexOf("addurl:https://x.example/ext.pkg") >= 0 {
			return "", readErr
		}
		if name != "ext" {
			return "", nil
		}
		return current, nil
	})
	prevAdd := pkgmgr.SetAddURLFunc(func(ctx context.Context, url string, force bool) pkgmgr.MutateOutcome {
		log.add("addurl:" + url)
		if addInstalls != "" {
			current = addInstalls
		}
		return pkgmgr.MutateOutcome{Action: pkgmgr.ActionInstalled}
	})
	prevArchive := readExternalArchive
	readExternalArchive = func(ctx context.Context, url string) (string, string, error) {
		log.add("fetch:" + url)
		i := strings.LastIndex(archive, "-")
		return archive[:i], archive[i+1:], nil
	}
	t.Cleanup(func() {
		pkgmgr.SetInstalledVersionFunc(prevVersion)
		pkgmgr.SetAddURLFunc(prevAdd)
		readExternalArchive = prevArchive
	})
	forceJSON := "false"
	if force {
		forceJSON = "true"
	}
	sp := payloadWith(t, `{"software":{"present":[],"absent":[],
		"external":[{"name":"ext","version":"`+version+`","url":"https://x.example/ext.pkg","force":`+forceJSON+`}],
		"allow_unverified":false}}`)
	return executeSyncSoftware(context.Background(), sp, ""), log
}

func externalItem(res SyncAPIResult) *SyncAPIItemResult {
	for i := range res.Results {
		if res.Results[i].Name == "ext" {
			return &res.Results[i]
		}
	}
	return nil
}

// A version that names a build is compared by the package's exact name, so a
// settled device downloads nothing, and a package named "ext-1.0" does not
// stand in for ext 1.0 (#262 point 2).
func TestExternalPackage_APinnedVersionIsComparedByExactName(t *testing.T) {
	res, log := externalCase(t, "1.0", "ext-1.0", "1.0", "1.0", false, nil)
	if item := externalItem(res); !res.Success || item == nil || item.Action != string(pkgmgr.ActionAlreadyPresent) {
		t.Fatalf("%+v", res.Results)
	}
	if log.indexOf("fetch:https://x.example/ext.pkg") >= 0 || log.indexOf("addurl:https://x.example/ext.pkg") >= 0 {
		t.Errorf("a settled pinned entry fetched or added: %v", log.all())
	}

	res, log = externalCase(t, "", "ext-1.0", "1.0", "1.0", false, nil)
	if !res.Success || log.indexOf("addurl:https://x.example/ext.pkg") < 0 {
		t.Errorf("a missing package was not added: %+v %v", res.Results, log.all())
	}
}

// A version without a digit names no build: the archive's own version decides,
// and the add is skipped when that version is installed (#262 point 1).
func TestExternalPackage_ABuildlessVersionUsesTheArchivesVersion(t *testing.T) {
	res, log := externalCase(t, "2.0", "ext-2.0", "2.0", "latest", false, nil)
	if item := externalItem(res); !res.Success || item == nil || item.Action != string(pkgmgr.ActionAlreadyPresent) {
		t.Fatalf("%+v", res.Results)
	}
	if log.indexOf("fetch:https://x.example/ext.pkg") < 0 || log.indexOf("addurl:https://x.example/ext.pkg") >= 0 {
		t.Errorf("latest at the archive's version: want a fetch and no add, got %v", log.all())
	}

	res, log = externalCase(t, "1.0", "ext-2.0", "2.0", "latest", false, nil)
	if item := externalItem(res); !res.Success || item == nil || item.Action != string(pkgmgr.ActionInstalled) || log.indexOf("addurl:https://x.example/ext.pkg") < 0 {
		t.Errorf("latest behind the archive: want an add, got %+v %v", res.Results, log.all())
	}
}

// Before any add, an archive that holds another package, or another build than
// the version the entry names, is refused, and nothing is installed.
func TestExternalPackage_AnArchiveThatIsNotTheEntryIsRefused(t *testing.T) {
	for _, tc := range []struct{ name, archive, version, want string }{
		{"another package", "other-1.0", "1.0", "holds the package other, not ext"},
		{"another build", "ext-1.1", "1.0", "holds ext-1.1, not the version 1.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, log := externalCase(t, "", tc.archive, "", tc.version, false, nil)
			item := externalItem(res)
			if res.Success || item == nil || item.Action != "refused" || !strings.Contains(item.Error, tc.want) {
				t.Errorf("item %+v, want refused with %q", item, tc.want)
			}
			if log.indexOf("addurl:https://x.example/ext.pkg") >= 0 {
				t.Errorf("the add ran: %v", log.all())
			}
		})
	}
}

func enabledAs(b bool) *bool { return &b }

// A repository whose snippet leaves out enabled, or sends null, arrives through
// the task's own parse and is written enabled; an explicit false is written
// disabled.
func TestSoftwareRepository_ALeftOutEnabledIsWrittenOn(t *testing.T) {
	for _, tc := range []struct {
		name, enabled, want string
	}{
		{"left out", ``, "enabled: yes,"},
		{"null", `"enabled": null,`, "enabled: yes,"},
		{"false", `"enabled": false,`, "enabled: no,"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			log := &orderLog{}
			stubPkg(t, log, nil)
			repo := strings.Replace(repoJSON, `"enabled": true,`, tc.enabled, 1)
			sp := payloadWith(t, `{"software":{"present":[],"absent":[],"repositories":[`+repo+`],"external":[],"allow_unverified":false}}`)
			if res := executeSyncSoftware(context.Background(), sp, ""); !res.Success {
				t.Fatalf("sync failed: %v", res.Errors)
			}
			body, err := os.ReadFile(pkgrepo.ConfPath("mimugmail"))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(body), tc.want) {
				t.Errorf("want %q in:\n%s", tc.want, body)
			}
		})
	}
}

// A `pkg add` that exits 0 but leaves the archive's build uninstalled is an
// error (#142): pkg 2.3.1 does that over another installed version.
func TestExternalPackage_AnAddThatInstallsNothingIsAnError(t *testing.T) {
	for _, tc := range []struct {
		name, version string
		force         bool
		readErr       error
		want          string
	}{
		{"another version left in place", "1.1", false, nil, "left the installed version in place; set force"},
		{"forced, nothing installed", "1.1", true, nil, "pkg add -f finished, but ext-1.1 is not installed"},
		{"the check cannot read pkg", "1.1", false, errors.New("pkg: database locked"), "could not be read"},
		{"latest, another version left in place", "latest", false, nil, "left the installed version in place"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, _ := externalCase(t, "1.0", "ext-1.1", "", tc.version, tc.force, tc.readErr)
			item := externalItem(res)
			if res.Success || item == nil || item.Status != "error" || !strings.Contains(item.Error, tc.want) {
				t.Errorf("item %+v, want an error with %q", item, tc.want)
			}
		})
	}
}

// Only pkg add's own URL prefixes are downloaded (pkg src/add.c is_url);
// anything else is a path on the box, read where it is, as pkg reads it.
func TestFetchAndReadArchive_DownloadsOnlyWhatPkgReadsAsAURL(t *testing.T) {
	for s, want := range map[string]bool{
		"https://x.example/ext-1.0.pkg": true,
		"http://x.example/ext-1.0.pkg":  true,
		"file:///tmp/ext-1.0.pkg":       true,
		"ftp://x.example/ext-1.0.pkg":   false,
		"pkg+https://x.example/ext.pkg": false,
		"HTTPS://x.example/ext-1.0.pkg": false,
		"/tmp/ext-1.0.pkg":              false,
	} {
		if got := pkgURL(s); got != want {
			t.Errorf("%q: %v, want %v", s, got, want)
		}
	}

	var read string
	prevArchive := pkgmgr.SetArchiveNameVersionFunc(func(ctx context.Context, path string) (string, string, error) {
		read = path
		return "ext", "1.0", nil
	})
	prevEnv := pkgmgr.SetFetchEnvFunc(func(ctx context.Context) ([]string, error) {
		t.Error("a path on the box asked for pkg's fetch environment")
		return nil, nil
	})
	t.Cleanup(func() {
		pkgmgr.SetArchiveNameVersionFunc(prevArchive)
		pkgmgr.SetFetchEnvFunc(prevEnv)
	})
	name, version, err := fetchAndReadArchive(context.Background(), "/tmp/ext-1.0.pkg")
	if err != nil || name != "ext" || version != "1.0" || read != "/tmp/ext-1.0.pkg" {
		t.Errorf("got %q %q %v, read %q", name, version, err, read)
	}
}

// A SYNC with no software section has no policy attached: the repository files
// a policy wrote are removed, an administrator's own file stays, and no pkg
// command runs (no catalog fetch, no package removed).
func TestSyncSoftwareSection_NoPolicyRemovesOnlyTheManagedRepositories(t *testing.T) {
	log := &orderLog{}
	stubPkg(t, log, nil)
	sp := payloadWith(t, `{"software":{"present":[],"absent":[],"repositories":[`+repoJSON+`],"external":[],"allow_unverified":false}}`)
	if res := syncSoftwareSection(context.Background(), sp, ""); !res.Success {
		t.Fatalf("policy sync failed: %v", res.Errors)
	}
	if _, err := os.Stat(pkgrepo.ConfPath("mimugmail")); err != nil {
		t.Fatalf("the policy's repository was not written: %v", err)
	}
	if _, err := os.Stat(pkgrepo.FingerprintDir("mimugmail")); err != nil {
		t.Fatalf("the policy's fingerprints were not written: %v", err)
	}
	foreign := filepath.Join(pkgrepo.ReposDirForTest(), "own.conf")
	if err := os.WriteFile(foreign, []byte("own: {\n  url: \"https://x.example\"\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	before := len(log.all())

	res := syncSoftwareSection(context.Background(), nil, "")
	if !res.Success {
		t.Fatalf("no-policy sync failed: %v", res.Errors)
	}
	if _, err := os.Stat(pkgrepo.ConfPath("mimugmail")); !os.IsNotExist(err) {
		t.Errorf("the managed repository survived a SYNC without a policy: %v", err)
	}
	if _, err := os.Stat(pkgrepo.FingerprintDir("mimugmail")); !os.IsNotExist(err) {
		t.Errorf("the managed repository's fingerprints survived a SYNC without a policy: %v", err)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Errorf("an administrator's own repository file was removed: %v", err)
	}
	removed := false
	for _, it := range res.Results {
		if it.Type == "REPOSITORY" && it.Name == "mimugmail" && it.Action == string(pkgmgr.ActionRepoRemoved) {
			removed = true
		}
	}
	if !removed {
		t.Errorf("results %+v, want the removal reported", res.Results)
	}
	if calls := log.all()[before:]; len(calls) != 0 {
		t.Errorf("a SYNC without a policy ran pkg: %v", calls)
	}

	if res := syncSoftwareSection(context.Background(), nil, ""); !res.Success || len(res.Results) != 0 {
		t.Errorf("the next SYNC without a policy: %+v", res)
	}
}
