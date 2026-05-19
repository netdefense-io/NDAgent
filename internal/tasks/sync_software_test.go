package tasks

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/netdefense-io/ndagent/internal/pkgmgr"
)

// ----------------------------------------------------------------------------
// parseSoftwarePayload
// ----------------------------------------------------------------------------

func mustPayload(t *testing.T, body string) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("bad fixture JSON: %v", err)
	}
	return m
}

func TestParseSoftwarePayload_Missing(t *testing.T) {
	sp, err := parseSoftwarePayload(mustPayload(t, `{}`))
	if err != nil || sp != nil {
		t.Fatalf("expected (nil, nil), got (%v, %v)", sp, err)
	}
}

func TestParseSoftwarePayload_EmptyLists(t *testing.T) {
	sp, err := parseSoftwarePayload(mustPayload(t, `{"software":{"present":[],"absent":[]}}`))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if sp != nil {
		t.Fatalf("empty-both should collapse to nil; got %+v", sp)
	}
}

func TestParseSoftwarePayload_PresentOnly(t *testing.T) {
	sp, err := parseSoftwarePayload(mustPayload(t,
		`{"software":{"present":["bash","os-zabbix72-agent"],"absent":[]}}`))
	if err != nil || sp == nil {
		t.Fatalf("unexpected: %v %v", sp, err)
	}
	if len(sp.Present) != 2 || len(sp.Absent) != 0 {
		t.Fatalf("bad parse: %+v", sp)
	}
}

func TestParseSoftwarePayload_TopLevelMustBeObject(t *testing.T) {
	_, err := parseSoftwarePayload(mustPayload(t, `{"software":[]}`))
	if err == nil {
		t.Fatal("expected error for array top-level")
	}
}

func TestParseSoftwarePayload_NonStringEntry(t *testing.T) {
	_, err := parseSoftwarePayload(mustPayload(t, `{"software":{"present":[1],"absent":[]}}`))
	if err == nil {
		t.Fatal("expected error for non-string entry")
	}
}

// ----------------------------------------------------------------------------
// validSoftwareName — the only line of defense if a poisoned row slips past
// NDDataModels' validator and the signed-hash check.
// ----------------------------------------------------------------------------

func TestValidSoftwareName(t *testing.T) {
	good := []string{"bash", "os-zabbix72-agent", "py311-cryptography",
		"ca_root_nss", "gnupg-2.4", "libplist+", "A", "9pkg"}
	bad := []string{
		"", "-leading", ".leading", "+leading",
		"a; rm -rf /", "$(whoami)", "`uname`",
		"../etc/passwd", "pkg with space",
		"pkg|other", "pkg&other", "pkg>file", "pkg\nname",
	}
	for _, n := range good {
		if !validSoftwareName(n) {
			t.Errorf("expected %q valid", n)
		}
	}
	for _, n := range bad {
		if validSoftwareName(n) {
			t.Errorf("expected %q rejected", n)
		}
	}
}

// ----------------------------------------------------------------------------
// executeSyncSoftware — exercise the orchestrator with the package-level
// stubs swapped out, so the pkg(8) binary is never invoked.
// ----------------------------------------------------------------------------

type callLog struct {
	updates  int
	infos    []string
	installs []string
	removes  []string
}

// swapPkgmgr installs in-memory stubs for pkgmgr's four call paths.
// `installed` is mutated in place so a successful Install/Delete is visible
// to a follow-up IsInstalled within the same test.
func swapPkgmgr(t *testing.T,
	installed map[string]bool,
	notFound map[string]bool,
	installErr map[string]string,
	removeErr map[string]string,
	updateErr error,
) *callLog {
	t.Helper()
	cl := &callLog{}

	prevInstall := pkgmgr.SetInstallFunc(func(_ context.Context, name string) pkgmgr.MutateOutcome {
		cl.installs = append(cl.installs, name)
		if msg, ok := installErr[name]; ok {
			return pkgmgr.MutateOutcome{Action: pkgmgr.ActionError, ErrMsg: msg}
		}
		if notFound[name] {
			return pkgmgr.MutateOutcome{Action: pkgmgr.ActionNotFound}
		}
		installed[name] = true
		return pkgmgr.MutateOutcome{Action: pkgmgr.ActionInstalled}
	})
	prevRemove := pkgmgr.SetRemoveFunc(func(_ context.Context, name string) pkgmgr.MutateOutcome {
		cl.removes = append(cl.removes, name)
		if msg, ok := removeErr[name]; ok {
			return pkgmgr.MutateOutcome{Action: pkgmgr.ActionError, ErrMsg: msg}
		}
		delete(installed, name)
		return pkgmgr.MutateOutcome{Action: pkgmgr.ActionRemoved}
	})
	prevUpdate := pkgmgr.SetUpdateFunc(func(_ context.Context) error {
		cl.updates++
		return updateErr
	})
	prevIsInstalled := pkgmgr.SetIsInstalledFunc(func(_ context.Context, name string) (bool, error) {
		cl.infos = append(cl.infos, name)
		return installed[name], nil
	})

	t.Cleanup(func() {
		pkgmgr.SetInstallFunc(prevInstall)
		pkgmgr.SetRemoveFunc(prevRemove)
		pkgmgr.SetUpdateFunc(prevUpdate)
		pkgmgr.SetIsInstalledFunc(prevIsInstalled)
	})
	return cl
}

func TestExecuteSyncSoftware_NilPayloadNoop(t *testing.T) {
	r := executeSyncSoftware(context.Background(), nil)
	if !r.Success || len(r.Results) != 0 {
		t.Fatalf("nil payload should be a clean no-op: %+v", r)
	}
}

func TestExecuteSyncSoftware_AlreadyPresentAndAbsent(t *testing.T) {
	installed := map[string]bool{"bash": true}
	cl := swapPkgmgr(t, installed, nil, nil, nil, nil)

	r := executeSyncSoftware(context.Background(), &softwarePayload{
		Present: []string{"bash"},
		Absent:  []string{"os-zabbix6-agent"},
	})

	if !r.Success {
		t.Fatalf("expected success, errors=%v", r.Errors)
	}
	actions := map[string]string{}
	for _, item := range r.Results {
		actions[item.Name] = item.Action
	}
	if actions["bash"] != "ALREADY_PRESENT" {
		t.Errorf("bash: want ALREADY_PRESENT, got %q", actions["bash"])
	}
	if actions["os-zabbix6-agent"] != "ALREADY_ABSENT" {
		t.Errorf("os-zabbix6-agent: want ALREADY_ABSENT, got %q", actions["os-zabbix6-agent"])
	}
	if len(cl.installs) != 0 || len(cl.removes) != 0 {
		t.Errorf("idempotent no-op should not call install/remove; got installs=%v removes=%v",
			cl.installs, cl.removes)
	}
}

func TestExecuteSyncSoftware_InstallThenRemove(t *testing.T) {
	installed := map[string]bool{"old-pkg": true}
	cl := swapPkgmgr(t, installed, nil, nil, nil, nil)

	r := executeSyncSoftware(context.Background(), &softwarePayload{
		Present: []string{"new-pkg"},
		Absent:  []string{"old-pkg"},
	})
	if !r.Success {
		t.Fatalf("expected success, errors=%v", r.Errors)
	}
	// Absent runs before present.
	if len(cl.removes) != 1 || cl.removes[0] != "old-pkg" {
		t.Errorf("expected remove of old-pkg, got %v", cl.removes)
	}
	if len(cl.installs) != 1 || cl.installs[0] != "new-pkg" {
		t.Errorf("expected install of new-pkg, got %v", cl.installs)
	}
	// Sanity: catalog refresh happened exactly once.
	if cl.updates != 1 {
		t.Errorf("expected 1 pkg update, got %d", cl.updates)
	}
}

func TestExecuteSyncSoftware_NotFoundFailsTask(t *testing.T) {
	swapPkgmgr(t, map[string]bool{}, map[string]bool{"bogus-pkg": true}, nil, nil, nil)

	r := executeSyncSoftware(context.Background(), &softwarePayload{
		Present: []string{"bogus-pkg"},
	})
	if r.Success {
		t.Fatal("NOT_FOUND must fail overall task")
	}
	if r.Results[0].Action != "NOT_FOUND" {
		t.Errorf("expected NOT_FOUND, got %q", r.Results[0].Action)
	}
}

func TestExecuteSyncSoftware_InvalidNameFailsTask(t *testing.T) {
	swapPkgmgr(t, map[string]bool{}, nil, nil, nil, nil)

	r := executeSyncSoftware(context.Background(), &softwarePayload{
		Present: []string{"bad name"},
	})
	if r.Success {
		t.Fatal("INVALID_NAME must fail overall task")
	}
	if r.Results[0].Action != "INVALID_NAME" {
		t.Errorf("expected INVALID_NAME, got %q", r.Results[0].Action)
	}
}

func TestExecuteSyncSoftware_PkgErrorFailsTask(t *testing.T) {
	installed := map[string]bool{}
	swapPkgmgr(t, installed, nil, map[string]string{"flaky-pkg": "transient pkg error"}, nil, nil)

	r := executeSyncSoftware(context.Background(), &softwarePayload{
		Present: []string{"flaky-pkg"},
	})
	if r.Success {
		t.Fatal("pkg ERROR must fail overall task")
	}
	if r.Results[0].Action != "ERROR" || r.Results[0].Error == "" {
		t.Errorf("expected ERROR with msg, got %+v", r.Results[0])
	}
}

func TestExecuteSyncSoftware_PkgUpdateFailureIsTolerated(t *testing.T) {
	// Stale catalog ≠ task failure. The per-package operation succeeds
	// against the cached metadata; we just surface the update failure as a
	// top-level error string for visibility.
	installed := map[string]bool{"bash": true}
	cl := swapPkgmgr(t, installed, nil, nil, nil, errors.New("pkg update boom"))

	r := executeSyncSoftware(context.Background(), &softwarePayload{
		Present: []string{"bash"},
	})
	if !r.Success {
		t.Fatalf("update failure alone must not flip Success=false; errors=%v", r.Errors)
	}
	if len(r.Errors) == 0 {
		t.Errorf("expected the update failure to be surfaced in r.Errors")
	}
	if cl.updates != 1 {
		t.Errorf("expected 1 update attempt, got %d", cl.updates)
	}
}
