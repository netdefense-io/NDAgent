package tasks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// pluginListConfig writes a config.xml whose plugin list holds names.
func pluginListConfig(t *testing.T, names ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.xml")
	body := "<?xml version=\"1.0\"?>\n<opnsense>\n  <system>\n    <firmware>\n      <plugins>" +
		strings.Join(names, ",") + "</plugins>\n    </firmware>\n  </system>\n</opnsense>\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPluginList_FollowsWhatThePassInstalledAndRemoved(t *testing.T) {
	installed := map[string]bool{"os-old": true}
	cl := swapPkgmgr(t, installed, nil, nil, nil, nil)

	r := executeSyncSoftware(context.Background(), &softwarePayload{
		Present: []string{"os-new", "bash"},
		Absent:  []string{"os-old"},
	}, pluginListConfig(t, "os-old"))

	if !r.Success {
		t.Fatalf("errors %v", r.Errors)
	}
	if want := []string{"install os-new", "remove os-old"}; !reflect.DeepEqual(cl.registers, want) {
		t.Errorf("register.php calls %v, want %v (only os-* packages are plugins)", cl.registers, want)
	}
}

// Plugins an earlier agent installed or removed without telling OPNsense are
// put right by the next sync, though the packages themselves need nothing.
func TestPluginList_HealsPluginsAlreadyAsWanted(t *testing.T) {
	installed := map[string]bool{"os-kept": true}
	cl := swapPkgmgr(t, installed, nil, nil, nil, nil)

	r := executeSyncSoftware(context.Background(), &softwarePayload{
		Present: []string{"os-kept"},
		Absent:  []string{"os-gone"},
	}, pluginListConfig(t, "os-gone"))

	if !r.Success || len(cl.installs) != 0 || len(cl.removes) != 0 {
		t.Fatalf("success %v, installs %v, removes %v", r.Success, cl.installs, cl.removes)
	}
	if want := []string{"remove os-gone", "install os-kept"}; !reflect.DeepEqual(cl.registers, want) {
		t.Errorf("register.php calls %v, want %v", cl.registers, want)
	}
}

func TestPluginList_ASettledDeviceRunsNothing(t *testing.T) {
	installed := map[string]bool{"os-kept": true}
	cl := swapPkgmgr(t, installed, nil, nil, nil, nil)

	executeSyncSoftware(context.Background(), &softwarePayload{
		Present: []string{"os-kept"},
		Absent:  []string{"os-gone"},
	}, pluginListConfig(t, "os-kept", "os-other"))

	if len(cl.registers) != 0 {
		t.Errorf("register.php ran %v for a list that is already right", cl.registers)
	}
}

func TestPluginList_APackageThatFailedIsLeftAlone(t *testing.T) {
	installed := map[string]bool{"os-stuck": true}
	cl := swapPkgmgr(t, installed, map[string]bool{"os-missing": true},
		map[string]string{"os-broken": "conflict"}, map[string]string{"os-stuck": "locked"}, nil)

	r := executeSyncSoftware(context.Background(), &softwarePayload{
		Present: []string{"os-missing", "os-broken"},
		Absent:  []string{"os-stuck"},
	}, pluginListConfig(t, "os-stuck"))

	if r.Success {
		t.Fatal("the package failures must still fail the task")
	}
	if len(cl.registers) != 0 {
		t.Errorf("register.php ran %v for packages whose install or removal failed", cl.registers)
	}
}

func TestPluginList_AFailureIsAWarningThatKeepsTheTask(t *testing.T) {
	installed := map[string]bool{}
	swapPkgmgr(t, installed, nil, nil, nil, nil)
	registerPluginFunc = func(action, name string) error { return errors.New("exited 1: Registering nothing.") }

	r := executeSyncSoftware(context.Background(), &softwarePayload{Present: []string{"os-new"}},
		pluginListConfig(t))

	if !r.Success || len(r.Errors) != 0 {
		t.Fatalf("success %v, errors %v: the package is installed, so the task stands", r.Success, r.Errors)
	}
	var warning *SyncAPIItemResult
	for i := range r.Results {
		if r.Results[i].Status == "warning" {
			warning = &r.Results[i]
		}
	}
	if warning == nil || warning.Name != "os-new" || warning.Action != "warning" ||
		!strings.Contains(warning.Error, "register.php install") || !strings.Contains(warning.Error, "Registering nothing.") {
		t.Errorf("warning item %+v", warning)
	}
}

// Without the list every plugin goes to register.php, which changes only what
// differs.
func TestPluginList_AnUnreadableListChecksEveryPlugin(t *testing.T) {
	installed := map[string]bool{"os-kept": true}
	cl := swapPkgmgr(t, installed, nil, nil, nil, nil)

	executeSyncSoftware(context.Background(), &softwarePayload{
		Present: []string{"os-kept"},
		Absent:  []string{"os-gone"},
	}, filepath.Join(t.TempDir(), "missing.xml"))

	if want := []string{"remove os-gone", "install os-kept"}; !reflect.DeepEqual(cl.registers, want) {
		t.Errorf("register.php calls %v, want %v", cl.registers, want)
	}
}

func TestPluginList_ADoneContextRunsNothing(t *testing.T) {
	result := SyncAPIResult{Success: true, Results: []SyncAPIItemResult{
		{Type: "SOFTWARE", Name: "os-new", Action: "INSTALLED", Status: "success"},
	}}
	calls := 0
	prev := registerPluginFunc
	registerPluginFunc = func(string, string) error { calls++; return nil }
	t.Cleanup(func() { registerPluginFunc = prev })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	syncPluginRegistry(ctx, pluginListConfig(t), &result)
	if calls != 0 {
		t.Errorf("register.php ran %d times under a done context", calls)
	}
}
