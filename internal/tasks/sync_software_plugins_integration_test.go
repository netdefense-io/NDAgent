//go:build integration
// +build integration

package tasks

import (
	"context"
	"os"
	"testing"

	"github.com/netdefense-io/ndagent/internal/config"
	"github.com/netdefense-io/ndagent/internal/pkgmgr"
)

// TestIntegration_SoftwarePluginList installs and removes an OPNsense plugin
// through a software pass, on the device itself, and checks OPNsense's plugin
// list after each. It runs as root on an OPNsense device:
//
//	ND_INTEGRATION_PLUGIN=os-helloworld ./tasks.test -test.run TestIntegration_SoftwarePluginList -test.v
//
// The plugin must be neither installed nor listed when it starts, and it is
// neither when it ends.
func TestIntegration_SoftwarePluginList(t *testing.T) {
	plugin := os.Getenv("ND_INTEGRATION_PLUGIN")
	if plugin == "" {
		t.Skip("ND_INTEGRATION_PLUGIN must name an os-* plugin that is not installed")
	}
	const configXML = "/conf/config.xml"
	ctx := context.Background()

	listed := func() bool {
		t.Helper()
		names, err := config.ReadRegisteredPlugins(ctx, configXML)
		if err != nil {
			t.Fatalf("reading the plugin list: %v", err)
		}
		return names[plugin]
	}
	if installed, err := pkgmgr.IsInstalled(ctx, plugin); err != nil || installed || listed() {
		t.Skipf("%s is installed (%v, %v) or listed; the test would change a plugin it did not add", plugin, installed, err)
	}
	t.Cleanup(func() {
		if installed, _ := pkgmgr.IsInstalled(ctx, plugin); installed {
			pkgmgr.Delete(ctx, plugin)
		}
		_ = registerPluginFunc("remove", plugin)
	})

	r := executeSyncSoftware(ctx, &softwarePayload{Present: []string{plugin}}, configXML)
	if !r.Success || len(r.Results) == 0 || r.Results[len(r.Results)-1].Action != string(pkgmgr.ActionInstalled) {
		t.Fatalf("install pass: %+v", r)
	}
	if !listed() {
		t.Fatal("the installed plugin is not in OPNsense's plugin list")
	}

	r = executeSyncSoftware(ctx, &softwarePayload{Absent: []string{plugin}}, configXML)
	if !r.Success || r.Results[len(r.Results)-1].Action != string(pkgmgr.ActionRemoved) {
		t.Fatalf("removal pass: %+v", r)
	}
	if listed() {
		t.Fatal("the removed plugin is still in OPNsense's plugin list, so OPNsense would install it again")
	}
}
