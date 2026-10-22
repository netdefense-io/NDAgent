package tasks

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/netdefense-io/ndagent/internal/config"
	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/pkgmgr"
)

// opnsenseRegisterScript keeps OPNsense's plugin list; its firmware GUI runs it
// after every plugin install and removal (install.sh, remove.sh).
const opnsenseRegisterScript = "/usr/local/opnsense/scripts/firmware/register.php"

// register.php takes a second at most; the ceiling is for a config.xml write
// that waits on another one.
const (
	pluginRegisterCeiling = 60 * time.Second
	pluginRegisterGrace   = 15 * time.Second
)

// registerPluginFunc runs register.php; a variable so tests can stand in.
var registerPluginFunc = runRegisterScript

// syncPluginRegistry keeps OPNsense's plugin list (system.firmware.plugins) in
// step with the os-* packages a software pass left installed or absent, as the
// firmware GUI does. OPNsense installs a listed plugin again when it is
// missing, so one the policy removed has to leave the list, and one it
// installed has to join it or a series upgrade can drop it. Plugins the pass
// found already as wanted are checked too, which heals the list of a device an
// earlier agent managed. A failure is a warning: the package is as the policy
// wants, and the next sync tries again.
func syncPluginRegistry(ctx context.Context, configXMLPath string, result *SyncAPIResult) {
	want := map[string]bool{}
	for _, item := range result.Results {
		if item.Type != "SOFTWARE" || !strings.HasPrefix(item.Name, "os-") {
			continue
		}
		switch pkgmgr.SoftwareAction(item.Action) {
		case pkgmgr.ActionInstalled, pkgmgr.ActionAlreadyPresent:
			want[item.Name] = true
		case pkgmgr.ActionRemoved, pkgmgr.ActionAlreadyAbsent:
			want[item.Name] = false
		}
	}
	if len(want) == 0 {
		return
	}

	log := logging.Named("SYNC_SOFTWARE")
	listed, err := config.ReadRegisteredPlugins(ctx, configXMLPath)
	if err != nil {
		// register.php changes only what differs, so without the list every
		// plugin is handed to it.
		log.Warnw("Could not read OPNsense's plugin list; checking every plugin with register.php", "error", err)
		listed = nil
	}

	names := make([]string, 0, len(want))
	for name := range want {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if ctx.Err() != nil {
			return
		}
		if listed != nil && listed[name] == want[name] {
			continue
		}
		action := "install"
		if !want[name] {
			action = "remove"
		}
		if err := registerPluginFunc(action, name); err != nil {
			log.Warnw("OPNsense's plugin list was not updated", "plugin", name, "action", action, "error", err)
			result.Results = append(result.Results, SyncAPIItemResult{
				Type:   "SOFTWARE",
				Name:   name,
				Action: "warning",
				Status: "warning",
				Error:  fmt.Sprintf("OPNsense's plugin list was not updated (register.php %s): %v", action, err),
			})
			continue
		}
		log.Infow("OPNsense's plugin list updated", "plugin", name, "action", action)
	}
}

// runRegisterScript runs register.php. It saves config.xml, so it runs as every
// such script does (runHelperSubprocess): never under the sync's context, whose
// end would kill it with SIGKILL in the middle of the save.
func runRegisterScript(action, name string) error {
	if _, err := os.Stat(opnsenseRegisterScript); err != nil {
		return err
	}
	stdout, code, err := runHelperSubprocess(phpInterpreter, []string{opnsenseRegisterScript, action, name}, nil,
		pluginRegisterCeiling, pluginRegisterGrace)
	if err != nil {
		return err
	}
	if code != 0 {
		msg := strings.TrimSpace(string(stdout))
		if i := strings.IndexByte(msg, '\n'); i >= 0 {
			msg = msg[:i]
		}
		return fmt.Errorf("exited %d: %s", code, msg)
	}
	return nil
}
