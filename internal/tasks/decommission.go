package tasks

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/opnapi"
	"github.com/netdefense-io/ndagent/internal/util"
)

// Self-decommission: what the agent does when the control plane says this
// device has been permanently deleted, and proves it with a tombstone
// signed by a pinned NDManager key.
//
// It is NOT a task. There is no DECOMMISSION task type, no dispatch
// envelope and no task_response: the device row is gone, so there is
// nothing left to report to and no endpoint that would accept a report.
// The trigger is the verified tombstone on the Phase 1 registration
// check (internal/network/registration.go).
//
// The sequence is ordered by reversibility, and that ordering is the
// whole design:
//
//  1. Everything NetDefense put on the box that an operator could
//     otherwise put back by hand — firewall objects, VPN, DNS, Zabbix,
//     synced identities, synced package repositories — is reconciled to
//     empty first, with bounded retries, while the agent still holds its
//     OPNsense credentials.
//  2. The two NetDefense-owned OPNsense identities go next, the agent's
//     own API user LAST of all API calls, because deleting it is what
//     ends the agent's ability to talk to OPNsense at all. That API
//     delete is then followed by a LOCAL deprovision through the
//     plugin's own PHP, which is what actually removes the agent's user:
//     OPNsense refuses over the API to delete the account the request
//     authenticates as.
//  3. Plugin settings are cleared so a later reinstall sees no stored
//     deviceId.
//  4. Only then does the irreversible half start: a detached helper
//     uninstalls the package, the pkg repository and /var/db/ndagent,
//     and the agent asks to be shut down.
//
// A failure in the reversible half is recorded and the sequence
// CONTINUES — per the decommission contract, a partially failed cleanup
// must not leave a deleted device running NetDefense software forever.
// The local log at /var/log/ndagent-decommission.log is what an operator
// reads afterwards; it lives outside /var/db/ndagent on purpose, so the
// wipe does not take the evidence with it.

const (
	// DecommissionLogPath records what the sequence did. Outside
	// /var/db/ndagent deliberately: that directory is removed by the
	// helper, and the log has to outlive it.
	DecommissionLogPath = "/var/log/ndagent-decommission.log"

	// decommissionHelperPath is the detached uninstall helper shipped in
	// the package. Same Setsid pattern as PLUGIN_INSTALL: it must outlive
	// the agent AND pkg's own pre-deinstall hook stopping the service.
	decommissionHelperPath = "/usr/local/sbin/ndagent-decommission.sh"

	// pluginConfigureScript is the plugin's own CLI helper. Two of its
	// modes are used here: --deprovision-accounts removes the two
	// NetDefense OPNsense accounts locally, and --reset-identity clears
	// deviceId/token/enabled in config.xml and reloads the template.
	// Both go through the plugin's models rather than ad-hoc PHP from Go.
	pluginConfigureScript = "/usr/local/opnsense/scripts/OPNsense/NetDefense/configure.php"

	readonlyIdentityName = "netdefense-readonly"
	agentIdentityName    = "netdefense-agent"
)

// decommissionBackoffs are the waits between reconcile attempts for one
// family. Three attempts per family; the wait after the final failed
// attempt is skipped, because nothing follows it — the family is recorded
// as failed and the sequence moves on.
var decommissionBackoffs = []time.Duration{10 * time.Second, 30 * time.Second, 60 * time.Second}

// DecommissionFamily is one managed-object family reconciled to an empty
// desired state, using the same executor an ordinary SYNC would use.
type DecommissionFamily struct {
	Name      string
	Reconcile func(ctx context.Context) error
}

// Decommissioner runs the sequence. Every outside effect is a field, so
// the ordering and the retry behaviour can be tested without an OPNsense,
// a pkg(8) or a process to fork.
type Decommissioner struct {
	Families []DecommissionFamily

	// RemoveReadonlyIdentity removes the netdefense-readonly user and
	// group; RemoveAgentIdentity removes the netdefense-agent API user.
	// Both go through opnapi.Client.DeleteUser/DeleteGroup directly and
	// deliberately do NOT touch ProtectedUsernames/ProtectedGroupNames —
	// the SYNC guard stays exactly as strict as it is today.
	RemoveReadonlyIdentity func(ctx context.Context) error
	RemoveAgentIdentity    func(ctx context.Context) error

	// DeprovisionAccounts removes both accounts locally, through the
	// plugin's own PHP, after the API attempts above. It is not optional
	// and not conditional on having an API client: the OPNsense API
	// cannot delete netdefense-agent at all (it is the identity the
	// request authenticates as), so this is the step that actually
	// removes it.
	DeprovisionAccounts func(ctx context.Context) error

	ResetPluginSettings func(ctx context.Context) error
	ForkHelper          func(ctx context.Context) error
	Shutdown            func()

	Backoffs []time.Duration
	Sleep    func(ctx context.Context, d time.Duration) error

	// Log is the decommission log file. Optional: nil logs to syslog only.
	logMu sync.Mutex
	Log   *os.File
}

// NewDecommissioner wires the production sequence.
//
// apiClient may be nil (a device with no OPNsense API credentials): the
// object families and the identity removals are then skipped, and the
// irreversible half still runs. A deleted device must not keep the
// package installed just because it could not reach its own API.
func NewDecommissioner(apiClient *opnapi.Client, packageName string, shutdown func()) *Decommissioner {
	d := &Decommissioner{
		Shutdown: shutdown,
		Backoffs: decommissionBackoffs,
		Sleep:    util.ShutdownAwareSleep,
	}

	if apiClient != nil {
		// Same executors, same order as HandleSyncAPI. An empty desired
		// state is already the "delete everything managed" signal for
		// every one of them — that behaviour is load-bearing for ordinary
		// template detachment and is reused here rather than duplicated.
		d.Families = []DecommissionFamily{
			{Name: "vpn", Reconcile: func(ctx context.Context) error {
				return syncResultError(executeSyncVPN(ctx, apiClient, nil))
			}},
			{Name: "aliases_rules", Reconcile: func(ctx context.Context) error {
				return syncResultError(executeSyncAPI(ctx, apiClient, nil, nil))
			}},
			{Name: "users_groups", Reconcile: func(ctx context.Context) error {
				return syncResultError(executeSyncUsersGroups(ctx, apiClient, nil, nil, false))
			}},
			{Name: "unbound", Reconcile: func(ctx context.Context) error {
				return syncResultError(executeSyncUnbound(ctx, apiClient, nil, nil, nil, nil))
			}},
			{Name: "zabbix", Reconcile: func(ctx context.Context) error {
				return syncResultError(executeSyncZabbix(ctx, apiClient, nil, nil, nil, false))
			}},
			{Name: "software_repositories", Reconcile: func(ctx context.Context) error {
				// An empty policy prunes every NetDefense-managed pkg
				// repository file (netdefense-*.conf). It cannot remove
				// packages NDManager installed: "absent" is what drives
				// removal and an empty policy names none. Those stay.
				return syncResultError(executeSyncSoftware(ctx, &softwarePayload{}))
			}},
		}
		d.RemoveReadonlyIdentity = func(ctx context.Context) error {
			return removeReadonlyIdentity(ctx, apiClient)
		}
		d.RemoveAgentIdentity = func(ctx context.Context) error {
			return removeAgentIdentity(ctx, apiClient)
		}
	}

	// Always wired, apiClient or not: this is the local removal path and
	// the only one that can take netdefense-agent off the box.
	d.DeprovisionAccounts = deprovisionLocalAccounts
	d.ResetPluginSettings = resetPluginIdentity
	d.ForkHelper = func(ctx context.Context) error { return forkDecommissionHelper(packageName) }
	return d
}

// Run executes the sequence. It returns an error only when the
// irreversible half could not be started; every reversible-half failure
// is logged and stepped over.
func (d *Decommissioner) Run(ctx context.Context, deletedAt, kid string) error {
	d.openLog()
	defer d.closeLog()

	d.logf("=== decommission start %s deleted_at=%s tombstone_kid=%s ===",
		time.Now().UTC().Format(time.RFC3339), deletedAt, kid)

	for _, family := range d.Families {
		d.reconcileFamily(ctx, family)
	}

	// Identities last, and the agent's own API user last of those: once
	// netdefense-agent is gone, no further OPNsense call can succeed.
	d.step(ctx, "remove "+readonlyIdentityName, d.RemoveReadonlyIdentity)
	d.step(ctx, "remove "+agentIdentityName, d.RemoveAgentIdentity)

	// The API call above CANNOT remove netdefense-agent: Usermanager
	// refuses to delete the account the request authenticates as. This
	// local pass, through the plugin's own PHP as root, is what actually
	// takes both accounts off the box — and it is idempotent, so the
	// uninstall helper runs it again before pkg delete.
	d.step(ctx, "deprovision local accounts", d.DeprovisionAccounts)

	// Clear the stored identity so a later install.sh --auto-setup on
	// this box starts from nothing instead of hitting configure.php's
	// existing-deviceId guard.
	d.step(ctx, "reset plugin settings", d.ResetPluginSettings)

	// Irreversible half.
	if d.ForkHelper != nil {
		if err := d.ForkHelper(ctx); err != nil {
			d.logf("FAILED: fork uninstall helper: %v", err)
			d.logf("=== decommission incomplete: package and /var/db/ndagent remain ===")
			if d.Shutdown != nil {
				d.Shutdown()
			}
			return fmt.Errorf("fork decommission helper: %w", err)
		}
		d.logf("OK: forked uninstall helper %s", decommissionHelperPath)
	}

	d.logf("=== decommission handed off to the uninstall helper; agent shutting down ===")
	if d.Shutdown != nil {
		d.Shutdown()
	}
	return nil
}

// reconcileFamily runs one family with bounded retries. It never returns
// an error: a family that will not converge is recorded and the sequence
// continues, because leaving a deleted device half-managed forever is
// worse than leaving one object behind.
func (d *Decommissioner) reconcileFamily(ctx context.Context, family DecommissionFamily) {
	if family.Reconcile == nil {
		return
	}
	backoffs := d.Backoffs
	if len(backoffs) == 0 {
		backoffs = decommissionBackoffs
	}

	for attempt := 1; attempt <= len(backoffs); attempt++ {
		err := family.Reconcile(ctx)
		if err == nil {
			d.logf("OK: family %s reconciled to empty (attempt %d)", family.Name, attempt)
			return
		}
		d.logf("WARN: family %s attempt %d/%d failed: %v", family.Name, attempt, len(backoffs), err)

		if attempt == len(backoffs) {
			break
		}
		if d.Sleep != nil {
			if serr := d.Sleep(ctx, backoffs[attempt-1]); serr != nil {
				d.logf("WARN: family %s retry interrupted: %v", family.Name, serr)
				break
			}
		}
	}
	d.logf("FAILED: family %s did not reconcile; continuing", family.Name)
}

// step runs one non-retried stage of the sequence, recording the outcome
// and continuing either way.
func (d *Decommissioner) step(ctx context.Context, name string, fn func(ctx context.Context) error) {
	if fn == nil {
		return
	}
	if err := fn(ctx); err != nil {
		d.logf("FAILED: %s: %v", name, err)
		return
	}
	d.logf("OK: %s", name)
}

func (d *Decommissioner) openLog() {
	if d.Log != nil {
		return
	}
	f, err := os.OpenFile(DecommissionLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		logging.Named("decommission").Warnw("Could not open the decommission log; syslog only",
			"path", DecommissionLogPath, "error", err)
		return
	}
	d.Log = f
}

func (d *Decommissioner) closeLog() {
	d.logMu.Lock()
	defer d.logMu.Unlock()
	if d.Log != nil {
		_ = d.Log.Close()
		d.Log = nil
	}
}

// logf writes one line to both syslog and the decommission log file.
func (d *Decommissioner) logf(format string, args ...interface{}) {
	line := fmt.Sprintf(format, args...)
	logging.Named("decommission").Info(line)

	d.logMu.Lock()
	defer d.logMu.Unlock()
	if d.Log != nil {
		_, _ = fmt.Fprintf(d.Log, "%s %s\n", time.Now().UTC().Format(time.RFC3339), line)
	}
}

// syncResultError turns an executor result into an error. The executors
// report failure in-band (Success + Errors) because they feed a task
// response; here there is no task, only "did it converge".
func syncResultError(result SyncAPIResult) error {
	if result.Success {
		return nil
	}
	if len(result.Errors) == 0 {
		return fmt.Errorf("reconcile reported failure with no error detail")
	}
	return fmt.Errorf("%s", strings.Join(result.Errors, "; "))
}

// removeReadonlyIdentity deletes the netdefense-readonly user and its
// same-named group. Absent is success: the sequence is re-runnable, and
// a device that never provisioned the read-only identity is already in
// the desired state.
func removeReadonlyIdentity(ctx context.Context, client *opnapi.Client) error {
	var problems []string

	if err := deleteUserByName(ctx, client, readonlyIdentityName); err != nil {
		problems = append(problems, err.Error())
	}

	group, err := client.GetGroupByName(ctx, readonlyIdentityName)
	if err != nil {
		problems = append(problems, fmt.Sprintf("look up group %s: %v", readonlyIdentityName, err))
	} else if group != nil {
		if uuid, ok := group["uuid"].(string); ok && uuid != "" {
			if err := client.DeleteGroup(ctx, uuid); err != nil {
				problems = append(problems, fmt.Sprintf("delete group %s: %v", readonlyIdentityName, err))
			}
		}
	}

	if len(problems) > 0 {
		return fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	return nil
}

// removeAgentIdentity deletes the netdefense-agent API user. This is the
// last OPNsense call the agent will ever make on this device.
func removeAgentIdentity(ctx context.Context, client *opnapi.Client) error {
	return deleteUserByName(ctx, client, agentIdentityName)
}

func deleteUserByName(ctx context.Context, client *opnapi.Client, name string) error {
	user, err := client.GetUserByName(ctx, name)
	if err != nil {
		return fmt.Errorf("look up user %s: %w", name, err)
	}
	if user == nil {
		return nil
	}
	uuid, _ := user["uuid"].(string)
	if uuid == "" {
		return fmt.Errorf("user %s has no uuid in the API response", name)
	}
	if err := client.DeleteUser(ctx, uuid); err != nil {
		return fmt.Errorf("delete user %s: %w", name, err)
	}
	return nil
}

// resetPluginIdentity clears deviceId/token/enabled in config.xml through
// the plugin's own model and reloads the template, so a later reinstall
// on this box is a genuinely fresh device rather than one that inherits a
// deviceId bound to a key and a row that no longer exist.
var resetPluginIdentity = func(ctx context.Context) error {
	return runPluginConfigure(ctx, "--reset-identity")
}

// deprovisionLocalAccounts removes the netdefense-agent and
// netdefense-readonly OPNsense accounts LOCALLY, as root, outside any API
// session.
//
// This is the only way netdefense-agent can go. OPNsense's Usermanager
// refuses to delete the account whose credentials authenticate the
// request — `{"errorMessage":"Not allowed to remove logged in user
// netdefense-agent","errorTitle":"Usermanager"}`, HTTP 500 — and the
// agent authenticates as exactly that user, so RemoveAgentIdentity above
// fails deterministically on every device. Without this step a
// decommissioned box keeps a `page-all` user with a live API key in
// config.xml, on a box the operator has been told is wiped.
//
// It also removes netdefense-readonly, so it doubles as the belt-and-
// braces pass for a device with no usable API at all. Idempotent: the
// uninstall helper runs it once more before `pkg delete`.
var deprovisionLocalAccounts = func(ctx context.Context) error {
	return runPluginConfigure(ctx, "--deprovision-accounts")
}

func runPluginConfigure(ctx context.Context, mode string) error {
	if _, err := os.Stat(pluginConfigureScript); err != nil {
		return fmt.Errorf("plugin helper not present at %s: %w", pluginConfigureScript, err)
	}
	cmd := exec.CommandContext(ctx, phpInterpreter, pluginConfigureScript, mode, "--json")
	cmd.Env = util.DeviceExecEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("configure.php %s failed: %w; output: %s", mode, err, string(out))
	}
	return nil
}

const phpInterpreter = "/usr/local/bin/php"

// forkDecommissionHelper starts the detached uninstall helper.
//
// Exactly the HandlePluginInstall pattern: own session (Setsid), no
// inherited descriptors, Process.Release because nobody will be alive to
// reap it. The helper has to survive both the agent's own exit and pkg's
// pre-deinstall stopping the service it is about to remove.
var forkDecommissionHelper = func(packageName string) error {
	if _, err := os.Stat(decommissionHelperPath); err != nil {
		return fmt.Errorf("helper missing at %s: %w", decommissionHelperPath, err)
	}

	cmdExec := exec.Command(decommissionHelperPath, packageName)
	cmdExec.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmdExec.Stdout = nil
	cmdExec.Stderr = nil
	cmdExec.Stdin = nil

	if err := cmdExec.Start(); err != nil {
		return err
	}
	_ = cmdExec.Process.Release()
	return nil
}
