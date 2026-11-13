package tasks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// CROWDSEC_SETTINGS drives the os-crowdsec plugin's single settings model.
// A reconfigure restarts crowdsec and the bouncer and runs a full hub pass
// against CrowdSec's servers, so this executor writes and reconfigures only
// for a real difference, at most once per SYNC, and never retries.

const (
	crowdsecSnippetType = "CROWDSEC_SETTINGS"
	crowdsecItemType    = "crowdsec_settings"

	// crowdsecRetryAfter bounds the failed-apply memory: the agent cannot tell
	// a forced SYNC from a changed one, so a failed apply is retried at the
	// earliest after this long when nothing else changed.
	crowdsecRetryAfter = time.Hour
)

// crowdsecKeys are the settings a snippet may carry, in a stable order. A key
// added here needs its default in crowdsecDefaults.
var crowdsecKeys = []string{
	"agent_enabled", "lapi_enabled", "firewall_bouncer_enabled",
	"rules_enabled", "rules_log", "rules_tag", "crowdsec_firewall_verbose",
	"enroll_key",
}

// crowdsecDefaults are os-crowdsec's model defaults (General.xml 1.0.12) for
// the snippet's keys, in the wire form. A key the snippet leaves out takes its
// default (the operator's rule, 2026-11-12), when the installed plugin has it.
// enroll_key is a TextField, so the plugin's get returns it as stored and a
// key set by hand reads as changed against the empty default.
var crowdsecDefaults = map[string]string{
	"agent_enabled": "1", "lapi_enabled": "1", "firewall_bouncer_enabled": "1",
	"rules_enabled": "1", "rules_log": "0", "crowdsec_firewall_verbose": "0",
	"rules_tag": "", "enroll_key": "",
}

var crowdsecBoolKeys = map[string]bool{
	"agent_enabled": true, "lapi_enabled": true, "firewall_bouncer_enabled": true,
	"rules_enabled": true, "rules_log": true, "crowdsec_firewall_verbose": true,
	"lapi_manual_configuration": true,
}

// Overridable by tests.
var (
	crowdsecStatePath    = "/var/db/ndagent/crowdsec-apply.json"
	crowdsecPollInterval = time.Second
	crowdsecPollTimeout  = 30 * time.Second
	// crowdsecEngineSettle is how long the engine has to stay the same process
	// for an apply to count: longer than daemon(8)'s 10 s restart delay. An
	// engine that crashes later than that passes; the one heal per
	// crowdsecRetryAfter bounds what it costs.
	crowdsecEngineSettle = 11 * time.Second
	crowdsecNow          = time.Now
)

// crowdsecSnippetContent is the strict typed form of the snippet content.
type crowdsecSnippetContent struct {
	AgentEnabled           *bool   `json:"agent_enabled"`
	LAPIEnabled            *bool   `json:"lapi_enabled"`
	FirewallBouncerEnabled *bool   `json:"firewall_bouncer_enabled"`
	RulesEnabled           *bool   `json:"rules_enabled"`
	RulesLog               *bool   `json:"rules_log"`
	RulesTag               *string `json:"rules_tag"`
	FirewallVerbose        *bool   `json:"crowdsec_firewall_verbose"`
	EnrollKey              *string `json:"enroll_key"`
}

// crowdsecDesired is the parsed CROWDSEC_SETTINGS snippet; Values holds only
// the keys it sets, in the plugin's wire form ("0"/"1" for booleans).
// The defaults of the keys it leaves out are filled in by executeSyncCrowdsec,
// not here, which skips silently a key the installed plugin does not have.
type crowdsecDesired struct {
	Name   string
	Values map[string]string
}

func boolWire(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func (c crowdsecSnippetContent) values() map[string]string {
	out := map[string]string{}
	for key, b := range map[string]*bool{
		"agent_enabled":             c.AgentEnabled,
		"lapi_enabled":              c.LAPIEnabled,
		"firewall_bouncer_enabled":  c.FirewallBouncerEnabled,
		"rules_enabled":             c.RulesEnabled,
		"rules_log":                 c.RulesLog,
		"crowdsec_firewall_verbose": c.FirewallVerbose,
	} {
		if b != nil {
			out[key] = boolWire(*b)
		}
	}
	if c.RulesTag != nil {
		out["rules_tag"] = *c.RulesTag
	}
	if c.EnrollKey != nil {
		out["enroll_key"] = *c.EnrollKey
	}
	return out
}

// parseAPICrowdsecSettings extracts the CROWDSEC_SETTINGS singleton. Nil when
// the payload carries none; more than one is an error, because the control
// plane sends at most one and picking among several here would hide a fault.
func parseAPICrowdsecSettings(payload map[string]interface{}) (*crowdsecDesired, error) {
	snippetsRaw, ok := payload["snippets"]
	if !ok {
		return nil, nil
	}
	snippetsArray, ok := snippetsRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("snippets must be an array")
	}

	var found *crowdsecDesired
	var firstLabel string
	for idx, s := range snippetsArray {
		snippetMap, ok := s.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("snippet at index %d must be an object", idx)
		}
		if ct, _ := snippetMap["config_type"].(string); ct != crowdsecSnippetType {
			continue
		}
		label := snippetLabel(crowdsecItemType, snippetMap, idx)
		if found != nil {
			return nil, fmt.Errorf("%s: only one CROWDSEC_SETTINGS snippet is allowed per device (already have %s)", label, firstLabel)
		}

		content, _ := snippetMap["content"].(string)
		if content == "" {
			return nil, fmt.Errorf("%s: missing content", label)
		}
		var parsed crowdsecSnippetContent
		dec := json.NewDecoder(strings.NewReader(content))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&parsed); err != nil {
			return nil, fmt.Errorf("%s: invalid content: %v", label, err)
		}
		if _, err := dec.Token(); err != io.EOF {
			return nil, fmt.Errorf("%s: invalid content: trailing data after the JSON object", label)
		}

		name, _ := snippetMap["snippet_name"].(string)
		found = &crowdsecDesired{Name: name, Values: parsed.values()}
		firstLabel = label
	}
	return found, nil
}

// normalizeCrowdsecValue folds the device's spellings of a setting to the wire
// form the snippet values use.
func normalizeCrowdsecValue(key, value string) string {
	if crowdsecBoolKeys[key] {
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "1", "true", "yes", "on":
			return "1"
		}
		return "0"
	}
	return value
}

func crowdsecEnabledPair(model map[string]string) bool {
	return model["agent_enabled"] == "1" || model["lapi_enabled"] == "1" || model["firewall_bouncer_enabled"] == "1"
}

// crowdsecGuardViolation returns a message naming the pair when the state
// leaves the agent or the bouncer pointed at a LAPI nobody serves; the plugin
// accepts that state without complaint.
func crowdsecGuardViolation(model map[string]string) string {
	if model["lapi_enabled"] == "1" || model["lapi_manual_configuration"] == "1" {
		return ""
	}
	var on []string
	if model["agent_enabled"] == "1" {
		on = append(on, "agent_enabled=true")
	}
	if model["firewall_bouncer_enabled"] == "1" {
		on = append(on, "firewall_bouncer_enabled=true")
	}
	if len(on) == 0 {
		return ""
	}
	return fmt.Sprintf("lapi_enabled=false together with %s leaves them without a local API to talk to (lapi_manual_configuration is off)", strings.Join(on, " and "))
}

// ---------------------------------------------------------------------------
// Failed-apply memory
// ---------------------------------------------------------------------------

type crowdsecFailure struct {
	Hash string    `json:"hash"`
	At   time.Time `json:"at"`
}

type crowdsecFailureFile struct {
	Failures []crowdsecFailure `json:"failures"`
	// Heals are the restarts of a matching model, keyed without the status:
	// at most one per crowdsecRetryAfter, whatever the status reads, since
	// each is a hub pass against CrowdSec's servers.
	Heals []crowdsecFailure `json:"heals,omitempty"`
}

// crowdsecStateHash identifies a (desired content, device state) pair; the
// file keeps only this digest, never a value.
func crowdsecStateHash(desired, model map[string]string, status string) string {
	var b strings.Builder
	write := func(prefix string, m map[string]string) {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "%s %s=%q\n", prefix, k, m[k])
		}
	}
	write("d", desired)
	write("m", model)
	fmt.Fprintf(&b, "s %q\n", status)
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// SYNC tasks run one at a time (the per-agent FIFO), so the memory file needs
// no lock.
func loadCrowdsecMemory() crowdsecFailureFile {
	data, err := os.ReadFile(crowdsecStatePath)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			logging.Named("SYNC_API").Warnw("CrowdSec: could not read the failed-apply memory", "error", err)
		}
		return crowdsecFailureFile{}
	}
	var f crowdsecFailureFile
	if err := json.Unmarshal(data, &f); err != nil {
		logging.Named("SYNC_API").Warnw("CrowdSec: ignoring an unreadable failed-apply memory", "error", err)
		return crowdsecFailureFile{}
	}
	return f
}

func recentlyAt(entries []crowdsecFailure, hash string) bool {
	for _, e := range entries {
		if e.Hash == hash && crowdsecNow().Sub(e.At) < crowdsecRetryAfter {
			return true
		}
	}
	return false
}

func recentOnly(entries []crowdsecFailure) []crowdsecFailure {
	var kept []crowdsecFailure
	for _, e := range entries {
		if crowdsecNow().Sub(e.At) < crowdsecRetryAfter {
			kept = append(kept, e)
		}
	}
	return kept
}

func crowdsecRecentlyFailed(hash string) bool {
	return recentlyAt(loadCrowdsecMemory().Failures, hash)
}

func crowdsecRecentlyHealed(hash string) bool {
	return recentlyAt(loadCrowdsecMemory().Heals, hash)
}

func rememberCrowdsecFailure(hashes ...string) {
	f := loadCrowdsecMemory()
	f.Failures = nil
	now := crowdsecNow()
	for _, h := range hashes {
		f.Failures = append(f.Failures, crowdsecFailure{Hash: h, At: now})
	}
	f.Heals = recentOnly(f.Heals)
	if err := writeCrowdsecFailures(f); err != nil {
		logging.Named("SYNC_API").Warnw("CrowdSec: could not record the failed apply", "error", err)
	}
}

func rememberCrowdsecHeal(hash string) {
	f := loadCrowdsecMemory()
	f.Heals = append(recentOnly(f.Heals), crowdsecFailure{Hash: hash, At: crowdsecNow()})
	if err := writeCrowdsecFailures(f); err != nil {
		logging.Named("SYNC_API").Warnw("CrowdSec: could not record the restart", "error", err)
	}
}

// clearCrowdsecFailures forgets the failed applies after a verified one; the
// heals of the last crowdsecRetryAfter stay.
func clearCrowdsecFailures() {
	heals := recentOnly(loadCrowdsecMemory().Heals)
	if len(heals) > 0 {
		if err := writeCrowdsecFailures(crowdsecFailureFile{Heals: heals}); err != nil {
			logging.Named("SYNC_API").Warnw("CrowdSec: could not clear the failed-apply memory", "error", err)
		}
		return
	}
	if err := os.Remove(crowdsecStatePath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		logging.Named("SYNC_API").Warnw("CrowdSec: could not clear the failed-apply memory", "error", err)
	}
}

func writeCrowdsecFailures(f crowdsecFailureFile) error {
	data, err := json.Marshal(f)
	if err != nil {
		return err
	}
	dir := filepath.Dir(crowdsecStatePath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".crowdsec-apply.*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), crowdsecStatePath)
}

// ---------------------------------------------------------------------------
// Executor
// ---------------------------------------------------------------------------

func crowdsecSleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func isCrowdsecTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// crowdsecEngineDown is the status of a service whose supervisor runs while
// the crowdsec engine does not.
const crowdsecEngineDown = "engine not running"

// crowdsecEnginePidfile is the pidfile daemon(8) writes for the engine it
// supervises (os-crowdsec's rc script runs it with -p /var/run/crowdsec.pid).
var crowdsecEnginePidfile = "/var/run/crowdsec.pid"

// crowdsecEnginePID returns the pid of the running crowdsec engine, 0 when it
// does not run. Tests replace it.
var crowdsecEnginePID = supervisedCrowdsecPID

// supervisedCrowdsecPID is the pid in the engine's pidfile when a process of
// that pid is named exactly crowdsec, so neither a stale pidfile nor another
// crowdsec run (a config test, one started by hand) counts. The bouncer's
// process name only starts with "crowdsec".
func supervisedCrowdsecPID(ctx context.Context) (int, error) {
	// daemon(8) keeps the file for as long as it supervises: it empties it
	// when the engine dies (FreeBSD 14.3 and later; earlier releases leave the
	// dead pid in it), so an empty file is an engine that is down. No file at
	// all is a layout this check does not know, so it decides nothing.
	data, err := os.ReadFile(crowdsecEnginePidfile)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return 0, nil
	}
	pids, err := processesNamed(ctx, "crowdsec")
	if err != nil {
		return 0, err
	}
	for _, p := range pids {
		if p == pid {
			return pid, nil
		}
	}
	return 0, nil
}

// processesNamed returns the pids of the processes named exactly name: pgrep
// exits 0 when there are some and 1 when there are none. It is /bin/pgrep, on
// the rc.d PATH.
func processesNamed(ctx context.Context, name string) ([]int, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "pgrep", "-x", name).Output()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, field := range strings.Fields(string(out)) {
		if pid, err := strconv.Atoi(field); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

// crowdsecServiceStatus is the plugin's service status, checked against the
// engine, and the engine's pid when it was checked. The plugin answers from
// the pid of the daemon(8) that supervises crowdsec, which stays "running"
// while it retries an engine that cannot start, so a "running" for a model
// that runs the engine (agent or LAPI on) also needs the engine itself. A
// probe that cannot run leaves the plugin's answer, with no pid.
func crowdsecServiceStatus(ctx context.Context, client *opnapi.Client, model map[string]string) (string, int, error) {
	status, err := client.CrowdsecServiceStatus(ctx)
	if err != nil || status != "running" || (model["agent_enabled"] != "1" && model["lapi_enabled"] != "1") {
		return status, 0, err
	}
	pid, probeErr := crowdsecEnginePID(ctx)
	if probeErr != nil {
		logging.Named("SYNC_API").Warnw("Could not check the CrowdSec engine process; taking the plugin's status", "error", probeErr)
		return status, 0, nil
	}
	if pid == 0 {
		return crowdsecEngineDown, 0, nil
	}
	return status, pid, nil
}

type crowdsecRun struct {
	client  *opnapi.Client
	name    string
	results []SyncAPIItemResult
	errors  []string
}

func (r *crowdsecRun) fail(item SyncAPIItemResult, msg string) {
	item.Status = "error"
	item.Error = msg
	r.results = append(r.results, item)
	r.errors = append(r.errors, msg)
}

func (r *crowdsecRun) result() SyncAPIResult {
	return SyncAPIResult{Success: len(r.errors) == 0, Message: "No changes applied", Results: r.results, Errors: r.errors}
}

func (r *crowdsecRun) applyFail(msg string) {
	r.fail(SyncAPIItemResult{Type: "crowdsec_apply", Name: "reconfigure", Action: "apply"}, msg)
}

// reconfigure runs the one reconfigure of this SYNC and checks the service
// status against the enablement the model asks for. It returns whether the
// apply is verified.
func (r *crowdsecRun) reconfigure(ctx context.Context, model map[string]string) bool {
	log := logging.Named("SYNC_API")
	want := "disabled"
	if crowdsecEnabledPair(model) {
		want = "running"
	}

	if err := r.client.ReconfigureCrowdsec(ctx); err != nil {
		if ctx.Err() != nil || !isCrowdsecTimeout(err) {
			r.applyFail(fmt.Sprintf("CrowdSec settings snippet %q: %v", r.name, err))
			return false
		}
		// The call may still have run to the end on the device; the status
		// below decides, and nothing is sent again.
		log.Warnw("CrowdSec reconfigure did not answer in time; verifying with the service status", "error", err)
		r.results = append(r.results, SyncAPIItemResult{
			Type: "crowdsec_apply", Name: "reconfigure", Action: "apply", Status: "warning",
			Error: "the reconfigure did not answer in time; the result is taken from the service status",
		})
	}

	// An engine that crashes and is started again every few seconds reads as
	// up between two restarts, so the same engine has to be seen again once
	// crowdsecEngineSettle has passed. An engine first seen late gets the time
	// to settle past the poll's deadline; ceiling bounds a crash loop, which
	// shows a new engine at every restart.
	deadline := crowdsecNow().Add(crowdsecPollTimeout)
	ceiling := deadline.Add(crowdsecEngineSettle + 2*crowdsecPollInterval)
	var status string
	var statusErr error
	var seenPID, engines int
	var seenAt time.Time
	for {
		var pid int
		status, pid, statusErr = crowdsecServiceStatus(ctx, r.client, model)
		if statusErr == nil && status == want {
			if pid == 0 || crowdsecEngineSettle <= 0 || (pid == seenPID && crowdsecNow().Sub(seenAt) >= crowdsecEngineSettle) {
				return true
			}
			if pid != seenPID {
				seenPID, seenAt = pid, crowdsecNow()
				engines++
				if settled := seenAt.Add(crowdsecEngineSettle + crowdsecPollInterval); settled.After(deadline) {
					deadline = settled
					if deadline.After(ceiling) {
						deadline = ceiling
					}
				}
			}
		}
		if ctx.Err() != nil || !crowdsecNow().Before(deadline) {
			break
		}
		crowdsecSleep(ctx, crowdsecPollInterval)
	}
	if statusErr != nil {
		r.applyFail(fmt.Sprintf("CrowdSec settings snippet %q: could not read the service status after the reconfigure: %v", r.name, statusErr))
	} else if status == crowdsecEngineDown && engines > 0 {
		r.applyFail(fmt.Sprintf("CrowdSec settings snippet %q: the crowdsec engine started after the reconfigure but did not stay up for %s; see /var/log/crowdsec/crowdsec.log on the device", r.name, crowdsecEngineSettle))
	} else if status == crowdsecEngineDown {
		r.applyFail(fmt.Sprintf("CrowdSec settings snippet %q: the crowdsec engine is not running after the reconfigure, though its supervisor is; see /var/log/crowdsec/crowdsec.log on the device", r.name))
	} else if status == want && engines > 1 {
		r.applyFail(fmt.Sprintf("CrowdSec settings snippet %q: the crowdsec engine did not stay up for %s after the reconfigure: it keeps being restarted; see /var/log/crowdsec/crowdsec.log on the device", r.name, crowdsecEngineSettle))
	} else if status == want {
		r.applyFail(fmt.Sprintf("CrowdSec settings snippet %q: the crowdsec engine could not be seen running for %s before the poll ended", r.name, crowdsecEngineSettle))
	} else {
		r.applyFail(fmt.Sprintf("CrowdSec settings snippet %q: the service status is %q after the reconfigure, expected %q", r.name, status, want))
	}
	return false
}

// executeSyncCrowdsec applies the CROWDSEC_SETTINGS snippet. Without a
// snippet it does nothing at all; removing the snippet leaves the device as
// it is, because the plugin's defaults turn protection on. With one, every key
// it leaves out is set to its default (crowdsecDefaults): an empty snippet
// puts the device at the plugin's defaults.
func executeSyncCrowdsec(ctx context.Context, client *opnapi.Client, desired *crowdsecDesired) SyncAPIResult {
	if desired == nil {
		return SyncAPIResult{Success: true, Message: "No changes applied"}
	}
	log := logging.Named("SYNC_API")
	run := &crowdsecRun{client: client, name: desired.Name}

	current, err := client.GetCrowdsecGeneral(ctx)
	if err != nil {
		if opnapi.IsNotFound(err) {
			// An assigned snippet that cannot apply is a warning, not a
			// neutral skip, so the console shows it; it does not fail the
			// task, because the device lacks the plugin, not the sync.
			msg := fmt.Sprintf("CrowdSec settings snippet %q was not applied: os-crowdsec is not installed on this device (install it, for example with a software policy)", desired.Name)
			log.Warnw("SYNC_API: " + msg)
			run.results = append(run.results, SyncAPIItemResult{
				Type: crowdsecItemType, Name: desired.Name, Action: "skipped", Status: "warning", Error: msg,
			})
			return run.result()
		}
		run.fail(SyncAPIItemResult{Type: "crowdsec_discovery", Name: "general", Action: "discover"},
			fmt.Sprintf("CrowdSec settings snippet %q: failed to read the plugin settings: %v", desired.Name, err))
		return run.result()
	}

	// Keys the installed plugin does not have are reported and not sent: the
	// device would drop them and still answer "saved". A key the snippet
	// leaves out is sent as its default, and silently skipped when the plugin
	// does not have it.
	wanted := map[string]string{}
	defaulted := map[string]bool{}
	for _, key := range crowdsecKeys {
		value, set := desired.Values[key]
		_, known := current[key]
		if !set {
			if known {
				wanted[key] = crowdsecDefaults[key]
				defaulted[key] = true
			}
			continue
		}
		if !known {
			run.results = append(run.results, SyncAPIItemResult{
				Type: crowdsecItemType, Name: desired.Name, Action: "skipped", Status: "warning",
				Error: fmt.Sprintf("setting %q is not known to the installed os-crowdsec plugin and was not sent", key),
			})
			continue
		}
		wanted[key] = value
	}

	normalized := map[string]string{}
	for key, value := range current {
		normalized[key] = normalizeCrowdsecValue(key, value)
	}
	changed := map[string]string{}
	var changedKeys []string
	for _, key := range crowdsecKeys {
		if value, ok := wanted[key]; ok && normalized[key] != value {
			changed[key] = value
			changedKeys = append(changedKeys, key)
		}
	}

	status, _, statusErr := crowdsecServiceStatus(ctx, client, normalized)
	if statusErr != nil {
		status = ""
	}
	preHash := crowdsecStateHash(wanted, normalized, status)

	if len(changed) == 0 {
		run.heal(ctx, normalized, wanted, status, statusErr, preHash)
		return run.result()
	}

	merged := map[string]string{}
	for k, v := range normalized {
		merged[k] = v
	}
	for k, v := range changed {
		merged[k] = v
	}
	enablementChanged := false
	for _, key := range []string{"agent_enabled", "lapi_enabled", "firewall_bouncer_enabled"} {
		if _, ok := changed[key]; ok {
			enablementChanged = true
		}
	}
	if enablementChanged {
		if msg := crowdsecGuardViolation(merged); msg != "" {
			var fromDefault []string
			for _, key := range []string{"agent_enabled", "lapi_enabled", "firewall_bouncer_enabled"} {
				if defaulted[key] {
					fromDefault = append(fromDefault, key)
				}
			}
			if len(fromDefault) > 0 {
				msg += fmt.Sprintf("; %s left out of the snippet, so at the plugin's default", strings.Join(fromDefault, ", "))
			}
			run.fail(SyncAPIItemResult{Type: crowdsecItemType, Name: desired.Name, Action: "refused"},
				fmt.Sprintf("CrowdSec settings snippet %q: %s", desired.Name, msg))
			return run.result()
		}
	}
	if defaulted["lapi_enabled"] && changed["lapi_enabled"] == "1" && normalized["lapi_manual_configuration"] == "1" {
		run.results = append(run.results, SyncAPIItemResult{
			Type: crowdsecItemType, Name: desired.Name, Action: "updated", Status: "warning",
			Error: fmt.Sprintf("CrowdSec settings snippet %q leaves out lapi_enabled, which takes the plugin's default and starts a local LAPI on this device, whose agent and bouncer use a remote one (lapi_manual_configuration); set lapi_enabled to false to keep it off", desired.Name),
		})
	}

	if crowdsecRecentlyFailed(preHash) {
		run.withheld()
		return run.result()
	}

	if err := client.SetCrowdsecGeneral(ctx, changed); err != nil {
		var verr *opnapi.CrowdsecValidationError
		if errors.As(err, &verr) {
			fields := make([]string, 0, len(verr.Fields))
			for f := range verr.Fields {
				fields = append(fields, f)
			}
			sort.Strings(fields)
			for _, f := range fields {
				run.fail(SyncAPIItemResult{Type: crowdsecItemType, Name: desired.Name, Action: "skipped"},
					fmt.Sprintf("CrowdSec settings snippet %q: %s: %s", desired.Name, f, verr.Fields[f]))
			}
		} else {
			run.fail(SyncAPIItemResult{Type: crowdsecItemType, Name: desired.Name, Action: "skipped"},
				fmt.Sprintf("CrowdSec settings snippet %q: %v", desired.Name, err))
		}
		return run.result()
	}

	// The write is accepted, so the one reconfigure below runs whatever the
	// read-back says: the next SYNC would see no difference and never apply
	// the kept keys.
	effective := merged
	droppedSet := map[string]bool{}
	after, err := client.GetCrowdsecGeneral(ctx)
	if err != nil {
		run.fail(SyncAPIItemResult{Type: crowdsecItemType, Name: desired.Name, Action: "skipped"},
			fmt.Sprintf("CrowdSec settings snippet %q: could not read the settings back: %v", desired.Name, err))
	} else {
		var dropped []string
		effective = map[string]string{}
		for k, v := range after {
			effective[k] = normalizeCrowdsecValue(k, v)
		}
		for _, key := range changedKeys {
			if effective[key] != changed[key] {
				dropped = append(dropped, key)
				droppedSet[key] = true
			}
		}
		if len(dropped) > 0 {
			run.fail(SyncAPIItemResult{Type: crowdsecItemType, Name: desired.Name, Action: "skipped"},
				fmt.Sprintf("CrowdSec settings snippet %q: the device did not keep %s", desired.Name, strings.Join(dropped, ", ")))
			if len(dropped) == len(changedKeys) {
				return run.result()
			}
		}
	}

	run.results = append(run.results, SyncAPIItemResult{
		Type: crowdsecItemType, Name: desired.Name, Action: "updated", Status: "success",
	})
	log.Infow("CrowdSec settings written", "name", desired.Name, "keys", changedKeys)

	verified := run.reconfigure(ctx, effective)
	if verified {
		clearCrowdsecFailures()
	} else {
		// Both digests are kept: the pre-set one blocks a repeat when the
		// device drifts back to this state, the post-set one blocks the heal
		// the next SYNC would run on the settings this apply left behind.
		postStatus, _, _ := crowdsecServiceStatus(ctx, client, effective)
		rememberCrowdsecFailure(preHash, crowdsecStateHash(wanted, effective, postStatus))
	}

	if key, ok := changed["enroll_key"]; ok && key != "" && verified && !droppedSet["enroll_key"] {
		run.results = append(run.results, SyncAPIItemResult{
			Type: "crowdsec_enrollment", Name: "enroll_key", Action: "requested", Status: "success",
			Error: "Enrollment was requested and is not verified: the agent cannot see whether the CrowdSec Console accepts the key, or whether an engine already enrolled takes it. Accept the engine in the Console to complete it",
		})
	}
	return run.result()
}

// heal runs the one reconfigure for a device whose settings already match but
// whose service is not running although it should be.
func (r *crowdsecRun) heal(ctx context.Context, model, wanted map[string]string, status string, statusErr error, hash string) {
	if !crowdsecEnabledPair(model) {
		return
	}
	if statusErr != nil {
		r.results = append(r.results, SyncAPIItemResult{
			Type: "crowdsec_apply", Name: "status", Action: "check", Status: "warning",
			Error: fmt.Sprintf("CrowdSec settings snippet %q: could not read the service status: %v", r.name, statusErr),
		})
		return
	}
	if status == "running" {
		return
	}
	if crowdsecRecentlyFailed(hash) {
		r.withheld()
		return
	}
	if msg := crowdsecGuardViolation(model); msg != "" {
		r.results = append(r.results, SyncAPIItemResult{
			Type: "crowdsec_apply", Name: "reconfigure", Action: "skipped", Status: "warning",
			Error: fmt.Sprintf("CrowdSec settings snippet %q: not restarted: %s", r.name, msg),
		})
		return
	}
	healKey := crowdsecStateHash(wanted, model, "")
	if crowdsecRecentlyHealed(healKey) {
		r.fail(SyncAPIItemResult{Type: "crowdsec_apply", Name: "reconfigure", Action: "skipped"},
			fmt.Sprintf("CrowdSec settings snippet %q: the service status is %q again; it was restarted less than %s ago, so it is not restarted again yet", r.name, status, crowdsecRetryAfter))
		return
	}
	logging.Named("SYNC_API").Infow("CrowdSec settings match but the service is not running; reconfiguring once", "status", status)
	rememberCrowdsecHeal(healKey)
	if r.reconfigure(ctx, model) {
		clearCrowdsecFailures()
		r.results = append(r.results, SyncAPIItemResult{
			Type: crowdsecItemType, Name: r.name, Action: "restarted", Status: "success",
		})
		return
	}
	postStatus, _, _ := crowdsecServiceStatus(ctx, r.client, model)
	rememberCrowdsecFailure(hash, crowdsecStateHash(wanted, model, postStatus))
}

func (r *crowdsecRun) withheld() {
	r.fail(SyncAPIItemResult{Type: "crowdsec_apply", Name: "reconfigure", Action: "skipped"},
		fmt.Sprintf("CrowdSec settings snippet %q: not applied again because the previous apply failed and neither the snippet nor the device changed since; try again later or change the snippet", r.name))
}

// syncCrowdsecFromPayload parses and applies the CROWDSEC_SETTINGS snippet. A
// bad snippet fails this section only: the rest of the SYNC still applies.
func syncCrowdsecFromPayload(ctx context.Context, client *opnapi.Client, payload map[string]interface{}) SyncAPIResult {
	desired, err := parseAPICrowdsecSettings(payload)
	if err != nil {
		msg := fmt.Sprintf("Failed to parse crowdsec_settings: %v", err)
		return SyncAPIResult{
			Success: false,
			Message: msg,
			Results: []SyncAPIItemResult{{Type: crowdsecItemType, Name: "crowdsec_settings", Action: "parse", Status: "error", Error: msg}},
			Errors:  []string{msg},
		}
	}
	return executeSyncCrowdsec(ctx, client, desired)
}
