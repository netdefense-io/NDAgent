package tasks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// recorder collects the sequence's steps in execution order, which is
// what most of these assertions are actually about: the ordering is the
// safety property, not an implementation detail.
type recorder struct {
	steps []string
}

func (r *recorder) add(s string) { r.steps = append(r.steps, s) }

func (r *recorder) indexOf(s string) int {
	for i, got := range r.steps {
		if got == s {
			return i
		}
	}
	return -1
}

// newTestDecommissioner builds a Decommissioner whose every effect is
// recorded and whose sleeps are instant.
func newTestDecommissioner(t *testing.T, rec *recorder) *Decommissioner {
	t.Helper()
	d := &Decommissioner{
		Backoffs: []time.Duration{time.Millisecond, 2 * time.Millisecond, 3 * time.Millisecond},
		Sleep:    func(context.Context, time.Duration) error { return nil },
		RemoveReadonlyIdentity: func(context.Context) error {
			rec.add("remove_readonly")
			return nil
		},
		RemoveAgentIdentity: func(context.Context) error {
			rec.add("remove_agent")
			return nil
		},
		DeprovisionAccounts: func(context.Context) error {
			rec.add("deprovision_accounts")
			return nil
		},
		ResetPluginSettings: func(context.Context) error {
			rec.add("reset_settings")
			return nil
		},
		ForkHelper: func(context.Context) error {
			rec.add("fork_helper")
			return nil
		},
		Shutdown: func() { rec.add("shutdown") },
	}
	// Log to a temp file so the real /var/log path is never touched and
	// the written lines can be asserted.
	f, err := os.Create(filepath.Join(t.TempDir(), "decommission.log"))
	if err != nil {
		t.Fatalf("temp log: %v", err)
	}
	d.Log = f
	return d
}

func TestDecommission_OrderIsReversibleHalfFirst(t *testing.T) {
	rec := &recorder{}
	d := newTestDecommissioner(t, rec)
	d.Families = []DecommissionFamily{
		{Name: "vpn", Reconcile: func(context.Context) error { rec.add("family_vpn"); return nil }},
		{Name: "aliases_rules", Reconcile: func(context.Context) error { rec.add("family_aliases_rules"); return nil }},
	}

	if err := d.Run(context.Background(), "2026-09-18T23:40:12Z", "abcd"); err != nil {
		t.Fatalf("Run: %v", err)
	}

	want := []string{
		"family_vpn",
		"family_aliases_rules",
		"remove_readonly",
		"remove_agent",
		"deprovision_accounts",
		"reset_settings",
		"fork_helper",
		"shutdown",
	}
	if strings.Join(rec.steps, ",") != strings.Join(want, ",") {
		t.Fatalf("sequence = %v, want %v", rec.steps, want)
	}
}

// netdefense-agent backs the API credentials every other call uses, so it
// must be the last OPNsense call of the whole sequence.
func TestDecommission_AgentIdentityRemovedAfterEverythingElse(t *testing.T) {
	rec := &recorder{}
	d := newTestDecommissioner(t, rec)
	d.Families = []DecommissionFamily{
		{Name: "zabbix", Reconcile: func(context.Context) error { rec.add("family_zabbix"); return nil }},
	}

	if err := d.Run(context.Background(), "", ""); err != nil {
		t.Fatalf("Run: %v", err)
	}

	agent := rec.indexOf("remove_agent")
	readonly := rec.indexOf("remove_readonly")
	family := rec.indexOf("family_zabbix")
	if !(family < readonly && readonly < agent) {
		t.Fatalf("expected families < readonly < agent, got %v", rec.steps)
	}
}

// The helper is what makes the change irreversible. It must never run
// before the reconciliation that needs the package still installed.
func TestDecommission_HelperForkedOnlyAfterReconciliation(t *testing.T) {
	rec := &recorder{}
	d := newTestDecommissioner(t, rec)
	d.Families = []DecommissionFamily{
		{Name: "a", Reconcile: func(context.Context) error { rec.add("family_a"); return nil }},
		{Name: "b", Reconcile: func(context.Context) error { rec.add("family_b"); return nil }},
	}

	if err := d.Run(context.Background(), "", ""); err != nil {
		t.Fatalf("Run: %v", err)
	}

	fork := rec.indexOf("fork_helper")
	for _, step := range []string{
		"family_a", "family_b", "remove_readonly", "remove_agent",
		"deprovision_accounts", "reset_settings",
	} {
		if rec.indexOf(step) > fork {
			t.Fatalf("%s ran after the helper fork: %v", step, rec.steps)
		}
	}
	if rec.indexOf("shutdown") < fork {
		t.Fatalf("shutdown requested before the helper was forked: %v", rec.steps)
	}
}

func TestDecommission_FamilyRetriesThenContinues(t *testing.T) {
	rec := &recorder{}
	d := newTestDecommissioner(t, rec)

	var attempts int
	var sleeps []time.Duration
	d.Sleep = func(_ context.Context, delay time.Duration) error {
		sleeps = append(sleeps, delay)
		return nil
	}
	d.Families = []DecommissionFamily{
		{Name: "flaky", Reconcile: func(context.Context) error {
			attempts++
			return errors.New("api unreachable")
		}},
		{Name: "after", Reconcile: func(context.Context) error { rec.add("family_after"); return nil }},
	}

	if err := d.Run(context.Background(), "", ""); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if attempts != 3 {
		t.Errorf("attempts = %d, want 3", attempts)
	}
	// Two waits for three attempts: nothing follows the final failure.
	if len(sleeps) != 2 {
		t.Errorf("sleeps = %v, want 2 entries", sleeps)
	}
	if len(sleeps) == 2 && !(sleeps[0] < sleeps[1]) {
		t.Errorf("backoff did not grow: %v", sleeps)
	}
	// Continue-on-failure: a family that will not converge must not stop
	// the sequence, or a deleted device keeps running NetDefense forever.
	if rec.indexOf("family_after") < 0 {
		t.Error("the next family did not run after a failed one")
	}
	if rec.indexOf("fork_helper") < 0 || rec.indexOf("shutdown") < 0 {
		t.Errorf("the irreversible half was skipped after a failed family: %v", rec.steps)
	}
}

func TestDecommission_SucceedsOnFirstAttemptWithoutSleeping(t *testing.T) {
	rec := &recorder{}
	d := newTestDecommissioner(t, rec)

	slept := false
	d.Sleep = func(context.Context, time.Duration) error { slept = true; return nil }
	d.Families = []DecommissionFamily{
		{Name: "ok", Reconcile: func(context.Context) error { return nil }},
	}

	if err := d.Run(context.Background(), "", ""); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if slept {
		t.Error("a family that converged on the first attempt should not back off")
	}
}

// A failure to remove an identity is recorded and stepped over, the same
// as a family failure — the package still has to come off.
func TestDecommission_IdentityFailureDoesNotStopTheSequence(t *testing.T) {
	rec := &recorder{}
	d := newTestDecommissioner(t, rec)
	d.RemoveReadonlyIdentity = func(context.Context) error {
		rec.add("remove_readonly")
		return errors.New("user endpoint 500")
	}

	if err := d.Run(context.Background(), "", ""); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rec.indexOf("fork_helper") < 0 {
		t.Fatalf("helper not forked after an identity failure: %v", rec.steps)
	}
}

// The local deprovision is the step that actually removes
// netdefense-agent: OPNsense refuses to delete the account whose
// credentials authenticate the API request, so the API call before it
// fails on every real device. It therefore has to run AFTER the API
// attempts (they are still the path that removes netdefense-readonly and
// its group) and BEFORE the helper fork, which takes the plugin's PHP off
// the box.
func TestDecommission_LocalDeprovisionRunsAfterTheAPIRemovalsAndBeforeTheFork(t *testing.T) {
	rec := &recorder{}
	d := newTestDecommissioner(t, rec)

	if err := d.Run(context.Background(), "", ""); err != nil {
		t.Fatalf("Run: %v", err)
	}

	deprovision := rec.indexOf("deprovision_accounts")
	if deprovision < 0 {
		t.Fatalf("the local deprovision never ran: %v", rec.steps)
	}
	if rec.indexOf("remove_agent") > deprovision {
		t.Errorf("the API removal ran after the local deprovision: %v", rec.steps)
	}
	if rec.indexOf("fork_helper") < deprovision {
		t.Errorf("the helper was forked before the local deprovision: %v", rec.steps)
	}
}

// The real device always takes this path: the API delete of
// netdefense-agent returns HTTP 500 "Not allowed to remove logged in
// user". That failure is recorded, the local deprovision still runs, and
// the wipe still completes.
func TestDecommission_LocalDeprovisionStillRunsWhenTheAPIRemovalIsRefused(t *testing.T) {
	rec := &recorder{}
	d := newTestDecommissioner(t, rec)
	d.RemoveAgentIdentity = func(context.Context) error {
		rec.add("remove_agent")
		return errors.New(`API error: status 500, body: ` +
			`{"errorMessage":"Not allowed to remove logged in user netdefense-agent",` +
			`"errorTitle":"Usermanager"}`)
	}
	logPath := d.Log.Name()

	if err := d.Run(context.Background(), "", ""); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if rec.indexOf("deprovision_accounts") < 0 {
		t.Fatalf("the local deprovision was skipped after the API refusal: %v", rec.steps)
	}
	if rec.indexOf("fork_helper") < 0 {
		t.Fatalf("the helper was not forked after the API refusal: %v", rec.steps)
	}

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	body := string(raw)
	if !strings.Contains(body, "FAILED: remove netdefense-agent") {
		t.Errorf("the API refusal was not recorded in the log:\n%s", body)
	}
	if !strings.Contains(body, "OK: deprovision local accounts") {
		t.Errorf("the local deprovision outcome was not recorded in the log:\n%s", body)
	}
}

// Same continue-on-failure rule as every other reversible step: a failed
// deprovision is recorded and stepped over. The uninstall helper runs the
// same call once more before pkg delete, so this is not the last chance.
func TestDecommission_DeprovisionFailureDoesNotStopTheSequence(t *testing.T) {
	rec := &recorder{}
	d := newTestDecommissioner(t, rec)
	d.DeprovisionAccounts = func(context.Context) error {
		rec.add("deprovision_accounts")
		return errors.New("configure.php --deprovision-accounts failed: exit status 22")
	}
	logPath := d.Log.Name()

	if err := d.Run(context.Background(), "", ""); err != nil {
		t.Fatalf("Run: %v", err)
	}

	for _, step := range []string{"reset_settings", "fork_helper", "shutdown"} {
		if rec.indexOf(step) < 0 {
			t.Fatalf("%s was skipped after a failed deprovision: %v", step, rec.steps)
		}
	}

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if !strings.Contains(string(raw), "FAILED: deprovision local accounts") {
		t.Errorf("the deprovision failure was not recorded in the log:\n%s", string(raw))
	}
}

// A device that never had OPNsense API credentials still has both
// accounts in config.xml if a provisioning run got that far, so the local
// deprovision must be wired with or without an API client.
func TestNewDecommissioner_DeprovisionWiredWithoutAnAPIClient(t *testing.T) {
	d := NewDecommissioner(nil, "os-netdefense", func() {})

	if d.DeprovisionAccounts == nil {
		t.Fatal("DeprovisionAccounts is nil for a device with no API client")
	}
	if d.RemoveAgentIdentity != nil || d.RemoveReadonlyIdentity != nil {
		t.Error("the API identity removals should stay unwired without an API client")
	}
	if len(d.Families) != 0 {
		t.Errorf("families = %d, want 0 without an API client", len(d.Families))
	}
}

func TestDecommission_ForkFailureStillShutsDownAndReports(t *testing.T) {
	rec := &recorder{}
	d := newTestDecommissioner(t, rec)
	d.ForkHelper = func(context.Context) error {
		rec.add("fork_helper")
		return errors.New("helper missing")
	}

	err := d.Run(context.Background(), "", "")
	if err == nil {
		t.Fatal("expected an error when the uninstall helper cannot be started")
	}
	if rec.indexOf("shutdown") < 0 {
		t.Errorf("agent did not shut down after a failed fork: %v", rec.steps)
	}
}

// The log is the only post-mortem record: the device row is gone, no
// task response is sent, and /var/db/ndagent is about to be deleted.
func TestDecommission_WritesTheLocalLog(t *testing.T) {
	rec := &recorder{}
	d := newTestDecommissioner(t, rec)
	logPath := d.Log.Name()
	d.Families = []DecommissionFamily{
		{Name: "flaky", Reconcile: func(context.Context) error { return errors.New("boom") }},
	}

	if err := d.Run(context.Background(), "2026-09-18T23:40:12Z", "deadbeef"); err != nil {
		t.Fatalf("Run: %v", err)
	}

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	body := string(raw)
	for _, want := range []string{
		"decommission start",
		"2026-09-18T23:40:12Z",
		"deadbeef",
		"FAILED: family flaky",
		"forked uninstall helper",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("log does not mention %q:\n%s", want, body)
		}
	}
}

func TestSyncResultError(t *testing.T) {
	if err := syncResultError(SyncAPIResult{Success: true}); err != nil {
		t.Errorf("success result produced error %v", err)
	}
	err := syncResultError(SyncAPIResult{Success: false, Errors: []string{"alias x", "rule y"}})
	if err == nil || !strings.Contains(err.Error(), "alias x") || !strings.Contains(err.Error(), "rule y") {
		t.Errorf("failure result lost its detail: %v", err)
	}
	if err := syncResultError(SyncAPIResult{Success: false}); err == nil {
		t.Error("a failed result with no detail must still be an error")
	}
}
