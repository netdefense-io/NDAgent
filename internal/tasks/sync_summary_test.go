package tasks

import "testing"

func TestBuildSyncSummary_NoChanges(t *testing.T) {
	got := buildSyncSummary(nil, 0)
	if got != "No changes applied" {
		t.Errorf("got %q, want %q", got, "No changes applied")
	}
}

func TestBuildSyncSummary_SingleSectionSingleOp(t *testing.T) {
	results := []SyncAPIItemResult{
		{Type: "alias", Action: "created", Status: "success"},
		{Type: "alias", Action: "created", Status: "success"},
	}
	got := buildSyncSummary(results, 0)
	want := "Aliases +2"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBuildSyncSummary_MultiSectionMixedOps(t *testing.T) {
	results := []SyncAPIItemResult{
		{Type: "alias", Action: "created", Status: "success"},
		{Type: "alias", Action: "created", Status: "success"},
		{Type: "rule", Action: "created", Status: "success"},
		{Type: "rule", Action: "updated", Status: "success"},
		{Type: "rule", Action: "deleted", Status: "success"},
		{Type: "zabbix_settings", Action: "updated", Status: "success"},
	}
	got := buildSyncSummary(results, 0)
	want := "Aliases +2; Rules +1 ~1 -1; Zabbix settings ~1"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBuildSyncSummary_VPNActionVerbsNormalized(t *testing.T) {
	// VPN executor uses present-tense verbs and "ok" status; both should
	// be treated as equivalent to past-tense + "success".
	results := []SyncAPIItemResult{
		{Type: "wg_server", Action: "create", Status: "ok"},
		{Type: "wg_client", Action: "update", Status: "ok"},
		{Type: "wg_client", Action: "delete", Status: "ok"},
	}
	got := buildSyncSummary(results, 0)
	want := "VPN servers +1; VPN clients ~1 -1"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBuildSyncSummary_ErrorsSuffix(t *testing.T) {
	results := []SyncAPIItemResult{
		{Type: "alias", Action: "created", Status: "success"},
	}
	got := buildSyncSummary(results, 2)
	want := "Aliases +1 (2 errors)"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBuildSyncSummary_FailedItemsSkipped(t *testing.T) {
	results := []SyncAPIItemResult{
		{Type: "alias", Action: "created", Status: "success"},
		{Type: "alias", Action: "created", Status: "error"},
		{Type: "rule", Action: "updated", Status: "error"},
	}
	got := buildSyncSummary(results, 2)
	want := "Aliases +1 (2 errors)"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBuildSyncSummary_UnknownTypeIgnored(t *testing.T) {
	// An unrecognized Type produces no section; the rest still render.
	results := []SyncAPIItemResult{
		{Type: "alias", Action: "created", Status: "success"},
		{Type: "mystery_type", Action: "created", Status: "success"},
	}
	got := buildSyncSummary(results, 0)
	want := "Aliases +1"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBuildSyncSummary_SectionOrderStable(t *testing.T) {
	// Sections render in the order declared by syncSectionLabels
	// regardless of the order entries appear in the input slice.
	results := []SyncAPIItemResult{
		{Type: "zabbix_userparameter", Action: "created", Status: "success"},
		{Type: "rule", Action: "created", Status: "success"},
		{Type: "alias", Action: "created", Status: "success"},
		{Type: "user", Action: "created", Status: "success"},
	}
	got := buildSyncSummary(results, 0)
	want := "Aliases +1; Rules +1; Users +1; Zabbix userparams +1"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
