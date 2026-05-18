package tasks

import (
	"fmt"
	"strings"
)

// syncSectionLabels maps SyncAPIItemResult.Type values to the
// human-readable label used in the sync summary. Iteration order
// determines section order in the rendered message.
var syncSectionLabels = []struct {
	Type  string
	Label string
}{
	{"alias", "Aliases"},
	{"rule", "Rules"},
	{"user", "Users"},
	{"group", "Groups"},
	{"host_override", "Unbound host-overrides"},
	{"host_alias", "Unbound host-aliases"},
	{"domain_forward", "Unbound domain-forwards"},
	{"unbound_acl", "Unbound ACLs"},
	{"wg_server", "VPN servers"},
	{"wg_client", "VPN clients"},
	{"zabbix_settings", "Zabbix settings"},
	{"zabbix_userparameter", "Zabbix userparams"},
	{"zabbix_alias", "Zabbix aliases"},
}

// normalizeSyncAction collapses the past/present-tense action variants
// used across executors (VPN emits "create", everything else emits
// "created") into a single canonical form. Unrecognized values return
// an empty string so the caller can skip them.
func normalizeSyncAction(action string) string {
	switch action {
	case "create", "created":
		return "created"
	case "update", "updated":
		return "updated"
	case "delete", "deleted":
		return "deleted"
	}
	return ""
}

// isSyncSuccessStatus accepts the two success tokens historically used
// by the sub-executors ("success" elsewhere, "ok" in sync_vpn).
func isSyncSuccessStatus(status string) bool {
	return status == "success" || status == "ok"
}

// buildSyncSummary produces a compact one-line summary of sync results.
//
// Per section the format is "<Label> +A ~M -D"; operations with zero
// count are omitted and sections that were not touched at all are
// dropped entirely. Sections are joined with "; ". When nothing was
// touched the message is "No changes applied". When errorCount > 0 the
// suffix " (N errors)" is appended.
func buildSyncSummary(results []SyncAPIItemResult, errorCount int) string {
	type counts struct{ created, updated, deleted int }
	tally := map[string]*counts{}
	for _, r := range results {
		if !isSyncSuccessStatus(r.Status) {
			continue
		}
		act := normalizeSyncAction(r.Action)
		if act == "" {
			continue
		}
		c := tally[r.Type]
		if c == nil {
			c = &counts{}
			tally[r.Type] = c
		}
		switch act {
		case "created":
			c.created++
		case "updated":
			c.updated++
		case "deleted":
			c.deleted++
		}
	}

	var parts []string
	for _, section := range syncSectionLabels {
		c, ok := tally[section.Type]
		if !ok {
			continue
		}
		var ops []string
		if c.created > 0 {
			ops = append(ops, fmt.Sprintf("+%d", c.created))
		}
		if c.updated > 0 {
			ops = append(ops, fmt.Sprintf("~%d", c.updated))
		}
		if c.deleted > 0 {
			ops = append(ops, fmt.Sprintf("-%d", c.deleted))
		}
		if len(ops) == 0 {
			continue
		}
		parts = append(parts, section.Label+" "+strings.Join(ops, " "))
	}

	message := "No changes applied"
	if len(parts) > 0 {
		message = strings.Join(parts, "; ")
	}
	if errorCount > 0 {
		message = fmt.Sprintf("%s (%d errors)", message, errorCount)
	}
	return message
}
