//go:build integration
// +build integration

package tasks

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// Lab test for an alias whose snippet now carries another uuid under the same
// name, through the real OPNsense alias and rule API:
//
//	go test -tags=integration -run TestIntegration_AliasMove ./internal/tasks/
//
// Like a SYNC, each pass removes every managed alias and rule its payload does
// not name. It refuses to run on a device that holds managed aliases or rules
// of its own unless ND_INTEGRATION_ALLOW_SWEEP=1 says they may go; run a forced
// SYNC of the device afterwards to restore them.

const (
	moveRefOld   = "221f3268-5e1f-4a11-9c11-0000000000a1"
	moveRefNew   = "221f3268-5e1f-4a11-9c11-0000000000a2"
	moveUnrefOld = "221f3268-5e1f-4a11-9c11-0000000000b1"
	moveUnrefNew = "221f3268-5e1f-4a11-9c11-0000000000b2"
	moveRule     = "221f3268-5e1f-4a11-9c11-0000000000c1"
)

func TestIntegration_AliasMove(t *testing.T) {
	client := integrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	ours := map[string]bool{moveRefOld: true, moveRefNew: true, moveUnrefOld: true, moveUnrefNew: true, moveRule: true}
	foreign := foreignManaged(ctx, t, client, ours)
	if len(foreign) > 0 && os.Getenv("ND_INTEGRATION_ALLOW_SWEEP") != "1" {
		t.Skipf("the device holds %d managed aliases or rules this test would remove (%s); set ND_INTEGRATION_ALLOW_SWEEP=1 to allow it", len(foreign), strings.Join(foreign, ", "))
	}
	t.Cleanup(func() {
		cleanup := executeSyncAPI(context.Background(), client, nil, nil)
		if !cleanup.Success {
			t.Errorf("cleanup: %v", cleanup.Errors)
		}
	})

	alias := func(uuid, name, address string) APIAliasPayload {
		return desiredAlias(t, name, `{"uuid":"`+uuid+`","enabled":"1","name":"`+name+`","type":"host","content":"`+address+`","description":"alias move lab test"}`)
	}
	rule := desiredRule(t, "nd_mv_rule", RulePositionAppend, 100,
		`{"uuid":"`+moveRule+`","enabled":"0","action":"pass","interface":"lan","source_net":"nd_mv_ref","description":"alias move lab test"}`)

	pass := func(what string, aliases []APIAliasPayload, rules []APIRulePayload) SyncAPIResult {
		t.Helper()
		result := executeSyncAPI(ctx, client, aliases, rules)
		if !result.Success {
			t.Fatalf("%s: %v (validation %+v)", what, result.Errors, result.ValidationErrors)
		}
		return result
	}
	present := func(uuid string) map[string]interface{} {
		t.Helper()
		rows, err := client.ListAllAliases(ctx)
		if err != nil {
			t.Fatalf("list aliases: %v", err)
		}
		for _, row := range rows {
			if row["uuid"] == uuid {
				return row
			}
		}
		return nil
	}

	pass("setup", []APIAliasPayload{alias(moveRefOld, "nd_mv_ref", "192.0.2.10"), alias(moveUnrefOld, "nd_mv_unref", "192.0.2.20")}, []APIRulePayload{rule})

	moved := pass("new uuids", []APIAliasPayload{alias(moveRefNew, "nd_mv_ref", "192.0.2.11"), alias(moveUnrefNew, "nd_mv_unref", "192.0.2.20")}, []APIRulePayload{rule})
	if present(moveUnrefOld) != nil || present(moveUnrefNew) == nil {
		t.Error("the alias nothing refers to did not take its new uuid")
	}
	if row := present(moveRefOld); row == nil || row["content"] != "192.0.2.11" {
		t.Errorf("the alias the rule names = %v, want it under its old uuid with the new content", row)
	}
	if present(moveRefNew) != nil {
		t.Error("an alias was created under the new uuid while the old object holds the name")
	}
	warning := ruleItem(moved.Results, "alias", moveRefOld)
	if warning == nil || warning.Code != codeAliasKeptUnderEarlierUUID || !strings.Contains(warning.Error, "Cannot delete alias nd_mv_ref") {
		t.Errorf("kept warning = %+v", warning)
	} else {
		t.Logf("kept warning: %s", warning.Error)
	}

	pass("rule removed", []APIAliasPayload{alias(moveRefNew, "nd_mv_ref", "192.0.2.11"), alias(moveUnrefNew, "nd_mv_unref", "192.0.2.20")}, nil)
	if present(moveRefOld) != nil || present(moveRefNew) == nil {
		t.Error("the alias did not take its new uuid in the sync that removed the rule naming it")
	}
}

// foreignManaged lists the managed aliases and rules on the device that are
// not this test's.
func foreignManaged(ctx context.Context, t *testing.T, client *opnapi.Client, ours map[string]bool) []string {
	t.Helper()
	aliases, err := client.ListAllAliases(ctx)
	if err != nil {
		t.Fatalf("list aliases: %v", err)
	}
	rules, err := client.ListAllRules(ctx)
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	var foreign []string
	for _, row := range append(opnapi.FilterManagedAliases(aliases), opnapi.FilterManagedRules(rules)...) {
		if uuid, _ := row["uuid"].(string); !ours[uuid] {
			foreign = append(foreign, uuid)
		}
	}
	return foreign
}
