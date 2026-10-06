package tasks

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

const (
	ruleA = "221f3268-000a-4000-8000-00000000000a"
	ruleB = "221f3268-000b-4000-8000-00000000000b"
	ruleC = "221f3268-000c-4000-8000-00000000000c"
)

func ruleItem(results []SyncAPIItemResult, typ, uuid string) *SyncAPIItemResult {
	for i := range results {
		if results[i].Type == typ && results[i].UUID == uuid {
			return &results[i]
		}
	}
	return nil
}

// TestExecuteSyncAPI_WritesTheDeclarativeBody is the reported bug: a RULE
// snippet's "log" reached the device as off. Every field of the snippet is
// sent, in OPNsense's string forms, and every field it leaves out at the
// model's default.
func TestExecuteSyncAPI_WritesTheDeclarativeBody(t *testing.T) {
	device := newFakeRuleDevice(t, ruleTemplate(t), nil)
	rule := desiredRule(t, "logtest", RulePositionPrepend, 100,
		`{"uuid":"`+ruleA+`","action":"pass","interface":"lan","direction":"in","ipprotocol":"inet",
		  "protocol":"any","source_net":"any","destination_net":"any","description":"logtest",
		  "log":"1","quick":false,"statetype":"sloppy"}`, "base")

	result := executeSyncAPI(context.Background(), device.client, nil, []APIRulePayload{rule})

	if !result.Success {
		t.Fatalf("sync failed: %v", result.Errors)
	}
	body := device.lastBody(ruleA)
	if len(body) != 54 {
		t.Errorf("setRule body has %d fields, want the 53 settable ones and the sequence", len(body))
	}
	for field, want := range map[string]string{"log": "1", "quick": "0", "statetype": "sloppy", "description": "logtest [nd-template:base]"} {
		if body[field] != want {
			t.Errorf("%s = %q, want %q", field, body[field], want)
		}
	}
	if item := ruleItem(result.Results, "rule", ruleA); item == nil || item.Action != "created" || item.Status != "success" {
		t.Errorf("rule item = %+v", item)
	}
}

// TestExecuteSyncAPI_UnchangedRulesAreNotRewritten: a sync against a device
// that already holds every rule as desired writes nothing, so it cuts no
// config revision and its summary says so.
func TestExecuteSyncAPI_UnchangedRulesAreNotRewritten(t *testing.T) {
	device := newFakeRuleDevice(t, ruleTemplate(t), nil)
	rules := []APIRulePayload{
		desiredRule(t, "one", RulePositionPrepend, 100, `{"uuid":"`+ruleA+`","action":"pass","interface":"lan","protocol":"udp","log":true}`),
		desiredRule(t, "two", RulePositionAppend, 100, `{"uuid":"`+ruleB+`","action":"block","interface":"wan"}`),
	}

	first := executeSyncAPI(context.Background(), device.client, nil, rules)
	if !first.Success || device.setCount() != 2 {
		t.Fatalf("first sync: success=%v sets=%d errors=%v", first.Success, device.setCount(), first.Errors)
	}
	// OPNsense stores a protocol upper-cased.
	device.edit(ruleA, func(row map[string]interface{}) { row["protocol"] = "UDP" })

	second := executeSyncAPI(context.Background(), device.client, nil, rules)

	if !second.Success {
		t.Fatalf("second sync failed: %v", second.Errors)
	}
	if device.setCount() != 2 {
		t.Errorf("the second sync wrote %d rule(s); a converged device needs none", device.setCount()-2)
	}
	for _, uuid := range []string{ruleA, ruleB} {
		if item := ruleItem(second.Results, "rule", uuid); item == nil || item.Action != "unchanged" || item.Status != "success" {
			t.Errorf("%s item = %+v, want unchanged", uuid, item)
		}
	}
	if summary := buildSyncSummary(second.Results, len(second.Errors)); summary != "No changes applied" {
		t.Errorf("summary = %q", summary)
	}
}

// TestExecuteSyncAPI_SequenceIsPartOfTheComparison: a rule whose content did
// not change is still written when placement gives it another sequence. On
// the 26.7 defaults (local rules at 1 and 11) a lan PREPEND rule takes 1; a
// second one of a lower priority takes 1 and moves the first to 2.
func TestExecuteSyncAPI_SequenceIsPartOfTheComparison(t *testing.T) {
	device := freshDevice(t)
	a := desiredRule(t, "a", RulePositionPrepend, 200, `{"uuid":"`+ruleA+`","action":"pass","interface":"lan"}`)
	b := desiredRule(t, "b", RulePositionPrepend, 100, `{"uuid":"`+ruleB+`","action":"block","interface":"lan"}`)

	first := executeSyncAPI(context.Background(), device.client, nil, []APIRulePayload{a})
	if !first.Success || device.lastBody(ruleA)["sequence"] != "1" {
		t.Fatalf("first sync: success=%v body=%v errors=%v", first.Success, device.lastBody(ruleA), first.Errors)
	}

	second := executeSyncAPI(context.Background(), device.client, nil, []APIRulePayload{a, b})

	if !second.Success {
		t.Fatalf("second sync failed: %v", second.Errors)
	}
	if w := device.writesTo(ruleA); len(w) != 2 {
		t.Errorf("writes to A = %v, want a second setRule", w)
	}
	if got := device.lastBody(ruleA)["sequence"]; got != "2" {
		t.Errorf("A's sequence = %q, want 2 behind the new B", got)
	}
	if item := ruleItem(second.Results, "rule", ruleA); item == nil || item.Action != "updated" || item.Status != "success" {
		t.Errorf("A's item = %+v, want updated", item)
	}
}

func TestExecuteSyncAPI_RemovingAFieldRestoresItsDefault(t *testing.T) {
	device := newFakeRuleDevice(t, ruleTemplate(t), nil)
	withLog := desiredRule(t, "s", RulePositionPrepend, 100, `{"uuid":"`+ruleA+`","action":"pass","interface":"lan","log":"1"}`)
	withoutLog := desiredRule(t, "s", RulePositionPrepend, 100, `{"uuid":"`+ruleA+`","action":"pass","interface":"lan"}`)

	executeSyncAPI(context.Background(), device.client, nil, []APIRulePayload{withLog})
	result := executeSyncAPI(context.Background(), device.client, nil, []APIRulePayload{withoutLog})

	if !result.Success {
		t.Fatalf("sync failed: %v", result.Errors)
	}
	if got := device.lastBody(ruleA)["log"]; got != "0" {
		t.Errorf("log = %q after the snippet dropped it, want 0", got)
	}
}

// TestExecuteSyncAPI_RefusedRuleIsNeitherWrittenNorSwept: a rule refused before
// it was written keeps whatever the device holds, while every other rule
// applies and the orphan sweep still runs.
func TestExecuteSyncAPI_RefusedRuleIsNeitherWrittenNorSwept(t *testing.T) {
	existing := map[string]interface{}{"uuid": ruleA, "interface": "lan", "log": "1", "description": "kept"}
	orphan := map[string]interface{}{"uuid": ruleB, "interface": "lan", "description": "gone"}
	local := map[string]interface{}{"uuid": "7179a1de-88f9-428f-a5b7-d4814890be9f", "interface": "lan", "sequence": "101", "enabled": "1", "description": "GUI rule"}
	device := newFakeRuleDevice(t, ruleTemplate(t), []map[string]interface{}{existing, orphan, local})
	installedReleaseName = func(context.Context, *opnapi.Client) string { return "26.7" }
	t.Cleanup(func() { installedReleaseName = defaultInstalledReleaseName })

	rules := []APIRulePayload{
		desiredRule(t, "typo", RulePositionPrepend, 100, `{"uuid":"`+ruleA+`","action":"pass","interface":"lan","lgo":"1","description":"kept"}`),
		desiredRule(t, "good", RulePositionPrepend, 200, `{"uuid":"`+ruleC+`","action":"pass","interface":"lan","description":"new"}`),
	}

	result := executeSyncAPI(context.Background(), device.client, nil, rules)

	if result.Success {
		t.Error("the sync must fail while a rule is refused")
	}
	if w := device.writesTo(ruleA); len(w) != 0 {
		t.Errorf("the refused rule was touched: %v", w)
	}
	if w := device.writesTo(ruleB); len(w) != 1 || w[0] != "del "+ruleB {
		t.Errorf("the orphan was not swept: %v", w)
	}
	if w := device.writesTo(ruleC); len(w) != 1 || w[0] != "set "+ruleC {
		t.Errorf("the good rule was not written: %v", w)
	}
	if w := device.writesTo(local["uuid"].(string)); len(w) != 0 {
		t.Errorf("a local rule was touched: %v", w)
	}

	item := ruleItem(result.Results, "rule", ruleA)
	if item == nil || item.Status != "blocked" || item.Code != codeRuleFieldUnknown {
		t.Fatalf("refused rule item = %+v", item)
	}
	want := `Rule "kept" (snippet "typo"): field "lgo" (did you mean "log"?) is not in this device's rule model (OPNsense 26.7)`
	if item.Error != want {
		t.Errorf("message = %q\n         want %q", item.Error, want)
	}
	assertErrorHasMatchingResultItem(t, "refused rule", result.Errors, result.Results)
}

func TestExecuteSyncAPI_DeviceRefusalIsReportedPerRule(t *testing.T) {
	device := newFakeRuleDevice(t, ruleTemplate(t), nil)
	device.answer = func(uuid string, body map[string]string) (int, interface{}, bool) {
		if uuid != ruleA {
			return 0, nil, false
		}
		return http.StatusOK, map[string]interface{}{
			"result":      "failed",
			"validations": map[string]interface{}{"rule.destination_port": "Port is only valid for TCP, UDP or TCP/UDP."},
		}, true
	}

	rules := []APIRulePayload{
		desiredRule(t, "web", RulePositionPrepend, 100, `{"uuid":"`+ruleA+`","action":"pass","interface":"lan","destination_port":"443","description":"https"}`),
		desiredRule(t, "dns", RulePositionPrepend, 200, `{"uuid":"`+ruleB+`","action":"pass","interface":"lan","description":"dns"}`),
	}

	result := executeSyncAPI(context.Background(), device.client, nil, rules)

	item := ruleItem(result.Results, "rule", ruleA)
	if item == nil || item.Status != "error" || item.Code != codeRuleRejectedByDevice {
		t.Fatalf("item = %+v", item)
	}
	if want := `Rule "https" (snippet "web"): destination_port: Port is only valid for TCP, UDP or TCP/UDP.`; item.Error != want {
		t.Errorf("message = %q, want %q", item.Error, want)
	}
	if other := ruleItem(result.Results, "rule", ruleB); other == nil || other.Status != "success" {
		t.Errorf("the other rule = %+v", other)
	}
	assertErrorHasMatchingResultItem(t, "device refusal", result.Errors, result.Results)
}

func TestExecuteSyncAPI_UnexpectedDeviceAnswerIsReportedPerRule(t *testing.T) {
	device := newFakeRuleDevice(t, ruleTemplate(t), nil)
	device.answer = func(string, map[string]string) (int, interface{}, bool) {
		return http.StatusInternalServerError, map[string]string{"errorMessage": "Unexpected error, check log for details"}, true
	}

	result := executeSyncAPI(context.Background(), device.client, nil, []APIRulePayload{
		desiredRule(t, "web", RulePositionPrepend, 100, `{"uuid":"`+ruleA+`","action":"pass","interface":"lan","description":"https"}`),
	})

	item := ruleItem(result.Results, "rule", ruleA)
	if item == nil || item.Status != "error" || item.Code != "" || !strings.HasPrefix(item.Error, `Rule "https" (snippet "web"): API error: status 500`) {
		t.Fatalf("item = %+v", item)
	}
	assertErrorHasMatchingResultItem(t, "HTTP 500", result.Errors, result.Results)
}

// TestExecuteSyncAPI_UnreadableModelWritesNoRuleAndStillSweeps: without the
// device's rule model no body can be built or checked, so no rule is written,
// and the orphan sweep, which needs no model, still runs.
func TestExecuteSyncAPI_UnreadableModelWritesNoRuleAndStillSweeps(t *testing.T) {
	orphan := map[string]interface{}{"uuid": ruleB, "interface": "lan", "description": "gone"}
	device := newFakeRuleDevice(t, ruleTemplate(t), []map[string]interface{}{orphan})
	device.templateFail = true

	result := executeSyncAPI(context.Background(), device.client, nil, []APIRulePayload{
		desiredRule(t, "web", RulePositionPrepend, 100, `{"uuid":"`+ruleA+`","action":"pass","interface":"lan"}`),
	})

	if device.setCount() != 0 {
		t.Errorf("a rule was written without the model: %v", device.writes)
	}
	if w := device.writesTo(ruleB); len(w) != 1 || w[0] != "del "+ruleB {
		t.Errorf("the orphan was not swept: %v", w)
	}
	if result.Success {
		t.Error("the sync must fail")
	}
	var found bool
	for _, r := range result.Results {
		if r.Type == "rule_discovery" && r.Code == codeRuleModelUnavailable && r.Status == "error" {
			found = true
		}
	}
	if !found {
		t.Errorf("no %s item in %+v", codeRuleModelUnavailable, result.Results)
	}
	assertErrorHasMatchingResultItem(t, "model unavailable", result.Errors, result.Results)
}

func TestExecuteSyncAPI_MissingInterfaceKeepsItsCode(t *testing.T) {
	device := newFakeRuleDevice(t, ruleTemplate(t, withInterfaces("lan", "wan")), nil)

	result := executeSyncAPI(context.Background(), device.client, nil, []APIRulePayload{
		desiredRule(t, "vpn", RulePositionPrepend, 100, `{"uuid":"`+ruleA+`","action":"pass","interface":"wireguard","description":"Ops VPN access"}`),
	})

	item := ruleItem(result.Results, "rule", ruleA)
	if item == nil || item.Status != "blocked" || item.Code != codeRuleInterfaceNotFound {
		t.Fatalf("item = %+v", item)
	}
	if len(result.ValidationErrors) != 1 || result.ValidationErrors[0].ErrorCode != codeRuleInterfaceNotFound {
		t.Errorf("validation errors = %+v", result.ValidationErrors)
	}
	if device.setCount() != 0 {
		t.Errorf("the rule was written: %v", device.writes)
	}
	assertErrorHasMatchingResultItem(t, "missing interface", result.Errors, result.Results)
}

// TestExecuteSyncAPI_AliasFromTheSameSyncIsAnOverloadOption: the rule model is
// read after the aliases are written, so a rule may name, as its overload
// table, an alias the same sync creates.
func TestExecuteSyncAPI_AliasFromTheSameSyncIsAnOverloadOption(t *testing.T) {
	device := newFakeRuleDevice(t, ruleTemplate(t), nil)
	const aliasUUID = "221f3268-00a1-4000-8000-0000000000a1"
	aliases := []APIAliasPayload{desiredAlias(t, "abusers", `{"uuid":"`+aliasUUID+`","name":"abusers","type":"host","content":"192.0.2.10"}`)}
	rules := []APIRulePayload{desiredRule(t, "limit", RulePositionPrepend, 100,
		`{"uuid":"`+ruleA+`","action":"pass","interface":"lan","protocol":"TCP","max-src-conn-rate":"10","max-src-conn-rates":"5","overload":"abusers"}`)}

	result := executeSyncAPI(context.Background(), device.client, aliases, rules)

	if !result.Success {
		t.Fatalf("sync failed: %v", result.Errors)
	}
	if got := device.lastBody(ruleA)["overload"]; got != aliasUUID {
		t.Errorf("overload = %q, want the new alias's UUID", got)
	}
}
