package tasks

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// withRuleModel2675 turns the 26.7 GA rule template into 26.7.5's, from that
// release's Filter.xml: four settable fields more, and the audit record
// (JsonAuditField), which getRule answers as an object.
func withRuleModel2675(template map[string]interface{}) {
	template["received-on-not"] = "0"
	template["received-on"] = optionList("lan", "LAN", "wan", "WAN", "wireguard", "WireGuard (Group)")
	template["max-pkt-rate-number"] = ""
	template["max-pkt-rate-seconds"] = ""
	template["audit"] = map[string]interface{}{
		"created":  map[string]interface{}{"username": "", "time": "", "description": ""},
		"updated":  map[string]interface{}{"username": "", "time": "", "description": ""},
		"userdata": map[string]interface{}{"note": ""},
	}
}

// auditRecord is what a rule pulled from a 26.7.5 or later device carries:
// OPNsense stamps it on every API save.
var auditRecord = map[string]interface{}{
	"created":  map[string]interface{}{"username": "root@192.0.2.9", "time": "1791234806.40", "description": "/api/firewall/filter/set_rule"},
	"updated":  map[string]interface{}{"username": "root@192.0.2.9", "time": "1791234806.40", "description": "/api/firewall/filter/set_rule"},
	"userdata": map[string]interface{}{"note": ""},
}

func contentOf(t *testing.T, row map[string]interface{}) string {
	t.Helper()
	raw, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// assertBodyHoldsRow checks that every field the body sets holds the row's value,
// the description aside (its template tags are SYNC's).
func assertBodyHoldsRow(t *testing.T, body map[string]string, row map[string]interface{}) {
	t.Helper()
	for name, got := range body {
		if name == "description" || name == "sequence" {
			continue
		}
		if want, _ := row[name].(string); got != want {
			t.Errorf("%s = %q, the pulled row holds %q", name, got, want)
		}
	}
}

// TestRawPulledRuleRowsSyncCleanly: stored pulled RULE snippets are the raw
// rows OPNsense's search answered, with every field at its value, display
// labels, alias metadata as lists of objects and the legacy markers. They
// apply as they are, and a rule pulled from a 26.7.5 device carries its audit
// record too, which is never sent.
func TestRawPulledRuleRowsSyncCleanly(t *testing.T) {
	model := ruleModel26(t)
	for _, uuid := range []string{capturedManagedRule, defaultAllow4, defaultAllow6} {
		row := searchRow(t, uuid)
		row["audit"] = auditRecord
		rule := desiredRule(t, "pulled", RulePositionPrepend, 1000, contentOf(t, row), "Allow-HTTPS-from-SOC")

		body, refusal := buildRuleBody(rule, model, release267)
		if refusal != nil {
			t.Fatalf("%s: a raw pulled row was refused: %+v", uuid, refusal)
		}
		if len(body) != 53 {
			t.Errorf("%s: body has %d fields, want 53", uuid, len(body))
		}
		if _, sent := body["audit"]; sent {
			t.Errorf("%s: the audit record is sent", uuid)
		}
		assertBodyHoldsRow(t, body, row)
	}

	pulled := searchRow(t, capturedManagedRule)
	body, _ := buildRuleBody(desiredRule(t, "pulled", RulePositionPrepend, 1000, contentOf(t, pulled), "Allow-HTTPS-from-SOC"), model, release267)
	if body["description"] != "Test var 40000 sniptest01 [nd-template:Allow-HTTPS-from-SOC]" {
		t.Errorf("description = %q: the pulled row's doubled tag is not stripped", body["description"])
	}
}

// rawAliasRow is an alias as OPNsense 26.7's alias search lists it: every model
// field at its stored value, the statistics, display labels and the grid's
// category UUID list, as stored pulled ALIAS snippets hold it.
func rawAliasRow() map[string]interface{} {
	return map[string]interface{}{
		"uuid": "5a5a5a5a-0000-4000-8000-000000000002", "enabled": "1", "name": "SOC_Hosts", "type": "host",
		"%type": "Host(s)", "path_expression": "", "proto": "", "interface": "", "counters": "0", "updatefreq": "",
		"content": "soc.example.com\n192.0.2.10", "password": "", "username": "", "authtype": "", "expire": "",
		"categories": "", "categories_uuid": []interface{}{},
		"current_items": "2", "last_updated": "2026-10-05 14:00:00", "eval_nomatch": "0", "eval_match": "12",
		"in_block_p": "0", "in_block_b": "0", "in_pass_p": "12", "in_pass_b": "1500",
		"out_block_p": "0", "out_block_b": "0", "out_pass_p": "0", "out_pass_b": "0",
		"description": "SOC hosts [nd-template:Allow-HTTPS-from-SOC]",
	}
}

func TestRawPulledAliasRowSyncsCleanly(t *testing.T) {
	row := rawAliasRow()
	alias := desiredAlias(t, "pulled", contentOf(t, row), "base")

	body, refusal := buildAliasBody(alias, opnapi.ParseEntityModel(aliasTemplate(t)), release267)
	if refusal != nil {
		t.Fatalf("a raw pulled alias was refused: %+v", refusal)
	}
	if len(body) != 15 {
		t.Errorf("body has %d fields, want 15", len(body))
	}
	for _, statistic := range ignoredContentKeys["ALIAS"].names {
		if _, sent := body[statistic]; sent {
			t.Errorf("%s is sent", statistic)
		}
	}
	assertBodyHoldsRow(t, body, row)
	if body["description"] != "SOC hosts [nd-template:base]" {
		t.Errorf("description = %q", body["description"])
	}
}

// TestRuleModelDiffersByPointRelease: the field set is each device's own. 26.7.5
// adds four settable fields and an audit record 26.7 GA does not have, so the
// same content applies on one and is refused on the other, with the device's
// release in the message, so an older OPNsense reads differently from a typo.
func TestRuleModelDiffersByPointRelease(t *testing.T) {
	ga := ruleModel26(t)
	newer := ruleModel26(t, withRuleModel2675)

	minimal := desiredRule(t, "s", RulePositionPrepend, 100, `{"uuid":"`+testRuleUUID+`","action":"pass","interface":"lan"}`)
	gaBody, _ := buildRuleBody(minimal, ga, release267)
	newBody, _ := buildRuleBody(minimal, newer, func() string { return "26.7.5" })
	if len(gaBody) != 53 || len(newBody) != 57 {
		t.Errorf("bodies have %d and %d fields, want 53 on 26.7 and 57 on 26.7.5", len(gaBody), len(newBody))
	}
	for field, want := range map[string]string{"received-on-not": "0", "received-on": "", "max-pkt-rate-number": "", "max-pkt-rate-seconds": ""} {
		if got, ok := newBody[field]; !ok || got != want {
			t.Errorf("26.7.5 %s = %q (present %v), want the default %q", field, got, ok, want)
		}
	}
	if _, sent := newBody["audit"]; sent {
		t.Error("the audit record is sent on 26.7.5")
	}

	rateLimited := desiredRule(t, "rate", RulePositionPrepend, 100, `{"uuid":"`+testRuleUUID+`","action":"pass","interface":"lan","description":"rate",
		"received-on":"wan","received-on-not":"1","max-pkt-rate-number":100,"max-pkt-rate-seconds":10}`)

	body, refusal := buildRuleBody(rateLimited, newer, func() string { return "26.7.5" })
	if refusal != nil {
		t.Fatalf("26.7.5 refused its own fields: %+v", refusal)
	}
	for field, want := range map[string]string{"received-on": "wan", "received-on-not": "1", "max-pkt-rate-number": "100", "max-pkt-rate-seconds": "10"} {
		if body[field] != want {
			t.Errorf("%s = %q, want %q", field, body[field], want)
		}
	}

	_, refusal = buildRuleBody(rateLimited, ga, release267)
	if refusal == nil || refusal.Code != codeRuleFieldUnknown {
		t.Fatalf("26.7 GA: refusal = %+v, want %s", refusal, codeRuleFieldUnknown)
	}
	want := `Rule "rate" (snippet "rate"): fields "max-pkt-rate-number", "max-pkt-rate-seconds", "received-on", "received-on-not" are not in this device's rule model (OPNsense 26.7)`
	if refusal.Message != want {
		t.Errorf("message = %q\n         want %q", refusal.Message, want)
	}

	// A raw rule pulled from a 26.7.5 device carries the four at their
	// defaults: it applies on 26.7.5, and 26.7 GA refuses it, naming them.
	row := searchRow(t, capturedManagedRule)
	for field, value := range map[string]interface{}{"received-on-not": "0", "received-on": "", "max-pkt-rate-number": "", "max-pkt-rate-seconds": "", "audit": auditRecord} {
		row[field] = value
	}
	raw := desiredRule(t, "pulled", RulePositionPrepend, 100, contentOf(t, row))
	if _, refusal := buildRuleBody(raw, newer, func() string { return "26.7.5" }); refusal != nil {
		t.Errorf("26.7.5 refused a rule pulled from 26.7.5: %+v", refusal)
	}
	if _, refusal := buildRuleBody(raw, ga, release267); refusal == nil || !strings.Contains(refusal.Message, `"received-on"`) {
		t.Errorf("26.7 GA: refusal = %+v", refusal)
	}
}

func TestPortableRule_DropsTheAuditRecord(t *testing.T) {
	model := ruleModel26(t, withRuleModel2675)
	row := searchRow(t, capturedManagedRule)
	for field, value := range map[string]interface{}{"received-on-not": "0", "received-on": "wan", "max-pkt-rate-number": "", "max-pkt-rate-seconds": "", "audit": "eyJjcmVhdGVkIjp7fX0="} {
		row[field] = value
	}

	got := portableRule(row, model)

	if _, ok := got["audit"]; ok {
		t.Error("PULL emits the audit record")
	}
	if got["received-on"] != "wan" {
		t.Errorf("received-on = %v, want the non-default value", got["received-on"])
	}
	for _, atDefault := range []string{"received-on-not", "max-pkt-rate-number", "max-pkt-rate-seconds"} {
		if _, ok := got[atDefault]; ok {
			t.Errorf("%s is pulled at its default", atDefault)
		}
	}
}

// TestIgnoredUnboundKeysHoldAnyValue: a pulled UNBOUND snippet's template list
// is never read, whatever it holds.
func TestIgnoredUnboundKeysHoldAnyValue(t *testing.T) {
	for _, templates := range []string{`null`, `[]`, `["base"]`, `{"x":1}`} {
		if _, err := parseHostOverrideContent(`{"uuid":"221f3268-0001-4000-8000-000000000001","hostname":"nas","domain":"lan","templates":`+templates+`}`, nil); err != nil {
			t.Errorf("host override, templates %s: %v", templates, err)
		}
		if _, err := parseDomainForwardContent(`{"uuid":"221f3268-0001-4000-8000-000000000001","domain":"corp","server":"192.0.2.53","templates":`+templates+`}`, nil); err != nil {
			t.Errorf("domain forward, templates %s: %v", templates, err)
		}
		if _, err := parseHostAliasContent(`{"uuid":"221f3268-0001-4000-8000-000000000001","hostname":"www","domain":"lan","templates":`+templates+`}`, nil); err != nil {
			t.Errorf("host alias, templates %s: %v", templates, err)
		}
		if _, err := parseUnboundACLContent(`{"uuid":"221f3268-0001-4000-8000-000000000001","name":"lan","action":"allow","templates":`+templates+`}`, nil); err != nil {
			t.Errorf("ACL, templates %s: %v", templates, err)
		}
	}
}

// TestBooleanAndListForms: the JSON kinds the control plane keeps accepting
// for these fields are applied: a boolean enabled flag, UNBOUND's forwarding
// booleans, an ALIAS content list and an UNBOUND_ACL network list.
func TestBooleanAndListForms(t *testing.T) {
	for _, flag := range []bool{true, false} {
		want := opnapi.BoolToOPNsense(flag)
		rule, _ := buildRuleBody(desiredRule(t, "s", RulePositionPrepend, 100, `{"uuid":"`+testRuleUUID+`","action":"pass","enabled":`+want2json(flag)+`}`), ruleModel26(t), release267)
		if rule["enabled"] != want {
			t.Errorf("RULE enabled %v = %q", flag, rule["enabled"])
		}
		alias, _ := buildAlias(t, `{"uuid":"`+testAliasUUID+`","name":"a","type":"host","enabled":`+want2json(flag)+`}`)
		if alias["enabled"] != want {
			t.Errorf("ALIAS enabled %v = %q", flag, alias["enabled"])
		}

		override, err := parseHostOverrideContent(`{"uuid":"221f3268-0001-4000-8000-000000000001","hostname":"nas","domain":"lan","enabled":`+want2json(flag)+`}`, nil)
		if err != nil || opnapi.ConvertToOPNHostOverride(override).Enabled != want {
			t.Errorf("host override enabled %v: %+v, %v", flag, override, err)
		}
		forward, err := parseDomainForwardContent(`{"uuid":"221f3268-0001-4000-8000-000000000001","domain":"corp","server":"192.0.2.53",
			"enabled":`+want2json(flag)+`,"forward_tcp_upstream":`+want2json(flag)+`,"forward_first":`+want2json(!flag)+`}`, nil)
		if err != nil {
			t.Fatal(err)
		}
		wire := opnapi.ConvertToOPNDomainForward(forward)
		if wire.Enabled != want || wire.ForwardTCPUpstream != want || wire.ForwardFirst != opnapi.BoolToOPNsense(!flag) {
			t.Errorf("domain forward %v: %+v", flag, wire)
		}
	}

	alias, _ := buildAlias(t, `{"uuid":"`+testAliasUUID+`","name":"a","type":"network","content":["10.0.0.0/8","192.0.2.0/24"]}`)
	if alias["content"] != "10.0.0.0/8\n192.0.2.0/24" {
		t.Errorf("ALIAS content list = %q", alias["content"])
	}
	acl, err := parseUnboundACLContent(`{"uuid":"221f3268-0001-4000-8000-000000000001","name":"lan","action":"allow","networks":["10.0.0.0/8","192.0.2.0/24"]}`, nil)
	if err != nil || opnapi.ConvertToOPNACL(acl).Networks != "10.0.0.0/8,192.0.2.0/24" {
		t.Errorf("ACL networks list: %+v, %v", acl, err)
	}
}

func want2json(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// TestExecuteSyncAPI_RawPulledSnippetsApply runs stored raw pulled snippets, a
// rule and an alias, through a whole sync.
func TestExecuteSyncAPI_RawPulledSnippetsApply(t *testing.T) {
	device := newFakeRuleDevice(t, ruleTemplate(t), nil)
	ruleRow := searchRow(t, capturedManagedRule)
	ruleRow["uuid"] = ruleA
	ruleRow["audit"] = auditRecord
	aliasRow := rawAliasRow()
	aliasRow["uuid"] = testAliasUUID

	result := executeSyncAPI(context.Background(), device.client,
		[]APIAliasPayload{desiredAlias(t, "soc", contentOf(t, aliasRow), "Allow-HTTPS-from-SOC")},
		[]APIRulePayload{desiredRule(t, "sniptest01", RulePositionPrepend, 1000, contentOf(t, ruleRow), "Allow-HTTPS-from-SOC")})

	if !result.Success {
		t.Fatalf("sync failed: %v", result.Errors)
	}
	if body := device.lastBody(ruleA); body["source_net"] != "SOC_Hosts" || body["interface"] != "lan,wireguard" {
		t.Errorf("rule body = %v", body)
	}
	if body := device.lastBody(testAliasUUID); body["content"] != "soc.example.com\n192.0.2.10" {
		t.Errorf("alias body = %v", body)
	}
}
