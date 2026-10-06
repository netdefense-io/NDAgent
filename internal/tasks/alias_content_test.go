package tasks

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

const testAliasUUID = "221f3268-00a1-4000-8000-000000000001"

func buildAlias(t *testing.T, content string, options ...func(map[string]interface{})) (map[string]string, *contentRefusal) {
	t.Helper()
	template := aliasTemplate(t)
	for _, option := range options {
		option(template)
	}
	return buildAliasBody(desiredAlias(t, "aliases-snippet", content, "base"), opnapi.ParseEntityModel(template), release267)
}

// TestBuildAliasBody_DeclarativeBodyLiteral pins the setItem body: every one of
// the 15 fields a 26.7 alias model lets content set (the 12 statistics it
// keeps are not among them), at the content's value or the model's default.
// The expected JSON is written out from the template, not from this code.
func TestBuildAliasBody_DeclarativeBodyLiteral(t *testing.T) {
	body, refusal := buildAlias(t, `{"uuid":"`+testAliasUUID+`","name":"web_servers","type":"host",
		"content":["192.0.2.10","192.0.2.11"],"description":"Web"}`)
	if refusal != nil {
		t.Fatalf("refused: %+v", refusal)
	}

	got, err := json.Marshal(map[string]interface{}{"alias": body})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"alias":{"authtype":"","categories":"","content":"192.0.2.10\n192.0.2.11","counters":"0","description":"Web [nd-template:base]","enabled":"1","expire":"","interface":"","name":"web_servers","password":"","path_expression":"","proto":"","type":"host","updatefreq":"","username":""}}`
	if string(got) != want {
		t.Errorf("setItem body:\n got %s\nwant %s", got, want)
	}
}

// TestBuildAliasBody_FieldsTheOldParserDropped: the ten fields beside name,
// type, content, enabled and description now reach the device; a dynamic
// IPv6 host alias, which requires an interface, can be created.
func TestBuildAliasBody_FieldsTheOldParserDropped(t *testing.T) {
	categories := withCategories("c1000000-0000-4000-8000-000000000001", "blocklists")
	body, refusal := buildAlias(t, `{"uuid":"`+testAliasUUID+`","name":"printer6","type":"dynipv6host","content":"::1:2",
		"interface":"lan","proto":["IPv4","IPv6"],"counters":true,"updatefreq":1.5,"expire":3600,
		"authtype":"Basic","username":"feed","password":"secret","path_expression":".data[]","categories":"blocklists"}`, categories)
	if refusal != nil {
		t.Fatalf("refused: %+v", refusal)
	}
	want := map[string]string{
		"interface": "lan", "proto": "IPv4,IPv6", "counters": "1", "updatefreq": "1.5", "expire": "3600",
		"authtype": "Basic", "username": "feed", "password": "secret", "path_expression": ".data[]",
		"categories": "c1000000-0000-4000-8000-000000000001",
	}
	for field, value := range want {
		if body[field] != value {
			t.Errorf("%s = %q, want %q", field, body[field], value)
		}
	}
}

func TestBuildAliasBody_ContentForms(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{"one entry", `"192.0.2.10"`, "192.0.2.10"},
		{"newline-separated", `"192.0.2.10\n192.0.2.11"`, "192.0.2.10\n192.0.2.11"},
		{"a list", `["10.0.0.0/8","172.16.0.0/12"]`, "10.0.0.0/8\n172.16.0.0/12"},
		{"port numbers", `[80, 443]`, "80\n443"},
		{"absent", `null`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, refusal := buildAlias(t, `{"uuid":"`+testAliasUUID+`","name":"a","type":"host","content":`+tc.content+`}`)
			if refusal != nil {
				t.Fatalf("refused: %+v", refusal)
			}
			if body["content"] != tc.want {
				t.Errorf("content = %q, want %q", body["content"], tc.want)
			}
		})
	}

	_, refusal := buildAlias(t, `{"uuid":"`+testAliasUUID+`","name":"a","type":"host","content":[{"host":"x"}]}`)
	if refusal == nil || refusal.Code != codeAliasValueInvalid || !strings.Contains(refusal.Message, "content:") {
		t.Errorf("a list of objects: refusal = %+v", refusal)
	}
}

func TestBuildAliasBody_UnknownKeyRefused(t *testing.T) {
	_, refusal := buildAlias(t, `{"uuid":"`+testAliasUUID+`","name":"web","type":"host","contnet":"192.0.2.10"}`)
	if refusal == nil || refusal.Code != codeAliasFieldUnknown {
		t.Fatalf("refusal = %+v, want %s", refusal, codeAliasFieldUnknown)
	}
	want := `Alias "web" (snippet "aliases-snippet"): field "contnet" (did you mean "content"?) is not in this device's alias model (OPNsense 26.7)`
	if refusal.Message != want {
		t.Errorf("message = %q\n         want %q", refusal.Message, want)
	}
}

// TestBuildAliasBody_PullArtifactsAreIgnored: a snippet pulled before PULL went
// portable holds the search grid's display values, its category UUID list and
// the alias statistics; none is sent and none is refused.
func TestBuildAliasBody_PullArtifactsAreIgnored(t *testing.T) {
	body, refusal := buildAlias(t, `{"uuid":"`+testAliasUUID+`","name":"web","type":"host","%type":"Host(s)",
		"categories_uuid":[],"current_items":"2","last_updated":"2026-10-01 10:00:00","in_block_p":"0","eval_match":"5"}`)
	if refusal != nil {
		t.Fatalf("refused: %+v", refusal)
	}
	if len(body) != 15 {
		t.Errorf("body has %d fields, want 15", len(body))
	}
	for _, key := range []string{"%type", "categories_uuid", "current_items", "last_updated", "in_block_p", "eval_match"} {
		if _, sent := body[key]; sent {
			t.Errorf("%s is in the body", key)
		}
	}
}

func TestBuildAliasBody_OptionChecks(t *testing.T) {
	_, refusal := buildAlias(t, `{"uuid":"`+testAliasUUID+`","name":"web","type":"hosts","proto":"IPv5"}`)
	if refusal == nil || refusal.Code != codeAliasValueInvalid {
		t.Fatalf("refusal = %+v", refusal)
	}
	for _, want := range []string{`proto: "IPv5" not on this device (available: IPv4, IPv6)`, `type: "hosts" not on this device`} {
		if !strings.Contains(refusal.Message, want) {
			t.Errorf("message %q missing %q", refusal.Message, want)
		}
	}
}

func TestParseAliasContent_RequiresUUIDNameAndType(t *testing.T) {
	for _, content := range []string{`null`, `{"uuid":"` + testAliasUUID + `","type":"host"}`, `{"uuid":"` + testAliasUUID + `","name":"a"}`, `{"name":"a","type":"host"}`} {
		if _, err := parseAliasContent(content, nil); err == nil {
			t.Errorf("parseAliasContent(%s) accepted it", content)
		}
	}
}

// TestExecuteSyncAPI_AliasWrittenThenUnchanged: an alias is written with every
// field of the model, and a second sync against the converged device writes
// nothing.
func TestExecuteSyncAPI_AliasWrittenThenUnchanged(t *testing.T) {
	device := newFakeRuleDevice(t, ruleTemplate(t), nil)
	aliases := []APIAliasPayload{desiredAlias(t, "feeds", `{"uuid":"`+testAliasUUID+`","name":"blocklist","type":"urltable",
		"content":"https://feeds.example.com/list.txt","updatefreq":"1","description":"Feed"}`, "base")}

	first := executeSyncAPI(context.Background(), device.client, aliases, nil)
	if !first.Success {
		t.Fatalf("first sync failed: %v", first.Errors)
	}
	body := device.lastBody(testAliasUUID)
	if len(body) != 15 || body["updatefreq"] != "1" || body["type"] != "urltable" {
		t.Errorf("setItem body = %v", body)
	}

	second := executeSyncAPI(context.Background(), device.client, aliases, nil)
	if !second.Success {
		t.Fatalf("second sync failed: %v", second.Errors)
	}
	if w := device.writesTo(testAliasUUID); len(w) != 1 {
		t.Errorf("writes = %v, want the first sync's only", w)
	}
	var item *SyncAPIItemResult
	for i := range second.Results {
		if second.Results[i].Type == "alias" {
			item = &second.Results[i]
		}
	}
	if item == nil || item.Action != "unchanged" {
		t.Errorf("alias item = %+v, want unchanged", item)
	}
}

func TestExecuteSyncAPI_AliasRefusalsAreReportedPerAlias(t *testing.T) {
	device := newFakeRuleDevice(t, ruleTemplate(t), nil)
	device.answer = func(uuid string, body map[string]string) (int, interface{}, bool) {
		if body["name"] != "rejected" {
			return 0, nil, false
		}
		return http.StatusOK, map[string]interface{}{
			"result":      "failed",
			"validations": map[string]interface{}{"alias.content": []string{"Entry \"x\" is not a valid hostname or IP address."}},
		}, true
	}
	aliases := []APIAliasPayload{
		desiredAlias(t, "typo", `{"uuid":"221f3268-00a1-4000-8000-0000000000a1","name":"typo","type":"host","conten":"x"}`),
		desiredAlias(t, "device", `{"uuid":"221f3268-00a1-4000-8000-0000000000a2","name":"rejected","type":"host","content":"x"}`),
		desiredAlias(t, "good", `{"uuid":"221f3268-00a1-4000-8000-0000000000a3","name":"good","type":"host","content":"192.0.2.1"}`),
	}

	result := executeSyncAPI(context.Background(), device.client, aliases, nil)

	codes := map[string]string{}
	for _, r := range result.Results {
		if r.Type == "alias" {
			codes[r.Name] = r.Status + " " + r.Code
		}
	}
	want := map[string]string{
		"typo":     "blocked " + codeAliasFieldUnknown,
		"rejected": "error " + codeAliasRejectedByDevice,
		"good":     "success ",
	}
	if !reflect.DeepEqual(codes, want) {
		t.Errorf("alias items = %v, want %v", codes, want)
	}
	assertErrorHasMatchingResultItem(t, "alias refusals", result.Errors, result.Results)
}

// TestExecuteSyncAPI_UnreadableAliasModelKeepsTheAliases: no alias is written,
// and an alias already on the device is not swept either: it is still desired.
func TestExecuteSyncAPI_UnreadableAliasModelKeepsTheAliases(t *testing.T) {
	device := newFakeRuleDevice(t, ruleTemplate(t), nil)
	device.aliasTemplateFail = true
	device.aliases = []map[string]interface{}{{"uuid": testAliasUUID, "name": "kept", "type": "host", "content": "192.0.2.1"}}

	result := executeSyncAPI(context.Background(), device.client, []APIAliasPayload{
		desiredAlias(t, "kept", `{"uuid":"`+testAliasUUID+`","name":"kept","type":"host","content":"192.0.2.2"}`),
	}, nil)

	if w := device.writesTo(testAliasUUID); len(w) != 0 {
		t.Errorf("the alias was touched: %v", w)
	}
	var found bool
	for _, r := range result.Results {
		if r.Type == "alias_discovery" && r.Code == codeAliasModelUnavailable {
			found = true
		}
	}
	if !found || result.Success {
		t.Errorf("success=%v, results=%+v", result.Success, result.Results)
	}
	assertErrorHasMatchingResultItem(t, "alias model", result.Errors, result.Results)
}

func TestPortableAlias(t *testing.T) {
	template := aliasTemplate(t)
	withCategories("c1000000-0000-4000-8000-000000000001", "blocklists")(template)
	model := opnapi.ParseEntityModel(template)
	row := map[string]interface{}{
		"uuid": "5a5a5a5a-0000-4000-8000-000000000001", "enabled": "1", "name": "blocklist", "type": "urltable",
		"%type": "URL Table (IPs)", "path_expression": "", "proto": "", "interface": "", "counters": "0",
		"updatefreq": "1", "content": "https://feeds.example.com/list.txt", "password": "", "username": "",
		"authtype": "", "expire": "", "categories": "c1000000-0000-4000-8000-000000000001", "categories_uuid": []interface{}{},
		"current_items": "2048", "last_updated": "2026-10-01 10:00:00", "description": "Feed [nd-template:old]",
	}

	got := aliasContract.portable(row, model, aliasAlwaysPulled)

	want := map[string]interface{}{
		"uuid": "5a5a5a5a-0000-4000-8000-000000000001", "enabled": "1", "name": "blocklist", "type": "urltable",
		"updatefreq": "1", "content": "https://feeds.example.com/list.txt", "categories": "blocklists", "description": "Feed",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("portable alias =\n %v\nwant\n %v", got, want)
	}
}

// TestExecuteSyncAPI_AliasRefusalNeverQuotesItsPassword: a refused alias is
// named by its fields, never their values, so a URL alias's password stays out
// of the task's errors and results, whatever key holds it.
func TestExecuteSyncAPI_AliasRefusalNeverQuotesItsPassword(t *testing.T) {
	const secret = "s3cr3t-Pa55word"
	device := newFakeRuleDevice(t, ruleTemplate(t), nil)
	aliases := []APIAliasPayload{
		desiredAlias(t, "typo", `{"uuid":"221f3268-00a1-4000-8000-0000000000a1","name":"feed1","type":"urltable",
			"content":"https://feeds.example.com/a","username":"feeds","password":"`+secret+`","pasword":"`+secret+`"}`),
		desiredAlias(t, "option", `{"uuid":"221f3268-00a1-4000-8000-0000000000a2","name":"feed2","type":"urltable",
			"content":"https://feeds.example.com/b","username":"feeds","password":"`+secret+`","authtype":"Kerberos"}`),
	}

	result := executeSyncAPI(context.Background(), device.client, aliases, nil)

	if result.Success {
		t.Fatal("the sync must fail")
	}
	codes := map[string]string{}
	for _, r := range result.Results {
		if strings.Contains(r.Error, secret) {
			t.Errorf("item %s %s quotes the password: %s", r.Type, r.Name, r.Error)
		}
		if r.Type == "alias" {
			codes[r.Name] = r.Code
		}
	}
	for _, e := range result.Errors {
		if strings.Contains(e, secret) {
			t.Errorf("error quotes the password: %s", e)
		}
	}
	if codes["feed1"] != codeAliasFieldUnknown || codes["feed2"] != codeAliasValueInvalid {
		t.Errorf("alias codes = %v", codes)
	}
}

// TestExecuteSyncAPI_AliasUnchangedAgainstTheGridRow: the alias search lists
// an alias with its statistics, display labels and category UUID list beside
// its fields; an alias the device holds as its stored pulled snippet says is
// still not written.
func TestExecuteSyncAPI_AliasUnchangedAgainstTheGridRow(t *testing.T) {
	device := newFakeRuleDevice(t, ruleTemplate(t), nil)
	row := rawAliasRow()
	row["uuid"] = testAliasUUID
	device.aliases = []map[string]interface{}{row}
	pulled := rawAliasRow()
	pulled["uuid"] = testAliasUUID

	result := executeSyncAPI(context.Background(), device.client,
		[]APIAliasPayload{desiredAlias(t, "soc", contentOf(t, pulled), "Allow-HTTPS-from-SOC")}, nil)

	if !result.Success {
		t.Fatalf("sync failed: %v", result.Errors)
	}
	if w := device.writesTo(testAliasUUID); len(w) != 0 {
		t.Errorf("the alias was written: %v", w)
	}
	var item *SyncAPIItemResult
	for i := range result.Results {
		if result.Results[i].Type == "alias" {
			item = &result.Results[i]
		}
	}
	if item == nil || item.Action != "unchanged" || item.Status != "success" {
		t.Errorf("alias item = %+v, want unchanged", item)
	}
}
