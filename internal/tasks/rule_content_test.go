package tasks

import (
	"encoding/json"
	"strings"
	"testing"
)

const testRuleUUID = "221f3268-0001-4000-8000-000000000001"

// release267 names the device's release the way a message does on the lab's
// 26.7 boxes.
func release267() string { return "26.7" }

func buildBody(t *testing.T, content string, options ...func(map[string]interface{})) (map[string]string, *contentRefusal) {
	t.Helper()
	rule := desiredRule(t, "rules-snippet", RulePositionPrepend, 1000, content, "base")
	return buildRuleBody(rule, ruleModel26(t, options...), release267)
}

// TestBuildRuleBody_DeclarativeBodyLiteral pins the setRule body for a short
// snippet: every one of the 53 fields a 26.7 rule model lets content set, at
// the content's value or the model's default. The expected JSON is written out
// from the captured template, not from this code.
func TestBuildRuleBody_DeclarativeBodyLiteral(t *testing.T) {
	body, refusal := buildBody(t, `{"uuid":"`+testRuleUUID+`","action":"block","interface":"lan",
		"description":"Block telnet","protocol":"TCP","destination_port":"23","log":true}`)
	if refusal != nil {
		t.Fatalf("refused: %+v", refusal)
	}
	if len(body) != 53 {
		t.Errorf("body has %d fields, want the 53 settable ones", len(body))
	}

	got, err := json.Marshal(map[string]interface{}{"rule": body})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"rule":{"action":"block","adaptiveend":"","adaptivestart":"","allowopts":"0","categories":"","description":"Block telnet [nd-template:base]","destination_net":"any","destination_not":"0","destination_port":"23","direction":"in","disablereplyto":"0","divert-to":"","enabled":"1","gateway":"","icmp6type":"","icmptype":"","interface":"lan","interfacenot":"0","ipprotocol":"inet","log":"1","max":"","max-src-conn":"","max-src-conn-rate":"","max-src-conn-rates":"","max-src-nodes":"","max-src-states":"","nopfsync":"0","nosync":"0","overload":"","prio":"","protocol":"TCP","quick":"1","replyto":"","sched":"","set-prio":"","set-prio-low":"","shaper1":"","shaper2":"","source_net":"any","source_not":"0","source_port":"","state-policy":"","statetimeout":"","statetype":"keep","tag":"","tagged":"","tcpflags1":"","tcpflags2":"","tcpflags_any":"0","tos":"","udp-first":"","udp-multiple":"","udp-single":""}}`
	if string(got) != want {
		t.Errorf("setRule body:\n got %s\nwant %s", got, want)
	}
}

// TestBuildRuleBody_AbsentFieldIsTheDefault is the reported bug's other half:
// a rule is what its content says, so content without "log" logs nothing.
func TestBuildRuleBody_AbsentFieldIsTheDefault(t *testing.T) {
	body, refusal := buildBody(t, `{"uuid":"`+testRuleUUID+`","action":"pass","interface":"lan"}`)
	if refusal != nil {
		t.Fatalf("refused: %+v", refusal)
	}
	for field, want := range map[string]string{"log": "0", "quick": "1", "enabled": "1", "statetype": "keep", "source_net": "any"} {
		if body[field] != want {
			t.Errorf("%s = %q, want the model default %q", field, body[field], want)
		}
	}
}

func TestBuildRuleBody_ValueKinds(t *testing.T) {
	cases := []struct {
		name    string
		field   string
		value   string // JSON
		want    string
		refused bool
	}{
		{"bool true on a boolean", "log", `true`, "1", false},
		{"bool false on a boolean", "log", `false`, "0", false},
		{"string true on a boolean", "log", `"true"`, "1", false},
		{"string FALSE on a boolean", "log", `"FALSE"`, "0", false},
		{"number 1 on a boolean", "log", `1`, "1", false},
		{"number 0 on a boolean", "log", `0`, "0", false},
		{"string 1 on a boolean", "log", `"1"`, "1", false},
		{"other string on a boolean is sent for OPNsense to judge", "log", `"yes"`, "yes", false},
		{"null is absent", "log", `null`, "0", false},
		{"bool false on the optional tcpflags_any", "tcpflags_any", `false`, "0", false},
		{"number on an integer field", "statetimeout", `443`, "443", false},
		{"exponent form is decimal", "statetimeout", `1e3`, "1000", false},
		{"fraction stays a fraction", "statetimeout", `1.5`, "1.5", false},
		{"string true on a text field is text", "tag", `"true"`, "true", false},
		{"array on a list field", "interface", `["lan","wan"]`, "lan,wan", false},
		{"blanks in a list value", "interface", `" lan , wan "`, "lan,wan", false},
		{"numbers in a list", "icmp6type", `[1, 128]`, "1,128", false},
		{"object", "description", `{"a":1}`, "", true},
		{"nested array", "interface", `[["lan"]]`, "", true},
		{"array holding a boolean", "interface", `[true]`, "", true},
		{"bool on a list field", "direction", `true`, "", true},
		{"bool on a port", "destination_port", `true`, "", true},
		{"bool on an integer field", "statetimeout", `false`, "", true},
		{"empty list value is none selected", "interface", `""`, "", false},
		{"null list value is the default", "interface", `null`, "", false},
		{"empty array is none selected", "interface", `[]`, "", false},
		{"blank list value", "interface", `" "`, "", true},
		{"commas only", "interface", `" , "`, "", true},
		{"array of blanks", "interface", `["",""]`, "", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, refusal := buildBody(t, `{"uuid":"`+testRuleUUID+`","action":"pass","`+tc.field+`":`+tc.value+`}`)
			if tc.refused {
				if refusal == nil || refusal.Code != codeRuleValueInvalid {
					t.Fatalf("refusal = %+v, want %s", refusal, codeRuleValueInvalid)
				}
				if !strings.Contains(refusal.Message, tc.field+":") {
					t.Errorf("message %q does not name the field", refusal.Message)
				}
				return
			}
			if refusal != nil {
				t.Fatalf("refused: %+v", refusal)
			}
			if body[tc.field] != tc.want {
				t.Errorf("%s = %q, want %q", tc.field, body[tc.field], tc.want)
			}
			raw, _ := json.Marshal(body)
			var sent map[string]interface{}
			_ = json.Unmarshal(raw, &sent)
			for field, v := range sent {
				if _, ok := v.(string); !ok {
					t.Errorf("%s is sent as %T; setRule answers anything but a string with HTTP 500", field, v)
				}
			}
		})
	}
}

func TestBuildRuleBody_UnknownKeyRefusedWithSuggestion(t *testing.T) {
	_, refusal := buildBody(t, `{"uuid":"`+testRuleUUID+`","description":"web","lgo":"1"}`)
	if refusal == nil || refusal.Code != codeRuleFieldUnknown {
		t.Fatalf("refusal = %+v, want %s", refusal, codeRuleFieldUnknown)
	}
	for _, want := range []string{`Rule "web" (snippet "rules-snippet")`, `"lgo" (did you mean "log"?)`, "OPNsense 26.7"} {
		if !strings.Contains(refusal.Message, want) {
			t.Errorf("message %q missing %q", refusal.Message, want)
		}
	}
}

func TestBuildRuleBody_UnknownKeyWithoutANearField(t *testing.T) {
	_, refusal := buildBody(t, `{"uuid":"`+testRuleUUID+`","color":"red","zzzz":"1"}`)
	if refusal == nil || refusal.Code != codeRuleFieldUnknown {
		t.Fatalf("refusal = %+v, want %s", refusal, codeRuleFieldUnknown)
	}
	if !strings.Contains(refusal.Message, `fields "color", "zzzz" are not in`) || strings.Contains(refusal.Message, "did you mean") {
		t.Errorf("message = %q", refusal.Message)
	}
}

// TestBuildRuleBody_ContainerIsNeverSuggested: a container field cannot be set
// from content: naming it is refused as not settable, and it is never offered
// as the field content meant.
func TestBuildRuleBody_ContainerIsNeverSuggested(t *testing.T) {
	container := func(template map[string]interface{}) {
		template["schedules"] = map[string]interface{}{"weekly": map[string]interface{}{"day": "1"}}
	}
	cases := map[string]string{
		"schedules": `Rule 221f3268-0001-4000-8000-000000000001 (snippet "rules-snippet"): field "schedules" is not settable`,
		"schedule":  `Rule 221f3268-0001-4000-8000-000000000001 (snippet "rules-snippet"): field "schedule" is not in this device's rule model (OPNsense 26.7)`,
	}
	for key, want := range cases {
		_, refusal := buildBody(t, `{"uuid":"`+testRuleUUID+`","action":"pass","`+key+`":"x"}`, container)
		if refusal == nil || refusal.Code != codeRuleFieldUnknown {
			t.Fatalf("%s: refusal = %+v, want %s", key, refusal, codeRuleFieldUnknown)
		}
		if refusal.Message != want {
			t.Errorf("%s: message = %q\n want %q", key, refusal.Message, want)
		}
	}

	_, refusal := buildBody(t, `{"uuid":"`+testRuleUUID+`","action":"pass","schedules":"x","lgo":"1"}`, container)
	want := `Rule 221f3268-0001-4000-8000-000000000001 (snippet "rules-snippet"): field "lgo" (did you mean "log"?) is not in this device's rule model (OPNsense 26.7); field "schedules" is not settable`
	if refusal == nil || refusal.Message != want {
		t.Errorf("both kinds: refusal = %+v\n want %q", refusal, want)
	}
}

// TestBuildRuleBody_PullArtifactsAreIgnored: snippets pulled before PULL went
// portable hold the search grid's extras and the computed keys; they are
// skipped in silence, never sent and never refused.
func TestBuildRuleBody_PullArtifactsAreIgnored(t *testing.T) {
	body, refusal := buildBody(t, `{"uuid":"`+testRuleUUID+`","action":"pass","%action":"Pass","alias_meta_source_net":[{"value":"lan"}],
		"category_colors":[],"sequence":"7","sort_order":"400000.0000007","prio_group":"400000",
		"legacy":true,"is_automatic":false,"ref":"","seq":3,"#priority":400000}`)
	if refusal != nil {
		t.Fatalf("refused: %+v", refusal)
	}
	if len(body) != 53 {
		t.Errorf("body has %d fields, want 53", len(body))
	}
	for _, key := range []string{"%action", "alias_meta_source_net", "category_colors", "sequence", "sort_order", "prio_group", "legacy", "seq"} {
		if _, sent := body[key]; sent {
			t.Errorf("%s is in the body", key)
		}
	}
}

func TestBuildRuleBody_CategoryAndOverloadByName(t *testing.T) {
	categories := withCategories(
		"c1000000-0000-4000-8000-000000000001", "web",
		"c2000000-0000-4000-8000-000000000002", "dns",
	)
	cases := []struct {
		name  string
		field string
		value string
		want  string
	}{
		{"category names", "categories", `"web,dns"`, "c1000000-0000-4000-8000-000000000001,c2000000-0000-4000-8000-000000000002"},
		{"category names as a list", "categories", `["dns"]`, "c2000000-0000-4000-8000-000000000002"},
		{"category UUID still accepted", "categories", `"c1000000-0000-4000-8000-000000000001"`, "c1000000-0000-4000-8000-000000000001"},
		{"overload alias by name", "overload", `"SOC_Hosts"`, "221f3268-0000-4000-8000-00000000a001"},
		{"overload alias by UUID", "overload", `"221f3268-0000-4000-8000-00000000a001"`, "221f3268-0000-4000-8000-00000000a001"},
		{"overload internal alias", "overload", `"virusprot"`, "virusprot"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, refusal := buildBody(t, `{"uuid":"`+testRuleUUID+`","action":"pass","`+tc.field+`":`+tc.value+`}`, categories)
			if refusal != nil {
				t.Fatalf("refused: %+v", refusal)
			}
			if body[tc.field] != tc.want {
				t.Errorf("%s = %q, want %q", tc.field, body[tc.field], tc.want)
			}
		})
	}

	_, refusal := buildBody(t, `{"uuid":"`+testRuleUUID+`","action":"pass","categories":"web,mail"}`, categories)
	if refusal == nil || refusal.Code != codeRuleValueInvalid {
		t.Fatalf("an unknown category: refusal = %+v", refusal)
	}
	if !strings.Contains(refusal.Message, `categories: "mail" not on this device (available: dns, web)`) {
		t.Errorf("message = %q", refusal.Message)
	}

	_, refusal = buildBody(t, `{"uuid":"`+testRuleUUID+`","action":"pass","categories":"web"}`)
	if refusal == nil || !strings.Contains(refusal.Message, "(available: none)") {
		t.Errorf("a device without categories: refusal = %+v", refusal)
	}
}

func TestBuildRuleBody_OptionChecks(t *testing.T) {
	body, refusal := buildBody(t, `{"uuid":"`+testRuleUUID+`","action":"pass","protocol":"tcp"}`)
	if refusal != nil || body["protocol"] != "tcp" {
		t.Errorf(`protocol "tcp": body %q, refusal %+v; OPNsense stores a protocol upper-cased, so it is sent`, body["protocol"], refusal)
	}

	_, refusal = buildBody(t, `{"uuid":"`+testRuleUUID+`","action":"pass","statetype":"SLOPPY","gateway":"WAN_GW"}`)
	if refusal == nil || refusal.Code != codeRuleValueInvalid {
		t.Fatalf("refusal = %+v", refusal)
	}
	for _, want := range []string{
		`statetype: "SLOPPY" not on this device (available: keep, modulate, none, sloppy, synproxy)`,
		`gateway: "WAN_GW" not on this device (available: Null4, Null6, WAN_DHCP, WAN_DHCP6)`,
	} {
		if !strings.Contains(refusal.Message, want) {
			t.Errorf("message %q missing %q", refusal.Message, want)
		}
	}

	_, refusal = buildBody(t, `{"uuid":"`+testRuleUUID+`","action":"pass","protocol":"NOPE"}`)
	if refusal == nil || !strings.Contains(refusal.Message, "and 118 more") {
		t.Errorf("a long option list is cut short: %+v", refusal)
	}

	noGateways := func(template map[string]interface{}) { template["gateway"] = optionList("", "none") }
	_, refusal = buildBody(t, `{"uuid":"`+testRuleUUID+`","action":"pass","gateway":"WAN_GW"}`, noGateways)
	if refusal == nil || !strings.Contains(refusal.Message, `gateway: "WAN_GW" not on this device (available: none)`) {
		t.Errorf("a device whose only gateway option is none: refusal = %+v", refusal)
	}
}

// TestBuildRuleBody_ActionIsRequired: the model's default action is pass, so a
// rule that left its action out would let traffic through by omission.
func TestBuildRuleBody_ActionIsRequired(t *testing.T) {
	for _, content := range []string{
		`{"uuid":"` + testRuleUUID + `","interface":"lan"}`,
		`{"uuid":"` + testRuleUUID + `","action":null}`,
		`{"uuid":"` + testRuleUUID + `","action":""}`,
	} {
		_, refusal := buildBody(t, content)
		if refusal == nil || refusal.Code != codeRuleValueInvalid || !strings.HasSuffix(refusal.Message, ": action is required") {
			t.Errorf("%s: refusal = %+v", content, refusal)
		}
	}
}

// TestBuildRuleBody_ProblemTexts pins the reason a value is refused with.
func TestBuildRuleBody_ProblemTexts(t *testing.T) {
	_, refusal := buildBody(t, `{"uuid":"`+testRuleUUID+`","action":"pass","destination_port":true,"interface":" , ","direction":false}`)
	if refusal == nil || refusal.Code != codeRuleValueInvalid {
		t.Fatalf("refusal = %+v", refusal)
	}
	for _, want := range []string{
		"destination_port: takes text or a number, not true or false",
		"interface: holds no option key",
		"direction: takes the key of one of the device's options, not true or false",
	} {
		if !strings.Contains(refusal.Message, want) {
			t.Errorf("message %q missing %q", refusal.Message, want)
		}
	}
}

func TestBuildRuleBody_InterfaceIsLeftToItsOwnCheck(t *testing.T) {
	body, refusal := buildBody(t, `{"uuid":"`+testRuleUUID+`","action":"pass","interface":"opt9"}`)
	if refusal != nil {
		t.Fatalf("refused: %+v; checkRuleInterfaces reports a missing interface with its own code", refusal)
	}
	if body["interface"] != "opt9" {
		t.Errorf("interface = %q", body["interface"])
	}
}

func TestRuleDescription_TemplateTagsAreNotDoubled(t *testing.T) {
	cases := map[string]string{
		"Allow HTTPS":                         "Allow HTTPS [nd-template:soc]",
		"Allow HTTPS [nd-template:soc]":       "Allow HTTPS [nd-template:soc]",
		"Allow HTTPS [x] [nd-template:old]":   "Allow HTTPS [x] [nd-template:soc]",
		"":                                    "[nd-template:soc]",
		"[nd-template:soc] [nd-template:soc]": "[nd-template:soc]",
	}
	for in, want := range cases {
		if got := withTemplateTags(in, []string{"soc"}); got != want {
			t.Errorf("withTemplateTags(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRuleRowMatches(t *testing.T) {
	body := map[string]string{"protocol": "UDP", "log": "1", "interface": "lan,wan", "destination_port": "HTTPS", "tag": "Web"}
	row := func(change func(map[string]interface{})) map[string]interface{} {
		r := map[string]interface{}{"protocol": "UDP", "log": "1", "interface": "lan,wan", "destination_port": "HTTPS", "tag": "Web"}
		change(r)
		return r
	}
	cases := []struct {
		name string
		row  map[string]interface{}
		want bool
	}{
		{"equal", row(func(r map[string]interface{}) { r["%log"] = "x" }), true},
		{"protocol case", row(func(r map[string]interface{}) { r["protocol"] = "udp" }), true},
		{"service name stored lower-cased", row(func(r map[string]interface{}) { r["destination_port"] = "https" }), true},
		{"port differs", row(func(r map[string]interface{}) { r["destination_port"] = "http" }), false},
		{"port stored upper-cased", row(func(r map[string]interface{}) { r["destination_port"] = "HTTPs" }), false},
		{"text field case", row(func(r map[string]interface{}) { r["tag"] = "web" }), false},
		{"value differs", row(func(r map[string]interface{}) { r["log"] = "0" }), false},
		{"list order differs", row(func(r map[string]interface{}) { r["interface"] = "wan,lan" }), false},
		{"field missing", row(func(r map[string]interface{}) { delete(r, "log") }), false},
		{"a number in its decimal form", row(func(r map[string]interface{}) { r["log"] = float64(1) }), true},
		{"a number that differs", row(func(r map[string]interface{}) { r["log"] = float64(0) }), false},
		{"neither text nor a number", row(func(r map[string]interface{}) { r["log"] = true }), false},
	}
	for _, tc := range cases {
		if got := ruleRowMatches(body, tc.row); got != tc.want {
			t.Errorf("%s: ruleRowMatches = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestRuleRowMatches_PortNames: OPNsense stores "any" and the well-known
// services trimmed and lower-cased, and every other port value, an alias name
// included, as written; two port aliases may differ only in case.
func TestRuleRowMatches_PortNames(t *testing.T) {
	cases := []struct {
		want, got string
		match     bool
	}{
		{"MyPorts", "myports", false},
		{"MyPorts", "MyPorts", true},
		{" HTTPS ", "https", true},
		{"ANY", "any", true},
		{"Ssh", "ssh", true},
		{"443", "443", true},
		{"HTTPS", "HTTPS", true},
		{"https", "HTTPS", false},
		{"https\u00a0", "https", false},
		{"\fhttps", "https", false},
		{"ISA\u212aMP", "isakmp", false},
		{"ISAKMP", "isakmp", true},
		{"\thttps\x00", "https", true},
		{"https\n", "https", true},
		{"\r\nssh", "ssh", true},
		{"\x0bhttps", "https", true},
		{"Domain-S", "domain-s", true},
		{"LDAPS", "ldaps", true},
		{"SIP-TLS", "sip-tls", true},
		{"Submissions", "submissions", true},
	}
	for _, tc := range cases {
		body := map[string]string{"destination_port": tc.want, "source_port": tc.want}
		row := map[string]interface{}{"destination_port": tc.got, "source_port": tc.got}
		if got := ruleRowMatches(body, row); got != tc.match {
			t.Errorf("content %q, device %q: ruleRowMatches = %v, want %v", tc.want, tc.got, got, tc.match)
		}
	}
}

// TestOpnsensePortFold: PHP's trim() set, then ASCII-only lower case.
func TestOpnsensePortFold(t *testing.T) {
	cases := map[string]string{
		"\n\r\v https \v\r\n": "https",
		"AZ":                  "az",
		"\x00SSH\t":           "ssh",
		"https\u00a0":         "https\u00a0",
		"\fhttps":             "\fhttps",
		"ISA\u212aMP":         "isa\u212amp",
	}
	for in, want := range cases {
		if got := opnsensePortFold(in); got != want {
			t.Errorf("opnsensePortFold(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCapList(t *testing.T) {
	cases := []struct {
		items []string
		want  string
	}{
		{nil, "none"},
		{[]string{""}, "none"},
		{[]string{"", "a", "b"}, "a, b"},
		{[]string{"a", "", "b", "c"}, "a, b and 1 more"},
	}
	for _, tc := range cases {
		if got := capList(tc.items, 2); got != tc.want {
			t.Errorf("capList(%q) = %q, want %q", tc.items, got, tc.want)
		}
	}
}

func TestEditDistance(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"lgo", "log", 2},
		{"log", "log", 0},
		{"", "abc", 3},
		{"quik", "quick", 1},
		{"source-net", "source_net", 1},
	}
	for _, tc := range cases {
		if got := editDistance(tc.a, tc.b); got != tc.want {
			t.Errorf("editDistance(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestParseRuleContent_RequiresAnObjectWithAUUID(t *testing.T) {
	for _, content := range []string{`null`, `[]`, `"rule"`, `{}`, `{"uuid":""}`} {
		if _, err := parseRuleContent(content, nil); err == nil {
			t.Errorf("parseRuleContent(%s) accepted it", content)
		}
	}
}
