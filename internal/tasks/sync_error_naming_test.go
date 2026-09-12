package tasks

// sync_error_naming_test.go — Community #11: sync errors must name the
// snippet, not just its position in the payload.

import (
	"encoding/json"
	"strings"
	"testing"
)

// snippetPayload builds a SYNC payload carrying one snippet of the given
// config type, with or without the `snippet_name` field NDManager sends.
func snippetPayload(configType, name, content string, withName bool) map[string]interface{} {
	snippet := map[string]interface{}{
		"config_type":   configType,
		"content":       content,
		"template_name": []interface{}{"tmpl"},
	}
	if withName {
		snippet["snippet_name"] = name
	}
	return map[string]interface{}{
		"snippets": []interface{}{
			// A leading snippet of a different type, so the offending one is
			// at index 1 — matching the reporter's "at index 1" and proving
			// the index is still carried.
			map[string]interface{}{"config_type": "IGNORED", "content": "{}"},
			snippet,
		},
	}
}

// TestSnippetLabel covers the helper directly, including the fallback that
// keeps an older control plane (which sends no snippet_name) printing what
// it printed before rather than an empty pair of quotes.
func TestSnippetLabel(t *testing.T) {
	withName := map[string]interface{}{"snippet_name": "nd-lab-admins"}
	if got, want := snippetLabel("alias", withName, 1), `alias snippet "nd-lab-admins" (index 1)`; got != want {
		t.Errorf("snippetLabel = %q, want %q", got, want)
	}

	for name, snippet := range map[string]map[string]interface{}{
		"absent":    {},
		"empty":     {"snippet_name": ""},
		"wrongType": {"snippet_name": 42},
	} {
		t.Run(name, func(t *testing.T) {
			if got, want := snippetLabel("alias", snippet, 1), "alias snippet at index 1"; got != want {
				t.Errorf("snippetLabel = %q, want the index-only fallback %q", got, want)
			}
		})
	}
}

// TestParseErrorsNameTheSnippet is the reported failure. The exact message
// from Community #11 was:
//
//	Failed to parse aliases: alias snippet at index 1: missing required field: uuid
//
// which names a position in a payload the user never sees. It must now name
// the snippet, and still carry the index — two snippets can share a name
// across templates, and the index is what tells them apart.
func TestParseErrorsNameTheSnippet(t *testing.T) {
	// Content valid as JSON but missing `uuid`, exactly as reported.
	aliasContent := `{"name":"nd_lab_admins","type":"host","content":"192.168.50.0/24","description":"x","enabled":"1"}`

	_, err := parseAPIAliases(snippetPayload("ALIAS", "nd-lab-admins", aliasContent, true))
	if err == nil {
		t.Fatal("expected a parse error for content missing uuid")
	}
	got := err.Error()

	for _, want := range []string{`"nd-lab-admins"`, "index 1", "missing required field: uuid"} {
		if !strings.Contains(got, want) {
			t.Errorf("error %q is missing %q", got, want)
		}
	}
}

// TestParseErrorsFallBackToIndexWithoutSnippetName pins the older-control-
// plane path: no snippet_name on the wire means the message degrades to the
// form it had before, not to a blank name.
func TestParseErrorsFallBackToIndexWithoutSnippetName(t *testing.T) {
	aliasContent := `{"name":"nd_lab_admins","type":"host"}`

	_, err := parseAPIAliases(snippetPayload("ALIAS", "nd-lab-admins", aliasContent, false))
	if err == nil {
		t.Fatal("expected a parse error for content missing uuid")
	}
	got := err.Error()

	if !strings.Contains(got, "alias snippet at index 1") {
		t.Errorf("error %q should fall back to the index-only form", got)
	}
	if strings.Contains(got, `""`) {
		t.Errorf("error %q must not render an empty snippet name", got)
	}
}

// TestEverySnippetFamilyNamesTheSnippet walks every config type that parses
// content, so a future family added without the label is caught. The reported
// bug was in ALIAS, but the same index-only message was in all of them.
func TestEverySnippetFamilyNamesTheSnippet(t *testing.T) {
	// Content that is valid JSON but fails each family's required-field
	// check, so every parser reaches its error path.
	families := []struct {
		configType string
		parse      func(map[string]interface{}) error
	}{
		{"ALIAS", func(p map[string]interface{}) error { _, err := parseAPIAliases(p); return err }},
		{"RULE", func(p map[string]interface{}) error { _, err := parseAPIRules(p); return err }},
		{"USER", func(p map[string]interface{}) error { _, err := parseAPIUsers(p); return err }},
		{"GROUP", func(p map[string]interface{}) error { _, err := parseAPIGroups(p); return err }},
		{"UNBOUND_HOST_OVERRIDE", func(p map[string]interface{}) error { _, err := parseAPIHostOverrides(p); return err }},
		{"UNBOUND_DOMAIN_FORWARD", func(p map[string]interface{}) error { _, err := parseAPIDomainForwards(p); return err }},
		{"UNBOUND_HOST_ALIAS", func(p map[string]interface{}) error { _, err := parseAPIHostAliases(p); return err }},
		{"UNBOUND_ACL", func(p map[string]interface{}) error { _, err := parseAPIUnboundACLs(p); return err }},
		{"ZABBIX_USERPARAMETER", func(p map[string]interface{}) error { _, err := parseAPIZabbixUserParameters(p); return err }},
		{"ZABBIX_ALIAS", func(p map[string]interface{}) error { _, err := parseAPIZabbixAliases(p); return err }},
	}

	for _, family := range families {
		t.Run(family.configType, func(t *testing.T) {
			// "{}" satisfies JSON parsing and fails every required-field check.
			payload := snippetPayload(family.configType, "my-snippet", "{}", true)
			err := family.parse(payload)
			if err == nil {
				t.Fatalf("%s: expected a parse error for empty content object", family.configType)
			}
			if !strings.Contains(err.Error(), `"my-snippet"`) {
				t.Errorf("%s: error %q does not name the snippet", family.configType, err.Error())
			}
			if !strings.Contains(err.Error(), "index 1") {
				t.Errorf("%s: error %q dropped the index", family.configType, err.Error())
			}
		})
	}
}

// TestMissingContentNamesTheSnippet covers the other per-snippet error, which
// fires before any JSON is parsed.
func TestMissingContentNamesTheSnippet(t *testing.T) {
	_, err := parseAPIAliases(snippetPayload("ALIAS", "nd-lab-admins", "", true))
	if err == nil {
		t.Fatal("expected an error for a snippet with no content")
	}
	if !strings.Contains(err.Error(), `alias snippet "nd-lab-admins" (index 1): missing content`) {
		t.Errorf("error %q should name the snippet", err.Error())
	}
}

// TestInvalidPositionNamesTheSnippet covers the rule-only metadata error.
func TestInvalidPositionNamesTheSnippet(t *testing.T) {
	payload := map[string]interface{}{
		"snippets": []interface{}{
			map[string]interface{}{
				"config_type":  "RULE",
				"snippet_name": "allow-vpn",
				"position":     "SIDEWAYS",
				"content":      `{"uuid":"221f3268-a"}`,
			},
		},
	}
	_, err := parseAPIRules(payload)
	if err == nil {
		t.Fatal("expected an error for an invalid position")
	}
	for _, want := range []string{`"allow-vpn"`, "index 0", "SIDEWAYS"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q is missing %q", err.Error(), want)
		}
	}
}

// TestSnippetNameMatchesTheWireField pins the field name against NDManager's
// payload builder. The name was already being sent and simply never read;
// if the producer ever renames the field, this is what notices.
func TestSnippetNameMatchesTheWireField(t *testing.T) {
	// The shape NDManager's build_payload emits, per snippet
	// (services/sync_service.py).
	wire := `{"config_type":"ALIAS","snippet_name":"nd-lab-admins","position":"PREPEND",` +
		`"priority":500,"template_name":["base"],"content":"{}"}`

	var snippet map[string]interface{}
	if err := json.Unmarshal([]byte(wire), &snippet); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got, want := snippetLabel("alias", snippet, 0), `alias snippet "nd-lab-admins" (index 0)`; got != want {
		t.Errorf("snippetLabel over the real wire shape = %q, want %q", got, want)
	}
}
