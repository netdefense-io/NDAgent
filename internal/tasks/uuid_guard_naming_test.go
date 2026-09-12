package tasks

// uuid_guard_naming_test.go — the UUID-prefix guards must name the snippet
// and the template that carried the bad UUID.
//
// Lab E2E on the snippet-naming pass (#79) found this family had been
// missed: these six guards still produced
//
//	Invalid rule UUID aaaaaaaa-...: must start with 221f3268
//
// with no snippet name, no index and no template — and they abort the whole
// sync, so the user got an empty results list and one hex string to work
// from.

import (
	"strings"
	"testing"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

const foreignUUID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"

// TestInvalidUUIDMessageNamesSnippetAndTemplate is the table over all six
// guarded families. Each entry parses a snippet whose content carries a
// UUID outside the managed prefix and asserts the message the guard would
// build from the parsed payload.
//
// Driven through the real parsers rather than hand-built payloads, so it
// also pins that each parser records its provenance — a parser that forgot
// to set SnippetName/SnippetIndex fails here rather than silently degrading
// the message at runtime.
func TestInvalidUUIDMessageNamesSnippetAndTemplate(t *testing.T) {
	cases := []struct {
		kind       string
		configType string
		content    string
		// message renders what the guard in HandleSyncAPI would produce.
		message func(map[string]interface{}) (string, error)
	}{
		{
			kind:       "alias",
			configType: "ALIAS",
			content:    `{"uuid":"` + foreignUUID + `","name":"a","type":"host"}`,
			message: func(p map[string]interface{}) (string, error) {
				got, err := parseAPIAliases(p)
				if err != nil {
					return "", err
				}
				a := got[0]
				return invalidUUIDMessage("alias", a.SnippetName, a.SnippetIndex, a.Templates, a.UUID), nil
			},
		},
		{
			kind:       "rule",
			configType: "RULE",
			content:    `{"uuid":"` + foreignUUID + `","action":"pass"}`,
			message: func(p map[string]interface{}) (string, error) {
				got, err := parseAPIRules(p)
				if err != nil {
					return "", err
				}
				r := got[0]
				return invalidUUIDMessage("rule", r.SnippetName, r.SnippetIndex, r.Templates, r.UUID), nil
			},
		},
		{
			kind:       "host_override",
			configType: "UNBOUND_HOST_OVERRIDE",
			content:    `{"uuid":"` + foreignUUID + `","hostname":"h","domain":"d"}`,
			message: func(p map[string]interface{}) (string, error) {
				got, err := parseAPIHostOverrides(p)
				if err != nil {
					return "", err
				}
				o := got[0]
				return invalidUUIDMessage("host_override", o.SnippetName, o.SnippetIndex, o.Templates, o.UUID), nil
			},
		},
		{
			kind:       "domain_forward",
			configType: "UNBOUND_DOMAIN_FORWARD",
			content:    `{"uuid":"` + foreignUUID + `","domain":"d","server":"1.1.1.1"}`,
			message: func(p map[string]interface{}) (string, error) {
				got, err := parseAPIDomainForwards(p)
				if err != nil {
					return "", err
				}
				f := got[0]
				return invalidUUIDMessage("domain_forward", f.SnippetName, f.SnippetIndex, f.Templates, f.UUID), nil
			},
		},
		{
			kind:       "host_alias",
			configType: "UNBOUND_HOST_ALIAS",
			content:    `{"uuid":"` + foreignUUID + `","parent_hostname":"p","parent_domain":"d","hostname":"h","domain":"d"}`,
			message: func(p map[string]interface{}) (string, error) {
				got, err := parseAPIHostAliases(p)
				if err != nil {
					return "", err
				}
				a := got[0]
				return invalidUUIDMessage("host_alias", a.SnippetName, a.SnippetIndex, a.Templates, a.UUID), nil
			},
		},
		{
			kind:       "unbound_acl",
			configType: "UNBOUND_ACL",
			content:    `{"uuid":"` + foreignUUID + `","name":"n","action":"allow","networks":["10.0.0.0/8"]}`,
			message: func(p map[string]interface{}) (string, error) {
				got, err := parseAPIUnboundACLs(p)
				if err != nil {
					return "", err
				}
				a := got[0]
				return invalidUUIDMessage("unbound_acl", a.SnippetName, a.SnippetIndex, a.Templates, a.UUID), nil
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			payload := map[string]interface{}{
				"snippets": []interface{}{
					// A leading snippet of another type, so the offender is
					// at index 1 and the index is demonstrably carried.
					map[string]interface{}{"config_type": "IGNORED", "content": "{}"},
					map[string]interface{}{
						"config_type":   tc.configType,
						"snippet_name":  "bad-" + tc.kind,
						"template_name": []interface{}{"base"},
						"content":       tc.content,
					},
				},
			}

			msg, err := tc.message(payload)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}

			for _, want := range []string{
				tc.kind + " snippet",     // the family
				`"bad-` + tc.kind + `"`,  // the snippet name
				"index 1",                // the position, still carried
				foreignUUID,              // the offending UUID
				opnapi.NDAgentUUIDPrefix, // what a managed UUID must start with
				`template "base"`,        // the template that carried it
			} {
				if !strings.Contains(msg, want) {
					t.Errorf("message %q is missing %q", msg, want)
				}
			}
		})
	}
}

// TestInvalidUUIDMessageFallsBackWithoutSnippetName pins the older-control-
// plane path, matching the fallback the parse errors already use.
func TestInvalidUUIDMessageFallsBackWithoutSnippetName(t *testing.T) {
	msg := invalidUUIDMessage("rule", "", 3, nil, foreignUUID)

	if !strings.Contains(msg, "rule snippet at index 3") {
		t.Errorf("message %q should fall back to the index-only form", msg)
	}
	if strings.Contains(msg, `""`) {
		t.Errorf("message %q must not render an empty snippet name", msg)
	}
	if strings.Contains(msg, "template") {
		t.Errorf("message %q should omit the template clause when there are none", msg)
	}
}

// TestInvalidUUIDMessagePluralisesTemplates covers a snippet reached through
// more than one template — the user needs all of them, since the fix may be
// in any.
func TestInvalidUUIDMessagePluralisesTemplates(t *testing.T) {
	msg := invalidUUIDMessage("alias", "shared", 0, []string{"base", "extra"}, foreignUUID)

	if !strings.Contains(msg, `templates "base", "extra"`) {
		t.Errorf("message %q should list every template that carries the snippet", msg)
	}
	if strings.Contains(msg, `template "base",`) && !strings.Contains(msg, "templates") {
		t.Errorf("message %q used the singular form for two templates", msg)
	}
}

// TestParsersRecordSnippetProvenance asserts the provenance fields directly,
// so a parser that stops setting them fails here even if the message format
// changes. Provenance is agent-internal and json:"-", so nothing on the wire
// depends on it.
func TestParsersRecordSnippetProvenance(t *testing.T) {
	payload := map[string]interface{}{
		"snippets": []interface{}{
			map[string]interface{}{"config_type": "IGNORED", "content": "{}"},
			map[string]interface{}{
				"config_type":  "ALIAS",
				"snippet_name": "nd-lab-admins",
				"content":      `{"uuid":"221f3268-a","name":"a","type":"host"}`,
			},
		},
	}

	aliases, err := parseAPIAliases(payload)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(aliases) != 1 {
		t.Fatalf("got %d aliases, want 1", len(aliases))
	}
	if aliases[0].SnippetName != "nd-lab-admins" {
		t.Errorf("SnippetName = %q, want nd-lab-admins", aliases[0].SnippetName)
	}
	if aliases[0].SnippetIndex != 1 {
		t.Errorf("SnippetIndex = %d, want 1 (the position in the payload, not in the filtered slice)", aliases[0].SnippetIndex)
	}
}
