package tasks

import "strings"

// ignoredKeySet is, for one snippet type, the content keys it ignores: a key
// equal to one of names, or starting with one of prefixes, compared exactly
// and case-sensitively.
type ignoredKeySet struct {
	names    []string
	prefixes []string
}

// ignoredContentKeys is, per snippet type, the content keys no agent applies:
// what PULL stores that no agent reads (OPNsense's display labels and grid
// decorations, the models' computed and volatile fields, the legacy-row
// markers, a rule's audit record, the Unbound template list) and RULE's
// sequence, which placement assigns. An ignored key may hold any JSON value
// (a pulled rule's alias_meta_* are lists of objects), so it is skipped before
// any check of its value, and never sent.
//
// It is NDDataModels' is_ignored_content_key, which the control plane applies
// too. testdata/ignored-content-keys/vectors.json is a byte-for-byte copy of
// the shared vectors that pin the two equal: change them together.
var ignoredContentKeys = map[string]ignoredKeySet{
	"ALIAS": {
		names: []string{
			"categories_uuid", "current_items", "eval_match", "eval_nomatch",
			"in_block_b", "in_block_p", "in_pass_b", "in_pass_p", "last_updated",
			"out_block_b", "out_block_p", "out_pass_b", "out_pass_p",
		},
		prefixes: []string{"%"},
	},
	"AUTH_ORDER":  {},
	"AUTH_SERVER": {},
	"GROUP":       {},
	"RULE": {
		names: []string{
			"#priority", "audit", "category_colors", "is_automatic", "legacy",
			"prio_group", "ref", "seq", "sequence", "sort_order",
		},
		prefixes: []string{"%", "alias_meta_"},
	},
	"TRUST_CA":               {},
	"TRUST_CERT":             {},
	"UNBOUND_ACL":            {names: []string{"templates"}},
	"UNBOUND_DOMAIN_FORWARD": {names: []string{"templates"}},
	"UNBOUND_HOST_ALIAS":     {names: []string{"templates"}},
	"UNBOUND_HOST_OVERRIDE":  {names: []string{"templates"}},
	"USER":                   {},
	"ZABBIX_ALIAS":           {},
	"ZABBIX_SETTINGS":        {},
	"ZABBIX_USERPARAMETER":   {},
}

// isIgnoredContentKey reports whether a snippet of this type ignores key.
func isIgnoredContentKey(snippetType, key string) bool {
	set := ignoredContentKeys[snippetType]
	for _, name := range set.names {
		if key == name {
			return true
		}
	}
	for _, prefix := range set.prefixes {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}
