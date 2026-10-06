package tasks

import (
	"context"
	"fmt"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// Result codes of the ALIAS family.
const (
	codeAliasFieldUnknown     = "ALIAS_FIELD_UNKNOWN"
	codeAliasValueInvalid     = "ALIAS_VALUE_INVALID"
	codeAliasRejectedByDevice = "ALIAS_REJECTED_BY_DEVICE"
	codeAliasModelUnavailable = "ALIAS_MODEL_UNAVAILABLE"
)

// aliasContract is the ALIAS family's field contract: any field of the
// device's alias model. The keys an alias never applies are ALIAS's ignored
// keys: the statistics OPNsense keeps on the model without storing them
// (volatile fields), and what a pulled alias carried from the search grid.
// Content entries are separated by newlines, OPNsense's separator for them;
// the template's content options are only the alias names it suggests.
var aliasContract = fieldContract{
	snippetType:  "ALIAS",
	entity:       "alias",
	codeUnknown:  codeAliasFieldUnknown,
	codeInvalid:  codeAliasValueInvalid,
	nameMapped:   map[string]bool{"categories": true},
	newlineLists: map[string]bool{"content": true},
}

// aliasAlwaysPulled are the fields a pulled alias carries even at their
// default.
var aliasAlwaysPulled = map[string]bool{
	"enabled":     true,
	"name":        true,
	"type":        true,
	"content":     true,
	"description": true,
}

// aliasLabel names an alias in a message by its name and its snippet.
func aliasLabel(a APIAliasPayload) string {
	if a.SnippetName != "" {
		return fmt.Sprintf("Alias %q (snippet %q)", a.Name, a.SnippetName)
	}
	return fmt.Sprintf("Alias %q (snippet at index %d)", a.Name, a.SnippetIndex)
}

// buildAliasBody turns a desired alias's content into the body setItem takes:
// every field the device's alias model lets content set, at the content's
// value or the model's default. See fieldContract.build for what refuses it.
func buildAliasBody(a APIAliasPayload, model opnapi.EntityModel, release func() string) (map[string]string, *contentRefusal) {
	body, refusal := aliasContract.build(a.Content, model, aliasLabel(a), release)
	if refusal != nil {
		return nil, refusal
	}
	body["description"] = withTemplateTags(body["description"], a.Templates)
	return body, nil
}

// pullAlias finds an alias by exact name and returns it as portable alias
// content (fieldContract.portable), its categories named.
func pullAlias(ctx context.Context, client *opnapi.Client, name string) (map[string]interface{}, error) {
	row, err := client.GetAliasByName(ctx, name)
	if err != nil || row == nil {
		return nil, err
	}
	model, err := client.GetAliasModel(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read the alias model: %w", err)
	}
	return aliasContract.portable(row, model, aliasAlwaysPulled), nil
}
