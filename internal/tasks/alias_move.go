package tasks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// aliasMove is one alias under a new uuid: a managed alias the device holds
// under a uuid no desired alias carries any more, and the one desired alias
// that carries its name under a uuid the device does not hold. A snippet's
// uuid edited in place, or replaced by a pull that overwrites the snippet,
// arrives this way.
//
// OPNsense names an alias wherever it is used, and cannot give one that is in
// use a new uuid: it deletes no alias a rule or another alias refers to, and a
// rename moves every reference with it. So the snippet's content is first
// written onto the old object, which keeps the name and what refers to it.
// Once the rules and aliases no longer wanted are gone, the old object is
// deleted and the alias created again under the snippet's uuid; when OPNsense
// refuses the delete, the old object stays with the snippet's content, and a
// later SYNC moves it once nothing refers to it. The old object is never an
// orphan for the sweep.
type aliasMove struct {
	alias   APIAliasPayload
	oldUUID string
	oldRow  map[string]interface{}

	// body is set once the old object holds the snippet's content; written
	// says whether that took a write.
	body    map[string]string
	written bool
}

// findAliasMoves pairs each desired alias the device does not hold with the
// managed alias of the same name that no desired alias claims, keyed by the
// desired alias's uuid. A name two desired aliases share pairs nothing: that
// is a collision between snippets, refused as before.
func findAliasMoves(aliases []APIAliasPayload, managed []map[string]interface{}, desired map[string]APIAliasPayload) map[string]*aliasMove {
	held := map[string]bool{}
	orphans := map[string]map[string]interface{}{}
	for _, row := range managed {
		uuid, _ := row["uuid"].(string)
		name, _ := row["name"].(string)
		held[uuid] = true
		if _, wanted := desired[uuid]; !wanted && name != "" {
			orphans[name] = row
		}
	}
	claims := map[string]int{}
	for _, alias := range aliases {
		claims[alias.Name]++
	}
	moves := map[string]*aliasMove{}
	for _, alias := range aliases {
		row, found := orphans[alias.Name]
		if !found || held[alias.UUID] || claims[alias.Name] != 1 {
			continue
		}
		oldUUID, _ := row["uuid"].(string)
		moves[alias.UUID] = &aliasMove{alias: alias, oldUUID: oldUUID, oldRow: row}
	}
	return moves
}

// adopt writes the snippet's content onto the old object unless it already
// holds it. A refused write is the alias's result, and the old object stays
// as it was until a later pass.
func (m *aliasMove) adopt(ctx context.Context, client *opnapi.Client, body map[string]string) (*SyncAPIItemResult, string) {
	if !aliasContract.rowMatches(body, m.oldRow) {
		if err := client.SetAlias(ctx, m.oldUUID, body); err != nil {
			item, msg := aliasWriteResult(m.alias, "updated", err)
			return &item, msg
		}
		m.written = true
	}
	m.body = body
	return nil, ""
}

// finish deletes the old object and creates the alias under the snippet's
// uuid, or keeps the old object when OPNsense does not delete it. A delete that
// did not succeed is checked on the device first: the old object can be gone
// all the same (the answer was lost, or it was gone already), and then the
// alias is created as after a delete.
func (m *aliasMove) finish(ctx context.Context, client *opnapi.Client) ([]SyncAPIItemResult, []string) {
	if delErr := client.DeleteAlias(ctx, m.oldUUID); delErr != nil {
		row, err := client.GetAliasByName(ctx, m.alias.Name)
		holder := ""
		if row != nil {
			holder, _ = row["uuid"].(string)
		}
		switch {
		case err != nil:
			msg := fmt.Sprintf("%s: OPNsense did not confirm the removal of its earlier uuid %s (%s), and the alias could not be read back (%v): "+
				"it may be missing until the next SYNC", aliasLabel(m.alias), m.oldUUID, opnsenseErrorMessage(delErr), err)
			return []SyncAPIItemResult{{Type: "alias", UUID: m.alias.UUID, Name: m.alias.Name, Action: "created", Status: "error", Error: msg}}, []string{msg}
		case holder == m.oldUUID:
			return m.kept(delErr), nil
		case row != nil:
			msg := fmt.Sprintf("%s: after OPNsense did not confirm the removal of its earlier uuid %s (%s), the name is held by uuid %s; "+
				"the alias was not created", aliasLabel(m.alias), m.oldUUID, opnsenseErrorMessage(delErr), holder)
			return []SyncAPIItemResult{{Type: "alias", UUID: m.alias.UUID, Name: m.alias.Name, Action: "created", Status: "error", Error: msg}}, []string{msg}
		}
	}
	deleted := SyncAPIItemResult{Type: "alias", UUID: m.oldUUID, Name: m.alias.Name, Action: "deleted", Status: "success"}
	created, msg := aliasWriteResult(m.alias, "created", client.SetAlias(ctx, m.alias.UUID, m.body))
	if msg != "" {
		return []SyncAPIItemResult{deleted, created}, []string{msg}
	}
	return []SyncAPIItemResult{deleted, created}, nil
}

// kept is the result of a move OPNsense refused: the alias stays under its
// earlier uuid, with the snippet's content.
func (m *aliasMove) kept(delErr error) []SyncAPIItemResult {
	action := "unchanged"
	if m.written {
		action = "updated"
	}
	return []SyncAPIItemResult{
		{Type: "alias", UUID: m.alias.UUID, Name: m.alias.Name, Action: action, Status: "success"},
		{
			Type: "alias", UUID: m.oldUUID, Name: m.alias.Name, Action: "kept", Status: "warning",
			Code: codeAliasKeptUnderEarlierUUID,
			Error: fmt.Sprintf("alias %q stays under its earlier uuid %s with the snippet's content: OPNsense did not remove it (%s). "+
				"OPNsense removes no alias that rules or other aliases refer to; a later SYNC moves it to uuid %s once it can",
				m.alias.Name, m.oldUUID, opnsenseErrorMessage(delErr), m.alias.UUID),
		},
	}
}

// aliasWriteResult is the result item of writing alias, and the task error a
// failed write adds ("" when it succeeded).
func aliasWriteResult(alias APIAliasPayload, action string, err error) (SyncAPIItemResult, string) {
	item := SyncAPIItemResult{Type: "alias", UUID: alias.UUID, Name: alias.Name, Action: action, Status: "success"}
	if err == nil {
		return item, ""
	}
	item.Status = "error"
	if refused, isRefusal := validationFailure(err); isRefusal {
		item.Error = fmt.Sprintf("%s: %s", aliasLabel(alias), strings.Join(refused.Messages(), "; "))
		item.Code = codeAliasRejectedByDevice
	} else {
		item.Error = fmt.Sprintf("%s: %v", aliasLabel(alias), err)
	}
	return item, item.Error
}

// opnsenseErrorMessage is the errorMessage OPNsense refused a call with, on one
// line, or the error itself when the answer carries none.
func opnsenseErrorMessage(err error) string {
	var apiErr *opnapi.APIError
	if errors.As(err, &apiErr) {
		var answer struct {
			ErrorMessage string `json:"errorMessage"`
		}
		if json.Unmarshal([]byte(apiErr.Body), &answer) == nil && answer.ErrorMessage != "" {
			return strings.Join(strings.Fields(answer.ErrorMessage), " ")
		}
	}
	return err.Error()
}
