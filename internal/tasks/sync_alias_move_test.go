package tasks

// sync_alias_move_test.go — a managed alias whose snippet now carries another
// uuid under the same name: the uuid edited in place, or replaced by a pull
// that overwrites the snippet. OPNsense cannot give an alias that something
// refers to a new uuid, so the agent moves it when nothing does and keeps the
// old object, with the snippet's content, while something does.

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

const (
	aliasOldUUID   = "221f3268-0001-4000-8000-0000000000a1"
	aliasNewUUID   = "221f3268-0001-4000-8000-0000000000b1"
	aliasOuterUUID = "221f3268-0001-4000-8000-0000000000c1"
)

// webAlias is the snippet "web": the alias nd_web holding one address.
func webAlias(t *testing.T, uuid, address string) APIAliasPayload {
	t.Helper()
	return desiredAlias(t, "web", `{"uuid":"`+uuid+`","enabled":"1","name":"nd_web","type":"host","content":"`+address+`","description":"web servers"}`)
}

// outerAlias is the snippet "outer": an alias whose content names nd_web.
func outerAlias(t *testing.T) APIAliasPayload {
	t.Helper()
	return desiredAlias(t, "outer", `{"uuid":"`+aliasOuterUUID+`","enabled":"1","name":"nd_outer","type":"host","content":"nd_web","description":"outer"}`)
}

// deviceAlias is the device's alias with this uuid, or nil.
func (f *fakeRuleDevice) deviceAlias(uuid string) map[string]interface{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, row := range f.aliases {
		if row["uuid"] == uuid {
			copied := map[string]interface{}{}
			for k, v := range row {
				copied[k] = v
			}
			return copied
		}
	}
	return nil
}

// aliasWritesSince returns the alias writes and deletes made after the first n
// mutating calls.
func (f *fakeRuleDevice) aliasWritesSince(n int) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, w := range f.writes[n:] {
		if strings.HasPrefix(w, "alias ") || strings.HasPrefix(w, "aliasdel ") {
			out = append(out, w)
		}
	}
	return out
}

func (f *fakeRuleDevice) writeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.writes)
}

func syncAliases(t *testing.T, device *fakeRuleDevice, aliases []APIAliasPayload, rules []APIRulePayload) SyncAPIResult {
	t.Helper()
	return executeSyncAPI(context.Background(), device.client, aliases, rules)
}

func mustSucceed(t *testing.T, what string, result SyncAPIResult) {
	t.Helper()
	if !result.Success {
		t.Fatalf("%s failed: %v (validation %+v)", what, result.Errors, result.ValidationErrors)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestAliasMove_UnreferencedAliasTakesItsNewUUIDInOneSync(t *testing.T) {
	device := newFakeRuleDevice(t, ruleTemplate(t), nil)
	device.refuseAliasesInUse = true
	mustSucceed(t, "first sync", syncAliases(t, device, []APIAliasPayload{webAlias(t, aliasOldUUID, "192.0.2.10")}, nil))
	before := device.writeCount()

	result := syncAliases(t, device, []APIAliasPayload{webAlias(t, aliasNewUUID, "192.0.2.10")}, nil)

	mustSucceed(t, "the sync with the new uuid", result)
	if got, want := device.aliasWritesSince(before), []string{"aliasdel " + aliasOldUUID, "alias " + aliasNewUUID}; !equalStrings(got, want) {
		t.Errorf("writes = %v, want %v: the old object removed, then the alias created under the new uuid", got, want)
	}
	if device.deviceAlias(aliasOldUUID) != nil {
		t.Error("the old object is still on the device")
	}
	if row := device.deviceAlias(aliasNewUUID); row == nil || row["name"] != "nd_web" || row["content"] != "192.0.2.10" {
		t.Errorf("alias under the new uuid = %v", row)
	}
	if item := ruleItem(result.Results, "alias", aliasOldUUID); item == nil || item.Action != "deleted" || item.Status != "success" {
		t.Errorf("old object item = %+v, want deleted", item)
	}
	if item := ruleItem(result.Results, "alias", aliasNewUUID); item == nil || item.Action != "created" || item.Status != "success" {
		t.Errorf("new alias item = %+v, want created", item)
	}
}

// When the content changes with the uuid, the old object takes the content
// first: a content the device refuses must never cost the alias.
func TestAliasMove_NewContentIsWrittenBeforeTheOldObjectGoes(t *testing.T) {
	device := newFakeRuleDevice(t, ruleTemplate(t), nil)
	mustSucceed(t, "first sync", syncAliases(t, device, []APIAliasPayload{webAlias(t, aliasOldUUID, "192.0.2.10")}, nil))
	before := device.writeCount()

	mustSucceed(t, "the sync with the new uuid", syncAliases(t, device, []APIAliasPayload{webAlias(t, aliasNewUUID, "192.0.2.11")}, nil))

	want := []string{"alias " + aliasOldUUID, "aliasdel " + aliasOldUUID, "alias " + aliasNewUUID}
	if got := device.aliasWritesSince(before); !equalStrings(got, want) {
		t.Errorf("writes = %v, want %v", got, want)
	}
	if row := device.deviceAlias(aliasNewUUID); row == nil || row["content"] != "192.0.2.11" {
		t.Errorf("alias under the new uuid = %v, want the new content", row)
	}
}

func TestAliasMove_ContentTheDeviceRefusesLeavesTheOldObjectAsItWas(t *testing.T) {
	device := newFakeRuleDevice(t, ruleTemplate(t), nil)
	mustSucceed(t, "first sync", syncAliases(t, device, []APIAliasPayload{webAlias(t, aliasOldUUID, "192.0.2.10")}, nil))
	device.answer = func(uuid string, body map[string]string) (int, interface{}, bool) {
		if body["content"] != "bogus" {
			return 0, nil, false
		}
		return http.StatusOK, map[string]interface{}{
			"result":      "failed",
			"validations": map[string]string{"alias.content": `Entry "bogus" is not a valid hostname, IP address or range.`},
		}, true
	}

	result := syncAliases(t, device, []APIAliasPayload{webAlias(t, aliasNewUUID, "bogus")}, nil)

	if result.Success {
		t.Fatal("a content the device refuses must fail the sync")
	}
	item := ruleItem(result.Results, "alias", aliasNewUUID)
	if item == nil || item.Status != "error" || item.Code != codeAliasRejectedByDevice || !strings.Contains(item.Error, "not a valid hostname") {
		t.Errorf("alias item = %+v, want the device's refusal", item)
	}
	if row := device.deviceAlias(aliasOldUUID); row == nil || row["content"] != "192.0.2.10" {
		t.Errorf("old object = %v, want it untouched", row)
	}
	if device.deviceAlias(aliasNewUUID) != nil {
		t.Error("the alias was created under the new uuid although its content was refused")
	}
}

// OPNsense refuses to delete an alias that another alias names: the old object
// stays, with the snippet's content, the sync succeeds, and a warning says why.
func TestAliasMove_AliasNamedByAnotherAliasKeepsItsUUIDAndTakesTheContent(t *testing.T) {
	device := newFakeRuleDevice(t, ruleTemplate(t), nil)
	device.refuseAliasesInUse = true
	mustSucceed(t, "first sync", syncAliases(t, device, []APIAliasPayload{webAlias(t, aliasOldUUID, "192.0.2.10"), outerAlias(t)}, nil))

	result := syncAliases(t, device, []APIAliasPayload{webAlias(t, aliasNewUUID, "192.0.2.11"), outerAlias(t)}, nil)

	mustSucceed(t, "the sync with the new uuid", result)
	if row := device.deviceAlias(aliasOldUUID); row == nil || row["name"] != "nd_web" || row["content"] != "192.0.2.11" {
		t.Errorf("old object = %v, want it kept with the new content", row)
	}
	if device.deviceAlias(aliasNewUUID) != nil {
		t.Error("an alias was created under the new uuid while the old object holds the name")
	}
	if item := ruleItem(result.Results, "alias", aliasNewUUID); item == nil || item.Action != "updated" || item.Status != "success" {
		t.Errorf("alias item = %+v, want an update", item)
	}
	warning := ruleItem(result.Results, "alias", aliasOldUUID)
	if warning == nil || warning.Status != "warning" || warning.Action != "kept" || warning.Code != codeAliasKeptUnderEarlierUUID {
		t.Fatalf("old object item = %+v, want the kept warning", warning)
	}
	for _, want := range []string{`"nd_web"`, aliasOldUUID, aliasNewUUID, "Cannot delete alias nd_web", "[aliases.alias." + aliasOuterUUID + "]"} {
		if !strings.Contains(warning.Error, want) {
			t.Errorf("warning %q is missing %q", warning.Error, want)
		}
	}

	// While something still refers to it, a later sync changes nothing.
	before := device.writeCount()
	again := syncAliases(t, device, []APIAliasPayload{webAlias(t, aliasNewUUID, "192.0.2.11"), outerAlias(t)}, nil)
	mustSucceed(t, "the next sync", again)
	if got := device.aliasWritesSince(before); len(got) != 0 {
		t.Errorf("writes = %v, want none", got)
	}
	if item := ruleItem(again.Results, "alias", aliasNewUUID); item == nil || item.Action != "unchanged" {
		t.Errorf("alias item = %+v, want unchanged", item)
	}

	// The sync that drops the last alias naming it also moves it.
	last := syncAliases(t, device, []APIAliasPayload{webAlias(t, aliasNewUUID, "192.0.2.11")}, nil)
	mustSucceed(t, "the sync without the outer alias", last)
	if device.deviceAlias(aliasOuterUUID) != nil || device.deviceAlias(aliasOldUUID) != nil {
		t.Error("the outer alias or the old object is still on the device")
	}
	if row := device.deviceAlias(aliasNewUUID); row == nil || row["content"] != "192.0.2.11" {
		t.Errorf("alias under the new uuid = %v", row)
	}
	if item := ruleItem(last.Results, "alias", aliasNewUUID); item == nil || item.Action != "created" {
		t.Errorf("alias item = %+v, want created", item)
	}
}

// A rule of the sync that names the alias must not refuse the sync: the old
// object keeps the name, so it is no orphan for the in-use pre-flight.
func TestAliasMove_RuleNamingTheAliasDoesNotBlockTheSync(t *testing.T) {
	device := newFakeRuleDevice(t, ruleTemplate(t), nil)
	device.refuseAliasesInUse = true
	rule := desiredRule(t, "web-in", RulePositionAppend, 100,
		`{"uuid":"`+ruleA+`","action":"pass","interface":"lan","source_net":"nd_web","description":"web in"}`)
	mustSucceed(t, "first sync", syncAliases(t, device, []APIAliasPayload{webAlias(t, aliasOldUUID, "192.0.2.10")}, []APIRulePayload{rule}))

	result := syncAliases(t, device, []APIAliasPayload{webAlias(t, aliasNewUUID, "192.0.2.10")}, []APIRulePayload{rule})

	mustSucceed(t, "the sync with the new uuid", result)
	if len(result.ValidationErrors) != 0 {
		t.Errorf("validation errors = %+v, want none", result.ValidationErrors)
	}
	if device.deviceAlias(aliasOldUUID) == nil {
		t.Error("the old object was removed although a rule names it")
	}
	if warning := ruleItem(result.Results, "alias", aliasOldUUID); warning == nil || warning.Code != codeAliasKeptUnderEarlierUUID {
		t.Errorf("old object item = %+v, want the kept warning", warning)
	}
	device.mu.Lock()
	sourceNet := device.find(ruleA)["source_net"]
	device.mu.Unlock()
	if sourceNet != "nd_web" {
		t.Errorf("rule source = %v, want it still naming nd_web", sourceNet)
	}

	// Once the rule goes, the same sync moves the alias.
	last := syncAliases(t, device, []APIAliasPayload{webAlias(t, aliasNewUUID, "192.0.2.10")}, nil)
	mustSucceed(t, "the sync without the rule", last)
	if device.deviceAlias(aliasOldUUID) != nil || device.deviceAlias(aliasNewUUID) == nil {
		t.Error("the alias did not move once no rule named it")
	}
}

// dropAlias removes the device's alias with this uuid; the caller holds the lock.
func (f *fakeRuleDevice) dropAlias(uuid string) {
	for i, row := range f.aliases {
		if row["uuid"] == uuid {
			f.aliases = append(f.aliases[:i], f.aliases[i+1:]...)
			return
		}
	}
}

// A delete OPNsense did not confirm is checked on the device before the alias
// is reported kept: when the old object is gone all the same, the alias is
// created under its new uuid instead of being missing until the next sync.
func TestAliasMove_AnUnconfirmedDeleteOfAGoneObjectStillCreatesTheAlias(t *testing.T) {
	for name, answer := range map[string]struct {
		status int
		body   interface{}
	}{
		"the answer was lost":         {http.StatusBadGateway, nil},
		"the object was gone already": {http.StatusOK, map[string]string{"result": "not found"}},
	} {
		t.Run(name, func(t *testing.T) {
			device := newFakeRuleDevice(t, ruleTemplate(t), nil)
			mustSucceed(t, "first sync", syncAliases(t, device, []APIAliasPayload{webAlias(t, aliasOldUUID, "192.0.2.10")}, nil))
			device.aliasDelete = func(uuid string) (int, interface{}, bool) {
				device.dropAlias(uuid)
				return answer.status, answer.body, true
			}

			result := syncAliases(t, device, []APIAliasPayload{webAlias(t, aliasNewUUID, "192.0.2.10")}, nil)

			mustSucceed(t, "the sync with the new uuid", result)
			if row := device.deviceAlias(aliasNewUUID); row == nil || row["name"] != "nd_web" || row["content"] != "192.0.2.10" {
				t.Errorf("alias under the new uuid = %v, want it created", row)
			}
			if item := ruleItem(result.Results, "alias", aliasOldUUID); item == nil || item.Action != "deleted" || item.Status != "success" {
				t.Errorf("old object item = %+v, want deleted, never kept", item)
			}
			if item := ruleItem(result.Results, "alias", aliasNewUUID); item == nil || item.Action != "created" || item.Status != "success" {
				t.Errorf("new alias item = %+v, want created", item)
			}
		})
	}
}

func TestAliasMove_AnUnconfirmedDeleteThatCannotBeCheckedFailsTheSync(t *testing.T) {
	device := newFakeRuleDevice(t, ruleTemplate(t), nil)
	mustSucceed(t, "first sync", syncAliases(t, device, []APIAliasPayload{webAlias(t, aliasOldUUID, "192.0.2.10")}, nil))
	device.aliasDelete = func(uuid string) (int, interface{}, bool) {
		device.aliasSearchFail = true
		return http.StatusBadGateway, nil, true
	}

	result := syncAliases(t, device, []APIAliasPayload{webAlias(t, aliasNewUUID, "192.0.2.10")}, nil)

	if result.Success {
		t.Fatal("a move that could not be checked must fail the sync")
	}
	item := ruleItem(result.Results, "alias", aliasNewUUID)
	if item == nil || item.Status != "error" || !strings.Contains(item.Error, "may be missing until the next SYNC") {
		t.Errorf("alias item = %+v, want the unconfirmed move", item)
	}
	for _, r := range result.Results {
		if r.Action == "kept" {
			t.Errorf("item %+v: an unchecked move was reported kept", r)
		}
	}
}

func TestAliasMove_AnUnconfirmedDeleteWithTheNameTakenFailsTheSync(t *testing.T) {
	const otherUUID = "6c0e1a2b-0001-4000-8000-0000000000e1"
	device := newFakeRuleDevice(t, ruleTemplate(t), nil)
	mustSucceed(t, "first sync", syncAliases(t, device, []APIAliasPayload{webAlias(t, aliasOldUUID, "192.0.2.10")}, nil))
	device.aliasDelete = func(uuid string) (int, interface{}, bool) {
		device.dropAlias(uuid)
		device.aliases = append(device.aliases, map[string]interface{}{"uuid": otherUUID, "name": "nd_web", "type": "host", "content": "198.51.100.1"})
		return http.StatusOK, map[string]string{"result": "not found"}, true
	}

	result := syncAliases(t, device, []APIAliasPayload{webAlias(t, aliasNewUUID, "192.0.2.10")}, nil)

	if result.Success {
		t.Fatal("a name another object took must fail the sync")
	}
	if item := ruleItem(result.Results, "alias", aliasNewUUID); item == nil || item.Status != "error" || !strings.Contains(item.Error, "held by uuid "+otherUUID) {
		t.Errorf("alias item = %+v, want the name named as taken", item)
	}
	if device.deviceAlias(aliasNewUUID) != nil {
		t.Error("an alias was created under the new uuid while another object holds the name")
	}
}

func TestFindAliasMoves(t *testing.T) {
	managed := []map[string]interface{}{
		{"uuid": aliasOldUUID, "name": "nd_web"},
		{"uuid": aliasOuterUUID, "name": "nd_db"},
	}
	alias := func(uuid, name string) APIAliasPayload { return APIAliasPayload{UUID: uuid, Name: name} }
	byUUID := func(aliases ...APIAliasPayload) map[string]APIAliasPayload {
		out := map[string]APIAliasPayload{}
		for _, a := range aliases {
			out[a.UUID] = a
		}
		return out
	}

	for name, tc := range map[string]struct {
		desired []APIAliasPayload
		want    map[string]string // desired uuid -> old uuid
	}{
		"a new uuid under a name only an orphan holds moves": {
			desired: []APIAliasPayload{alias(aliasNewUUID, "nd_web"), alias(aliasOuterUUID, "nd_db")},
			want:    map[string]string{aliasNewUUID: aliasOldUUID},
		},
		"an alias the device holds under its uuid is no move": {
			desired: []APIAliasPayload{alias(aliasOldUUID, "nd_web")},
			want:    map[string]string{},
		},
		"two snippets claiming the name are a collision, not a move": {
			desired: []APIAliasPayload{alias(aliasNewUUID, "nd_web"), alias("221f3268-0001-4000-8000-0000000000d1", "nd_web")},
			want:    map[string]string{},
		},
		"a name no orphan holds is no move": {
			desired: []APIAliasPayload{alias(aliasNewUUID, "nd_other")},
			want:    map[string]string{},
		},
		"a name a desired alias still holds is no move": {
			desired: []APIAliasPayload{alias(aliasOldUUID, "nd_renamed"), alias(aliasNewUUID, "nd_db"), alias(aliasOuterUUID, "nd_db")},
			want:    map[string]string{},
		},
		"a uuid the device holds under another name is updated in place, not moved": {
			desired: []APIAliasPayload{alias(aliasOuterUUID, "nd_web")},
			want:    map[string]string{},
		},
	} {
		t.Run(name, func(t *testing.T) {
			moves := findAliasMoves(tc.desired, managed, byUUID(tc.desired...))
			got := map[string]string{}
			for uuid, move := range moves {
				got[uuid] = move.oldUUID
			}
			if len(got) != len(tc.want) {
				t.Fatalf("moves = %v, want %v", got, tc.want)
			}
			for uuid, old := range tc.want {
				if got[uuid] != old {
					t.Errorf("moves = %v, want %v", got, tc.want)
				}
			}
		})
	}
}
