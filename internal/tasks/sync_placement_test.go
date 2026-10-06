package tasks

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// The two default LAN allow rules of a fresh 26.7 box, as captured: MVC rules at
// sequences 1 and 11 of the single-interface section.
const (
	defaultAllow4 = "7179a1de-88f9-428f-a5b7-d4814890be9f"
	defaultAllow6 = "651c4e72-1a2d-494b-b1ed-2a89b26888d6"
)

// freshDevice is e2e-a as captured: OPNsense's automatic and legacy rows, the
// two default LAN rules and one managed floating rule, with the WireGuard
// plugin group.
func freshDevice(t *testing.T) *fakeRuleDevice {
	t.Helper()
	device := newFakeRuleDevice(t, ruleTemplate(t), searchRows26(t))
	device.groups = []opnapi.InterfaceGroup{{Name: "wireguard", Sequence: 10}, {Name: "openvpn", Sequence: 10}, {Name: "enc0", Sequence: 10}}
	return device
}

func itemsOfType(results []SyncAPIItemResult, typ string) []SyncAPIItemResult {
	var out []SyncAPIItemResult
	for _, r := range results {
		if r.Type == typ {
			out = append(out, r)
		}
	}
	return out
}

// TestExecuteSyncAPI_PrependOnFreshDefaults is the reported PREPEND bug: on a
// fresh 26.7 box the default LAN allows sit at 1 and 11, so a LAN PREPEND rule
// written at 100 was evaluated after them. It now takes sequence 1, the first
// default rule moves to 2 by a sequence-only write, and nothing else is
// touched.
func TestExecuteSyncAPI_PrependOnFreshDefaults(t *testing.T) {
	device := freshDevice(t)
	rule := desiredRule(t, "block-telnet", RulePositionPrepend, 100,
		`{"uuid":"`+ruleA+`","action":"block","interface":"lan","protocol":"TCP","destination_port":"23","description":"Block telnet"}`)

	result := executeSyncAPI(context.Background(), device.client, nil, []APIRulePayload{rule})

	if !result.Success {
		t.Fatalf("sync failed: %v", result.Errors)
	}
	if got := device.sequenceOf(ruleA); got != 1 {
		t.Errorf("PREPEND rule sequence = %d, want 1", got)
	}
	if got := device.sequenceOf(defaultAllow4); got != 2 {
		t.Errorf("default allow sequence = %d, want 2", got)
	}
	if got := device.sequenceOf(defaultAllow6); got != 11 {
		t.Errorf("second default rule sequence = %d, want 11 (untouched)", got)
	}

	// The local rule is written first, and with nothing but its sequence.
	if w := device.writesTo(defaultAllow4); !reflect.DeepEqual(w, []string{"set " + defaultAllow4}) {
		t.Errorf("writes to the default rule = %v", w)
	}
	if body := device.lastBody(defaultAllow4); !reflect.DeepEqual(body, map[string]string{"sequence": "2"}) {
		t.Errorf("local write body = %v, want the sequence only", body)
	}
	for i, w := range device.writes {
		if w == "set "+ruleA && i < len(device.writes) && !containsString(device.writes[:i], "set "+defaultAllow4) {
			t.Errorf("the managed rule was written before the local rule moved out of its way: %v", device.writes)
		}
	}
	for _, row := range searchRows26(t) {
		if legacy, _ := row["legacy"].(bool); legacy {
			if w := device.writesTo(row["uuid"].(string)); len(w) > 0 {
				t.Errorf("a legacy or generated row was written: %v", w)
			}
		}
	}

	moved := itemsOfType(result.Results, "rule_local")
	if len(moved) != 1 {
		t.Fatalf("rule_local items = %+v, want one", moved)
	}
	want := SyncAPIItemResult{Type: "rule_local", UUID: defaultAllow4, Name: "Default allow LAN to any rule", Action: "renumbered",
		Status: "success", Code: codeRuleLocalRenumbered, Before: []string{"1"}, After: []string{"2"}}
	if !reflect.DeepEqual(moved[0], want) {
		t.Errorf("renumber item = %+v\nwant %+v", moved[0], want)
	}

	// Converged: the next sync writes nothing.
	sets := device.setCount()
	again := executeSyncAPI(context.Background(), device.client, nil, []APIRulePayload{rule})
	if !again.Success || device.setCount() != sets {
		t.Errorf("second sync: success=%v, %d more write(s): %v", again.Success, device.setCount()-sets, device.writes)
	}
}

// TestExecuteSyncAPI_AppendFollowsANewGUIRule: OPNsense puts a rule added in the
// GUI at the highest sequence + 100, above the APPEND rules; the next sync
// moves the APPEND rule after it and touches no local rule.
func TestExecuteSyncAPI_AppendFollowsANewGUIRule(t *testing.T) {
	device := freshDevice(t)
	rule := desiredRule(t, "deny-rest", RulePositionAppend, 100, `{"uuid":"`+ruleB+`","action":"block","interface":"lan","description":"Deny the rest"}`)

	executeSyncAPI(context.Background(), device.client, nil, []APIRulePayload{rule})
	if got := device.sequenceOf(ruleB); got != 111 {
		t.Fatalf("APPEND rule sequence = %d, want 111, after the default rule at 11", got)
	}

	device.mu.Lock()
	device.rows = append(device.rows, map[string]interface{}{"uuid": "0c0c0c0c-0000-4000-8000-000000000001", "interface": "lan", "sequence": "211", "enabled": "1", "description": "GUI rule"})
	device.mu.Unlock()

	result := executeSyncAPI(context.Background(), device.client, nil, []APIRulePayload{rule})

	if !result.Success {
		t.Fatalf("sync failed: %v", result.Errors)
	}
	if got := device.sequenceOf(ruleB); got != 311 {
		t.Errorf("APPEND rule sequence = %d, want 311, after the GUI rule", got)
	}
	if moved := itemsOfType(result.Results, "rule_local"); len(moved) != 0 {
		t.Errorf("an APPEND rule moved a local rule: %+v", moved)
	}
}

// TestExecuteSyncAPI_LocalRuleThatCannotMove: a local rule OPNsense refuses to
// re-save keeps its sequence; the PREPEND rule goes right after it and the
// task fails naming it.
func TestExecuteSyncAPI_LocalRuleThatCannotMove(t *testing.T) {
	device := freshDevice(t)
	device.answer = func(uuid string, body map[string]string) (int, interface{}, bool) {
		if uuid != defaultAllow4 {
			return 0, nil, false
		}
		return http.StatusOK, map[string]interface{}{
			"result":      "failed",
			"validations": map[string]interface{}{"rule.gateway": "Option [OLD_GW] not in list."},
		}, true
	}
	rule := desiredRule(t, "block-telnet", RulePositionPrepend, 100, `{"uuid":"`+ruleA+`","action":"block","interface":"lan","description":"Block telnet"}`)

	result := executeSyncAPI(context.Background(), device.client, nil, []APIRulePayload{rule})

	if result.Success {
		t.Error("the sync must fail while a local rule could not be moved")
	}
	if got := device.sequenceOf(ruleA); got != 6 {
		t.Errorf("PREPEND rule sequence = %d, want 6: after the stuck rule at 1, before the rule at 11", got)
	}
	failed := itemsOfType(result.Results, "rule_local")
	if len(failed) != 1 || failed[0].Status != "error" || failed[0].Code != codeRuleLocalRenumberFailed ||
		!strings.Contains(failed[0].Error, "gateway: Option [OLD_GW] not in list.") {
		t.Errorf("rule_local items = %+v", failed)
	}
	assertErrorHasMatchingResultItem(t, "stuck local rule", result.Errors, result.Results)
}

// TestExecuteSyncAPI_PlacementWarnings: a single-interface PREPEND rule behind
// an enabled local floating rule that can match its traffic is reported, and
// the task still succeeds.
func TestExecuteSyncAPI_PlacementWarnings(t *testing.T) {
	device := freshDevice(t)
	device.mu.Lock()
	device.rows = append(device.rows, map[string]interface{}{"uuid": "0f0f0f0f-0000-4000-8000-000000000001", "interface": "", "sequence": "300", "enabled": "1", "description": "Floating catch"})
	device.mu.Unlock()
	rule := desiredRule(t, "block-telnet", RulePositionPrepend, 100, `{"uuid":"`+ruleA+`","action":"block","interface":"lan","description":"Block telnet"}`)

	result := executeSyncAPI(context.Background(), device.client, nil, []APIRulePayload{rule})

	if !result.Success {
		t.Fatalf("a warning must not fail the sync: %v", result.Errors)
	}
	warnings := itemsOfType(result.Results, "rule_placement")
	if len(warnings) != 1 || warnings[0].Status != "warning" || warnings[0].Code != codeRulePrependAfterLocal || warnings[0].UUID != ruleA ||
		!strings.Contains(warnings[0].Error, `"Floating catch"`) {
		t.Errorf("warnings = %+v", warnings)
	}
}

// TestExecuteSyncAPI_PlacementInputsUnavailable: without the interface list
// and the group list, managed rules keep their sequences, a new rule goes after
// every rule, nothing local moves, and a warning says why.
func TestExecuteSyncAPI_PlacementInputsUnavailable(t *testing.T) {
	device := freshDevice(t)
	device.interfaceListFail = true
	device.groupSearchFail = true
	rules := []APIRulePayload{
		desiredRule(t, "kept", RulePositionPrepend, 100, `{"uuid":"`+capturedManagedRule+`","action":"pass","interface":"lan,wireguard","source_net":"SOC_Hosts","description":"Test var 40000 sniptest01"}`, "Allow-HTTPS-from-SOC"),
		desiredRule(t, "new", RulePositionPrepend, 200, `{"uuid":"`+ruleA+`","action":"pass","interface":"lan","description":"new"}`),
	}

	result := executeSyncAPI(context.Background(), device.client, nil, rules)

	if !result.Success {
		t.Fatalf("sync failed: %v", result.Errors)
	}
	if got := device.sequenceOf(capturedManagedRule); got != 100 {
		t.Errorf("existing managed rule sequence = %d, want its own 100", got)
	}
	if got := device.sequenceOf(ruleA); got != 200 {
		t.Errorf("new rule sequence = %d, want 200 (the highest sequence + 100)", got)
	}
	if moved := itemsOfType(result.Results, "rule_local"); len(moved) != 0 {
		t.Errorf("a local rule moved: %+v", moved)
	}
	warnings := itemsOfType(result.Results, "rule_placement")
	if len(warnings) != 1 || warnings[0].Code != codeRulePlacementUnavailable || warnings[0].Status != "warning" {
		t.Errorf("warnings = %+v", warnings)
	}
}

// TestExecuteSyncAPI_SectionMismatchIsPlacedAgain: when the device ranks a
// written rule in another section than computed, placement runs once more
// from what the device reports.
func TestExecuteSyncAPI_SectionMismatchIsPlacedAgain(t *testing.T) {
	device := freshDevice(t)
	// The device ranks wireguard at 300020, not at the sequence its group
	// list reports.
	device.rank = func(row map[string]interface{}) int {
		if row["interface"] == "wireguard" {
			return 300020
		}
		value, _ := row["interface"].(string)
		if len(splitInterfaces(value)) == 1 {
			return sectionInterface
		}
		return sectionFloating
	}
	// A local WireGuard rule at 1. Placement first computes 300010, where
	// there is no local rule, and puts the managed rule at 100; the device
	// ranks both at 300020, so the second pass must place it before the
	// local rule.
	const localVPN = "0d0d0d0d-0000-4000-8000-000000000001"
	device.mu.Lock()
	device.rows = append(device.rows, map[string]interface{}{"uuid": localVPN, "interface": "wireguard", "sequence": "1", "enabled": "1", "description": "Local VPN rule"})
	device.mu.Unlock()
	rule := desiredRule(t, "vpn", RulePositionPrepend, 100, `{"uuid":"`+ruleA+`","action":"pass","interface":"wireguard","description":"VPN to LAN"}`)

	result := executeSyncAPI(context.Background(), device.client, nil, []APIRulePayload{rule})

	if !result.Success {
		t.Fatalf("sync failed: %v", result.Errors)
	}
	if got, local := device.sequenceOf(ruleA), device.sequenceOf(localVPN); got != 1 || local != 2 {
		t.Errorf("managed rule at %d, local rule at %d; want 1 and 2", got, local)
	}
	if item := ruleItem(result.Results, "rule", ruleA); item == nil || item.Action != "created" || item.Status != "success" {
		t.Errorf("rule item = %+v, want the first pass's created item", item)
	}
}

// TestExecuteSyncAPI_SectionNeverSettlesIsAnError: a device that keeps ranking
// the rule somewhere else fails the task once placement has run twice.
func TestExecuteSyncAPI_SectionNeverSettlesIsAnError(t *testing.T) {
	device := freshDevice(t)
	device.rank = func(row map[string]interface{}) int {
		if row["uuid"] == ruleA {
			return 300000 + device.searches
		}
		return sectionInterface
	}
	rule := desiredRule(t, "vpn", RulePositionPrepend, 100, `{"uuid":"`+ruleA+`","action":"pass","interface":"wireguard","description":"VPN to LAN"}`)

	result := executeSyncAPI(context.Background(), device.client, nil, []APIRulePayload{rule})

	if result.Success {
		t.Error("the sync must fail when the rule's section is not verified")
	}
	unverified := itemsOfType(result.Results, "rule_placement")
	if len(unverified) != 1 || unverified[0].Code != codeRulePlacementUnverified || unverified[0].Status != "error" {
		t.Errorf("items = %+v", unverified)
	}
	assertErrorHasMatchingResultItem(t, "unverified", result.Errors, result.Results)
}

// TestExecuteSyncAPI_NoSequenceRoom: an APPEND rule that no sequence is left
// for is refused, not written, and fails the task.
func TestExecuteSyncAPI_NoSequenceRoom(t *testing.T) {
	device := freshDevice(t)
	device.mu.Lock()
	device.rows = append(device.rows, map[string]interface{}{"uuid": "0e0e0e0e-0000-4000-8000-000000000001", "interface": "lan", "sequence": strconv.Itoa(maxRuleSequence), "enabled": "1", "description": "Last"})
	device.mu.Unlock()
	rule := desiredRule(t, "deny-rest", RulePositionAppend, 100, `{"uuid":"`+ruleB+`","action":"pass","interface":"lan","description":"Deny the rest"}`)

	result := executeSyncAPI(context.Background(), device.client, nil, []APIRulePayload{rule})

	if result.Success {
		t.Error("the sync must fail")
	}
	if w := device.writesTo(ruleB); len(w) != 0 {
		t.Errorf("the rule was written: %v", w)
	}
	item := ruleItem(result.Results, "rule", ruleB)
	if item == nil || item.Status != "blocked" || item.Code != codeRuleNoSequenceRoom {
		t.Errorf("item = %+v", item)
	}
	assertErrorHasMatchingResultItem(t, "no room", result.Errors, result.Results)
}

// lanLocal is a local MVC rule on lan at this sequence.
func lanLocal(uuid string, seq int, description string) map[string]interface{} {
	return map[string]interface{}{"uuid": uuid, "interface": "lan", "sequence": strconv.Itoa(seq), "enabled": "1", "description": description, "action": "pass"}
}

// deleteRow deletes a live row, as the device owner would; the caller holds
// the lock.
func (f *fakeRuleDevice) deleteRow(uuid string) {
	for i, row := range f.rows {
		if row["uuid"] == uuid {
			f.rows = append(f.rows[:i], f.rows[i+1:]...)
			return
		}
	}
}

func prependRules(t *testing.T, n int) []APIRulePayload {
	t.Helper()
	var rules []APIRulePayload
	for i := 1; i <= n; i++ {
		uuid := fmt.Sprintf("221f3268-0000-4000-8000-0000000000%02d", i)
		rules = append(rules, desiredRule(t, fmt.Sprintf("p%d", i), RulePositionPrepend, i*10,
			fmt.Sprintf(`{"uuid":"%s","action":"block","interface":"lan","description":"managed %d"}`, uuid, i)))
	}
	return rules
}

func writeIndex(writes []string, want string) int {
	for i, w := range writes {
		if w == want {
			return i
		}
	}
	return -1
}

const (
	blockX   = "0b0b0b0b-0000-4000-8000-0000000000b1"
	allowAll = "0b0b0b0b-0000-4000-8000-0000000000b2"
)

// TestExecuteSyncAPI_LocalRulesMoveHighestFirst: local rules are renumbered
// from the highest sequence down, so no write ever puts a local rule ahead of
// one that has not moved yet.
func TestExecuteSyncAPI_LocalRulesMoveHighestFirst(t *testing.T) {
	device := newFakeRuleDevice(t, ruleTemplate(t), []map[string]interface{}{lanLocal(blockX, 1, "Block X"), lanLocal(allowAll, 2, "Allow all")})

	result := executeSyncAPI(context.Background(), device.client, nil, prependRules(t, 3))

	if !result.Success {
		t.Fatalf("sync failed: %v", result.Errors)
	}
	if i, j := writeIndex(device.writes, "set "+allowAll), writeIndex(device.writes, "set "+blockX); i < 0 || j < 0 || i > j {
		t.Errorf("writes = %v, want Allow all moved before Block X", device.writes)
	}
	if bx, aa := device.sequenceOf(blockX), device.sequenceOf(allowAll); bx != 4 || aa != 5 {
		t.Errorf("Block X at %d, Allow all at %d; want 4 and 5", bx, aa)
	}
}

// TestExecuteSyncAPI_LocalMoveFailingPartWayKeepsTheOrder: when the device
// refuses to move the higher of two local rules that must move, the lower one
// is never written, so the two keep their order, and the PREPEND rules go after
// both.
func TestExecuteSyncAPI_LocalMoveFailingPartWayKeepsTheOrder(t *testing.T) {
	device := newFakeRuleDevice(t, ruleTemplate(t), []map[string]interface{}{lanLocal(blockX, 1, "Block X"), lanLocal(allowAll, 2, "Allow all")})
	device.answer = func(uuid string, body map[string]string) (int, interface{}, bool) {
		if uuid != allowAll {
			return 0, nil, false
		}
		return http.StatusOK, map[string]interface{}{"result": "failed", "validations": map[string]interface{}{"rule.gateway": "Option [OLD_GW] not in list."}}, true
	}

	result := executeSyncAPI(context.Background(), device.client, nil, prependRules(t, 3))

	if result.Success {
		t.Error("the sync must fail while a local rule could not be moved")
	}
	if w := device.writesTo(blockX); len(w) != 0 {
		t.Errorf("Block X was written: %v", w)
	}
	if bx, aa := device.sequenceOf(blockX), device.sequenceOf(allowAll); bx != 1 || aa != 2 {
		t.Errorf("Block X at %d, Allow all at %d; want them where they were, 1 and 2", bx, aa)
	}
	for i, want := range []int{102, 202, 302} {
		if got := device.sequenceOf(fmt.Sprintf("221f3268-0000-4000-8000-0000000000%02d", i+1)); got != want {
			t.Errorf("PREPEND rule %d at %d, want %d", i+1, got, want)
		}
	}
	assertErrorHasMatchingResultItem(t, "stuck local rule", result.Errors, result.Results)
}

// The sentences a withheld firewall apply gives per local rule, spelled out.
const (
	withheldRecreated  = `Local rule %q was deleted on the device during its renumber, which re-created it with OPNsense's defaults, a pass rule on every interface, and it could not be deleted or disabled.`
	withheldUnreadable = `Local rule %q may be a rule its renumber re-created after it was deleted on the device, which could not be ruled out: it could not be read back after the move.`
	withheldMixed      = `Local rule %q may be a rule its renumber re-created after it was deleted on the device, which could not be ruled out: it changed during the move, and some of its values are back at OPNsense's defaults.`
)

// withheldApply is the message of a withheld firewall apply.
func withheldApply(sentence, rule string) string {
	return "Firewall rules were not applied this SYNC. " + fmt.Sprintf(sentence, rule) + " Check the device, then SYNC again"
}

// TestExecuteSyncAPI_LocalMoveIsReadBeforeAndAfter: setRule creates a rule it
// does not find, with OPNsense's defaults (a pass rule on every interface), so
// a local renumber reads the rule before writing its sequence and again after.
// A rule deleted before the write is not written. One the write re-created is
// deleted again, else disabled, else the firewall rules are not applied; so
// are they when the rule cannot be read back. Any other change is reported
// and left alone; one that put some of the rule's values back at their
// defaults, as an owner's edit to a default value does, also withholds the
// apply, since a re-created rule the owner edited since looks the same.
func TestExecuteSyncAPI_LocalMoveIsReadBeforeAndAfter(t *testing.T) {
	const gone, disabled = "gone", "disabled"
	deleteOnSet := func(f *fakeRuleDevice, call, uuid string) bool {
		if call == "set" {
			f.deleteRow(uuid)
		}
		return true
	}
	editOnSet := func(field, value string) func(f *fakeRuleDevice, call, uuid string) bool {
		return func(f *fakeRuleDevice, call, uuid string) bool {
			if call == "set" {
				f.find(uuid)[field] = value
			}
			return true
		}
	}
	cases := []struct {
		name    string
		setup   map[string]interface{} // the local rule's fields before the SYNC
		before  func(f *fakeRuleDevice, call, uuid string) bool
		code    string
		status  string
		message string // in the item's error
		exact   bool   // the message is the item's whole error
		writes  []string
		row     string // the local rule's sequence afterwards, gone or disabled
		prepend int
		success bool
		applied bool
		// withheld is the sentence the withheld apply gives for the rule.
		withheld string
	}{
		{
			name: "deleted before the move",
			before: func(f *fakeRuleDevice, call, uuid string) bool {
				if call == "get" && f.calls["get "+uuid] == 1 {
					f.deleteRow(uuid)
				}
				return true
			},
			code: codeRuleLocalVanished, status: "warning", row: gone, prepend: 5, success: true, applied: true,
		},
		{
			name:   "unreadable before the move",
			before: func(f *fakeRuleDevice, call, uuid string) bool { return !(call == "get" && f.calls["get "+uuid] == 1) },
			code:   codeRuleLocalRenumberFailed, status: "error", row: "1", prepend: 6, applied: true,
		},
		{
			name:   "deleted during the move, which re-created it",
			before: deleteOnSet,
			code:   codeRuleLocalRenumberUnverified, status: "error", message: "NetDefense deleted it again",
			writes: []string{"set", "del"}, row: gone, prepend: 5, applied: true,
		},
		{
			name: "re-created, and deleted on the second try",
			before: func(f *fakeRuleDevice, call, uuid string) bool {
				return deleteOnSet(f, call, uuid) && !(call == "del" && f.calls["del "+uuid] == 1)
			},
			code: codeRuleLocalRenumberUnverified, status: "error", message: "NetDefense deleted it again",
			writes: []string{"set", "del", "del"}, row: gone, prepend: 5, applied: true,
		},
		{
			name: "re-created, not deletable, so disabled",
			before: func(f *fakeRuleDevice, call, uuid string) bool {
				return deleteOnSet(f, call, uuid) && call != "del"
			},
			code: codeRuleLocalRenumberUnverified, status: "error", message: "NetDefense disabled it",
			writes: []string{"set", "del", "del", "toggle"}, row: disabled, prepend: 5, applied: true,
		},
		{
			name: "re-created, neither deletable nor disableable",
			before: func(f *fakeRuleDevice, call, uuid string) bool {
				return deleteOnSet(f, call, uuid) && call != "del" && call != "toggle"
			},
			code: codeRuleLocalRenumberUnverified, status: "error", message: "the firewall rules are not applied this SYNC",
			writes: []string{"set", "del", "del", "toggle"}, row: "2", prepend: 5,
			withheld: withheldRecreated,
		},
		{
			name: "re-created, and edited before the read-back",
			before: func(f *fakeRuleDevice, call, uuid string) bool {
				if call == "get" && f.calls["get "+uuid] == 2 {
					f.find(uuid)["description"] = "edited on the device"
				}
				return deleteOnSet(f, call, uuid)
			},
			code: codeRuleLocalRenumberUnverified, status: "error", message: "NetDefense deleted it again",
			writes: []string{"set", "del"}, row: gone, prepend: 5, applied: true,
		},
		{
			name: "edited during the move",
			before: func(f *fakeRuleDevice, call, uuid string) bool {
				if call == "get" && f.calls["get "+uuid] == 2 {
					f.find(uuid)["description"] = "edited on the device"
				}
				return true
			},
			code: codeRuleLocalRenumberUnverified, status: "error",
			message: `Local rule "Default allow LAN to any rule" changed on the device while NetDefense moved it from sequence 1 to 2; it was left as it is, so check it`,
			exact:   true,
			writes:  []string{"set"}, row: "2", prepend: 1, applied: true,
		},
		{
			name:   "the owner clears the description during the move",
			before: editOnSet("description", ""),
			code:   codeRuleLocalRenumberUnverified, status: "error", message: `Local rule "Default allow LAN to any rule" changed on the device while NetDefense moved it from sequence 1 to 2, and some of its values are back at OPNsense's defaults: ` +
				`it may be a rule the move re-created after it was deleted, edited since. It was left as it is, and the firewall rules are not applied this SYNC: check it on the device`,
			exact:  true,
			writes: []string{"set"}, row: "2", prepend: 1,
			withheld: withheldMixed,
		},
		{
			name:   "the owner turns the action to pass during the move",
			setup:  map[string]interface{}{"action": "block"},
			before: editOnSet("action", "pass"),
			code:   codeRuleLocalRenumberUnverified, status: "error", message: `Local rule "Default allow LAN to any rule" changed on the device while NetDefense moved it from sequence 1 to 2, and some of its values are back at OPNsense's defaults: ` +
				`it may be a rule the move re-created after it was deleted, edited since. It was left as it is, and the firewall rules are not applied this SYNC: check it on the device`,
			exact:  true,
			writes: []string{"set"}, row: "2", prepend: 1,
			withheld: withheldMixed,
		},
		{
			name:   "the owner enables the rule during the move",
			setup:  map[string]interface{}{"enabled": "0"},
			before: editOnSet("enabled", "1"),
			code:   codeRuleLocalRenumberUnverified, status: "error", message: `Local rule "Default allow LAN to any rule" changed on the device while NetDefense moved it from sequence 1 to 2, and some of its values are back at OPNsense's defaults: ` +
				`it may be a rule the move re-created after it was deleted, edited since. It was left as it is, and the firewall rules are not applied this SYNC: check it on the device`,
			exact:  true,
			writes: []string{"set"}, row: "2", prepend: 1,
			withheld: withheldMixed,
		},
		{
			name: "re-created, and given one of its own values back before the read-back",
			before: func(f *fakeRuleDevice, call, uuid string) bool {
				if call == "get" && f.calls["get "+uuid] == 2 {
					f.find(uuid)["interface"] = "lan"
				}
				return deleteOnSet(f, call, uuid)
			},
			code: codeRuleLocalRenumberUnverified, status: "error", message: `Local rule "Default allow LAN to any rule" changed on the device while NetDefense moved it from sequence 1 to 2, and some of its values are back at OPNsense's defaults: ` +
				`it may be a rule the move re-created after it was deleted, edited since. It was left as it is, and the firewall rules are not applied this SYNC: check it on the device`,
			exact:  true,
			writes: []string{"set"}, row: "2", prepend: 1,
			withheld: withheldMixed,
		},
		{
			name:   "unreadable once after the move",
			before: func(f *fakeRuleDevice, call, uuid string) bool { return !(call == "get" && f.calls["get "+uuid] == 2) },
			code:   codeRuleLocalRenumbered, status: "success",
			writes: []string{"set"}, row: "2", prepend: 1, success: true, applied: true,
		},
		{
			name: "unreadable after the move",
			before: func(f *fakeRuleDevice, call, uuid string) bool {
				return !(call == "get" && f.calls["get "+uuid] >= 2)
			},
			code: codeRuleLocalRenumberUnverified, status: "error",
			message: `Local rule "Default allow LAN to any rule" was moved from sequence 1 to 2, but could not be read back: ` + fakeError + `. Had it been deleted on the device meanwhile, the move re-created it as a pass rule, so the firewall rules are not applied this SYNC: check the rule on the device`,
			exact:   true,
			writes:  []string{"set"}, row: "2", prepend: 1,
			withheld: withheldUnreadable,
		},
		{
			name: "deleted right after the move",
			before: func(f *fakeRuleDevice, call, uuid string) bool {
				if call == "get" && f.calls["get "+uuid] == 2 {
					f.deleteRow(uuid)
				}
				return true
			},
			code: codeRuleLocalVanished, status: "warning",
			message: `Local rule "Default allow LAN to any rule" was deleted on the device during this SYNC, right after NetDefense moved it`,
			exact:   true,
			writes:  []string{"set"}, row: gone, prepend: 5, success: true, applied: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			device := freshDevice(t)
			for field, value := range tc.setup {
				device.edit(defaultAllow4, func(row map[string]interface{}) { row[field] = value })
			}
			device.before = func(call, uuid string) bool {
				if uuid != defaultAllow4 {
					return true
				}
				return tc.before(device, call, uuid)
			}
			rule := desiredRule(t, "block-telnet", RulePositionPrepend, 100, `{"uuid":"`+ruleA+`","action":"block","interface":"lan","description":"Block telnet"}`)

			result := executeSyncAPI(context.Background(), device.client, nil, []APIRulePayload{rule})

			if result.Success != tc.success {
				t.Errorf("success = %v, want %v: %v", result.Success, tc.success, result.Errors)
			}
			var writes []string
			for _, w := range device.writesTo(defaultAllow4) {
				writes = append(writes, strings.Fields(w)[0])
			}
			if !reflect.DeepEqual(writes, tc.writes) {
				t.Errorf("writes to the local rule = %v, want %v", writes, tc.writes)
			}
			switch row := device.row(defaultAllow4); tc.row {
			case gone:
				if row != nil {
					t.Errorf("the local rule is still there: %v", row)
				}
			case disabled:
				if row == nil || row["enabled"] != "0" {
					t.Errorf("the re-created rule = %v, want it disabled", row)
				}
			default:
				if row == nil || row["sequence"] != tc.row {
					t.Errorf("the local rule = %v, want it at sequence %s", row, tc.row)
				}
			}
			if got := device.sequenceOf(ruleA); got != tc.prepend {
				t.Errorf("PREPEND rule at %d, want %d", got, tc.prepend)
			}
			var found bool
			for _, item := range itemsOfType(result.Results, "rule_local") {
				if item.UUID == defaultAllow4 && item.Code == tc.code && item.Status == tc.status && (item.Error == tc.message || !tc.exact && strings.Contains(item.Error, tc.message)) {
					found = true
				}
			}
			if !found {
				t.Errorf("no %s item with status %s saying %q: %+v", tc.code, tc.status, tc.message, itemsOfType(result.Results, "rule_local"))
			}
			applied := writeIndex(device.writes, "apply") >= 0
			if applied != tc.applied {
				t.Errorf("applied = %v, want %v: %v", applied, tc.applied, device.writes)
			}
			if i, j := writeIndex(device.writes, "del "+defaultAllow4), writeIndex(device.writes, "apply"); applied && i > j {
				t.Errorf("the re-created rule was deleted after the apply: %v", device.writes)
			}
			if withheld := itemsOfType(result.Results, "rule_apply"); !tc.applied {
				want := withheldApply(tc.withheld, "Default allow LAN to any rule")
				if len(withheld) != 1 || withheld[0].Code != codeRuleApplyWithheld || withheld[0].Action != "skipped" || withheld[0].Error != want {
					t.Errorf("rule_apply items = %+v\nwant one %s: %s", withheld, codeRuleApplyWithheld, want)
				}
			}
			if !tc.success {
				assertErrorHasMatchingResultItem(t, tc.name, result.Errors, result.Results)
			}
		})
	}
}

// TestExecuteSyncAPI_LocalRuleOfDefaultsIsNotMoved: a local rule holding
// nothing but OPNsense's defaults is what a renumber would re-create had the
// rule been deleted meanwhile, so the read after the write could not tell the
// two apart: it is not moved, and the PREPEND rules go after it.
func TestExecuteSyncAPI_LocalRuleOfDefaultsIsNotMoved(t *testing.T) {
	const passAll = "0c0c0c0c-0000-4000-8000-0000000000d1"
	row := map[string]interface{}{"uuid": passAll}
	for name, value := range ruleModel26(t).Values() {
		row[name] = value
	}
	row["sequence"] = "1"
	device := newFakeRuleDevice(t, ruleTemplate(t), []map[string]interface{}{row})
	rule := desiredRule(t, "floating", RulePositionPrepend, 100, `{"uuid":"`+ruleA+`","action":"block","interface":"","description":"Block telnet"}`)

	result := executeSyncAPI(context.Background(), device.client, nil, []APIRulePayload{rule})

	if result.Success {
		t.Error("the sync must fail: the PREPEND rule is placed after a local rule")
	}
	if w := device.writesTo(passAll); len(w) != 0 {
		t.Errorf("the local rule was written: %v", w)
	}
	if got := device.sequenceOf(ruleA); got != 101 {
		t.Errorf("PREPEND rule at %d, want 101, after the local rule at 1", got)
	}
	failed := itemsOfType(result.Results, "rule_local")
	want := `Local rule "0c0c0c0c-0000-4000-8000-0000000000d1" could not be moved from sequence 1 to 2, so the PREPEND rules of its section are placed after it: ` +
		`it reads as nothing but OPNsense's defaults (it may name a gateway or schedule that no longer exists), so a rule the move re-created could not be told from it: ` +
		`give it a description, or fix what it names`
	if len(failed) != 1 || failed[0].Code != codeRuleLocalRenumberFailed || failed[0].Error != want {
		t.Errorf("rule_local items = %+v\nwant: %s", failed, want)
	}
	assertErrorHasMatchingResultItem(t, "defaults", result.Errors, result.Results)
}

// mismatchDevice ranks the wireguard group at 300020 while its group list
// says sequence 10, and holds a local WireGuard rule at 1.
func mismatchDevice(t *testing.T) (*fakeRuleDevice, string) {
	t.Helper()
	device := freshDevice(t)
	device.rank = func(row map[string]interface{}) int {
		if row["interface"] == "wireguard" {
			return 300020
		}
		value, _ := row["interface"].(string)
		if len(splitInterfaces(value)) == 1 {
			return sectionInterface
		}
		return sectionFloating
	}
	const localVPN = "0d0d0d0d-0000-4000-8000-000000000001"
	device.rows = append(device.rows, map[string]interface{}{"uuid": localVPN, "interface": "wireguard", "sequence": "1", "enabled": "1", "description": "Local VPN rule"})
	return device, localVPN
}

// TestExecuteSyncAPI_StaticSectionMismatchConverges: a device that ranks a
// group's rules in another section than its group list says is placed by its
// own ranking from the second SYNC on, so a converged SYNC writes nothing;
// every SYNC says the ranking disagrees.
func TestExecuteSyncAPI_StaticSectionMismatchConverges(t *testing.T) {
	device, localVPN := mismatchDevice(t)
	rule := desiredRule(t, "vpn", RulePositionPrepend, 100, `{"uuid":"`+ruleA+`","action":"pass","interface":"wireguard","description":"VPN to LAN"}`)

	for i := 1; i <= 3; i++ {
		sets := device.setCount()
		result := executeSyncAPI(context.Background(), device.client, nil, []APIRulePayload{rule})

		if !result.Success {
			t.Fatalf("SYNC %d failed: %v", i, result.Errors)
		}
		if got, local := device.sequenceOf(ruleA), device.sequenceOf(localVPN); got != 1 || local != 2 {
			t.Errorf("SYNC %d: managed rule at %d, local rule at %d; want 1 and 2", i, got, local)
		}
		if i > 1 && device.setCount() != sets {
			t.Errorf("SYNC %d wrote %d rule(s); a converged device needs none", i, device.setCount()-sets)
		}
		warnings := itemsOfType(result.Results, "rule_placement")
		if len(warnings) != 1 || warnings[0].Code != codeRuleSectionMismatch || warnings[0].Status != "warning" || warnings[0].UUID != ruleA ||
			!strings.Contains(warnings[0].Error, "group sequence 20") || !strings.Contains(warnings[0].Error, "group sequence 10") {
			t.Errorf("SYNC %d: placement items = %+v, want one %s", i, warnings, codeRuleSectionMismatch)
		}
	}
}

// TestExecuteSyncAPI_SecondPassLeavesAFailedRuleAlone: a rule the device
// refused in the first pass is not sent again by the second, and is reported
// once.
func TestExecuteSyncAPI_SecondPassLeavesAFailedRuleAlone(t *testing.T) {
	device, _ := mismatchDevice(t)
	device.answer = func(uuid string, body map[string]string) (int, interface{}, bool) {
		if uuid != ruleB {
			return 0, nil, false
		}
		return http.StatusOK, map[string]interface{}{"result": "failed", "validations": map[string]interface{}{"rule.gateway": "Option [X] not in list."}}, true
	}
	rules := []APIRulePayload{
		desiredRule(t, "vpn", RulePositionPrepend, 100, `{"uuid":"`+ruleA+`","action":"pass","interface":"wireguard","description":"VPN to LAN"}`),
		desiredRule(t, "bad", RulePositionPrepend, 200, `{"uuid":"`+ruleB+`","action":"pass","interface":"lan","description":"Refused by the device"}`),
	}

	result := executeSyncAPI(context.Background(), device.client, nil, rules)

	if w := device.writesTo(ruleB); len(w) != 1 {
		t.Errorf("writes to the refused rule = %v, want one", w)
	}
	var items, errs int
	for _, item := range result.Results {
		if item.UUID == ruleB {
			items++
		}
	}
	for _, e := range result.Errors {
		if strings.Contains(e, "Refused by the device") {
			errs++
		}
	}
	if items != 1 || errs != 1 {
		t.Errorf("items = %d, errors = %d for the refused rule; want one of each: %v", items, errs, result.Errors)
	}
	assertErrorHasMatchingResultItem(t, "refused in the first pass", result.Errors, result.Results)
}

// TestExecuteSyncAPI_FixedLocalIsNotRetriedInTheSecondPass: a local rule the
// device refused to move in the first pass is not asked again by the second.
func TestExecuteSyncAPI_FixedLocalIsNotRetriedInTheSecondPass(t *testing.T) {
	device, _ := mismatchDevice(t)
	device.answer = func(uuid string, body map[string]string) (int, interface{}, bool) {
		if uuid != defaultAllow4 {
			return 0, nil, false
		}
		return http.StatusOK, map[string]interface{}{"result": "failed", "validations": map[string]interface{}{"rule.gateway": "Option [OLD_GW] not in list."}}, true
	}
	rules := []APIRulePayload{
		desiredRule(t, "lan", RulePositionPrepend, 100, `{"uuid":"`+ruleA+`","action":"block","interface":"lan","description":"Block telnet"}`),
		desiredRule(t, "vpn", RulePositionPrepend, 200, `{"uuid":"`+ruleB+`","action":"pass","interface":"wireguard","description":"VPN to LAN"}`),
	}

	result := executeSyncAPI(context.Background(), device.client, nil, rules)

	if w := device.writesTo(defaultAllow4); len(w) != 1 {
		t.Errorf("writes to the local rule = %v, want the one refused attempt", w)
	}
	var failed []SyncAPIItemResult
	for _, item := range itemsOfType(result.Results, "rule_local") {
		if item.UUID == defaultAllow4 {
			failed = append(failed, item)
		}
	}
	if len(failed) != 1 || failed[0].Code != codeRuleLocalRenumberFailed {
		t.Errorf("items for the local rule = %+v, want one %s", failed, codeRuleLocalRenumberFailed)
	}
	if got := device.sequenceOf(ruleA); got != 6 {
		t.Errorf("lan PREPEND rule at %d, want 6, after the local rule that cannot move", got)
	}
}

// TestExecuteSyncAPI_RefusedRuleKeepsItsPlace: a managed rule the pre-flight
// refused is not written, and placement holds it where it is: no local rule
// is moved onto its sequence, and the PREPEND rules go after it when they
// cannot get ahead of it.
func TestExecuteSyncAPI_RefusedRuleKeepsItsPlace(t *testing.T) {
	device := freshDevice(t)
	device.rows = append(device.rows, map[string]interface{}{"uuid": ruleC, "interface": "lan", "sequence": "2", "enabled": "1", "action": "pass", "description": "Refused"})
	installedReleaseName = func(context.Context, *opnapi.Client) string { return "26.7" }
	t.Cleanup(func() { installedReleaseName = defaultInstalledReleaseName })
	rules := []APIRulePayload{
		desiredRule(t, "typo", RulePositionPrepend, 50, `{"uuid":"`+ruleC+`","action":"pass","interface":"lan","lgo":"1","description":"Refused"}`),
		desiredRule(t, "block-telnet", RulePositionPrepend, 100, `{"uuid":"`+ruleA+`","action":"block","interface":"lan","description":"Block telnet"}`),
	}

	result := executeSyncAPI(context.Background(), device.client, nil, rules)

	if result.Success {
		t.Error("the sync must fail while a rule is refused")
	}
	if w := device.writesTo(ruleC); len(w) != 0 {
		t.Errorf("the refused rule was written: %v", w)
	}
	if w := device.writesTo(defaultAllow4); len(w) != 0 {
		t.Errorf("the local rule was moved onto the refused rule's sequence: %v", w)
	}
	if got := device.sequenceOf(ruleA); got != 6 {
		t.Errorf("PREPEND rule at %d, want 6: after the refused rule at 2, before the local rule at 11", got)
	}
	for _, w := range itemsOfType(result.Results, "rule_placement") {
		if strings.Contains(w.Error, "Refused") {
			t.Errorf("the refused rule is reported as a local rule: %+v", w)
		}
	}
}

// TestExecuteSyncAPI_PlacementInputsEachUnavailable: either placement input
// failing alone keeps the managed rules' sequences and says why.
func TestExecuteSyncAPI_PlacementInputsEachUnavailable(t *testing.T) {
	for _, input := range []string{"interface list", "group search"} {
		t.Run(input, func(t *testing.T) {
			device := freshDevice(t)
			device.interfaceListFail = input == "interface list"
			device.groupSearchFail = input == "group search"
			rule := desiredRule(t, "block-telnet", RulePositionPrepend, 100, `{"uuid":"`+ruleA+`","action":"block","interface":"lan","description":"Block telnet"}`)

			result := executeSyncAPI(context.Background(), device.client, nil, []APIRulePayload{rule})

			if !result.Success {
				t.Fatalf("sync failed: %v", result.Errors)
			}
			if moved := itemsOfType(result.Results, "rule_local"); len(moved) != 0 {
				t.Errorf("a local rule moved: %+v", moved)
			}
			warnings := itemsOfType(result.Results, "rule_placement")
			if len(warnings) != 1 || warnings[0].Code != codeRulePlacementUnavailable || !strings.Contains(warnings[0].Error, "404") {
				t.Errorf("warnings = %+v", warnings)
			}
		})
	}
}

// TestExecuteSyncAPI_ConfiguredLegacyRuleIsNeverWritten: a legacy rule the
// owner configured comes after every MVC rule of its section, so an APPEND
// rule there is evaluated before it, which is reported; the legacy rule, shown
// by its interface's name, is never written.
func TestExecuteSyncAPI_ConfiguredLegacyRuleIsNeverWritten(t *testing.T) {
	device := freshDevice(t)
	const legacyRule = "1e1e1e1e-0000-4000-8000-000000000001"
	device.rows = append(device.rows, map[string]interface{}{"uuid": legacyRule, "legacy": true, "seq": float64(5), "interface": "LAN",
		"sort_order": "400000.1000040", "description": "Legacy LAN allow"})
	rule := desiredRule(t, "deny-rest", RulePositionAppend, 100, `{"uuid":"`+ruleB+`","action":"block","interface":"lan","description":"Deny the rest"}`)

	result := executeSyncAPI(context.Background(), device.client, nil, []APIRulePayload{rule})

	if !result.Success {
		t.Fatalf("sync failed: %v", result.Errors)
	}
	if w := device.writesTo(legacyRule); len(w) != 0 {
		t.Errorf("the legacy rule was written: %v", w)
	}
	warnings := itemsOfType(result.Results, "rule_placement")
	if len(warnings) != 1 || warnings[0].Code != codeRuleAppendBeforeLocal || warnings[0].Error != `Rule "Deny the rest" (snippet "deny-rest") is APPEND, but OPNsense evaluates it before the local rule "Legacy LAN allow": legacy rules come after every rule of their section; migrate them under Firewall > Migration assistant` {
		t.Errorf("warnings = %+v", warnings)
	}
}

// TestExecuteSyncAPI_DisabledLocalRuleNeverWarns: a disabled local floating
// rule keeps its place but is not reported ahead of a lan PREPEND rule.
func TestExecuteSyncAPI_DisabledLocalRuleNeverWarns(t *testing.T) {
	device := freshDevice(t)
	device.rows = append(device.rows, map[string]interface{}{"uuid": "0f0f0f0f-0000-4000-8000-000000000001", "interface": "", "sequence": "300", "enabled": "0", "description": "Floating catch"})
	rule := desiredRule(t, "block-telnet", RulePositionPrepend, 100, `{"uuid":"`+ruleA+`","action":"block","interface":"lan","description":"Block telnet"}`)

	result := executeSyncAPI(context.Background(), device.client, nil, []APIRulePayload{rule})

	if !result.Success {
		t.Fatalf("sync failed: %v", result.Errors)
	}
	if warnings := itemsOfType(result.Results, "rule_placement"); len(warnings) != 0 {
		t.Errorf("warnings = %+v, want none for a disabled local rule", warnings)
	}
}

// TestExecuteSyncAPI_RuleChangingSection: a managed rule whose interfaces move
// it to another section is placed in the new one.
func TestExecuteSyncAPI_RuleChangingSection(t *testing.T) {
	device := freshDevice(t)
	rule := desiredRule(t, "block-telnet", RulePositionPrepend, 100, `{"uuid":"`+ruleA+`","action":"block","interface":"lan","description":"Block telnet"}`)
	executeSyncAPI(context.Background(), device.client, nil, []APIRulePayload{rule})
	if got := device.sequenceOf(ruleA); got != 1 {
		t.Fatalf("lan PREPEND rule at %d, want 1", got)
	}

	moved := desiredRule(t, "block-telnet", RulePositionPrepend, 100, `{"uuid":"`+ruleA+`","action":"block","interface":"lan,wan","description":"Block telnet"}`)
	result := executeSyncAPI(context.Background(), device.client, nil, []APIRulePayload{moved})

	if !result.Success {
		t.Fatalf("sync failed: %v", result.Errors)
	}
	if got := device.sequenceOf(ruleA); got != 100 {
		t.Errorf("floating PREPEND rule at %d, want 100, the first of a section without local rules", got)
	}
	if item := ruleItem(result.Results, "rule", ruleA); item == nil || item.Action != "updated" {
		t.Errorf("rule item = %+v", item)
	}
	if moves := itemsOfType(result.Results, "rule_local"); len(moves) != 0 {
		t.Errorf("a local rule moved: %+v", moves)
	}
}

// TestExecuteSyncAPI_RulesBeyondTheFirstPage: the ruleset is read page by
// page, and the local rules that decide placement may be on a later page.
func TestExecuteSyncAPI_RulesBeyondTheFirstPage(t *testing.T) {
	var rows []map[string]interface{}
	for i := 1; i <= 45; i++ {
		rows = append(rows, map[string]interface{}{"uuid": fmt.Sprintf("0a0a0a0a-0000-4000-8000-%012d", i), "interface": "wan", "sequence": strconv.Itoa(100 * i), "enabled": "1", "description": fmt.Sprintf("wan %d", i)})
	}
	device := newFakeRuleDevice(t, ruleTemplate(t), append(rows, searchRows26(t)...))
	rule := desiredRule(t, "block-telnet", RulePositionPrepend, 100, `{"uuid":"`+ruleA+`","action":"block","interface":"lan","description":"Block telnet"}`)

	result := executeSyncAPI(context.Background(), device.client, nil, []APIRulePayload{rule})

	if !result.Success {
		t.Fatalf("sync failed: %v", result.Errors)
	}
	if got, local := device.sequenceOf(ruleA), device.sequenceOf(defaultAllow4); got != 1 || local != 2 {
		t.Errorf("PREPEND rule at %d, default allow at %d; want 1 and 2", got, local)
	}
	if moved := itemsOfType(result.Results, "rule_local"); len(moved) != 1 || moved[0].UUID != defaultAllow4 {
		t.Errorf("rule_local items = %+v", moved)
	}
}

// TestExecuteSyncAPI_LocalRuleWithoutADescription is named by its UUID.
func TestExecuteSyncAPI_LocalRuleWithoutADescription(t *testing.T) {
	device := newFakeRuleDevice(t, ruleTemplate(t), []map[string]interface{}{lanLocal(blockX, 1, "")})
	rule := desiredRule(t, "block-telnet", RulePositionPrepend, 100, `{"uuid":"`+ruleA+`","action":"block","interface":"lan","description":"Block telnet"}`)

	result := executeSyncAPI(context.Background(), device.client, nil, []APIRulePayload{rule})

	if moved := itemsOfType(result.Results, "rule_local"); len(moved) != 1 || moved[0].Name != blockX {
		t.Errorf("rule_local items = %+v, want one named by the UUID", moved)
	}
}

// TestExecuteSyncAPI_RecreatedRuleIsNoLocalRule: a rule a renumber re-created
// and that could not be removed stays on the device, but it is not the
// owner's rule: a second placement pass neither moves it nor reports it as a
// local rule, and the firewall rules are not applied.
func TestExecuteSyncAPI_RecreatedRuleIsNoLocalRule(t *testing.T) {
	device, _ := mismatchDevice(t)
	device.before = func(call, uuid string) bool {
		if uuid != defaultAllow4 {
			return true
		}
		if call == "set" {
			device.deleteRow(uuid)
		}
		return call != "del" && call != "toggle"
	}
	rules := []APIRulePayload{
		desiredRule(t, "lan", RulePositionPrepend, 100, `{"uuid":"`+ruleA+`","action":"block","interface":"lan","description":"Block telnet"}`),
		desiredRule(t, "vpn", RulePositionPrepend, 200, `{"uuid":"`+ruleB+`","action":"pass","interface":"wireguard","description":"VPN to LAN"}`),
	}

	result := executeSyncAPI(context.Background(), device.client, nil, rules)

	if device.searches < 3 {
		t.Fatalf("searches = %d: the wireguard rule's section mismatch should have placed the rules twice", device.searches)
	}
	var writes []string
	for _, w := range device.writesTo(defaultAllow4) {
		writes = append(writes, strings.Fields(w)[0])
	}
	if want := []string{"set", "del", "del", "toggle"}; !reflect.DeepEqual(writes, want) {
		t.Errorf("writes to the re-created rule = %v, want %v", writes, want)
	}
	for _, item := range itemsOfType(result.Results, "rule_placement") {
		if strings.Contains(item.Error, defaultAllow4) {
			t.Errorf("the re-created rule is reported as a local rule: %+v", item)
		}
	}
	want := withheldApply(withheldRecreated, "Default allow LAN to any rule")
	if withheld := itemsOfType(result.Results, "rule_apply"); len(withheld) != 1 || withheld[0].Code != codeRuleApplyWithheld || withheld[0].Error != want {
		t.Errorf("rule_apply items = %+v\nwant: %s", withheld, want)
	}
	assertErrorHasMatchingResultItem(t, "re-created", result.Errors, result.Results)
}

// TestExecuteSyncAPI_LocalMoveOnA2675Device: OPNsense derives a rule's
// sort_order from its sequence on every read and, from 26.7.5, stamps its
// audit record on every save; neither is a change the read after a renumber
// may report.
func TestExecuteSyncAPI_LocalMoveOnA2675Device(t *testing.T) {
	device := newFakeRuleDevice(t, ruleTemplate(t, withRuleModel2675), searchRows26(t))
	device.groups = []opnapi.InterfaceGroup{{Name: "wireguard", Sequence: 10}}
	rule := desiredRule(t, "block-telnet", RulePositionPrepend, 100, `{"uuid":"`+ruleA+`","action":"block","interface":"lan","description":"Block telnet"}`)

	result := executeSyncAPI(context.Background(), device.client, nil, []APIRulePayload{rule})

	if !result.Success {
		t.Fatalf("sync failed: %v", result.Errors)
	}
	if got := device.sequenceOf(defaultAllow4); got != 2 {
		t.Errorf("default allow at %d, want 2", got)
	}
	if audit, _ := device.row(defaultAllow4)["audit"].(map[string]interface{}); audit == nil {
		t.Error("the renumber stamped no audit record: the fake does not model 26.7.5")
	}
	if moved := itemsOfType(result.Results, "rule_local"); len(moved) != 1 || moved[0].Code != codeRuleLocalRenumbered {
		t.Errorf("rule_local items = %+v, want the one renumber", moved)
	}
}

// TestExecuteSyncAPI_PartialReadIsNoRead: a read of a local rule that lacks a
// field of the device's rule model would pass a missing field for one back at
// its default, and a rule for one the move re-created. A partial read before
// the move keeps the rule where it is; one after it withholds the apply.
// Neither deletes or disables anything.
func TestExecuteSyncAPI_PartialReadIsNoRead(t *testing.T) {
	cases := []struct {
		name    string
		partial func(gets int) bool // which getRule/<uuid> answers {"rule":{}}
		code    string
		writes  []string
		applied bool
	}{
		{"before the move", func(gets int) bool { return gets == 1 }, codeRuleLocalRenumberFailed, nil, true},
		{"after the move", func(gets int) bool { return gets >= 2 }, codeRuleLocalRenumberUnverified, []string{"set"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			device := freshDevice(t)
			device.answerGet = func(uuid string) (interface{}, bool) {
				if uuid == defaultAllow4 && tc.partial(device.calls["get "+uuid]) {
					return map[string]interface{}{"rule": map[string]interface{}{}}, true
				}
				return nil, false
			}
			rule := desiredRule(t, "block-telnet", RulePositionPrepend, 100, `{"uuid":"`+ruleA+`","action":"block","interface":"lan","description":"Block telnet"}`)

			result := executeSyncAPI(context.Background(), device.client, nil, []APIRulePayload{rule})

			var writes []string
			for _, w := range device.writesTo(defaultAllow4) {
				writes = append(writes, strings.Fields(w)[0])
			}
			if !reflect.DeepEqual(writes, tc.writes) {
				t.Errorf("writes to the local rule = %v, want %v", writes, tc.writes)
			}
			if row := device.row(defaultAllow4); row == nil || row["enabled"] != "1" {
				t.Errorf("the local rule = %v, want it kept and enabled", row)
			}
			if applied := writeIndex(device.writes, "apply") >= 0; applied != tc.applied {
				t.Errorf("applied = %v, want %v", applied, tc.applied)
			}
			if want := withheldApply(withheldUnreadable, "Default allow LAN to any rule"); !tc.applied {
				if withheld := itemsOfType(result.Results, "rule_apply"); len(withheld) != 1 || withheld[0].Error != want {
					t.Errorf("rule_apply items = %+v\nwant: %s", withheld, want)
				}
			}
			var found bool
			for _, item := range itemsOfType(result.Results, "rule_local") {
				if item.UUID == defaultAllow4 && item.Code == tc.code && strings.Contains(item.Error, "the device answered without its") {
					found = true
				}
			}
			if !found {
				t.Errorf("no %s item naming the missing field: %+v", tc.code, itemsOfType(result.Results, "rule_local"))
			}
			assertErrorHasMatchingResultItem(t, tc.name, result.Errors, result.Results)
		})
	}
}

// TestExecuteSyncAPI_OwnerEditOfASingleValueIsKept: a local rule whose only
// value besides the defaults the owner changes to another value during its
// move kept nothing of itself and lost nothing to a default: it is the
// owner's edit, kept, and the apply goes ahead.
func TestExecuteSyncAPI_OwnerEditOfASingleValueIsKept(t *testing.T) {
	const local = "0c0c0c0c-0000-4000-8000-0000000000d2"
	row := map[string]interface{}{"uuid": local}
	for name, value := range ruleModel26(t).Values() {
		row[name] = value
	}
	row["sequence"] = "1"
	row["description"] = "Allow all from the lab"
	device := newFakeRuleDevice(t, ruleTemplate(t), []map[string]interface{}{row})
	device.before = func(call, uuid string) bool {
		if call == "set" && uuid == local {
			device.find(uuid)["description"] = "Allow all from the office"
		}
		return true
	}
	rule := desiredRule(t, "floating", RulePositionPrepend, 100, `{"uuid":"`+ruleA+`","action":"block","interface":"","description":"Block telnet"}`)

	result := executeSyncAPI(context.Background(), device.client, nil, []APIRulePayload{rule})

	if got := device.row(local); got == nil || got["description"] != "Allow all from the office" || got["sequence"] != "2" {
		t.Errorf("the local rule = %v, want the owner's edit kept at sequence 2", got)
	}
	if w := device.writesTo(local); !reflect.DeepEqual(w, []string{"set " + local}) {
		t.Errorf("writes to the local rule = %v", w)
	}
	if writeIndex(device.writes, "apply") < 0 {
		t.Errorf("the apply was withheld: %v", device.writes)
	}
	items := itemsOfType(result.Results, "rule_local")
	var found bool
	for _, item := range items {
		if item.Code == codeRuleLocalRenumberUnverified && item.Error == `Local rule "Allow all from the lab" changed on the device while NetDefense moved it from sequence 1 to 2; it was left as it is, so check it` {
			found = true
		}
	}
	if !found {
		t.Errorf("rule_local items = %+v", items)
	}
}

// fakeError is the error the client returns for an HTTP 500 of the fake device.
var fakeError = (&opnapi.APIError{StatusCode: http.StatusInternalServerError, Body: `{"errorMessage":"Unexpected error, check log for details"}` + "\n"}).Error()

// saveAndLoseTheAnswer makes a device save a setRule and answer it with HTTP
// 500, as a write whose answer is lost after the save does; deleteFirst makes
// the owner delete the rule just before, so the save re-creates it. The
// caller holds the device's lock.
func saveAndLoseTheAnswer(device *fakeRuleDevice, uuid string, deleteFirst bool) bool {
	if deleteFirst {
		device.deleteRow(uuid)
	}
	bodies := device.bodies[uuid]
	target := device.find(uuid)
	if target == nil {
		target = map[string]interface{}{"uuid": uuid}
		for name, value := range opnapi.ParseEntityModel(device.template).Values() {
			target[name] = value
		}
		device.rows = append(device.rows, target)
	}
	for k, v := range bodies[len(bodies)-1] {
		target[k] = v
	}
	return false
}

// TestExecuteSyncAPI_LostWriteAnswer: only a refusal with field validations
// says a setRule saved nothing. A write whose answer is lost (a timeout, a
// 5xx, a dropped connection) may have saved, so the rule is read back as after
// any write: a rule the save re-created after the owner deleted it is deleted
// again, a rule the save moved is moved, a rule it did not move is stuck, a
// rule that cannot be read back is planned where it was, and a rule gone at
// the read-back may have been deleted before the move or after it.
func TestExecuteSyncAPI_LostWriteAnswer(t *testing.T) {
	lost := fakeError
	unreadable := func(why string) string {
		return `Local rule "Default allow LAN to any rule" may have been moved from sequence 1 to 2 (the answer to the move was lost: ` + lost + `), but could not be read back: ` + why + `. Had it been deleted on the device meanwhile, the move may have re-created it as a pass rule, so the firewall rules are not applied this SYNC: check the rule on the device`
	}
	gone := `Local rule "Default allow LAN to any rule" is gone from the device: it was deleted during this SYNC, and the answer to its move was lost (` + lost + `), so it may have been deleted before the move or after it. If the move still lands, it re-creates the rule as a pass rule on every interface, with no description: check the device for one`
	cases := []struct {
		name    string
		before  func(device *fakeRuleDevice, call, uuid string) bool
		code    string
		status  string
		message string
		exact   bool   // the message is the item's whole error
		row     string // the local rule's sequence afterwards, or gone
		prepend int
		success bool
		applied bool
	}{
		{
			name: "saved, the answer lost",
			before: func(device *fakeRuleDevice, call, uuid string) bool {
				return call != "set" || device.calls["set "+uuid] > 1 || saveAndLoseTheAnswer(device, uuid, false)
			},
			code: codeRuleLocalRenumbered, status: "success", row: "2", prepend: 1, success: true, applied: true,
		},
		{
			name: "deleted by the owner, re-created by the save, the answer lost",
			before: func(device *fakeRuleDevice, call, uuid string) bool {
				return call != "set" || device.calls["set "+uuid] > 1 || saveAndLoseTheAnswer(device, uuid, true)
			},
			code: codeRuleLocalRenumberUnverified, status: "error", message: "NetDefense deleted it again", row: "gone", prepend: 5, applied: true,
		},
		{
			name:    "not saved, the answer lost",
			before:  func(device *fakeRuleDevice, call, uuid string) bool { return call != "set" },
			code:    codeRuleLocalRenumberFailed,
			status:  "error",
			message: `Local rule "Default allow LAN to any rule" could not be moved from sequence 1 to 2, so the PREPEND rules of its section are placed after it: ` + lost,
			exact:   true,
			row:     "1", prepend: 6, applied: true,
		},
		{
			name: "not saved, the answer lost, the owner edited the rule",
			before: func(device *fakeRuleDevice, call, uuid string) bool {
				if call == "set" {
					device.find(uuid)["description"] = "edited by the owner"
				}
				return call != "set"
			},
			code:    codeRuleLocalRenumberFailed,
			status:  "error",
			message: `Local rule "Default allow LAN to any rule" could not be moved from sequence 1 to 2, so the PREPEND rules of its section are placed after it: ` + lost,
			exact:   true,
			row:     "1", prepend: 6, applied: true,
		},
		{
			name: "saved, the answer lost, unreadable after",
			before: func(device *fakeRuleDevice, call, uuid string) bool {
				if call == "get" {
					return device.calls["get "+uuid] < 2
				}
				return call != "set" || saveAndLoseTheAnswer(device, uuid, false)
			},
			code:    codeRuleLocalRenumberUnverified,
			status:  "error",
			message: unreadable(lost),
			exact:   true,
			row:     "2", prepend: 6, // planned around the rule where it was: the move is unconfirmed
		},
		{
			name: "saved, the answer lost, read back without its sequence",
			before: func(device *fakeRuleDevice, call, uuid string) bool {
				if call == "get" && device.calls["get "+uuid] == 2 {
					device.answerGet = func(u string) (interface{}, bool) {
						if u != uuid {
							return nil, false
						}
						return answerWithout(device, u, "sequence")
					}
				}
				return call != "set" || saveAndLoseTheAnswer(device, uuid, false)
			},
			code:    codeRuleLocalRenumberUnverified,
			status:  "error",
			message: unreadable("the device answered without its sequence field"),
			exact:   true,
			row:     "2", prepend: 6,
		},
		{
			name: "deleted by the owner, not saved, the answer lost",
			before: func(device *fakeRuleDevice, call, uuid string) bool {
				if call == "set" {
					device.deleteRow(uuid)
				}
				return call != "set"
			},
			code: codeRuleLocalVanished, status: "warning", message: gone, exact: true, row: "gone", prepend: 5, success: true, applied: true,
		},
		{
			name: "saved, deleted by the owner, the answer lost",
			before: func(device *fakeRuleDevice, call, uuid string) bool {
				if call != "set" {
					return true
				}
				saveAndLoseTheAnswer(device, uuid, false)
				device.deleteRow(uuid)
				return false
			},
			code: codeRuleLocalVanished, status: "warning", message: gone, exact: true, row: "gone", prepend: 5, success: true, applied: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			device := freshDevice(t)
			device.before = func(call, uuid string) bool {
				if uuid != defaultAllow4 {
					return true
				}
				return tc.before(device, call, uuid)
			}
			rule := desiredRule(t, "block-telnet", RulePositionPrepend, 100, `{"uuid":"`+ruleA+`","action":"block","interface":"lan","description":"Block telnet"}`)

			result := executeSyncAPI(context.Background(), device.client, nil, []APIRulePayload{rule})

			switch row := device.row(defaultAllow4); {
			case tc.row == "gone" && row != nil:
				t.Errorf("the local rule is still there: %v", row)
			case tc.row != "gone" && (row == nil || row["sequence"] != tc.row || row["interface"] != "lan"):
				t.Errorf("the local rule = %v, want the owner's rule at sequence %s", row, tc.row)
			}
			if got := device.sequenceOf(ruleA); got != tc.prepend {
				t.Errorf("PREPEND rule at %d, want %d", got, tc.prepend)
			}
			if result.Success != tc.success {
				t.Errorf("success = %v, want %v: %v", result.Success, tc.success, result.Errors)
			}
			if applied := writeIndex(device.writes, "apply") >= 0; applied != tc.applied {
				t.Errorf("applied = %v, want %v", applied, tc.applied)
			}
			var found bool
			for _, item := range itemsOfType(result.Results, "rule_local") {
				if item.UUID == defaultAllow4 && item.Code == tc.code && item.Status == tc.status && (item.Error == tc.message || !tc.exact && strings.Contains(item.Error, tc.message)) {
					found = true
				}
			}
			if !found {
				t.Errorf("no %s item with status %s saying %q: %+v", tc.code, tc.status, tc.message, itemsOfType(result.Results, "rule_local"))
			}
			if !result.Success {
				assertErrorHasMatchingResultItem(t, tc.name, result.Errors, result.Results)
			}
		})
	}
}

// answerWithout answers getRule/<uuid> with the rule's plain values, and its
// lists as the template has them, but without one field.
func answerWithout(device *fakeRuleDevice, uuid, missing string) (interface{}, bool) {
	row := device.find(uuid)
	if row == nil {
		return nil, false
	}
	rule := map[string]interface{}{}
	for key, field := range device.template {
		if key == missing {
			continue
		}
		if v, ok := row[key].(string); ok {
			if _, isList := field.(map[string]interface{}); !isList {
				rule[key] = v
				continue
			}
		}
		rule[key] = field
	}
	return map[string]interface{}{"rule": rule}, true
}

// TestExecuteSyncAPI_PartialReadMissingOneField: a read lacking a single field
// of the device's rule model, not the first one, is no read either.
func TestExecuteSyncAPI_PartialReadMissingOneField(t *testing.T) {
	device := freshDevice(t)
	device.answerGet = func(uuid string) (interface{}, bool) {
		if uuid != defaultAllow4 || device.calls["get "+uuid] != 1 {
			return nil, false
		}
		return answerWithout(device, uuid, "tcpflags2")
	}
	rule := desiredRule(t, "block-telnet", RulePositionPrepend, 100, `{"uuid":"`+ruleA+`","action":"block","interface":"lan","description":"Block telnet"}`)

	result := executeSyncAPI(context.Background(), device.client, nil, []APIRulePayload{rule})

	var held bool
	for _, item := range itemsOfType(result.Results, "rule_local") {
		if item.UUID == defaultAllow4 && item.Code == codeRuleLocalRenumberFailed && strings.Contains(item.Error, "the device answered without its tcpflags2 field") {
			held = true
		}
	}
	if !held {
		t.Errorf("a read lacking one field of the model was taken for a read: %+v", itemsOfType(result.Results, "rule_local"))
	}
	if w := device.writesTo(defaultAllow4); len(w) != 0 {
		t.Errorf("the local rule was written: %v", w)
	}
}

// TestExecuteSyncAPI_TwoWithheldRulesReadAsTwoSentences: the withheld apply
// gives one sentence per local rule, apart.
func TestExecuteSyncAPI_TwoWithheldRulesReadAsTwoSentences(t *testing.T) {
	device := freshDevice(t)
	device.before = func(call, uuid string) bool {
		if uuid != defaultAllow4 && uuid != defaultAllow6 {
			return true
		}
		return !(call == "get" && device.calls["get "+uuid] >= 2)
	}

	result := executeSyncAPI(context.Background(), device.client, nil, prependRules(t, 11))

	want := "Firewall rules were not applied this SYNC. " +
		fmt.Sprintf(withheldUnreadable, "Default allow LAN IPv6 to any rule") + " " +
		fmt.Sprintf(withheldUnreadable, "Default allow LAN to any rule") + " Check the device, then SYNC again"
	if withheld := itemsOfType(result.Results, "rule_apply"); len(withheld) != 1 || withheld[0].Error != want {
		t.Errorf("rule_apply items = %+v\nwant: %s", withheld, want)
	}
}

// ruleTemplate2675Shape is the 26.7 GA template with what 26.7.5's Filter.xml
// adds to a rule, in the shapes OPNsense answers them: JsonAuditField's
// getNodeData() always returns its full schema, an object.
func ruleTemplate2675Shape(t *testing.T) map[string]interface{} {
	t.Helper()
	template := ruleTemplate(t)
	iface, _ := template["interface"].(map[string]interface{})
	receivedOn := map[string]interface{}{}
	for k, v := range iface {
		pair, _ := v.(map[string]interface{})
		receivedOn[k] = map[string]interface{}{"value": pair["value"], "selected": 0}
	}
	template["received-on"] = receivedOn
	template["received-on-not"] = "0"
	template["max-pkt-rate-number"] = ""
	template["max-pkt-rate-seconds"] = ""
	template["audit"] = auditSchema("", "")
	return template
}

// auditSchema is JsonAuditField's answer, stamped at these times when given.
func auditSchema(created, updated string) map[string]interface{} {
	entry := func(time string) map[string]interface{} {
		e := map[string]interface{}{"username": "", "time": "", "description": ""}
		if time != "" {
			e["username"], e["time"], e["description"], e["%time"] = "root", time, "/api/firewall/filter/setRule made changes", "2026-10-05 12:00:00"
		}
		return e
	}
	return map[string]interface{}{"created": entry(created), "updated": entry(updated), "userdata": map[string]interface{}{"note": ""}}
}

// serveRules2675 answers getRule/<uuid> as 26.7.5 does for a stored rule: the
// template's keys, the row's values, option lists marking the selected keys,
// and the audit record stamped.
func serveRules2675(device *fakeRuleDevice, template map[string]interface{}) func(uuid string) (interface{}, bool) {
	return func(uuid string) (interface{}, bool) {
		row := device.find(uuid)
		if row == nil {
			return nil, false
		}
		rule := map[string]interface{}{}
		for key, field := range template {
			if key == "audit" {
				rule[key] = auditSchema("1791234765.99", "1791234806.40")
				continue
			}
			value, set := row[key].(string)
			if options, isList := field.(map[string]interface{}); isList {
				selected := map[string]bool{}
				for _, k := range strings.Split(value, ",") {
					selected[k] = true
				}
				marked := map[string]interface{}{}
				for k, option := range options {
					pair, _ := option.(map[string]interface{})
					copied := map[string]interface{}{"value": pair["value"], "selected": 0}
					if set && selected[k] || !set && isSelected(pair["selected"]) {
						copied["selected"] = 1
					}
					marked[k] = copied
				}
				rule[key] = marked
				continue
			}
			if set {
				rule[key] = value
			} else {
				rule[key] = field
			}
		}
		return map[string]interface{}{"rule": rule}, true
	}
}

// TestExecuteSyncAPI_2675ShapesDoNotTripReadRule: the reads around a renumber
// are compared, and required, on the fields content can set, never the audit
// record 26.7.5 answers as an object in the template and in every read.
func TestExecuteSyncAPI_2675ShapesDoNotTripReadRule(t *testing.T) {
	for _, shape := range []string{"26.7 GA", "26.7.5"} {
		t.Run(shape, func(t *testing.T) {
			device := freshDevice(t)
			if shape == "26.7.5" {
				template := ruleTemplate2675Shape(t)
				device = newFakeRuleDevice(t, template, searchRows26(t))
				device.answerGet = serveRules2675(device, template)
			}
			rule := desiredRule(t, "block-telnet", RulePositionPrepend, 100, `{"uuid":"`+ruleA+`","action":"block","interface":"lan","description":"Block telnet"}`)

			result := executeSyncAPI(context.Background(), device.client, nil, []APIRulePayload{rule})

			if !result.Success {
				t.Fatalf("the SYNC failed: %v", result.Errors)
			}
			if got, local := device.sequenceOf(ruleA), device.sequenceOf(defaultAllow4); got != 1 || local != 2 {
				t.Errorf("PREPEND rule at %d, default allow at %d; want 1 and 2", got, local)
			}
		})
	}
}

// TestExecuteSyncAPI_UnconfirmedMoveKeepsLocalOrder: a move whose answer was lost
// and whose read-back failed is not known to have happened, so the local rules
// below it are planned around where it was. Taken for moved, it let the rule
// below be pushed past a rule that never moved: the two local rules inverted.
func TestExecuteSyncAPI_UnconfirmedMoveKeepsLocalOrder(t *testing.T) {
	device := freshDevice(t)
	device.before = func(call, uuid string) bool {
		if uuid != defaultAllow6 {
			return true
		}
		switch call {
		case "set":
			return false // the answer is lost, and nothing was saved
		case "get":
			return device.calls["get "+uuid] < 2 // neither the read-back nor its retry works
		}
		return true
	}

	result := executeSyncAPI(context.Background(), device.client, nil, prependRules(t, 11))

	if v4, v6 := device.sequenceOf(defaultAllow4), device.sequenceOf(defaultAllow6); v4 >= v6 {
		t.Errorf("the IPv4 allow rule is at %d, the IPv6 allow rule at %d: the local rules were inverted", v4, v6)
	}
	if writeIndex(device.writes, "apply") >= 0 {
		t.Errorf("the apply was not withheld: %v", device.writes)
	}
	for _, item := range itemsOfType(result.Results, "rule_local") {
		if item.UUID == defaultAllow6 && item.Code == codeRuleLocalRenumbered {
			t.Errorf("a move that may not have happened is reported as done: %+v", item)
		}
	}
}

// TestExecuteSyncAPI_UnconfirmedEditedMoveKeepsLocalOrder: the same for a move
// whose answer was lost, that saved nothing, and whose rule the owner edited
// meanwhile: it reads back changed, and still at its old sequence.
func TestExecuteSyncAPI_UnconfirmedEditedMoveKeepsLocalOrder(t *testing.T) {
	device := freshDevice(t)
	device.before = func(call, uuid string) bool {
		if uuid == defaultAllow6 && call == "set" {
			device.find(uuid)["description"] = "" // the owner's edit, to a default value
			return false                          // the answer is lost, and nothing was saved
		}
		return true
	}

	result := executeSyncAPI(context.Background(), device.client, nil, prependRules(t, 11))

	if v4, v6 := device.sequenceOf(defaultAllow4), device.sequenceOf(defaultAllow6); v4 >= v6 {
		t.Errorf("the IPv4 allow rule is at %d, the IPv6 allow rule at %d: the local rules were inverted", v4, v6)
	}
	for _, item := range itemsOfType(result.Results, "rule_local") {
		if item.UUID == defaultAllow6 && item.Code == codeRuleLocalRenumbered {
			t.Errorf("a move that did not happen is reported as done: %+v", item)
		}
	}
}

// TestExecuteSyncAPI_UnconfirmedSecondMoveNamesTheFirst: a replan moves a local
// rule twice in one SYNC when a rule below it cannot be moved. When the answer
// to the second move is lost and the rule cannot be read back, its first move
// is not reported renumbered, so the unverified item names it.
func TestExecuteSyncAPI_UnconfirmedSecondMoveNamesTheFirst(t *testing.T) {
	device := freshDevice(t)
	device.edit(defaultAllow4, func(row map[string]interface{}) { row["sequence"] = "2" })
	device.edit(defaultAllow6, func(row map[string]interface{}) { row["sequence"] = "3" })
	device.answer = func(uuid string, body map[string]string) (int, interface{}, bool) {
		if uuid == defaultAllow4 {
			return http.StatusOK, map[string]interface{}{"result": "failed", "validations": map[string]interface{}{"rule.gateway": "Option [OLD_GW] not in list."}}, true
		}
		return 0, nil, false
	}
	device.before = func(call, uuid string) bool {
		if uuid != defaultAllow6 || device.calls["set "+uuid] < 2 {
			return true
		}
		if call == "set" {
			return saveAndLoseTheAnswer(device, uuid, false) // the second move: saved, its answer lost
		}
		return call != "get" // and the rule cannot be read back
	}

	result := executeSyncAPI(context.Background(), device.client, nil, prependRules(t, 2))

	if w := device.writesTo(defaultAllow6); len(w) != 2 {
		t.Fatalf("writes to the IPv6 allow rule = %v, want its two moves", w)
	}
	want := `Local rule "Default allow LAN IPv6 to any rule", moved from sequence 3 to 4 earlier in this SYNC, may have been moved from sequence 4 to 5 (the answer to the move was lost: ` + fakeError + `), but could not be read back: ` + fakeError + `. Had it been deleted on the device meanwhile, the move may have re-created it as a pass rule, so the firewall rules are not applied this SYNC: check the rule on the device`
	var found bool
	for _, item := range itemsOfType(result.Results, "rule_local") {
		if item.UUID != defaultAllow6 {
			continue
		}
		switch {
		case item.Code == codeRuleLocalRenumbered:
			t.Errorf("a move that may have been overtaken is reported renumbered: %+v", item)
		case item.Code == codeRuleLocalRenumberUnverified && item.Error == want:
			found = true
		}
	}
	if !found {
		t.Errorf("no %s item saying %q: %+v", codeRuleLocalRenumberUnverified, want, itemsOfType(result.Results, "rule_local"))
	}
	if writeIndex(device.writes, "apply") >= 0 {
		t.Errorf("the apply was not withheld: %v", device.writes)
	}
}
