package tasks

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// labTopology is e2e-a's: lan and wan interfaces, the WireGuard plugin group
// at sequence 10 holding wg0, and a hand-made group with no sequence set.
func labTopology() ruleTopology {
	return newRuleTopology(
		map[string]string{"lan": "interface", "wan": "interface", "opt1": "interface", "wg0": "interface", "wireguard": "group", "dmz_group": "group"},
		[]opnapi.InterfaceGroup{
			{Name: "wireguard", Sequence: 10, Members: []string{"wg0"}},
			{Name: "openvpn", Sequence: 10},
			{Name: "dmz_group", Members: []string{"opt1"}},
		},
	)
}

func TestRuleTopology_Section(t *testing.T) {
	topology := labTopology()
	cases := []struct {
		interfaces string
		not        bool
		want       int
	}{
		{"lan", false, 400000},
		{"wireguard", false, 300010},
		{"dmz_group", false, 300000},
		{"lan,wan", false, 200000},
		{"", false, 200000},
		{"lan", true, 200000},
		{"opt9", false, 400000},
	}
	for _, tc := range cases {
		if got := topology.section(splitInterfaces(tc.interfaces), tc.not); got != tc.want {
			t.Errorf("section(%q, not=%v) = %d, want %d", tc.interfaces, tc.not, got, tc.want)
		}
	}
}

func TestRowSequenceAndSection(t *testing.T) {
	cases := []struct {
		row     map[string]interface{}
		seq     int
		section int
	}{
		{map[string]interface{}{"sequence": "11", "prio_group": "400000"}, 11, 400000},
		{map[string]interface{}{"sequence": float64(7), "prio_group": float64(300010)}, 7, 300010},
		{map[string]interface{}{"sequence": nil, "prio_group": nil, "sort_order": "400000.1000031"}, 0, 400000},
		{map[string]interface{}{"sort_order": "000005.1000024"}, 0, 5},
	}
	for _, tc := range cases {
		if got := rowSequence(tc.row); got != tc.seq {
			t.Errorf("rowSequence(%v) = %d, want %d", tc.row, got, tc.seq)
		}
		if got := rowSection(tc.row); got != tc.section {
			t.Errorf("rowSection(%v) = %d, want %d", tc.row, got, tc.section)
		}
	}
}

func managedRule(uuid string, position RulePosition, priority, order, section, current int) *placedRule {
	return &placedRule{uuid: uuid, name: uuid, section: section, position: position, priority: priority, order: order, current: current}
}

func localRule(uuid string, section, current int) *placedRule {
	return &placedRule{uuid: uuid, name: uuid, section: section, current: current, enabled: true}
}

func TestPlanRulePlacement(t *testing.T) {
	const lan = sectionInterface
	cases := []struct {
		name      string
		managed   []*placedRule
		locals    []*placedRule
		want      map[string]int
		wantMoves []localMove
		noRoom    []string
	}{
		{
			name:      "fresh 26.7 defaults with one PREPEND rule",
			managed:   []*placedRule{managedRule("p1", RulePositionPrepend, 100, 0, lan, 0)},
			locals:    []*placedRule{localRule("allow4", lan, 1), localRule("allow6", lan, 11)},
			want:      map[string]int{"p1": 1},
			wantMoves: []localMove{{uuid: "allow4", name: "allow4", from: 1, to: 2}},
		},
		{
			name: "fresh 26.7 defaults with three PREPEND rules",
			managed: []*placedRule{
				managedRule("p1", RulePositionPrepend, 100, 0, lan, 0),
				managedRule("p2", RulePositionPrepend, 200, 1, lan, 0),
				managedRule("p3", RulePositionPrepend, 300, 2, lan, 0),
			},
			locals:    []*placedRule{localRule("allow4", lan, 1), localRule("allow6", lan, 11)},
			want:      map[string]int{"p1": 1, "p2": 2, "p3": 3},
			wantMoves: []localMove{{uuid: "allow4", name: "allow4", from: 1, to: 4}},
		},
		{
			name: "GUI rules at 101 and 201 leave room below them",
			managed: []*placedRule{
				managedRule("p1", RulePositionPrepend, 100, 0, lan, 0),
				managedRule("p2", RulePositionPrepend, 200, 1, lan, 0),
			},
			locals: []*placedRule{localRule("gui1", lan, 101), localRule("gui2", lan, 201)},
			want:   map[string]int{"p1": 33, "p2": 67},
		},
		{
			name: "the old 100/200 layout interleaved with GUI rules is spaced again below them",
			managed: []*placedRule{
				managedRule("p1", RulePositionPrepend, 100, 0, lan, 100),
				managedRule("p2", RulePositionPrepend, 200, 1, lan, 200),
			},
			locals: []*placedRule{localRule("gui1", lan, 101), localRule("gui2", lan, 201)},
			want:   map[string]int{"p1": 33, "p2": 67},
		},
		{
			name:    "a new PREPEND rule goes into the gap before the kept one",
			managed: []*placedRule{managedRule("new", RulePositionPrepend, 50, 0, lan, 0), managedRule("old", RulePositionPrepend, 100, 1, lan, 40)},
			locals:  []*placedRule{localRule("gui", lan, 101)},
			want:    map[string]int{"new": 20, "old": 40},
		},
		{
			name:    "APPEND after the last local rule",
			managed: []*placedRule{managedRule("a1", RulePositionAppend, 100, 0, lan, 0), managedRule("a2", RulePositionAppend, 200, 1, lan, 0)},
			locals:  []*placedRule{localRule("allow4", lan, 2), localRule("allow6", lan, 11)},
			want:    map[string]int{"a1": 111, "a2": 211},
		},
		{
			name:    "a GUI rule added at max+100 pushes the APPEND rule after it",
			managed: []*placedRule{managedRule("a1", RulePositionAppend, 100, 0, lan, 111)},
			locals:  []*placedRule{localRule("allow4", lan, 2), localRule("allow6", lan, 11), localRule("gui", lan, 211)},
			want:    map[string]int{"a1": 311},
		},
		{
			name: "converged: nothing moves",
			managed: []*placedRule{
				managedRule("p1", RulePositionPrepend, 100, 0, lan, 1),
				managedRule("a1", RulePositionAppend, 100, 1, lan, 111),
			},
			locals: []*placedRule{localRule("allow4", lan, 2), localRule("allow6", lan, 11)},
			want:   map[string]int{"p1": 1, "a1": 111},
		},
		{
			name:    "tied local rules move together, in OPNsense's order",
			managed: []*placedRule{managedRule("p1", RulePositionPrepend, 1, 0, lan, 0), managedRule("p2", RulePositionPrepend, 2, 1, lan, 0)},
			locals:  []*placedRule{localRule("10bc0000-0000-4000-8000-000000000001", lan, 1), localRule("2abc0000-0000-4000-8000-000000000001", lan, 1)},
			want:    map[string]int{"p1": 1, "p2": 2},
			wantMoves: []localMove{
				{uuid: "2abc0000-0000-4000-8000-000000000001", name: "2abc0000-0000-4000-8000-000000000001", from: 1, to: 3},
				{uuid: "10bc0000-0000-4000-8000-000000000001", name: "10bc0000-0000-4000-8000-000000000001", from: 1, to: 3},
			},
		},
		{
			name:    "the push ends at the first rule already out of the way",
			managed: []*placedRule{managedRule("p1", RulePositionPrepend, 1, 0, lan, 0)},
			locals: []*placedRule{
				localRule("allow4", lan, 1), localRule("allow6", lan, 11),
				localRule("tieA", lan, 5000), localRule("tieB", lan, 5000),
			},
			want:      map[string]int{"p1": 1},
			wantMoves: []localMove{{uuid: "allow4", name: "allow4", from: 1, to: 2}},
		},
		{
			name: "PREPEND rules by priority, not by payload order",
			managed: []*placedRule{
				managedRule("low", RulePositionPrepend, 300, 0, lan, 0),
				managedRule("high", RulePositionPrepend, 100, 1, lan, 0),
			},
			locals: []*placedRule{localRule("gui", lan, 301)},
			want:   map[string]int{"high": 100, "low": 200},
		},
		{
			name:      "a rule without a position is PREPEND",
			managed:   []*placedRule{managedRule("p1", "", 100, 0, lan, 0)},
			locals:    []*placedRule{localRule("allow4", lan, 1), localRule("allow6", lan, 11)},
			want:      map[string]int{"p1": 1},
			wantMoves: []localMove{{uuid: "allow4", name: "allow4", from: 1, to: 2}},
		},
		{
			name: "PREPEND rules after local rules that cannot move, APPEND rules after them",
			managed: []*placedRule{
				managedRule("p1", RulePositionPrepend, 1, 0, lan, 0),
				managedRule("a1", RulePositionAppend, 1, 1, lan, 0),
			},
			locals: []*placedRule{
				{uuid: "stuck1", name: "stuck1", section: lan, current: 1, fixed: true, enabled: true},
				{uuid: "stuck2", name: "stuck2", section: lan, current: 2, fixed: true, enabled: true},
			},
			want: map[string]int{"p1": 102, "a1": 202},
		},
		{
			name:    "a managed rule held where it is is a local rule that cannot move",
			managed: []*placedRule{managedRule("p1", RulePositionPrepend, 1, 0, lan, 0)},
			locals: []*placedRule{
				localRule("allow4", lan, 1),
				{uuid: "refused", name: "refused", section: lan, current: 2, fixed: true, held: true},
				localRule("allow6", lan, 11),
			},
			want: map[string]int{"p1": 6},
		},
		{
			name:      "a disabled local rule keeps its place",
			managed:   []*placedRule{managedRule("p1", RulePositionPrepend, 1, 0, lan, 0)},
			locals:    []*placedRule{{uuid: "off", name: "off", section: lan, current: 1}, localRule("on", lan, 2)},
			want:      map[string]int{"p1": 1},
			wantMoves: []localMove{{uuid: "off", name: "off", from: 1, to: 2}, {uuid: "on", name: "on", from: 2, to: 3}},
		},
		{
			name:    "legacy rules are never placed",
			managed: []*placedRule{managedRule("p1", RulePositionPrepend, 1, 0, lan, 0)},
			locals:  []*placedRule{{uuid: "legacy", name: "legacy", section: lan, legacy: true, enabled: true}},
			want:    map[string]int{"p1": 100},
		},
		{
			name:    "a section without local rules: PREPEND by hundreds, APPEND after them",
			managed: []*placedRule{managedRule("a1", RulePositionAppend, 1, 0, sectionFloating, 0), managedRule("p1", RulePositionPrepend, 1, 1, sectionFloating, 0), managedRule("p2", RulePositionPrepend, 2, 2, sectionFloating, 0)},
			want:    map[string]int{"p1": 100, "p2": 200, "a1": 300},
		},
		{
			name: "local rules of another section are not touched",
			managed: []*placedRule{
				managedRule("p1", RulePositionPrepend, 1, 0, sectionFloating, 0),
			},
			locals: []*placedRule{localRule("allow4", lan, 1)},
			want:   map[string]int{"p1": 100},
		},
		{
			name: "equal priorities keep the payload order",
			managed: []*placedRule{
				managedRule("second", RulePositionPrepend, 100, 1, lan, 0),
				managedRule("first", RulePositionPrepend, 100, 0, lan, 0),
			},
			locals: []*placedRule{localRule("gui", lan, 301)},
			want:   map[string]int{"first": 100, "second": 200},
		},
		{
			name: "APPEND rules run out of room near the highest sequence",
			managed: func() []*placedRule {
				var out []*placedRule
				for i := 0; i < 12; i++ {
					out = append(out, managedRule(string(rune('a'+i)), RulePositionAppend, i, i, lan, 0))
				}
				return out
			}(),
			locals: []*placedRule{localRule("high", lan, 999990)},
			want:   map[string]int{"a": 999991, "b": 999992, "c": 999993, "d": 999994, "e": 999995, "f": 999996, "g": 999997, "h": 999998, "i": 999999},
			noRoom: []string{"j", "k", "l"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan := planRulePlacement(tc.managed, tc.locals)
			if !reflect.DeepEqual(plan.sequence, tc.want) {
				t.Errorf("sequences = %v, want %v", plan.sequence, tc.want)
			}
			if !reflect.DeepEqual(plan.moves, tc.wantMoves) {
				t.Errorf("moves = %+v, want %+v", plan.moves, tc.wantMoves)
			}
			var noRoom []string
			for uuid := range plan.noRoom {
				noRoom = append(noRoom, uuid)
			}
			if !reflect.DeepEqual(sortedKeys(plan.noRoom), tc.noRoom) && !(len(noRoom) == 0 && len(tc.noRoom) == 0) {
				t.Errorf("no room = %v, want %v", sortedKeys(plan.noRoom), tc.noRoom)
			}
		})
	}
}

// TestPlanRulePlacement_FixedLocalRule: when a local rule cannot be moved, the
// PREPEND rules are placed right after it, as close to the front as they get.
func TestPlanRulePlacement_FixedLocalRule(t *testing.T) {
	stuck := localRule("allow4", sectionInterface, 1)
	stuck.fixed = true
	plan := planRulePlacement(
		[]*placedRule{managedRule("p1", RulePositionPrepend, 1, 0, sectionInterface, 0)},
		[]*placedRule{stuck, localRule("allow6", sectionInterface, 11)},
	)
	if plan.sequence["p1"] != 6 || len(plan.moves) != 0 {
		t.Errorf("sequence = %d, moves = %+v; want p1 between the stuck rule (1) and the next (11), nothing moved", plan.sequence["p1"], plan.moves)
	}
}

// TestPushLocals_HighestSequence: a push that would take a local rule past the
// highest sequence OPNsense accepts does not happen.
func TestPushLocals_HighestSequence(t *testing.T) {
	locals := []*placedRule{localRule("a", sectionInterface, maxRuleSequence-1), localRule("b", sectionInterface, maxRuleSequence)}
	if moves, ok := pushLocals(locals, maxRuleSequence-1); ok {
		t.Errorf("pushLocals = %+v, ok; want no push past %d", moves, maxRuleSequence)
	}
}

// TestNaturalCompare pins OPNsense's order of two rules of one section and
// sequence: the expected signs are what PHP's ksort(SORT_NATURAL |
// SORT_FLAG_CASE) gives over ArrayField::sortedBy's key for each pair. The
// implementation agreed with PHP on 100,000 random UUID pairs, 13.7% of which
// byte order puts the other way round.
func TestNaturalCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2abc0000-0000-4000-8000-000000000001", "10bc0000-0000-4000-8000-000000000001", -1},
		{"9f000000-0000-4000-8000-000000000001", "10000000-0000-4000-8000-000000000001", -1},
		{"7179a1de-88f9-428f-a5b7-d4814890be9f", "651c4e72-1a2d-494b-b1ed-2a89b26888d6", 1},
		{"0d5bec00-0000-4000-8000-00000000a001", "221f3268-0000-4000-8000-000000000001", -1},
		{"a1111111-0000-4000-8000-000000000001", "9bbbbbbb-0000-4000-8000-000000000001", 1},
		{"00ab0000-0000-4000-8000-000000000001", "0ab00000-0000-4000-8000-000000000001", 1},
		{"01230000-0000-4000-8000-000000000001", "1230a000-0000-4000-8000-000000000001", -1},
		{"a0010000-0000-4000-8000-000000000001", "a01b0000-0000-4000-8000-000000000001", -1},
		{"ABCD0000-0000-4000-8000-000000000001", "abce0000-0000-4000-8000-000000000001", -1},
		{"12345678-0000-4000-8000-000000000001", "12345678-0000-4000-8000-00000000001a", -1},
		{"Ab000000-0000-4000-8000-000000000001", "aa000000-0000-4000-8000-000000000001", 1},
		{"aB000000-0000-4000-8000-000000000001", "Aa000000-0000-4000-8000-000000000001", 1},
	}
	for _, tc := range cases {
		if got := naturalCompare(tc.a, tc.b); got != tc.want {
			t.Errorf("naturalCompare(%s, %s) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
		if got := naturalCompare(tc.b, tc.a); got != -tc.want {
			t.Errorf("naturalCompare(%s, %s) = %d, want %d", tc.b, tc.a, got, -tc.want)
		}
	}
	if got := naturalCompare(defaultAllow4, defaultAllow4); got != 0 {
		t.Errorf("a UUID against itself = %d", got)
	}
}

func TestRuleReachOverlaps(t *testing.T) {
	topology := labTopology()
	reach := func(interfaces string, not bool) ruleReach { return topology.reach(splitInterfaces(interfaces), not) }
	cases := []struct {
		name string
		a, b ruleReach
		want bool
	}{
		{"every interface", reach("", false), reach("wan", false), true},
		{"two inverted selections", reach("lan", true), reach("wan", true), true},
		{"inverted, not excluding the other's interface", reach("wan", true), reach("lan", false), true},
		{"inverted, excluding the other's interface", reach("lan", true), reach("lan", false), false},
		{"disjoint interfaces", reach("lan", false), reach("wan,opt1", false), false},
		{"a group holding the interface", reach("dmz_group", false), reach("opt1", false), true},
	}
	for _, tc := range cases {
		if got := tc.a.overlaps(tc.b); got != tc.want {
			t.Errorf("%s: overlaps = %v, want %v", tc.name, got, tc.want)
		}
		if got := tc.b.overlaps(tc.a); got != tc.want {
			t.Errorf("%s, the other way round: overlaps = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestPlanRulePlacement_ConvergesAfterItsOwnPlan: placing again from the state a
// plan produced changes nothing.
func TestPlanRulePlacement_ConvergesAfterItsOwnPlan(t *testing.T) {
	managed := []*placedRule{
		managedRule("p1", RulePositionPrepend, 1, 0, sectionInterface, 0),
		managedRule("p2", RulePositionPrepend, 2, 1, sectionInterface, 0),
		managedRule("a1", RulePositionAppend, 1, 2, sectionInterface, 0),
	}
	locals := []*placedRule{localRule("allow4", sectionInterface, 1), localRule("allow6", sectionInterface, 11)}

	first := planRulePlacement(managed, locals)
	for _, m := range managed {
		m.current = first.sequence[m.uuid]
	}
	for _, mv := range first.moves {
		for _, l := range locals {
			if l.uuid == mv.uuid {
				l.current = mv.to
			}
		}
	}

	second := planRulePlacement(managed, locals)
	if len(second.moves) != 0 || !reflect.DeepEqual(second.sequence, first.sequence) {
		t.Errorf("second plan = %+v, want the first one's sequences and no moves", second)
	}
}

func TestPlacementWarnings(t *testing.T) {
	topology := labTopology()
	at := func(uuid string, position RulePosition, priority int, interfaces string, not bool) *placedRule {
		keys := splitInterfaces(interfaces)
		return &placedRule{uuid: uuid, name: uuid, position: position, priority: priority,
			section: topology.section(keys, not), reach: topology.reach(keys, not)}
	}
	local := func(uuid, interfaces string, not, enabled, legacy bool) *placedRule {
		keys := splitInterfaces(interfaces)
		return &placedRule{uuid: uuid, name: uuid, section: topology.section(keys, not), reach: topology.reach(keys, not), enabled: enabled, legacy: legacy}
	}
	held := func(r *placedRule) *placedRule { r.held, r.fixed = true, true; return r }
	unranked := func(r *placedRule) *placedRule { r.section = 0; return r }
	label := func(uuid string) string { return "Rule " + uuid }

	cases := []struct {
		name    string
		managed []*placedRule
		locals  []*placedRule
		want    []string // "code uuid"
	}{
		{"a floating local rule ahead of a lan PREPEND rule", []*placedRule{at("m", RulePositionPrepend, 1, "lan", false)},
			[]*placedRule{local("float", "", false, true, false)}, []string{"RULE_PREPEND_AFTER_LOCAL m"}},
		{"a disabled one is silent", []*placedRule{at("m", RulePositionPrepend, 1, "lan", false)},
			[]*placedRule{local("float", "", false, false, false)}, nil},
		{"a multi-interface local rule naming lan", []*placedRule{at("m", RulePositionPrepend, 1, "lan", false)},
			[]*placedRule{local("multi", "lan,wan", false, true, false)}, []string{"RULE_PREPEND_AFTER_LOCAL m"}},
		{"a multi-interface local rule not naming lan", []*placedRule{at("m", RulePositionPrepend, 1, "lan", false)},
			[]*placedRule{local("multi", "wan,opt1", false, true, false)}, nil},
		{"an inverted local rule not excluding lan", []*placedRule{at("m", RulePositionPrepend, 1, "lan", false)},
			[]*placedRule{local("notwan", "wan", true, true, false)}, []string{"RULE_PREPEND_AFTER_LOCAL m"}},
		{"an inverted local rule excluding lan", []*placedRule{at("m", RulePositionPrepend, 1, "lan", false)},
			[]*placedRule{local("notlan", "lan", true, true, false)}, nil},
		{"a group rule holding the interface", []*placedRule{at("m", RulePositionPrepend, 1, "opt1", false)},
			[]*placedRule{local("dmz", "dmz_group", false, true, false)}, []string{"RULE_PREPEND_AFTER_LOCAL m"}},
		{"a group rule not holding it", []*placedRule{at("m", RulePositionPrepend, 1, "lan", false)},
			[]*placedRule{local("dmz", "dmz_group", false, true, false)}, nil},
		{"a later-section local rule after a floating APPEND", []*placedRule{at("m", RulePositionAppend, 1, "lan,opt1", false)},
			[]*placedRule{local("lanonly", "lan", false, true, false)}, []string{"RULE_APPEND_BEFORE_LOCAL m"}},
		{"a legacy local rule of the same section after an APPEND", []*placedRule{at("m", RulePositionAppend, 1, "lan", false)},
			[]*placedRule{local("legacy", "lan", false, true, true)}, []string{"RULE_APPEND_BEFORE_LOCAL m"}},
		{"a legacy local rule of the same section after a PREPEND", []*placedRule{at("m", RulePositionPrepend, 1, "lan", false)},
			[]*placedRule{local("legacy", "lan", false, true, true)}, nil},
		{"managed rules inverted across sections", []*placedRule{at("lanrule", RulePositionPrepend, 10, "lan", false), at("floater", RulePositionPrepend, 20, "", false)},
			nil, []string{"RULE_SECTION_ORDER floater"}},
		{"managed rules in order across sections", []*placedRule{at("floater", RulePositionPrepend, 10, "", false), at("lanrule", RulePositionPrepend, 20, "lan", false)},
			nil, nil},
		{"managed rules inverted but disjoint", []*placedRule{at("lanrule", RulePositionPrepend, 10, "lan", false), at("other", RulePositionPrepend, 20, "wan,opt1", false)},
			nil, nil},
		{"a rule without a position warns as PREPEND", []*placedRule{at("m", "", 1, "lan", false)},
			[]*placedRule{local("float", "", false, true, false)}, []string{"RULE_PREPEND_AFTER_LOCAL m"}},
		{"a held managed rule is silent", []*placedRule{at("m", RulePositionPrepend, 1, "lan", false)},
			[]*placedRule{held(local("refused", "", false, true, false))}, nil},
		{"a row of unknown section is silent", []*placedRule{at("m", RulePositionPrepend, 1, "lan", false)},
			[]*placedRule{unranked(local("odd", "lan", false, true, false))}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, w := range placementWarnings(tc.managed, tc.locals, label) {
				got = append(got, w.code+" "+w.uuid)
				if !strings.HasPrefix(w.message, "Rule ") {
					t.Errorf("message %q does not name the rule", w.message)
				}
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("warnings = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestPlacementWarnings_SectionOrderOncePerRule: a rule OPNsense evaluates
// ahead of several rules meant to come first is reported once, naming them.
func TestPlacementWarnings_SectionOrderOncePerRule(t *testing.T) {
	topology := labTopology()
	at := func(uuid string, priority int, interfaces string) *placedRule {
		keys := splitInterfaces(interfaces)
		return &placedRule{uuid: uuid, name: uuid, position: RulePositionPrepend, priority: priority,
			section: topology.section(keys, false), reach: topology.reach(keys, false)}
	}
	warnings := placementWarnings(
		[]*placedRule{at("lan1", 10, "lan"), at("lan2", 20, "lan"), at("floater", 30, "")},
		nil, func(uuid string) string { return "Rule " + uuid },
	)
	if len(warnings) != 1 || warnings[0].uuid != "floater" || warnings[0].code != codeRuleSectionOrder {
		t.Fatalf("warnings = %+v, want one %s for floater", warnings, codeRuleSectionOrder)
	}
	if !strings.HasPrefix(warnings[0].message, "Rule floater comes after Rule lan1, Rule lan2 by position and priority") {
		t.Errorf("message = %q", warnings[0].message)
	}
}

// TestPlacementWarnings_SectionOrderNamesAtMostTheCap: a rule OPNsense
// evaluates ahead of many rules meant to come first names the first of them
// and counts the rest.
func TestPlacementWarnings_SectionOrderNamesAtMostTheCap(t *testing.T) {
	topology := labTopology()
	at := func(uuid string, priority int, interfaces string) *placedRule {
		keys := splitInterfaces(interfaces)
		return &placedRule{uuid: uuid, name: uuid, position: RulePositionPrepend, priority: priority,
			section: topology.section(keys, false), reach: topology.reach(keys, false)}
	}
	var managed []*placedRule
	for i := 0; i < optionListCap+5; i++ {
		managed = append(managed, at(fmt.Sprintf("lan%02d", i), i, "lan"))
	}
	managed = append(managed, at("floater", 1000, ""))

	warnings := placementWarnings(managed, nil, func(uuid string) string { return "Rule " + uuid })

	if len(warnings) != 1 || warnings[0].uuid != "floater" {
		t.Fatalf("warnings = %+v, want one for floater", warnings)
	}
	if want := "Rule lan14 and 5 more by position and priority"; !strings.Contains(warnings[0].message, want) {
		t.Errorf("message = %q, want it to end the list with %q", warnings[0].message, want)
	}
	if strings.Contains(warnings[0].message, "Rule lan15") {
		t.Errorf("message names more than %d rules: %q", optionListCap, warnings[0].message)
	}
}

// TestSameInterfaces: a row is bound like a desired rule when it names the
// same interfaces, in any order, inverted or not alike.
func TestSameInterfaces(t *testing.T) {
	row := map[string]interface{}{"interface": "wan,lan", "interfacenot": "0"}
	if !sameInterfaces(row, []string{"lan", "wan"}, false) {
		t.Error("the same interfaces in another order differ")
	}
	if sameInterfaces(row, []string{"lan", "wan"}, true) {
		t.Error("an inverted selection of the same interfaces is the same binding")
	}
	if sameInterfaces(row, []string{"lan"}, false) {
		t.Error("fewer interfaces are the same binding")
	}
}

func TestFillOpen(t *testing.T) {
	cases := []struct {
		current []int
		lo      int
		want    []int
	}{
		{[]int{0, 0, 0}, 0, []int{100, 200, 300}},
		{[]int{100, 200}, 0, []int{100, 200}},
		{[]int{0, 200}, 0, []int{100, 200}},
		{[]int{300, 200}, 0, []int{300, 400}},
		{[]int{0}, 999950, []int{999951}},
		{[]int{0, 0}, 999999, []int{0, 0}},
	}
	for _, tc := range cases {
		if got := fillOpen(tc.current, tc.lo); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("fillOpen(%v, %d) = %v, want %v", tc.current, tc.lo, got, tc.want)
		}
	}
}

// TestRecreatedByTheMove pins what the read after a renumber counts: a row was
// re-created when it kept none of the rule's own values and one of them is
// back at its default. The placement fields and the audit record never count,
// even when they come back at their defaults, and even when a release answers
// the audit record as a string.
func TestRecreatedByTheMove(t *testing.T) {
	template := ruleTemplate(t)
	template["audit"] = ""
	s := newRuleSync(nil, nil, nil, nil, nil, opnapi.ParseEntityModel(template))
	row := func(changes map[string]string) map[string]string {
		values := s.model.Values()
		for k, v := range changes {
			values[k] = v
		}
		return values
	}
	cases := []struct {
		name          string
		before, after map[string]string
		want          bool
	}{
		{"moved to the template's default sequence", row(map[string]string{"sequence": "7"}), row(map[string]string{"sequence": "200"}), false},
		{"sort_order and prio_group back at their defaults",
			row(map[string]string{"sort_order": "400000.0000007", "prio_group": "400000"}), row(nil), false},
		{"the audit record back at its default", row(map[string]string{"audit": "eyJjcmVhdGVkIjp7fX0="}), row(nil), false},
		{"the description back at its default",
			row(map[string]string{"description": "Allow LAN", "sequence": "7"}), row(map[string]string{"sequence": "8"}), true},
		{"one of the rule's own values kept",
			row(map[string]string{"description": "Allow LAN", "interface": "lan"}), row(map[string]string{"interface": "lan"}), false},
		{"a floating rule re-created, its section unchanged",
			row(map[string]string{"action": "block", "description": "x", "prio_group": "200000"}), row(map[string]string{"prio_group": "200000"}), true},
	}
	for _, tc := range cases {
		if got := s.recreatedByTheMove(tc.before, tc.after); got != tc.want {
			t.Errorf("%s: recreatedByTheMove = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestReadRule_ARealRead: readRule takes a rule as a 26.7 device answers
// getRule/<uuid> (captured from the lab's default LAN allow rule, lab values
// replaced), display values included. The fields the reads are compared on
// are the template's less the placement fields: 53.
func TestReadRule_ARealRead(t *testing.T) {
	raw := ruleFixture(t, "get-rule-lan-allow-26.7.json")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/firewall/filter/getRule/"+defaultAllow4 {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(raw)
	}))
	t.Cleanup(server.Close)
	s := newRuleSync(opnapi.NewClient(server.URL, "key", "secret", true), nil, nil, nil, nil, ruleModel26(t))

	values, found, err := s.readRule(context.Background(), defaultAllow4)
	if err != nil || !found {
		t.Fatalf("readRule: found=%v err=%v", found, err)
	}
	for field, want := range map[string]string{"interface": "lan", "description": "Default allow LAN to any rule", "source_net": "lan", "action": "pass", "sequence": "1"} {
		if values[field] != want {
			t.Errorf("%s = %q, want %q", field, values[field], want)
		}
	}

	var want []string
	for name := range ruleTemplate(t) {
		if name != "sequence" && name != "sort_order" && name != "prio_group" {
			want = append(want, name)
		}
	}
	sort.Strings(want)
	if got := s.comparedFields(); len(got) != 53 || !reflect.DeepEqual(got, want) {
		t.Errorf("comparedFields = %d %v\nwant the template less the placement fields: %d %v", len(got), got, len(want), want)
	}
}
