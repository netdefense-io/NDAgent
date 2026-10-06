package tasks

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// Rule placement decides the sequence of every managed rule, so PREPEND and
// APPEND mean what users expect: OPNsense evaluates a ruleset section by
// section (floating, then interface groups, then single interfaces) and, inside
// a section, MVC rules by sequence before legacy rules. NetDefense orders rules
// inside a section, never across sections.
//
// Inside a section the order is the PREPEND rules, then the local MVC rules in
// their current order, then the APPEND rules. When the PREPEND rules do not fit
// below the first local rule, the local rules are pushed up, keeping their
// order: that is the one thing NetDefense ever changes on a rule it does not
// own, and only its sequence.

// OPNsense's rule sections (FilterRuleField::getPriority): a rule bound to no
// interface, to several, or to an inverted selection is floating; one bound to
// a single interface group ranks by the group's sequence; one bound to a single
// interface comes last.
const (
	sectionFloating  = 200000
	sectionGroups    = 300000
	sectionInterface = 400000

	// maxRuleSequence is the largest sequence OPNsense accepts.
	maxRuleSequence = 999999
	// sequenceStep spaces new rules, leaving room for later ones.
	sequenceStep = 100
)

// Result codes of rule placement.
const (
	codeRuleNoSequenceRoom          = "RULE_NO_SEQUENCE_ROOM"
	codeRuleLocalRenumberFailed     = "RULE_LOCAL_RENUMBER_FAILED"
	codeRuleLocalRenumberUnverified = "RULE_LOCAL_RENUMBER_UNVERIFIED"
	codeRuleLocalRenumbered         = "RULE_LOCAL_RENUMBERED"
	codeRuleLocalVanished           = "RULE_LOCAL_VANISHED"
	codeRulePrependAfterLocal       = "RULE_PREPEND_AFTER_LOCAL"
	codeRuleAppendBeforeLocal       = "RULE_APPEND_BEFORE_LOCAL"
	codeRuleSectionOrder            = "RULE_SECTION_ORDER"
	codeRuleSectionMismatch         = "RULE_SECTION_MISMATCH"
	codeRulePlacementUnavailable    = "RULE_PLACEMENT_UNAVAILABLE"
	codeRulePlacementUnverified     = "RULE_PLACEMENT_UNVERIFIED"
	codeRuleApplyWithheld           = "RULE_APPLY_WITHHELD"
)

// ruleTopology is what decides a rule's section: which interface keys are
// groups, with each group's sequence and members.
type ruleTopology struct {
	groups map[string]opnapi.InterfaceGroup
}

// newRuleTopology joins the interface types with the group list. A group the
// list does not name ranks at sequence 0, as OPNsense ranks it.
func newRuleTopology(types map[string]string, groups []opnapi.InterfaceGroup) ruleTopology {
	byName := make(map[string]opnapi.InterfaceGroup, len(groups))
	for _, g := range groups {
		byName[g.Name] = g
	}
	topology := ruleTopology{groups: map[string]opnapi.InterfaceGroup{}}
	for key, kind := range types {
		if kind != "group" {
			continue
		}
		group := byName[key]
		group.Name = key
		topology.groups[key] = group
	}
	return topology
}

// section is the section OPNsense ranks a rule bound to these interfaces in.
func (t ruleTopology) section(interfaces []string, interfaceNot bool) int {
	if len(interfaces) != 1 || interfaceNot {
		return sectionFloating
	}
	if group, ok := t.groups[interfaces[0]]; ok {
		return sectionGroups + group.Sequence
	}
	return sectionInterface
}

// ruleReach is the traffic a rule can match, by interface: every interface,
// every interface but some, or some. A group stands for its members too.
type ruleReach struct {
	all  bool
	not  bool
	keys map[string]bool
}

func (t ruleTopology) reach(interfaces []string, interfaceNot bool) ruleReach {
	if len(interfaces) == 0 {
		return ruleReach{all: true}
	}
	keys := map[string]bool{}
	for _, key := range interfaces {
		keys[key] = true
		for _, member := range t.groups[key].Members {
			keys[member] = true
		}
	}
	return ruleReach{not: interfaceNot, keys: keys}
}

// overlaps reports whether two rules can match the same traffic.
func (r ruleReach) overlaps(o ruleReach) bool {
	switch {
	case r.all || o.all:
		return true
	case r.not && o.not:
		return true
	case r.not:
		return hasKeyOutside(o.keys, r.keys)
	case o.not:
		return hasKeyOutside(r.keys, o.keys)
	}
	for key := range r.keys {
		if o.keys[key] {
			return true
		}
	}
	return false
}

func hasKeyOutside(keys, excluded map[string]bool) bool {
	for key := range keys {
		if !excluded[key] {
			return true
		}
	}
	return false
}

// placedRule is one rule as placement sees it.
type placedRule struct {
	uuid     string
	name     string
	section  int
	position RulePosition // managed rules only
	priority int          // managed rules only
	order    int          // a managed rule's place in the payload
	// current is the rule's sequence now, in this section; 0 when it has
	// none there.
	current int
	// fixed marks a local rule OPNsense refused to re-save: it keeps its
	// sequence.
	fixed bool
	// held marks a managed rule this pass refused before writing it: it
	// stays where it is, placed around as a fixed local rule, and is never
	// reported as one.
	held    bool
	enabled bool
	legacy  bool
	reach   ruleReach
}

// localMove is a local rule placement pushes up.
type localMove struct {
	uuid string
	name string
	from int
	to   int
}

// rulePlan is where placement puts the rules.
type rulePlan struct {
	sequence map[string]int  // managed rule -> sequence
	noRoom   map[string]bool // managed rules no sequence is left for
	moves    []localMove
}

// planRulePlacement places the managed rules of every section among the local
// MVC rules of that section. Legacy rules are never placed: OPNsense evaluates
// them after every MVC rule of their section.
func planRulePlacement(managed, locals []*placedRule) rulePlan {
	plan := rulePlan{sequence: map[string]int{}, noRoom: map[string]bool{}}

	bySection := map[int][]*placedRule{}
	for _, r := range managed {
		bySection[r.section] = append(bySection[r.section], r)
	}
	sections := make([]int, 0, len(bySection))
	for s := range bySection {
		sections = append(sections, s)
	}
	sort.Ints(sections)

	for _, s := range sections {
		var prepend, appendRules, sectionLocals []*placedRule
		for _, r := range bySection[s] {
			if r.position == RulePositionAppend {
				appendRules = append(appendRules, r)
			} else {
				prepend = append(prepend, r)
			}
		}
		sortManaged(prepend)
		sortManaged(appendRules)
		for _, l := range locals {
			if l.section == s && !l.legacy {
				sectionLocals = append(sectionLocals, l)
			}
		}
		sortLocals(sectionLocals)
		placeSection(prepend, appendRules, sectionLocals, &plan)
	}
	return plan
}

// sortManaged orders managed rules by priority; equal priorities keep the
// payload order, which the control plane already breaks by snippet name.
func sortManaged(rules []*placedRule) {
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].priority != rules[j].priority {
			return rules[i].priority < rules[j].priority
		}
		return rules[i].order < rules[j].order
	})
}

// sortLocals orders local rules as OPNsense evaluates them: by sequence, ties
// broken by UUID in OPNsense's order (naturalCompare).
func sortLocals(rules []*placedRule) {
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].current != rules[j].current {
			return rules[i].current < rules[j].current
		}
		return naturalCompare(rules[i].uuid, rules[j].uuid) < 0
	})
}

// naturalCompare orders two rules of one section and sequence the way
// OPNsense does. It sorts a ruleset with PHP's ksort(SORT_NATURAL |
// SORT_FLAG_CASE) on a key that ends in the rule's UUID (ArrayField::sortedBy),
// so for a tie the UUIDs compare as strnatcasecmp compares them: a run of
// digits as a number ("2abc..." before "10bc...", where byte order puts
// "10bc..." first), or digit by digit when either run starts with a zero, and
// anything else by upper-cased byte.
func naturalCompare(a, b string) int {
	i, j := 0, 0
	for {
		if i < len(a) && j < len(b) && isASCIIDigit(a[i]) && isASCIIDigit(b[j]) {
			var r int
			if a[i] == '0' || b[j] == '0' {
				r, i, j = compareDigitsLeft(a, i, b, j)
			} else {
				r, i, j = compareDigitsRight(a, i, b, j)
			}
			if r != 0 {
				return r
			}
		}
		switch {
		case i >= len(a) && j >= len(b):
			return 0
		case i >= len(a):
			return -1
		case j >= len(b):
			return 1
		}
		if ca, cb := asciiUpper(a[i]), asciiUpper(b[j]); ca != cb {
			if ca < cb {
				return -1
			}
			return 1
		}
		i++
		j++
	}
}

// compareDigitsRight compares two runs of digits as numbers: the longer run is
// greater, else the first differing digit decides.
func compareDigitsRight(a string, i int, b string, j int) (int, int, int) {
	bias := 0
	for ; ; i, j = i+1, j+1 {
		aDigit, bDigit := i < len(a) && isASCIIDigit(a[i]), j < len(b) && isASCIIDigit(b[j])
		switch {
		case !aDigit && !bDigit:
			return bias, i, j
		case !aDigit:
			return -1, i, j
		case !bDigit:
			return 1, i, j
		case bias == 0 && a[i] < b[j]:
			bias = -1
		case bias == 0 && a[i] > b[j]:
			bias = 1
		}
	}
}

// compareDigitsLeft compares two runs of digits digit by digit, as decimal
// fractions: the first differing digit decides, and a run that ends first is
// smaller.
func compareDigitsLeft(a string, i int, b string, j int) (int, int, int) {
	for ; ; i, j = i+1, j+1 {
		aDigit, bDigit := i < len(a) && isASCIIDigit(a[i]), j < len(b) && isASCIIDigit(b[j])
		switch {
		case !aDigit && !bDigit:
			return 0, i, j
		case !aDigit:
			return -1, i, j
		case !bDigit:
			return 1, i, j
		case a[i] < b[j]:
			return -1, i, j
		case a[i] > b[j]:
			return 1, i, j
		}
	}
}

func isASCIIDigit(c byte) bool { return c >= '0' && c <= '9' }

func asciiUpper(c byte) byte {
	if c >= 'a' && c <= 'z' {
		return c - 'a' + 'A'
	}
	return c
}

func placeSection(prepend, appendRules, locals []*placedRule, plan *rulePlan) {
	assign := func(rules []*placedRule, seqs []int) {
		for i, r := range rules {
			if seqs[i] == 0 {
				plan.noRoom[r.uuid] = true
				continue
			}
			plan.sequence[r.uuid] = seqs[i]
		}
	}

	if len(locals) == 0 {
		pSeqs := fillOpen(currents(prepend), 0)
		assign(prepend, pSeqs)
		assign(appendRules, fillOpen(currents(appendRules), lastPlaced(pSeqs, 0)))
		return
	}

	final := make([]int, len(locals))
	for i, l := range locals {
		final[i] = l.current
	}
	appendFloor := 0
	if len(prepend) > 0 {
		pSeqs, moves, afterAll := placePrepend(prepend, locals)
		assign(prepend, pSeqs)
		for _, mv := range moves {
			for i, l := range locals {
				if l.uuid == mv.uuid {
					final[i] = mv.to
				}
			}
		}
		plan.moves = append(plan.moves, moves...)
		if afterAll {
			appendFloor = lastPlaced(pSeqs, 0)
		}
	}
	for _, seq := range final {
		appendFloor = max(appendFloor, seq)
	}
	assign(appendRules, fillOpen(currents(appendRules), appendFloor))
}

// placePrepend puts the PREPEND rules before the first local rule. When they do
// not fit below it, they take the lowest sequences and the local rules are
// pushed up just enough, in order. When a local rule that must move cannot
// (OPNsense refused to re-save it), the PREPEND rules go as close to the front
// as they can: after the local rules they cannot get ahead of.
func placePrepend(prepend, locals []*placedRule) (seqs []int, moves []localMove, afterAll bool) {
	for j := 0; j <= len(locals); j++ {
		lo := 0
		if j > 0 {
			lo = locals[j-1].current
		}
		if j == len(locals) {
			return fillOpen(currents(prepend), lo), nil, true
		}
		hi := locals[j].current
		if len(prepend) <= hi-lo-1 {
			return fillBounded(currents(prepend), lo, hi), nil, false
		}
		if moves, ok := pushLocals(locals[j:], lo+len(prepend)); ok {
			seqs = make([]int, len(prepend))
			for i := range seqs {
				seqs[i] = lo + i + 1
			}
			return seqs, moves, false
		}
	}
	return nil, nil, true
}

// pushLocals raises the local rules to just above floor, keeping their order,
// and reports false when a rule that would have to move cannot. Rules tied at
// one sequence move together, so OPNsense's own tie-break keeps ordering
// them, and the push ends at the first rule already above the one before it.
func pushLocals(locals []*placedRule, floor int) ([]localMove, bool) {
	var moves []localMove
	prev := floor
	for i := 0; i < len(locals); {
		j := i
		for j < len(locals) && locals[j].current == locals[i].current {
			j++
		}
		want := max(locals[i].current, prev+1)
		if want == locals[i].current {
			break
		}
		for _, l := range locals[i:j] {
			if l.fixed || want > maxRuleSequence {
				return nil, false
			}
			moves = append(moves, localMove{uuid: l.uuid, name: l.name, from: l.current, to: want})
		}
		prev = want
		i = j
	}
	return moves, true
}

func currents(rules []*placedRule) []int {
	out := make([]int, len(rules))
	for i, r := range rules {
		out[i] = r.current
	}
	return out
}

// lastPlaced is the last sequence handed out, or floor when none was.
func lastPlaced(seqs []int, floor int) int {
	last := floor
	for _, s := range seqs {
		if s > last {
			last = s
		}
	}
	return last
}

// keptInOrder marks the longest run of current sequences, inside (lo, hi) and
// already increasing in the target order: those rules keep their sequence.
func keptInOrder(current []int, lo, hi int) []bool {
	n := len(current)
	length := make([]int, n)
	prev := make([]int, n)
	best := -1
	for i := 0; i < n; i++ {
		prev[i] = -1
		if current[i] <= lo || current[i] >= hi {
			continue
		}
		length[i] = 1
		for k := 0; k < i; k++ {
			if length[k] > 0 && current[k] < current[i] && length[k]+1 > length[i] {
				length[i] = length[k] + 1
				prev[i] = k
			}
		}
		if best == -1 || length[i] > length[best] {
			best = i
		}
	}
	kept := make([]bool, n)
	for i := best; i >= 0; i = prev[i] {
		kept[i] = true
	}
	return kept
}

// fillBounded gives every rule a sequence inside (lo, hi), increasing in
// order: the rules already in order keep theirs, the others go into the gaps,
// evenly spaced, and the whole block is spaced evenly anew only when a gap has
// no room. The caller ensures hi-lo-1 >= len(current).
func fillBounded(current []int, lo, hi int) []int {
	kept := keptInOrder(current, lo, hi)
	if seqs, ok := fillGaps(current, kept, lo, hi); ok {
		return seqs
	}
	n := len(current)
	seqs := make([]int, n)
	for i := range seqs {
		seqs[i] = lo + (hi-lo)*(i+1)/(n+1)
	}
	return seqs
}

// fillGaps keeps the kept rules' sequences and spaces the others evenly
// between their kept neighbours (or lo and hi); ok is false when a gap has no
// room for its rules.
func fillGaps(current []int, kept []bool, lo, hi int) ([]int, bool) {
	seqs := make([]int, len(current))
	left, start := lo, 0
	for i := 0; i <= len(current); i++ {
		if i < len(current) && !kept[i] {
			continue
		}
		right := hi
		if i < len(current) {
			right = current[i]
		}
		k := i - start
		if k > right-left-1 {
			return nil, false
		}
		for m := 1; m <= k; m++ {
			seqs[start+m-1] = left + (right-left)*m/(k+1)
		}
		if i < len(current) {
			seqs[i] = current[i]
			left = current[i]
		}
		start = i + 1
	}
	return seqs, true
}

// fillOpen gives every rule a sequence above lo: the rules already in order
// keep theirs, the ones between kept rules go into the gaps, and the ones after
// the last kept rule follow it sequenceStep apart, or one apart near
// maxRuleSequence. A rule no sequence is left for gets 0.
func fillOpen(current []int, lo int) []int {
	n := len(current)
	kept := keptInOrder(current, lo, maxRuleSequence+1)
	last := -1
	for i := range kept {
		if kept[i] {
			last = i
		}
	}

	seqs := make([]int, n)
	if last >= 0 {
		inner, ok := fillGaps(current[:last+1], kept[:last+1], lo, current[last]+1)
		if !ok {
			return trail(n, lo)
		}
		copy(seqs, inner)
	}
	tail := trail(n-last-1, max(lo, lastPlaced(seqs, lo)))
	copy(seqs[last+1:], tail)
	return seqs
}

// trail hands out n sequences after floor, sequenceStep apart when they fit,
// else one apart; past maxRuleSequence a rule gets 0.
func trail(n, floor int) []int {
	seqs := make([]int, n)
	step := sequenceStep
	if floor+step*n > maxRuleSequence {
		step = 1
	}
	for i := range seqs {
		if seq := floor + step*(i+1); seq <= maxRuleSequence {
			seqs[i] = seq
		}
	}
	return seqs
}

// placementWarning is a rule placement cannot put where its position asks,
// because OPNsense's sections decide.
type placementWarning struct {
	uuid    string
	name    string
	code    string
	message string
}

// placementWarnings reports the managed rules whose position OPNsense's
// sections overrule, against enabled local rules that can match the same
// traffic. A disabled local rule keeps its place but never warns, and neither
// does a managed rule held where it is or a row whose section is unknown.
func placementWarnings(managed, locals []*placedRule, label func(uuid string) string) []placementWarning {
	var warnings []placementWarning

	for _, m := range managed {
		var ahead, behind, legacyBehind []string
		for _, l := range locals {
			if !l.enabled || l.held || l.section == 0 || !l.reach.overlaps(m.reach) {
				continue
			}
			switch {
			case m.position != RulePositionAppend && l.section < m.section:
				ahead = append(ahead, l.name)
			case m.position == RulePositionAppend && l.section > m.section:
				behind = append(behind, l.name)
			case m.position == RulePositionAppend && l.section == m.section && l.legacy:
				legacyBehind = append(legacyBehind, l.name)
			}
		}
		if len(ahead) > 0 {
			warnings = append(warnings, placementWarning{
				uuid: m.uuid, name: m.name, code: codeRulePrependAfterLocal,
				message: fmt.Sprintf("%s is PREPEND, but OPNsense evaluates %s first: floating rules come before interface-group rules, and both before single-interface rules",
					label(m.uuid), describeLocals(ahead)),
			})
		}
		if len(behind) > 0 {
			warnings = append(warnings, placementWarning{
				uuid: m.uuid, name: m.name, code: codeRuleAppendBeforeLocal,
				message: fmt.Sprintf("%s is APPEND, but OPNsense evaluates it before %s: floating rules come before interface-group rules, and both before single-interface rules",
					label(m.uuid), describeLocals(behind)),
			})
		}
		if len(legacyBehind) > 0 {
			warnings = append(warnings, placementWarning{
				uuid: m.uuid, name: m.name, code: codeRuleAppendBeforeLocal,
				message: fmt.Sprintf("%s is APPEND, but OPNsense evaluates it before %s: legacy rules come after every rule of their section; migrate them under Firewall > Migration assistant",
					label(m.uuid), describeLocals(legacyBehind)),
			})
		}
	}

	// Managed rules among themselves: PREPEND before APPEND, each by priority.
	// Across sections OPNsense's order wins; report each rule it moves ahead
	// of overlapping rules meant to come first, once, naming them.
	intended := append([]*placedRule(nil), managed...)
	sort.SliceStable(intended, func(i, j int) bool {
		pi, pj := intended[i].position == RulePositionAppend, intended[j].position == RulePositionAppend
		if pi != pj {
			return !pi
		}
		if intended[i].priority != intended[j].priority {
			return intended[i].priority < intended[j].priority
		}
		return intended[i].order < intended[j].order
	})
	for i, second := range intended {
		var meantFirst []string
		count := 0
		for _, first := range intended[:i] {
			if second.section < first.section && second.reach.overlaps(first.reach) {
				if count++; count <= optionListCap {
					meantFirst = append(meantFirst, label(first.uuid))
				}
			}
		}
		if count > 0 {
			named := strings.Join(meantFirst, ", ")
			if count > len(meantFirst) {
				named = fmt.Sprintf("%s and %d more", named, count-len(meantFirst))
			}
			warnings = append(warnings, placementWarning{
				uuid: second.uuid, name: second.name, code: codeRuleSectionOrder,
				message: fmt.Sprintf("%s comes after %s by position and priority, but OPNsense evaluates it first: floating rules come before interface-group rules, and both before single-interface rules",
					label(second.uuid), named),
			})
		}
	}
	return warnings
}

func describeLocals(names []string) string {
	sort.Strings(names)
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = fmt.Sprintf("%q", n)
	}
	if len(names) == 1 {
		return "the local rule " + quoted[0]
	}
	return fmt.Sprintf("%d local rules: %s", len(names), capList(quoted, optionListCap))
}

// sectionName names a section as the firewall rules page groups rules.
func sectionName(section int) string {
	switch {
	case section == sectionFloating:
		return "floating rules"
	case section >= sectionGroups && section < sectionInterface:
		return fmt.Sprintf("interface-group rules (group sequence %d)", section-sectionGroups)
	case section == sectionInterface:
		return "single-interface rules"
	}
	return fmt.Sprintf("section %d", section)
}

// rowSequence reads a rule row's sequence, which OPNsense sends as a string.
func rowSequence(row map[string]interface{}) int {
	switch v := row["sequence"].(type) {
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(v))
		return n
	case float64:
		return int(v)
	}
	return 0
}

// rowSection reads the section OPNsense ranked a row in: the prio_group of an
// MVC rule, or the leading number of a legacy row's sort_order.
func rowSection(row map[string]interface{}) int {
	switch v := row["prio_group"].(type) {
	case string:
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	case float64:
		return int(v)
	}
	if order, ok := row["sort_order"].(string); ok {
		head, _, _ := strings.Cut(order, ".")
		n, _ := strconv.Atoi(head)
		return n
	}
	return 0
}

// splitInterfaces reads a comma list of interface keys.
func splitInterfaces(value string) []string {
	var keys []string
	for _, key := range strings.Split(value, ",") {
		if key = strings.TrimSpace(key); key != "" {
			keys = append(keys, key)
		}
	}
	return keys
}
