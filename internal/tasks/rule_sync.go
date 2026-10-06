package tasks

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// ruleSync places and writes the desired rules that passed the pre-flight,
// and collects their results.
type ruleSync struct {
	client   *opnapi.Client
	model    opnapi.EntityModel
	rules    []APIRulePayload
	byUUID   map[string]APIRulePayload
	bodies   map[string]map[string]string
	existed  map[string]bool // managed rules on the device before this SYNC
	held     map[string]bool // desired rules the pre-flight refused
	labelKey map[string]string

	results []SyncAPIItemResult
	errors  []string

	// fixed are the local rules OPNsense refused to re-save this pass.
	fixed map[string]bool
	// gone are the local rules deleted on the device during this SYNC.
	gone map[string]bool
	// moved maps a renumbered local rule to its sequence before this SYNC.
	moved map[string]localMove
	// failed are the managed rules whose write failed, or that no sequence
	// was left for: a second pass leaves them alone.
	failed map[string]bool
	// drift maps a managed rule OPNsense ranks in another section than the
	// interface groups say to {computed, ranked}.
	drift map[string][2]int
	// withheld are the local rules a renumber may have re-created, and that
	// could not be ruled out or removed, each with why: while there are any,
	// the firewall rules are not applied.
	withheld []withheldRule
}

// withheldRule is a local rule the firewall apply waits on, and why, as a
// sentence of the apply's message.
type withheldRule struct {
	name string
	why  string
}

func newRuleSync(client *opnapi.Client, rules []APIRulePayload, bodies map[string]map[string]string, existed, held map[string]bool, model opnapi.EntityModel) *ruleSync {
	labelKey := map[string]string{}
	if field, ok := model.Field("interface"); ok {
		for key, label := range field.Options {
			labelKey[label] = key
		}
	}
	byUUID := make(map[string]APIRulePayload, len(rules))
	for _, r := range rules {
		byUUID[r.UUID] = r
	}
	return &ruleSync{
		client:   client,
		model:    model,
		rules:    rules,
		byUUID:   byUUID,
		bodies:   bodies,
		existed:  existed,
		held:     held,
		labelKey: labelKey,
		fixed:    map[string]bool{},
		gone:     map[string]bool{},
		moved:    map[string]localMove{},
		failed:   map[string]bool{},
		drift:    map[string][2]int{},
	}
}

func (s *ruleSync) label(uuid string) string {
	if r, ok := s.byUUID[uuid]; ok {
		return ruleLabel(r)
	}
	return "Rule " + uuid
}

// run writes the rules. allRules is the device's ruleset as discovered at the
// start of this SYNC.
func (s *ruleSync) run(ctx context.Context, allRules []map[string]interface{}) {
	log := logging.Named("SYNC_API")
	if len(s.rules) == 0 {
		return
	}

	types, typeErr := s.client.GetInterfaceTypes(ctx)
	groups, groupErr := s.client.ListInterfaceGroups(ctx)
	if typeErr != nil || groupErr != nil {
		log.Warnw("SYNC_API: rule placement inputs unavailable; managed rules keep their sequences",
			"interface_list_error", typeErr, "group_list_error", groupErr)
		s.runWithoutPlacement(ctx, allRules, typeErr, groupErr)
		return
	}
	topology := newRuleTopology(types, groups)

	managed, locals := s.placementInputs(topology, allRules)
	plan, locals := s.renumberLocals(ctx, managed, locals)
	written := s.writeManaged(ctx, managed, plan, allRules, nil)

	// OPNsense decides a rule's section itself; check that every rule written
	// landed where placement computed, and place once more from what the
	// device reports if one did not: the rows read hold each rule's section.
	if mismatched, rows := s.misplaced(ctx, written); len(mismatched) > 0 {
		log.Warnw("SYNC_API: rules landed in another section than computed; placing them again", "rules", len(mismatched))
		managed, locals = s.placementInputs(topology, rows)
		plan, locals = s.renumberLocals(ctx, managed, locals)
		for uuid, section := range mismatched {
			written[uuid] = section
		}
		for uuid, section := range s.writeManaged(ctx, managed, plan, rows, written) {
			written[uuid] = section
		}
		stillMisplaced, _ := s.misplaced(ctx, written)
		for _, uuid := range sortedKeys(stillMisplaced) {
			delete(s.drift, uuid)
			msg := fmt.Sprintf("%s: OPNsense put the rule in another section than NetDefense computed, so its place among the local rules is not verified", s.label(uuid))
			s.report(SyncAPIItemResult{Type: "rule_placement", UUID: uuid, Name: s.name(uuid), Action: "verify", Status: "error", Code: codeRulePlacementUnverified, Error: msg}, true)
		}
	}

	for _, uuid := range sortedKeys(s.drift) {
		computed, ranked := s.drift[uuid][0], s.drift[uuid][1]
		msg := fmt.Sprintf("%s: OPNsense ranks it among the %s, while this device's interface groups put it among the %s; it is placed where OPNsense ranks it",
			s.label(uuid), sectionName(ranked), sectionName(computed))
		s.report(SyncAPIItemResult{Type: "rule_placement", UUID: uuid, Name: s.name(uuid), Action: "warning", Status: "warning", Code: codeRuleSectionMismatch, Error: msg}, false)
	}
	s.reportMoves()
	for _, w := range placementWarnings(managed, locals, s.label) {
		s.report(SyncAPIItemResult{Type: "rule_placement", UUID: w.uuid, Name: w.name, Action: "warning", Status: "warning", Code: w.code, Error: w.message}, false)
	}
}

func (s *ruleSync) name(uuid string) string {
	return s.byUUID[uuid].Description
}

// report records a result item; an error also fails the task.
func (s *ruleSync) report(item SyncAPIItemResult, isError bool) {
	s.results = append(s.results, item)
	if isError {
		s.errors = append(s.errors, item.Error)
	}
}

// placementInputs turns the device's rows into what placement works on: the
// managed rules to write, each in the section OPNsense ranks it in, and the
// local rules, MVC and legacy. A managed rule the pre-flight refused stays
// where it is, as a fixed local rule. A managed rule the device holds bound to
// the same interfaces is in the section the device ranks it in; another is in
// the section the interface groups give. A row a renumber re-created, and
// that could not be deleted, is not a local rule.
func (s *ruleSync) placementInputs(topology ruleTopology, rows []map[string]interface{}) (managed, locals []*placedRule) {
	byUUID := map[string]map[string]interface{}{}
	for _, row := range rows {
		uuid, _ := row["uuid"].(string)
		if uuid == "" || s.gone[uuid] {
			continue
		}
		byUUID[uuid] = row
		value, _ := row["interface"].(string)
		not, _ := row["interfacenot"].(string)
		if strings.HasPrefix(uuid, opnapi.NDAgentUUIDPrefix+"-") {
			if s.held[uuid] {
				locals = append(locals, &placedRule{
					uuid: uuid, name: localName(row), section: rowSection(row), current: rowSequence(row),
					fixed: true, held: true, reach: topology.reach(splitInterfaces(value), not == "1"),
				})
			}
			continue
		}
		if legacy, _ := row["legacy"].(bool); legacy {
			// Only a configured legacy rule competes with ours; the rules
			// OPNsense generates are documented, not reported.
			if _, configured := row["seq"].(float64); !configured {
				continue
			}
			locals = append(locals, &placedRule{
				uuid: uuid, name: localName(row), section: rowSection(row), legacy: true, enabled: true,
				reach: topology.reach(s.interfaceKeys(value), false),
			})
			continue
		}
		enabled, _ := row["enabled"].(string)
		locals = append(locals, &placedRule{
			uuid: uuid, name: localName(row), section: rowSection(row), current: rowSequence(row),
			enabled: enabled == "1", fixed: s.fixed[uuid],
			reach: topology.reach(splitInterfaces(value), not == "1"),
		})
	}

	for i, r := range s.rules {
		body := s.bodies[r.UUID]
		interfaces := splitInterfaces(body["interface"])
		not := body["interfacenot"] == "1"
		computed := topology.section(interfaces, not)
		section := computed
		row, exists := byUUID[r.UUID]
		if exists && sameInterfaces(row, interfaces, not) {
			if ranked := rowSection(row); ranked != 0 {
				section = ranked
			}
		}
		if section != computed {
			s.drift[r.UUID] = [2]int{computed, section}
		}
		current := 0
		if exists && rowSection(row) == section {
			current = rowSequence(row)
		}
		managed = append(managed, &placedRule{
			uuid: r.UUID, name: r.Description, section: section, position: r.Position, priority: r.Priority,
			order: i, current: current, reach: topology.reach(interfaces, not),
		})
	}
	return managed, locals
}

// localName names a device row in a message: its description, or its UUID
// when it has none.
func localName(row map[string]interface{}) string {
	if description, _ := row["description"].(string); description != "" {
		return description
	}
	uuid, _ := row["uuid"].(string)
	return uuid
}

// sameInterfaces reports whether a device row binds a rule to these
// interfaces, inverted or not as given, in any order.
func sameInterfaces(row map[string]interface{}, interfaces []string, not bool) bool {
	value, _ := row["interface"].(string)
	rowNot, _ := row["interfacenot"].(string)
	have := splitInterfaces(value)
	if (rowNot == "1") != not || len(have) != len(interfaces) {
		return false
	}
	bound := map[string]bool{}
	for _, key := range have {
		bound[key] = true
	}
	for _, key := range interfaces {
		if !bound[key] {
			return false
		}
	}
	return true
}

// interfaceKeys maps a legacy row's interface labels back to keys; the search
// shows a legacy rule's interfaces by their display names.
func (s *ruleSync) interfaceKeys(value string) []string {
	labels := splitInterfaces(value)
	for i, label := range labels {
		if key, ok := s.labelKey[label]; ok {
			labels[i] = key
		}
	}
	return labels
}

// renumberLocals plans placement and writes the local renumbers it needs, as
// sequence-only writes, highest sequence first: a write never passes a rule
// that has not moved yet, so a renumber that stops part way leaves the local
// rules in their order. A local rule that could not be moved keeps its
// sequence and one deleted on the device drops out; either way placement is
// planned again, and the PREPEND rules go as close to the front as they can.
// It returns the plan and the local rules that are still there.
func (s *ruleSync) renumberLocals(ctx context.Context, managed, locals []*placedRule) (rulePlan, []*placedRule) {
	for {
		plan := planRulePlacement(managed, locals)
		replan := false
		for i := len(plan.moves) - 1; i >= 0 && !replan; i-- {
			mv := plan.moves[i]
			switch s.moveLocal(ctx, mv) {
			case localMoved:
				first, seen := s.moved[mv.uuid]
				if !seen {
					first = mv
				}
				first.to = mv.to
				s.moved[mv.uuid] = first
				for _, l := range locals {
					if l.uuid == mv.uuid {
						l.current = mv.to
					}
				}
			case localStuck:
				s.fixed[mv.uuid] = true
				for _, l := range locals {
					if l.uuid == mv.uuid {
						l.fixed = true
					}
				}
				replan = true
			case localGone:
				s.gone[mv.uuid] = true
				delete(s.moved, mv.uuid)
				kept := locals[:0:0]
				for _, l := range locals {
					if l.uuid != mv.uuid {
						kept = append(kept, l)
					}
				}
				locals = kept
				replan = true
			}
		}
		if !replan {
			return plan, locals
		}
	}
}

// localOutcome is what became of one local renumber.
type localOutcome int

const (
	localMoved localOutcome = iota
	localStuck              // not moved: it keeps its sequence
	localGone               // deleted on the device
)

// moveLocal writes a local rule's new sequence, and nothing else of it.
// setRule creates a rule it does not find, with OPNsense's defaults: a pass
// rule on every interface. So the rule is read first and not written when it
// is gone, and read again after the write, also when the write's answer was
// lost: a row that changed and now holds the defaults is what the write
// created after the rule was deleted on the device, and is deleted again. Any
// other change is reported and left alone, since it was made on the device
// during this SYNC; one that put some of the rule's values back at their
// defaults also withholds the apply, since it may be a re-created rule the
// owner edited since. A move whose answer was lost counts as made only when
// the rule reads at its new sequence: one that reads at another saved
// nothing, and one that cannot be read back is planned where it was.
func (s *ruleSync) moveLocal(ctx context.Context, mv localMove) localOutcome {
	report := func(status, code, msg string) {
		s.report(SyncAPIItemResult{Type: "rule_local", UUID: mv.uuid, Name: mv.name, Action: "renumber", Status: status, Code: code, Error: msg}, status == "error")
	}
	notMoved := func(reason string) localOutcome {
		report("error", codeRuleLocalRenumberFailed, fmt.Sprintf("Local rule %q could not be moved from sequence %d to %d, so the PREPEND rules of its section are placed after it: %s",
			mv.name, mv.from, mv.to, reason))
		return localStuck
	}

	before, found, err := s.readRule(ctx, mv.uuid)
	if err != nil {
		return notMoved(fmt.Sprintf("it could not be read before the move: %v", err))
	}
	if !found {
		report("warning", codeRuleLocalVanished, fmt.Sprintf("Local rule %q was deleted on the device during this SYNC, so it was not moved", mv.name))
		return localGone
	}
	// A rule holding nothing but the defaults is what the write would
	// re-create were the rule deleted meanwhile: the read after it could not
	// tell the two apart, so such a rule is not moved. A reference to
	// something that no longer exists reads as the default too.
	if s.sameRule(before, s.model.Values()) {
		return notMoved("it reads as nothing but OPNsense's defaults (it may name a gateway or schedule that no longer exists), so a rule the move re-created could not be told from it: give it a description, or fix what it names")
	}
	// A refusal with field validations saved nothing. Any other error (a
	// timeout, a dropped connection, a 5xx, an answer that cannot be read)
	// may follow a save, so the rule is read back as after any write.
	writeErr := s.client.SetRule(ctx, mv.uuid, map[string]string{"sequence": strconv.Itoa(mv.to)})
	if _, refused := validationFailure(writeErr); refused {
		return notMoved(renumberFailure(writeErr))
	}

	// After a lost answer the rule's sequence tells whether the write saved,
	// so a read without it is no read.
	readBack := func() (map[string]string, bool, error) {
		after, found, err := s.readRule(ctx, mv.uuid)
		if _, ok := after["sequence"]; err == nil && found && writeErr != nil && !ok {
			err = fmt.Errorf("the device answered without its sequence field")
		}
		return after, found, err
	}
	after, found, err := readBack()
	if err != nil {
		after, found, err = readBack()
	}
	switch {
	case err != nil:
		// Most likely the owner's rule, intact: it is neither deleted nor
		// disabled, but the rules are not applied while it may be a pass rule.
		s.withheld = append(s.withheld, withheldRule{mv.name, fmt.Sprintf(
			"Local rule %q may be a rule its renumber re-created after it was deleted on the device, which could not be ruled out: it could not be read back after the move.", mv.name)})
		rule, moved, recreated := fmt.Sprintf("%q", mv.name), fmt.Sprintf("was moved from sequence %d to %d", mv.from, mv.to), "re-created"
		if writeErr != nil {
			moved = fmt.Sprintf("may have been moved from sequence %d to %d (the answer to the move was lost: %v)", mv.from, mv.to, writeErr)
			recreated = "may have re-created"
			if first, seen := s.moved[mv.uuid]; seen {
				rule = fmt.Sprintf("%q, moved from sequence %d to %d earlier in this SYNC,", mv.name, first.from, first.to)
			}
		}
		report("error", codeRuleLocalRenumberUnverified, fmt.Sprintf("Local rule %s %s, but could not be read back: %v. Had it been deleted on the device meanwhile, the move %s it as a pass rule, so the firewall rules are not applied this SYNC: check the rule on the device",
			rule, moved, err, recreated))
		if writeErr != nil {
			// The move is not known to have happened, so the rules below it
			// are planned around where it was. An earlier move of the rule
			// this SYNC is not reported renumbered either, since this one
			// may have taken it past where that one put it: the item above
			// names it instead.
			delete(s.moved, mv.uuid)
			return localStuck
		}
		return localMoved
	case !found:
		gone := fmt.Sprintf("Local rule %q was deleted on the device during this SYNC, right after NetDefense moved it", mv.name)
		if writeErr != nil {
			gone = fmt.Sprintf("Local rule %q is gone from the device: it was deleted during this SYNC, and the answer to its move was lost (%v), so it may have been deleted before the move or after it. If the move still lands, it re-creates the rule as a pass rule on every interface, with no description: check the device for one", mv.name, writeErr)
		}
		report("warning", codeRuleLocalVanished, gone)
		return localGone
	case writeErr != nil && after["sequence"] != strconv.Itoa(mv.to):
		// The write's answer was lost and it saved nothing: a row it
		// re-created would read at the new sequence.
		return notMoved(renumberFailure(writeErr))
	case s.sameRule(before, after):
		return localMoved
	case s.recreatedByTheMove(before, after):
		return s.removeRecreated(ctx, mv, report)
	}
	if _, reverted := s.ownValues(before, after); reverted {
		s.withheld = append(s.withheld, withheldRule{mv.name, fmt.Sprintf(
			"Local rule %q may be a rule its renumber re-created after it was deleted on the device, which could not be ruled out: it changed during the move, and some of its values are back at OPNsense's defaults.", mv.name)})
		report("error", codeRuleLocalRenumberUnverified, fmt.Sprintf("Local rule %q changed on the device while NetDefense moved it from sequence %d to %d, and some of its values are back at OPNsense's defaults: it may be a rule the move re-created after it was deleted, edited since. It was left as it is, and the firewall rules are not applied this SYNC: check it on the device",
			mv.name, mv.from, mv.to))
		return localMoved
	}
	report("error", codeRuleLocalRenumberUnverified, fmt.Sprintf("Local rule %q changed on the device while NetDefense moved it from sequence %d to %d; it was left as it is, so check it",
		mv.name, mv.from, mv.to))
	return localMoved
}

// readRule reads a rule as getRule/<uuid> answers it. An answer without every
// field the reads are compared on is no read: a missing field would pass for
// one back at its default.
func (s *ruleSync) readRule(ctx context.Context, uuid string) (map[string]string, bool, error) {
	values, found, err := s.client.GetRule(ctx, uuid)
	if err != nil || !found {
		return values, found, err
	}
	for _, name := range s.comparedFields() {
		if _, ok := values[name]; !ok {
			return nil, true, fmt.Errorf("the device answered without its %s field", name)
		}
	}
	return values, true, nil
}

// comparedFields are the fields of the device's rule model two reads of a rule
// are compared on: every field content can set. A renumber changes only the
// placement fields, which RULE ignores, OPNsense stamps its audit record on
// every save, and the containers are no values.
func (s *ruleSync) comparedFields() []string {
	var names []string
	for _, name := range s.model.Names() {
		if field, _ := s.model.Field(name); !ruleContract.skipped(name) && !field.Nested {
			names = append(names, name)
		}
	}
	return names
}

// ownValues compares a rule read after its renumber with the rule read before
// it, on the values the rule held besides the model's defaults: kept reports
// whether one of them is still there, reverted whether one is back at its
// default.
func (s *ruleSync) ownValues(before, after map[string]string) (kept, reverted bool) {
	for _, name := range s.comparedFields() {
		field, _ := s.model.Field(name)
		if before[name] == field.Default {
			continue
		}
		switch after[name] {
		case before[name]:
			kept = true
		case field.Default:
			reverted = true
		}
	}
	return kept, reverted
}

// recreatedByTheMove reports whether a rule read after its renumber is one the
// write created after the rule was deleted on the device: OPNsense's defaults
// hold in every field, so none of the values the rule held besides the
// defaults is still there, and at least one is back at its default; whatever
// the device owner edited since may differ. A rule that kept even one of its
// own values is the owner's, edited.
func (s *ruleSync) recreatedByTheMove(before, after map[string]string) bool {
	kept, reverted := s.ownValues(before, after)
	return reverted && !kept
}

// removeRecreated takes out a rule a renumber re-created: OPNsense's defaults,
// a pass rule on every interface. It is deleted, a second time if need be,
// else disabled (toggleRule never creates a rule, unlike setRule), and when
// neither can be confirmed the firewall rules are not applied this SYNC. The
// row is no local rule either way.
func (s *ruleSync) removeRecreated(ctx context.Context, mv localMove, report func(status, code, msg string)) localOutcome {
	what := fmt.Sprintf("Local rule %q was deleted on the device while NetDefense moved it, and the move re-created it with OPNsense's defaults, a pass rule on every interface", mv.name)
	for attempt := 0; attempt < 2; attempt++ {
		_ = s.client.DeleteRule(ctx, mv.uuid)
		if _, found, err := s.readRule(ctx, mv.uuid); err == nil && !found {
			report("error", codeRuleLocalRenumberUnverified, what+"; NetDefense deleted it again")
			return localGone
		}
	}
	_ = s.client.ToggleRule(ctx, mv.uuid, false)
	values, found, err := s.readRule(ctx, mv.uuid)
	switch {
	case err == nil && !found:
		report("error", codeRuleLocalRenumberUnverified, what+"; it is gone again")
	case err == nil && values["enabled"] == "0":
		report("error", codeRuleLocalRenumberUnverified, what+"; it could not be deleted, so NetDefense disabled it: delete it on the device")
	default:
		s.withheld = append(s.withheld, withheldRule{mv.name, fmt.Sprintf(
			"Local rule %q was deleted on the device during its renumber, which re-created it with OPNsense's defaults, a pass rule on every interface, and it could not be deleted or disabled.", mv.name)})
		report("error", codeRuleLocalRenumberUnverified, what+"; it could not be deleted or disabled, so the firewall rules are not applied this SYNC: delete it on the device")
	}
	return localGone
}

// sameRule reports whether two reads of a rule agree on every field they are
// compared on.
func (s *ruleSync) sameRule(a, b map[string]string) bool {
	for _, name := range s.comparedFields() {
		if a[name] != b[name] {
			return false
		}
	}
	return true
}

func renumberFailure(err error) string {
	if refused, ok := validationFailure(err); ok {
		return strings.Join(refused.Messages(), "; ")
	}
	return err.Error()
}

// reportMoves records one item per local rule this SYNC moved: where it was,
// and where it is now.
func (s *ruleSync) reportMoves() {
	for _, uuid := range sortedKeys(s.moved) {
		mv := s.moved[uuid]
		if mv.from == mv.to {
			continue
		}
		s.report(SyncAPIItemResult{
			Type: "rule_local", UUID: mv.uuid, Name: mv.name, Action: "renumbered", Status: "success",
			Code: codeRuleLocalRenumbered, Before: []string{strconv.Itoa(mv.from)}, After: []string{strconv.Itoa(mv.to)},
		}, false)
	}
}

// writeManaged writes every managed rule whose body or sequence changed, and
// returns the section placement computed for each rule it wrote. A second
// pass (previous set) only corrects sequences: it leaves alone a rule the
// first pass could not write, and reports a rule again only when the
// correction fails.
func (s *ruleSync) writeManaged(ctx context.Context, managed []*placedRule, plan rulePlan, rows []map[string]interface{}, previous map[string]int) map[string]int {
	byUUID := map[string]map[string]interface{}{}
	for _, row := range rows {
		if uuid, _ := row["uuid"].(string); uuid != "" {
			byUUID[uuid] = row
		}
	}
	sections := map[string]int{}
	for _, m := range managed {
		sections[m.uuid] = m.section
	}

	written := map[string]int{}
	for _, rule := range s.rules {
		if previous != nil && s.failed[rule.UUID] {
			continue
		}
		if plan.noRoom[rule.UUID] {
			if previous == nil {
				msg := fmt.Sprintf("%s: no sequence is left after the last local rule of its section (the highest OPNsense accepts is %d)", ruleLabel(rule), maxRuleSequence)
				s.report(SyncAPIItemResult{Type: "rule", UUID: rule.UUID, Name: rule.Description, Action: "blocked", Status: "blocked", Code: codeRuleNoSequenceRoom, Error: msg}, true)
				s.failed[rule.UUID] = true
			}
			continue
		}

		body := s.bodies[rule.UUID]
		body["sequence"] = strconv.Itoa(plan.sequence[rule.UUID])
		if row, ok := byUUID[rule.UUID]; ok && ruleRowMatches(body, row) {
			if previous == nil {
				s.report(SyncAPIItemResult{Type: "rule", UUID: rule.UUID, Name: rule.Description, Action: "unchanged", Status: "success"}, false)
			}
			continue
		}

		action := "created"
		if s.existed[rule.UUID] {
			action = "updated"
		}
		err := s.client.SetRule(ctx, rule.UUID, body)
		if err == nil {
			written[rule.UUID] = sections[rule.UUID]
			if previous == nil {
				s.report(SyncAPIItemResult{Type: "rule", UUID: rule.UUID, Name: rule.Description, Action: action, Status: "success"}, false)
			}
			continue
		}

		item := SyncAPIItemResult{Type: "rule", UUID: rule.UUID, Name: rule.Description, Action: action, Status: "error"}
		if refused, ok := validationFailure(err); ok {
			item.Error = fmt.Sprintf("%s: %s", ruleLabel(rule), strings.Join(refused.Messages(), "; "))
			item.Code = codeRuleRejectedByDevice
		} else {
			item.Error = fmt.Sprintf("%s: %v", ruleLabel(rule), err)
		}
		if previous != nil {
			s.dropItem("rule", rule.UUID)
		}
		s.report(item, true)
		s.failed[rule.UUID] = true
	}
	return written
}

// dropItem removes an earlier item for this rule, which a later one replaces.
func (s *ruleSync) dropItem(typ, uuid string) {
	for i, item := range s.results {
		if item.Type == typ && item.UUID == uuid {
			s.results = append(s.results[:i], s.results[i+1:]...)
			return
		}
	}
}

// misplaced lists the written rules the device ranks in another section than
// placement computed, with the section the device reports, and returns the
// rows it read.
func (s *ruleSync) misplaced(ctx context.Context, written map[string]int) (map[string]int, []map[string]interface{}) {
	if len(written) == 0 {
		return nil, nil
	}
	rows, err := s.client.ListAllRules(ctx)
	if err != nil {
		logging.Named("SYNC_API").Warnw("SYNC_API: could not list rules to check their sections", "error", err)
		return nil, nil
	}
	out := map[string]int{}
	for _, row := range rows {
		uuid, _ := row["uuid"].(string)
		computed, ok := written[uuid]
		if !ok {
			continue
		}
		if observed := rowSection(row); observed != 0 && observed != computed {
			out[uuid] = observed
		}
	}
	return out, rows
}

// runWithoutPlacement writes the rules when placement's inputs cannot be read:
// a managed rule keeps the sequence it has, and a new one goes after every
// rule, as OPNsense places a rule added without one.
func (s *ruleSync) runWithoutPlacement(ctx context.Context, allRules []map[string]interface{}, errs ...error) {
	byUUID := map[string]map[string]interface{}{}
	highest := 0
	for _, row := range allRules {
		if uuid, _ := row["uuid"].(string); uuid != "" {
			byUUID[uuid] = row
		}
		highest = max(highest, rowSequence(row))
	}

	plan := rulePlan{sequence: map[string]int{}, noRoom: map[string]bool{}}
	next := highest
	for _, r := range s.rules {
		if row, ok := byUUID[r.UUID]; ok && rowSequence(row) > 0 {
			plan.sequence[r.UUID] = rowSequence(row)
			continue
		}
		next += sequenceStep
		if next > maxRuleSequence {
			plan.noRoom[r.UUID] = true
			continue
		}
		plan.sequence[r.UUID] = next
	}
	s.writeManaged(ctx, nil, plan, allRules, nil)

	var reasons []string
	for _, err := range errs {
		if err != nil {
			reasons = append(reasons, err.Error())
		}
	}
	s.report(SyncAPIItemResult{
		Type: "rule_placement", Name: "placement", Action: "warning", Status: "warning", Code: codeRulePlacementUnavailable,
		Error: fmt.Sprintf("Managed rules keep their sequences and new ones go last, because this device's interface groups could not be read: %s",
			strings.Join(reasons, "; ")),
	}, false)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
