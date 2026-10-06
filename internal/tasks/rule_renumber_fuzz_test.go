package tasks

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// renumberFuzzRegressions are seeds that once failed: a local rule deleted
// during its renumber and re-created by it, then left on the device because
// its read-back failed once (2387, 2678, 3252, 5413, 6466) or the owner edited
// it before the read-back (3866, 7211), or applied because the owner gave it
// back one of its own values (30452, 56040); and the owner's own rule deleted
// for an edit back to a default value during its renumber (the rest).
var renumberFuzzRegressions = []int{
	2387, 2678, 3252, 5413, 6466, 3866, 7211, 30452, 56040,
	38, 1386, 1420, 1507, 2100, 2172, 2377, 2653, 2694, 2851, 2949, 3203, 3842, 3968,
	4079, 4084, 4171, 4654, 4727, 4820, 6140, 7217, 7487, 7723, 7733, 7745, 7929,
}

// lostAnswerFuzzRegressions are seeds of the lost-answer mode that once
// applied a rule a save with a lost answer had re-created after the owner
// deleted it (13 to 116), or reported a rule renumbered to where a first move
// put it while a second one, its answer lost, may have taken it further (the
// rest).
var lostAnswerFuzzRegressions = []int{
	13, 16, 25, 40, 76, 93, 110, 116,
	30, 262, 1975, 3807, 4189, 5936, 6468, 7542,
}

// unsavedAnswerFuzzRegressions are seeds of the unsaved-answer mode that once
// took a move that saved nothing for made, because the owner had edited the
// rule (2851 to 24221) or it could not be read back (the rest): the rule was
// reported renumbered, or a local rule was pushed past it.
var unsavedAnswerFuzzRegressions = []int{
	2851, 3968, 4171, 8513, 13939, 16180, 16399, 21061, 22462, 23610, 23796, 24221,
	63, 124, 351, 774, 1525, 1609, 2000, 2274, 2283, 2785, 3033, 3282,
}

// fuzzAnswer is what becomes of the move of the local rule a seed picks.
type fuzzAnswer int

const (
	fuzzAnswered    fuzzAnswer = iota // answered, as every other write
	fuzzLostSaved                     // saved, its answer lost
	fuzzLostUnsaved                   // not saved, its answer lost
)

// fuzzLocalUUIDs are local rule UUIDs whose natural and byte orders often
// disagree.
var fuzzLocalUUIDs = []string{
	"2abc0000-0000-4000-8000-000000000001", "10bc0000-0000-4000-8000-000000000001", "9f000000-0000-4000-8000-000000000001",
	"01230000-0000-4000-8000-000000000001", "1230a000-0000-4000-8000-000000000001", "00ab0000-0000-4000-8000-000000000001",
	"0ab00000-0000-4000-8000-000000000001", "a0010000-0000-4000-8000-000000000001", "a01b0000-0000-4000-8000-000000000001",
	"ABCD0000-0000-4000-8000-000000000001", "abce0000-0000-4000-8000-000000000001", "7179a1de-88f9-428f-a5b7-d4814890be9f",
	"651c4e72-1a2d-494b-b1ed-2a89b26888d6", "0d5bec00-0000-4000-8000-00000000a001", "12345678-0000-4000-8000-000000000001",
	"12345678-0000-4000-8000-00000000001a", "9bbbbbbb-0000-4000-8000-000000000001", "5e5e5e5e-0000-4000-8000-000000000002",
}

// fuzzOwnerEdits are the edits the owner makes during a SYNC: to another
// value, or back to the model's default.
var fuzzOwnerEdits = []struct{ field, value string }{
	{"description", "edited by the owner"},
	{"description", ""},
	{"action", "pass"},
	{"enabled", "1"},
	{"action", "block"},
}

type fuzzKey struct {
	seq  int
	uuid string
}

func fuzzLess(a, b fuzzKey) bool {
	if a.seq != b.seq {
		return a.seq < b.seq
	}
	return naturalCompare(a.uuid, b.uuid) < 0
}

// TestRuleRenumberFuzz runs random lan rulesets with PREPEND and APPEND rules
// through SYNCs during which local rules refuse their move, vanish, are edited
// or cannot be read, and checks that no local rule is reordered or changed
// beyond its sequence, that a rule reported renumbered is where the report
// says, that no re-created rule is left enabled and applied, that nothing
// outside the section is written, and that the device converges once the
// trouble is over. NDAGENT_RULE_FUZZ_SEEDS=N runs seeds 0 to N-1 besides the
// regressions.
func TestRuleRenumberFuzz(t *testing.T) {
	runRenumberFuzz(t, fuzzAnswered, renumberFuzzRegressions, "NDAGENT_RULE_FUZZ_SEEDS")
}

// TestRuleRenumberFuzzLostAnswers is the same fuzz with the first or the
// second write to one local rule saved and its answer lost (HTTP 500), after
// the owner deleted the rule or not, and readable after it or not.
// NDAGENT_RULE_FUZZ_LOST_SEEDS=N runs seeds 0 to N-1 besides the regressions.
func TestRuleRenumberFuzzLostAnswers(t *testing.T) {
	runRenumberFuzz(t, fuzzLostSaved, lostAnswerFuzzRegressions, "NDAGENT_RULE_FUZZ_LOST_SEEDS")
}

// TestRuleRenumberFuzzUnsavedAnswers is the same fuzz with the first or the
// second write to one local rule not saved and its answer lost (HTTP 500),
// after the owner deleted the rule or not, and readable after it or not.
// NDAGENT_RULE_FUZZ_UNSAVED_SEEDS=N runs seeds 0 to N-1 besides the
// regressions.
func TestRuleRenumberFuzzUnsavedAnswers(t *testing.T) {
	runRenumberFuzz(t, fuzzLostUnsaved, unsavedAnswerFuzzRegressions, "NDAGENT_RULE_FUZZ_UNSAVED_SEEDS")
}

func runRenumberFuzz(t *testing.T, answer fuzzAnswer, regressions []int, env string) {
	seeds := append([]int(nil), regressions...)
	if n, _ := strconv.Atoi(os.Getenv(env)); n > 0 {
		for seed := 0; seed < n; seed++ {
			seeds = append(seeds, seed)
		}
	}
	violations := map[string][]int{}
	for _, seed := range seeds {
		// A subtest per seed: its fake device's server closes when the seed
		// ends, not when the whole run does.
		t.Run(strconv.Itoa(seed), func(t *testing.T) {
			fuzzRenumber(t, seed, answer, func(kind string, seed int, detail string) {
				if len(violations[kind]) == 0 {
					t.Logf("seed %d: %s: %s", seed, kind, detail)
				}
				violations[kind] = append(violations[kind], seed)
			})
		})
	}
	kinds := make([]string, 0, len(violations))
	for kind := range violations {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	for _, kind := range kinds {
		t.Errorf("%s: seeds %v", kind, violations[kind])
	}
}

func fuzzRenumber(t *testing.T, seed int, answer fuzzAnswer, note func(kind string, seed int, detail string)) {
	r := rand.New(rand.NewSource(int64(seed)*7919 + 13))

	pool := append([]string(nil), fuzzLocalUUIDs...)
	r.Shuffle(len(pool), func(i, j int) { pool[i], pool[j] = pool[j], pool[i] })
	nLocals := 1 + r.Intn(6)
	var rows []map[string]interface{}
	original := map[string]fuzzKey{}
	origRow := map[string]map[string]interface{}{}
	var localUUIDs []string
	tie := 0
	for i := 0; i < nLocals; i++ {
		seq := 1 + r.Intn(10)
		if r.Intn(3) == 0 && tie > 0 {
			seq = tie
		}
		tie = seq
		uuid := pool[i]
		iface := []string{"lan", "lan", "lan", "wan"}[r.Intn(4)]
		row := map[string]interface{}{"uuid": uuid, "interface": iface, "sequence": strconv.Itoa(seq), "enabled": []string{"1", "1", "0"}[r.Intn(3)],
			"description": []string{"", "allow", "block x", "rule " + strconv.Itoa(i)}[r.Intn(4)], "action": []string{"pass", "block"}[r.Intn(2)]}
		rows = append(rows, row)
		original[uuid] = fuzzKey{seq, uuid}
		kept := map[string]interface{}{}
		for k, v := range row {
			kept[k] = v
		}
		origRow[uuid] = kept
		localUUIDs = append(localUUIDs, uuid)
	}
	// Other sections: a floating and a group local rule, and a configured
	// legacy row.
	const floatLocal = "6f6f6f6f-0000-4000-8000-0000000000f1"
	const groupLocal = "6a6a6a6a-0000-4000-8000-0000000000f2"
	const legacyLocal = "1e1e1e1e-0000-4000-8000-0000000000f3"
	rows = append(rows,
		map[string]interface{}{"uuid": floatLocal, "interface": "", "sequence": strconv.Itoa(1 + r.Intn(5)), "enabled": "1", "description": "float", "action": "pass"},
		map[string]interface{}{"uuid": groupLocal, "interface": "wireguard", "sequence": strconv.Itoa(1 + r.Intn(5)), "enabled": "1", "description": "group", "action": "pass"},
		map[string]interface{}{"uuid": legacyLocal, "legacy": true, "seq": float64(3), "interface": "LAN", "sort_order": "400000.1000040", "description": "legacy"},
	)
	// Odd seeds run against 26.7.5's rule model, which stamps an audit record
	// on every save.
	template := ruleTemplate(t)
	if seed%2 == 1 {
		template = ruleTemplate(t, withRuleModel2675)
	}
	device := newFakeRuleDevice(t, template, rows)
	device.groups = []opnapi.InterfaceGroup{{Name: "wireguard", Sequence: 10}}
	untouched := map[string]bool{floatLocal: true, groupLocal: true, legacyLocal: true}
	untouchedSeq := map[string]int{floatLocal: device.sequenceOf(floatLocal), groupLocal: device.sequenceOf(groupLocal)}

	nP, nA := r.Intn(6), r.Intn(3)
	var desired []APIRulePayload
	n := 0
	managedSet := map[string]bool{}
	for i := 0; i < nP; i++ {
		n++
		u := fmt.Sprintf("221f3268-0000-4000-8000-0000000000%02d", n)
		managedSet[u] = true
		desired = append(desired, desiredRule(t, fmt.Sprintf("p%d", n), RulePositionPrepend, (i+1)*10,
			fmt.Sprintf(`{"uuid":"%s","action":"block","interface":"lan","description":"managed %d"}`, u, n)))
	}
	for i := 0; i < nA; i++ {
		n++
		u := fmt.Sprintf("221f3268-0000-4000-8000-0000000000%02d", n)
		managedSet[u] = true
		desired = append(desired, desiredRule(t, fmt.Sprintf("a%d", n), RulePositionAppend, (i+1)*10,
			fmt.Sprintf(`{"uuid":"%s","action":"block","interface":"lan","description":"managed %d"}`, u, n)))
	}

	// Trouble: local rules that refuse their move, and one call at which a
	// local rule vanishes, is edited, or cannot be read.
	refuse := map[string]bool{}
	for _, u := range localUUIDs {
		if r.Intn(5) == 0 {
			refuse[u] = true
		}
	}
	vanishAt, editAt, unreadAt := -1, -1, -1
	if r.Intn(3) == 0 {
		vanishAt = r.Intn(8)
	}
	if r.Intn(5) == 0 {
		editAt = r.Intn(8)
	}
	if r.Intn(6) == 0 {
		unreadAt = r.Intn(8)
	}
	vanishTheRowCalled := r.Intn(2) == 0
	// The owner's edit, drawn apart so the rest of a seed stays what it was.
	edit := fuzzOwnerEdits[rand.New(rand.NewSource(int64(seed)*104729+3)).Intn(len(fuzzOwnerEdits))]
	// The lost answer, drawn apart as well: which local rule's move has its
	// answer lost, whether the owner deleted the rule first, whether the rule
	// can be read after it, and whether the first or the second write to the
	// rule is the one (a replan can move a rule twice).
	lr := rand.New(rand.NewSource(int64(seed)*15485863 + 7))
	lostTarget, lostDelete := localUUIDs[lr.Intn(len(localUUIDs))], lr.Intn(2) == 0
	lostUnread := lr.Intn(4) == 0
	lostNth, lostWrites := 1+lr.Intn(2), 0
	lostDone := false
	deleted := map[string]bool{}
	edited := map[string]bool{}
	calls := 0
	device.answer = func(uuid string, body map[string]string) (int, interface{}, bool) {
		if refuse[uuid] {
			return http.StatusOK, map[string]interface{}{"result": "failed", "validations": map[string]interface{}{"rule.gateway": "Option [OLD_GW] not in list."}}, true
		}
		return 0, nil, false
	}
	isLocal := func(u string) bool { _, ok := original[u]; return ok }
	device.before = func(call, uuid string) bool {
		if !isLocal(uuid) {
			return true
		}
		k := calls
		calls++
		if k == vanishAt {
			target := uuid
			if !vanishTheRowCalled {
				target = localUUIDs[r.Intn(len(localUUIDs))]
			}
			if isLocal(target) && !deleted[target] {
				device.deleteRow(target)
				deleted[target] = true
			}
		}
		if k == editAt && call == "get" {
			if row := device.find(uuid); row != nil {
				row[edit.field] = edit.value
				edited[uuid] = true
			}
		}
		if answer != fuzzAnswered && call == "set" && uuid == lostTarget && !lostDone && !refuse[uuid] {
			if lostWrites++; lostWrites < lostNth {
				return true
			}
			lostDone = true
			deleteFirst := lostDelete && !deleted[uuid]
			if deleteFirst {
				deleted[uuid] = true
			}
			if answer == fuzzLostSaved {
				return saveAndLoseTheAnswer(device, uuid, deleteFirst)
			}
			if deleteFirst {
				device.deleteRow(uuid)
			}
			return false
		}
		if answer != fuzzAnswered && lostUnread && lostDone && call == "get" && uuid == lostTarget {
			return false
		}
		return !(k == unreadAt && call == "get")
	}

	result := executeSyncAPI(context.Background(), device.client, nil, desired)
	trouble := len(refuse) > 0 || vanishAt >= 0 || editAt >= 0 || unreadAt >= 0 || lostDone

	device.mu.Lock()
	finalRows := append([]map[string]interface{}(nil), device.rows...)
	device.mu.Unlock()
	finalByUUID := map[string]map[string]interface{}{}
	for _, row := range finalRows {
		u, _ := row["uuid"].(string)
		finalByUUID[u] = row
		if !isLocal(u) && !untouched[u] && !managedSet[u] {
			note("a row nobody owns is on the device", seed, fmt.Sprintf("%v", row))
		}
	}
	// A re-created rule may stay, disabled, or enabled while the apply is
	// withheld; never enabled and applied.
	applied := lastWriteIndex(device.writes, "apply") >= 0
	for u := range deleted {
		if row := finalByUUID[u]; row != nil && row["enabled"] != "0" && applied {
			note("a re-created rule was left enabled and applied", seed, fmt.Sprintf("%v", row))
		}
	}
	// A local rule reported renumbered is where the report says, unless the
	// owner deleted it.
	for _, item := range itemsOfType(result.Results, "rule_local") {
		if item.Code != codeRuleLocalRenumbered || deleted[item.UUID] {
			continue
		}
		if row := finalByUUID[item.UUID]; row == nil || len(item.After) != 1 || strconv.Itoa(rowSequence(row)) != item.After[0] {
			note("a local rule reported renumbered is not where the report says", seed, fmt.Sprintf("%s: reported %v, device %v", item.UUID[:4], item.After, row["sequence"]))
		}
	}
	for u := range edited {
		switch row := finalByUUID[u]; {
		case deleted[u]:
		case row == nil:
			note("a local rule the owner edited was deleted", seed, fmt.Sprintf("%s: %s = %q", u[:4], edit.field, edit.value))
		case row["enabled"] == "0" && origRow[u]["enabled"] != "0" && !(edit.field == "enabled" && edit.value == "0"):
			note("a local rule the owner edited was disabled", seed, fmt.Sprintf("%s: %s = %q", u[:4], edit.field, edit.value))
		}
	}
	var survivors []string
	for _, u := range localUUIDs {
		if !deleted[u] && finalByUUID[u] != nil {
			survivors = append(survivors, u)
		}
	}
	sort.SliceStable(survivors, func(i, j int) bool { return fuzzLess(original[survivors[i]], original[survivors[j]]) })
	final := func(u string) fuzzKey { return fuzzKey{rowSequence(finalByUUID[u]), u} }
	for i := 0; i < len(survivors); i++ {
		for j := i + 1; j < len(survivors); j++ {
			if a, b := survivors[i], survivors[j]; fuzzLess(final(b), final(a)) {
				note("local order inverted", seed, fmt.Sprintf("%s(%d->%d) now after %s(%d->%d)", a[:4], original[a].seq, final(a).seq, b[:4], original[b].seq, final(b).seq))
			}
		}
	}
	for _, u := range survivors {
		for k, want := range origRow[u] {
			if k == "sequence" || k == "uuid" || (k == edit.field && edited[u]) {
				continue
			}
			if got := finalByUUID[u][k]; got != want {
				note("a local rule's field other than its sequence changed", seed, fmt.Sprintf("%s %s: %v -> %v", u[:4], k, want, got))
			}
		}
	}
	for _, u := range localUUIDs {
		for _, body := range device.bodies[u] {
			if len(body) != 1 || body["sequence"] == "" {
				note("a local write carried more than the sequence", seed, fmt.Sprintf("%s %v", u[:4], body))
			}
		}
	}
	for u := range untouched {
		if w := device.writesTo(u); len(w) > 0 {
			note("a rule of another section or a legacy row was written", seed, fmt.Sprintf("%s %v", u[:4], w))
		}
	}
	for u, want := range untouchedSeq {
		if got := rowSequence(finalByUUID[u]); got != want {
			note("a rule of another section changed sequence", seed, u[:4])
		}
	}
	if del, apply := lastWriteIndex(device.writes, "del "), lastWriteIndex(device.writes, "apply"); apply >= 0 && del > apply {
		note("a rule was deleted after the apply", seed, strings.Join(device.writes, " | "))
	}
	if !trouble {
		if !result.Success {
			note("a clean run failed", seed, fmt.Sprintf("%v", result.Errors))
		}
		maxLocal, minLocal := 0, 1<<30
		for _, u := range survivors {
			maxLocal, minLocal = max(maxLocal, final(u).seq), min(minLocal, final(u).seq)
		}
		prev := 0
		for _, rule := range desired {
			s := device.sequenceOf(rule.UUID)
			if rule.Position == RulePositionAppend {
				if s <= maxLocal || s <= prev {
					note("a clean run left an APPEND rule before a local rule", seed, fmt.Sprintf("@%d, last local @%d", s, maxLocal))
				}
				continue
			}
			if len(survivors) > 0 && s >= minLocal {
				note("a clean run left a PREPEND rule after a local rule", seed, fmt.Sprintf("@%d, first local @%d", s, minLocal))
			}
			if s <= prev {
				note("a clean run left PREPEND rules out of order", seed, fmt.Sprintf("@%d after @%d", s, prev))
			}
			prev = s
		}
	}

	// The trouble over, a second SYNC settles and a third writes nothing.
	device.answer = nil
	device.before = nil
	second := executeSyncAPI(context.Background(), device.client, nil, desired)
	writes := len(device.writes)
	third := executeSyncAPI(context.Background(), device.client, nil, desired)
	if got := device.writes[writes:]; len(got) > 1 || (len(got) == 1 && got[0] != "apply") {
		note("not converged once the trouble is over", seed, strings.Join(got, " | "))
	}
	if !second.Success || !third.Success {
		note("a SYNC after the trouble failed", seed, fmt.Sprintf("%v / %v", second.Errors, third.Errors))
	}
}

func lastWriteIndex(writes []string, prefix string) int {
	last := -1
	for i, w := range writes {
		if strings.HasPrefix(w, prefix) {
			last = i
		}
	}
	return last
}
