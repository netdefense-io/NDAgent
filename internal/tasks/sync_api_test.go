package tasks

import (
	"testing"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

func TestNewSequenceCalculator_NoRules(t *testing.T) {
	calc := NewSequenceCalculator(nil)

	if calc.MinUnmanaged != 100000 {
		t.Errorf("MinUnmanaged = %d, want 100000", calc.MinUnmanaged)
	}
	if calc.MaxUnmanaged != 100000 {
		t.Errorf("MaxUnmanaged = %d, want 100000", calc.MaxUnmanaged)
	}
}

func TestNewSequenceCalculator_OnlyManagedRules(t *testing.T) {
	// Given: Only managed rules (with NDAgent UUID prefix)
	allRules := []map[string]interface{}{
		{"uuid": opnapi.NDAgentUUIDPrefix + "-aaaa-4abc-9001-000000000001", "sequence": "100"},
		{"uuid": opnapi.NDAgentUUIDPrefix + "-bbbb-4abc-9001-000000000002", "sequence": "200"},
	}

	calc := NewSequenceCalculator(allRules)

	// Then: Should use defaults since no unmanaged rules exist
	if calc.MinUnmanaged != 100000 {
		t.Errorf("MinUnmanaged = %d, want 100000 (default)", calc.MinUnmanaged)
	}
	if calc.MaxUnmanaged != 100000 {
		t.Errorf("MaxUnmanaged = %d, want 100000 (default)", calc.MaxUnmanaged)
	}
}

func TestNewSequenceCalculator_WithUnmanagedRules(t *testing.T) {
	// Given: Mix of managed and unmanaged rules
	allRules := []map[string]interface{}{
		{"uuid": opnapi.NDAgentUUIDPrefix + "-aaaa-4abc-9001-000000000001", "sequence": "100"}, // managed
		{"uuid": "other-uuid-1", "sequence": "5000"},                                           // unmanaged
		{"uuid": "other-uuid-2", "sequence": "10000"},                                          // unmanaged
		{"uuid": "other-uuid-3", "sequence": "7500"},                                           // unmanaged
	}

	calc := NewSequenceCalculator(allRules)

	// Then: Should find unmanaged bounds
	if calc.MinUnmanaged != 5000 {
		t.Errorf("MinUnmanaged = %d, want 5000", calc.MinUnmanaged)
	}
	if calc.MaxUnmanaged != 10000 {
		t.Errorf("MaxUnmanaged = %d, want 10000", calc.MaxUnmanaged)
	}
}

func TestNewSequenceCalculator_SequenceAsFloat64(t *testing.T) {
	// Given: Sequence as float64 (common when parsing JSON)
	allRules := []map[string]interface{}{
		{"uuid": "other-uuid-1", "sequence": float64(3000)},
	}

	calc := NewSequenceCalculator(allRules)

	if calc.MinUnmanaged != 3000 {
		t.Errorf("MinUnmanaged = %d, want 3000", calc.MinUnmanaged)
	}
}

func TestComputeSequences_PrependOnly(t *testing.T) {
	calc := &SequenceCalculator{MinUnmanaged: 100000, MaxUnmanaged: 100000}

	rules := []APIRulePayload{
		{UUID: "221f3268-1", Position: RulePositionPrepend, Priority: 200},
		{UUID: "221f3268-2", Position: RulePositionPrepend, Priority: 100},
		{UUID: "221f3268-3", Position: RulePositionPrepend, Priority: 300},
	}

	sequences := calc.ComputeSequences(rules)

	// Sorted by priority: 100, 200, 300 -> sequences 100, 200, 300
	if sequences["221f3268-2"] != 100 {
		t.Errorf("Rule with priority 100 got sequence %d, want 100", sequences["221f3268-2"])
	}
	if sequences["221f3268-1"] != 200 {
		t.Errorf("Rule with priority 200 got sequence %d, want 200", sequences["221f3268-1"])
	}
	if sequences["221f3268-3"] != 300 {
		t.Errorf("Rule with priority 300 got sequence %d, want 300", sequences["221f3268-3"])
	}
}

func TestComputeSequences_AppendOnly(t *testing.T) {
	calc := &SequenceCalculator{MinUnmanaged: 5000, MaxUnmanaged: 10000}

	rules := []APIRulePayload{
		{UUID: "221f3268-1", Position: RulePositionAppend, Priority: 200},
		{UUID: "221f3268-2", Position: RulePositionAppend, Priority: 100},
	}

	sequences := calc.ComputeSequences(rules)

	// APPEND starts at MaxUnmanaged + 1000 = 11000
	// Sorted by priority: 100, 200 -> sequences 11000, 11100
	if sequences["221f3268-2"] != 11000 {
		t.Errorf("Rule with priority 100 got sequence %d, want 11000", sequences["221f3268-2"])
	}
	if sequences["221f3268-1"] != 11100 {
		t.Errorf("Rule with priority 200 got sequence %d, want 11100", sequences["221f3268-1"])
	}
}

func TestComputeSequences_PrependAndAppend(t *testing.T) {
	calc := &SequenceCalculator{MinUnmanaged: 5000, MaxUnmanaged: 10000}

	rules := []APIRulePayload{
		{UUID: "221f3268-prepend-1", Position: RulePositionPrepend, Priority: 200},
		{UUID: "221f3268-prepend-2", Position: RulePositionPrepend, Priority: 100},
		{UUID: "221f3268-append-1", Position: RulePositionAppend, Priority: 100},
		{UUID: "221f3268-append-2", Position: RulePositionAppend, Priority: 200},
	}

	sequences := calc.ComputeSequences(rules)

	// PREPEND rules sorted by priority: 100, 200 -> sequences 100, 200
	if sequences["221f3268-prepend-2"] != 100 {
		t.Errorf("PREPEND rule with priority 100 got sequence %d, want 100", sequences["221f3268-prepend-2"])
	}
	if sequences["221f3268-prepend-1"] != 200 {
		t.Errorf("PREPEND rule with priority 200 got sequence %d, want 200", sequences["221f3268-prepend-1"])
	}

	// APPEND rules sorted by priority: 100, 200 -> sequences 11000, 11100
	if sequences["221f3268-append-1"] != 11000 {
		t.Errorf("APPEND rule with priority 100 got sequence %d, want 11000", sequences["221f3268-append-1"])
	}
	if sequences["221f3268-append-2"] != 11100 {
		t.Errorf("APPEND rule with priority 200 got sequence %d, want 11100", sequences["221f3268-append-2"])
	}
}

func TestComputeSequences_DefaultPosition(t *testing.T) {
	calc := &SequenceCalculator{MinUnmanaged: 100000, MaxUnmanaged: 100000}

	// Rule without explicit position should default to PREPEND (empty string treated as PREPEND)
	rules := []APIRulePayload{
		{UUID: "221f3268-1", Position: "", Priority: 100},
	}

	sequences := calc.ComputeSequences(rules)

	// Should be treated as PREPEND -> sequence 100
	if sequences["221f3268-1"] != 100 {
		t.Errorf("Default position rule got sequence %d, want 100 (PREPEND)", sequences["221f3268-1"])
	}
}

func TestComputeSequences_SamePriority(t *testing.T) {
	calc := &SequenceCalculator{MinUnmanaged: 100000, MaxUnmanaged: 100000}

	// Multiple rules with same priority - order should be stable
	rules := []APIRulePayload{
		{UUID: "221f3268-a", Position: RulePositionPrepend, Priority: 100},
		{UUID: "221f3268-b", Position: RulePositionPrepend, Priority: 100},
		{UUID: "221f3268-c", Position: RulePositionPrepend, Priority: 100},
	}

	sequences := calc.ComputeSequences(rules)

	// All should get distinct sequences (100, 200, 300 in some order)
	seqSet := make(map[int]bool)
	for _, r := range rules {
		seq := sequences[r.UUID]
		if seqSet[seq] {
			t.Errorf("Duplicate sequence %d found", seq)
		}
		seqSet[seq] = true
	}
}

func TestParseAPIRules_WithPositionAndPriority(t *testing.T) {
	payload := map[string]interface{}{
		"snippets": []interface{}{
			map[string]interface{}{
				"config_type": "RULE",
				"position":    "APPEND",
				"priority":    float64(500),
				"content":     `{"uuid": "221f3268-test-uuid", "action": "block", "interface": "lan"}`,
			},
		},
	}

	rules, err := parseAPIRules(payload)
	if err != nil {
		t.Fatalf("parseAPIRules failed: %v", err)
	}

	if len(rules) != 1 {
		t.Fatalf("Expected 1 rule, got %d", len(rules))
	}

	if rules[0].Position != RulePositionAppend {
		t.Errorf("Position = %s, want APPEND", rules[0].Position)
	}
	if rules[0].Priority != 500 {
		t.Errorf("Priority = %d, want 500", rules[0].Priority)
	}
}

func TestParseAPIRules_DefaultPositionAndPriority(t *testing.T) {
	payload := map[string]interface{}{
		"snippets": []interface{}{
			map[string]interface{}{
				"config_type": "RULE",
				// No position or priority specified
				"content": `{"uuid": "221f3268-test-uuid", "action": "pass"}`,
			},
		},
	}

	rules, err := parseAPIRules(payload)
	if err != nil {
		t.Fatalf("parseAPIRules failed: %v", err)
	}

	if len(rules) != 1 {
		t.Fatalf("Expected 1 rule, got %d", len(rules))
	}

	// Should have defaults
	if rules[0].Position != RulePositionPrepend {
		t.Errorf("Default Position = %s, want PREPEND", rules[0].Position)
	}
	if rules[0].Priority != 1000 {
		t.Errorf("Default Priority = %d, want 1000", rules[0].Priority)
	}
}

func TestParseAPIRules_InvalidPosition(t *testing.T) {
	payload := map[string]interface{}{
		"snippets": []interface{}{
			map[string]interface{}{
				"config_type": "RULE",
				"position":    "INVALID",
				"content":     `{"uuid": "221f3268-test-uuid"}`,
			},
		},
	}

	_, err := parseAPIRules(payload)
	if err == nil {
		t.Error("Expected error for invalid position, got nil")
	}
}

func TestParseAPIRules_CaseInsensitivePosition(t *testing.T) {
	testCases := []struct {
		input    string
		expected RulePosition
	}{
		{"prepend", RulePositionPrepend},
		{"PREPEND", RulePositionPrepend},
		{"Prepend", RulePositionPrepend},
		{"append", RulePositionAppend},
		{"APPEND", RulePositionAppend},
		{"Append", RulePositionAppend},
	}

	for _, tc := range testCases {
		payload := map[string]interface{}{
			"snippets": []interface{}{
				map[string]interface{}{
					"config_type": "RULE",
					"position":    tc.input,
					"content":     `{"uuid": "221f3268-test-uuid"}`,
				},
			},
		}

		rules, err := parseAPIRules(payload)
		if err != nil {
			t.Errorf("Position %q: unexpected error: %v", tc.input, err)
			continue
		}

		if rules[0].Position != tc.expected {
			t.Errorf("Position %q: got %s, want %s", tc.input, rules[0].Position, tc.expected)
		}
	}
}
