package opnapi

import (
	"encoding/json"
	"testing"
)

func TestFlexibleValidation_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantErrors  bool
		wantMessage string
		wantMapLen  int
	}{
		{
			name:        "empty string",
			input:       `""`,
			wantErrors:  false,
			wantMessage: "",
			wantMapLen:  0,
		},
		{
			name:        "empty array",
			input:       `[]`,
			wantErrors:  false,
			wantMessage: "",
			wantMapLen:  0,
		},
		{
			name:        "null value",
			input:       `null`,
			wantErrors:  false,
			wantMessage: "",
			wantMapLen:  0,
		},
		{
			name:        "string error message",
			input:       `"validation error occurred"`,
			wantErrors:  true,
			wantMessage: "validation error occurred",
			wantMapLen:  0,
		},
		{
			name:        "map structure",
			input:       `{"field1":[{"error":"invalid value"}]}`,
			wantErrors:  true,
			wantMessage: "",
			wantMapLen:  1,
		},
		{
			name:        "nested map structure",
			input:       `{"rule.interface":[{"msg":"interface is required"}],"rule.action":[{"msg":"invalid action"}]}`,
			wantErrors:  true,
			wantMessage: "",
			wantMapLen:  2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var fv FlexibleValidation
			err := json.Unmarshal([]byte(tt.input), &fv)
			if err != nil {
				t.Fatalf("UnmarshalJSON() error = %v", err)
			}

			if got := fv.HasErrors(); got != tt.wantErrors {
				t.Errorf("HasErrors() = %v, want %v", got, tt.wantErrors)
			}

			if fv.Message != tt.wantMessage {
				t.Errorf("Message = %q, want %q", fv.Message, tt.wantMessage)
			}

			if len(fv.Errors) != tt.wantMapLen {
				t.Errorf("len(Errors) = %d, want %d", len(fv.Errors), tt.wantMapLen)
			}
		})
	}
}

func TestFlexibleValidation_String(t *testing.T) {
	tests := []struct {
		name   string
		fv     FlexibleValidation
		want   string
		notNil bool
	}{
		{
			name:   "with message",
			fv:     FlexibleValidation{Message: "error message"},
			want:   "error message",
			notNil: true,
		},
		{
			name: "with errors map",
			fv: FlexibleValidation{
				Errors: map[string][]map[string]string{
					"field": {{"error": "value"}},
				},
			},
			notNil: true,
		},
		{
			name: "empty",
			fv:   FlexibleValidation{},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.fv.String()
			if tt.notNil && got == "" {
				t.Error("String() returned empty string, expected non-empty")
			}
			if tt.want != "" && got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFlexibleValidation_InResponse(t *testing.T) {
	// Test that FlexibleValidation works correctly within SetRuleResponse
	tests := []struct {
		name       string
		input      string
		wantErrors bool
	}{
		{
			name:       "success response with empty validations",
			input:      `{"result":"saved","uuid":"test-uuid","validations":""}`,
			wantErrors: false,
		},
		{
			name:       "success response with no validations field",
			input:      `{"result":"saved","uuid":"test-uuid"}`,
			wantErrors: false,
		},
		{
			name:       "error response with string validation",
			input:      `{"result":"failed","validations":"interface required"}`,
			wantErrors: true,
		},
		{
			name:       "error response with map validation",
			input:      `{"result":"failed","validations":{"rule.interface":[{"msg":"required"}]}}`,
			wantErrors: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var resp SetRuleResponse
			err := json.Unmarshal([]byte(tt.input), &resp)
			if err != nil {
				t.Fatalf("UnmarshalJSON() error = %v", err)
			}

			if got := resp.ValidationErrors.HasErrors(); got != tt.wantErrors {
				t.Errorf("ValidationErrors.HasErrors() = %v, want %v", got, tt.wantErrors)
			}
		})
	}
}
