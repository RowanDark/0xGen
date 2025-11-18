package rewrite

import (
	"encoding/json"
	"testing"
)

func TestRuleValidation(t *testing.T) {
	tests := []struct {
		name    string
		rule    *Rule
		wantErr bool
	}{
		{
			name: "valid rule",
			rule: &Rule{
				Name:    "test-rule",
				Enabled: true,
				Scope: RuleScope{
					Direction: DirectionRequest,
				},
				Conditions: []Condition{
					{
						Type:     ConditionContains,
						Location: LocationURL,
						Pattern:  "test",
					},
				},
				Actions: []Action{
					{
						Type:     ActionAdd,
						Location: LocationHeader,
						Name:     "X-Test",
						Value:    "test",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "missing name",
			rule: &Rule{
				Name:    "",
				Enabled: true,
				Scope: RuleScope{
					Direction: DirectionRequest,
				},
				Actions: []Action{
					{
						Type:     ActionAdd,
						Location: LocationHeader,
						Name:     "X-Test",
						Value:    "test",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "no actions",
			rule: &Rule{
				Name:    "test-rule",
				Enabled: true,
				Scope: RuleScope{
					Direction: DirectionRequest,
				},
				Actions: []Action{},
			},
			wantErr: true,
		},
		{
			name: "invalid regex in scope",
			rule: &Rule{
				Name:    "test-rule",
				Enabled: true,
				Scope: RuleScope{
					Direction:  DirectionRequest,
					URLPattern: "[invalid",
				},
				Actions: []Action{
					{
						Type:     ActionAdd,
						Location: LocationHeader,
						Name:     "X-Test",
						Value:    "test",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid regex in condition",
			rule: &Rule{
				Name:    "test-rule",
				Enabled: true,
				Scope: RuleScope{
					Direction: DirectionRequest,
				},
				Conditions: []Condition{
					{
						Type:     ConditionRegex,
						Location: LocationBody,
						Pattern:  "[invalid",
					},
				},
				Actions: []Action{
					{
						Type:     ActionAdd,
						Location: LocationHeader,
						Name:     "X-Test",
						Value:    "test",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "extract without pattern",
			rule: &Rule{
				Name:    "test-rule",
				Enabled: true,
				Scope: RuleScope{
					Direction: DirectionRequest,
				},
				Actions: []Action{
					{
						Type:      ActionExtract,
						Location:  LocationHeader,
						Name:      "Authorization",
						ExtractTo: "token",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "transform with invalid type",
			rule: &Rule{
				Name:    "test-rule",
				Enabled: true,
				Scope: RuleScope{
					Direction: DirectionRequest,
				},
				Actions: []Action{
					{
						Type:      ActionTransform,
						Location:  LocationHeader,
						Name:      "X-Data",
						Transform: "invalid_transform",
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Rule.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRuleSerialization(t *testing.T) {
	rule := &Rule{
		ID:          1,
		Name:        "test-rule",
		Description: "Test rule",
		Enabled:     true,
		Priority:    10,
		Scope: RuleScope{
			Direction:  DirectionRequest,
			Methods:    []string{"GET", "POST"},
			URLPattern: "^https://api\\.example\\.com/.*",
		},
		Conditions: []Condition{
			{
				Type:     ConditionContains,
				Location: LocationURL,
				Pattern:  "/api/",
			},
		},
		Actions: []Action{
			{
				Type:     ActionAdd,
				Location: LocationHeader,
				Name:     "X-Test",
				Value:    "test",
			},
		},
		Tags: []string{"test", "example"},
	}

	// Validate first to compile regexes
	if err := rule.Validate(); err != nil {
		t.Fatalf("Rule validation failed: %v", err)
	}

	// Serialize to JSON
	data, err := json.Marshal(rule)
	if err != nil {
		t.Fatalf("Failed to marshal rule: %v", err)
	}

	// Deserialize from JSON
	var decoded Rule
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal rule: %v", err)
	}

	// Validate decoded rule
	if err := decoded.Validate(); err != nil {
		t.Fatalf("Decoded rule validation failed: %v", err)
	}

	// Compare fields
	if decoded.Name != rule.Name {
		t.Errorf("Name mismatch: got %s, want %s", decoded.Name, rule.Name)
	}
	if decoded.Priority != rule.Priority {
		t.Errorf("Priority mismatch: got %d, want %d", decoded.Priority, rule.Priority)
	}
	if decoded.Scope.Direction != rule.Scope.Direction {
		t.Errorf("Direction mismatch: got %v, want %v", decoded.Scope.Direction, rule.Scope.Direction)
	}
}

func TestDirectionJSON(t *testing.T) {
	tests := []struct {
		direction Direction
		json      string
	}{
		{DirectionRequest, `"request"`},
		{DirectionResponse, `"response"`},
		{DirectionBoth, `"both"`},
	}

	for _, tt := range tests {
		t.Run(tt.direction.String(), func(t *testing.T) {
			// Marshal
			data, err := json.Marshal(tt.direction)
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}
			if string(data) != tt.json {
				t.Errorf("Marshal = %s, want %s", string(data), tt.json)
			}

			// Unmarshal
			var d Direction
			if err := json.Unmarshal([]byte(tt.json), &d); err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}
			if d != tt.direction {
				t.Errorf("Unmarshal = %v, want %v", d, tt.direction)
			}
		})
	}
}

func TestRuleClone(t *testing.T) {
	original := &Rule{
		ID:       1,
		Name:     "test",
		Enabled:  true,
		Priority: 10,
		Scope: RuleScope{
			Direction: DirectionRequest,
			Methods:   []string{"GET"},
		},
		Conditions: []Condition{
			{Type: ConditionContains, Pattern: "test"},
		},
		Actions: []Action{
			{Type: ActionAdd, Name: "X-Test", Value: "test"},
		},
		Tags: []string{"tag1"},
	}

	clone := original.Clone()

	// Modify clone
	clone.Name = "modified"
	clone.Priority = 20
	clone.Methods = append(clone.Methods, "POST")
	clone.Conditions[0].Pattern = "modified"
	clone.Actions[0].Value = "modified"
	clone.Tags[0] = "modified"

	// Original should be unchanged
	if original.Name == clone.Name {
		t.Error("Clone modified original name")
	}
	if original.Priority == clone.Priority {
		t.Error("Clone modified original priority")
	}
	if original.Conditions[0].Pattern == clone.Conditions[0].Pattern {
		t.Error("Clone modified original condition")
	}
	if original.Actions[0].Value == clone.Actions[0].Value {
		t.Error("Clone modified original action")
	}
	if original.Tags[0] == clone.Tags[0] {
		t.Error("Clone modified original tags")
	}
}
