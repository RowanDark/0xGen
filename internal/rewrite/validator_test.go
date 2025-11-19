package rewrite

import (
	"log/slog"
	"os"
	"testing"
)

func TestValidator(t *testing.T) {
	validator := NewValidator(slog.New(slog.NewTextHandler(os.Stdout, nil)))

	tests := []struct {
		name          string
		rule          *Rule
		wantErrors    int
		wantSeverity  Severity
		wantErrorType ErrorType
	}{
		{
			name: "valid rule",
			rule: &Rule{
				Name:    "valid",
				Enabled: true,
				Scope:   RuleScope{Direction: DirectionRequest},
				Actions: []Action{{Type: ActionAdd, Location: LocationHeader, Name: "X-Test", Value: "test"}},
			},
			wantErrors: 0,
		},
		{
			name: "invalid regex in scope",
			rule: &Rule{
				Name:    "invalid-regex",
				Enabled: true,
				Scope:   RuleScope{Direction: DirectionRequest, URLPattern: "[invalid"},
				Actions: []Action{{Type: ActionAdd, Location: LocationHeader, Name: "X-Test", Value: "test"}},
			},
			wantErrors:    1,
			wantSeverity:  SeverityError,
			wantErrorType: ErrorTypeRegex,
		},
		{
			name: "overly broad pattern",
			rule: &Rule{
				Name:    "broad-pattern",
				Enabled: true,
				Scope:   RuleScope{Direction: DirectionRequest},
				Conditions: []Condition{
					{Type: ConditionRegex, Location: LocationBody, Pattern: ".*"},
				},
				Actions: []Action{{Type: ActionAdd, Location: LocationHeader, Name: "X-Test", Value: "test"}},
			},
			wantErrors:    1,
			wantSeverity:  SeverityWarning,
			wantErrorType: ErrorTypePerformance,
		},
		{
			name: "performance warning on body",
			rule: &Rule{
				Name:    "body-operation",
				Enabled: true,
				Scope:   RuleScope{Direction: DirectionRequest},
				Actions: []Action{{Type: ActionReplace, Location: LocationBody, Pattern: "old", Value: "new"}},
			},
			wantErrors:    1,
			wantSeverity:  SeverityInfo,
			wantErrorType: ErrorTypePerformance,
		},
		{
			name: "contradictory actions",
			rule: &Rule{
				Name:    "contradictory",
				Enabled: true,
				Scope:   RuleScope{Direction: DirectionRequest},
				Actions: []Action{
					{Type: ActionAdd, Location: LocationHeader, Name: "X-Test", Value: "test"},
					{Type: ActionRemove, Location: LocationHeader, Name: "X-Test"},
				},
			},
			wantErrors:    1,
			wantSeverity:  SeverityWarning,
			wantErrorType: ErrorTypeLogic,
		},
		{
			name: "infinite loop potential",
			rule: &Rule{
				Name:    "infinite-loop",
				Enabled: true,
				Scope:   RuleScope{Direction: DirectionRequest},
				Conditions: []Condition{
					{Type: ConditionExists, Location: LocationHeader, Name: "X-Test"},
				},
				Actions: []Action{
					{Type: ActionReplace, Location: LocationHeader, Name: "X-Test", Pattern: ".*", Value: "new"},
				},
			},
			wantErrors:    1,
			wantSeverity:  SeverityWarning,
			wantErrorType: ErrorTypeInfiniteLoop,
		},
		{
			name: "security warning - hardcoded secret",
			rule: &Rule{
				Name:    "hardcoded-secret",
				Enabled: true,
				Scope:   RuleScope{Direction: DirectionRequest},
				Actions: []Action{
					{Type: ActionAdd, Location: LocationHeader, Name: "X-API-Key", Value: "api_key=\"secret123\""},
				},
			},
			wantErrors:    1,
			wantSeverity:  SeverityWarning,
			wantErrorType: ErrorTypeSecurity,
		},
		{
			name: "security warning - removing security header",
			rule: &Rule{
				Name:    "remove-security-header",
				Enabled: true,
				Scope:   RuleScope{Direction: DirectionResponse},
				Actions: []Action{
					{Type: ActionRemove, Location: LocationHeader, Name: "Content-Security-Policy"},
				},
			},
			wantErrors:    1,
			wantSeverity:  SeverityWarning,
			wantErrorType: ErrorTypeSecurity,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := validator.ValidateRule(tt.rule)

			if len(errors) != tt.wantErrors {
				t.Errorf("ValidateRule() returned %d errors, want %d", len(errors), tt.wantErrors)
				for _, err := range errors {
					t.Logf("  Error: %s - %s", err.Type, err.Message)
				}
				return
			}

			if tt.wantErrors > 0 {
				if errors[0].Severity != tt.wantSeverity {
					t.Errorf("Error severity = %s, want %s", errors[0].Severity, tt.wantSeverity)
				}
				if errors[0].Type != tt.wantErrorType {
					t.Errorf("Error type = %s, want %s", errors[0].Type, tt.wantErrorType)
				}
			}
		})
	}
}

func TestValidatorRuleConflicts(t *testing.T) {
	validator := NewValidator(slog.New(slog.NewTextHandler(os.Stdout, nil)))

	rules := []*Rule{
		{
			ID:      1,
			Name:    "add-header",
			Enabled: true,
			Scope:   RuleScope{Direction: DirectionRequest},
			Actions: []Action{
				{Type: ActionAdd, Location: LocationHeader, Name: "X-Test", Value: "test"},
			},
		},
		{
			ID:      2,
			Name:    "remove-header",
			Enabled: true,
			Scope:   RuleScope{Direction: DirectionRequest},
			Actions: []Action{
				{Type: ActionRemove, Location: LocationHeader, Name: "X-Test"},
			},
		},
	}

	errors := validator.checkRuleConflicts(rules)

	if len(errors) == 0 {
		t.Error("Should detect conflict between add and remove actions")
	}

	found := false
	for _, err := range errors {
		if err.Type == ErrorTypeConflict {
			found = true
			break
		}
	}

	if !found {
		t.Error("Should have ErrorTypeConflict")
	}
}

func TestValidatorSamePriority(t *testing.T) {
	validator := NewValidator(slog.New(slog.NewTextHandler(os.Stdout, nil)))

	rules := []*Rule{
		{
			ID:       1,
			Name:     "rule1",
			Enabled:  true,
			Priority: 10,
			Scope:    RuleScope{Direction: DirectionRequest},
			Actions:  []Action{{Type: ActionAdd, Location: LocationHeader, Name: "X-1", Value: "1"}},
		},
		{
			ID:       2,
			Name:     "rule2",
			Enabled:  true,
			Priority: 10,
			Scope:    RuleScope{Direction: DirectionRequest},
			Actions:  []Action{{Type: ActionAdd, Location: LocationHeader, Name: "X-2", Value: "2"}},
		},
	}

	errors := validator.checkRuleConflicts(rules)

	// Should have at least one info message about same priority
	found := false
	for _, err := range errors {
		if err.Severity == SeverityInfo && err.Type == ErrorTypeLogic {
			found = true
			break
		}
	}

	if !found {
		t.Error("Should warn about rules with same priority")
	}
}

func TestValidatorComplexRegex(t *testing.T) {
	validator := NewValidator(slog.New(slog.NewTextHandler(os.Stdout, nil)))

	rule := &Rule{
		Name:    "complex-regex",
		Enabled: true,
		Scope:   RuleScope{Direction: DirectionRequest},
		Conditions: []Condition{
			{
				Type:     ConditionRegex,
				Location: LocationBody,
				Pattern:  "(.*)+", // Catastrophic backtracking
			},
		},
		Actions: []Action{{Type: ActionAdd, Location: LocationHeader, Name: "X-Test", Value: "test"}},
	}

	errors := validator.ValidateRule(rule)

	if len(errors) == 0 {
		t.Error("Should detect potentially slow regex")
	}

	found := false
	for _, err := range errors {
		if err.Type == ErrorTypePerformance {
			found = true
			if err.Suggestion == "" {
				t.Error("Should provide suggestion for performance issue")
			}
			break
		}
	}

	if !found {
		t.Error("Should have performance warning")
	}
}

func TestValidatorRegexErrors(t *testing.T) {
	validator := NewValidator(slog.New(slog.NewTextHandler(os.Stdout, nil)))

	tests := []struct {
		name     string
		pattern  string
		location string
	}{
		{"scope url pattern", "[invalid", "scope"},
		{"condition pattern", "(?P<unclosed", "condition"},
		{"action pattern", "(unmatched", "action"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rule *Rule

			switch tt.location {
			case "scope":
				rule = &Rule{
					Name:    "test",
					Enabled: true,
					Scope:   RuleScope{Direction: DirectionRequest, URLPattern: tt.pattern},
					Actions: []Action{{Type: ActionAdd, Location: LocationHeader, Name: "X-Test", Value: "test"}},
				}
			case "condition":
				rule = &Rule{
					Name:    "test",
					Enabled: true,
					Scope:   RuleScope{Direction: DirectionRequest},
					Conditions: []Condition{
						{Type: ConditionRegex, Location: LocationBody, Pattern: tt.pattern},
					},
					Actions: []Action{{Type: ActionAdd, Location: LocationHeader, Name: "X-Test", Value: "test"}},
				}
			case "action":
				rule = &Rule{
					Name:    "test",
					Enabled: true,
					Scope:   RuleScope{Direction: DirectionRequest},
					Actions: []Action{{Type: ActionReplace, Location: LocationBody, Pattern: tt.pattern, Value: "new"}},
				}
			}

			errors := validator.ValidateRule(rule)

			if len(errors) == 0 {
				t.Error("Should detect invalid regex")
			}

			if errors[0].Type != ErrorTypeRegex {
				t.Errorf("Error type = %s, want %s", errors[0].Type, ErrorTypeRegex)
			}

			if errors[0].Severity != SeverityError {
				t.Errorf("Severity = %s, want %s", errors[0].Severity, SeverityError)
			}
		})
	}
}

func TestValidatorReDoSProtection(t *testing.T) {
	validator := NewValidator(slog.New(slog.NewTextHandler(os.Stdout, nil)))

	tests := []struct {
		name        string
		pattern     string
		shouldError bool
		errorType   ErrorType
		description string
	}{
		{
			name:        "nested quantifier (.+)+",
			pattern:     "(.+)+",
			shouldError: true,
			errorType:   ErrorTypeRegex,
			description: "classic ReDoS pattern with nested quantifiers",
		},
		{
			name:        "nested quantifier (.*)+",
			pattern:     "(.*)+",
			shouldError: true,
			errorType:   ErrorTypePerformance,
			description: "catastrophic backtracking pattern",
		},
		{
			name:        "nested quantifier (.+)*",
			pattern:     "(.+)*",
			shouldError: true,
			errorType:   ErrorTypeRegex,
			description: "nested quantifier variation",
		},
		{
			name:        "overlapping alternation (a|a)+",
			pattern:     "(a|a)+",
			shouldError: true,
			errorType:   ErrorTypeRegex,
			description: "overlapping alternation causes exponential backtracking",
		},
		{
			name:        "nested groups with quantifiers",
			pattern:     "((a+)+)+",
			shouldError: true,
			errorType:   ErrorTypeRegex,
			description: "deeply nested quantifiers",
		},
		{
			name:        "safe pattern - simple match",
			pattern:     "^[a-z]+$",
			shouldError: false,
			description: "simple character class is safe",
		},
		{
			name:        "safe pattern - email-like",
			pattern:     `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`,
			shouldError: false,
			description: "common email pattern is safe",
		},
		{
			name:        "safe pattern - word boundaries",
			pattern:     `\bword\b`,
			shouldError: false,
			description: "word boundary pattern is safe",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &Rule{
				Name:    "redos-test",
				Enabled: true,
				Scope:   RuleScope{Direction: DirectionRequest},
				Conditions: []Condition{
					{Type: ConditionRegex, Location: LocationBody, Pattern: tt.pattern},
				},
				Actions: []Action{{Type: ActionAdd, Location: LocationHeader, Name: "X-Test", Value: "test"}},
			}

			errors := validator.ValidateRule(rule)

			if tt.shouldError {
				if len(errors) == 0 {
					t.Errorf("Expected error for pattern %q (%s), got none", tt.pattern, tt.description)
				} else {
					// Check that at least one error is of expected type
					found := false
					for _, err := range errors {
						if err.Type == tt.errorType || err.Type == ErrorTypePerformance || err.Type == ErrorTypeRegex {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Expected error type %s or performance/regex for pattern %q, got %v", tt.errorType, tt.pattern, errors)
					}
				}
			} else {
				// Should not have regex or performance errors
				for _, err := range errors {
					if err.Type == ErrorTypeRegex || (err.Type == ErrorTypePerformance && err.Severity == SeverityError) {
						t.Errorf("Unexpected error for safe pattern %q: %s - %s", tt.pattern, err.Type, err.Message)
					}
				}
			}
		})
	}
}

func TestValidatorReDoSInActionPatterns(t *testing.T) {
	validator := NewValidator(slog.New(slog.NewTextHandler(os.Stdout, nil)))

	// Test that ReDoS patterns in action patterns are also caught
	rule := &Rule{
		Name:    "redos-action",
		Enabled: true,
		Scope:   RuleScope{Direction: DirectionRequest},
		Actions: []Action{
			{Type: ActionReplace, Location: LocationBody, Pattern: "(.+)+", Value: "safe"},
		},
	}

	errors := validator.ValidateRule(rule)

	// Should detect the dangerous pattern
	found := false
	for _, err := range errors {
		if err.Type == ErrorTypeRegex || err.Type == ErrorTypePerformance {
			found = true
			break
		}
	}

	if !found {
		t.Error("Should detect ReDoS pattern in action regex")
	}
}

func TestValidatorReDoSInURLPattern(t *testing.T) {
	validator := NewValidator(slog.New(slog.NewTextHandler(os.Stdout, nil)))

	// Test that ReDoS patterns in URL scope patterns are also caught
	rule := &Rule{
		Name:    "redos-url",
		Enabled: true,
		Scope:   RuleScope{Direction: DirectionRequest, URLPattern: "(.+)+"},
		Actions: []Action{{Type: ActionAdd, Location: LocationHeader, Name: "X-Test", Value: "test"}},
	}

	errors := validator.ValidateRule(rule)

	// Should detect the dangerous pattern
	found := false
	for _, err := range errors {
		if err.Type == ErrorTypeRegex || err.Type == ErrorTypePerformance {
			found = true
			break
		}
	}

	if !found {
		t.Error("Should detect ReDoS pattern in URL pattern scope")
	}
}
