package rewrite

import (
	"fmt"
	"log/slog"
	"regexp"
	"strings"
)

// Validator checks rules for common mistakes and potential issues.
type Validator struct {
	logger *slog.Logger
}

// NewValidator creates a new validator.
func NewValidator(logger *slog.Logger) *Validator {
	if logger == nil {
		logger = slog.Default()
	}
	return &Validator{logger: logger}
}

// ValidationError represents a validation warning or error.
type ValidationError struct {
	RuleID      int          `json:"rule_id,omitempty"`
	RuleName    string       `json:"rule_name,omitempty"`
	Severity    Severity     `json:"severity"`
	Type        ErrorType    `json:"type"`
	Message     string       `json:"message"`
	Suggestion  string       `json:"suggestion,omitempty"`
	Location    string       `json:"location,omitempty"` // Which part of the rule
}

// Severity levels for validation errors.
type Severity string

const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
	SeverityInfo    Severity = "info"
)

// ErrorType categorizes the type of validation error.
type ErrorType string

const (
	ErrorTypeRegex        ErrorType = "regex"
	ErrorTypeConflict     ErrorType = "conflict"
	ErrorTypePerformance  ErrorType = "performance"
	ErrorTypeInfiniteLoop ErrorType = "infinite_loop"
	ErrorTypeLogic        ErrorType = "logic"
	ErrorTypeSecurity     ErrorType = "security"
)

// ValidateRules validates a set of rules and returns warnings/errors.
func (v *Validator) ValidateRules(rules []*Rule) []ValidationError {
	errors := make([]ValidationError, 0)

	for _, rule := range rules {
		errors = append(errors, v.ValidateRule(rule)...)
	}

	// Check for conflicts between rules
	errors = append(errors, v.checkRuleConflicts(rules)...)

	return errors
}

// ValidateRule validates a single rule.
func (v *Validator) ValidateRule(rule *Rule) []ValidationError {
	errors := make([]ValidationError, 0)

	// Check regex patterns
	errors = append(errors, v.checkRegexPatterns(rule)...)

	// Check for overly broad patterns
	errors = append(errors, v.checkBroadPatterns(rule)...)

	// Check for performance issues
	errors = append(errors, v.checkPerformance(rule)...)

	// Check for logical issues
	errors = append(errors, v.checkLogic(rule)...)

	// Check for potential infinite loops
	errors = append(errors, v.checkInfiniteLoops(rule)...)

	// Check for security issues
	errors = append(errors, v.checkSecurity(rule)...)

	return errors
}

// checkRegexPatterns validates regex patterns in the rule.
func (v *Validator) checkRegexPatterns(rule *Rule) []ValidationError {
	errors := make([]ValidationError, 0)

	// Check scope URL pattern
	if rule.Scope.URLPattern != "" {
		if _, err := regexp.Compile(rule.Scope.URLPattern); err != nil {
			errors = append(errors, ValidationError{
				RuleID:     rule.ID,
				RuleName:   rule.Name,
				Severity:   SeverityError,
				Type:       ErrorTypeRegex,
				Message:    fmt.Sprintf("Invalid URL pattern regex: %v", err),
				Location:   "scope.url_pattern",
				Suggestion: "Check your regex syntax. Common issues: unescaped characters, unclosed groups.",
			})
		}
	}

	// Check condition patterns
	for i, cond := range rule.Conditions {
		if cond.Type == ConditionRegex && cond.Pattern != "" {
			if _, err := regexp.Compile(cond.Pattern); err != nil {
				errors = append(errors, ValidationError{
					RuleID:     rule.ID,
					RuleName:   rule.Name,
					Severity:   SeverityError,
					Type:       ErrorTypeRegex,
					Message:    fmt.Sprintf("Invalid regex in condition %d: %v", i, err),
					Location:   fmt.Sprintf("conditions[%d].pattern", i),
					Suggestion: "Verify your regex pattern is valid.",
				})
			}
		}
	}

	// Check action patterns
	for i, action := range rule.Actions {
		if action.Type == ActionReplace && action.Pattern != "" {
			if _, err := regexp.Compile(action.Pattern); err != nil {
				errors = append(errors, ValidationError{
					RuleID:     rule.ID,
					RuleName:   rule.Name,
					Severity:   SeverityError,
					Type:       ErrorTypeRegex,
					Message:    fmt.Sprintf("Invalid regex in action %d: %v", i, err),
					Location:   fmt.Sprintf("actions[%d].pattern", i),
					Suggestion: "Check your replacement pattern syntax.",
				})
			}
		}
	}

	return errors
}

// checkBroadPatterns checks for overly broad regex patterns.
func (v *Validator) checkBroadPatterns(rule *Rule) []ValidationError {
	errors := make([]ValidationError, 0)

	dangerousPatterns := []struct {
		pattern    string
		suggestion string
	}{
		{`^.*$`, "This matches everything. Be more specific or remove the pattern."},
		{`.+`, "This matches any non-empty string. Consider using a more specific pattern."},
		{`.*`, "This matches anything including empty strings. Be more specific."},
		{`^.*`, "This matches from the start to anywhere. Consider adding an end anchor or being more specific."},
		{`.*$`, "This matches from anywhere to the end. Consider adding a start anchor or being more specific."},
	}

	// Check conditions
	for i, cond := range rule.Conditions {
		if cond.Type == ConditionRegex {
			for _, dp := range dangerousPatterns {
				if cond.Pattern == dp.pattern {
					errors = append(errors, ValidationError{
						RuleID:     rule.ID,
						RuleName:   rule.Name,
						Severity:   SeverityWarning,
						Type:       ErrorTypePerformance,
						Message:    fmt.Sprintf("Overly broad regex pattern in condition %d: %s", i, cond.Pattern),
						Location:   fmt.Sprintf("conditions[%d].pattern", i),
						Suggestion: dp.suggestion,
					})
				}
			}
		}
	}

	// Check actions
	for i, action := range rule.Actions {
		if action.Type == ActionReplace {
			for _, dp := range dangerousPatterns {
				if action.Pattern == dp.pattern {
					errors = append(errors, ValidationError{
						RuleID:     rule.ID,
						RuleName:   rule.Name,
						Severity:   SeverityWarning,
						Type:       ErrorTypePerformance,
						Message:    fmt.Sprintf("Overly broad regex pattern in action %d: %s", i, action.Pattern),
						Location:   fmt.Sprintf("actions[%d].pattern", i),
						Suggestion: dp.suggestion,
					})
				}
			}
		}
	}

	return errors
}

// checkPerformance checks for potential performance issues.
func (v *Validator) checkPerformance(rule *Rule) []ValidationError {
	errors := make([]ValidationError, 0)

	// Check for complex regex patterns that might be slow
	complexPatterns := []string{
		`.*.*`, // Nested quantifiers
		`.+.+`, // Multiple greedy quantifiers
		`(.*)+`, // Quantifier on group with quantifier
		`(.+)+`, // Catastrophic backtracking
	}

	for i, cond := range rule.Conditions {
		if cond.Type == ConditionRegex {
			for _, cp := range complexPatterns {
				if strings.Contains(cond.Pattern, cp) {
					errors = append(errors, ValidationError{
						RuleID:     rule.ID,
						RuleName:   rule.Name,
						Severity:   SeverityWarning,
						Type:       ErrorTypePerformance,
						Message:    fmt.Sprintf("Potentially slow regex in condition %d (catastrophic backtracking risk)", i),
						Location:   fmt.Sprintf("conditions[%d].pattern", i),
						Suggestion: "Simplify your regex or use non-greedy quantifiers (.*? instead of .*).",
					})
				}
			}
		}
	}

	// Warn about body operations on large responses
	for i, action := range rule.Actions {
		if action.Location == LocationBody {
			errors = append(errors, ValidationError{
				RuleID:     rule.ID,
				RuleName:   rule.Name,
				Severity:   SeverityInfo,
				Type:       ErrorTypePerformance,
				Message:    fmt.Sprintf("Action %d operates on body - may be slow for large responses", i),
				Location:   fmt.Sprintf("actions[%d]", i),
				Suggestion: "Consider adding a Content-Length condition to skip large bodies.",
			})
		}
	}

	return errors
}

// checkLogic checks for logical issues in the rule.
func (v *Validator) checkLogic(rule *Rule) []ValidationError {
	errors := make([]ValidationError, 0)

	// Check for contradictory conditions
	hasExists := false
	hasNotExists := false
	for i, cond := range rule.Conditions {
		if cond.Type == ConditionExists && !cond.Negate {
			hasExists = true
		}
		if cond.Type == ConditionExists && cond.Negate {
			hasNotExists = true
		}

		// Check for same location with contradictory checks
		if i < len(rule.Conditions)-1 {
			for j := i + 1; j < len(rule.Conditions); j++ {
				if rule.Conditions[i].Location == rule.Conditions[j].Location &&
					rule.Conditions[i].Name == rule.Conditions[j].Name {
					// Same location and name - check for contradictions
					if rule.Conditions[i].Type == ConditionMatch && rule.Conditions[j].Type == ConditionNotMatch {
						errors = append(errors, ValidationError{
							RuleID:     rule.ID,
							RuleName:   rule.Name,
							Severity:   SeverityWarning,
							Type:       ErrorTypeLogic,
							Message:    fmt.Sprintf("Contradictory conditions: %d and %d check the same location", i, j),
							Location:   "conditions",
							Suggestion: "Remove one of the contradictory conditions.",
						})
					}
				}
			}
		}
	}

	if hasExists && hasNotExists {
		errors = append(errors, ValidationError{
			RuleID:     rule.ID,
			RuleName:   rule.Name,
			Severity:   SeverityWarning,
			Type:       ErrorTypeLogic,
			Message:    "Rule has both 'exists' and 'not exists' conditions",
			Location:   "conditions",
			Suggestion: "This rule may never match. Review your conditions.",
		})
	}

	// Check for actions that might cancel each other
	addedHeaders := make(map[string]bool)
	removedHeaders := make(map[string]bool)
	for _, action := range rule.Actions {
		if action.Location == LocationHeader {
			if action.Type == ActionAdd {
				addedHeaders[action.Name] = true
			}
			if action.Type == ActionRemove {
				removedHeaders[action.Name] = true
			}
		}
	}

	for header := range addedHeaders {
		if removedHeaders[header] {
			errors = append(errors, ValidationError{
				RuleID:     rule.ID,
				RuleName:   rule.Name,
				Severity:   SeverityWarning,
				Type:       ErrorTypeLogic,
				Message:    fmt.Sprintf("Rule both adds and removes header '%s'", header),
				Location:   "actions",
				Suggestion: "Remove one of the conflicting actions or split into separate rules.",
			})
		}
	}

	return errors
}

// checkInfiniteLoops checks for potential infinite loop scenarios.
func (v *Validator) checkInfiniteLoops(rule *Rule) []ValidationError {
	errors := make([]ValidationError, 0)

	// Check if rule modifies something it also checks
	for _, cond := range rule.Conditions {
		for _, action := range rule.Actions {
			if cond.Location == action.Location && cond.Name == action.Name {
				if action.Type == ActionReplace || action.Type == ActionAdd {
					errors = append(errors, ValidationError{
						RuleID:     rule.ID,
						RuleName:   rule.Name,
						Severity:   SeverityWarning,
						Type:       ErrorTypeInfiniteLoop,
						Message:    fmt.Sprintf("Rule checks and modifies the same location: %s[%s]", action.Location, action.Name),
						Location:   "conditions/actions",
						Suggestion: "Ensure the condition won't match after the action, or split into separate rules.",
					})
				}
			}
		}
	}

	return errors
}

// checkSecurity checks for potential security issues.
func (v *Validator) checkSecurity(rule *Rule) []ValidationError {
	errors := make([]ValidationError, 0)

	// Check for hardcoded secrets in actions
	secretPatterns := []struct {
		pattern string
		name    string
	}{
		{`(?i)password\s*=\s*['"]\w+['"]`, "password"},
		{`(?i)api[_-]?key\s*=\s*['"]\w+['"]`, "API key"},
		{`(?i)secret\s*=\s*['"]\w+['"]`, "secret"},
		{`(?i)token\s*=\s*['"]\w+['"]`, "token"},
	}

	for i, action := range rule.Actions {
		for _, sp := range secretPatterns {
			matched, _ := regexp.MatchString(sp.pattern, action.Value)
			if matched {
				errors = append(errors, ValidationError{
					RuleID:     rule.ID,
					RuleName:   rule.Name,
					Severity:   SeverityWarning,
					Type:       ErrorTypeSecurity,
					Message:    fmt.Sprintf("Possible hardcoded %s in action %d", sp.name, i),
					Location:   fmt.Sprintf("actions[%d].value", i),
					Suggestion: "Consider using variables instead of hardcoding sensitive values.",
				})
			}
		}
	}

	// Warn about disabling security headers
	securityHeaders := []string{
		"Content-Security-Policy",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"Strict-Transport-Security",
		"X-XSS-Protection",
	}

	for i, action := range rule.Actions {
		if action.Type == ActionRemove && action.Location == LocationHeader {
			for _, sh := range securityHeaders {
				if strings.EqualFold(action.Name, sh) {
					errors = append(errors, ValidationError{
						RuleID:     rule.ID,
						RuleName:   rule.Name,
						Severity:   SeverityWarning,
						Type:       ErrorTypeSecurity,
						Message:    fmt.Sprintf("Action %d removes security header '%s'", i, sh),
						Location:   fmt.Sprintf("actions[%d]", i),
						Suggestion: "Be cautious when removing security headers.",
					})
				}
			}
		}
	}

	return errors
}

// checkRuleConflicts checks for conflicts between multiple rules.
func (v *Validator) checkRuleConflicts(rules []*Rule) []ValidationError {
	errors := make([]ValidationError, 0)

	// Check for rules with same priority
	priorityMap := make(map[int][]*Rule)
	for _, rule := range rules {
		if rule.Enabled {
			priorityMap[rule.Priority] = append(priorityMap[rule.Priority], rule)
		}
	}

	for priority, rulesAtPriority := range priorityMap {
		if len(rulesAtPriority) > 1 {
			ruleNames := make([]string, len(rulesAtPriority))
			for i, r := range rulesAtPriority {
				ruleNames[i] = r.Name
			}
			errors = append(errors, ValidationError{
				Severity:   SeverityInfo,
				Type:       ErrorTypeLogic,
				Message:    fmt.Sprintf("Multiple rules have the same priority %d: %s", priority, strings.Join(ruleNames, ", ")),
				Suggestion: "Consider setting different priorities for deterministic rule order.",
			})
		}
	}

	// Check for conflicting actions across rules
	// (This is complex - simplified version)
	for i := 0; i < len(rules)-1; i++ {
		for j := i + 1; j < len(rules); j++ {
			if rules[i].Enabled && rules[j].Enabled {
				// Check if rules might conflict
				if v.rulesConflict(rules[i], rules[j]) {
					errors = append(errors, ValidationError{
						Severity: SeverityInfo,
						Type:     ErrorTypeConflict,
						Message: fmt.Sprintf("Rules '%s' and '%s' may conflict",
							rules[i].Name, rules[j].Name),
						Suggestion: "Review rule order and actions to ensure expected behavior.",
					})
				}
			}
		}
	}

	return errors
}

// rulesConflict checks if two rules might conflict.
func (v *Validator) rulesConflict(r1, r2 *Rule) bool {
	// Simple heuristic: check if they operate on same locations
	for _, a1 := range r1.Actions {
		for _, a2 := range r2.Actions {
			if a1.Location == a2.Location && a1.Name == a2.Name {
				// Same location - potential conflict
				if (a1.Type == ActionRemove && a2.Type == ActionAdd) ||
					(a1.Type == ActionAdd && a2.Type == ActionRemove) {
					return true
				}
			}
		}
	}
	return false
}
