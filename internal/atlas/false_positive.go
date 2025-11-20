package atlas

import (
	"context"
	"strings"
)

// FalsePositiveDetector analyzes findings for false positives.
type FalsePositiveDetector struct {
	rules []FPRule
}

// FPRule defines a false positive detection rule.
type FPRule struct {
	Pattern     string
	FindingType string
	Action      FPAction
	Reason      string
}

// FPAction defines what action to take when rule matches.
type FPAction string

const (
	FPActionFlag     FPAction = "flag"     // Mark as potential FP
	FPActionSuppress FPAction = "suppress" // Auto-suppress
)

// FPAnalysis contains false positive analysis results.
type FPAnalysis struct {
	IsFalsePositive bool
	Confidence      float64
	Reasoning       string
	Reasons         []string
}

// NewFalsePositiveDetector creates a new FP detector.
func NewFalsePositiveDetector() *FalsePositiveDetector {
	return &FalsePositiveDetector{
		rules: defaultFPRules(),
	}
}

// defaultFPRules returns the default false positive detection rules.
func defaultFPRules() []FPRule {
	return []FPRule{
		// SQLi false positives
		{
			Pattern:     "syntax highlighting",
			FindingType: "SQL Injection",
			Action:      FPActionSuppress,
			Reason:      "Response contains syntax highlighting code, likely documentation",
		},
		{
			Pattern:     "SQL tutorial",
			FindingType: "SQL Injection",
			Action:      FPActionSuppress,
			Reason:      "Response contains SQL tutorial content",
		},
		{
			Pattern:     "example query",
			FindingType: "SQL Injection",
			Action:      FPActionFlag,
			Reason:      "Response may be showing example SQL queries",
		},
		{
			Pattern:     "documentation",
			FindingType: "SQL Injection",
			Action:      FPActionFlag,
			Reason:      "Response appears to be documentation",
		},

		// XSS false positives
		{
			Pattern:     "<script> tag documentation",
			FindingType: "Cross-Site Scripting",
			Action:      FPActionFlag,
			Reason:      "Response contains HTML/JavaScript documentation",
		},
		{
			Pattern:     "html tutorial",
			FindingType: "Cross-Site Scripting",
			Action:      FPActionFlag,
			Reason:      "Response contains HTML tutorial content",
		},
		{
			Pattern:     "code example",
			FindingType: "Cross-Site Scripting",
			Action:      FPActionFlag,
			Reason:      "Response contains code examples",
		},
		{
			Pattern:     "syntax:javascript",
			FindingType: "Cross-Site Scripting",
			Action:      FPActionSuppress,
			Reason:      "Response is syntax-highlighted code block",
		},

		// Path traversal false positives
		{
			Pattern:     "file not found",
			FindingType: "Path Traversal",
			Action:      FPActionFlag,
			Reason:      "File not found error may indicate filtering",
		},
		{
			Pattern:     "access denied",
			FindingType: "Path Traversal",
			Action:      FPActionFlag,
			Reason:      "Access denied indicates some filtering",
		},

		// Command injection false positives
		{
			Pattern:     "command reference",
			FindingType: "Command Injection",
			Action:      FPActionFlag,
			Reason:      "Response contains command reference documentation",
		},
		{
			Pattern:     "shell tutorial",
			FindingType: "Command Injection",
			Action:      FPActionFlag,
			Reason:      "Response contains shell tutorial content",
		},
	}
}

// Analyze checks if finding is likely a false positive.
func (d *FalsePositiveDetector) Analyze(ctx context.Context, f *Finding) (*FPAnalysis, error) {
	analysis := &FPAnalysis{
		IsFalsePositive: false,
		Confidence:      0,
		Reasons:         []string{},
	}

	// Rule-based detection
	for _, rule := range d.rules {
		if !strings.Contains(f.Type, rule.FindingType) {
			continue
		}

		responseLower := strings.ToLower(f.Response)
		if strings.Contains(responseLower, strings.ToLower(rule.Pattern)) {
			if rule.Action == FPActionSuppress {
				analysis.IsFalsePositive = true
				analysis.Confidence = 0.9
				analysis.Reasoning = rule.Reason
				analysis.Reasons = append(analysis.Reasons, rule.Reason)
				return analysis, nil
			}
			analysis.Reasons = append(analysis.Reasons, rule.Reason)
			analysis.Confidence = 0.5 // Flagged but not suppressed
		}
	}

	// Additional heuristics
	analysis = d.applyHeuristics(f, analysis)

	return analysis, nil
}

// applyHeuristics applies additional false positive detection heuristics.
func (d *FalsePositiveDetector) applyHeuristics(f *Finding, analysis *FPAnalysis) *FPAnalysis {
	responseLower := strings.ToLower(f.Response)

	// Check for test/demo pages
	testIndicators := []string{
		"test page",
		"demo page",
		"example application",
		"sample code",
		"playground",
		"sandbox",
	}

	for _, indicator := range testIndicators {
		if strings.Contains(responseLower, indicator) {
			analysis.Reasons = append(analysis.Reasons, "Response appears to be from a test/demo page")
			if analysis.Confidence < 0.6 {
				analysis.Confidence = 0.6
			}
			break
		}
	}

	// Check for error pages that might show payloads
	errorIndicators := []string{
		"400 bad request",
		"invalid input",
		"validation error",
		"parameter error",
	}

	for _, indicator := range errorIndicators {
		if strings.Contains(responseLower, indicator) {
			analysis.Reasons = append(analysis.Reasons, "Response shows validation/error message - payload may have been rejected")
			if analysis.Confidence < 0.4 {
				analysis.Confidence = 0.4
			}
			break
		}
	}

	// Check response length - very short responses with payloads might be errors
	if len(f.Response) < 100 && f.Payload != "" && strings.Contains(f.Response, f.Payload) {
		analysis.Reasons = append(analysis.Reasons, "short response length suggests potential error echo")
		if analysis.Confidence < 0.3 {
			analysis.Confidence = 0.3
		}
	}

	// Set reasoning if we have reasons
	if len(analysis.Reasons) > 0 {
		analysis.Reasoning = strings.Join(analysis.Reasons, "; ")
	}

	return analysis
}

// AddRule adds a custom false positive detection rule.
func (d *FalsePositiveDetector) AddRule(rule FPRule) {
	d.rules = append(d.rules, rule)
}

// GetRules returns all FP detection rules.
func (d *FalsePositiveDetector) GetRules() []FPRule {
	return d.rules
}
