package atlas

import (
	"context"
	"strings"
	"testing"
)

func TestFalsePositiveDetector_SQLiTutorial(t *testing.T) {
	detector := NewFalsePositiveDetector()

	finding := &Finding{
		Type:     "SQL Injection (Error-based)",
		URL:      "http://example.com/tutorial",
		Response: "This is a SQL tutorial showing example queries with SQL syntax highlighting...",
	}

	analysis, err := detector.Analyze(context.Background(), finding)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if !analysis.IsFalsePositive {
		t.Error("SQL tutorial should be detected as false positive")
	}

	if analysis.Confidence < 0.8 {
		t.Errorf("Confidence should be high for tutorial, got %.2f", analysis.Confidence)
	}
}

func TestFalsePositiveDetector_XSSDocumentation(t *testing.T) {
	detector := NewFalsePositiveDetector()

	finding := &Finding{
		Type:     "Cross-Site Scripting (Reflected)",
		URL:      "http://example.com/docs",
		Response: "HTML tutorial: The <script> tag documentation...",
	}

	analysis, err := detector.Analyze(context.Background(), finding)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	// Should be flagged but not auto-suppressed
	if len(analysis.Reasons) == 0 {
		t.Error("XSS in documentation should be flagged")
	}

	if analysis.Confidence >= 0.9 {
		t.Errorf("Documentation should have moderate confidence, got %.2f", analysis.Confidence)
	}
}

func TestFalsePositiveDetector_TestPage(t *testing.T) {
	detector := NewFalsePositiveDetector()

	finding := &Finding{
		Type:     "SQL Injection (Error-based)",
		URL:      "http://example.com/test",
		Response: "This is a test page for demonstration purposes...",
	}

	analysis, err := detector.Analyze(context.Background(), finding)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	// Should apply test page heuristic
	hasTestPageReason := false
	for _, reason := range analysis.Reasons {
		if strings.Contains(reason, "test/demo page") {
			hasTestPageReason = true
			break
		}
	}

	if !hasTestPageReason {
		t.Error("Test page heuristic should be applied")
	}

	if analysis.Confidence == 0 {
		t.Error("Confidence should be non-zero for test page")
	}
}

func TestFalsePositiveDetector_ValidationError(t *testing.T) {
	detector := NewFalsePositiveDetector()

	finding := &Finding{
		Type:     "SQL Injection (Error-based)",
		URL:      "http://example.com/user",
		Response: "400 Bad Request: Invalid input detected",
	}

	analysis, err := detector.Analyze(context.Background(), finding)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	// Should flag validation errors
	hasValidationReason := false
	for _, reason := range analysis.Reasons {
		if strings.Contains(reason, "validation") || strings.Contains(reason, "error") {
			hasValidationReason = true
			break
		}
	}

	if !hasValidationReason {
		t.Error("Validation error heuristic should be applied")
	}
}

func TestFalsePositiveDetector_ShortResponse(t *testing.T) {
	detector := NewFalsePositiveDetector()

	payload := "' OR 1=1--"
	finding := &Finding{
		Type:     "SQL Injection (Error-based)",
		URL:      "http://example.com/user",
		Response: payload, // Very short response that just echoes payload
		Payload:  payload,
	}

	analysis, err := detector.Analyze(context.Background(), finding)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	// Should flag short responses
	hasShortResponseReason := false
	for _, reason := range analysis.Reasons {
		if strings.Contains(reason, "short response") {
			hasShortResponseReason = true
			break
		}
	}

	if !hasShortResponseReason {
		t.Error("Short response heuristic should be applied")
	}
}

func TestFalsePositiveDetector_LegitimateVulnerability(t *testing.T) {
	detector := NewFalsePositiveDetector()

	finding := &Finding{
		Type:     "SQL Injection (Error-based)",
		URL:      "http://example.com/user",
		Response: "Database error: You have an error in your SQL syntax near 'admin' at line 1\nUser data: admin, admin@example.com, 12345",
		Payload:  "' OR 1=1--",
	}

	analysis, err := detector.Analyze(context.Background(), finding)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	// Should not be flagged as FP (no matching patterns)
	if analysis.IsFalsePositive {
		t.Error("Legitimate vulnerability should not be marked as false positive")
	}

	if analysis.Confidence > 0.7 {
		t.Errorf("Confidence should be low for legitimate vuln, got %.2f", analysis.Confidence)
	}
}

func TestFalsePositiveDetector_AddCustomRule(t *testing.T) {
	detector := NewFalsePositiveDetector()

	customRule := FPRule{
		Pattern:     "staging environment",
		FindingType: "SQL Injection",
		Action:      FPActionSuppress,
		Reason:      "Finding in staging environment",
	}

	detector.AddRule(customRule)

	finding := &Finding{
		Type:     "SQL Injection (Error-based)",
		URL:      "http://staging.example.com/user",
		Response: "This is a staging environment warning...",
	}

	analysis, err := detector.Analyze(context.Background(), finding)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if !analysis.IsFalsePositive {
		t.Error("Custom rule should suppress finding")
	}
}

func TestFalsePositiveDetector_GetRules(t *testing.T) {
	detector := NewFalsePositiveDetector()

	rules := detector.GetRules()

	if len(rules) == 0 {
		t.Error("Detector should have default rules")
	}

	// Check for expected default rules
	hasSQLiRule := false
	hasXSSRule := false

	for _, rule := range rules {
		if strings.Contains(rule.FindingType, "SQL Injection") {
			hasSQLiRule = true
		}
		if strings.Contains(rule.FindingType, "Cross-Site Scripting") {
			hasXSSRule = true
		}
	}

	if !hasSQLiRule {
		t.Error("Should have SQL Injection rules")
	}

	if !hasXSSRule {
		t.Error("Should have XSS rules")
	}
}

func TestFalsePositiveDetector_NoFalsePositive(t *testing.T) {
	detector := NewFalsePositiveDetector()

	finding := &Finding{
		Type:     "SQL Injection (Error-based)",
		URL:      "http://example.com/api/users",
		Response: "SELECT * FROM users WHERE id = 1; Results: [user data here]",
	}

	analysis, err := detector.Analyze(context.Background(), finding)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if analysis.IsFalsePositive {
		t.Error("Real vulnerability should not be flagged as FP")
	}

	// Should have low confidence or no reasons
	if analysis.Confidence > 0.7 {
		t.Errorf("Confidence should be low for real vuln, got %.2f", analysis.Confidence)
	}
}
