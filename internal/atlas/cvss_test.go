package atlas

import (
	"testing"
)

func TestCVSSCalculator_SQLi(t *testing.T) {
	calc := NewCVSSCalculator()

	finding := &Finding{
		Type:     "SQL Injection (Error-based)",
		Severity: "", // Will be calculated
	}

	calc.EnrichFinding(finding)

	// SQL Injection should score high (> 7.0)
	if finding.CVSS < 7.0 {
		t.Errorf("SQL Injection should score >= 7.0, got %.1f", finding.CVSS)
	}

	if finding.CWE != "CWE-89" {
		t.Errorf("expected CWE-89, got %s", finding.CWE)
	}

	if finding.OWASP != "A03:2021 - Injection" {
		t.Errorf("expected A03:2021, got %s", finding.OWASP)
	}

	if finding.Severity != SeverityHigh && finding.Severity != SeverityCritical {
		t.Errorf("expected High or Critical severity, got %s", finding.Severity)
	}

	if finding.Remediation == "" {
		t.Error("Remediation should be set")
	}
}

func TestCVSSCalculator_XSS(t *testing.T) {
	calc := NewCVSSCalculator()

	finding := &Finding{
		Type: "Cross-Site Scripting (Reflected)",
	}

	calc.EnrichFinding(finding)

	// XSS should be medium to high severity
	if finding.CVSS < 4.0 {
		t.Errorf("XSS should score >= 4.0, got %.1f", finding.CVSS)
	}

	if finding.CWE != "CWE-79" {
		t.Errorf("expected CWE-79, got %s", finding.CWE)
	}

	if finding.OWASP != "A03:2021 - Injection" {
		t.Errorf("expected A03:2021, got %s", finding.OWASP)
	}
}

func TestCVSSCalculator_PathTraversal(t *testing.T) {
	calc := NewCVSSCalculator()

	finding := &Finding{
		Type: "Path Traversal",
	}

	calc.EnrichFinding(finding)

	if finding.CWE != "CWE-22" {
		t.Errorf("expected CWE-22, got %s", finding.CWE)
	}

	if finding.OWASP != "A01:2021 - Broken Access Control" {
		t.Errorf("expected A01:2021, got %s", finding.OWASP)
	}
}

func TestCVSSCalculator_SSRF(t *testing.T) {
	calc := NewCVSSCalculator()

	finding := &Finding{
		Type: "Server-Side Request Forgery (Cloud Metadata)",
	}

	calc.EnrichFinding(finding)

	// SSRF should score medium to high (6.0+)
	if finding.CVSS < 6.0 {
		t.Errorf("SSRF should score >= 6.0, got %.1f", finding.CVSS)
	}

	if finding.CWE != "CWE-918" {
		t.Errorf("expected CWE-918, got %s", finding.CWE)
	}

	if finding.OWASP != "A10:2021 - Server-Side Request Forgery" {
		t.Errorf("expected A10:2021, got %s", finding.OWASP)
	}
}

func TestCVSSCalculator_XXE(t *testing.T) {
	calc := NewCVSSCalculator()

	finding := &Finding{
		Type: "XML External Entity (File Disclosure)",
	}

	calc.EnrichFinding(finding)

	// XXE should score medium to high (6.0+)
	if finding.CVSS < 6.0 {
		t.Errorf("XXE should score >= 6.0, got %.1f", finding.CVSS)
	}

	if finding.CWE != "CWE-611" {
		t.Errorf("expected CWE-611, got %s", finding.CWE)
	}
}

func TestCVSSCalculator_CommandInjection(t *testing.T) {
	calc := NewCVSSCalculator()

	finding := &Finding{
		Type: "Command Injection",
	}

	calc.EnrichFinding(finding)

	// Command Injection should score critical
	if finding.CVSS < 8.0 {
		t.Errorf("Command Injection should score >= 8.0, got %.1f", finding.CVSS)
	}

	if finding.CWE != "CWE-78" {
		t.Errorf("expected CWE-78, got %s", finding.CWE)
	}
}

func TestCVSSCalculator_Authentication(t *testing.T) {
	calc := NewCVSSCalculator()

	finding := &Finding{
		Type: "Missing Authentication",
	}

	calc.EnrichFinding(finding)

	if finding.CWE != "CWE-287" {
		t.Errorf("expected CWE-287, got %s", finding.CWE)
	}

	if finding.OWASP != "A07:2021 - Identification and Authentication Failures" {
		t.Errorf("expected A07:2021, got %s", finding.OWASP)
	}
}

func TestCVSSCalculator_CVSSToSeverity(t *testing.T) {
	calc := NewCVSSCalculator()

	tests := []struct {
		score    float64
		severity Severity
	}{
		{9.5, SeverityCritical},
		{9.0, SeverityCritical},
		{8.5, SeverityHigh},
		{7.0, SeverityHigh},
		{6.5, SeverityMedium},
		{4.0, SeverityMedium},
		{3.5, SeverityLow},
		{0.1, SeverityLow},
		{0.0, SeverityInfo},
	}

	for _, tt := range tests {
		result := calc.cvssToSeverity(tt.score)
		if result != tt.severity {
			t.Errorf("score %.1f: expected %s, got %s", tt.score, tt.severity, result)
		}
	}
}

func TestCVSSCalculator_DontDowngradeSeverity(t *testing.T) {
	calc := NewCVSSCalculator()

	// Finding with manually set higher severity
	finding := &Finding{
		Type:     "Path Traversal", // Usually Medium severity
		Severity: SeverityCritical,  // Manually set to Critical
	}

	calc.EnrichFinding(finding)

	// Should not downgrade severity
	if finding.Severity != SeverityCritical {
		t.Errorf("EnrichFinding should not downgrade severity, got %s", finding.Severity)
	}
}

func TestCVSSCalculator_PreserveCWE(t *testing.T) {
	calc := NewCVSSCalculator()

	finding := &Finding{
		Type: "SQL Injection (Error-based)",
		CWE:  "CWE-Custom",
	}

	calc.EnrichFinding(finding)

	// Should not override existing CWE
	if finding.CWE != "CWE-Custom" {
		t.Errorf("EnrichFinding should preserve existing CWE, got %s", finding.CWE)
	}
}

func TestCVSSCalculator_CalculateScore(t *testing.T) {
	calc := NewCVSSCalculator()

	finding := &Finding{
		Type: "SQL Injection (Error-based)",
	}

	score := calc.CalculateCVSS(finding)

	// Score should be between 0 and 10
	if score < 0 || score > 10 {
		t.Errorf("CVSS score should be between 0 and 10, got %.1f", score)
	}

	// Score should be rounded to 1 decimal place
	rounded := float64(int(score*10)) / 10
	if score != rounded {
		t.Errorf("CVSS score should be rounded to 1 decimal, got %.2f", score)
	}
}
