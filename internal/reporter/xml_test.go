package reporter

import (
	"encoding/xml"
	"strings"
	"testing"
	"time"

	"github.com/RowanDark/0xgen/internal/findings"
)

func TestRenderXML(t *testing.T) {
	testFindings := []findings.Finding{
		{
			ID:       "TEST001",
			Type:     "SQL Injection",
			Message:  "SQL injection vulnerability found",
			Target:   "https://example.com/api/users",
			Severity: findings.SeverityCritical,
			Plugin:   "sqli-detector",
			Evidence: "Payload: ' OR 1=1--",
			DetectedAt: findings.NewTimestamp(time.Now()),
			Metadata: map[string]string{
				"cwe": "CWE-89",
			},
		},
		{
			ID:       "TEST002",
			Type:     "XSS",
			Message:  "Cross-site scripting vulnerability",
			Target:   "https://example.com/search",
			Severity: findings.SeverityHigh,
			Plugin:   "xss-detector",
			Evidence: "Payload: <script>alert(1)</script>",
			DetectedAt: findings.NewTimestamp(time.Now()),
		},
	}

	opts := ReportOptions{}
	data, err := RenderXML(testFindings, opts)
	if err != nil {
		t.Fatalf("RenderXML() failed: %v", err)
	}

	output := string(data)

	// Check XML declaration
	if !strings.HasPrefix(output, "<?xml version") {
		t.Error("XML output missing declaration")
	}

	// Check root element
	if !strings.Contains(output, "<SecurityReport") {
		t.Error("XML output missing root SecurityReport element")
	}

	// Check summary
	if !strings.Contains(output, "<Summary>") {
		t.Error("XML output missing Summary element")
	}
	if !strings.Contains(output, "<TotalFindings>2</TotalFindings>") {
		t.Error("XML output missing total findings count")
	}

	// Check findings
	if !strings.Contains(output, "SQL Injection") {
		t.Error("XML output missing SQL Injection finding")
	}
	if !strings.Contains(output, "TEST001") {
		t.Error("XML output missing TEST001")
	}

	// Verify it's valid XML by unmarshaling
	var report XMLReport
	if err := xml.Unmarshal(data, &report); err != nil {
		t.Fatalf("Generated XML is invalid: %v", err)
	}

	// Verify structure
	if report.Version != "1.0" {
		t.Errorf("Expected version 1.0, got %s", report.Version)
	}
	if report.Summary.Total != 2 {
		t.Errorf("Expected 2 total findings, got %d", report.Summary.Total)
	}
	if len(report.Findings) != 2 {
		t.Errorf("Expected 2 findings, got %d", len(report.Findings))
	}

	// Check severity breakdown
	if report.Summary.SeverityBreakdown.Critical != 1 {
		t.Errorf("Expected 1 critical finding, got %d", report.Summary.SeverityBreakdown.Critical)
	}
	if report.Summary.SeverityBreakdown.High != 1 {
		t.Errorf("Expected 1 high finding, got %d", report.Summary.SeverityBreakdown.High)
	}

	// Check metadata
	if len(report.Findings[0].Metadata) == 0 {
		t.Error("Expected metadata for first finding")
	}
}

func TestRenderXMLEmpty(t *testing.T) {
	opts := ReportOptions{}
	data, err := RenderXML([]findings.Finding{}, opts)
	if err != nil {
		t.Fatalf("RenderXML() with empty findings failed: %v", err)
	}

	// Should still be valid XML
	var report XMLReport
	if err := xml.Unmarshal(data, &report); err != nil {
		t.Fatalf("Generated XML is invalid: %v", err)
	}

	if report.Summary.Total != 0 {
		t.Errorf("Expected 0 total findings, got %d", report.Summary.Total)
	}
	if len(report.Findings) != 0 {
		t.Errorf("Expected 0 findings, got %d", len(report.Findings))
	}
}
