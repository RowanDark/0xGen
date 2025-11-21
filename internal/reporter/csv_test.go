package reporter

import (
	"strings"
	"testing"
	"time"

	"github.com/RowanDark/0xgen/internal/findings"
)

func TestRenderCSV(t *testing.T) {
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
	data, err := RenderCSV(testFindings, opts)
	if err != nil {
		t.Fatalf("RenderCSV() failed: %v", err)
	}

	output := string(data)

	// Check header
	if !strings.Contains(output, "ID,Severity,Type,Message,Target,Plugin,Evidence,Detected At") {
		t.Error("CSV output missing expected header")
	}

	// Check data rows
	if !strings.Contains(output, "TEST001") {
		t.Error("CSV output missing TEST001")
	}
	if !strings.Contains(output, "SQL Injection") {
		t.Error("CSV output missing SQL Injection")
	}
	if !strings.Contains(output, "crit") {
		t.Error("CSV output missing critical severity")
	}

	// Check summary
	if !strings.Contains(output, "# Summary") {
		t.Error("CSV output missing summary section")
	}
	if !strings.Contains(output, "# Total Findings: 2") {
		t.Error("CSV output missing total findings count")
	}
}

func TestRenderCSVEmpty(t *testing.T) {
	opts := ReportOptions{}
	data, err := RenderCSV([]findings.Finding{}, opts)
	if err != nil {
		t.Fatalf("RenderCSV() with empty findings failed: %v", err)
	}

	output := string(data)

	// Should still have header
	if !strings.Contains(output, "ID,Severity,Type") {
		t.Error("Empty CSV should still have header")
	}

	// Should have summary
	if !strings.Contains(output, "# Total Findings: 0") {
		t.Error("Empty CSV should have zero count in summary")
	}
}
