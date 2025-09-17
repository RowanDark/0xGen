package reporter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RowanDark/Glyph/internal/findings"
)

func TestRenderMarkdown(t *testing.T) {
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	findings := []findings.Finding{
		{ID: "1", Plugin: "p1", Type: "t", Message: "m", Target: "https://a", Severity: findings.SeverityHigh, DetectedAt: base},
		{ID: "2", Plugin: "p1", Type: "t", Message: "m", Target: "https://a", Severity: findings.SeverityMedium, DetectedAt: base},
		{ID: "3", Plugin: "p2", Type: "t", Message: "m", Target: "https://b", Severity: findings.SeverityLow, DetectedAt: base},
	}
	md := RenderMarkdown(findings, 5)
	if !strings.Contains(md, "Total findings: 3") {
		t.Fatalf("missing total count: %s", md)
	}
	if !strings.Contains(md, "| High | 1 |") {
		t.Fatalf("missing high count: %s", md)
	}
	if !strings.Contains(md, "1. **https://a** — 2 findings") {
		t.Fatalf("missing top target: %s", md)
	}
}

func TestRenderReportWritesFile(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "findings.jsonl")
	output := filepath.Join(dir, "report.md")

	writer := NewJSONL(input)
	sample := findings.Finding{
		ID:         "x",
		Plugin:     "p",
		Type:       "t",
		Message:    "m",
		Evidence:   "",
		Severity:   findings.SeverityCritical,
		DetectedAt: time.Unix(1710000000, 0).UTC(),
	}
	if err := writer.Write(sample); err != nil {
		t.Fatalf("write finding: %v", err)
	}

	if err := RenderReport(input, output, 3); err != nil {
		t.Fatalf("render report: %v", err)
	}

	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	if !strings.Contains(string(data), "Critical") {
		t.Fatalf("report missing severity: %s", data)
	}
	if !strings.Contains(string(data), "(not specified)") {
		t.Fatalf("report missing placeholder target: %s", data)
	}
}
