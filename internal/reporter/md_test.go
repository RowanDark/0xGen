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
	findings := []findings.Finding{
		{ID: "1", Target: "https://a", Severity: "high"},
		{ID: "2", Target: "https://a", Severity: "med"},
		{ID: "3", Target: "https://b", Severity: "low"},
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
	sample := findings.Finding{ID: "x", Plugin: "p", Target: "", Evidence: "", Severity: "crit", TS: time.Unix(1710000000, 0).UTC()}
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
