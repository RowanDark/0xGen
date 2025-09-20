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
		{ID: "01HZXK4QAZ3ZKAB1Y7P5Z9Q4C4", Plugin: "p1", Type: "t", Message: "high", Target: "https://a", Severity: findings.SeverityHigh, DetectedAt: findings.NewTimestamp(base.Add(2 * time.Hour))},
		{ID: "01HZXK4QAZ3ZKAB1Y7P5Z9Q4C5", Plugin: "p1", Type: "t", Message: "medium", Target: "https://a", Severity: findings.SeverityMedium, DetectedAt: findings.NewTimestamp(base.Add(1 * time.Hour))},
		{ID: "01HZXK4QAZ3ZKAB1Y7P5Z9Q4C6", Plugin: "p2", Type: "t", Message: "low", Target: "https://b", Severity: findings.SeverityLow, DetectedAt: findings.NewTimestamp(base)},
	}

	got := RenderMarkdown(findings)
	goldenPath := filepath.Join("testdata", "report.golden")
	wantBytes, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	want := string(wantBytes)
	if got != want {
		t.Fatalf("markdown mismatch\nwant:\n%s\n\ngot:\n%s", want, got)
	}
}

func TestRenderReportWritesFile(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "findings.jsonl")
	output := filepath.Join(dir, "report.md")

	writer := NewJSONL(input)
	sample := findings.Finding{
		ID:         findings.NewID(),
		Plugin:     "p",
		Type:       "t",
		Message:    "m",
		Evidence:   "",
		Severity:   findings.SeverityCritical,
		DetectedAt: findings.NewTimestamp(time.Unix(1710000000, 0).UTC()),
	}
	if err := writer.Write(sample); err != nil {
		t.Fatalf("write finding: %v", err)
	}

	if err := RenderReport(input, output); err != nil {
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
