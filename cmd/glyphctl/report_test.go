package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RowanDark/Glyph/internal/findings"
	"github.com/RowanDark/Glyph/internal/reporter"
)

func TestRunReportSuccess(t *testing.T) {
	restore := silenceOutput(t)
	defer restore()

	dir := t.TempDir()
	input := filepath.Join(dir, "findings.jsonl")
	output := filepath.Join(dir, "report.md")

	writer := reporter.NewJSONL(input)
	sample := findings.Finding{
		ID:         findings.NewID(),
		Plugin:     "p",
		Type:       "t",
		Message:    "m",
		Target:     "https://example.com",
		Evidence:   "issue",
		Severity:   findings.SeverityLow,
		DetectedAt: findings.NewTimestamp(time.Unix(1710000000, 0).UTC()),
	}
	if err := writer.Write(sample); err != nil {
		t.Fatalf("write finding: %v", err)
	}

	if code := runReport([]string{"--input", input, "--out", output, "--top", "3"}); code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	if !strings.Contains(string(data), "Findings Report") {
		t.Fatalf("report missing header: %s", data)
	}
}

func TestRunReportMissingArgs(t *testing.T) {
	restore := silenceOutput(t)
	defer restore()

	if code := runReport([]string{"--input", "", "--out", ""}); code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
}
