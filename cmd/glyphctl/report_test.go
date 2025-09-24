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
		Version:    findings.SchemaVersion,
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

	now := time.Date(2024, 2, 1, 12, 0, 0, 0, time.UTC)
	if code := runReportAt([]string{"--input", input, "--out", output}, now); code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "## Totals by Severity") {
		t.Fatalf("report missing severity section: %s", content)
	}
	if !strings.Contains(content, "## Last 20 Findings") {
		t.Fatalf("report missing recent findings section: %s", content)
	}
	if !strings.Contains(content, "issue") {
		t.Fatalf("report missing evidence excerpt: %s", content)
	}
}

func TestRunReportMissingArgs(t *testing.T) {
	restore := silenceOutput(t)
	defer restore()

	if code := runReport([]string{"--input", "", "--out", ""}); code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
}

func TestRunReportMatchesGolden(t *testing.T) {
	restore := silenceOutput(t)
	defer restore()

	dir := t.TempDir()
	output := filepath.Join(dir, "report.md")
	input := filepath.Join("testdata", "findings.jsonl")

	now := time.Date(2024, 2, 1, 12, 0, 0, 0, time.UTC)
	if code := runReportAt([]string{"--input", input, "--out", output}, now); code != 0 {
		t.Fatalf("runReport exited with %d", code)
	}

	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read generated report: %v", err)
	}

	goldenPath := filepath.Join("testdata", "report_no_filter.golden")
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}

	if string(got) != string(want) {
		t.Fatalf("report mismatch\nwant:\n%s\n\ngot:\n%s", string(want), string(got))
	}
}

func TestRunReportSince24hMatchesGolden(t *testing.T) {
	restore := silenceOutput(t)
	defer restore()

	dir := t.TempDir()
	output := filepath.Join(dir, "report.md")
	input := filepath.Join("testdata", "findings.jsonl")

	now := time.Date(2024, 2, 1, 12, 0, 0, 0, time.UTC)
	if code := runReportAt([]string{"--input", input, "--out", output, "--since", "24h"}, now); code != 0 {
		t.Fatalf("runReport exited with %d", code)
	}

	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read generated report: %v", err)
	}

	goldenPath := filepath.Join("testdata", "report_since_24h.golden")
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}

	if string(got) != string(want) {
		t.Fatalf("report mismatch\nwant:\n%s\n\ngot:\n%s", string(want), string(got))
	}
}

func TestRunReportInvalidSince(t *testing.T) {
	restore := silenceOutput(t)
	defer restore()

	now := time.Date(2024, 2, 1, 12, 0, 0, 0, time.UTC)
	if code := runReportAt([]string{"--input", "in", "--out", "out", "--since", "nonsense"}, now); code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
}
