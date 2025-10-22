package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRunExportJSONL(t *testing.T) {
	restore := silenceOutput(t)
	defer restore()

	dir := t.TempDir()
	inputPath := filepath.Join(dir, "findings.jsonl")
	writeFixtureJSONL(t, inputPath)
	outputPath := filepath.Join(dir, "cases.jsonl")

	if code := runExport([]string{"--input", inputPath, "--out", outputPath, "--format", "jsonl"}); code != 0 {
		t.Fatalf("runExport jsonl exited with %d", code)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read export: %v", err)
	}
	if len(data) == 0 {
		t.Fatalf("expected JSONL output")
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("expected telemetry + single case entry, got %d lines", len(lines))
	}
	var telemetry map[string]any
	if err := json.Unmarshal(lines[0], &telemetry); err != nil {
		t.Fatalf("unmarshal telemetry: %v", err)
	}
	if telemetry["type"] != "telemetry" {
		t.Fatalf("expected telemetry entry, got %v", telemetry["type"])
	}
}

func TestRunExportSARIF(t *testing.T) {
	restore := silenceOutput(t)
	defer restore()

	dir := t.TempDir()
	inputPath := filepath.Join(dir, "findings.jsonl")
	writeFixtureJSONL(t, inputPath)
	outputPath := filepath.Join(dir, "cases.sarif")

	if code := runExport([]string{"--input", inputPath, "--out", outputPath, "--format", "sarif"}); code != 0 {
		t.Fatalf("runExport sarif exited with %d", code)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read sarif: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal sarif: %v", err)
	}
	if doc["version"] != "2.1.0" {
		t.Fatalf("unexpected SARIF version: %v", doc["version"])
	}
}

func TestRunExportCSV(t *testing.T) {
	restore := silenceOutput(t)
	defer restore()

	dir := t.TempDir()
	inputPath := filepath.Join(dir, "findings.jsonl")
	writeFixtureJSONL(t, inputPath)
	outputPath := filepath.Join(dir, "cases.csv")

	if code := runExport([]string{"--input", inputPath, "--out", outputPath, "--format", "csv"}); code != 0 {
		t.Fatalf("runExport csv exited with %d", code)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}
	if bytes.Count(data, []byte("\n")) < 1 {
		t.Fatalf("expected csv header and rows")
	}
}

func TestRunExportMissingFormat(t *testing.T) {
	restore := silenceOutput(t)
	defer restore()

	dir := t.TempDir()
	inputPath := filepath.Join(dir, "findings.jsonl")
	writeFixtureJSONL(t, inputPath)

	if code := runExport([]string{"--input", inputPath}); code != 2 {
		t.Fatalf("expected error exit code, got %d", code)
	}
}

func writeFixtureJSONL(t *testing.T, path string) {
	t.Helper()
	fixture := filepath.Join("..", "..", "internal", "cases", "testdata", "sample_web_service_findings.json")
	data, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var records []map[string]any
	if err := json.Unmarshal(data, &records); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create jsonl: %v", err)
	}
	defer file.Close()
	enc := json.NewEncoder(file)
	for _, rec := range records {
		if err := enc.Encode(rec); err != nil {
			t.Fatalf("encode jsonl record: %v", err)
		}
	}
}
