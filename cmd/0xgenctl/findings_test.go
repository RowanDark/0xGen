package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunFindingsValidateSuccess(t *testing.T) {
	restore := silenceOutput(t)
	defer restore()

	input := filepath.Join("testdata", "findings.jsonl")
	if code := runFindingsValidate([]string{"--input", input}); code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
}

func TestRunFindingsValidateInvalid(t *testing.T) {
	restore := silenceOutput(t)
	defer restore()

	dir := t.TempDir()
	path := filepath.Join(dir, "bad.jsonl")
	if err := os.WriteFile(path, []byte(`{"id":"missing-version"}`+"\n"), 0o644); err != nil {
		t.Fatalf("write invalid fixture: %v", err)
	}
	if code := runFindingsValidate([]string{"--input", path}); code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
}

func TestRunFindingsMigrate(t *testing.T) {
	restore := silenceOutput(t)
	defer restore()

	input := filepath.Join("testdata", "findings.v0.1.jsonl")
	output := filepath.Join(t.TempDir(), "findings.v0.2.jsonl")
	if code := runFindingsMigrate([]string{"--input", input, "--output", output}); code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read migrated file: %v", err)
	}
	wantPath := filepath.Join("testdata", "findings.v0.2.golden.jsonl")
	want, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("migration mismatch\nwant:\n%s\n\ngot:\n%s", string(want), string(got))
	}
}
