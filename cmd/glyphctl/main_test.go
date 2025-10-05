package main

import (
	"os"
	"path/filepath"
	"testing"
)

func silenceOutput(t *testing.T) func() {
	t.Helper()
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open dev null: %v", err)
	}
	stdout := os.Stdout
	stderr := os.Stderr
	os.Stdout = devNull
	os.Stderr = devNull
	return func() {
		os.Stdout = stdout
		os.Stderr = stderr
		if err := devNull.Close(); err != nil {
			t.Fatalf("close dev null: %v", err)
		}
	}
}

func TestRunManifestValidateValid(t *testing.T) {
	restore := silenceOutput(t)
	defer restore()

	path := filepath.Join("..", "..", "plugins", "samples", "passive-header-scan", "manifest.json")
	*manifestValidate = path
	t.Cleanup(func() { *manifestValidate = "" })

	if code := runManifestValidate(); code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
}

func TestRunManifestValidateInvalid(t *testing.T) {
	restore := silenceOutput(t)
	defer restore()

	path := filepath.Join("..", "..", "plugins", "samples", "invalid", "manifest.json")
	*manifestValidate = path
	t.Cleanup(func() { *manifestValidate = "" })

	if code := runManifestValidate(); code == 0 {
		t.Fatalf("expected non-zero exit code, got %d", code)
	}
}

func TestRunManifestValidateMissingFile(t *testing.T) {
	restore := silenceOutput(t)
	defer restore()

	*manifestValidate = filepath.Join(t.TempDir(), "missing.json")
	t.Cleanup(func() { *manifestValidate = "" })

	if code := runManifestValidate(); code != 2 {
		t.Fatalf("expected exit code 2 for read errors, got %d", code)
	}
}

func TestRunFindingsMissingSubcommand(t *testing.T) {
	restore := silenceOutput(t)
	defer restore()

	if code := runFindings(nil); code != 2 {
		t.Fatalf("expected exit code 2 for missing subcommand, got %d", code)
	}
}

func TestRunFindingsUnknownSubcommand(t *testing.T) {
	restore := silenceOutput(t)
	defer restore()

	if code := runFindings([]string{"bogus"}); code != 2 {
		t.Fatalf("expected exit code 2 for unknown subcommand, got %d", code)
	}
}

func TestRunVersion(t *testing.T) {
	restore := silenceOutput(t)
	defer restore()

	if code := runVersion(nil); code != 0 {
		t.Fatalf("expected version command to exit 0, got %d", code)
	}
}

func TestVersionFlag(t *testing.T) {
	restore := silenceOutput(t)
	defer restore()

	*showVersion = true
	t.Cleanup(func() { *showVersion = false })

	if handled := maybePrintVersion(); !handled {
		t.Fatalf("expected maybePrintVersion to handle --version flag")
	}
}

func TestRunDemo(t *testing.T) {
	restore := silenceOutput(t)
	defer restore()

	outDir := filepath.Join(t.TempDir(), "demo-out")
	if code := runDemo([]string{"--out", outDir}); code != 0 {
		t.Fatalf("expected demo command to exit 0, got %d", code)
	}

	if _, err := os.Stat(filepath.Join(outDir, "report.html")); err != nil {
		t.Fatalf("expected report.html to be written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "findings.jsonl")); err != nil {
		t.Fatalf("expected findings.jsonl to be written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "ranked.jsonl")); err != nil {
		t.Fatalf("expected ranked.jsonl to be written: %v", err)
	}
}
