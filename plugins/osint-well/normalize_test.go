package osintwell

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestNormalizeProducesJSONL(t *testing.T) {
	repoRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}

	fixture := filepath.Join(repoRoot, "tests", "amass_passive.json")
	outDir := t.TempDir()
	outputPath := filepath.Join(outDir, "assets.jsonl")

	normalize := filepath.Join(repoRoot, "normalize.js")
	cmd := exec.Command("node", normalize, fixture, outputPath)
	cmd.Env = append(os.Environ(), "GLYPH_OUT="+outDir)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("normalize.js failed: %v\n%s", err, stderr.String())
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("failed to read normalized output: %v", err)
	}

	expected := "{\"type\":\"subdomain\",\"value\":\"blog.example.com\",\"source\":\"amass\",\"ts\":\"2024-05-02T10:00:00.000Z\"}\n" +
		"{\"type\":\"subdomain\",\"value\":\"www.example.com\",\"source\":\"amass\",\"ts\":\"2024-05-01T00:00:00.000Z\"}\n"

	if string(data) != expected {
		t.Fatalf("unexpected normalization output\nexpected:\n%s\ngot:\n%s", expected, string(data))
	}
}
