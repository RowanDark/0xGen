package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/RowanDark/Glyph/internal/ranker"
)

func TestRunRankSuccess(t *testing.T) {
	restore := silenceOutput(t)
	defer restore()

	input := filepath.Join("..", "..", "internal", "ranker", "testdata", "findings.jsonl")
	output := filepath.Join(t.TempDir(), "ranked.jsonl")

	if code := runRank([]string{"--input", input, "--out", output}); code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	file, err := os.Open(output)
	if err != nil {
		t.Fatalf("open ranked output: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		t.Fatalf("expected ranked output to contain entries")
	}
	var first ranker.ScoredFinding
	if err := json.Unmarshal(scanner.Bytes(), &first); err != nil {
		t.Fatalf("unmarshal ranked finding: %v", err)
	}
	if first.ID != "01J0Y7AHAZ3ZKAB1Y7P5Z9Q4C0" {
		t.Fatalf("unexpected top ranked finding: %s", first.ID)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan ranked output: %v", err)
	}
}

func TestRunRankMissingArgs(t *testing.T) {
	restore := silenceOutput(t)
	defer restore()

	if code := runRank([]string{"--input", "", "--out", ""}); code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
}
