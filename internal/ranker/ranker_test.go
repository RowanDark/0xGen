package ranker_test

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/RowanDark/Glyph/internal/findings"
	"github.com/RowanDark/Glyph/internal/ranker"
)

func TestRankOrdersFindings(t *testing.T) {
	findings := loadFixture(t, "testdata/findings.jsonl")
	ranked := ranker.Rank(findings)

	if got, want := len(ranked), len(findings); got != want {
		t.Fatalf("ranked findings length mismatch: got %d want %d", got, want)
	}

	expectedTop := []string{
		"01J0Y7AHAZ3ZKAB1Y7P5Z9Q4C0", // critical RCE on public endpoint
		"01J0Y7AHAZ3ZKAB1Y7P5Z9Q4C1", // high severity secret on public endpoint
		"01J0Y7AHAZ3ZKAB1Y7P5Z9Q4C3", // high severity secret on internal endpoint
	}
	for i, wantID := range expectedTop {
		if ranked[i].ID != wantID {
			t.Fatalf("unexpected id at rank %d: got %s want %s", i, ranked[i].ID, wantID)
		}
	}

	// Duplicate detections on the same target should be collapsed so the
	// earliest detection keeps the high score.
	var primary, duplicate ranker.ScoredFinding
	for _, scored := range ranked {
		switch scored.ID {
		case "01J0Y7AHAZ3ZKAB1Y7P5Z9Q4C1":
			primary = scored
		case "01J0Y7AHAZ3ZKAB1Y7P5Z9Q4C2":
			duplicate = scored
		}
	}
	if primary.Score <= duplicate.Score {
		t.Fatalf("expected duplicate to receive a lower score: primary=%v duplicate=%v", primary.Score, duplicate.Score)
	}
	if duplicate.Primary {
		t.Fatalf("duplicate finding should not be marked primary")
	}

	// Ensure findings with the same score are ordered by detection timestamp.
	idxStaging := indexOf(ranked, "01J0Y7AHAZ3ZKAB1Y7P5Z9Q4C4")
	idxQA := indexOf(ranked, "01J0Y7AHAZ3ZKAB1Y7P5Z9Q4C5")
	if !(idxStaging < idxQA) {
		t.Fatalf("expected staging weak-credential finding to rank before QA due to earlier timestamp")
	}

	if primary.Frequency != 2 {
		t.Fatalf("expected frequency bonus for secret findings: got %d", primary.Frequency)
	}
	if primary.ExposureHint != "public" {
		t.Fatalf("expected exposure hint to be public, got %s", primary.ExposureHint)
	}

	tmp := t.TempDir()
	outputPath := filepath.Join(tmp, "ranked.jsonl")
	if err := ranker.WriteJSONL(outputPath, ranked); err != nil {
		t.Fatalf("write ranked output: %v", err)
	}
	if info, err := os.Stat(outputPath); err != nil {
		t.Fatalf("stat ranked output: %v", err)
	} else if info.Size() == 0 {
		t.Fatalf("expected ranked output to contain data")
	}
}

func loadFixture(t *testing.T, path string) []findings.Finding {
	t.Helper()

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime caller lookup failed")
	}

	file, err := os.Open(filepath.Join(filepath.Dir(currentFile), path))
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 1024), 1024*1024)

	var out []findings.Finding
	for scanner.Scan() {
		var f findings.Finding
		if err := json.Unmarshal(scanner.Bytes(), &f); err != nil {
			t.Fatalf("unmarshal finding: %v", err)
		}
		out = append(out, f)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan fixture: %v", err)
	}
	return out
}

func indexOf(ranked []ranker.ScoredFinding, id string) int {
	for idx, scored := range ranked {
		if scored.ID == id {
			return idx
		}
	}
	return -1
}
