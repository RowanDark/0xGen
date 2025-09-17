package reporter

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/RowanDark/Glyph/internal/findings"
)

func TestJSONLWriteAndRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "findings.jsonl")
	reporter := NewJSONL(path)

	f1 := findings.Finding{ID: "a", Plugin: "plugin-a", Target: "https://a", Evidence: "issue", Severity: "low", TS: time.Unix(1710000000, 0).UTC()}
	f2 := findings.Finding{ID: "b", Plugin: "plugin-b", Target: "https://b", Evidence: "issue", Severity: "high", TS: time.Unix(1710003600, 0).UTC()}

	if err := reporter.Write(f1); err != nil {
		t.Fatalf("write f1: %v", err)
	}
	if err := reporter.Write(f2); err != nil {
		t.Fatalf("write f2: %v", err)
	}

	findings, err := reporter.ReadAll()
	if err != nil {
		t.Fatalf("read all: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	if findings[0].ID != f1.ID || !findings[0].TS.Equal(f1.TS) {
		t.Fatalf("unexpected first finding: %+v", findings[0])
	}
	if findings[1].ID != f2.ID || !findings[1].TS.Equal(f2.TS) {
		t.Fatalf("unexpected second finding: %+v", findings[1])
	}
}

func TestReadJSONLMissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "missing.jsonl")
	findings, err := ReadJSONL(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected empty slice, got %d findings", len(findings))
	}
}
