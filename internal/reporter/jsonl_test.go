package reporter

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/RowanDark/Glyph/internal/findings"
)

func TestJSONLWriteAndRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "findings.jsonl")
	reporter := NewJSONL(path)

	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	f1 := findings.Finding{
		ID:         "a",
		Plugin:     "plugin-a",
		Type:       "missing-header",
		Message:    "Missing X-Test",
		Target:     "https://a",
		Evidence:   "issue",
		Severity:   findings.SeverityLow,
		DetectedAt: base,
	}
	f2 := findings.Finding{
		ID:         "b",
		Plugin:     "plugin-b",
		Type:       "missing-header",
		Message:    "Missing X-Other",
		Target:     "https://b",
		Evidence:   "issue",
		Severity:   findings.SeverityHigh,
		DetectedAt: base.Add(1 * time.Hour),
	}

	if err := reporter.Write(f1); err != nil {
		t.Fatalf("write f1: %v", err)
	}
	if err := reporter.Write(f2); err != nil {
		t.Fatalf("write f2: %v", err)
	}

	list, err := reporter.ReadAll()
	if err != nil {
		t.Fatalf("read all: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(list))
	}
	if list[0].ID != f1.ID || !list[0].DetectedAt.Equal(f1.DetectedAt) {
		t.Fatalf("unexpected first finding: %+v", list[0])
	}
	if list[1].ID != f2.ID || !list[1].DetectedAt.Equal(f2.DetectedAt) {
		t.Fatalf("unexpected second finding: %+v", list[1])
	}
}

func TestJSONLRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "findings.jsonl")
	content := `{"id":"a","plugin":"p","type":"x","message":"m","severity":"LOW","detected_at":"2024-01-01T00:00:00Z","unexpected":true}`
	if err := os.WriteFile(path, []byte(content+"\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	reporter := NewJSONL(path)
	if _, err := reporter.ReadAll(); err == nil {
		t.Fatal("expected error for unknown field, got nil")
	}
}

func TestJSONLRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "findings.jsonl")
	reporter := NewJSONL(path, WithMaxBytes(150))

	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		f := findings.Finding{
			ID:         fmt.Sprintf("id-%d", i),
			Plugin:     "plugin",
			Type:       "t",
			Message:    "m",
			Severity:   findings.SeverityInfo,
			DetectedAt: base.Add(time.Duration(i) * time.Minute),
		}
		if err := reporter.Write(f); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	matches, err := filepath.Glob(filepath.Join(dir, "findings.jsonl.*"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("expected rotated files to exist")
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
