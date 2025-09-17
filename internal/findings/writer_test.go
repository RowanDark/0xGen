package findings

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWriterWritesFindings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "findings.jsonl")
	writer := NewWriter(path)
	defer func() {
		_ = writer.Close()
	}()

	sample := Finding{
		ID:         "01HZXK4QAZ3ZKAB1Y7P5Z9Q4C4",
		Plugin:     "p",
		Type:       "t",
		Message:    "m",
		Severity:   SeverityLow,
		DetectedAt: NewTimestamp(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)),
	}

	if err := writer.Write(sample); err != nil {
		t.Fatalf("write finding: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read findings: %v", err)
	}
	if count := strings.Count(string(data), "\n"); count != 1 {
		t.Fatalf("expected 1 line, got %d", count)
	}
}

func TestWriterRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "findings.jsonl")
	writer := NewWriter(path, WithMaxBytes(200), WithMaxRotations(2))
	defer func() {
		_ = writer.Close()
	}()

	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 10; i++ {
		f := Finding{
			ID:         NewID(),
			Plugin:     "p",
			Type:       "t",
			Message:    "m",
			Severity:   SeverityInfo,
			DetectedAt: NewTimestamp(base.Add(time.Duration(i) * time.Second)),
		}
		if err := writer.Write(f); err != nil {
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
	if len(matches) > 2 {
		t.Fatalf("expected at most 2 rotated files, got %d", len(matches))
	}
}

func TestWriterRejectsInvalidFinding(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "findings.jsonl")
	writer := NewWriter(path)
	defer func() {
		_ = writer.Close()
	}()

	bad := Finding{}
	if err := writer.Write(bad); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestDefaultPathHonoursEnv(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GLYPH_OUT", dir)
	w := NewWriter("")
	defer func() {
		_ = w.Close()
	}()

	sample := Finding{
		ID:         NewID(),
		Plugin:     "p",
		Type:       "t",
		Message:    "m",
		Severity:   SeverityInfo,
		DetectedAt: NewTimestamp(time.Now()),
	}
	if err := w.Write(sample); err != nil {
		t.Fatalf("write finding: %v", err)
	}

	file := filepath.Join(dir, "findings.jsonl")
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("expected findings at %s: %v", file, err)
	}
}

func BenchmarkWriter(b *testing.B) {
	dir := b.TempDir()
	path := filepath.Join(dir, "findings.jsonl")
	writer := NewWriter(path)
	defer func() {
		_ = writer.Close()
	}()

	sample := Finding{
		ID:         NewID(),
		Plugin:     "p",
		Type:       "t",
		Message:    "m",
		Severity:   SeverityInfo,
		DetectedAt: NewTimestamp(time.Now()),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sample.ID = NewID()
		if err := writer.Write(sample); err != nil {
			b.Fatalf("write: %v", err)
		}
	}
}
