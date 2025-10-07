package perf

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestUpdateHistoryAndMarkdown(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")

	report := Report{
		Timestamp: time.Date(2024, 10, 10, 15, 0, 0, 0, time.UTC),
		GitRef:    "abc123",
		Workloads: []BusWorkloadMetrics{{
			Name:       "fanout",
			Throughput: 2000,
			CPUSeconds: 1.5,
			ErrorRate:  0.01,
			Memory: MemoryMetrics{
				BytesPerEvent: 512,
			},
		}},
	}

	history, err := UpdateHistory(path, report)
	if err != nil {
		t.Fatalf("update history: %v", err)
	}
	if got := len(history); got != 1 {
		t.Fatalf("expected 1 history entry, got %d", got)
	}

	// Append a newer run to ensure chronological ordering is preserved and
	// the data is persisted to disk.
	newer := report
	newer.Timestamp = newer.Timestamp.Add(24 * time.Hour)
	newer.GitRef = "def456"
	newer.Workloads[0].Throughput = 2400
	newer.Workloads[0].CPUSeconds = 1.2

	history, err = UpdateHistory(path, newer)
	if err != nil {
		t.Fatalf("update history second run: %v", err)
	}
	if got := len(history); got != 2 {
		t.Fatalf("expected 2 entries, got %d", got)
	}
	if history[0].GitRef != "abc123" || history[1].GitRef != "def456" {
		t.Fatalf("unexpected ordering: %+v", history)
	}

	md := RenderHistoryMarkdown(history)
	if !strings.Contains(md, "fanout") {
		t.Fatalf("markdown missing workload name: %s", md)
	}
	if !strings.Contains(md, "abc123") || !strings.Contains(md, "def456") {
		t.Fatalf("markdown missing git refs: %s", md)
	}
}

func TestSparklineConstant(t *testing.T) {
	t.Parallel()
	const length = 5
	line := sparkline([]float64{3, 3, 3, 3, 3})
	if utf8.RuneCountInString(line) != length {
		t.Fatalf("expected sparkline length %d, got %d", length, len(line))
	}
	if line != strings.Repeat("▁", length) {
		t.Fatalf("unexpected constant sparkline: %q", line)
	}
}
