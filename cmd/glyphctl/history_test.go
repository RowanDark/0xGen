package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RowanDark/Glyph/internal/history"
	"github.com/RowanDark/Glyph/internal/proxy"
)

func TestRunHistorySearchPrintsIDs(t *testing.T) {
	tempDir := t.TempDir()
	historyPath := filepath.Join(tempDir, "history.jsonl")

	entries := []proxy.HistoryEntry{
		{
			Timestamp: time.Now().UTC(),
			Protocol:  "https",
			Method:    "GET",
			URL:       "https://example.com/login",
		},
		{
			Timestamp: time.Now().UTC(),
			Protocol:  "https",
			Method:    "POST",
			URL:       "https://example.com/login",
		},
	}
	for _, entry := range entries {
		if err := history.Append(historyPath, entry); err != nil {
			t.Fatalf("append history: %v", err)
		}
	}

	output, code := captureStdout(t, func() int {
		return runHistorySearch([]string{"--history", historyPath, "--q", "method:POST"})
	})
	if code != 0 {
		t.Fatalf("runHistorySearch exit code = %d", code)
	}
	lines := strings.Fields(output)
	if len(lines) != 1 || lines[0] != "2" {
		t.Fatalf("expected to print ID 2, got %q", output)
	}
}

func captureStdout(t *testing.T, fn func() int) (string, int) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	code := fn()
	if err := w.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	os.Stdout = old
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("close reader: %v", err)
	}
	return string(data), code
}
