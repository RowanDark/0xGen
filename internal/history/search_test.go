package history_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/RowanDark/Glyph/internal/history"
	"github.com/RowanDark/Glyph/internal/proxy"
)

func TestLoadAndSearch(t *testing.T) {
	t.Helper()
	tempDir := t.TempDir()
	historyPath := filepath.Join(tempDir, "history.jsonl")

	fixtures := []proxy.HistoryEntry{
		{
			Timestamp:    time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
			Protocol:     "https",
			Method:       "GET",
			URL:          "https://example.com/login",
			StatusCode:   200,
			MatchedRules: []string{"auth-rewrite"},
		},
		{
			Timestamp:  time.Date(2024, 1, 1, 12, 5, 0, 0, time.UTC),
			Protocol:   "https",
			Method:     "POST",
			URL:        "https://example.com/login",
			StatusCode: 401,
			RequestHeaders: map[string][]string{
				"Content-Type": []string{"application/json"},
			},
		},
		{
			Timestamp:    time.Date(2024, 1, 1, 13, 0, 0, 0, time.UTC),
			Protocol:     "https",
			Method:       "POST",
			URL:          "https://api.internal/status",
			StatusCode:   500,
			MatchedRules: []string{"Upstream"},
		},
	}

	for _, entry := range fixtures {
		if err := history.Append(historyPath, entry); err != nil {
			t.Fatalf("append history: %v", err)
		}
	}

	index, err := history.Load(historyPath)
	if err != nil {
		t.Fatalf("load history: %v", err)
	}

	results, err := index.Search("host:example.com method:POST")
	if err != nil {
		t.Fatalf("search history: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected one result, got %d", len(results))
	}
	if results[0].ID != "2" {
		t.Fatalf("expected ID 2, got %s", results[0].ID)
	}
	if results[0].Record.StatusCode != 401 {
		t.Fatalf("unexpected status code: %d", results[0].Record.StatusCode)
	}

	rules, err := index.Search("rule:auth-rewrite")
	if err != nil {
		t.Fatalf("search by rule: %v", err)
	}
	if len(rules) != 1 || rules[0].ID != "1" {
		t.Fatalf("expected rule match ID 1, got %+v", rules)
	}

	status, err := index.Search("status:500")
	if err != nil {
		t.Fatalf("search by status: %v", err)
	}
	if len(status) != 1 || status[0].ID != "3" {
		t.Fatalf("expected status match ID 3, got %+v", status)
	}

	all, err := index.Search("")
	if err != nil {
		t.Fatalf("search all: %v", err)
	}
	if len(all) != len(fixtures) {
		t.Fatalf("expected %d results, got %d", len(fixtures), len(all))
	}
}

func TestEntryLookup(t *testing.T) {
	tempDir := t.TempDir()
	historyPath := filepath.Join(tempDir, "history.jsonl")

	entry := proxy.HistoryEntry{
		Timestamp:  time.Now().UTC(),
		Protocol:   "http",
		Method:     "GET",
		URL:        "http://example.org/demo",
		StatusCode: 200,
	}
	if err := history.Append(historyPath, entry); err != nil {
		t.Fatalf("append history: %v", err)
	}

	index, err := history.Load(historyPath)
	if err != nil {
		t.Fatalf("load history: %v", err)
	}

	got, ok := index.Entry("1")
	if !ok {
		t.Fatal("expected entry with ID 1")
	}
	if got.Record.URL != entry.URL {
		t.Fatalf("expected URL %q, got %q", entry.URL, got.Record.URL)
	}
	if got.Record.Method != entry.Method {
		t.Fatalf("expected method %q, got %q", entry.Method, got.Record.Method)
	}

	if _, ok := index.Entry("2"); ok {
		t.Fatal("unexpected entry with ID 2")
	}
}
