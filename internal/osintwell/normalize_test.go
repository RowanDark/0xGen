package osintwell

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNormalizeAggregatesAmassOutput(t *testing.T) {
	input := `{"timestamp":"2024-01-01T00:00:00Z","name":"a.example.com","domain":"example.com","sources":["DNS"],"addresses":[{"ip":"1.1.1.1"}]}
{"timestamp":"2024-01-02T00:00:00Z","name":"a.example.com","domain":"","sources":["CERT"],"addresses":[{"ip":"2.2.2.2"}],"tag":"dns"}
{"timestamp":"invalid","name":"b.example.com","domain":"example.com","sources":["WHOIS"],"addresses":[]}`

	now := func() time.Time { return time.Date(2024, 1, 3, 0, 0, 0, 0, time.UTC) }
	records, err := Normalize(strings.NewReader(input), now, "amass-passive")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}

	first := records[0]
	if first.Name != "a.example.com" {
		t.Fatalf("first record name = %q", first.Name)
	}
	if first.Domain != "example.com" {
		t.Fatalf("first record domain = %q", first.Domain)
	}
	if len(first.Addresses) != 2 || first.Addresses[0] != "1.1.1.1" || first.Addresses[1] != "2.2.2.2" {
		t.Fatalf("unexpected addresses: %#v", first.Addresses)
	}
	if len(first.Sources) != 2 {
		t.Fatalf("unexpected sources: %#v", first.Sources)
	}
	if len(first.Tags) != 1 || first.Tags[0] != "dns" {
		t.Fatalf("unexpected tags: %#v", first.Tags)
	}
	if !first.FirstSeen.Equal(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("first seen = %s", first.FirstSeen)
	}
	if first.Tool != "amass-passive" {
		t.Fatalf("tool label = %q", first.Tool)
	}

	second := records[1]
	if second.Name != "b.example.com" {
		t.Fatalf("second record name = %q", second.Name)
	}
	if !second.FirstSeen.Equal(now()) {
		t.Fatalf("second record first seen = %s", second.FirstSeen)
	}
}

func TestWriteRecords(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "assets.jsonl")
	records := []Record{
		{
			Name:      "a.example.com",
			Domain:    "example.com",
			Addresses: []string{"1.1.1.1"},
			Sources:   []string{"DNS"},
			Tags:      []string{"dns"},
			FirstSeen: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			Tool:      "amass-passive",
		},
	}
	if err := writeRecords(path, records); err != nil {
		t.Fatalf("write records: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read assets: %v", err)
	}
	if !strings.Contains(string(data), "amass-passive") {
		t.Fatalf("missing tool label in output: %s", data)
	}
}

func TestRunRequiresDomain(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Run(ctx, Config{}); err == nil {
		t.Fatal("expected error for missing domain")
	}
}
