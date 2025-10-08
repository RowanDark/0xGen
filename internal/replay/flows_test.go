package replay

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteAndLoadFlows(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "flows.jsonl")
	flows := []FlowRecord{
		{ID: "b", Sequence: 2, Type: "FLOW_RESPONSE", TimestampUnix: 20, SanitizedBase64: "b"},
		{ID: "a", Sequence: 1, Type: "FLOW_REQUEST", TimestampUnix: 10, SanitizedBase64: "a"},
	}
	if err := WriteFlows(path, flows); err != nil {
		t.Fatalf("write flows: %v", err)
	}
	loaded, err := LoadFlows(path)
	if err != nil {
		t.Fatalf("load flows: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("expected 2 records, got %d", len(loaded))
	}
	if loaded[0].ID != "a" || loaded[0].Sequence != 1 {
		t.Fatalf("records not sorted: %#v", loaded)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read flows: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("flows file should not be empty")
	}
}
