package raider

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPayloadsFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "payloads.txt")
	if err := os.WriteFile(path, []byte("one\ntwo\n"), 0o600); err != nil {
		t.Fatalf("write payload file: %v", err)
	}

	values, err := LoadPayloads(path)
	if err != nil {
		t.Fatalf("load payloads: %v", err)
	}
	if len(values) != 2 || values[0] != "one" || values[1] != "two" {
		t.Fatalf("unexpected payloads: %#v", values)
	}
}

func TestLoadPayloadsRange(t *testing.T) {
	values, err := LoadPayloads("3-5")
	if err != nil {
		t.Fatalf("load payloads: %v", err)
	}
	expected := []string{"3", "4", "5"}
	if len(values) != len(expected) {
		t.Fatalf("expected %d values, got %d", len(expected), len(values))
	}
	for i, v := range expected {
		if values[i] != v {
			t.Fatalf("unexpected value at %d: %q", i, values[i])
		}
	}
}

func TestLoadPayloadsWordList(t *testing.T) {
	values, err := LoadPayloads("alpha,beta , gamma")
	if err != nil {
		t.Fatalf("load payloads: %v", err)
	}
	expected := []string{"alpha", "beta", "gamma"}
	if len(values) != len(expected) {
		t.Fatalf("expected %d values, got %d", len(expected), len(values))
	}
	for i, v := range expected {
		if values[i] != v {
			t.Fatalf("unexpected value at %d: %q", i, values[i])
		}
	}
}
