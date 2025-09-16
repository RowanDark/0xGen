package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunInvalidManifestReturnsNonZero(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(manifestPath, []byte(`{"name":"demo","version":"1.0.0","entry":"/bin/demo"}`), 0o644); err != nil {
		t.Fatalf("failed to write manifest: %v", err)
	}

	var stdout, stderr strings.Builder
	code := run([]string{"--manifest", manifestPath}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("expected non-zero exit code, got %d", code)
	}
	if !strings.Contains(stderr.String(), "capability") {
		t.Fatalf("expected error mentioning capabilities, got %q", stderr.String())
	}
}
