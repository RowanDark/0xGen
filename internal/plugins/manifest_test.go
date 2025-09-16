package plugins

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadManifestRequiresCapabilities(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(manifestPath, []byte(`{"name":"demo","version":"1.0.0","entry":"/bin/demo"}`), 0o644); err != nil {
		t.Fatalf("failed to write manifest: %v", err)
	}

	if _, err := LoadManifest(manifestPath); err == nil {
		t.Fatalf("expected error when capabilities are missing")
	}
}
