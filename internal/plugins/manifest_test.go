package plugins_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RowanDark/Glyph/internal/plugins"
)

func TestAcceptsValidManifest(t *testing.T) {
	path := filepath.Join("..", "..", "plugins", "samples", "passive-header-scan", "manifest.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var m plugins.Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("json: %v", err)
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestRejectsInvalidManifest(t *testing.T) {
	path := filepath.Join("..", "..", "plugins", "samples", "invalid", "manifest.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var m plugins.Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("json: %v", err)
	}
	if err := m.Validate(); err == nil {
		t.Fatalf("expected validation error for invalid manifest")
	}
}

func TestValidateRequiresCapabilities(t *testing.T) {
	m := plugins.Manifest{
		Name:    "demo",
		Version: "1.0.0",
		Entry:   "plugin.js",
	}
	if err := m.Validate(); err == nil {
		t.Fatalf("expected error when capabilities are missing")
	}
}

func TestLoadManifestRejectsUnknownField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(path, []byte(`{"name":"demo","version":"1.0.0","entry":"plugin.js","capabilities":["CAP_HTTP_PASSIVE"],"unexpected":true}`), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	err := plugins.ValidateManifest(path)
	if err == nil {
		t.Fatalf("expected validation error for unknown field")
	}
	if !strings.Contains(err.Error(), "decode manifest") {
		t.Fatalf("expected decode error, got: %v", err)
	}
}
