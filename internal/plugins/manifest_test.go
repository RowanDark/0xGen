package plugins_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RowanDark/Glyph/internal/plugins"
)

func validManifest() plugins.Manifest {
	return plugins.Manifest{
		Name:         "demo",
		Version:      "1.0.0",
		Entry:        "plugin.js",
		Artifact:     "plugin.js",
		Capabilities: []string{"CAP_HTTP_PASSIVE"},
		Signature: &plugins.Signature{
			Signature: "plugin.js.sig",
			PublicKey: "glyph-plugin.pub",
		},
	}
}

func TestManifestValidateHappyPath(t *testing.T) {
	m := validManifest()
	if err := m.Validate(); err != nil {
		t.Fatalf("expected manifest to be valid, got error: %v", err)
	}
}

func TestManifestValidateRejectsUnknownCapability(t *testing.T) {
	m := validManifest()
	m.Capabilities = append(m.Capabilities, "CAP_UNKNOWN")

	err := m.Validate()
	if err == nil {
		t.Fatalf("expected validation error for unknown capability")
	}
	if !strings.Contains(err.Error(), "unknown capability") {
		t.Fatalf("expected unknown capability error, got: %v", err)
	}
}

func TestManifestValidateRejectsDuplicateCapability(t *testing.T) {
	m := validManifest()
	m.Capabilities = append(m.Capabilities, m.Capabilities[0])

	err := m.Validate()
	if err == nil {
		t.Fatalf("expected validation error for duplicate capability")
	}
	if !strings.Contains(err.Error(), "duplicate capability") {
		t.Fatalf("expected duplicate capability error, got: %v", err)
	}
}

func TestManifestValidateRejectsEmptyCapability(t *testing.T) {
	m := validManifest()
	m.Capabilities = append(m.Capabilities, "")

	err := m.Validate()
	if err == nil {
		t.Fatalf("expected validation error for empty capability")
	}
	if !strings.Contains(err.Error(), "cannot be empty") {
		t.Fatalf("expected empty capability error, got: %v", err)
	}
}

func TestValidateRequiresCapabilities(t *testing.T) {
	m := validManifest()
	m.Capabilities = nil

	if err := m.Validate(); err == nil {
		t.Fatalf("expected error when capabilities are missing")
	}
}

func TestValidateRequiresMetadata(t *testing.T) {
	m := plugins.Manifest{}

	if err := m.Validate(); err == nil {
		t.Fatalf("expected error when metadata fields are missing")
	}
}

func TestValidateRequiresSignature(t *testing.T) {
	m := validManifest()
	m.Signature = nil

	err := m.Validate()
	if err == nil {
		t.Fatalf("expected validation error when signature metadata is missing")
	}
	if !strings.Contains(err.Error(), "signature") {
		t.Fatalf("expected signature error, got: %v", err)
	}
}

func TestLoadManifestRejectsUnknownField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(path, []byte(`{"name":"demo","version":"1.0.0","entry":"plugin.js","artifact":"plugin.js","capabilities":["CAP_HTTP_PASSIVE"],"signature":{"signature":"plugin.js.sig","publicKey":"glyph-plugin.pub"},"unexpected":true}`), 0o644); err != nil {
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
