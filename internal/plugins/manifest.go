package plugins

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

var allowedCapabilities = []string{
	"CAP_EMIT_FINDINGS",
	"CAP_HTTP_ACTIVE",
	"CAP_HTTP_PASSIVE",
	"CAP_WS",
	"CAP_SPIDER",
	"CAP_REPORT",
	"CAP_STORAGE",
}

// Manifest represents the expected contents of a plugin manifest.
type Manifest struct {
	Name         string                 `json:"name"`
	Version      string                 `json:"version"`
	Entry        string                 `json:"entry"`
	Capabilities []string               `json:"capabilities"`
	Config       map[string]interface{} `json:"config,omitempty"`
}

// LoadManifest reads a manifest from disk and validates its contents.
func LoadManifest(path string) (*Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}

	var manifest Manifest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("decode manifest: %w", err)
	}

	if manifest.Name == "" {
		return nil, fmt.Errorf("manifest is missing name")
	}
	if manifest.Version == "" {
		return nil, fmt.Errorf("manifest is missing version")
	}
	if manifest.Entry == "" {
		return nil, fmt.Errorf("manifest is missing entry")
	}
	if len(manifest.Capabilities) == 0 {
		return nil, fmt.Errorf("manifest must declare at least one capability")
	}

	allowed := make(map[string]struct{}, len(allowedCapabilities))
	for _, c := range allowedCapabilities {
		allowed[c] = struct{}{}
	}
	seen := make(map[string]struct{}, len(manifest.Capabilities))
	for _, capability := range manifest.Capabilities {
		if capability == "" {
			return nil, fmt.Errorf("manifest cannot contain empty capability values")
		}
		if _, ok := allowed[capability]; !ok {
			return nil, fmt.Errorf("manifest contains unknown capability %q", capability)
		}
		if _, ok := seen[capability]; ok {
			return nil, fmt.Errorf("manifest contains duplicate capability %q", capability)
		}
		seen[capability] = struct{}{}
	}

	return &manifest, nil
}

// ValidateManifest ensures the manifest at the provided path is well-formed.
func ValidateManifest(path string) error {
	_, err := LoadManifest(path)
	return err
}
