package plugins

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
)

type Manifest struct {
	Name         string         `json:"name"`
	Version      string         `json:"version"`
	Entry        string         `json:"entry"`
	Artifact     string         `json:"artifact"`
	Trusted      bool           `json:"trusted"`
	Capabilities []string       `json:"capabilities"`
	Config       map[string]any `json:"config,omitempty"`
	Signature    *Signature     `json:"signature"`
}

var allowedCaps = map[string]struct{}{
	"CAP_EMIT_FINDINGS":    {},
	"CAP_AI_ANALYSIS":      {},
	"CAP_HTTP_ACTIVE":      {},
	"CAP_HTTP_PASSIVE":     {},
	"CAP_FLOW_INSPECT":     {},
	"CAP_FLOW_INSPECT_RAW": {},
	"CAP_WS":               {},
	"CAP_SPIDER":           {},
	"CAP_REPORT":           {},
	"CAP_STORAGE":          {},
}

func (m *Manifest) Validate() error {
	if m.Name == "" || m.Version == "" || m.Entry == "" || m.Artifact == "" {
		return errors.New("name, version, entry, and artifact are required")
	}
	if len(m.Capabilities) == 0 {
		return errors.New("at least one capability is required")
	}

	seen := make(map[string]struct{}, len(m.Capabilities))
	for _, c := range m.Capabilities {
		if c == "" {
			return errors.New("capability cannot be empty")
		}
		if _, ok := allowedCaps[c]; !ok {
			return fmt.Errorf("unknown capability: %s", c)
		}
		if _, dup := seen[c]; dup {
			return fmt.Errorf("duplicate capability: %s", c)
		}
		seen[c] = struct{}{}
	}

	if m.Signature == nil {
		return errors.New("signature metadata is required")
	}
	if err := m.Signature.Validate(); err != nil {
		return fmt.Errorf("signature: %w", err)
	}

	return nil
}

// Signature captures the metadata required to verify an artifact's detached
// signature.
type Signature struct {
	Signature   string `json:"signature"`
	Certificate string `json:"certificate,omitempty"`
	PublicKey   string `json:"publicKey,omitempty"`
}

// Validate ensures the signature metadata is well formed.
func (s *Signature) Validate() error {
	if s == nil {
		return errors.New("signature metadata missing")
	}
	if strings.TrimSpace(s.Signature) == "" {
		return errors.New("signature path is required")
	}
	hasCert := strings.TrimSpace(s.Certificate) != ""
	hasKey := strings.TrimSpace(s.PublicKey) != ""
	if !hasCert && !hasKey {
		return errors.New("either certificate or publicKey must be provided")
	}
	return nil
}

func AllowedCapabilities() []string {
	out := make([]string, 0, len(allowedCaps))
	for k := range allowedCaps {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func LoadManifest(path string) (*Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()

	var manifest Manifest
	if err := dec.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("decode manifest: %w", err)
	}
	if err := manifest.Validate(); err != nil {
		return nil, fmt.Errorf("validate manifest: %w", err)
	}

	return &manifest, nil
}

func ValidateManifest(path string) error {
	_, err := LoadManifest(path)
	return err
}
