package windows

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type scoopManifest struct {
	Version      string `json:"version"`
	Architecture map[string]struct {
		URL  string `json:"url"`
		Hash string `json:"hash"`
	} `json:"architecture"`
}

type wingetInstaller struct {
	Architecture    string   `yaml:"Architecture"`
	InstallerType   string   `yaml:"InstallerType"`
	InstallerURL    string   `yaml:"InstallerUrl"`
	InstallerSHA256 string   `yaml:"InstallerSha256"`
	Commands        []string `yaml:"Commands"`
}

type wingetManifest struct {
	PackageIdentifier string            `yaml:"PackageIdentifier"`
	PackageVersion    string            `yaml:"PackageVersion"`
	Installers        []wingetInstaller `yaml:"Installers"`
}

func TestScoopManifestStructure(t *testing.T) {
	path := filepath.Join("..", "..", "scoop", "bucket", "glyphctl.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read scoop manifest: %v", err)
	}
	var manifest scoopManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("parse scoop manifest: %v", err)
	}
	if strings.TrimSpace(manifest.Version) == "" {
		t.Fatalf("scoop manifest version must not be empty")
	}
	if len(manifest.Architecture) == 0 {
		t.Fatalf("scoop manifest must declare architectures")
	}
	for arch, entry := range manifest.Architecture {
		if strings.TrimSpace(entry.URL) == "" {
			t.Fatalf("architecture %s is missing a download URL", arch)
		}
		if !strings.Contains(entry.URL, manifest.Version) {
			t.Fatalf("architecture %s URL %q does not embed version %s", arch, entry.URL, manifest.Version)
		}
		if !strings.HasPrefix(entry.Hash, "sha256:") {
			t.Fatalf("architecture %s hash %q must start with sha256:", arch, entry.Hash)
		}
		if len(entry.Hash) != len("sha256:")+64 {
			t.Fatalf("architecture %s hash %q must contain 64 hex characters", arch, entry.Hash)
		}
	}
}

func TestWingetManifestStructure(t *testing.T) {
	path := filepath.Join("winget", "glyphctl.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read winget manifest: %v", err)
	}
	var manifest wingetManifest
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("parse winget manifest: %v", err)
	}
	if strings.TrimSpace(manifest.PackageIdentifier) == "" {
		t.Fatalf("winget manifest requires PackageIdentifier")
	}
	if strings.TrimSpace(manifest.PackageVersion) == "" {
		t.Fatalf("winget manifest requires PackageVersion")
	}
	if len(manifest.Installers) == 0 {
		t.Fatalf("winget manifest must include installers")
	}
	for _, installer := range manifest.Installers {
		if strings.TrimSpace(installer.Architecture) == "" {
			t.Fatalf("installer missing architecture")
		}
		if strings.TrimSpace(installer.InstallerType) == "" {
			t.Fatalf("installer %s missing type", installer.Architecture)
		}
		if !strings.EqualFold(installer.InstallerType, "portable") {
			t.Fatalf("installer %s type must be portable", installer.Architecture)
		}
		if strings.TrimSpace(installer.InstallerURL) == "" {
			t.Fatalf("installer %s missing URL", installer.Architecture)
		}
		if !strings.Contains(installer.InstallerURL, manifest.PackageVersion) {
			t.Fatalf("installer %s URL %q does not embed version %s", installer.Architecture, installer.InstallerURL, manifest.PackageVersion)
		}
		if len(installer.InstallerSHA256) != 64 {
			t.Fatalf("installer %s SHA256 must be 64 hex characters", installer.Architecture)
		}
		if len(installer.Commands) == 0 {
			t.Fatalf("installer %s must declare exported commands", installer.Architecture)
		}
	}
}
