package local

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	pluginspec "github.com/RowanDark/0xgen/internal/plugins"
	"github.com/RowanDark/0xgen/internal/plugins/integrity"
)

// Plugin represents a plugin discovered on disk.
type Plugin struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Version        string    `json:"version"`
	Capabilities   []string  `json:"capabilities"`
	Path           string    `json:"path"`
	ManifestPath   string    `json:"manifest_path"`
	ArtifactPath   string    `json:"artifact_path"`
	ArtifactSHA256 string    `json:"artifact_sha256,omitempty"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// Discover scans the provided directory for installed plugins.
func Discover(dir string) ([]Plugin, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read plugin directory: %w", err)
	}

	var discovered []Plugin
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pluginDir := filepath.Join(dir, entry.Name())
		manifestPath := filepath.Join(pluginDir, "manifest.json")
		manifest, err := pluginspec.LoadManifest(manifestPath)
		if err != nil {
			continue
		}

		artifactPath := manifest.Artifact
		if !filepath.IsAbs(artifactPath) {
			artifactPath = filepath.Join(pluginDir, artifactPath)
		}
		artifactPath = filepath.Clean(artifactPath)

		var artifactHash string
		if hash, err := integrity.HashFile(artifactPath); err == nil {
			artifactHash = hash
		}

		info, err := os.Stat(manifestPath)
		if err != nil {
			info = nil
		}

		discovered = append(discovered, Plugin{
			ID:             manifest.Name,
			Name:           manifest.Name,
			Version:        manifest.Version,
			Capabilities:   append([]string(nil), manifest.Capabilities...),
			Path:           pluginDir,
			ManifestPath:   manifestPath,
			ArtifactPath:   artifactPath,
			ArtifactSHA256: artifactHash,
			UpdatedAt: func() time.Time {
				if info != nil {
					return info.ModTime()
				}
				return time.Time{}
			}(),
		})
	}

	sort.SliceStable(discovered, func(i, j int) bool {
		if discovered[i].Name == discovered[j].Name {
			return discovered[i].Version < discovered[j].Version
		}
		return discovered[i].Name < discovered[j].Name
	})

	return discovered, nil
}
