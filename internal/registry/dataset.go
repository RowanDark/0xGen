package registry

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"
)

var allowedStatuses = map[string]struct{}{
	"compatible":  {},
	"limited":     {},
	"unsupported": {},
}

// Dataset represents the plugin registry payload persisted to disk or served
// via the registry API.
type Dataset struct {
	GeneratedAt   time.Time
	GlyphVersions []string
	Plugins       []Plugin
}

type datasetJSON struct {
	GeneratedAt time.Time `json:"generated_at"`
	Plugins     []Plugin  `json:"plugins"`
	OxgVersions []string  `json:"oxg_versions,omitempty"`
	GlyphLegacy []string  `json:"glyph_versions,omitempty"`
}

// UnmarshalJSON decodes a dataset, accepting both legacy glyph_* and new oxg_*
// field names to keep existing publishers working during the transition.
func (d *Dataset) UnmarshalJSON(data []byte) error {
	var payload datasetJSON
	if err := json.Unmarshal(data, &payload); err != nil {
		return err
	}
	d.GeneratedAt = payload.GeneratedAt
	d.Plugins = payload.Plugins
	switch {
	case payload.OxgVersions != nil:
		d.GlyphVersions = payload.OxgVersions
	case payload.GlyphLegacy != nil:
		d.GlyphVersions = payload.GlyphLegacy
	default:
		d.GlyphVersions = nil
	}
	return nil
}

// MarshalJSON encodes the dataset using the new oxg_* field names.
func (d Dataset) MarshalJSON() ([]byte, error) {
	payload := datasetJSON{
		GeneratedAt: d.GeneratedAt,
		Plugins:     d.Plugins,
	}
	if len(d.GlyphVersions) > 0 {
		payload.OxgVersions = d.GlyphVersions
	}
	return json.Marshal(payload)
}

// Plugin contains the metadata tracked for each registry entry.
type Plugin struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Author          string            `json:"author"`
	Language        string            `json:"language"`
	Summary         string            `json:"summary"`
	Capabilities    []string          `json:"capabilities"`
	Categories      []string          `json:"categories,omitempty"`
	LastUpdated     string            `json:"last_updated,omitempty"`
	SignatureSHA256 string            `json:"signature_sha256"`
	Links           map[string]string `json:"links"`
	Compatibility   map[string]Compatibility
}

type pluginJSON struct {
	ID              string                   `json:"id"`
	Name            string                   `json:"name"`
	Version         string                   `json:"version"`
	Author          string                   `json:"author"`
	Language        string                   `json:"language"`
	Summary         string                   `json:"summary"`
	Capabilities    []string                 `json:"capabilities"`
	Categories      []string                 `json:"categories,omitempty"`
	LastUpdated     string                   `json:"last_updated,omitempty"`
	SignatureSHA256 string                   `json:"signature_sha256"`
	Links           map[string]string        `json:"links"`
	Compatibility   map[string]Compatibility `json:"compatibility,omitempty"`
	OxgCompat       map[string]Compatibility `json:"oxg_compat,omitempty"`
}

// UnmarshalJSON decodes a plugin entry, tolerating both compatibility key names.
func (p *Plugin) UnmarshalJSON(data []byte) error {
	var payload pluginJSON
	if err := json.Unmarshal(data, &payload); err != nil {
		return err
	}
	p.ID = payload.ID
	p.Name = payload.Name
	p.Version = payload.Version
	p.Author = payload.Author
	p.Language = payload.Language
	p.Summary = payload.Summary
	p.Capabilities = payload.Capabilities
	p.Categories = payload.Categories
	p.LastUpdated = payload.LastUpdated
	p.SignatureSHA256 = payload.SignatureSHA256
	p.Links = payload.Links
	switch {
	case payload.OxgCompat != nil:
		p.Compatibility = payload.OxgCompat
	case payload.Compatibility != nil:
		p.Compatibility = payload.Compatibility
	default:
		p.Compatibility = nil
	}
	return nil
}

// MarshalJSON encodes the plugin entry using the new oxg_* compatibility key.
func (p Plugin) MarshalJSON() ([]byte, error) {
	payload := pluginJSON{
		ID:              p.ID,
		Name:            p.Name,
		Version:         p.Version,
		Author:          p.Author,
		Language:        p.Language,
		Summary:         p.Summary,
		Capabilities:    p.Capabilities,
		Categories:      p.Categories,
		LastUpdated:     p.LastUpdated,
		SignatureSHA256: p.SignatureSHA256,
		Links:           p.Links,
	}
	if len(p.Compatibility) > 0 {
		payload.OxgCompat = p.Compatibility
	}
	return json.Marshal(payload)
}

// Compatibility describes Glyph core support for a plugin release.
type Compatibility struct {
	Status string `json:"status"`
	Notes  string `json:"notes,omitempty"`
}

// Filter expresses the constraints used when searching the registry.
type Filter struct {
	Query      string
	Language   string
	Category   string
	Capability string
	Glyph      string
	Status     string
}

// Load reads a registry dataset from disk, validates its structure, and
// normalises the content for efficient querying.
func Load(path string) (Dataset, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Dataset{}, fmt.Errorf("read registry dataset: %w", err)
	}

	var dataset Dataset
	if err := json.Unmarshal(raw, &dataset); err != nil {
		return Dataset{}, fmt.Errorf("decode registry dataset: %w", err)
	}
	if err := dataset.Validate(); err != nil {
		return Dataset{}, err
	}
	dataset.normalise()

	return dataset, nil
}

// Validate checks that the dataset is well-formed.
func (d *Dataset) Validate() error {
	if d == nil {
		return errors.New("registry dataset is nil")
	}

	glyphSet := make(map[string]struct{}, len(d.GlyphVersions))
	trimmedGlyphs := d.GlyphVersions[:0]
	for _, version := range d.GlyphVersions {
		v := strings.TrimSpace(version)
		if v == "" {
			continue
		}
		if _, exists := glyphSet[v]; exists {
			continue
		}
		glyphSet[v] = struct{}{}
		trimmedGlyphs = append(trimmedGlyphs, v)
	}
	d.GlyphVersions = trimmedGlyphs

	for idx := range d.Plugins {
		plugin := &d.Plugins[idx]
		plugin.ID = strings.TrimSpace(plugin.ID)
		if plugin.ID == "" {
			return fmt.Errorf("registry plugin at index %d missing id", idx)
		}
		plugin.Name = strings.TrimSpace(plugin.Name)
		plugin.Author = strings.TrimSpace(plugin.Author)
		plugin.Language = strings.TrimSpace(plugin.Language)
		plugin.Summary = strings.TrimSpace(plugin.Summary)
		plugin.SignatureSHA256 = strings.TrimSpace(plugin.SignatureSHA256)

		plugin.Capabilities = unique(plugin.Capabilities)
		plugin.Categories = unique(plugin.Categories)

		if plugin.Compatibility != nil {
			for glyph, entry := range plugin.Compatibility {
				trimmedGlyph := strings.TrimSpace(glyph)
				if trimmedGlyph == "" {
					return fmt.Errorf("plugin %s has empty glyph version in compatibility", plugin.ID)
				}
				entry.Status = strings.TrimSpace(entry.Status)
				entry.Notes = strings.TrimSpace(entry.Notes)
				if entry.Status == "" {
					return fmt.Errorf("plugin %s compatibility for %s missing status", plugin.ID, trimmedGlyph)
				}
				if _, ok := allowedStatuses[entry.Status]; !ok {
					return fmt.Errorf(
						"plugin %s compatibility for %s has unknown status %q",
						plugin.ID,
						trimmedGlyph,
						entry.Status,
					)
				}
				plugin.Compatibility[trimmedGlyph] = entry
				if trimmedGlyph != glyph {
					delete(plugin.Compatibility, glyph)
				}
				if _, exists := glyphSet[trimmedGlyph]; !exists {
					glyphSet[trimmedGlyph] = struct{}{}
				}
			}
		}
	}

	if len(d.GlyphVersions) == 0 && len(glyphSet) > 0 {
		d.GlyphVersions = make([]string, 0, len(glyphSet))
		for version := range glyphSet {
			d.GlyphVersions = append(d.GlyphVersions, version)
		}
	}

	return nil
}

// FilterPlugins returns the set of plugins that match the provided constraints.
func (d Dataset) FilterPlugins(filter Filter) []Plugin {
	query := strings.ToLower(strings.TrimSpace(filter.Query))
	language := strings.TrimSpace(filter.Language)
	category := strings.TrimSpace(filter.Category)
	capability := strings.TrimSpace(filter.Capability)
	glyph := strings.TrimSpace(filter.Glyph)
	status := strings.TrimSpace(filter.Status)

	var results []Plugin
	for _, plugin := range d.Plugins {
		if language != "" && plugin.Language != language {
			continue
		}
		if category != "" && !contains(plugin.Categories, category) {
			continue
		}
		if capability != "" && !contains(plugin.Capabilities, capability) {
			continue
		}
		if glyph != "" {
			entry, ok := plugin.Compatibility[glyph]
			if !ok {
				continue
			}
			if status != "" && entry.Status != status {
				continue
			}
		} else if status != "" {
			found := false
			for _, entry := range plugin.Compatibility {
				if entry.Status == status {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		if query != "" && !matchesQuery(plugin, query) {
			continue
		}
		results = append(results, plugin)
	}
	return results
}

// Plugin returns the registry entry for the provided ID, performing a
// case-insensitive lookup.
func (d Dataset) Plugin(id string) (Plugin, bool) {
	trimmed := strings.TrimSpace(id)
	if trimmed == "" {
		return Plugin{}, false
	}
	for _, plugin := range d.Plugins {
		if plugin.ID == trimmed || strings.EqualFold(plugin.ID, trimmed) {
			return plugin, true
		}
	}
	return Plugin{}, false
}

func (d *Dataset) normalise() {
	d.GlyphVersions = unique(d.GlyphVersions)
	slices.Sort(d.GlyphVersions)

	slices.SortStableFunc(d.Plugins, func(a, b Plugin) int {
		left := strings.ToLower(strings.TrimSpace(a.Name))
		if left == "" {
			left = strings.ToLower(strings.TrimSpace(a.ID))
		}
		right := strings.ToLower(strings.TrimSpace(b.Name))
		if right == "" {
			right = strings.ToLower(strings.TrimSpace(b.ID))
		}
		return strings.Compare(left, right)
	})

	for idx := range d.Plugins {
		plugin := &d.Plugins[idx]
		plugin.Capabilities = unique(plugin.Capabilities)
		plugin.Categories = unique(plugin.Categories)
		slices.Sort(plugin.Capabilities)
		slices.Sort(plugin.Categories)
		if plugin.Compatibility != nil {
			for glyph, entry := range plugin.Compatibility {
				entry.Status = strings.TrimSpace(entry.Status)
				entry.Notes = strings.TrimSpace(entry.Notes)
				plugin.Compatibility[glyph] = entry
			}
		}
	}
}

func unique(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func matchesQuery(plugin Plugin, query string) bool {
	haystack := []string{
		plugin.Name,
		plugin.ID,
		plugin.Summary,
		plugin.Author,
		plugin.Language,
		strings.Join(plugin.Capabilities, " "),
		strings.Join(plugin.Categories, " "),
	}

	for version, entry := range plugin.Compatibility {
		haystack = append(haystack, "0xgen v"+version, entry.Status, entry.Notes)
	}

	joined := strings.ToLower(strings.Join(haystack, " "))
	return strings.Contains(joined, query)
}
