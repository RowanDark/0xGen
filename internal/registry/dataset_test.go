package registry

import (
	"path/filepath"
	"testing"
)

func TestLoadDataset(t *testing.T) {
	path := filepath.Join("testdata", "registry.json")
	dataset, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(dataset.Plugins) != 2 {
		t.Fatalf("expected 2 plugins, got %d", len(dataset.Plugins))
	}
	if dataset.GlyphVersions[0] != "1.0" || dataset.GlyphVersions[1] != "2.0" {
		t.Fatalf("unexpected glyph versions: %v", dataset.GlyphVersions)
	}

	alpha, ok := dataset.Plugin("alpha")
	if !ok {
		t.Fatalf("expected to find plugin alpha")
	}
	if alpha.Compatibility["2.0"].Status != "compatible" {
		t.Fatalf("unexpected status for alpha@2.0: %s", alpha.Compatibility["2.0"].Status)
	}

	filtered := dataset.FilterPlugins(Filter{Glyph: "2.0", Status: "compatible"})
	if len(filtered) != 1 || filtered[0].ID != "alpha" {
		t.Fatalf("expected only alpha to match, got %#v", filtered)
	}

	byQuery := dataset.FilterPlugins(Filter{Query: "crawler"})
	if len(byQuery) != 1 || byQuery[0].ID != "bravo" {
		t.Fatalf("expected bravo to match query, got %#v", byQuery)
	}

	if _, ok := dataset.Plugin("BRAVO"); !ok {
		t.Fatalf("case-insensitive lookup failed")
	}
}
