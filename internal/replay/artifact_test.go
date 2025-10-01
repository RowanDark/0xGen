package replay

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCreateAndExtractArtifact(t *testing.T) {
	dir := t.TempDir()
	artefactPath := filepath.Join(dir, "glyph.replay.tgz")

	manifest := Manifest{
		Version:       ManifestVersion,
		CreatedAt:     time.Unix(1700000000, 0).UTC(),
		Seeds:         map[string]int64{"cases": 2024},
		Runner:        DefaultRunnerInfo(),
		Plugins:       []PluginInfo{{Name: "seer", Version: "1.0.0", ManifestPath: "plugins/seer/manifest.json", Signature: "sig", SHA256: "deadbeef"}},
		FindingsFile:  "findings.jsonl",
		CasesFile:     "cases.json",
		CaseTimestamp: time.Unix(1700000000, 0).UTC(),
		Responses: []ResponseRecord{{
			RequestURL: "https://example.com",
			Method:     "GET",
			Status:     200,
			Headers:    map[string][]string{"Content-Type": {"text/html"}},
			BodyFile:   "responses/example.html",
		}},
	}

	files := map[string][]byte{
		"findings.jsonl":         []byte("{}\n"),
		"cases.json":             []byte("[]"),
		"responses/example.html": []byte("<html></html>"),
	}

	if err := CreateArtifact(artefactPath, manifest, files); err != nil {
		t.Fatalf("CreateArtifact failed: %v", err)
	}

	extractedDir := filepath.Join(dir, "extracted")
	gotManifest, err := ExtractArtifact(artefactPath, extractedDir)
	if err != nil {
		t.Fatalf("ExtractArtifact failed: %v", err)
	}

	if gotManifest.Version != ManifestVersion {
		t.Fatalf("unexpected manifest version: %s", gotManifest.Version)
	}
	if gotManifest.FindingsFile != "files/findings.jsonl" {
		t.Fatalf("unexpected findings file: %s", gotManifest.FindingsFile)
	}

	// Ensure files were extracted to the expected locations.
	data, err := os.ReadFile(filepath.Join(extractedDir, "files", "responses", "example.html"))
	if err != nil {
		t.Fatalf("read extracted response: %v", err)
	}
	if string(data) != "<html></html>" {
		t.Fatalf("unexpected response body: %q", string(data))
	}

	// Validate manifest round trip to JSON.
	enc, err := json.Marshal(gotManifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	var decoded Manifest
	if err := json.Unmarshal(enc, &decoded); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
}
