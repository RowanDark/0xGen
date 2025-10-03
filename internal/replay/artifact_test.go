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
		DNS: []DNSRecord{
			{Host: "Example.com", Addresses: []string{"2.2.2.2", "1.1.1.1", "1.1.1.1"}},
			{Host: "api.example.com", Addresses: []string{"3.3.3.3"}},
		},
		TLS: []TLSRecord{
			{Host: "api.example.com", JA3: "api-ja3", JA3Hash: "api-hash", NegotiatedALPN: "h2", OfferedALPN: []string{"http/1.1", "h2"}},
			{Host: "example.com", JA3: "root-ja3", JA3Hash: "root-hash", NegotiatedALPN: "http/1.1", OfferedALPN: []string{"http/1.1", "spdy/3"}},
		},
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

	if len(gotManifest.DNS) != 2 {
		t.Fatalf("expected 2 DNS records, got %d", len(gotManifest.DNS))
	}
	if gotManifest.DNS[0].Host != "api.example.com" {
		t.Fatalf("dns records not normalised: %#v", gotManifest.DNS)
	}
	if len(gotManifest.DNS[0].Addresses) != 1 || gotManifest.DNS[0].Addresses[0] != "3.3.3.3" {
		t.Fatalf("dns addresses not normalised: %#v", gotManifest.DNS[0])
	}
	if gotManifest.DNS[1].Host != "example.com" {
		t.Fatalf("dns host normalisation failed: %#v", gotManifest.DNS[1])
	}
	expectedAddrs := []string{"1.1.1.1", "2.2.2.2"}
	if !equalStrings(gotManifest.DNS[1].Addresses, expectedAddrs) {
		t.Fatalf("dns address ordering unexpected: %v", gotManifest.DNS[1].Addresses)
	}

	if len(gotManifest.TLS) != 2 {
		t.Fatalf("expected 2 TLS records, got %d", len(gotManifest.TLS))
	}
	if gotManifest.TLS[0].Host != "api.example.com" || gotManifest.TLS[0].NegotiatedALPN != "h2" {
		t.Fatalf("tls normalisation failed: %#v", gotManifest.TLS[0])
	}
	if !equalStrings(gotManifest.TLS[0].OfferedALPN, []string{"h2", "http/1.1"}) {
		t.Fatalf("tls offered ALPN normalisation failed: %v", gotManifest.TLS[0].OfferedALPN)
	}
	if gotManifest.TLS[1].Host != "example.com" || gotManifest.TLS[1].NegotiatedALPN != "http/1.1" {
		t.Fatalf("tls ordering unexpected: %#v", gotManifest.TLS[1])
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

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
