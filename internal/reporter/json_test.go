package reporter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/RowanDark/0xgen/internal/findings"
)

func TestRenderJSONIncludesSBOM(t *testing.T) {
	dir := t.TempDir()
	sbomPath := filepath.Join(dir, "sbom.json")
	sbomContents := []byte(`{"name":"0xgen"}`)
	if err := os.WriteFile(sbomPath, sbomContents, 0o644); err != nil {
		t.Fatalf("write sbom: %v", err)
	}

	base := time.Date(2024, 3, 10, 8, 0, 0, 0, time.UTC)
	sample := []findings.Finding{
		{
			Version:    findings.SchemaVersion,
			ID:         "01HXZ1K2A84YQ1P75JJE4T2ND2",
			Plugin:     "alpha",
			Type:       "http",
			Message:    "demo",
			Severity:   findings.SeverityHigh,
			DetectedAt: findings.NewTimestamp(base),
		},
	}

	data, err := RenderJSON(sample, ReportOptions{Now: base, SBOMPath: sbomPath})
	if err != nil {
		t.Fatalf("render json: %v", err)
	}

	var payload struct {
		SchemaVersion string `json:"schema_version"`
		FindingsCount int    `json:"findings_count"`
		SBOM          struct {
			Path   string `json:"path"`
			Digest struct {
				Algorithm string `json:"algorithm"`
				Value     string `json:"value"`
			} `json:"digest"`
		} `json:"sbom"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("parse json: %v", err)
	}

	if payload.SchemaVersion != BundleSchemaVersion {
		t.Fatalf("unexpected schema version %q", payload.SchemaVersion)
	}
	if payload.FindingsCount != 1 {
		t.Fatalf("unexpected findings count %d", payload.FindingsCount)
	}
	if payload.SBOM.Path == "" {
		t.Fatalf("expected sbom path")
	}
	expectedDigest, err := ComputeFileDigestHex(sbomPath)
	if err != nil {
		t.Fatalf("compute digest: %v", err)
	}
	if got := payload.SBOM.Digest.Algorithm + ":" + payload.SBOM.Digest.Value; got != expectedDigest {
		t.Fatalf("unexpected sbom digest %s want %s", got, expectedDigest)
	}
}
