package reporter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/RowanDark/Glyph/internal/cases"
	"github.com/RowanDark/Glyph/internal/exporter"
	"github.com/RowanDark/Glyph/internal/findings"
)

// BundleSchemaVersion identifies the JSON structure emitted by Glyph when exporting reports.
const BundleSchemaVersion = "1.0"

// Digest captures a cryptographic digest and the algorithm that produced it.
type Digest struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

// SBOMReference links the report bundle to the SBOM used during analysis.
type SBOMReference struct {
	Path      string `json:"path"`
	Digest    Digest `json:"digest"`
	SizeBytes int64  `json:"size_bytes,omitempty"`
}

// Bundle aggregates the dataset required to recreate the interactive report view.
type Bundle struct {
	SchemaVersion string             `json:"schema_version"`
	GeneratedAt   time.Time          `json:"-"`
	FindingsCount int                `json:"findings_count"`
	Summary       Summary            `json:"summary"`
	Cases         []cases.Case       `json:"cases"`
	Findings      []findings.Finding `json:"findings"`
	Telemetry     exporter.Telemetry `json:"telemetry"`
	SBOM          *SBOMReference     `json:"sbom,omitempty"`
}

// MarshalJSON renders the bundle using the public schema while preserving UTC ordering.
func (b Bundle) MarshalJSON() ([]byte, error) {
	type bundleJSON struct {
		SchemaVersion string             `json:"schema_version"`
		GeneratedAt   string             `json:"generated_at"`
		FindingsCount int                `json:"findings_count"`
		Summary       Summary            `json:"summary"`
		Cases         []cases.Case       `json:"cases"`
		Findings      []findings.Finding `json:"findings"`
		Telemetry     exporter.Telemetry `json:"telemetry"`
		SBOM          *SBOMReference     `json:"sbom,omitempty"`
	}

	payload := bundleJSON{
		SchemaVersion: b.SchemaVersion,
		GeneratedAt:   b.GeneratedAt.UTC().Format(time.RFC3339),
		FindingsCount: b.FindingsCount,
		Summary:       b.Summary,
		Cases:         b.Cases,
		Findings:      b.Findings,
		Telemetry:     b.Telemetry,
		SBOM:          b.SBOM,
	}
	return json.Marshal(payload)
}

// BuildBundle constructs the structured dataset backing HTML and JSON reports.
func BuildBundle(ctx context.Context, list []findings.Finding, opts ReportOptions) (Bundle, error) {
	summary, filtered, _, _ := buildSummary(list, opts)

	if ctx == nil {
		ctx = context.Background()
	}
	clockNow := summary.GeneratedAt
	if !opts.Now.IsZero() {
		clockNow = opts.Now.UTC()
	}
	builder := cases.NewBuilder(
		cases.WithDeterministicMode(1),
		cases.WithClock(func() time.Time { return clockNow }),
	)
	casesList, err := builder.Build(ctx, filtered)
	if err != nil {
		return Bundle{}, fmt.Errorf("build cases: %w", err)
	}
	if casesList == nil {
		casesList = []cases.Case{}
	}

	telemetry := exporter.BuildTelemetry(casesList, len(filtered))

	bundle := Bundle{
		SchemaVersion: BundleSchemaVersion,
		GeneratedAt:   summary.GeneratedAt,
		FindingsCount: len(filtered),
		Summary:       summary,
		Cases:         casesList,
		Findings:      filtered,
		Telemetry:     telemetry,
	}

	sbomPath := strings.TrimSpace(opts.SBOMPath)
	if sbomPath != "" {
		ref, err := buildSBOMReference(sbomPath)
		if err != nil {
			return Bundle{}, err
		}
		bundle.SBOM = &ref
	}

	return bundle, nil
}

func buildSBOMReference(path string) (SBOMReference, error) {
	info, err := os.Stat(path)
	if err != nil {
		return SBOMReference{}, fmt.Errorf("stat sbom: %w", err)
	}
	digest, err := computeFileDigest(path)
	if err != nil {
		return SBOMReference{}, fmt.Errorf("hash sbom: %w", err)
	}
	ref := SBOMReference{
		Path:      filepath.ToSlash(path),
		Digest:    Digest{Algorithm: "sha256", Value: hex.EncodeToString(digest)},
		SizeBytes: info.Size(),
	}
	return ref, nil
}

func computeFileDigest(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}
