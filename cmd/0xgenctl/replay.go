package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/RowanDark/0xgen/internal/cases"
	"github.com/RowanDark/0xgen/internal/env"
	"github.com/RowanDark/0xgen/internal/findings"
	"github.com/RowanDark/0xgen/internal/replay"
	"github.com/RowanDark/0xgen/internal/reporter"
)

func runReplay(args []string) int {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	outDir := fs.String("out", "", "directory to write replay outputs (defaults to ${0XGEN_OUT:-.}/replay)")
	caseFilter := fs.String("case", "", "identifier of the case to replay")
	verifyOnly := fs.Bool("verify-only", false, "only verify recorded cases without writing outputs")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: 0xgenctl replay [--out dir] [--case id] <artifact>")
		return 2
	}

	artefactPath := strings.TrimSpace(fs.Arg(0))
	if artefactPath == "" {
		fmt.Fprintln(os.Stderr, "artifact path is required")
		return 2
	}
	if _, err := os.Stat(artefactPath); err != nil {
		fmt.Fprintf(os.Stderr, "open artifact: %v\n", err)
		return 1
	}

	dest := strings.TrimSpace(*outDir)
	if dest == "" {
		if val, ok := env.Lookup("0XGEN_OUT"); ok {
			if trimmed := strings.TrimSpace(val); trimmed != "" {
				dest = filepath.Join(trimmed, "replay")
			}
		}
		if dest == "" {
			cwd, err := os.Getwd()
			if err != nil {
				fmt.Fprintf(os.Stderr, "determine working directory: %v\n", err)
				return 1
			}
			dest = filepath.Join(cwd, "replay")
		}
	}

	tmpDir, err := os.MkdirTemp("", "0xgen-replay-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create temp dir: %v\n", err)
		return 1
	}
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	manifest, err := replay.ExtractArtifact(artefactPath, tmpDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "extract artifact: %v\n", err)
		return 1
	}

	findingsPath := filepath.Join(tmpDir, filepath.FromSlash(manifest.FindingsFile))
	findingsList, err := reporter.ReadJSONL(findingsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load findings: %v\n", err)
		return 1
	}
	orderedFindings := replay.OrderFindings(findingsList, manifest.FindingOrder)

	builder := configureCaseBuilder(manifest)
	builtCases, err := builder.Build(context.Background(), findingsList)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build cases: %v\n", err)
		return 1
	}

	expectedCasesPath := filepath.Join(tmpDir, filepath.FromSlash(manifest.CasesFile))
	expectedCases, err := replay.LoadCases(expectedCasesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load recorded cases: %v\n", err)
		return 1
	}

	orderedBuilt := replay.OrderCases(builtCases, manifest.CaseOrder)
	orderedExpected := replay.OrderCases(expectedCases, manifest.CaseOrder)

	filterID := strings.TrimSpace(*caseFilter)
	var filteredFindings []findings.Finding
	if filterID != "" {
		var ok bool
		orderedBuilt, ok = selectCaseByID(orderedBuilt, filterID)
		if !ok {
			fmt.Fprintf(os.Stderr, "case %s not present in replay output\n", filterID)
			return 1
		}
		orderedExpected, ok = selectCaseByID(orderedExpected, filterID)
		if !ok {
			fmt.Fprintf(os.Stderr, "case %s not present in recorded cases\n", filterID)
			return 1
		}
		filteredFindings = filterFindingsForCase(orderedFindings, orderedBuilt[0])
	} else {
		filteredFindings = orderedFindings
	}

	if !replay.CasesEqualWithOrder(orderedBuilt, orderedExpected, manifest.CaseOrder) {
		fmt.Fprintln(os.Stderr, "replayed cases diverged from recorded output")
		return 1
	}

	caseProv, haveCaseProv := manifest.ProvenanceByScope("cases")
	caseAlgorithm := normaliseAlgorithm(caseProv.Algorithm)
	caseDigest, err := replay.ComputeCaseDigest(orderedBuilt, manifest.CaseOrder, caseAlgorithm)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hash cases: %v\n", err)
		return 1
	}
	expectedCaseDigest := strings.TrimSpace(caseProv.Digest)
	caseVerified := false
	if haveCaseProv {
		if filterID == "" {
			if expectedCaseDigest == "" || !strings.EqualFold(caseDigest, expectedCaseDigest) {
				fmt.Fprintln(os.Stderr, "case provenance digest mismatch")
				return 1
			}
			caseVerified = true
		}
	}

	findingProv, haveFindingProv := manifest.ProvenanceByScope("findings")
	findingAlgorithm := normaliseAlgorithm(findingProv.Algorithm)
	findingDigest, err := replay.ComputeFindingsDigest(filteredFindings, manifest.FindingOrder, findingAlgorithm)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hash findings: %v\n", err)
		return 1
	}
	expectedFindingDigest := strings.TrimSpace(findingProv.Digest)
	findingVerified := false
	if haveFindingProv {
		if filterID == "" {
			if expectedFindingDigest == "" || !strings.EqualFold(findingDigest, expectedFindingDigest) {
				fmt.Fprintln(os.Stderr, "finding provenance digest mismatch")
				return 1
			}
			findingVerified = true
		}
	}

	var flowRecords []replay.FlowRecord
	if strings.TrimSpace(manifest.FlowsFile) != "" {
		flowsPath := filepath.Join(tmpDir, filepath.FromSlash(manifest.FlowsFile))
		flowRecords, err = replay.LoadFlows(flowsPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "load flows: %v\n", err)
			return 1
		}
	}

	if *verifyOnly {
		fmt.Fprintf(os.Stdout, "verified %d cases from %s\n", len(orderedBuilt), artefactPath)
		return 0
	}

	if err := os.MkdirAll(dest, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "create output directory: %v\n", err)
		return 1
	}

	outputCasesPath := filepath.Join(dest, "cases.replay.json")
	if err := replay.WriteCases(outputCasesPath, orderedBuilt, replay.WithCaseOrder(manifest.CaseOrder)); err != nil {
		fmt.Fprintf(os.Stderr, "write replay cases: %v\n", err)
		return 1
	}

	findingsOutput := filepath.Join(dest, "findings.replay.jsonl")
	if err := replay.WriteFindings(findingsOutput, filteredFindings); err != nil {
		fmt.Fprintf(os.Stderr, "write findings: %v\n", err)
		return 1
	}

	if len(flowRecords) > 0 {
		flowsOutput := filepath.Join(dest, "flows.replay.jsonl")
		if err := replay.WriteFlows(flowsOutput, flowRecords); err != nil {
			fmt.Fprintf(os.Stderr, "write flows: %v\n", err)
			return 1
		}
	}

	if err := exportSupplemental(manifest, tmpDir, dest); err != nil {
		fmt.Fprintf(os.Stderr, "export supplemental data: %v\n", err)
		return 1
	}

	records := []provenanceRecord{
		{
			Scope:          "cases",
			Algorithm:      caseAlgorithm,
			Digest:         caseDigest,
			ExpectedDigest: expectedCaseDigest,
			Verified:       caseVerified,
		},
		{
			Scope:          "findings",
			Algorithm:      findingAlgorithm,
			Digest:         findingDigest,
			ExpectedDigest: expectedFindingDigest,
			Verified:       findingVerified,
		},
	}
	if err := writeProvenanceReport(filepath.Join(dest, "provenance.replay.json"), artefactPath, records); err != nil {
		fmt.Fprintf(os.Stderr, "write provenance: %v\n", err)
		return 1
	}

	fmt.Fprintf(os.Stdout, "replayed %d cases to %s\n", len(orderedBuilt), outputCasesPath)
	return 0
}

func configureCaseBuilder(manifest replay.Manifest) *cases.Builder {
	var opts []cases.Option
	if manifest.CaseTimestamp.IsZero() {
		manifest.CaseTimestamp = time.Now().UTC()
	}
	opts = append(opts, cases.WithClock(func() time.Time { return manifest.CaseTimestamp }))
	if seed, ok := manifest.Seeds["cases"]; ok {
		opts = append(opts, cases.WithDeterministicMode(seed))
	}
	return cases.NewBuilder(opts...)
}

func exportSupplemental(manifest replay.Manifest, root, dest string) error {
	if len(manifest.Responses) == 0 && len(manifest.Robots) == 0 {
		return nil
	}
	copyFile := func(relPath, targetDir string) error {
		if strings.TrimSpace(relPath) == "" {
			return nil
		}
		src := filepath.Join(root, filepath.FromSlash(relPath))
		if _, err := os.Stat(src); err != nil {
			return fmt.Errorf("missing supplemental file %s: %w", relPath, err)
		}
		if err := os.MkdirAll(targetDir, 0o755); err != nil {
			return fmt.Errorf("create supplemental directory: %w", err)
		}
		dst := filepath.Join(targetDir, filepath.Base(relPath))
		data, err := os.ReadFile(src)
		if err != nil {
			return fmt.Errorf("read supplemental file %s: %w", relPath, err)
		}
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			return fmt.Errorf("write supplemental file %s: %w", relPath, err)
		}
		return nil
	}

	responsesDir := filepath.Join(dest, "responses")
	for _, resp := range manifest.Responses {
		if err := copyFile(resp.BodyFile, responsesDir); err != nil {
			return err
		}
	}
	robotsDir := filepath.Join(dest, "robots")
	for _, rob := range manifest.Robots {
		if err := copyFile(rob.BodyFile, robotsDir); err != nil {
			return err
		}
	}
	return nil
}

func selectCaseByID(list []cases.Case, id string) ([]cases.Case, bool) {
	trimmed := strings.TrimSpace(id)
	if trimmed == "" {
		return nil, false
	}
	for _, c := range list {
		if c.ID == trimmed {
			return []cases.Case{c}, true
		}
	}
	return nil, false
}

func filterFindingsForCase(list []findings.Finding, c cases.Case) []findings.Finding {
	if len(c.Sources) == 0 {
		return nil
	}
	allowed := make(map[string]struct{}, len(c.Sources))
	for _, src := range c.Sources {
		if trimmed := strings.TrimSpace(src.ID); trimmed != "" {
			allowed[trimmed] = struct{}{}
		}
	}
	if len(allowed) == 0 {
		return nil
	}
	filtered := make([]findings.Finding, 0, len(allowed))
	for _, f := range list {
		if _, ok := allowed[f.ID]; ok {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

func normaliseAlgorithm(alg string) string {
	trimmed := strings.TrimSpace(strings.ToLower(alg))
	if trimmed == "" {
		return "sha256"
	}
	return trimmed
}

type provenanceRecord struct {
	Scope          string `json:"scope"`
	Algorithm      string `json:"algorithm"`
	Digest         string `json:"digest"`
	ExpectedDigest string `json:"expected_digest,omitempty"`
	Verified       bool   `json:"verified"`
}

type provenanceReport struct {
	Artifact    string             `json:"artifact"`
	GeneratedAt time.Time          `json:"generated_at"`
	Records     []provenanceRecord `json:"records"`
}

func writeProvenanceReport(path, artefact string, records []provenanceRecord) error {
	report := provenanceReport{
		Artifact:    artefact,
		GeneratedAt: time.Now().UTC(),
		Records:     records,
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("encode provenance: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write provenance file: %w", err)
	}
	return nil
}
