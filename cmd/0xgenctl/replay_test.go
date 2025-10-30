package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/RowanDark/0xgen/internal/cases"
	"github.com/RowanDark/0xgen/internal/findings"
	"github.com/RowanDark/0xgen/internal/replay"
)

func TestRunReplay(t *testing.T) {
	dir := t.TempDir()
	findingsPath := filepath.Join(dir, "findings.jsonl")
	casesPath := filepath.Join(dir, "cases.json")

	finding := findings.Finding{
		Version:    findings.SchemaVersion,
		ID:         "01HV7RCFF0J1AY7P5Z9Q4C1100",
		Plugin:     "seer",
		Type:       "demo",
		Message:    "Demo finding",
		Target:     "https://example.com",
		Severity:   findings.SeverityHigh,
		DetectedAt: findings.NewTimestamp(time.Unix(1700002000, 0).UTC()),
	}
	findingBytes, err := json.Marshal(finding)
	if err != nil {
		t.Fatalf("marshal finding: %v", err)
	}
	if err := os.WriteFile(findingsPath, append(findingBytes, '\n'), 0o644); err != nil {
		t.Fatalf("write findings: %v", err)
	}

	builder := cases.NewBuilder(
		cases.WithDeterministicMode(42),
		cases.WithClock(func() time.Time { return time.Unix(1700002000, 0).UTC() }),
	)
	built, err := builder.Build(t.Context(), []findings.Finding{finding})
	if err != nil {
		t.Fatalf("build cases: %v", err)
	}
	if err := replay.WriteCases(casesPath, built, replay.WithCaseOrder([]string{built[0].ID})); err != nil {
		t.Fatalf("write cases: %v", err)
	}

	caseDigest, err := replay.ComputeCaseDigest(built, []string{built[0].ID}, "sha256")
	if err != nil {
		t.Fatalf("hash cases: %v", err)
	}
	findingDigest, err := replay.ComputeFindingsDigest([]findings.Finding{finding}, []string{finding.ID}, "sha256")
	if err != nil {
		t.Fatalf("hash findings: %v", err)
	}

	manifest := replay.Manifest{
		Version:       replay.ManifestVersion,
		CreatedAt:     time.Unix(1700002000, 0).UTC(),
		Seeds:         map[string]int64{"cases": 42},
		Runner:        replay.DefaultRunnerInfo(),
		FindingsFile:  "findings.jsonl",
		FindingOrder:  []string{finding.ID},
		CasesFile:     "cases.json",
		CaseOrder:     []string{built[0].ID},
		FlowsFile:     "flows.jsonl",
		CaseTimestamp: time.Unix(1700002000, 0).UTC(),
		Responses: []replay.ResponseRecord{{
			RequestURL: "https://example.com",
			Method:     "GET",
			Status:     200,
			BodyFile:   "responses/example.json",
		}},
		Provenance: []replay.Provenance{
			{Scope: "cases", Algorithm: "sha256", Digest: caseDigest},
			{Scope: "findings", Algorithm: "sha256", Digest: findingDigest},
		},
	}

	files := map[string][]byte{
		"findings.jsonl":         mustReadFile(t, findingsPath),
		"cases.json":             mustReadFile(t, casesPath),
		"flows.jsonl":            []byte("{\"id\":\"1\",\"sequence\":1,\"type\":\"FLOW_REQUEST\",\"timestamp_unix\":1700002000,\"sanitized_base64\":\"Zmxvdy0x\"}\n"),
		"responses/example.json": []byte(`{"status":"ok"}`),
	}

	artefact := filepath.Join(dir, "0xgen.replay.tgz")
	if err := replay.CreateArtifact(artefact, manifest, files); err != nil {
		t.Fatalf("CreateArtifact failed: %v", err)
	}

	outDir := filepath.Join(dir, "out")
	if code := runReplay([]string{"--out", outDir, artefact}); code != 0 {
		t.Fatalf("runReplay exited with %d", code)
	}

	generated, err := replay.LoadCases(filepath.Join(outDir, "cases.replay.json"))
	if err != nil {
		t.Fatalf("load replay cases: %v", err)
	}
	if !replay.CasesEqualWithOrder(built, generated, manifest.CaseOrder) {
		t.Fatalf("replayed cases do not match original")
	}

	findingsData, err := os.ReadFile(filepath.Join(outDir, "findings.replay.jsonl"))
	if err != nil {
		t.Fatalf("findings output missing: %v", err)
	}
	if len(findingsData) == 0 {
		t.Fatalf("expected findings output to contain data")
	}

	// Verify supplemental data copied.
	if _, err := os.Stat(filepath.Join(outDir, "responses", "example.json")); err != nil {
		t.Fatalf("supplemental response not exported: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "flows.replay.jsonl")); err != nil {
		t.Fatalf("flows output missing: %v", err)
	}

	provPath := filepath.Join(outDir, "provenance.replay.json")
	provData, err := os.ReadFile(provPath)
	if err != nil {
		t.Fatalf("provenance output missing: %v", err)
	}
	var report struct {
		Records []struct {
			Scope    string `json:"scope"`
			Verified bool   `json:"verified"`
		} `json:"records"`
	}
	if err := json.Unmarshal(provData, &report); err != nil {
		t.Fatalf("decode provenance: %v", err)
	}
	if len(report.Records) != 2 {
		t.Fatalf("unexpected provenance records: %v", report.Records)
	}
	for _, rec := range report.Records {
		if !rec.Verified {
			t.Fatalf("expected provenance for %s to be verified", rec.Scope)
		}
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file %s: %v", path, err)
	}
	return data
}
