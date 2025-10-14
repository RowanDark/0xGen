package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RowanDark/0xgen/internal/cases"
	"github.com/RowanDark/0xgen/internal/exporter"
	"github.com/RowanDark/0xgen/internal/findings"
)

func TestLoadUIDataset(t *testing.T) {
	path := filepath.Join("testdata", "findings.jsonl")
	dataset, err := loadUIDataset(path)
	if err != nil {
		t.Fatalf("loadUIDataset: %v", err)
	}
	if dataset.FindingsCount == 0 {
		t.Fatalf("expected findings to be loaded")
	}
	if len(dataset.Cases) == 0 {
		t.Fatalf("expected cases to be built")
	}
	if dataset.RefreshedAt == "" {
		t.Fatalf("expected refreshed timestamp to be populated")
	}
}

func TestNewUIServerState(t *testing.T) {
	dataset := uiDataset{
		Cases: []cases.Case{{
			ID:          "case-1",
			Version:     cases.CaseSchemaVersion,
			Asset:       cases.Asset{Kind: "service", Identifier: "api"},
			Vector:      cases.AttackVector{Kind: "http"},
			Summary:     "Example case",
			Risk:        cases.Risk{Severity: findings.SeverityHigh, Score: 7.5},
			GeneratedAt: findings.NewTimestamp(time.Date(2024, time.January, 1, 12, 0, 0, 0, time.UTC)),
		}},
		Telemetry:     exporter.Telemetry{CaseCount: 1, FindingCount: 1},
		FindingsCount: 1,
		RefreshedAt:   time.Now().UTC().Format(time.RFC3339),
	}

	state, err := newUIServerState(dataset)
	if err != nil {
		t.Fatalf("newUIServerState: %v", err)
	}
	if got, want := len(state.caseIndex), len(dataset.Cases); got != want {
		t.Fatalf("unexpected index length: got %d want %d", got, want)
	}
	if len(state.casesJSON) == 0 {
		t.Fatalf("expected cases JSON to be populated")
	}
	if len(state.sarif) == 0 {
		t.Fatalf("expected sarif payload to be populated")
	}
}

func TestFormatPOC(t *testing.T) {
	c := cases.Case{Proof: cases.ProofOfConcept{Summary: "Steps", Steps: []string{" step one ", "", "step two"}}}
	payload := formatPOC(c)
	if !strings.Contains(payload, "Steps") {
		t.Fatalf("expected summary to be included: %q", payload)
	}
	if strings.Count(payload, "step") < 2 {
		t.Fatalf("expected steps to be numbered: %q", payload)
	}
}

func TestSanitizeFilename(t *testing.T) {
	if got, want := sanitizeFilename("../case::01"), "case-01"; got != want {
		t.Fatalf("sanitizeFilename: got %q want %q", got, want)
	}
	if got := sanitizeFilename("   "); got != "case" {
		t.Fatalf("sanitizeFilename empty: got %q", got)
	}
}
