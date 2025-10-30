package replay

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/RowanDark/0xgen/internal/cases"
	"github.com/RowanDark/0xgen/internal/findings"
)

func TestCasesEqual(t *testing.T) {
	ts := time.Unix(1700001000, 0).UTC()
	base := cases.Case{
		Version:     findings.SchemaVersion,
		ID:          "CASE1",
		Asset:       cases.Asset{Kind: "web", Identifier: "example.com"},
		Vector:      cases.AttackVector{Kind: "http"},
		GeneratedAt: findings.NewTimestamp(ts),
		Risk:        cases.Risk{Severity: findings.SeverityMedium},
	}
	left := []cases.Case{base}
	right := []cases.Case{base.Clone()}
	if !CasesEqual(left, right) {
		t.Fatalf("expected cases to be equal")
	}

	right[0].Summary = "changed"
	if CasesEqual(left, right) {
		t.Fatalf("expected cases to differ")
	}
}

func TestWriteAndLoadCases(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cases.json")

	c := cases.Case{
		Version: findings.SchemaVersion,
		ID:      "CASE-1",
		Asset:   cases.Asset{Kind: "service", Identifier: "api"},
		Vector:  cases.AttackVector{Kind: "api"},
		Risk:    cases.Risk{Severity: findings.SeverityLow},
	}

	if err := WriteCases(path, []cases.Case{c}); err != nil {
		t.Fatalf("WriteCases failed: %v", err)
	}

	loaded, err := LoadCases(path)
	if err != nil {
		t.Fatalf("LoadCases failed: %v", err)
	}
	if len(loaded) != 1 || loaded[0].ID != c.ID {
		t.Fatalf("unexpected loaded cases: %+v", loaded)
	}
}

func TestOrderCasesWithManifestOrder(t *testing.T) {
	base := cases.Case{ID: "CASE-1", Risk: cases.Risk{Severity: findings.SeverityLow}}
	other := cases.Case{ID: "CASE-2", Risk: cases.Risk{Severity: findings.SeverityHigh}}

	ordered := OrderCases([]cases.Case{base, other}, []string{"CASE-2", "CASE-1"})
	if len(ordered) != 2 {
		t.Fatalf("unexpected length: %d", len(ordered))
	}
	if ordered[0].ID != "CASE-2" || ordered[1].ID != "CASE-1" {
		t.Fatalf("unexpected order: %v", []string{ordered[0].ID, ordered[1].ID})
	}
}

func TestComputeCaseDigest(t *testing.T) {
	ts := findings.NewTimestamp(time.Unix(1700003000, 0).UTC())
	first := cases.Case{ID: "CASE-A", GeneratedAt: ts, Risk: cases.Risk{Severity: findings.SeverityMedium}}
	second := cases.Case{ID: "CASE-B", GeneratedAt: ts, Risk: cases.Risk{Severity: findings.SeverityLow}}

	list := []cases.Case{first, second}
	digestA, err := ComputeCaseDigest(list, []string{"CASE-B", "CASE-A"}, "sha256")
	if err != nil {
		t.Fatalf("ComputeCaseDigest failed: %v", err)
	}
	digestB, err := ComputeCaseDigest([]cases.Case{second, first}, []string{"CASE-B", "CASE-A"}, "sha256")
	if err != nil {
		t.Fatalf("ComputeCaseDigest failed: %v", err)
	}
	if digestA != digestB {
		t.Fatalf("expected stable digest, got %q vs %q", digestA, digestB)
	}
	if _, err := ComputeCaseDigest(list, nil, "unsupported"); err == nil {
		t.Fatalf("expected error for unsupported algorithm")
	}
}
