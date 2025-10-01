package replay

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/RowanDark/Glyph/internal/cases"
	"github.com/RowanDark/Glyph/internal/findings"
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
