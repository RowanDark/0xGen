package seertests

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/RowanDark/Glyph/internal/findings"
	"github.com/RowanDark/Glyph/internal/seer"
)

type fixtureCase struct {
	Name      string            `json:"name"`
	Target    string            `json:"target"`
	Content   string            `json:"content"`
	Allowlist []string          `json:"allowlist"`
	Expect    []expectedFinding `json:"expect"`
}

type expectedFinding struct {
	Type       string   `json:"type"`
	Severity   string   `json:"severity"`
	Evidence   string   `json:"evidence"`
	MinEntropy *float64 `json:"min_entropy"`
}

func TestFixtureFindings(t *testing.T) {
	fixturesDir := "fixtures"
	entries, err := os.ReadDir(fixturesDir)
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}

	if len(entries) == 0 {
		t.Fatalf("no fixtures found in %s", fixturesDir)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		name := strings.TrimSuffix(entry.Name(), ".json")
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(fixturesDir, entry.Name()))
			if err != nil {
				t.Fatalf("read fixture %s: %v", entry.Name(), err)
			}

			var fixture fixtureCase
			if err := json.Unmarshal(raw, &fixture); err != nil {
				t.Fatalf("decode fixture %s: %v", entry.Name(), err)
			}

			ts := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
			results := seer.Scan(fixture.Target, fixture.Content, seer.Config{
				Allowlist: fixture.Allowlist,
				Now:       func() time.Time { return ts },
			})

			if len(results) != len(fixture.Expect) {
				t.Fatalf("fixture %s: expected %d findings, got %d", fixture.Name, len(fixture.Expect), len(results))
			}

			for i, exp := range fixture.Expect {
				got := results[i]
				if got.Type != exp.Type {
					t.Fatalf("fixture %s finding %d type = %q, want %q", fixture.Name, i, got.Type, exp.Type)
				}

				wantSeverity, err := parseSeverity(exp.Severity)
				if err != nil {
					t.Fatalf("fixture %s invalid severity %q: %v", fixture.Name, exp.Severity, err)
				}
				if got.Severity != wantSeverity {
					t.Fatalf("fixture %s finding %d severity = %q, want %q", fixture.Name, i, got.Severity, wantSeverity)
				}

				if got.Evidence != exp.Evidence {
					t.Fatalf("fixture %s finding %d evidence = %q, want %q", fixture.Name, i, got.Evidence, exp.Evidence)
				}

				if got.Target != fixture.Target {
					t.Fatalf("fixture %s finding %d target = %q, want %q", fixture.Name, i, got.Target, fixture.Target)
				}

				if got.DetectedAt.Time() != ts {
					t.Fatalf("fixture %s finding %d timestamp mismatch", fixture.Name, i)
				}

				if got.Metadata["pattern"] != got.Type {
					t.Fatalf("fixture %s finding %d pattern metadata = %q", fixture.Name, i, got.Metadata["pattern"])
				}

				if got.Metadata["redacted_match"] != got.Evidence {
					t.Fatalf("fixture %s finding %d redacted mismatch", fixture.Name, i)
				}

				if exp.MinEntropy != nil {
					entropyStr := got.Metadata["entropy"]
					if entropyStr == "" {
						t.Fatalf("fixture %s finding %d missing entropy metadata", fixture.Name, i)
					}
					entropy, err := strconv.ParseFloat(entropyStr, 64)
					if err != nil {
						t.Fatalf("fixture %s finding %d entropy parse error: %v", fixture.Name, i, err)
					}
					if entropy < *exp.MinEntropy {
						t.Fatalf("fixture %s finding %d entropy %.2f below threshold %.2f", fixture.Name, i, entropy, *exp.MinEntropy)
					}
				}
			}
		})
	}
}

func parseSeverity(raw string) (findings.Severity, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "info":
		return findings.SeverityInfo, nil
	case "low":
		return findings.SeverityLow, nil
	case "med", "medium":
		return findings.SeverityMedium, nil
	case "high":
		return findings.SeverityHigh, nil
	case "crit", "critical":
		return findings.SeverityCritical, nil
	default:
		return "", fmt.Errorf("unknown severity: %s", raw)
	}
}
