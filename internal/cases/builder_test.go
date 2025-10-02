package cases

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RowanDark/Glyph/internal/findings"
)

type stubSummarizer struct {
	output SummaryOutput
}

func (s stubSummarizer) Summarize(_ context.Context, _ SummaryInput) (SummaryOutput, error) {
	return s.output, nil
}

func TestBuilderCollapsesFindings(t *testing.T) {
	builder := NewBuilder(
		WithDeterministicMode(42),
		WithClock(func() time.Time { return time.Unix(1700000000, 0).UTC() }),
	)

	findingsList := []findings.Finding{
		{
			Version:    findings.SchemaVersion,
			ID:         "F1",
			Plugin:     "seer",
			Type:       "seer.generic_api_key",
			Message:    "High entropy API key discovered",
			Target:     "https://example.com/app.js",
			Severity:   findings.SeverityHigh,
			DetectedAt: findings.NewTimestamp(time.Unix(1700000000, 0)),
			Metadata:   map[string]string{"vector": "code", "asset_kind": "repo", "asset_id": "example/app"},
		},
		{
			Version:  findings.SchemaVersion,
			ID:       "F2",
			Plugin:   "excavator",
			Type:     "excavator.open_directory",
			Message:  "Directory listing enabled",
			Target:   "https://example.com/app.js",
			Severity: findings.SeverityMedium,
			Metadata: map[string]string{"vector": "web", "label:environment": "prod"},
		},
		{
			Version:  findings.SchemaVersion,
			ID:       "F3",
			Plugin:   "proxy",
			Type:     "proxy.session",
			Message:  "Captured authenticated request",
			Target:   "https://example.com/api",
			Severity: findings.SeverityHigh,
			Evidence: "GET /api/key",
		},
	}

	cases, err := builder.Build(context.Background(), findingsList)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}

	if len(cases) != 1 {
		t.Fatalf("expected 1 case, got %d", len(cases))
	}

	c := cases[0]
	if got := len(c.Sources); got != len(findingsList) {
		t.Fatalf("expected %d sources, got %d", len(findingsList), got)
	}
	if c.Risk.Severity != findings.SeverityHigh {
		t.Fatalf("unexpected risk severity: %s", c.Risk.Severity)
	}
	if !strings.Contains(c.Summary, "example.com") {
		t.Fatalf("summary did not mention target: %q", c.Summary)
	}
}

func TestDeterministicReplayStableJSON(t *testing.T) {
	cache := NewMemoryCache()
	builder := NewBuilder(
		WithDeterministicMode(1234),
		WithClock(func() time.Time { return time.Unix(1700001000, 0).UTC() }),
		WithCache(cache),
	)

	fs := []findings.Finding{{
		Version:  findings.SchemaVersion,
		ID:       "A",
		Plugin:   "seer",
		Type:     "seer.jwt_token",
		Message:  "Potential JWT detected",
		Target:   "https://api.example.com",
		Evidence: "header.payload.signature",
		Severity: findings.SeverityMedium,
	}, {
		Version:  findings.SchemaVersion,
		ID:       "B",
		Plugin:   "proxy",
		Type:     "proxy.flow",
		Message:  "Replayable request captured",
		Target:   "https://api.example.com",
		Severity: findings.SeverityMedium,
	}}

	run := func() string {
		cases, err := builder.Build(context.Background(), fs)
		if err != nil {
			t.Fatalf("build failed: %v", err)
		}
		if len(cases) != 1 {
			t.Fatalf("expected single case, got %d", len(cases))
		}
		data, err := ExportJSON(cases[0])
		if err != nil {
			t.Fatalf("ExportJSON failed: %v", err)
		}
		return string(data)
	}

	first := run()
	second := run()
	if first != second {
		t.Fatalf("deterministic runs produced different JSON\nfirst: %s\nsecond: %s", first, second)
	}
}

func TestGoldenSummary(t *testing.T) {
	builder := NewBuilder(
		WithDeterministicMode(2024),
		WithClock(func() time.Time { return time.Unix(1700003000, 0).UTC() }),
	)

	fs := []findings.Finding{{
		Version:  findings.SchemaVersion,
		ID:       "1",
		Plugin:   "seer",
		Type:     "seer.email",
		Message:  "Email address found",
		Target:   "https://corp.example.com",
		Severity: findings.SeverityLow,
	}, {
		Version:  findings.SchemaVersion,
		ID:       "2",
		Plugin:   "excavator",
		Type:     "excavator.exposed_file",
		Message:  "Public log leak",
		Target:   "https://corp.example.com/logs",
		Evidence: "access.log",
		Severity: findings.SeverityMedium,
	}}

	cases, err := builder.Build(context.Background(), fs)
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	if len(cases) != 1 {
		t.Fatalf("expected single case, got %d", len(cases))
	}

	got, err := json.MarshalIndent(cases[0], "", "  ")
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	got = append(got, '\n')

	goldenPath := filepath.Join("testdata", "golden_case.json")
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}

	if string(want) != string(got) {
		t.Fatalf("golden mismatch\nwant:\n%s\ngot:\n%s", string(want), string(got))
	}
}

func TestGoldenSampleWebService(t *testing.T) {
	builder := NewBuilder(
		WithDeterministicMode(5150),
		WithClock(func() time.Time { return time.Unix(1700009000, 0).UTC() }),
	)

	fs := loadFindingsFixture(t, filepath.Join("testdata", "sample_web_service_findings.json"))

	cases, err := builder.Build(context.Background(), fs)
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	if len(cases) != 1 {
		t.Fatalf("expected single case, got %d", len(cases))
	}

	got, err := json.MarshalIndent(cases[0], "", "  ")
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	got = append(got, '\n')

	goldenPath := filepath.Join("testdata", "sample_web_service_case.json")
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}

	if string(want) != string(got) {
		t.Fatalf("golden mismatch\nwant:\n%s\ngot:\n%s", string(want), string(got))
	}
}

func TestBuilderRedactsSecrets(t *testing.T) {
	builder := NewBuilder(
		WithSummarizer(stubSummarizer{output: SummaryOutput{
			Summary:      "Token AKIA123456789012345678901234 leaked",
			ProofSummary: "Contact alice@example.com",
			ReproductionSteps: []string{
				"Use secret token=AKIA123456789012345678901234",
			},
			RiskSeverity:    findings.SeverityHigh,
			RiskRationale:   "API key exposed secret=supersecretvalue123456",
			ConfidenceScore: 0.9,
		}}),
		WithDeterministicMode(7),
	)
	fs := []findings.Finding{{
		Version:  findings.SchemaVersion,
		ID:       "sec-1",
		Plugin:   "seer",
		Type:     "seer.secret",
		Message:  "Token AKIA123456789012345678901234 discovered",
		Target:   "https://example.com/?token=AKIA123456789012345678901234",
		Evidence: "token=AKIA123456789012345678901234",
		Severity: findings.SeverityHigh,
		Metadata: map[string]string{
			"leak":  "user@example.com",
			"token": "Bearer AKIA123456789012345678901234",
		},
	}}

	cases, err := builder.Build(context.Background(), fs)
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	if len(cases) != 1 {
		t.Fatalf("expected single case, got %d", len(cases))
	}
	c := cases[0]
	if strings.Contains(c.Summary, "AKIA123456789012345678901234") {
		t.Fatalf("summary leaked secret: %q", c.Summary)
	}
	if c.Proof.Summary != "Contact [REDACTED_EMAIL]" {
		t.Fatalf("proof summary not redacted: %q", c.Proof.Summary)
	}
	if len(c.Proof.Steps) != 1 || !strings.Contains(c.Proof.Steps[0], "[REDACTED_SECRET]") {
		t.Fatalf("proof steps not redacted: %#v", c.Proof.Steps)
	}
	if !strings.Contains(c.Risk.Rationale, "[REDACTED_SECRET]") {
		t.Fatalf("risk rationale not redacted: %q", c.Risk.Rationale)
	}
	if len(c.Evidence) == 0 {
		t.Fatalf("expected evidence entries")
	}
	evidence := c.Evidence[0]
	if evidence.Evidence != "token=[REDACTED_SECRET]" {
		t.Fatalf("evidence not redacted: %q", evidence.Evidence)
	}
	if leak := evidence.Metadata["leak"]; leak != "[REDACTED_EMAIL]" {
		t.Fatalf("metadata email not redacted: %q", leak)
	}
	if token := evidence.Metadata["token"]; !strings.Contains(token, "[REDACTED_SECRET]") {
		t.Fatalf("metadata token not redacted: %q", token)
	}
}

func TestPromptsIncludeEvidence(t *testing.T) {
	proto := Case{Asset: Asset{Identifier: "api.example.com", Kind: "web"}, Vector: AttackVector{Kind: "web_crawl"}}
	findings := []NormalisedFinding{{
		Plugin:   "seer",
		Severity: findings.SeverityHigh,
		Message:  "API key exposed",
		Evidence: "AKIA...",
	}}

	prompts := BuildPrompts(proto, findings)
	if !strings.Contains(prompts.SummaryPrompt, "API key exposed") {
		t.Fatalf("summary prompt missing message: %q", prompts.SummaryPrompt)
	}
	if !strings.Contains(prompts.ReproductionPrompt, "AKIA") {
		t.Fatalf("reproduction prompt missing evidence: %q", prompts.ReproductionPrompt)
	}
}

func loadFindingsFixture(t *testing.T, path string) []findings.Finding {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read findings fixture: %v", err)
	}
	var fs []findings.Finding
	if err := json.Unmarshal(data, &fs); err != nil {
		t.Fatalf("unmarshal findings fixture: %v", err)
	}
	return fs
}
