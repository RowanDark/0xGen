package seer

import (
	"testing"
	"time"

	"github.com/RowanDark/Glyph/internal/findings"
)

func TestScanFindsSecrets(t *testing.T) {
	content := `AWS key: AKIAABCDEFGHIJKLMNOP
Slack token: xoxb-123456789012-abcdefghijklmnop
Generic key: api_key = sk_live_a1B2c3D4e5F6g7H8
Email: alerts@example.com`

	ts := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	results := Scan("https://example.com", content, Config{
		Allowlist: []string{"alerts@example.com"},
		Now:       func() time.Time { return ts },
	})

	if len(results) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(results))
	}

	check := func(idx int, wantType string, wantSeverity findings.Severity, wantEvidence string) {
		t.Helper()
		f := results[idx]
		if f.Type != wantType {
			t.Fatalf("finding %d type = %q, want %q", idx, f.Type, wantType)
		}
		if f.Severity != wantSeverity {
			t.Fatalf("finding %d severity = %q, want %q", idx, f.Severity, wantSeverity)
		}
		if f.Evidence != wantEvidence {
			t.Fatalf("finding %d evidence = %q, want %q", idx, f.Evidence, wantEvidence)
		}
		if f.Plugin != "seer" {
			t.Fatalf("finding %d plugin = %q, want seer", idx, f.Plugin)
		}
		if !f.DetectedAt.Time().Equal(ts) {
			t.Fatalf("finding %d timestamp mismatch: %s", idx, f.DetectedAt.Time())
		}
		if f.Metadata["pattern"] != wantType {
			t.Fatalf("finding %d metadata pattern = %q", idx, f.Metadata["pattern"])
		}
		if f.Metadata["redacted_match"] != wantEvidence {
			t.Fatalf("finding %d metadata redaction mismatch", idx)
		}
	}

	check(0, "seer.aws_access_key", findings.SeverityHigh, "****************MNOP")
        check(1, "seer.generic_api_key", findings.SeverityMedium, "********************g7H8")
	if entropy := results[1].Metadata["entropy"]; entropy == "" {
		t.Fatalf("generic finding missing entropy")
	}
        check(2, "seer.slack_token", findings.SeverityHigh, "******************************mnop")
}

func TestScanDeduplicatesAndRedactsEmails(t *testing.T) {
	content := `Contact us: security@example.com or SECURITY@example.com`
	ts := time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC)

	results := Scan("https://example.com", content, Config{Now: func() time.Time { return ts }})
	if len(results) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(results))
	}
	f := results[0]
	if f.Type != "seer.email_address" {
		t.Fatalf("email finding type = %q", f.Type)
	}
	if f.Evidence != "s******y@example.com" {
		t.Fatalf("email evidence = %q", f.Evidence)
	}
}
