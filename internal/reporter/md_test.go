package reporter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RowanDark/Glyph/internal/findings"
)

func TestRenderMarkdownGolden(t *testing.T) {
	base := time.Date(2024, 2, 10, 12, 0, 0, 0, time.UTC)
	since24h := base.Add(-24 * time.Hour)

	sample := []findings.Finding{
		{Version: findings.SchemaVersion, ID: "01HZXK4QAZ3ZKAB1Y7P5Z9Q4C4", Plugin: "alpha", Type: "t", Message: "alpha high", Target: "https://a", Severity: findings.SeverityHigh, DetectedAt: findings.NewTimestamp(base.Add(-2 * time.Hour))},
		{Version: findings.SchemaVersion, ID: "01HZXK4QAZ3ZKAB1Y7P5Z9Q4C5", Plugin: "beta", Type: "t", Message: "beta medium", Target: "https://b", Severity: findings.SeverityMedium, DetectedAt: findings.NewTimestamp(base.Add(-6 * time.Hour))},
		{Version: findings.SchemaVersion, ID: "01HZXK4QAZ3ZKAB1Y7P5Z9Q4C6", Plugin: "alpha", Type: "t", Message: "alpha critical", Target: "https://a", Severity: findings.SeverityCritical, DetectedAt: findings.NewTimestamp(base.Add(-25 * time.Hour))},
		{Version: findings.SchemaVersion, ID: "01HZXK4QAZ3ZKAB1Y7P5Z9Q4C7", Plugin: "gamma", Type: "t", Message: "gamma low", Target: "", Severity: findings.SeverityLow, DetectedAt: findings.NewTimestamp(base.Add(-26 * time.Hour))},
	}

	pluginNow := time.Date(2024, 3, 1, 15, 0, 0, 0, time.UTC)
	pluginFindings := []findings.Finding{
		{Version: findings.SchemaVersion, ID: "01HX000000000000000000001", Plugin: "alpha", Type: "t", Message: "alpha", Target: "https://one", Severity: findings.SeverityHigh, DetectedAt: findings.NewTimestamp(pluginNow.Add(-1 * time.Hour))},
		{Version: findings.SchemaVersion, ID: "01HX000000000000000000002", Plugin: "beta", Type: "t", Message: "beta", Target: "https://two", Severity: findings.SeverityMedium, DetectedAt: findings.NewTimestamp(pluginNow.Add(-2 * time.Hour))},
		{Version: findings.SchemaVersion, ID: "01HX000000000000000000003", Plugin: "gamma", Type: "t", Message: "gamma", Target: "https://three", Severity: findings.SeverityLow, DetectedAt: findings.NewTimestamp(pluginNow.Add(-3 * time.Hour))},
		{Version: findings.SchemaVersion, ID: "01HX000000000000000000004", Plugin: "delta", Type: "t", Message: "delta", Target: "https://four", Severity: findings.SeverityInfo, DetectedAt: findings.NewTimestamp(pluginNow.Add(-4 * time.Hour))},
		{Version: findings.SchemaVersion, ID: "01HX000000000000000000005", Plugin: "epsilon", Type: "t", Message: "epsilon", Target: "https://five", Severity: findings.SeverityLow, DetectedAt: findings.NewTimestamp(pluginNow.Add(-5 * time.Hour))},
		{Version: findings.SchemaVersion, ID: "01HX000000000000000000006", Plugin: "zeta", Type: "t", Message: "zeta", Target: "https://six", Severity: findings.SeverityLow, DetectedAt: findings.NewTimestamp(pluginNow.Add(-6 * time.Hour))},
		{Version: findings.SchemaVersion, ID: "01HX000000000000000000007", Plugin: "alpha", Type: "t", Message: "alpha repeat", Target: "https://one", Severity: findings.SeverityHigh, DetectedAt: findings.NewTimestamp(pluginNow.Add(-7 * time.Hour))},
		{Version: findings.SchemaVersion, ID: "01HX000000000000000000008", Plugin: "alpha", Type: "t", Message: "alpha another", Target: "https://one", Severity: findings.SeverityMedium, DetectedAt: findings.NewTimestamp(pluginNow.Add(-8 * time.Hour))},
		{Version: findings.SchemaVersion, ID: "01HX000000000000000000009", Plugin: "beta", Type: "t", Message: "beta repeat", Target: "https://two", Severity: findings.SeverityMedium, DetectedAt: findings.NewTimestamp(pluginNow.Add(-9 * time.Hour))},
		{Version: findings.SchemaVersion, ID: "01HX00000000000000000000A", Plugin: "gamma", Type: "t", Message: "gamma repeat", Target: "https://three", Severity: findings.SeverityLow, DetectedAt: findings.NewTimestamp(pluginNow.Add(-10 * time.Hour))},
	}

	cases := []struct {
		name   string
		list   []findings.Finding
		opts   ReportOptions
		golden string
	}{
		{
			name:   "no-filter",
			list:   sample,
			opts:   ReportOptions{Now: base},
			golden: "report_no_filter.golden",
		},
		{
			name:   "since-24h",
			list:   sample,
			opts:   ReportOptions{Now: base, Since: &since24h},
			golden: "report_since_24h.golden",
		},
		{
			name:   "by-plugin",
			list:   pluginFindings,
			opts:   ReportOptions{Now: pluginNow},
			golden: "report_by_plugin.golden",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RenderMarkdown(tc.list, tc.opts)
			goldenPath := filepath.Join("testdata", tc.golden)
			wantBytes, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("read golden: %v", err)
			}
			if diff := strings.Compare(got, string(wantBytes)); diff != 0 {
				t.Fatalf("markdown mismatch\nwant:\n%s\n\ngot:\n%s", string(wantBytes), got)
			}
		})
	}
}

func TestRenderReportWritesFile(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "findings.jsonl")
	output := filepath.Join(dir, "report.md")

	writer := NewJSONL(input)
	sample := findings.Finding{
		Version:    findings.SchemaVersion,
		ID:         findings.NewID(),
		Plugin:     "p",
		Type:       "t",
		Message:    "m",
		Evidence:   "",
		Severity:   findings.SeverityCritical,
		DetectedAt: findings.NewTimestamp(time.Unix(1710000000, 0).UTC()),
	}
	if err := writer.Write(sample); err != nil {
		t.Fatalf("write finding: %v", err)
	}

	if err := RenderReport(input, output, FormatMarkdown, ReportOptions{}); err != nil {
		t.Fatalf("render report: %v", err)
	}

	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	if !strings.Contains(string(data), "Critical") {
		t.Fatalf("report missing severity: %s", data)
	}
	if !strings.Contains(string(data), "(not specified)") {
		t.Fatalf("report missing placeholder target: %s", data)
	}
}
