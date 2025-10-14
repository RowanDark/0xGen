package reporter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RowanDark/0xgen/internal/findings"
)

func TestRenderHTMLGolden(t *testing.T) {
	base := time.Date(2024, 2, 10, 12, 0, 0, 0, time.UTC)
	since24h := base.Add(-24 * time.Hour)

	sample := []findings.Finding{
		{Version: findings.SchemaVersion, ID: "01HZXK4QAZ3ZKAB1Y7P5Z9Q4C4", Plugin: "alpha", Type: "t", Message: "alpha high", Target: "https://a", Severity: findings.SeverityHigh, DetectedAt: findings.NewTimestamp(base.Add(-2 * time.Hour))},
		{Version: findings.SchemaVersion, ID: "01HZXK4QAZ3ZKAB1Y7P5Z9Q4C5", Plugin: "beta", Type: "t", Message: "beta medium", Target: "https://b", Severity: findings.SeverityMedium, DetectedAt: findings.NewTimestamp(base.Add(-6 * time.Hour))},
		{Version: findings.SchemaVersion, ID: "01HZXK4QAZ3ZKAB1Y7P5Z9Q4C6", Plugin: "alpha", Type: "t", Message: "alpha critical", Target: "https://a", Severity: findings.SeverityCritical, DetectedAt: findings.NewTimestamp(base.Add(-25 * time.Hour))},
		{Version: findings.SchemaVersion, ID: "01HZXK4QAZ3ZKAB1Y7P5Z9Q4C7", Plugin: "gamma", Type: "t", Message: "gamma low", Target: "", Severity: findings.SeverityLow, DetectedAt: findings.NewTimestamp(base.Add(-26 * time.Hour))},
	}

	got, err := RenderHTML(sample, ReportOptions{Now: base, Since: &since24h})
	if err != nil {
		t.Fatalf("render html: %v", err)
	}
	goldenPath := filepath.Join("testdata", "report_since_24h.html.golden")
	wantBytes, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	want := string(wantBytes)
	if strings.TrimSpace(got) != strings.TrimSpace(want) {
		t.Fatalf("html mismatch\nwant:\n%s\n\ngot:\n%s", want, got)
	}
}
