package reporter

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/RowanDark/0xgen/internal/findings"
)

const (
	defaultOutputDir = "/out"
	findingsFilename = "findings.jsonl"
	reportFilename   = "report.md"
	// DefaultTopTargets controls how many targets appear in summary tables.
	DefaultTopTargets     = 10
	defaultTopPlugins     = 5
	defaultRecentFindings = 20
	evidenceExcerptLimit  = 160
)

var (
	// DefaultFindingsPath is where glyphd persists findings for other tools to consume.
	DefaultFindingsPath = filepath.Join(defaultOutputDir, findingsFilename)
	// DefaultReportPath is the default markdown summary written for CAP_REPORT consumers.
	DefaultReportPath = filepath.Join(defaultOutputDir, reportFilename)
)

func init() {
	if custom := strings.TrimSpace(os.Getenv("GLYPH_OUT")); custom != "" {
		DefaultFindingsPath = filepath.Join(custom, findingsFilename)
		DefaultReportPath = filepath.Join(custom, reportFilename)
	}
}

var severityOrder = []struct {
	key   findings.Severity
	label string
}{
	{key: findings.SeverityCritical, label: "Critical"},
	{key: findings.SeverityHigh, label: "High"},
	{key: findings.SeverityMedium, label: "Medium"},
	{key: findings.SeverityLow, label: "Low"},
	{key: findings.SeverityInfo, label: "Informational"},
}

// ReportOptions customises the filtering applied when rendering a report.
type ReportOptions struct {
	// Since filters findings to those detected on or after the provided timestamp.
	// A zero value disables the filter.
	Since *time.Time
	// Now identifies the end of the reporting window. When unset, time.Now() is used.
	Now time.Time
	// Context provides cancellation for expensive case aggregation.
	Context context.Context
	// SBOMPath links the generated report to the SBOM used for dependency analysis.
	SBOMPath string
}

func (o ReportOptions) reportingWindow() (time.Time, time.Time, bool) {
	now := o.Now
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	if o.Since == nil {
		return time.Time{}, now, false
	}
	since := o.Since.UTC()
	return since, now, true
}

// RenderReport loads findings from inputPath and writes a summary to outputPath.
func RenderReport(inputPath, outputPath string, format ReportFormat, opts ReportOptions) error {
	findings, err := ReadJSONL(inputPath)
	if err != nil {
		return err
	}

	var data []byte
	switch format {
	case FormatHTML:
		content, err := RenderHTML(findings, opts)
		if err != nil {
			return err
		}
		data = []byte(content)
	case FormatJSON:
		content, err := RenderJSON(findings, opts)
		if err != nil {
			return err
		}
		data = content
	case FormatMarkdown, "":
		content := RenderMarkdown(findings, opts)
		data = []byte(content)
	default:
		return fmt.Errorf("unsupported report format: %s", format)
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return fmt.Errorf("create report directory: %w", err)
	}
	if err := os.WriteFile(outputPath, data, 0o644); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}

// RenderMarkdown converts a slice of findings into a markdown report.
func RenderMarkdown(list []findings.Finding, opts ReportOptions) string {
	summary, _, _, _ := buildSummary(list, opts)

	var b strings.Builder
	b.WriteString("# Findings Report\n\n")
	if summary.WindowStart != nil {
		fmt.Fprintf(&b, "Reporting window: %s — %s (UTC)\n\n", summary.WindowStart.Format(time.RFC3339), summary.WindowEnd.Format(time.RFC3339))
	} else {
		fmt.Fprintf(&b, "Reporting window: All findings through %s (UTC)\n\n", summary.WindowEnd.Format(time.RFC3339))
	}
	fmt.Fprintf(&b, "Total findings: %d\n\n", summary.Total)

	b.WriteString("## Totals by Severity\n\n")
	b.WriteString("| Severity | Count |\n")
	b.WriteString("| --- | ---: |\n")
	for _, entry := range severityOrder {
		fmt.Fprintf(&b, "| %s | %d |\n", entry.label, summary.SeverityCount[entry.key])
	}
	b.WriteString("\n")

	b.WriteString("## Findings by Plugin (top 5)\n\n")
	if len(summary.Plugins) == 0 {
		b.WriteString("No plugins reported.\n\n")
	} else {
		fmt.Fprintf(&b, "Showing top %d plugins by finding volume.\n\n", len(summary.Plugins))
		b.WriteString("| Plugin | Findings |\n")
		b.WriteString("| --- | ---: |\n")
		for _, entry := range summary.Plugins {
			fmt.Fprintf(&b, "| %s | %d |\n", markdownCell(entry.Plugin), entry.Count)
		}
		b.WriteString("\n")
	}

	b.WriteString("## Top 10 Targets\n\n")
	if len(summary.Targets) == 0 {
		b.WriteString("No targets reported.\n\n")
	} else {
		fmt.Fprintf(&b, "Showing top %d targets by finding volume.\n\n", len(summary.Targets))
		for idx, entry := range summary.Targets {
			fmt.Fprintf(&b, "%d. **%s** — %d findings\n", idx+1, entry.Target, entry.Count)
		}
		b.WriteString("\n")
	}

	recentCap := defaultRecentFindings
	fmt.Fprintf(&b, "## Last %d Findings\n\n", recentCap)
	if summary.Total == 0 {
		b.WriteString("No findings recorded.\n")
		return b.String()
	}

	b.WriteString("| Plugin | Target | Evidence | Detected At |\n")
	b.WriteString("| --- | --- | --- | --- |\n")
	for _, f := range summary.Recent {
		ts := f.DetectedAt.Time().UTC().Format(time.RFC3339)
		plugin := markdownCell(strings.TrimSpace(f.Plugin))
		if plugin == "" {
			plugin = "(not specified)"
		}
		target := strings.TrimSpace(f.Target)
		if target == "" {
			target = "(not specified)"
		}
		targetCell := markdownCell(target)
		evidence := markdownCell(findingExcerpt(f))
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", plugin, targetCell, evidence, ts)
	}
	b.WriteString("\n")
	return b.String()
}

func markdownCell(input string) string {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return ""
	}
	trimmed = strings.ReplaceAll(trimmed, "\n", " ")
	trimmed = strings.ReplaceAll(trimmed, "\r", " ")
	trimmed = strings.ReplaceAll(trimmed, "|", "\\|")
	return trimmed
}
