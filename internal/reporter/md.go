package reporter

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/RowanDark/Glyph/internal/findings"
)

const (
	defaultOutputDir = "/out"
	findingsFilename = "findings.jsonl"
	reportFilename   = "report.md"
	// DefaultTopTargets controls how many targets appear in summary tables.
	DefaultTopTargets     = 10
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

var severityLabels = func() map[findings.Severity]string {
	out := make(map[findings.Severity]string, len(severityOrder))
	for _, entry := range severityOrder {
		out[entry.key] = entry.label
	}
	return out
}()

// RenderReport loads findings from inputPath and writes a markdown summary to outputPath.
func RenderReport(inputPath, outputPath string) error {
	findings, err := ReadJSONL(inputPath)
	if err != nil {
		return err
	}

	content := RenderMarkdown(findings)
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return fmt.Errorf("create report directory: %w", err)
	}
	if err := os.WriteFile(outputPath, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}

// RenderMarkdown converts a slice of findings into a markdown report.
func RenderMarkdown(list []findings.Finding) string {
	counts := map[findings.Severity]int{
		findings.SeverityCritical: 0,
		findings.SeverityHigh:     0,
		findings.SeverityMedium:   0,
		findings.SeverityLow:      0,
		findings.SeverityInfo:     0,
	}
	targets := map[string]int{}

	for _, f := range list {
		sev := canonicalSeverity(f.Severity)
		counts[sev]++

		target := strings.TrimSpace(f.Target)
		if target == "" {
			target = "(not specified)"
		}
		targets[target]++
	}

	type targetCount struct {
		Target string
		Count  int
	}

	ranked := make([]targetCount, 0, len(targets))
	for target, count := range targets {
		if count == 0 {
			continue
		}
		ranked = append(ranked, targetCount{Target: target, Count: count})
	}

	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].Count == ranked[j].Count {
			return ranked[i].Target < ranked[j].Target
		}
		return ranked[i].Count > ranked[j].Count
	})

	limit := len(ranked)
	if DefaultTopTargets > 0 && DefaultTopTargets < limit {
		limit = DefaultTopTargets
	}

	var b strings.Builder
	b.WriteString("# Findings Report\n\n")
	fmt.Fprintf(&b, "Total findings: %d\n\n", len(list))

	b.WriteString("## Severity Breakdown\n\n")
	b.WriteString("| Severity | Count |\n")
	b.WriteString("| --- | ---: |\n")
	for _, entry := range severityOrder {
		fmt.Fprintf(&b, "| %s | %d |\n", entry.label, counts[entry.key])
	}
	b.WriteString("\n")

	b.WriteString("## Top Targets\n\n")
	if limit == 0 {
		b.WriteString("No targets reported.\n\n")
	} else {
		fmt.Fprintf(&b, "Showing top %d targets by finding volume.\n\n", limit)
		for i := 0; i < limit; i++ {
			entry := ranked[i]
			fmt.Fprintf(&b, "%d. **%s** — %d findings\n", i+1, entry.Target, entry.Count)
		}
		b.WriteString("\n")
	}

	recentCap := defaultRecentFindings
	fmt.Fprintf(&b, "## Last %d Findings\n\n", recentCap)
	if len(list) == 0 {
		b.WriteString("No findings recorded.\n")
		return b.String()
	}

	recent := make([]findings.Finding, len(list))
	copy(recent, list)
	sort.Slice(recent, func(i, j int) bool {
		ti := recent[i].DetectedAt.Time()
		tj := recent[j].DetectedAt.Time()
		if ti.Equal(tj) {
			return recent[i].ID > recent[j].ID
		}
		return ti.After(tj)
	})
	if len(recent) > recentCap {
		recent = recent[:recentCap]
	}

	b.WriteString("| Detected At | Severity | Plugin | Target | Evidence |\n")
	b.WriteString("| --- | --- | --- | --- | --- |\n")
	for _, f := range recent {
		ts := f.DetectedAt.Time().Format(time.RFC3339)
		sev := severityLabels[canonicalSeverity(f.Severity)]
		plugin := markdownCell(f.Plugin)
		target := markdownCell(f.Target)
		if target == "" {
			target = "(not specified)"
		}
		evidence := evidenceExcerpt(f)
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", ts, sev, plugin, target, evidence)
	}
	b.WriteString("\n")
	return b.String()
}

func canonicalSeverity(input findings.Severity) findings.Severity {
	switch strings.ToLower(strings.TrimSpace(string(input))) {
	case string(findings.SeverityCritical):
		return findings.SeverityCritical
	case string(findings.SeverityHigh):
		return findings.SeverityHigh
	case string(findings.SeverityMedium):
		return findings.SeverityMedium
	case string(findings.SeverityLow):
		return findings.SeverityLow
	case string(findings.SeverityInfo):
		return findings.SeverityInfo
	default:
		return findings.SeverityInfo
	}
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

func evidenceExcerpt(f findings.Finding) string {
	raw := strings.TrimSpace(f.Evidence)
	if raw == "" {
		raw = strings.TrimSpace(f.Message)
	}
	if raw == "" {
		return "(not provided)"
	}
	raw = strings.ReplaceAll(raw, "\r", " ")
	raw = strings.ReplaceAll(raw, "\n", " ")
	raw = strings.Join(strings.Fields(raw), " ")
	if evidenceExcerptLimit > 0 {
		runes := []rune(raw)
		if len(runes) > evidenceExcerptLimit {
			raw = strings.TrimSpace(string(runes[:evidenceExcerptLimit])) + "…"
		}
	}
	cell := markdownCell(raw)
	if cell == "" {
		return "(not provided)"
	}
	return cell
}
