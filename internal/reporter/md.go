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

// RenderReport loads findings from inputPath and writes a markdown summary to outputPath.
func RenderReport(inputPath, outputPath string, opts ReportOptions) error {
	findings, err := ReadJSONL(inputPath)
	if err != nil {
		return err
	}

	content := RenderMarkdown(findings, opts)
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return fmt.Errorf("create report directory: %w", err)
	}
	if err := os.WriteFile(outputPath, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}

// RenderMarkdown converts a slice of findings into a markdown report.
func RenderMarkdown(list []findings.Finding, opts ReportOptions) string {
	since, now, filtered := opts.reportingWindow()
	var windowStart *time.Time
	if filtered {
		windowStart = &since
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	filteredList := list
	if windowStart != nil {
		trimmed := make([]findings.Finding, 0, len(list))
		for _, f := range list {
			ts := f.DetectedAt.Time().UTC()
			if ts.Before(*windowStart) {
				continue
			}
			if ts.After(now) {
				continue
			}
			trimmed = append(trimmed, f)
		}
		filteredList = trimmed
	}

	counts := map[findings.Severity]int{
		findings.SeverityCritical: 0,
		findings.SeverityHigh:     0,
		findings.SeverityMedium:   0,
		findings.SeverityLow:      0,
		findings.SeverityInfo:     0,
	}
	targets := map[string]int{}
	plugins := map[string]int{}

	for _, f := range filteredList {
		sev := canonicalSeverity(f.Severity)
		counts[sev]++

		target := strings.TrimSpace(f.Target)
		if target == "" {
			target = "(not specified)"
		}
		targets[target]++

		plugin := strings.TrimSpace(f.Plugin)
		if plugin == "" {
			plugin = "(not specified)"
		}
		plugins[plugin]++
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

	type pluginCount struct {
		Plugin string
		Count  int
	}

	pluginRanked := make([]pluginCount, 0, len(plugins))
	for plugin, count := range plugins {
		if count == 0 {
			continue
		}
		pluginRanked = append(pluginRanked, pluginCount{Plugin: plugin, Count: count})
	}

	sort.Slice(pluginRanked, func(i, j int) bool {
		if pluginRanked[i].Count == pluginRanked[j].Count {
			return pluginRanked[i].Plugin < pluginRanked[j].Plugin
		}
		return pluginRanked[i].Count > pluginRanked[j].Count
	})

	pluginLimit := len(pluginRanked)
	if defaultTopPlugins > 0 && pluginLimit > defaultTopPlugins {
		pluginLimit = defaultTopPlugins
	}

	var b strings.Builder
	b.WriteString("# Findings Report\n\n")
	if windowStart != nil {
		fmt.Fprintf(&b, "Reporting window: %s — %s (UTC)\n\n", windowStart.Format(time.RFC3339), now.Format(time.RFC3339))
	} else {
		fmt.Fprintf(&b, "Reporting window: All findings through %s (UTC)\n\n", now.Format(time.RFC3339))
	}
	fmt.Fprintf(&b, "Total findings: %d\n\n", len(filteredList))

	b.WriteString("## Totals by Severity\n\n")
	b.WriteString("| Severity | Count |\n")
	b.WriteString("| --- | ---: |\n")
	for _, entry := range severityOrder {
		fmt.Fprintf(&b, "| %s | %d |\n", entry.label, counts[entry.key])
	}
	b.WriteString("\n")

	b.WriteString("## Findings by Plugin (top 5)\n\n")
	if pluginLimit == 0 {
		b.WriteString("No plugins reported.\n\n")
	} else {
		fmt.Fprintf(&b, "Showing top %d plugins by finding volume.\n\n", pluginLimit)
		b.WriteString("| Plugin | Findings |\n")
		b.WriteString("| --- | ---: |\n")
		for i := 0; i < pluginLimit; i++ {
			entry := pluginRanked[i]
			fmt.Fprintf(&b, "| %s | %d |\n", markdownCell(entry.Plugin), entry.Count)
		}
		b.WriteString("\n")
	}

	b.WriteString("## Top 10 Targets\n\n")
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
	if len(filteredList) == 0 {
		b.WriteString("No findings recorded.\n")
		return b.String()
	}

	recent := make([]findings.Finding, len(filteredList))
	copy(recent, filteredList)
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

	b.WriteString("| Plugin | Target | Evidence | Detected At |\n")
	b.WriteString("| --- | --- | --- | --- |\n")
	for _, f := range recent {
		ts := f.DetectedAt.Time().UTC().Format(time.RFC3339)
		plugin := markdownCell(f.Plugin)
		target := markdownCell(f.Target)
		if target == "" {
			target = "(not specified)"
		}
		evidence := evidenceExcerpt(f)
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", plugin, target, evidence, ts)
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
