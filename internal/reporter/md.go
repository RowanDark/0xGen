package reporter

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/RowanDark/Glyph/internal/findings"
)

const (
	// DefaultFindingsPath is where glyphd persists findings for other tools to consume.
	DefaultFindingsPath = "/out/findings.jsonl"
	// DefaultReportPath is the default markdown summary written for CAP_REPORT consumers.
	DefaultReportPath = "/out/report.md"
	// DefaultTopTargets controls how many targets appear in summary tables.
	DefaultTopTargets = 5
)

var severityOrder = []struct {
	key   string
	label string
}{
	{key: "crit", label: "Critical"},
	{key: "high", label: "High"},
	{key: "med", label: "Medium"},
	{key: "low", label: "Low"},
	{key: "info", label: "Informational"},
}

// RenderReport loads findings from inputPath and writes a markdown summary to outputPath.
func RenderReport(inputPath, outputPath string, topN int) error {
	findings, err := ReadJSONL(inputPath)
	if err != nil {
		return err
	}

	if topN <= 0 {
		topN = DefaultTopTargets
	}

	content := RenderMarkdown(findings, topN)
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return fmt.Errorf("create report directory: %w", err)
	}
	if err := os.WriteFile(outputPath, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}

// RenderMarkdown converts a slice of findings into a markdown report.
func RenderMarkdown(list []findings.Finding, topN int) string {
	counts := map[string]int{
		"crit": 0,
		"high": 0,
		"med":  0,
		"low":  0,
		"info": 0,
	}
	targets := map[string]int{}

	for _, f := range list {
		sev := normalizeSeverity(f.Severity)
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
	if topN > 0 && topN < limit {
		limit = topN
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
		b.WriteString("No targets reported.\n")
		return b.String()
	}

	fmt.Fprintf(&b, "Showing top %d targets by finding volume.\n\n", limit)
	for i := 0; i < limit; i++ {
		entry := ranked[i]
		fmt.Fprintf(&b, "%d. **%s** — %d findings\n", i+1, entry.Target, entry.Count)
	}
	b.WriteString("\n")
	return b.String()
}

func normalizeSeverity(input string) string {
	switch strings.ToLower(strings.TrimSpace(input)) {
	case "critical", "crit":
		return "crit"
	case "high":
		return "high"
	case "medium", "med":
		return "med"
	case "low":
		return "low"
	case "info", "informational":
		return "info"
	default:
		return "info"
	}
}
