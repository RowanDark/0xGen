package comparison

import (
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/RowanDark/0xgen/internal/findings"
)

// FormatComparison formats a comparison result for display.
func FormatComparison(result *ComparisonResult) string {
	var out strings.Builder

	// Header
	out.WriteString("┌─ Scan Comparison ────────────────────────────────────────┐\n")
	out.WriteString("│                                                            │\n")
	out.WriteString(fmt.Sprintf("│  Scan A: %-48s │\n", truncateString(result.ScanA.Name+" ("+result.ScanA.ID+")", 48)))
	out.WriteString(fmt.Sprintf("│  Scan B: %-48s │\n", truncateString(result.ScanB.Name+" ("+result.ScanB.ID+")", 48)))
	if result.ScanA.Target != "" {
		out.WriteString(fmt.Sprintf("│  Target: %-48s │\n", truncateString(result.ScanA.Target, 48)))
	}
	out.WriteString("│                                                            │\n")

	// Summary
	out.WriteString("├─ Summary ────────────────────────────────────────────────┤\n")
	out.WriteString("│                                                            │\n")

	if result.Summary.NewCount > 0 {
		out.WriteString(fmt.Sprintf("│  🔴 New: %d vulnerabilities                                │\n", result.Summary.NewCount))
	}
	if result.Summary.FixedCount > 0 {
		out.WriteString(fmt.Sprintf("│  🟢 Fixed: %d vulnerabilities                              │\n", result.Summary.FixedCount))
	}
	if result.Summary.ChangedCount > 0 {
		out.WriteString(fmt.Sprintf("│  🟡 Changed: %d vulnerabilities                            │\n", result.Summary.ChangedCount))
	}
	if result.Summary.UnchangedCount > 0 {
		out.WriteString(fmt.Sprintf("│  ⚪ Unchanged: %d vulnerabilities                          │\n", result.Summary.UnchangedCount))
	}

	out.WriteString("│                                                            │\n")

	// New vulnerabilities
	if len(result.New) > 0 {
		out.WriteString("├─ New Vulnerabilities ────────────────────────────────────┤\n")
		out.WriteString("│                                                            │\n")

		for _, f := range result.New {
			icon := getSeverityIcon(f.Severity)
			out.WriteString(fmt.Sprintf("│  %s %s (%s)%s│\n",
				icon,
				truncateString(f.Type, 35),
				f.Severity,
				strings.Repeat(" ", max(0, 48-len(f.Type)-len(string(f.Severity))-5)),
			))
			if f.Target != "" {
				out.WriteString(fmt.Sprintf("│  └─ %-54s │\n", truncateString(f.Target, 54)))
			}
			out.WriteString(fmt.Sprintf("│     First seen: %-42s │\n", f.FirstSeen.Format("Jan 02, 2006")))
			out.WriteString("│                                                            │\n")
		}
	}

	// Fixed vulnerabilities
	if len(result.Fixed) > 0 {
		out.WriteString("├─ Fixed Vulnerabilities ──────────────────────────────────┤\n")
		out.WriteString("│                                                            │\n")

		for _, f := range result.Fixed {
			out.WriteString(fmt.Sprintf("│  🟢 %s (%s)%s│\n",
				truncateString(f.Type, 35),
				f.Severity,
				strings.Repeat(" ", max(0, 48-len(f.Type)-len(string(f.Severity))-5)),
			))
			if f.Target != "" {
				out.WriteString(fmt.Sprintf("│  └─ %-54s │\n", truncateString(f.Target, 54)))
			}
			out.WriteString(fmt.Sprintf("│     Fixed between %s - %s%s│\n",
				result.ScanA.Timestamp.Time().Format("Jan 02"),
				result.ScanB.Timestamp.Time().Format("Jan 02"),
				strings.Repeat(" ", 25),
			))
			out.WriteString("│                                                            │\n")
		}
	}

	// Changed vulnerabilities
	if len(result.Changed) > 0 {
		out.WriteString("├─ Changed Vulnerabilities ────────────────────────────────┤\n")
		out.WriteString("│                                                            │\n")

		for _, f := range result.Changed {
			icon := getSeverityIcon(f.Severity)
			out.WriteString(fmt.Sprintf("│  %s %s (%s)%s│\n",
				icon,
				truncateString(f.Type, 35),
				f.Severity,
				strings.Repeat(" ", max(0, 48-len(f.Type)-len(string(f.Severity))-5)),
			))
			for _, change := range f.Changes {
				out.WriteString(fmt.Sprintf("│     • %-52s │\n", truncateString(change, 52)))
			}
			out.WriteString("│                                                            │\n")
		}
	}

	out.WriteString("└────────────────────────────────────────────────────────────┘\n")

	return out.String()
}

// FormatTrends formats trend data for display.
func FormatTrends(trend *TrendData) string {
	var out strings.Builder

	title := fmt.Sprintf("Security Trends: %s (%s)", trend.Target, trend.Period)
	out.WriteString(fmt.Sprintf("┌─ %-56s ┐\n", title))
	out.WriteString("│                                                            │\n")

	// Chart
	out.WriteString("│  Total Vulnerabilities Over Time:                        │\n")
	out.WriteString("│                                                            │\n")

	chart := trend.GenerateASCIIChart()
	for _, line := range strings.Split(chart, "\n") {
		if line != "" {
			out.WriteString(fmt.Sprintf("│  %-58s│\n", line))
		}
	}

	out.WriteString("│                                                            │\n")

	// Severity trends
	out.WriteString("│  By Severity:                                            │\n")

	severities := []findings.Severity{
		findings.SeverityCritical,
		findings.SeverityHigh,
		findings.SeverityMedium,
		findings.SeverityLow,
	}

	for _, sev := range severities {
		if tr, exists := trend.Summary.SeverityTrends[sev]; exists {
			icon := getSeverityIcon(sev)
			arrow := getTrendArrow(tr.Direction)
			out.WriteString(fmt.Sprintf("│  %s %-10s: %d → %d (%s%.0f%%)%s│\n",
				icon,
				sev,
				tr.StartCount,
				tr.EndCount,
				arrow,
				tr.PercentChange,
				strings.Repeat(" ", max(0, 35-len(fmt.Sprintf("%d → %d (%.0f%%)", tr.StartCount, tr.EndCount, tr.PercentChange)))),
			))
		}
	}

	out.WriteString("│                                                            │\n")

	// Top issues
	if len(trend.Summary.TopIssues) > 0 {
		out.WriteString("│  Top Issues:                                             │\n")
		for i, issue := range trend.Summary.TopIssues {
			if i < 3 { // Show top 3
				out.WriteString(fmt.Sprintf("│  %d. %-54s │\n", i+1, truncateString(issue, 54)))
			}
		}
		out.WriteString("│                                                            │\n")
	}

	out.WriteString("└────────────────────────────────────────────────────────────┘\n")

	return out.String()
}

// FormatBaselineList formats a list of baselines.
func FormatBaselineList(baselines []Baseline) string {
	if len(baselines) == 0 {
		return "No baselines set"
	}

	var out strings.Builder
	out.WriteString("Baselines:\n\n")

	w := tabwriter.NewWriter(&out, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "Target\tScan ID\tSet At\tFindings\n")
	fmt.Fprintf(w, "------\t-------\t------\t--------\n")

	for _, b := range baselines {
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\n",
			truncateString(b.Target, 40),
			b.ScanID[:8], // Short ID
			b.SetAt.Format("2006-01-02 15:04"),
			b.Findings,
		)
	}

	w.Flush()
	return out.String()
}

// FormatJSON exports comparison result as JSON.
func FormatJSON(result *ComparisonResult) (string, error) {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// Helper functions

func getSeverityIcon(sev findings.Severity) string {
	icons := map[findings.Severity]string{
		findings.SeverityCritical: "🔴",
		findings.SeverityHigh:     "🟠",
		findings.SeverityMedium:   "🟡",
		findings.SeverityLow:      "🟢",
		findings.SeverityInfo:     "🔵",
	}
	if icon, ok := icons[sev]; ok {
		return icon
	}
	return "⚪"
}

func getTrendArrow(direction string) string {
	arrows := map[string]string{
		"up":     "↑",
		"down":   "↓",
		"stable": "→",
	}
	if arrow, ok := arrows[direction]; ok {
		return arrow
	}
	return "→"
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen < 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
