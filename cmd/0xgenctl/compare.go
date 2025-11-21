package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/RowanDark/0xgen/internal/comparison"
	"github.com/RowanDark/0xgen/internal/findings"
)

func runCompare(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "compare subcommand required")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  0xgenctl compare scans    - Compare two scans")
		fmt.Fprintln(os.Stderr, "  0xgenctl compare baseline - Compare scan against baseline")
		return 2
	}

	switch args[0] {
	case "scans":
		return runCompareScans(args[1:])
	case "baseline":
		return runCompareBaseline(args[1:])
	default:
		// Default to comparing scans
		return runCompareScans(args)
	}
}

func runCompareScans(args []string) int {
	fs := flag.NewFlagSet("compare scans", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	scanA := fs.String("scan-a", "", "first scan (findings file or scan ID)")
	scanB := fs.String("scan-b", "", "second scan (findings file or scan ID)")
	output := fs.String("output", "table", "output format: table, json")
	failOnNew := fs.Bool("fail-on-new", false, "exit with code 1 if new vulnerabilities found")
	failOnCritical := fs.Bool("fail-on-critical", false, "exit with code 1 if new critical vulnerabilities found")
	ignoreEvidence := fs.Bool("ignore-evidence", false, "ignore evidence when comparing findings")
	severityFilter := fs.String("severity", "info", "minimum severity to include: info, low, med, high, crit")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *scanA == "" || *scanB == "" {
		fmt.Fprintln(os.Stderr, "Error: both --scan-a and --scan-b are required")
		return 2
	}

	// Parse severity filter
	var sevFilter findings.Severity
	switch *severityFilter {
	case "info":
		sevFilter = findings.SeverityInfo
	case "low":
		sevFilter = findings.SeverityLow
	case "med", "medium":
		sevFilter = findings.SeverityMedium
	case "high":
		sevFilter = findings.SeverityHigh
	case "crit", "critical":
		sevFilter = findings.SeverityCritical
	default:
		fmt.Fprintf(os.Stderr, "Error: invalid severity %q\n", *severityFilter)
		return 2
	}

	// Configure comparison options
	opts := comparison.CompareOptions{
		IgnoreEvidence:    *ignoreEvidence,
		IgnoreTimestamps:  true,
		SeverityThreshold: sevFilter,
		MatchByType:       true,
	}

	// Load findings
	summaryA, findingsA, err := loadFindings(*scanA)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading scan A: %v\n", err)
		return 1
	}

	summaryB, findingsB, err := loadFindings(*scanB)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading scan B: %v\n", err)
		return 1
	}

	// Perform comparison
	result, err := comparison.Compare(summaryA, summaryB, findingsA, findingsB, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error comparing scans: %v\n", err)
		return 1
	}

	// Output results
	switch *output {
	case "json":
		jsonOutput, err := comparison.FormatJSON(result)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error formatting JSON: %v\n", err)
			return 1
		}
		fmt.Println(jsonOutput)
	case "table":
		fallthrough
	default:
		fmt.Print(comparison.FormatComparison(result))
	}

	// Check fail conditions
	if *failOnCritical && result.HasNewCritical() {
		fmt.Fprintln(os.Stderr, "\n⚠️  New critical vulnerabilities detected")
		return 1
	}

	if *failOnNew && result.HasNew() {
		fmt.Fprintln(os.Stderr, "\n⚠️  New vulnerabilities detected")
		return 1
	}

	return 0
}

func runCompareBaseline(args []string) int {
	fs := flag.NewFlagSet("compare baseline", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	scan := fs.String("scan", "", "scan to compare (findings file or scan ID)")
	target := fs.String("target", "", "target for baseline lookup")
	output := fs.String("output", "table", "output format: table, json")
	failOnNew := fs.Bool("fail-on-new", false, "exit with code 1 if new vulnerabilities found")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *scan == "" {
		fmt.Fprintln(os.Stderr, "Error: --scan is required")
		return 2
	}

	// Load baseline manager
	mgr, err := comparison.NewBaselineManager()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing baseline manager: %v\n", err)
		return 1
	}

	// Load current scan
	currentSummary, currentFindings, err := loadFindings(*scan)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading scan: %v\n", err)
		return 1
	}

	// Determine target for baseline lookup
	baselineTarget := *target
	if baselineTarget == "" {
		baselineTarget = currentSummary.Target
	}

	// Get baseline
	baseline, err := mgr.GetBaseline(baselineTarget)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		fmt.Fprintf(os.Stderr, "\nTip: Set a baseline first using:\n")
		fmt.Fprintf(os.Stderr, "  0xgenctl baseline set --scan %s --target %s\n", *scan, baselineTarget)
		return 1
	}

	// Load baseline scan
	baselineSummary, baselineFindings, err := loadFindings(baseline.ScanID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading baseline scan: %v\n", err)
		return 1
	}

	// Perform comparison
	opts := comparison.DefaultCompareOptions()
	result, err := comparison.Compare(baselineSummary, currentSummary, baselineFindings, currentFindings, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error comparing scans: %v\n", err)
		return 1
	}

	// Output results
	switch *output {
	case "json":
		jsonOutput, err := comparison.FormatJSON(result)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error formatting JSON: %v\n", err)
			return 1
		}
		fmt.Println(jsonOutput)
	default:
		fmt.Print(comparison.FormatComparison(result))
	}

	// Check fail conditions
	if *failOnNew && result.HasNew() {
		fmt.Fprintln(os.Stderr, "\n⚠️  New vulnerabilities detected compared to baseline")
		return 1
	}

	return 0
}

// loadFindings loads findings from a file or scan ID.
// For now, this is a simplified implementation that works with JSONL files.
func loadFindings(path string) (comparison.ScanSummary, []findings.Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return comparison.ScanSummary{}, nil, fmt.Errorf("read file: %w", err)
	}

	// Try to parse as JSONL (one finding per line)
	lines := splitLines(string(data))
	var findingsList []findings.Finding

	for _, line := range lines {
		if line == "" {
			continue
		}

		var f findings.Finding
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			// Try to parse as JSON array
			var findingsArray []findings.Finding
			if err2 := json.Unmarshal([]byte(line), &findingsArray); err2 == nil {
				findingsList = append(findingsList, findingsArray...)
				continue
			}
			// Skip invalid lines
			continue
		}

		findingsList = append(findingsList, f)
	}

	// Create summary
	summary := comparison.ScanSummary{
		ID:            path, // Use path as ID for now
		Name:          path,
		Target:        extractTarget(findingsList),
		Timestamp:     extractTimestamp(findingsList),
		TotalFindings: len(findingsList),
	}

	return summary, findingsList, nil
}

func splitLines(s string) []string {
	var lines []string
	current := ""
	for _, r := range s {
		if r == '\n' {
			lines = append(lines, current)
			current = ""
		} else {
			current += string(r)
		}
	}
	if current != "" {
		lines = append(lines, current)
	}
	return lines
}

func extractTarget(findingsList []findings.Finding) string {
	if len(findingsList) > 0 {
		return findingsList[0].Target
	}
	return "unknown"
}

func extractTimestamp(findingsList []findings.Finding) findings.Timestamp {
	if len(findingsList) > 0 {
		return findingsList[0].DetectedAt
	}
	return findings.Timestamp{}
}
