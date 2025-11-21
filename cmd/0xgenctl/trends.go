package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/RowanDark/0xgen/internal/comparison"
)

func runTrends(args []string) int {
	fs := flag.NewFlagSet("trends", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	target := fs.String("target", "", "target to analyze trends for")
	period := fs.String("period", "30d", "time period (e.g., 7d, 30d, 90d)")
	scansDir := fs.String("scans-dir", "", "directory containing scan files")
	output := fs.String("output", "table", "output format: table, json")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	// Parse period
	dur, err := parsePeriod(*period)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing period: %v\n", err)
		return 2
	}

	// Load scans
	var scans []comparison.ScanWithFindings

	if *scansDir != "" {
		// Load from directory
		scans, err = loadScansFromDirectory(*scansDir, *target, dur)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading scans: %v\n", err)
			return 1
		}
	} else {
		fmt.Fprintln(os.Stderr, "Error: --scans-dir is required")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  0xgenctl trends --target example.com --period 30d --scans-dir /path/to/scans")
		return 2
	}

	if len(scans) == 0 {
		fmt.Fprintf(os.Stderr, "No scans found for target %q in the last %s\n", *target, *period)
		return 0
	}

	// Analyze trends
	targetName := *target
	if targetName == "" {
		targetName = scans[0].Summary.Target
	}

	trend, err := comparison.AnalyzeTrends(scans, targetName, *period)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error analyzing trends: %v\n", err)
		return 1
	}

	// Output results
	switch *output {
	case "json":
		// TODO: Implement JSON output
		fmt.Fprintln(os.Stderr, "JSON output not yet implemented for trends")
		return 1
	case "table":
		fallthrough
	default:
		fmt.Print(comparison.FormatTrends(trend))
	}

	return 0
}

// loadScansFromDirectory loads all scan files from a directory.
func loadScansFromDirectory(dir string, targetFilter string, period time.Duration) ([]comparison.ScanWithFindings, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read directory: %w", err)
	}

	var scans []comparison.ScanWithFindings
	cutoff := time.Now().UTC().Add(-period)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// Only process .jsonl and .json files
		if !strings.HasSuffix(entry.Name(), ".jsonl") && !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		path := filepath.Join(dir, entry.Name())

		summary, findingsList, err := loadFindings(path)
		if err != nil {
			continue // Skip invalid files
		}

		// Apply target filter
		if targetFilter != "" && summary.Target != targetFilter {
			continue
		}

		// Apply time filter
		if summary.Timestamp.Time().Before(cutoff) {
			continue
		}

		scans = append(scans, comparison.ScanWithFindings{
			Summary:  summary,
			Findings: findingsList,
		})
	}

	// Sort by timestamp
	sort.Slice(scans, func(i, j int) bool {
		return scans[i].Summary.Timestamp.Time().Before(scans[j].Summary.Timestamp.Time())
	})

	return scans, nil
}

// parsePeriod converts a period string to a duration.
func parsePeriod(period string) (time.Duration, error) {
	// Handle common formats like "30d", "7d", "90d"
	if strings.HasSuffix(period, "d") {
		days := strings.TrimSuffix(period, "d")
		var numDays int
		if _, err := fmt.Sscanf(days, "%d", &numDays); err != nil {
			return 0, fmt.Errorf("invalid period format: %s", period)
		}
		return time.Duration(numDays) * 24 * time.Hour, nil
	}

	// Try to parse as Go duration
	return time.ParseDuration(period)
}
