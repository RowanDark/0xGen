package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/RowanDark/Glyph/internal/reporter"
)

func runReport(args []string) int {
	return runReportAt(args, time.Now().UTC())
}

func runReportAt(args []string, now time.Time) int {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	input := fs.String("input", reporter.DefaultFindingsPath, "path to findings JSONL input")
	output := fs.String("out", reporter.DefaultReportPath, "path to write the markdown report")
	sinceRaw := fs.String("since", "", "only include findings detected on or after this RFC-3339 timestamp or duration (e.g. 24h)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *input == "" || *output == "" {
		fmt.Fprintln(os.Stderr, "--input and --out must be provided")
		return 2
	}

	opts := reporter.ReportOptions{Now: now}
	if trimmed := strings.TrimSpace(*sinceRaw); trimmed != "" {
		since, err := parseSince(trimmed, now)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid --since value: %v\n", err)
			return 2
		}
		opts.Since = &since
	}

	if err := reporter.RenderReport(*input, *output, opts); err != nil {
		fmt.Fprintf(os.Stderr, "generate report: %v\n", err)
		return 1
	}

	return 0
}

func parseSince(input string, now time.Time) (time.Time, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if d, err := time.ParseDuration(input); err == nil {
		if d < 0 {
			return time.Time{}, fmt.Errorf("duration must be positive")
		}
		return now.Add(-d), nil
	}
	if ts, err := time.Parse(time.RFC3339, input); err == nil {
		return ts.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("expected duration (e.g. 24h) or RFC-3339 timestamp")
}
