package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/RowanDark/0xgen/internal/reporter"
)

func runReport(args []string) int {
	return runReportAt(args, time.Now().UTC())
}

func runReportAt(args []string, now time.Time) int {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	input := fs.String("input", reporter.DefaultFindingsPath, "path to findings JSONL input")
	output := fs.String("out", "", "path to write the report")
	formatRaw := fs.String("format", string(reporter.FormatMarkdown), "report format (md, html, or json)")
	sinceRaw := fs.String("since", "", "only include findings detected on or after this RFC-3339 timestamp or duration (e.g. 24h)")
	sbomPath := fs.String("sbom", "", "path to an SBOM file included in the JSON bundle metadata")
	signingKey := fs.String("sign", "", "path to a cosign-compatible private key used to sign JSON output")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *input == "" {
		fmt.Fprintln(os.Stderr, "--input must be provided")
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
	opts.SBOMPath = strings.TrimSpace(*sbomPath)

	format := reporter.ReportFormat(strings.ToLower(strings.TrimSpace(*formatRaw)))
	if format == "" {
		format = reporter.FormatMarkdown
	}
	if format != reporter.FormatMarkdown && format != reporter.FormatHTML && format != reporter.FormatJSON {
		fmt.Fprintf(os.Stderr, "invalid --format value %q (expected md, html, or json)\n", *formatRaw)
		return 2
	}

	if strings.TrimSpace(*signingKey) != "" && format != reporter.FormatJSON {
		fmt.Fprintln(os.Stderr, "--sign is only supported for --format json")
		return 2
	}

	outputPath := strings.TrimSpace(*output)
	if outputPath == "" {
		switch format {
		case reporter.FormatHTML:
			outputPath = reporter.DefaultHTMLReportPath
		case reporter.FormatJSON:
			outputPath = reporter.DefaultJSONReportPath
		default:
			outputPath = reporter.DefaultReportPath
		}
	}

	if err := reporter.RenderReport(*input, outputPath, format, opts); err != nil {
		fmt.Fprintf(os.Stderr, "generate report: %v\n", err)
		return 1
	}

	if format == reporter.FormatJSON {
		keyPath := strings.TrimSpace(*signingKey)
		if keyPath != "" {
			signaturePath, err := reporter.SignArtifact(outputPath, keyPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "sign JSON report: %v\n", err)
				return 1
			}
			fmt.Fprintf(os.Stdout, "Signature written to %s\n", signaturePath)
		}
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
