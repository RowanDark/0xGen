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
	formatRaw := fs.String("format", string(reporter.FormatMarkdown), "report format (md, html, json, csv, xml)")
	sinceRaw := fs.String("since", "", "only include findings detected on or after this RFC-3339 timestamp or duration (e.g. 24h)")
	sbomPath := fs.String("sbom", "", "path to an SBOM file included in the JSON bundle metadata")
	signingKey := fs.String("sign", "", "path to a cosign-compatible private key used to sign JSON output")

	// Integration options
	slackWebhook := fs.String("slack-webhook", "", "send report summary to Slack webhook URL")
	webhookURL := fs.String("webhook", "", "send report to generic webhook URL")
	webhookHeaders := fs.String("webhook-headers", "", "custom headers for webhook (format: 'Key1:Value1,Key2:Value2')")
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

	validFormats := map[reporter.ReportFormat]bool{
		reporter.FormatMarkdown: true,
		reporter.FormatHTML:     true,
		reporter.FormatJSON:     true,
		reporter.FormatCSV:      true,
		reporter.FormatXML:      true,
	}

	if !validFormats[format] {
		fmt.Fprintf(os.Stderr, "invalid --format value %q (expected md, html, json, csv, or xml)\n", *formatRaw)
		return 2
	}

	outputPath := strings.TrimSpace(*output)
	if outputPath == "" {
		switch format {
		case reporter.FormatHTML:
			outputPath = reporter.DefaultHTMLReportPath
		case reporter.FormatJSON:
			outputPath = reporter.DefaultJSONReportPath
		case reporter.FormatCSV:
			outputPath = "/out/0xgen_report.csv"
		case reporter.FormatXML:
			outputPath = "/out/0xgen_report.xml"
		default:
			outputPath = reporter.DefaultReportPath
		}
	}

	keyPath := strings.TrimSpace(*signingKey)
	if keyPath != "" && format == reporter.FormatMarkdown {
		fmt.Fprintln(os.Stderr, "--sign is not supported for markdown reports")
		return 2
	}

	if err := reporter.RenderReport(*input, outputPath, format, opts); err != nil {
		fmt.Fprintf(os.Stderr, "generate report: %v\n", err)
		return 1
	}

	fmt.Fprintf(os.Stdout, "Report written to: %s\n", outputPath)

	if keyPath != "" {
		signaturePath, err := reporter.SignArtifact(outputPath, keyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sign report: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stdout, "Signature written to %s\n", signaturePath)
	}

	// Handle integrations
	if *slackWebhook != "" || *webhookURL != "" {
		// Load findings for integration
		findings, err := reporter.ReadJSONL(*input)
		if err != nil {
			fmt.Fprintf(os.Stderr, "load findings for integration: %v\n", err)
			return 1
		}

		// Send to Slack
		if *slackWebhook != "" {
			fmt.Println("Sending to Slack...")
			if err := reporter.SendToSlack(*slackWebhook, findings, opts); err != nil {
				fmt.Fprintf(os.Stderr, "send to Slack: %v\n", err)
				return 1
			}
			fmt.Println("✓ Sent to Slack")
		}

		// Send to webhook
		if *webhookURL != "" {
			fmt.Println("Sending to webhook...")

			// Parse custom headers
			headers := make(map[string]string)
			if *webhookHeaders != "" {
				pairs := strings.Split(*webhookHeaders, ",")
				for _, pair := range pairs {
					parts := strings.SplitN(pair, ":", 2)
					if len(parts) == 2 {
						headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
					}
				}
			}

			if err := reporter.SendToWebhook(*webhookURL, findings, opts, headers); err != nil {
				fmt.Fprintf(os.Stderr, "send to webhook: %v\n", err)
				return 1
			}
			fmt.Println("✓ Sent to webhook")
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
