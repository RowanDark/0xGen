package reporter

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"

	"github.com/RowanDark/0xgen/internal/findings"
)

// RenderCSV generates a CSV export of findings.
func RenderCSV(list []findings.Finding, opts ReportOptions) ([]byte, error) {
	summary, filteredList, _, _ := buildSummary(list, opts)

	var buf strings.Builder
	writer := csv.NewWriter(&buf)

	// Write header
	header := []string{
		"ID",
		"Severity",
		"Type",
		"Message",
		"Target",
		"Plugin",
		"Evidence",
		"Detected At",
	}
	if err := writer.Write(header); err != nil {
		return nil, fmt.Errorf("write CSV header: %w", err)
	}

	// Write findings
	for _, f := range filteredList {
		row := []string{
			f.ID,
			string(f.Severity),
			f.Type,
			f.Message,
			f.Target,
			f.Plugin,
			strings.ReplaceAll(f.Evidence, "\n", " "),
			f.DetectedAt.Time().Format("2006-01-02 15:04:05"),
		}
		if err := writer.Write(row); err != nil {
			return nil, fmt.Errorf("write CSV row: %w", err)
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, fmt.Errorf("flush CSV: %w", err)
	}

	// Add summary metadata as comments at the end
	summaryLines := []string{
		"",
		"# Summary",
		fmt.Sprintf("# Total Findings: %d", summary.Total),
		fmt.Sprintf("# Critical: %d", summary.SeverityCount[findings.SeverityCritical]),
		fmt.Sprintf("# High: %d", summary.SeverityCount[findings.SeverityHigh]),
		fmt.Sprintf("# Medium: %d", summary.SeverityCount[findings.SeverityMedium]),
		fmt.Sprintf("# Low: %d", summary.SeverityCount[findings.SeverityLow]),
		fmt.Sprintf("# Info: %d", summary.SeverityCount[findings.SeverityInfo]),
		fmt.Sprintf("# Generated: %s", summary.GeneratedAt.Format("2006-01-02 15:04:05")),
	}

	for _, line := range summaryLines {
		buf.WriteString(line)
		buf.WriteString("\n")
	}

	return []byte(buf.String()), nil
}

// WriteCSV writes CSV output to a writer.
func WriteCSV(w io.Writer, list []findings.Finding, opts ReportOptions) error {
	data, err := RenderCSV(list, opts)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}
