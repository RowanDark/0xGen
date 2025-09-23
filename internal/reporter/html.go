package reporter

import (
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/RowanDark/Glyph/internal/findings"
)

var severityClass = map[findings.Severity]string{
	findings.SeverityCritical: "severity-critical",
	findings.SeverityHigh:     "severity-high",
	findings.SeverityMedium:   "severity-medium",
	findings.SeverityLow:      "severity-low",
	findings.SeverityInfo:     "severity-info",
}

const htmlStyles = `body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 32px; color: #1f2933; background-color: #ffffff; }
h1 { margin-bottom: 0.25rem; }
.meta { color: #52606d; margin: 0.25rem 0; }
.section { margin-top: 2rem; }
table { border-collapse: collapse; width: 100%; margin-top: 0.75rem; }
th, td { border: 1px solid #d2d6dc; padding: 0.5rem; text-align: left; vertical-align: top; }
th.numeric, td.numeric { text-align: right; }
ol { margin-top: 0.75rem; padding-left: 1.5rem; }
.severity-band { display: inline-block; padding: 0.25rem 0.5rem; border-radius: 9999px; font-weight: 600; }
.severity-critical { background-color: #b71c1c; color: #ffffff; }
.severity-high { background-color: #e65100; color: #ffffff; }
.severity-medium { background-color: #f9a825; color: #1f2933; }
.severity-low { background-color: #1e88e5; color: #ffffff; }
.severity-info { background-color: #546e7a; color: #ffffff; }
`

// RenderHTML converts a slice of findings into an HTML report.
func RenderHTML(list []findings.Finding, opts ReportOptions) string {
	summary := buildSummary(list, opts)

	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n")
	b.WriteString("<html lang=\"en\">\n")
	b.WriteString("<head>\n")
	b.WriteString("  <meta charset=\"utf-8\">\n")
	b.WriteString("  <title>Glyph Findings Report</title>\n")
	fmt.Fprintf(&b, "  <style>%s</style>\n", htmlStyles)
	b.WriteString("</head>\n")
	b.WriteString("<body>\n")
	b.WriteString("  <h1>Findings Report</h1>\n")
	fmt.Fprintf(&b, "  <p class=\"meta\">Generated at %s (UTC)</p>\n", summary.GeneratedAt.Format(time.RFC3339))
	if summary.WindowStart != nil {
		fmt.Fprintf(&b, "  <p class=\"meta\">Reporting window: %s — %s (UTC)</p>\n", summary.WindowStart.Format(time.RFC3339), summary.WindowEnd.Format(time.RFC3339))
	} else {
		fmt.Fprintf(&b, "  <p class=\"meta\">Reporting window: All findings through %s (UTC)</p>\n", summary.WindowEnd.Format(time.RFC3339))
	}
	fmt.Fprintf(&b, "  <p class=\"meta\">Total findings: %d</p>\n", summary.Total)

	b.WriteString("  <section class=\"section\">\n")
	b.WriteString("    <h2>Totals by Severity</h2>\n")
	b.WriteString("    <table>\n")
	b.WriteString("      <thead>\n")
	b.WriteString("        <tr><th scope=\"col\">Severity</th><th scope=\"col\" class=\"numeric\">Count</th></tr>\n")
	b.WriteString("      </thead>\n")
	b.WriteString("      <tbody>\n")
	for _, entry := range severityOrder {
		class := severityClass[entry.key]
		if class == "" {
			class = severityClass[findings.SeverityInfo]
		}
		fmt.Fprintf(&b, "        <tr><td><span class=\"severity-band %s\">%s</span></td><td class=\"numeric\">%d</td></tr>\n", class, entry.label, summary.SeverityCount[entry.key])
	}
	b.WriteString("      </tbody>\n")
	b.WriteString("    </table>\n")
	b.WriteString("  </section>\n")

	b.WriteString("  <section class=\"section\">\n")
	b.WriteString("    <h2>Findings by Plugin (top 5)</h2>\n")
	if len(summary.Plugins) == 0 {
		b.WriteString("    <p>No plugins reported.</p>\n")
	} else {
		fmt.Fprintf(&b, "    <p>Showing top %d plugins by finding volume.</p>\n", len(summary.Plugins))
		b.WriteString("    <table>\n")
		b.WriteString("      <thead>\n")
		b.WriteString("        <tr><th scope=\"col\">Plugin</th><th scope=\"col\" class=\"numeric\">Findings</th></tr>\n")
		b.WriteString("      </thead>\n")
		b.WriteString("      <tbody>\n")
		for _, entry := range summary.Plugins {
			fmt.Fprintf(&b, "        <tr><td>%s</td><td class=\"numeric\">%d</td></tr>\n", html.EscapeString(entry.Plugin), entry.Count)
		}
		b.WriteString("      </tbody>\n")
		b.WriteString("    </table>\n")
	}
	b.WriteString("  </section>\n")

	b.WriteString("  <section class=\"section\">\n")
	b.WriteString("    <h2>Top 10 Targets</h2>\n")
	if len(summary.Targets) == 0 {
		b.WriteString("    <p>No targets reported.</p>\n")
	} else {
		fmt.Fprintf(&b, "    <p>Showing top %d targets by finding volume.</p>\n", len(summary.Targets))
		b.WriteString("    <ol>\n")
		for _, entry := range summary.Targets {
			fmt.Fprintf(&b, "      <li><strong>%s</strong> — %d findings</li>\n", html.EscapeString(entry.Target), entry.Count)
		}
		b.WriteString("    </ol>\n")
	}
	b.WriteString("  </section>\n")

	b.WriteString("  <section class=\"section\">\n")
	fmt.Fprintf(&b, "    <h2>Last %d Findings</h2>\n", defaultRecentFindings)
	if summary.Total == 0 {
		b.WriteString("    <p>No findings recorded.</p>\n")
	} else {
		b.WriteString("    <table>\n")
		b.WriteString("      <thead>\n")
		b.WriteString("        <tr><th scope=\"col\">Plugin</th><th scope=\"col\">Target</th><th scope=\"col\">Evidence</th><th scope=\"col\">Detected At</th></tr>\n")
		b.WriteString("      </thead>\n")
		b.WriteString("      <tbody>\n")
		for _, f := range summary.Recent {
			plugin := strings.TrimSpace(f.Plugin)
			if plugin == "" {
				plugin = "(not specified)"
			}
			target := strings.TrimSpace(f.Target)
			if target == "" {
				target = "(not specified)"
			}
			evidence := findingExcerpt(f)
			ts := f.DetectedAt.Time().UTC().Format(time.RFC3339)
			fmt.Fprintf(&b, "        <tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n", html.EscapeString(plugin), html.EscapeString(target), html.EscapeString(evidence), html.EscapeString(ts))
		}
		b.WriteString("      </tbody>\n")
		b.WriteString("    </table>\n")
	}
	b.WriteString("  </section>\n")

	b.WriteString("</body>\n")
	b.WriteString("</html>\n")
	return b.String()
}
