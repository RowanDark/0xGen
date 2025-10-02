package reporter

import (
	"fmt"
	"html"
	"sort"
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

var severityPriority = map[findings.Severity]int{
	findings.SeverityCritical: 0,
	findings.SeverityHigh:     1,
	findings.SeverityMedium:   2,
	findings.SeverityLow:      3,
	findings.SeverityInfo:     4,
}

const htmlStyles = `:root {
 color-scheme: light dark;
 --bg-color: #f8fafc;
 --surface-color: #ffffff;
 --surface-muted: #f1f5f9;
 --border-color: #d8dee9;
 --text-color: #0f172a;
 --muted-color: #64748b;
 --accent-color: #2563eb;
 --accent-contrast: #ffffff;
 --severity-critical-bg: #b91c1c;
 --severity-critical-text: #ffffff;
 --severity-high-bg: #c2410c;
 --severity-high-text: #ffffff;
 --severity-medium-bg: #ca8a04;
 --severity-medium-text: #1f2937;
 --severity-low-bg: #1d4ed8;
 --severity-low-text: #ffffff;
 --severity-info-bg: #475569;
 --severity-info-text: #ffffff;
 --scope-in-bg: #0f766e;
 --scope-in-text: #ecfdf5;
 --scope-out-bg: #b91c1c;
 --scope-out-text: #fef2f2;
 --scope-neutral-bg: #475569;
 --scope-neutral-text: #f8fafc;
}

@media (prefers-color-scheme: dark) {
 :root {
  --bg-color: #0f172a;
  --surface-color: #111827;
  --surface-muted: #1e293b;
  --border-color: #1f2937;
  --text-color: #e2e8f0;
  --muted-color: #94a3b8;
  --accent-color: #38bdf8;
  --accent-contrast: #0f172a;
  --severity-critical-bg: #f87171;
  --severity-critical-text: #0f172a;
  --severity-high-bg: #fb923c;
  --severity-high-text: #0f172a;
  --severity-medium-bg: #facc15;
  --severity-medium-text: #0f172a;
  --severity-low-bg: #38bdf8;
  --severity-low-text: #0f172a;
  --severity-info-bg: #64748b;
  --severity-info-text: #0f172a;
  --scope-in-bg: #14b8a6;
  --scope-in-text: #022c22;
  --scope-out-bg: #ef4444;
  --scope-out-text: #450a0a;
  --scope-neutral-bg: #94a3b8;
  --scope-neutral-text: #0f172a;
 }
}

* { box-sizing: border-box; }
body {
 margin: 0;
 padding: 32px;
 font-family: "Inter", "Segoe UI", system-ui, -apple-system, sans-serif;
 background-color: var(--bg-color);
 color: var(--text-color);
 line-height: 1.6;
}

h1, h2, h3 { color: var(--text-color); margin-top: 0; }
p { margin: 0; }
a { color: inherit; }

.header {
 display: flex;
 justify-content: space-between;
 align-items: flex-start;
 gap: 24px;
 flex-wrap: wrap;
 margin-bottom: 32px;
}

.meta { color: var(--muted-color); margin-top: 4px; }

.header-actions { display: flex; gap: 12px; align-items: center; }
.docs-link {
 display: inline-flex;
 align-items: center;
 gap: 8px;
 background: var(--accent-color);
 color: var(--accent-contrast);
 padding: 10px 16px;
 border-radius: 9999px;
 text-decoration: none;
 font-weight: 600;
 box-shadow: 0 2px 8px rgba(37, 99, 235, 0.35);
 transition: transform 0.2s ease, box-shadow 0.2s ease;
}
.docs-link:hover { transform: translateY(-1px); box-shadow: 0 6px 16px rgba(37, 99, 235, 0.35); }

.section { margin-bottom: 40px; }

.stat-grid {
 display: grid;
 grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
 gap: 16px;
 margin-bottom: 24px;
}

.stat-card {
 background: var(--surface-color);
 border: 1px solid var(--border-color);
 border-radius: 16px;
 padding: 20px;
 box-shadow: 0 12px 30px rgba(15, 23, 42, 0.08);
}

.stat-card .label { display: block; color: var(--muted-color); font-size: 0.9rem; margin-bottom: 8px; }
.stat-card .value { font-size: 1.8rem; font-weight: 700; }

.panel-grid {
 display: grid;
 grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
 gap: 20px;
}

.panel {
 background: var(--surface-color);
 border: 1px solid var(--border-color);
 border-radius: 18px;
 padding: 20px;
 box-shadow: 0 12px 30px rgba(15, 23, 42, 0.08);
}

.panel table { width: 100%; border-collapse: collapse; }
.panel th, .panel td { padding: 8px 12px; border-bottom: 1px solid var(--border-color); text-align: left; }
.panel th.numeric, .panel td.numeric { text-align: right; }
.panel tbody tr:last-child td { border-bottom: none; }

.recent-table {
 width: 100%;
 border-collapse: collapse;
 margin-top: 16px;
 background: var(--surface-color);
 border: 1px solid var(--border-color);
 border-radius: 16px;
 overflow: hidden;
 box-shadow: 0 12px 30px rgba(15, 23, 42, 0.08);
}

.recent-table th, .recent-table td { padding: 12px 16px; border-bottom: 1px solid var(--border-color); text-align: left; vertical-align: top; }
.recent-table tr:last-child td { border-bottom: none; }
.recent-table tbody tr:nth-child(even) { background: var(--surface-muted); }

.case-list { display: flex; flex-direction: column; gap: 16px; }

.case {
 background: var(--surface-color);
 border: 1px solid var(--border-color);
 border-radius: 18px;
 box-shadow: 0 12px 30px rgba(15, 23, 42, 0.08);
 overflow: hidden;
}

.case summary {
 list-style: none;
 padding: 18px 22px;
 display: grid;
 grid-template-columns: auto 1fr auto;
 gap: 12px;
 align-items: center;
 cursor: pointer;
}

.case summary::-webkit-details-marker { display: none; }

.case summary .case-title { font-weight: 600; font-size: 1.05rem; }
.case summary .case-target { color: var(--muted-color); font-size: 0.9rem; }
.case summary .case-meta { text-align: right; font-size: 0.85rem; color: var(--muted-color); }

.case[open] summary { background: var(--surface-muted); border-bottom: 1px solid var(--border-color); }

.case-body { padding: 22px; display: grid; gap: 20px; }

.case-meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; }
.case-meta-grid span { display: block; font-size: 0.85rem; color: var(--muted-color); }
.case-meta-grid strong { display: block; font-size: 0.95rem; color: var(--text-color); }

.case-evidence, .case-poc, .case-meta { background: var(--surface-muted); border-radius: 12px; padding: 16px; }

.case-evidence-header, .case-poc-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }

.copy-button {
 border: none;
 background: var(--accent-color);
 color: var(--accent-contrast);
 padding: 6px 12px;
 border-radius: 8px;
 cursor: pointer;
 font-size: 0.85rem;
 font-weight: 600;
 transition: opacity 0.2s ease;
}
.copy-button:hover { opacity: 0.85; }

pre {
 background: transparent;
 margin: 0;
 padding: 0;
 font-family: "JetBrains Mono", "Fira Code", Consolas, monospace;
 font-size: 0.85rem;
 overflow-x: auto;
 white-space: pre-wrap;
 word-break: break-word;
}

.thumbnail-grid {
 display: grid;
 grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
 gap: 12px;
}

.thumbnail-grid img {
 width: 100%;
 border-radius: 12px;
 border: 1px solid var(--border-color);
 box-shadow: 0 10px 24px rgba(15, 23, 42, 0.15);
}

.scope-badge {
 display: inline-flex;
 align-items: center;
 padding: 4px 10px;
 border-radius: 9999px;
 font-size: 0.75rem;
 font-weight: 600;
 letter-spacing: 0.02em;
 text-transform: uppercase;
}

.scope-in { background: var(--scope-in-bg); color: var(--scope-in-text); }
.scope-out { background: var(--scope-out-bg); color: var(--scope-out-text); }
.scope-neutral { background: var(--scope-neutral-bg); color: var(--scope-neutral-text); }

.severity-pill {
 display: inline-flex;
 align-items: center;
 justify-content: center;
 padding: 6px 12px;
 border-radius: 9999px;
 font-weight: 600;
 font-size: 0.85rem;
}

.severity-critical { background: var(--severity-critical-bg); color: var(--severity-critical-text); }
.severity-high { background: var(--severity-high-bg); color: var(--severity-high-text); }
.severity-medium { background: var(--severity-medium-bg); color: var(--severity-medium-text); }
.severity-low { background: var(--severity-low-bg); color: var(--severity-low-text); }
.severity-info { background: var(--severity-info-bg); color: var(--severity-info-text); }

.metadata-list { display: grid; gap: 12px; }
.metadata-entry { display: flex; flex-direction: column; gap: 4px; }
.metadata-entry span { color: var(--muted-color); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }
.metadata-entry strong { font-size: 0.95rem; word-break: break-word; }

.empty-state {
 padding: 24px;
 background: var(--surface-muted);
 border-radius: 16px;
 color: var(--muted-color);
 text-align: center;
}

@media (max-width: 720px) {
 body { padding: 20px; }
 .case summary { grid-template-columns: 1fr; text-align: left; }
 .case summary .case-meta { text-align: left; }
 .header { flex-direction: column; }
}
`

const htmlScript = `(function(){
  function resetLabel(button, original){
    setTimeout(function(){ button.textContent = original; }, 1800);
  }
  document.addEventListener('click', function(evt){
    var button = evt.target.closest('[data-copy-target]');
    if (!button) { return; }
    var target = document.querySelector(button.getAttribute('data-copy-target'));
    if (!target) { return; }
    var text = target.textContent || '';
    var original = button.textContent;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function(){
        button.textContent = 'Copied!';
        resetLabel(button, original);
      }).catch(function(){
        button.textContent = 'Copy failed';
        resetLabel(button, original);
      });
    } else {
      var textarea = document.createElement('textarea');
      textarea.value = text;
      textarea.style.position = 'fixed';
      textarea.style.opacity = '0';
      document.body.appendChild(textarea);
      textarea.focus();
      textarea.select();
      try {
        document.execCommand('copy');
        button.textContent = 'Copied!';
      } catch (err) {
        button.textContent = 'Copy failed';
      }
      document.body.removeChild(textarea);
      resetLabel(button, original);
    }
  });
})();`

// RenderHTML converts a slice of findings into an HTML report.
func RenderHTML(list []findings.Finding, opts ReportOptions) string {
	summary := buildSummary(list, opts)
	filteredList, _, _ := filterFindings(list, opts)
	cases := buildCases(filteredList)

	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n")
	b.WriteString("<html lang=\"en\">\n")
	b.WriteString("<head>\n")
	b.WriteString("  <meta charset=\"utf-8\">\n")
	b.WriteString("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
	b.WriteString("  <title>Glyph Findings Report</title>\n")
	fmt.Fprintf(&b, "  <style>%s</style>\n", htmlStyles)
	fmt.Fprintf(&b, "  <script>%s</script>\n", htmlScript)
	b.WriteString("</head>\n")
	b.WriteString("<body>\n")

	b.WriteString("  <header class=\"header\">\n")
	b.WriteString("    <div>\n")
	b.WriteString("      <h1>Glyph Findings Report</h1>\n")
	fmt.Fprintf(&b, "      <p class=\"meta\">Generated at %s (UTC)</p>\n", summary.GeneratedAt.Format(time.RFC3339))
	if summary.WindowStart != nil {
		fmt.Fprintf(&b, "      <p class=\"meta\">Reporting window: %s — %s (UTC)</p>\n", summary.WindowStart.Format(time.RFC3339), summary.WindowEnd.Format(time.RFC3339))
	} else {
		fmt.Fprintf(&b, "      <p class=\"meta\">Reporting window: All findings through %s (UTC)</p>\n", summary.WindowEnd.Format(time.RFC3339))
	}
	fmt.Fprintf(&b, "      <p class=\"meta\">Total findings: %d</p>\n", summary.Total)
	b.WriteString("    </div>\n")
	b.WriteString("    <div class=\"header-actions\">\n")
	b.WriteString("      <a class=\"docs-link\" href=\"https://rowandark.github.io/Glyph/\" target=\"_blank\" rel=\"noreferrer noopener\">\n")
	b.WriteString("        View Documentation\n")
	b.WriteString("      </a>\n")
	b.WriteString("    </div>\n")
	b.WriteString("  </header>\n")

	renderSummarySection(&b, summary)
	renderRecentSection(&b, summary)
	renderCasesSection(&b, cases)

	b.WriteString("</body>\n")
	b.WriteString("</html>\n")
	return b.String()
}

func renderSummarySection(b *strings.Builder, summary reportSummary) {
	b.WriteString("  <section class=\"section\">\n")
	b.WriteString("    <h2>At a glance</h2>\n")
	b.WriteString("    <div class=\"stat-grid\">\n")
	fmt.Fprintf(b, "      <div class=\"stat-card\"><span class=\"label\">Findings</span><span class=\"value\">%d</span></div>\n", summary.Total)
	fmt.Fprintf(b, "      <div class=\"stat-card\"><span class=\"label\">Critical / High</span><span class=\"value\">%d / %d</span></div>\n", summary.SeverityCount[findings.SeverityCritical], summary.SeverityCount[findings.SeverityHigh])
	fmt.Fprintf(b, "      <div class=\"stat-card\"><span class=\"label\">Medium</span><span class=\"value\">%d</span></div>\n", summary.SeverityCount[findings.SeverityMedium])
	fmt.Fprintf(b, "      <div class=\"stat-card\"><span class=\"label\">Low / Informational</span><span class=\"value\">%d / %d</span></div>\n", summary.SeverityCount[findings.SeverityLow], summary.SeverityCount[findings.SeverityInfo])
	b.WriteString("    </div>\n")

	b.WriteString("    <div class=\"panel-grid\">\n")
	b.WriteString("      <article class=\"panel\">\n")
	b.WriteString("        <h3>Totals by Severity</h3>\n")
	b.WriteString("        <table>\n")
	b.WriteString("          <thead><tr><th scope=\"col\">Severity</th><th scope=\"col\" class=\"numeric\">Count</th></tr></thead>\n")
	b.WriteString("          <tbody>\n")
	for _, entry := range severityOrder {
		class := severityClass[entry.key]
		if class == "" {
			class = severityClass[findings.SeverityInfo]
		}
		fmt.Fprintf(b, "            <tr><td><span class=\"severity-pill %s\">%s</span></td><td class=\"numeric\">%d</td></tr>\n", class, entry.label, summary.SeverityCount[entry.key])
	}
	b.WriteString("          </tbody>\n")
	b.WriteString("        </table>\n")
	b.WriteString("      </article>\n")

	b.WriteString("      <article class=\"panel\">\n")
	b.WriteString("        <h3>Findings by Plugin</h3>\n")
	if len(summary.Plugins) == 0 {
		b.WriteString("        <p class=\"meta\">No plugins reported.</p>\n")
	} else {
		b.WriteString("        <table>\n")
		b.WriteString("          <thead><tr><th scope=\"col\">Plugin</th><th scope=\"col\" class=\"numeric\">Findings</th></tr></thead>\n")
		b.WriteString("          <tbody>\n")
		for _, entry := range summary.Plugins {
			fmt.Fprintf(b, "            <tr><td>%s</td><td class=\"numeric\">%d</td></tr>\n", html.EscapeString(entry.Plugin), entry.Count)
		}
		b.WriteString("          </tbody>\n")
		b.WriteString("        </table>\n")
	}
	b.WriteString("      </article>\n")

	b.WriteString("      <article class=\"panel\">\n")
	b.WriteString("        <h3>Top Targets</h3>\n")
	if len(summary.Targets) == 0 {
		b.WriteString("        <p class=\"meta\">No targets reported.</p>\n")
	} else {
		b.WriteString("        <table>\n")
		b.WriteString("          <thead><tr><th scope=\"col\">Target</th><th scope=\"col\" class=\"numeric\">Findings</th></tr></thead>\n")
		b.WriteString("          <tbody>\n")
		for _, entry := range summary.Targets {
			fmt.Fprintf(b, "            <tr><td>%s</td><td class=\"numeric\">%d</td></tr>\n", html.EscapeString(entry.Target), entry.Count)
		}
		b.WriteString("          </tbody>\n")
		b.WriteString("        </table>\n")
	}
	b.WriteString("      </article>\n")
	b.WriteString("    </div>\n")
	b.WriteString("  </section>\n")
}

func renderRecentSection(b *strings.Builder, summary reportSummary) {
	b.WriteString("  <section class=\"section\">\n")
	fmt.Fprintf(b, "    <h2>Last %d Findings</h2>\n", defaultRecentFindings)
	if summary.Total == 0 {
		b.WriteString("    <div class=\"empty-state\">No findings recorded.</div>\n")
		b.WriteString("  </section>\n")
		return
	}

	b.WriteString("    <table class=\"recent-table\">\n")
	b.WriteString("      <thead><tr><th scope=\"col\">Plugin</th><th scope=\"col\">Target</th><th scope=\"col\">Evidence</th><th scope=\"col\">Detected At</th></tr></thead>\n")
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
		fmt.Fprintf(b, "        <tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n", html.EscapeString(plugin), html.EscapeString(target), html.EscapeString(evidence), html.EscapeString(ts))
	}
	b.WriteString("      </tbody>\n")
	b.WriteString("    </table>\n")
	b.WriteString("  </section>\n")
}

func renderCasesSection(b *strings.Builder, cases []findings.Finding) {
	b.WriteString("  <section class=\"section\">\n")
	b.WriteString("    <h2>Cases</h2>\n")
	if len(cases) == 0 {
		b.WriteString("    <div class=\"empty-state\">No findings available to review.</div>\n")
		b.WriteString("  </section>\n")
		return
	}

	b.WriteString("    <div class=\"case-list\">\n")
	for idx, f := range cases {
		severity := canonicalSeverity(f.Severity)
		class := severityClass[severity]
		if class == "" {
			class = severityClass[findings.SeverityInfo]
		}
		label := severityLabel(severity)
		scopeLabel, scopeClass, hasScope := deriveScopeBadge(f.Metadata)
		detected := f.DetectedAt.Time().UTC().Format(time.RFC3339)
		openAttr := ""
		if idx == 0 {
			openAttr = " open"
		}

		fmt.Fprintf(b, "      <details class=\"case\"%s>\n", openAttr)
		b.WriteString("        <summary>\n")
		fmt.Fprintf(b, "          <span class=\"severity-pill %s\">%s</span>\n", class, label)
		fmt.Fprintf(b, "          <span class=\"case-title\">%s</span>\n", html.EscapeString(strings.TrimSpace(f.Message)))
		fmt.Fprintf(b, "          <span class=\"case-meta\">Detected %s</span>\n", html.EscapeString(detected))
		if hasScope {
			fmt.Fprintf(b, "          <span class=\"scope-badge %s\">%s</span>\n", scopeClass, html.EscapeString(scopeLabel))
		}
		b.WriteString("        </summary>\n")

		b.WriteString("        <div class=\"case-body\">\n")
		b.WriteString("          <div class=\"case-meta-grid\">\n")
		fmt.Fprintf(b, "            <div><span>Plugin</span><strong>%s</strong></div>\n", html.EscapeString(strings.TrimSpace(f.Plugin)))
		fmt.Fprintf(b, "            <div><span>Type</span><strong>%s</strong></div>\n", html.EscapeString(strings.TrimSpace(f.Type)))
		fmt.Fprintf(b, "            <div><span>Target</span><strong>%s</strong></div>\n", html.EscapeString(strings.TrimSpace(f.Target)))
		b.WriteString("          </div>\n")

		evidence := strings.TrimSpace(f.Evidence)
		if evidence != "" {
			b.WriteString("          <div class=\"case-evidence\">\n")
			b.WriteString("            <div class=\"case-evidence-header\">\n")
			b.WriteString("              <strong>Evidence</strong>\n")
			blockID := fmt.Sprintf("evidence-%d", idx)
			fmt.Fprintf(b, "              <button type=\"button\" class=\"copy-button\" data-copy-target=\"#%s\">Copy</button>\n", blockID)
			b.WriteString("            </div>\n")
			fmt.Fprintf(b, "            <pre id=\"%s\">%s</pre>\n", blockID, html.EscapeString(evidence))
			b.WriteString("          </div>\n")
		}

		thumbnails := extractThumbnails(f.Metadata)
		if len(thumbnails) > 0 {
			b.WriteString("          <div class=\"case-evidence\">\n")
			b.WriteString("            <div class=\"case-evidence-header\">\n")
			b.WriteString("              <strong>Evidence thumbnails</strong>\n")
			b.WriteString("            </div>\n")
			b.WriteString("            <div class=\"thumbnail-grid\">\n")
			for _, src := range thumbnails {
				fmt.Fprintf(b, "              <img src=\"%s\" alt=\"Evidence thumbnail\">\n", html.EscapeString(src))
			}
			b.WriteString("            </div>\n")
			b.WriteString("          </div>\n")
		}

		pocs := extractPOCs(f.Metadata)
		for pocIdx, entry := range pocs {
			blockID := fmt.Sprintf("poc-%d-%d", idx, pocIdx)
			b.WriteString("          <div class=\"case-poc\">\n")
			b.WriteString("            <div class=\"case-poc-header\">\n")
			fmt.Fprintf(b, "              <strong>Proof of Concept%s</strong>\n", entry.Label)
			fmt.Fprintf(b, "              <button type=\"button\" class=\"copy-button\" data-copy-target=\"#%s\">Copy</button>\n", blockID)
			b.WriteString("            </div>\n")
			fmt.Fprintf(b, "            <pre id=\"%s\">%s</pre>\n", blockID, html.EscapeString(entry.Value))
			b.WriteString("          </div>\n")
		}

		metadataEntries := extractMetadataEntries(f.Metadata)
		if len(metadataEntries) > 0 {
			b.WriteString("          <div class=\"case-meta\">\n")
			b.WriteString("            <div class=\"case-poc-header\"><strong>Metadata</strong></div>\n")
			b.WriteString("            <div class=\"metadata-list\">\n")
			for _, entry := range metadataEntries {
				fmt.Fprintf(b, "              <div class=\"metadata-entry\"><span>%s</span><strong>%s</strong></div>\n", html.EscapeString(entry.Key), html.EscapeString(entry.Value))
			}
			b.WriteString("            </div>\n")
			b.WriteString("          </div>\n")
		}

		b.WriteString("        </div>\n")
		b.WriteString("      </details>\n")
	}
	b.WriteString("    </div>\n")
	b.WriteString("  </section>\n")
}

func buildCases(list []findings.Finding) []findings.Finding {
	if len(list) == 0 {
		return nil
	}
	cases := make([]findings.Finding, len(list))
	copy(cases, list)
	sort.SliceStable(cases, func(i, j int) bool {
		si := severityPriority[canonicalSeverity(cases[i].Severity)]
		sj := severityPriority[canonicalSeverity(cases[j].Severity)]
		if si != sj {
			return si < sj
		}
		ti := cases[i].DetectedAt.Time()
		tj := cases[j].DetectedAt.Time()
		if !ti.Equal(tj) {
			return ti.After(tj)
		}
		return cases[i].ID < cases[j].ID
	})
	return cases
}

func severityLabel(sev findings.Severity) string {
	for _, entry := range severityOrder {
		if entry.key == sev {
			return entry.label
		}
	}
	return "Informational"
}

func deriveScopeBadge(meta map[string]string) (label, class string, ok bool) {
	if len(meta) == 0 {
		return "", "", false
	}
	for key, value := range meta {
		trimmedKey := strings.ToLower(strings.TrimSpace(key))
		trimmedValue := strings.TrimSpace(value)
		if trimmedValue == "" {
			continue
		}
		if !strings.Contains(trimmedKey, "scope") {
			continue
		}
		lowerValue := strings.ToLower(trimmedValue)
		switch {
		case strings.Contains(lowerValue, "out") || strings.Contains(lowerValue, "deny") || strings.Contains(lowerValue, "forbid"):
			return "Out of Scope", "scope-out", true
		case strings.Contains(lowerValue, "in") || strings.Contains(lowerValue, "allow") || strings.Contains(lowerValue, "eligible") || strings.Contains(lowerValue, "permit"):
			return "In Scope", "scope-in", true
		default:
			return trimmedValue, "scope-neutral", true
		}
	}
	return "", "", false
}

type pocEntry struct {
	Label string
	Value string
}

type metadataEntry struct {
	Key   string
	Value string
}

func extractPOCs(meta map[string]string) []pocEntry {
	if len(meta) == 0 {
		return nil
	}
	var entries []pocEntry
	for key, value := range meta {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		lowerKey := strings.ToLower(strings.TrimSpace(key))
		if strings.Contains(lowerKey, "poc") || strings.Contains(lowerKey, "proof") || strings.Contains(lowerKey, "exploit") || strings.Contains(lowerKey, "steps") {
			label := ""
			if lowerKey != "poc" {
				label = fmt.Sprintf(" (%s)", key)
			}
			entries = append(entries, pocEntry{Label: label, Value: trimmed})
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Label < entries[j].Label })
	return entries
}

func extractThumbnails(meta map[string]string) []string {
	if len(meta) == 0 {
		return nil
	}
	hints := []string{"thumbnail", "screenshot", "preview", "image"}
	seen := make(map[string]struct{})
	var sources []string
	for key, value := range meta {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		lowerKey := strings.ToLower(strings.TrimSpace(key))
		match := false
		for _, hint := range hints {
			if strings.Contains(lowerKey, hint) {
				match = true
				break
			}
		}
		if !match {
			lowerVal := strings.ToLower(trimmed)
			if strings.HasPrefix(lowerVal, "data:image") {
				match = true
			}
		}
		if !match {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		sources = append(sources, trimmed)
	}
	return sources
}

func extractMetadataEntries(meta map[string]string) []metadataEntry {
	if len(meta) == 0 {
		return nil
	}
	ignored := func(key string) bool {
		lowerKey := strings.ToLower(strings.TrimSpace(key))
		if strings.Contains(lowerKey, "scope") {
			return true
		}
		if strings.Contains(lowerKey, "poc") || strings.Contains(lowerKey, "proof") || strings.Contains(lowerKey, "exploit") || strings.Contains(lowerKey, "steps") {
			return true
		}
		if strings.Contains(lowerKey, "thumbnail") || strings.Contains(lowerKey, "screenshot") || strings.Contains(lowerKey, "preview") || strings.Contains(lowerKey, "image") {
			return true
		}
		return false
	}

	entries := make([]metadataEntry, 0, len(meta))
	for key, value := range meta {
		if ignored(key) {
			continue
		}
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		entries = append(entries, metadataEntry{Key: key, Value: trimmed})
	}
	sort.Slice(entries, func(i, j int) bool { return strings.ToLower(entries[i].Key) < strings.ToLower(entries[j].Key) })
	return entries
}
