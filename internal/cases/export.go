package cases

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"strings"
)

// ExportJSON renders the case as pretty-printed JSON.
func ExportJSON(c Case) ([]byte, error) {
	buf, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, err
	}
	buf = append(buf, '\n')
	return buf, nil
}

// ExportMarkdown renders a human readable markdown report for the case.
func ExportMarkdown(c Case) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Case %s\n\n", c.ID)
	fmt.Fprintf(&b, "- Asset: **%s** (%s)\n", c.Asset.Identifier, c.Asset.Kind)
	fmt.Fprintf(&b, "- Attack vector: **%s**", c.Vector.Kind)
	if c.Vector.Value != "" {
		fmt.Fprintf(&b, " (%s)", c.Vector.Value)
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "- Risk: **%s** (score %.1f)\n", strings.ToUpper(string(c.Risk.Severity)), c.Risk.Score)
	fmt.Fprintf(&b, "- Confidence: %.2f\n\n", c.Confidence)

	b.WriteString("## Summary\n")
	b.WriteString(c.Summary)
	b.WriteString("\n\n")

	if len(c.Proof.Steps) > 0 {
		b.WriteString("## Reproduction steps\n")
		for i, step := range c.Proof.Steps {
			fmt.Fprintf(&b, "%d. %s\n", i+1, step)
		}
		b.WriteString("\n")
	}

	if len(c.Evidence) > 0 {
		b.WriteString("## Evidence\n")
		for _, e := range c.Evidence {
			fmt.Fprintf(&b, "- **%s** (%s): %s\n", strings.Title(e.Plugin), e.Type, e.Message)
			if e.Evidence != "" {
				fmt.Fprintf(&b, "  - Evidence: `%s`\n", e.Evidence)
			}
		}
	}

	return b.String()
}

var htmlTemplate = template.Must(template.New("case").Funcs(template.FuncMap{
	"title": strings.Title,
	"upper": strings.ToUpper,
	"splitLines": func(s string) []string {
		s = strings.ReplaceAll(s, "\r\n", "\n")
		parts := strings.Split(s, "\n")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			out = append(out, p)
		}
		return out
	},
}).Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>Case {{ .ID }}</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 2rem; line-height: 1.5; }
h1 { font-size: 1.8rem; }
section { margin-bottom: 1.5rem; }
ul { padding-left: 1.2rem; }
code { background: #f6f8fa; padding: 0.2rem 0.4rem; border-radius: 3px; }
</style>
</head>
<body>
<h1>Case {{ .ID }}</h1>
<section>
  <p><strong>Asset:</strong> {{ .Asset.Identifier }} ({{ .Asset.Kind }})<br/>
     <strong>Vector:</strong> {{ .Vector.Kind }}{{ if .Vector.Value }} ({{ .Vector.Value }}){{ end }}<br/>
     <strong>Risk:</strong> {{ .Risk.Severity | upper }} ({{ printf "%.1f" .Risk.Score }})<br/>
     <strong>Confidence:</strong> {{ printf "%.2f" .Confidence }}</p>
</section>
<section>
  <h2>Summary</h2>
  {{ range splitLines .Summary }}<p>{{ . }}</p>{{ end }}
</section>
{{ if gt (len .Proof.Steps) 0 }}
<section>
  <h2>Reproduction steps</h2>
  <ol>
    {{ range .Proof.Steps }}<li>{{ . }}</li>{{ end }}
  </ol>
</section>
{{ end }}
{{ if gt (len .Evidence) 0 }}
<section>
  <h2>Evidence</h2>
  <ul>
    {{ range .Evidence }}<li><strong>{{ title .Plugin }}</strong> ({{ .Type }}): {{ .Message }}{{ if .Evidence }}<br/><code>{{ .Evidence }}</code>{{ end }}</li>{{ end }}
  </ul>
</section>
{{ end }}
</body>
</html>`))

// ExportHTML renders an HTML snapshot suitable for sharing.
func ExportHTML(c Case) (string, error) {
	var buf bytes.Buffer
	data := struct {
		Case
	}{Case: c}
	err := htmlTemplate.Execute(&buf, data)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}
