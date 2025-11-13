package blitz

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"strconv"
	"strings"
	"time"
)

// CSVExporter exports results to CSV format.
type CSVExporter struct{}

func (e *CSVExporter) Format() string {
	return "csv"
}

func (e *CSVExporter) Export(results []*FuzzResult, destination string) error {
	file, err := os.Create(destination)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{
		"ID", "Timestamp", "Position", "Position Name", "Payload",
		"Status Code", "Duration (ms)", "Content Length", "Error",
		"Request Method", "Request URL", "Response Body Preview",
		"Pattern Matches", "Anomaly Interesting",
	}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("write header: %w", err)
	}

	// Write rows
	for _, result := range results {
		row := []string{
			strconv.FormatInt(result.ID, 10),
			result.Timestamp.Format(time.RFC3339),
			strconv.Itoa(result.Position),
			result.PositionName,
			truncate(result.Payload, 100),
			strconv.Itoa(result.StatusCode),
			strconv.FormatInt(result.Duration, 10),
			strconv.FormatInt(result.ContentLen, 10),
			result.Error,
			result.Request.Method,
			result.Request.URL,
			truncate(result.Response.Body, 200),
			formatMatches(result.Matches),
			formatInteresting(result.Anomaly),
		}
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("write row: %w", err)
		}
	}

	return nil
}

// JSONExporter exports results to JSON format.
type JSONExporter struct {
	Pretty bool
}

func (e *JSONExporter) Format() string {
	return "json"
}

func (e *JSONExporter) Export(results []*FuzzResult, destination string) error {
	file, err := os.Create(destination)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)

	if e.Pretty {
		encoder.SetIndent("", "  ")
	}

	if err := encoder.Encode(results); err != nil {
		return fmt.Errorf("encode JSON: %w", err)
	}

	return nil
}

// HTMLExporter exports results to an HTML report.
type HTMLExporter struct {
	Title string
	Stats *Stats
}

func (e *HTMLExporter) Format() string {
	return "html"
}

func (e *HTMLExporter) Export(results []*FuzzResult, destination string) error {
	file, err := os.Create(destination)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer file.Close()

	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"formatTime": func(t time.Time) string {
			return t.Format("2006-01-02 15:04:05")
		},
		"formatDuration": func(ms int64) string {
			return fmt.Sprintf("%dms", ms)
		},
		"truncate": func(s string, length int) string {
			return truncate(s, length)
		},
		"statusClass": func(code int) string {
			if code >= 200 && code < 300 {
				return "success"
			} else if code >= 300 && code < 400 {
				return "redirect"
			} else if code >= 400 && code < 500 {
				return "client-error"
			} else if code >= 500 {
				return "server-error"
			}
			return "unknown"
		},
		"hasMatches": func(matches []PatternMatch) bool {
			return len(matches) > 0
		},
		"isInteresting": func(anomaly *AnomalyIndicator) bool {
			return anomaly != nil && anomaly.IsInteresting
		},
	}).Parse(htmlTemplate)

	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}

	data := struct {
		Title   string
		Stats   *Stats
		Results []*FuzzResult
	}{
		Title:   e.Title,
		Stats:   e.Stats,
		Results: results,
	}

	if err := tmpl.Execute(file, data); err != nil {
		return fmt.Errorf("execute template: %w", err)
	}

	return nil
}

// formatMatches converts pattern matches to a readable string.
func formatMatches(matches []PatternMatch) string {
	if len(matches) == 0 {
		return ""
	}

	var parts []string
	for _, match := range matches {
		parts = append(parts, fmt.Sprintf("%s: %d", match.Pattern, len(match.Matches)))
	}

	return strings.Join(parts, "; ")
}

// formatInteresting returns whether a result is interesting.
func formatInteresting(anomaly *AnomalyIndicator) string {
	if anomaly != nil && anomaly.IsInteresting {
		return "Yes"
	}
	return "No"
}

// htmlTemplate is the HTML report template.
const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: #f5f5f5;
            color: #333;
            line-height: 1.6;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px 20px;
            border-radius: 8px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        h1 {
            font-size: 2em;
            margin-bottom: 10px;
        }
        .subtitle {
            opacity: 0.9;
            font-size: 1.1em;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .stat-label {
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .stat-value {
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
            margin-top: 5px;
        }
        .results-table {
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        thead {
            background: #667eea;
            color: white;
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
        }
        th {
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 0.5px;
        }
        tbody tr {
            border-bottom: 1px solid #e0e0e0;
        }
        tbody tr:hover {
            background: #f9f9f9;
        }
        tbody tr:last-child {
            border-bottom: none;
        }
        .status-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
        }
        .status-badge.success {
            background: #d4edda;
            color: #155724;
        }
        .status-badge.redirect {
            background: #d1ecf1;
            color: #0c5460;
        }
        .status-badge.client-error {
            background: #fff3cd;
            color: #856404;
        }
        .status-badge.server-error {
            background: #f8d7da;
            color: #721c24;
        }
        .interesting {
            color: #e74c3c;
            font-weight: bold;
        }
        .error-text {
            color: #e74c3c;
            font-family: monospace;
            font-size: 0.9em;
        }
        .payload {
            font-family: 'Courier New', monospace;
            background: #f5f5f5;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.9em;
        }
        .match-badge {
            background: #ffeaa7;
            color: #d63031;
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 0.85em;
            font-weight: 600;
        }
        .no-results {
            text-align: center;
            padding: 60px 20px;
            color: #999;
        }
        footer {
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>{{.Title}}</h1>
            <div class="subtitle">Blitz Fuzzing Report</div>
        </header>

        {{if .Stats}}
        <div class="stats">
            <div class="stat-card">
                <div class="stat-label">Total Requests</div>
                <div class="stat-value">{{.Stats.TotalRequests}}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Successful</div>
                <div class="stat-value">{{.Stats.SuccessfulReqs}}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Failed</div>
                <div class="stat-value">{{.Stats.FailedReqs}}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Anomalies</div>
                <div class="stat-value">{{.Stats.AnomalyCount}}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Avg Duration</div>
                <div class="stat-value">{{.Stats.AvgDuration}}ms</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Pattern Matches</div>
                <div class="stat-value">{{.Stats.PatternMatchCount}}</div>
            </div>
        </div>
        {{end}}

        <div class="results-table">
            {{if .Results}}
            <table>
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Position</th>
                        <th>Payload</th>
                        <th>Status</th>
                        <th>Duration</th>
                        <th>Size</th>
                        <th>Matches</th>
                        <th>Interesting</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .Results}}
                    <tr>
                        <td>{{formatTime .Timestamp}}</td>
                        <td>{{.PositionName}}</td>
                        <td><span class="payload">{{truncate .Payload 50}}</span></td>
                        <td><span class="status-badge {{statusClass .StatusCode}}">{{.StatusCode}}</span></td>
                        <td>{{formatDuration .Duration}}</td>
                        <td>{{.ContentLen}} bytes</td>
                        <td>
                            {{if hasMatches .Matches}}
                                <span class="match-badge">{{len .Matches}}</span>
                            {{else}}
                                -
                            {{end}}
                        </td>
                        <td>
                            {{if isInteresting .Anomaly}}
                                <span class="interesting">✓</span>
                            {{else}}
                                -
                            {{end}}
                        </td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
            {{else}}
            <div class="no-results">
                <h3>No results to display</h3>
                <p>Run a fuzzing campaign to see results here.</p>
            </div>
            {{end}}
        </div>

        <footer>
            Generated by Blitz - 0xGen AI-Powered Fuzzer
        </footer>
    </div>
</body>
</html>`
