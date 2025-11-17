package delta

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"strconv"
	"time"
)

// ExportFormat defines the export format type
type ExportFormat string

const (
	ExportFormatCSV  ExportFormat = "csv"
	ExportFormatJSON ExportFormat = "json"
	ExportFormatHTML ExportFormat = "html"
)

// BatchExporter handles exporting batch comparison results
type BatchExporter struct{}

// NewBatchExporter creates a new batch exporter
func NewBatchExporter() *BatchExporter {
	return &BatchExporter{}
}

// Export exports batch comparison results to the specified format
func (be *BatchExporter) Export(result *BatchDiffResult, format ExportFormat) ([]byte, error) {
	switch format {
	case ExportFormatCSV:
		return be.ExportCSV(result)
	case ExportFormatJSON:
		return be.ExportJSON(result)
	case ExportFormatHTML:
		return be.ExportHTML(result)
	default:
		return nil, fmt.Errorf("unsupported export format: %s", format)
	}
}

// ExportCSV exports the similarity matrix to CSV format
func (be *BatchExporter) ExportCSV(result *BatchDiffResult) ([]byte, error) {
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	// Write header row
	header := make([]string, len(result.Responses)+1)
	header[0] = "Response"
	for i, resp := range result.Responses {
		if resp.Name != "" {
			header[i+1] = resp.Name
		} else {
			header[i+1] = fmt.Sprintf("Response_%d", i)
		}
	}
	if err := writer.Write(header); err != nil {
		return nil, fmt.Errorf("failed to write CSV header: %w", err)
	}

	// Write similarity matrix rows
	for i, row := range result.SimilarityMatrix {
		record := make([]string, len(row)+1)
		if result.Responses[i].Name != "" {
			record[0] = result.Responses[i].Name
		} else {
			record[0] = fmt.Sprintf("Response_%d", i)
		}

		for j, similarity := range row {
			record[j+1] = fmt.Sprintf("%.2f", similarity)
		}

		if err := writer.Write(record); err != nil {
			return nil, fmt.Errorf("failed to write CSV row: %w", err)
		}
	}

	// Write statistics section (pad to matrix width)
	n := len(result.Responses)
	emptyRow := make([]string, n+1)
	writer.Write(emptyRow)

	statRow := make([]string, n+1)
	statRow[0] = "Statistics"
	writer.Write(statRow)

	writeStatRow := func(label, value string) {
		row := make([]string, n+1)
		row[0] = label
		row[1] = value
		writer.Write(row)
	}

	writeStatRow("Total Responses", strconv.Itoa(result.Statistics.TotalResponses))
	writeStatRow("Total Comparisons", strconv.Itoa(result.Statistics.TotalComparisons))
	writeStatRow("Mean Similarity", fmt.Sprintf("%.2f%%", result.Statistics.MeanSimilarity))
	writeStatRow("Median Similarity", fmt.Sprintf("%.2f%%", result.Statistics.MedianSimilarity))
	writeStatRow("Std Dev Similarity", fmt.Sprintf("%.2f", result.Statistics.StdDevSimilarity))
	writeStatRow("Min Similarity", fmt.Sprintf("%.2f%%", result.Statistics.MinSimilarity))
	writeStatRow("Max Similarity", fmt.Sprintf("%.2f%%", result.Statistics.MaxSimilarity))
	writeStatRow("Compute Time", result.ComputeTime.String())

	// Write outliers section
	if len(result.Outliers) > 0 {
		writer.Write(emptyRow)
		outlierHeaderRow := make([]string, n+1)
		outlierHeaderRow[0] = "Outliers"
		writer.Write(outlierHeaderRow)

		for _, idx := range result.Outliers {
			name := result.Responses[idx].Name
			if name == "" {
				name = fmt.Sprintf("Response_%d", idx)
			}
			row := make([]string, n+1)
			row[0] = name
			row[1] = result.Responses[idx].ID
			writer.Write(row)
		}
	}

	// Write clusters section
	if len(result.Clusters) > 0 {
		writer.Write(emptyRow)
		clusterHeaderRow := make([]string, n+1)
		clusterHeaderRow[0] = "Clusters"
		writer.Write(clusterHeaderRow)

		clusterColsRow := make([]string, n+1)
		clusterColsRow[0] = "Cluster ID"
		clusterColsRow[1] = "Size"
		clusterColsRow[2] = "Avg Similarity"
		clusterColsRow[3] = "Response Indices"
		writer.Write(clusterColsRow)

		for _, cluster := range result.Clusters {
			indices := ""
			for i, idx := range cluster.ResponseIndices {
				if i > 0 {
					indices += "; "
				}
				indices += strconv.Itoa(idx)
			}
			row := make([]string, n+1)
			row[0] = strconv.Itoa(cluster.ClusterID)
			row[1] = strconv.Itoa(cluster.Size)
			row[2] = fmt.Sprintf("%.2f%%", cluster.AvgSimilarity)
			row[3] = indices
			writer.Write(row)
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, fmt.Errorf("CSV writer error: %w", err)
	}

	return buf.Bytes(), nil
}

// ExportJSON exports the full comparison results to JSON format
func (be *BatchExporter) ExportJSON(result *BatchDiffResult) ([]byte, error) {
	// Create a custom struct for JSON export with better formatting
	export := struct {
		*BatchDiffResult
		ExportedAt time.Time `json:"exported_at"`
		Version    string    `json:"version"`
	}{
		BatchDiffResult: result,
		ExportedAt:      time.Now(),
		Version:         "1.0",
	}

	data, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON: %w", err)
	}

	return data, nil
}

// ExportHTML exports a visual HTML report
func (be *BatchExporter) ExportHTML(result *BatchDiffResult) ([]byte, error) {
	tmpl := template.Must(template.New("report").Funcs(template.FuncMap{
		"formatFloat": func(f float64) string {
			return fmt.Sprintf("%.2f", f)
		},
		"formatDuration": func(d time.Duration) string {
			return d.String()
		},
		"getSimilarityClass": func(similarity float64) string {
			if similarity >= 95 {
				return "similarity-high"
			} else if similarity >= 80 {
				return "similarity-medium"
			}
			return "similarity-low"
		},
		"percentage": func(count, total int) string {
			if total == 0 {
				return "0.00"
			}
			return fmt.Sprintf("%.2f", float64(count)*100.0/float64(total))
		},
	}).Parse(htmlTemplate))

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, result); err != nil {
		return nil, fmt.Errorf("failed to execute HTML template: %w", err)
	}

	return buf.Bytes(), nil
}

// ExportSummary exports just the summary statistics in plain text format
func (be *BatchExporter) ExportSummary(result *BatchDiffResult, w io.Writer) error {
	fmt.Fprintf(w, "Batch Comparison Summary\n")
	fmt.Fprintf(w, "========================\n\n")

	fmt.Fprintf(w, "Responses: %d\n", result.Statistics.TotalResponses)
	fmt.Fprintf(w, "Comparisons: %d\n", result.Statistics.TotalComparisons)
	fmt.Fprintf(w, "Compute Time: %s\n\n", result.ComputeTime)

	fmt.Fprintf(w, "Similarity Statistics:\n")
	fmt.Fprintf(w, "  Mean:   %.2f%%\n", result.Statistics.MeanSimilarity)
	fmt.Fprintf(w, "  Median: %.2f%%\n", result.Statistics.MedianSimilarity)
	fmt.Fprintf(w, "  StdDev: %.2f\n", result.Statistics.StdDevSimilarity)
	fmt.Fprintf(w, "  Min:    %.2f%%\n", result.Statistics.MinSimilarity)
	fmt.Fprintf(w, "  Max:    %.2f%%\n\n", result.Statistics.MaxSimilarity)

	if len(result.Outliers) > 0 {
		fmt.Fprintf(w, "Outliers (%d):\n", len(result.Outliers))
		for _, idx := range result.Outliers {
			name := result.Responses[idx].Name
			if name == "" {
				name = fmt.Sprintf("Response_%d", idx)
			}
			fmt.Fprintf(w, "  - %s (index %d)\n", name, idx)
		}
		fmt.Fprintf(w, "\n")
	}

	if len(result.Clusters) > 0 {
		fmt.Fprintf(w, "Clusters (%d):\n", len(result.Clusters))
		for _, cluster := range result.Clusters {
			fmt.Fprintf(w, "  - Cluster %d: %d responses, %.2f%% avg similarity\n",
				cluster.ClusterID, cluster.Size, cluster.AvgSimilarity)
		}
		fmt.Fprintf(w, "\n")
	}

	if result.Statistics.StatusCodeDist != nil && len(result.Statistics.StatusCodeDist) > 0 {
		fmt.Fprintf(w, "Status Code Distribution:\n")
		for code, count := range result.Statistics.StatusCodeDist {
			fmt.Fprintf(w, "  - %d: %d responses\n", code, count)
		}
		fmt.Fprintf(w, "\n")
	}

	if result.Patterns != nil && len(result.Patterns.AIInsights) > 0 {
		fmt.Fprintf(w, "AI Insights:\n")
		for i, insight := range result.Patterns.AIInsights {
			fmt.Fprintf(w, "  %d. %s\n", i+1, insight)
		}
		fmt.Fprintf(w, "\n")
	}

	if result.Anomalies != nil && result.Anomalies.Summary != "" {
		fmt.Fprintf(w, "Anomalies:\n")
		fmt.Fprintf(w, "  %s\n\n", result.Anomalies.Summary)
	}

	return nil
}

// HTML template for batch comparison report
const htmlTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Batch Comparison Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #2c3e50;
            margin-bottom: 10px;
            font-size: 28px;
        }
        h2 {
            color: #34495e;
            margin: 25px 0 15px;
            font-size: 22px;
            border-bottom: 2px solid #3498db;
            padding-bottom: 8px;
        }
        h3 {
            color: #34495e;
            margin: 20px 0 10px;
            font-size: 18px;
        }
        .summary {
            background: #ecf0f1;
            padding: 20px;
            border-radius: 6px;
            margin: 20px 0;
        }
        .summary p {
            margin: 8px 0;
            font-size: 16px;
        }
        .summary strong {
            color: #2c3e50;
            display: inline-block;
            min-width: 180px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
            font-size: 14px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border: 1px solid #ddd;
        }
        th {
            background: #3498db;
            color: white;
            font-weight: 600;
        }
        tr:nth-child(even) {
            background: #f9f9f9;
        }
        tr:hover {
            background: #f0f0f0;
        }
        .similarity-matrix {
            overflow-x: auto;
            margin: 20px 0;
        }
        .similarity-matrix table {
            font-size: 12px;
        }
        .similarity-matrix th, .similarity-matrix td {
            padding: 8px;
            text-align: center;
            min-width: 80px;
        }
        .similarity-high {
            background: #d4edda !important;
            color: #155724;
            font-weight: 600;
        }
        .similarity-medium {
            background: #fff3cd !important;
            color: #856404;
        }
        .similarity-low {
            background: #f8d7da !important;
            color: #721c24;
            font-weight: 600;
        }
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
            margin: 2px;
        }
        .badge-primary {
            background: #3498db;
            color: white;
        }
        .badge-warning {
            background: #f39c12;
            color: white;
        }
        .badge-danger {
            background: #e74c3c;
            color: white;
        }
        .badge-success {
            background: #27ae60;
            color: white;
        }
        .insight-list {
            list-style: none;
            padding: 0;
        }
        .insight-list li {
            background: #e8f4f8;
            padding: 12px 15px;
            margin: 8px 0;
            border-left: 4px solid #3498db;
            border-radius: 4px;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        .stat-card {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 6px;
            border-left: 4px solid #3498db;
        }
        .stat-card h4 {
            color: #7f8c8d;
            font-size: 13px;
            margin-bottom: 8px;
            text-transform: uppercase;
        }
        .stat-card .value {
            font-size: 24px;
            font-weight: 600;
            color: #2c3e50;
        }
        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            text-align: center;
            color: #7f8c8d;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Batch Comparison Report</h1>
        <p style="color: #7f8c8d; margin-bottom: 20px;">Generated: {{ .ComputeTime | formatDuration }}</p>

        <div class="summary">
            <h2>Summary</h2>
            <p><strong>Total Responses:</strong> {{ .Statistics.TotalResponses }}</p>
            <p><strong>Total Comparisons:</strong> {{ .Statistics.TotalComparisons }}</p>
            <p><strong>Outliers Detected:</strong> {{ len .Outliers }}</p>
            <p><strong>Clusters Found:</strong> {{ len .Clusters }}</p>
            <p><strong>Compute Time:</strong> {{ .ComputeTime | formatDuration }}</p>
        </div>

        <h2>Similarity Statistics</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <h4>Mean Similarity</h4>
                <div class="value">{{ .Statistics.MeanSimilarity | formatFloat }}%</div>
            </div>
            <div class="stat-card">
                <h4>Median Similarity</h4>
                <div class="value">{{ .Statistics.MedianSimilarity | formatFloat }}%</div>
            </div>
            <div class="stat-card">
                <h4>Std Deviation</h4>
                <div class="value">{{ .Statistics.StdDevSimilarity | formatFloat }}</div>
            </div>
            <div class="stat-card">
                <h4>Min Similarity</h4>
                <div class="value">{{ .Statistics.MinSimilarity | formatFloat }}%</div>
            </div>
            <div class="stat-card">
                <h4>Max Similarity</h4>
                <div class="value">{{ .Statistics.MaxSimilarity | formatFloat }}%</div>
            </div>
        </div>

        <h2>Similarity Matrix</h2>
        <div class="similarity-matrix">
            <table>
                <thead>
                    <tr>
                        <th>Response</th>
                        {{ range $i, $resp := .Responses }}
                        <th>{{ if $resp.Name }}{{ $resp.Name }}{{ else }}R{{ $i }}{{ end }}</th>
                        {{ end }}
                    </tr>
                </thead>
                <tbody>
                    {{ range $i, $row := .SimilarityMatrix }}
                    <tr>
                        <th>{{ if (index $.Responses $i).Name }}{{ (index $.Responses $i).Name }}{{ else }}R{{ $i }}{{ end }}</th>
                        {{ range $j, $sim := $row }}
                        <td class="{{ getSimilarityClass $sim }}">{{ $sim | formatFloat }}%</td>
                        {{ end }}
                    </tr>
                    {{ end }}
                </tbody>
            </table>
        </div>

        {{ if .Outliers }}
        <h2>Outliers</h2>
        <table>
            <thead>
                <tr>
                    <th>Index</th>
                    <th>Response ID</th>
                    <th>Name</th>
                    <th>Status Code</th>
                </tr>
            </thead>
            <tbody>
                {{ range .Outliers }}
                <tr>
                    <td>{{ . }}</td>
                    <td>{{ (index $.Responses .).ID }}</td>
                    <td>{{ if (index $.Responses .).Name }}{{ (index $.Responses .).Name }}{{ else }}-{{ end }}</td>
                    <td>{{ if (index $.Responses .).StatusCode }}{{ (index $.Responses .).StatusCode }}{{ else }}-{{ end }}</td>
                </tr>
                {{ end }}
            </tbody>
        </table>
        {{ end }}

        {{ if .Clusters }}
        <h2>Response Clusters</h2>
        <table>
            <thead>
                <tr>
                    <th>Cluster ID</th>
                    <th>Size</th>
                    <th>Avg Similarity</th>
                    <th>Response Indices</th>
                </tr>
            </thead>
            <tbody>
                {{ range .Clusters }}
                <tr>
                    <td>{{ .ClusterID }}</td>
                    <td>{{ .Size }}</td>
                    <td>{{ .AvgSimilarity | formatFloat }}%</td>
                    <td>
                        {{ range .ResponseIndices }}
                        <span class="badge badge-primary">{{ . }}</span>
                        {{ end }}
                    </td>
                </tr>
                {{ end }}
            </tbody>
        </table>
        {{ end }}

        {{ if .Statistics.StatusCodeDist }}
        <h2>Status Code Distribution</h2>
        <table>
            <thead>
                <tr>
                    <th>Status Code</th>
                    <th>Count</th>
                    <th>Percentage</th>
                </tr>
            </thead>
            <tbody>
                {{ range $code, $count := .Statistics.StatusCodeDist }}
                <tr>
                    <td>{{ $code }}</td>
                    <td>{{ $count }}</td>
                    <td>{{ percentage $count $.Statistics.TotalResponses }}%</td>
                </tr>
                {{ end }}
            </tbody>
        </table>
        {{ end }}

        {{ if .Patterns }}
        {{ if .Patterns.AIInsights }}
        <h2>AI Insights</h2>
        <ul class="insight-list">
            {{ range .Patterns.AIInsights }}
            <li>{{ . }}</li>
            {{ end }}
        </ul>
        {{ end }}

        {{ if .Patterns.ConstantFields }}
        <h3>Constant Fields ({{ len .Patterns.ConstantFields }})</h3>
        <p>
            {{ range .Patterns.ConstantFields }}
            <span class="badge badge-success">{{ . }}</span>
            {{ end }}
        </p>
        {{ end }}

        {{ if .Patterns.VariableFields }}
        <h3>Variable Fields ({{ len .Patterns.VariableFields }})</h3>
        <p>
            {{ range .Patterns.VariableFields }}
            <span class="badge badge-warning">{{ . }}</span>
            {{ end }}
        </p>
        {{ end }}
        {{ end }}

        {{ if .Anomalies }}
        <h2>Anomaly Detection</h2>
        <div class="summary">
            <p>{{ .Anomalies.Summary }}</p>
        </div>

        {{ if .Anomalies.UnusualStatusCodes }}
        <h3>Unusual Status Codes</h3>
        <p>
            {{ range .Anomalies.UnusualStatusCodes }}
            <span class="badge badge-danger">Response {{ . }}</span>
            {{ end }}
        </p>
        {{ end }}

        {{ if .Anomalies.UnusualLengths }}
        <h3>Unusual Content Lengths</h3>
        <p>
            {{ range .Anomalies.UnusualLengths }}
            <span class="badge badge-warning">Response {{ . }}</span>
            {{ end }}
        </p>
        {{ end }}

        {{ if .Anomalies.SlowResponses }}
        <h3>Slow Responses</h3>
        <p>
            {{ range .Anomalies.SlowResponses }}
            <span class="badge badge-warning">Response {{ . }}</span>
            {{ end }}
        </p>
        {{ end }}
        {{ end }}

        <div class="footer">
            <p>Batch Comparison Report - 0xGen Delta Engine v1.0</p>
        </div>
    </div>
</body>
</html>
`
