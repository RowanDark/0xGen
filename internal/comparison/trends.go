package comparison

import (
	"fmt"
	"sort"
	"time"

	"github.com/RowanDark/0xgen/internal/findings"
)

// AnalyzeTrends analyzes vulnerability trends over a time period.
func AnalyzeTrends(scans []ScanWithFindings, target string, period string) (*TrendData, error) {
	if len(scans) == 0 {
		return nil, fmt.Errorf("no scans provided for trend analysis")
	}

	// Sort scans by timestamp
	sort.Slice(scans, func(i, j int) bool {
		return scans[i].Summary.Timestamp.Time().Before(scans[j].Summary.Timestamp.Time())
	})

	startTime := scans[0].Summary.Timestamp
	endTime := scans[len(scans)-1].Summary.Timestamp

	trend := &TrendData{
		Target:     target,
		Period:     period,
		StartTime:  startTime,
		EndTime:    endTime,
		DataPoints: make([]TrendDataPoint, 0, len(scans)),
	}

	// Build data points
	for _, scan := range scans {
		dp := TrendDataPoint{
			Timestamp:     scan.Summary.Timestamp,
			TotalFindings: len(scan.Findings),
			BySeverity:    make(map[findings.Severity]int),
			ByType:        make(map[string]int),
		}

		for _, finding := range scan.Findings {
			dp.BySeverity[finding.Severity]++
			dp.ByType[finding.Type]++
		}

		trend.DataPoints = append(trend.DataPoints, dp)
	}

	// Calculate summary
	trend.Summary = calculateTrendSummary(trend.DataPoints, scans)

	return trend, nil
}

// calculateTrendSummary generates summary statistics for trends.
func calculateTrendSummary(dataPoints []TrendDataPoint, scans []ScanWithFindings) TrendSummary {
	if len(dataPoints) == 0 {
		return TrendSummary{
			SeverityTrends: make(map[findings.Severity]SeverityTrend),
		}
	}

	first := dataPoints[0]
	last := dataPoints[len(dataPoints)-1]

	summary := TrendSummary{
		SeverityTrends: make(map[findings.Severity]SeverityTrend),
	}

	// Calculate overall trend direction
	totalChange := last.TotalFindings - first.TotalFindings
	if first.TotalFindings > 0 {
		summary.PercentChange = (float64(totalChange) / float64(first.TotalFindings)) * 100
	}

	if totalChange < 0 {
		summary.Direction = "improving"
	} else if totalChange > 0 {
		summary.Direction = "worsening"
	} else {
		summary.Direction = "stable"
	}

	// Calculate severity trends
	severities := []findings.Severity{
		findings.SeverityCritical,
		findings.SeverityHigh,
		findings.SeverityMedium,
		findings.SeverityLow,
	}

	for _, sev := range severities {
		startCount := first.BySeverity[sev]
		endCount := last.BySeverity[sev]

		trend := SeverityTrend{
			StartCount: startCount,
			EndCount:   endCount,
		}

		change := endCount - startCount
		if startCount > 0 {
			trend.PercentChange = (float64(change) / float64(startCount)) * 100
		}

		if change < 0 {
			trend.Direction = "down"
		} else if change > 0 {
			trend.Direction = "up"
		} else {
			trend.Direction = "stable"
		}

		summary.SeverityTrends[sev] = trend
	}

	// Find top persistent issues (appear in most scans)
	issueCounts := make(map[string]int)
	for _, scan := range scans {
		seen := make(map[string]bool)
		for _, finding := range scan.Findings {
			key := finding.Type
			if !seen[key] {
				issueCounts[key]++
				seen[key] = true
			}
		}
	}

	var topIssues []issueCountItem
	for issue, count := range issueCounts {
		topIssues = append(topIssues, issueCountItem{issue: issue, count: count})
	}
	sort.Slice(topIssues, func(i, j int) bool {
		return topIssues[i].count > topIssues[j].count
	})

	// Take top 5 persistent issues
	for i := 0; i < len(topIssues) && i < 5; i++ {
		summary.TopIssues = append(summary.TopIssues, topIssues[i].issue)
	}

	// Find recently fixed issues (in earlier scans but not recent)
	if len(scans) >= 2 {
		recentScan := scans[len(scans)-1]
		previousScan := scans[len(scans)-2]

		recentTypes := make(map[string]bool)
		for _, finding := range recentScan.Findings {
			recentTypes[finding.Type] = true
		}

		for _, finding := range previousScan.Findings {
			if !recentTypes[finding.Type] {
				summary.RecentlyFixed = append(summary.RecentlyFixed, finding.Type)
			}
		}
	}

	// Find new issues this period
	if len(scans) >= 2 {
		firstScan := scans[0]
		recentScan := scans[len(scans)-1]

		firstTypes := make(map[string]bool)
		for _, finding := range firstScan.Findings {
			firstTypes[finding.Type] = true
		}

		for _, finding := range recentScan.Findings {
			if !firstTypes[finding.Type] {
				summary.NewThisPeriod = append(summary.NewThisPeriod, finding.Type)
			}
		}
	}

	return summary
}

type issueCountItem struct {
	issue string
	count int
}

// ScanWithFindings combines a scan summary with its findings.
type ScanWithFindings struct {
	Summary  ScanSummary
	Findings []findings.Finding
}

// GetTrendDirection returns a simple string indicating trend direction.
func (t *TrendData) GetTrendDirection() string {
	return t.Summary.Direction
}

// GetSeverityTrendText returns a human-readable description of severity trends.
func (t *TrendData) GetSeverityTrendText() string {
	var lines []string

	severities := []findings.Severity{
		findings.SeverityCritical,
		findings.SeverityHigh,
		findings.SeverityMedium,
		findings.SeverityLow,
	}

	icons := map[string]string{
		"up":     "↑",
		"down":   "↓",
		"stable": "→",
	}

	severityIcons := map[findings.Severity]string{
		findings.SeverityCritical: "🔴",
		findings.SeverityHigh:     "🟠",
		findings.SeverityMedium:   "🟡",
		findings.SeverityLow:      "🟢",
	}

	for _, sev := range severities {
		if trend, exists := t.Summary.SeverityTrends[sev]; exists {
			icon := severityIcons[sev]
			arrow := icons[trend.Direction]
			line := fmt.Sprintf("%s %s: %d → %d (%s%.0f%%)",
				icon,
				sev,
				trend.StartCount,
				trend.EndCount,
				arrow,
				trend.PercentChange,
			)
			lines = append(lines, line)
		}
	}

	return fmt.Sprintf("%s", lines)
}

// ParsePeriod converts a period string (e.g., "30d", "7d", "24h") to a duration.
func ParsePeriod(period string) (time.Duration, error) {
	if period == "" {
		return 30 * 24 * time.Hour, nil // Default to 30 days
	}

	return time.ParseDuration(period)
}

// FilterScansByPeriod filters scans to those within the specified time period.
func FilterScansByPeriod(scans []ScanWithFindings, period time.Duration) []ScanWithFindings {
	if len(scans) == 0 {
		return scans
	}

	cutoff := time.Now().UTC().Add(-period)

	var filtered []ScanWithFindings
	for _, scan := range scans {
		if scan.Summary.Timestamp.Time().After(cutoff) || scan.Summary.Timestamp.Equal(cutoff) {
			filtered = append(filtered, scan)
		}
	}

	return filtered
}

// GenerateASCIIChart creates a simple ASCII chart of trend data.
func (t *TrendData) GenerateASCIIChart() string {
	if len(t.DataPoints) == 0 {
		return "No data available"
	}

	// Find max value for scaling
	maxFindings := 0
	for _, dp := range t.DataPoints {
		if dp.TotalFindings > maxFindings {
			maxFindings = dp.TotalFindings
		}
	}

	if maxFindings == 0 {
		return "No findings in period"
	}

	// Chart dimensions
	height := 10
	width := len(t.DataPoints)

	var chart []string

	// Build chart from top to bottom
	for row := height; row > 0; row-- {
		line := fmt.Sprintf("%3d │", (maxFindings*row)/height)

		for _, dp := range t.DataPoints {
			threshold := (maxFindings * row) / height
			if dp.TotalFindings >= threshold {
				line += "●"
			} else {
				line += " "
			}
			line += " "
		}

		chart = append(chart, line)
	}

	// Add x-axis
	xaxis := "  0 └"
	for i := 0; i < width*2; i++ {
		xaxis += "─"
	}
	chart = append(chart, xaxis)

	return fmt.Sprintf("%s", chart)
}
