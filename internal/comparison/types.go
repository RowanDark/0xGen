package comparison

import (
	"time"

	"github.com/RowanDark/0xgen/internal/findings"
)

// ComparisonResult represents the result of comparing two scans.
type ComparisonResult struct {
	ScanA       ScanSummary `json:"scan_a"`
	ScanB       ScanSummary `json:"scan_b"`
	Summary     Summary     `json:"summary"`
	New         []Finding   `json:"new"`
	Fixed       []Finding   `json:"fixed"`
	Changed     []Finding   `json:"changed"`
	Unchanged   []Finding   `json:"unchanged"`
	ComparedAt  time.Time   `json:"compared_at"`
}

// ScanSummary provides metadata about a scan.
type ScanSummary struct {
	ID            string             `json:"id"`
	Name          string             `json:"name,omitempty"`
	Target        string             `json:"target"`
	Timestamp     findings.Timestamp `json:"timestamp"`
	TotalFindings int                `json:"total_findings"`
}

// Summary provides high-level statistics about the comparison.
type Summary struct {
	NewCount       int `json:"new_count"`
	FixedCount     int `json:"fixed_count"`
	ChangedCount   int `json:"changed_count"`
	UnchangedCount int `json:"unchanged_count"`

	// Severity breakdown for new findings
	NewBySeverity map[findings.Severity]int `json:"new_by_severity"`

	// Severity breakdown for fixed findings
	FixedBySeverity map[findings.Severity]int `json:"fixed_by_severity"`
}

// Finding wraps a finding with comparison metadata.
type Finding struct {
	findings.Finding
	FirstSeen time.Time `json:"first_seen,omitempty"`
	LastSeen  time.Time `json:"last_seen,omitempty"`
	Changes   []string  `json:"changes,omitempty"` // Description of what changed
}

// TrendData represents vulnerability trends over time.
type TrendData struct {
	Target     string             `json:"target"`
	Period     string             `json:"period"` // e.g., "30d", "7d"
	StartTime  findings.Timestamp `json:"start_time"`
	EndTime    findings.Timestamp `json:"end_time"`
	DataPoints []TrendDataPoint   `json:"data_points"`
	Summary    TrendSummary       `json:"summary"`
}

// TrendDataPoint represents vulnerability counts at a specific time.
type TrendDataPoint struct {
	Timestamp     findings.Timestamp            `json:"timestamp"`
	TotalFindings int                           `json:"total_findings"`
	BySeverity    map[findings.Severity]int     `json:"by_severity"`
	ByType        map[string]int                `json:"by_type"`
}

// TrendSummary provides high-level trend statistics.
type TrendSummary struct {
	// Overall trend direction
	Direction string `json:"direction"` // "improving", "worsening", "stable"

	// Percentage change from start to end
	PercentChange float64 `json:"percent_change"`

	// Severity trends
	SeverityTrends map[findings.Severity]SeverityTrend `json:"severity_trends"`

	// Top persistent issues
	TopIssues []string `json:"top_issues"`

	// Recently fixed issues
	RecentlyFixed []string `json:"recently_fixed"`

	// New this period
	NewThisPeriod []string `json:"new_this_period"`
}

// SeverityTrend tracks how a severity level has changed.
type SeverityTrend struct {
	StartCount    int     `json:"start_count"`
	EndCount      int     `json:"end_count"`
	PercentChange float64 `json:"percent_change"`
	Direction     string  `json:"direction"` // "up", "down", "stable"
}

// Baseline represents a saved baseline scan for comparison.
type Baseline struct {
	ScanID    string    `json:"scan_id"`
	Target    string    `json:"target"`
	SetAt     time.Time `json:"set_at"`
	SetBy     string    `json:"set_by,omitempty"`
	Name      string    `json:"name,omitempty"`
	Findings  int       `json:"findings"`
}

// CompareOptions configures how scans are compared.
type CompareOptions struct {
	// IgnoreEvidence skips comparing evidence fields
	IgnoreEvidence bool

	// IgnoreTimestamps skips comparing timestamps
	IgnoreTimestamps bool

	// SeverityThreshold only compares findings above this severity
	SeverityThreshold findings.Severity

	// MatchByType determines if findings are matched by type+target
	MatchByType bool
}

// DefaultCompareOptions returns sensible defaults.
func DefaultCompareOptions() CompareOptions {
	return CompareOptions{
		IgnoreEvidence:    false,
		IgnoreTimestamps:  true,
		SeverityThreshold: findings.SeverityInfo,
		MatchByType:       true,
	}
}
