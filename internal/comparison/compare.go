package comparison

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/RowanDark/0xgen/internal/findings"
)

// Compare compares two sets of findings and returns the differences.
func Compare(scanA, scanB ScanSummary, findingsA, findingsB []findings.Finding, opts CompareOptions) (*ComparisonResult, error) {
	result := &ComparisonResult{
		ScanA:      scanA,
		ScanB:      scanB,
		ComparedAt: time.Now().UTC(),
		Summary: Summary{
			NewBySeverity:   make(map[findings.Severity]int),
			FixedBySeverity: make(map[findings.Severity]int),
		},
	}

	// Build lookup maps for efficient comparison
	mapA := buildFindingMap(findingsA, opts)
	mapB := buildFindingMap(findingsB, opts)

	// Identify new findings (in B but not in A)
	for key, findingB := range mapB {
		if _, exists := mapA[key]; !exists {
			// Apply severity filter
			if !meetsThreshold(findingB.Severity, opts.SeverityThreshold) {
				continue
			}

			result.New = append(result.New, Finding{
				Finding:   findingB,
				FirstSeen: scanB.Timestamp.Time(),
			})
			result.Summary.NewCount++
			result.Summary.NewBySeverity[findingB.Severity]++
		}
	}

	// Identify fixed findings (in A but not in B)
	for key, findingA := range mapA {
		if _, exists := mapB[key]; !exists {
			// Apply severity filter
			if !meetsThreshold(findingA.Severity, opts.SeverityThreshold) {
				continue
			}

			result.Fixed = append(result.Fixed, Finding{
				Finding:  findingA,
				LastSeen: scanA.Timestamp.Time(),
			})
			result.Summary.FixedCount++
			result.Summary.FixedBySeverity[findingA.Severity]++
		}
	}

	// Identify changed and unchanged findings (in both)
	for key, findingA := range mapA {
		if findingB, exists := mapB[key]; exists {
			// Apply severity filter
			if !meetsThreshold(findingA.Severity, opts.SeverityThreshold) {
				continue
			}

			changes := detectChanges(findingA, findingB, opts)
			if len(changes) > 0 {
				result.Changed = append(result.Changed, Finding{
					Finding:   findingB,
					FirstSeen: scanA.Timestamp.Time(),
					LastSeen:  scanB.Timestamp.Time(),
					Changes:   changes,
				})
				result.Summary.ChangedCount++
			} else {
				result.Unchanged = append(result.Unchanged, Finding{
					Finding:   findingB,
					FirstSeen: scanA.Timestamp.Time(),
					LastSeen:  scanB.Timestamp.Time(),
				})
				result.Summary.UnchangedCount++
			}
		}
	}

	// Sort findings by severity
	sortBySeverity(result.New)
	sortBySeverity(result.Fixed)
	sortBySeverity(result.Changed)
	sortBySeverity(result.Unchanged)

	return result, nil
}

// buildFindingMap creates a map of findings keyed by their unique identifier.
func buildFindingMap(findingsList []findings.Finding, opts CompareOptions) map[string]findings.Finding {
	m := make(map[string]findings.Finding)
	for _, f := range findingsList {
		key := generateFindingKey(f, opts)
		m[key] = f
	}
	return m
}

// generateFindingKey creates a unique key for a finding based on comparison options.
func generateFindingKey(f findings.Finding, opts CompareOptions) string {
	if opts.MatchByType {
		// Match by type + target combination
		return fmt.Sprintf("%s|%s", f.Type, f.Target)
	}
	// Match by message + target (more strict)
	return fmt.Sprintf("%s|%s|%s", f.Type, f.Target, f.Message)
}

// detectChanges identifies what changed between two findings.
func detectChanges(a, b findings.Finding, opts CompareOptions) []string {
	var changes []string

	if a.Severity != b.Severity {
		changes = append(changes, fmt.Sprintf("severity: %s → %s", a.Severity, b.Severity))
	}

	if a.Message != b.Message {
		changes = append(changes, "message changed")
	}

	if !opts.IgnoreEvidence && a.Evidence != b.Evidence {
		changes = append(changes, "evidence changed")
	}

	// Check metadata changes
	if len(a.Metadata) != len(b.Metadata) {
		changes = append(changes, "metadata changed")
	} else {
		for k, v := range a.Metadata {
			if bv, exists := b.Metadata[k]; !exists || bv != v {
				changes = append(changes, fmt.Sprintf("metadata.%s changed", k))
			}
		}
	}

	return changes
}

// meetsThreshold checks if a severity meets the threshold.
func meetsThreshold(severity, threshold findings.Severity) bool {
	severityOrder := map[findings.Severity]int{
		findings.SeverityInfo:     0,
		findings.SeverityLow:      1,
		findings.SeverityMedium:   2,
		findings.SeverityHigh:     3,
		findings.SeverityCritical: 4,
	}

	return severityOrder[severity] >= severityOrder[threshold]
}

// sortBySeverity sorts findings by severity (critical first) and then by type.
func sortBySeverity(findingsList []Finding) {
	sort.Slice(findingsList, func(i, j int) bool {
		severityOrder := map[findings.Severity]int{
			findings.SeverityCritical: 0,
			findings.SeverityHigh:     1,
			findings.SeverityMedium:   2,
			findings.SeverityLow:      3,
			findings.SeverityInfo:     4,
		}

		si := severityOrder[findingsList[i].Severity]
		sj := severityOrder[findingsList[j].Severity]

		if si != sj {
			return si < sj
		}

		// Secondary sort by type
		return findingsList[i].Type < findingsList[j].Type
	})
}

// CompareScanIDs is a convenience function that compares scans by their IDs.
// It loads the scan data and findings from the provided loader function.
func CompareScanIDs(scanIDA, scanIDB string, loader ScanLoader, opts CompareOptions) (*ComparisonResult, error) {
	// Load scan A
	summaryA, findingsA, err := loader(scanIDA)
	if err != nil {
		return nil, fmt.Errorf("load scan A (%s): %w", scanIDA, err)
	}

	// Load scan B
	summaryB, findingsB, err := loader(scanIDB)
	if err != nil {
		return nil, fmt.Errorf("load scan B (%s): %w", scanIDB, err)
	}

	return Compare(summaryA, summaryB, findingsA, findingsB, opts)
}

// ScanLoader is a function type for loading scan data.
type ScanLoader func(scanID string) (ScanSummary, []findings.Finding, error)

// HasNewCritical checks if there are any new critical findings.
func (r *ComparisonResult) HasNewCritical() bool {
	return r.Summary.NewBySeverity[findings.SeverityCritical] > 0
}

// HasNewHighOrCritical checks if there are any new high or critical findings.
func (r *ComparisonResult) HasNewHighOrCritical() bool {
	return r.Summary.NewBySeverity[findings.SeverityCritical] > 0 ||
		r.Summary.NewBySeverity[findings.SeverityHigh] > 0
}

// HasNew checks if there are any new findings.
func (r *ComparisonResult) HasNew() bool {
	return r.Summary.NewCount > 0
}

// GetImprovementScore calculates a score indicating overall improvement (-100 to 100).
// Positive = better, negative = worse.
func (r *ComparisonResult) GetImprovementScore() int {
	// Weight by severity
	severityWeights := map[findings.Severity]int{
		findings.SeverityCritical: 10,
		findings.SeverityHigh:     5,
		findings.SeverityMedium:   2,
		findings.SeverityLow:      1,
		findings.SeverityInfo:     0,
	}

	newScore := 0
	for sev, count := range r.Summary.NewBySeverity {
		newScore += count * severityWeights[sev]
	}

	fixedScore := 0
	for sev, count := range r.Summary.FixedBySeverity {
		fixedScore += count * severityWeights[sev]
	}

	// Calculate net improvement
	netImprovement := fixedScore - newScore

	// Normalize to -100 to 100 range
	maxScore := max(newScore, fixedScore)
	if maxScore == 0 {
		return 0
	}

	score := (netImprovement * 100) / maxScore
	if score > 100 {
		score = 100
	} else if score < -100 {
		score = -100
	}

	return score
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// GetSummaryText returns a human-readable summary.
func (r *ComparisonResult) GetSummaryText() string {
	var lines []string

	if r.Summary.NewCount > 0 {
		lines = append(lines, fmt.Sprintf("🔴 New: %d vulnerabilities", r.Summary.NewCount))
	}
	if r.Summary.FixedCount > 0 {
		lines = append(lines, fmt.Sprintf("🟢 Fixed: %d vulnerabilities", r.Summary.FixedCount))
	}
	if r.Summary.ChangedCount > 0 {
		lines = append(lines, fmt.Sprintf("🟡 Changed: %d vulnerabilities", r.Summary.ChangedCount))
	}
	if r.Summary.UnchangedCount > 0 {
		lines = append(lines, fmt.Sprintf("⚪ Unchanged: %d vulnerabilities", r.Summary.UnchangedCount))
	}

	if len(lines) == 0 {
		return "No changes detected"
	}

	return strings.Join(lines, "\n")
}
