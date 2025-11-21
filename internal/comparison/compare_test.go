package comparison

import (
	"testing"
	"time"

	"github.com/RowanDark/0xgen/internal/findings"
)

func TestCompare(t *testing.T) {
	// Create test data
	now := time.Now().UTC()
	earlier := now.Add(-24 * time.Hour)

	summaryA := ScanSummary{
		ID:            "scan-a",
		Name:          "Scan A",
		Target:        "https://example.com",
		Timestamp:     findings.NewTimestamp(earlier),
		TotalFindings: 3,
	}

	summaryB := ScanSummary{
		ID:            "scan-b",
		Name:          "Scan B",
		Target:        "https://example.com",
		Timestamp:     findings.NewTimestamp(now),
		TotalFindings: 4,
	}

	findingsA := []findings.Finding{
		{
			ID:         "f1",
			Type:       "SQL Injection",
			Message:    "SQL injection found",
			Target:     "https://example.com/api/users",
			Severity:   findings.SeverityCritical,
			DetectedAt: findings.NewTimestamp(earlier),
		},
		{
			ID:         "f2",
			Type:       "XSS",
			Message:    "XSS found",
			Target:     "https://example.com/search",
			Severity:   findings.SeverityHigh,
			DetectedAt: findings.NewTimestamp(earlier),
		},
		{
			ID:         "f3",
			Type:       "CORS Misconfiguration",
			Message:    "CORS misconfiguration",
			Target:     "https://example.com",
			Severity:   findings.SeverityMedium,
			DetectedAt: findings.NewTimestamp(earlier),
		},
	}

	findingsB := []findings.Finding{
		{
			ID:         "f1",
			Type:       "SQL Injection",
			Message:    "SQL injection found",
			Target:     "https://example.com/api/users",
			Severity:   findings.SeverityCritical,
			DetectedAt: findings.NewTimestamp(now),
		},
		{
			ID:         "f2",
			Type:       "XSS",
			Message:    "XSS found",
			Target:     "https://example.com/search",
			Severity:   findings.SeverityHigh,
			DetectedAt: findings.NewTimestamp(now),
		},
		// f3 (CORS) is missing - should be marked as fixed
		{
			ID:         "f4",
			Type:       "Path Traversal",
			Message:    "Path traversal vulnerability",
			Target:     "https://example.com/files",
			Severity:   findings.SeverityHigh,
			DetectedAt: findings.NewTimestamp(now),
		},
		// New finding
		{
			ID:         "f5",
			Type:       "Open Redirect",
			Message:    "Open redirect found",
			Target:     "https://example.com/redirect",
			Severity:   findings.SeverityLow,
			DetectedAt: findings.NewTimestamp(now),
		},
	}

	opts := DefaultCompareOptions()
	result, err := Compare(summaryA, summaryB, findingsA, findingsB, opts)
	if err != nil {
		t.Fatalf("Compare() failed: %v", err)
	}

	// Verify results
	if result.Summary.NewCount != 2 {
		t.Errorf("Expected 2 new findings, got %d", result.Summary.NewCount)
	}

	if result.Summary.FixedCount != 1 {
		t.Errorf("Expected 1 fixed finding, got %d", result.Summary.FixedCount)
	}

	if result.Summary.UnchangedCount != 2 {
		t.Errorf("Expected 2 unchanged findings, got %d", result.Summary.UnchangedCount)
	}

	// Verify new findings
	if len(result.New) != 2 {
		t.Errorf("Expected 2 new findings in detailed list, got %d", len(result.New))
	}

	// Verify fixed findings
	if len(result.Fixed) != 1 {
		t.Errorf("Expected 1 fixed finding in detailed list, got %d", len(result.Fixed))
	} else {
		if result.Fixed[0].Type != "CORS Misconfiguration" {
			t.Errorf("Expected fixed finding to be CORS Misconfiguration, got %s", result.Fixed[0].Type)
		}
	}

	// Verify severity breakdown
	if result.Summary.NewBySeverity[findings.SeverityHigh] != 1 {
		t.Errorf("Expected 1 new high severity finding, got %d", result.Summary.NewBySeverity[findings.SeverityHigh])
	}
}

func TestHasNewCritical(t *testing.T) {
	result := &ComparisonResult{
		Summary: Summary{
			NewBySeverity: map[findings.Severity]int{
				findings.SeverityCritical: 1,
				findings.SeverityHigh:     2,
			},
		},
	}

	if !result.HasNewCritical() {
		t.Error("Expected HasNewCritical() to return true")
	}

	result2 := &ComparisonResult{
		Summary: Summary{
			NewBySeverity: map[findings.Severity]int{
				findings.SeverityHigh: 2,
			},
		},
	}

	if result2.HasNewCritical() {
		t.Error("Expected HasNewCritical() to return false")
	}
}

func TestGetImprovementScore(t *testing.T) {
	tests := []struct {
		name     string
		newSev   map[findings.Severity]int
		fixedSev map[findings.Severity]int
		wantSign string // "positive", "negative", "zero"
	}{
		{
			name: "more fixed than new - improvement",
			newSev: map[findings.Severity]int{
				findings.SeverityMedium: 2,
			},
			fixedSev: map[findings.Severity]int{
				findings.SeverityCritical: 2,
			},
			wantSign: "positive",
		},
		{
			name: "more new than fixed - worsening",
			newSev: map[findings.Severity]int{
				findings.SeverityCritical: 2,
			},
			fixedSev: map[findings.Severity]int{
				findings.SeverityMedium: 2,
			},
			wantSign: "negative",
		},
		{
			name:     "no changes - stable",
			newSev:   map[findings.Severity]int{},
			fixedSev: map[findings.Severity]int{},
			wantSign: "zero",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &ComparisonResult{
				Summary: Summary{
					NewBySeverity:   tt.newSev,
					FixedBySeverity: tt.fixedSev,
				},
			}

			score := result.GetImprovementScore()

			switch tt.wantSign {
			case "positive":
				if score <= 0 {
					t.Errorf("Expected positive score, got %d", score)
				}
			case "negative":
				if score >= 0 {
					t.Errorf("Expected negative score, got %d", score)
				}
			case "zero":
				if score != 0 {
					t.Errorf("Expected zero score, got %d", score)
				}
			}
		})
	}
}

func TestMeetsThreshold(t *testing.T) {
	tests := []struct {
		severity  findings.Severity
		threshold findings.Severity
		want      bool
	}{
		{findings.SeverityCritical, findings.SeverityInfo, true},
		{findings.SeverityCritical, findings.SeverityMedium, true},
		{findings.SeverityLow, findings.SeverityMedium, false},
		{findings.SeverityMedium, findings.SeverityMedium, true},
		{findings.SeverityInfo, findings.SeverityHigh, false},
	}

	for _, tt := range tests {
		got := meetsThreshold(tt.severity, tt.threshold)
		if got != tt.want {
			t.Errorf("meetsThreshold(%s, %s) = %v, want %v",
				tt.severity, tt.threshold, got, tt.want)
		}
	}
}

func TestGenerateFindingKey(t *testing.T) {
	f := findings.Finding{
		Type:    "SQL Injection",
		Target:  "https://example.com/api",
		Message: "SQL injection found",
	}

	opts := CompareOptions{MatchByType: true}
	key1 := generateFindingKey(f, opts)

	expected := "SQL Injection|https://example.com/api"
	if key1 != expected {
		t.Errorf("generateFindingKey() = %q, want %q", key1, expected)
	}

	opts.MatchByType = false
	key2 := generateFindingKey(f, opts)

	if key2 == key1 {
		t.Error("Expected different key when MatchByType is false")
	}
}

func TestDetectChanges(t *testing.T) {
	f1 := findings.Finding{
		Type:     "SQL Injection",
		Target:   "https://example.com/api",
		Message:  "SQL injection found",
		Severity: findings.SeverityHigh,
		Evidence: "payload: ' OR 1=1",
	}

	// Same finding
	f2 := f1

	opts := DefaultCompareOptions()
	changes := detectChanges(f1, f2, opts)
	if len(changes) != 0 {
		t.Errorf("Expected no changes for identical findings, got %d", len(changes))
	}

	// Different severity
	f3 := f1
	f3.Severity = findings.SeverityCritical

	changes = detectChanges(f1, f3, opts)
	if len(changes) == 0 {
		t.Error("Expected changes when severity differs")
	}

	// Check that severity change is detected
	foundSeverityChange := false
	for _, change := range changes {
		if change == "severity: high → crit" {
			foundSeverityChange = true
			break
		}
	}
	if !foundSeverityChange {
		t.Error("Expected severity change to be detected")
	}
}
