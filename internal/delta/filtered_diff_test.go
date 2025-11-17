package delta

import (
	"testing"
	"time"
)

func TestFilterDiff(t *testing.T) {
	// Create a diff result with mixed noise and signal
	result := &DiffResult{
		Type: DiffTypeJSON,
		Changes: []Change{
			{Path: "$.timestamp", OldValue: "2025-01-15T10:00:00Z", NewValue: "2025-01-15T10:01:00Z", Type: ChangeTypeModified},
			{Path: "$.user.role", OldValue: "user", NewValue: "admin", Type: ChangeTypeModified},
			{Path: "$.session_id", OldValue: "abc123xyz789def456ghi012jkl345", NewValue: "mno678pqr901stu234vwx567yza890", Type: ChangeTypeModified},
			{Path: "$.balance", OldValue: "100.00", NewValue: "99.50", Type: ChangeTypeModified},
			{Path: "$.request_id", OldValue: "550e8400-e29b-41d4-a716-446655440000", NewValue: "7c9e6679-7425-40de-944b-e07fc1f90ae7", Type: ChangeTypeModified},
		},
		SimilarityScore: 70.0,
		LeftSize:        1000,
		RightSize:       1000,
	}

	config := DefaultFilterConfig()
	filtered := FilterDiff(result, config)

	if filtered == nil {
		t.Fatal("Expected filtered result")
	}

	// Should have separated noise and signal
	if len(filtered.SignalChanges) == 0 {
		t.Error("Expected some signal changes")
	}

	if len(filtered.NoiseChanges) == 0 {
		t.Error("Expected some noise changes")
	}

	// Total should match original
	total := len(filtered.SignalChanges) + len(filtered.NoiseChanges)
	if total != len(result.Changes) {
		t.Errorf("Signal + noise should equal total: %d + %d != %d",
			len(filtered.SignalChanges), len(filtered.NoiseChanges), len(result.Changes))
	}

	// Should have classifications for all changes
	if len(filtered.Classifications) != len(result.Changes) {
		t.Errorf("Expected %d classifications, got %d",
			len(result.Changes), len(filtered.Classifications))
	}

	// Check filter stats
	if filtered.FilterStats.TotalChanges != len(result.Changes) {
		t.Errorf("Expected total changes %d, got %d",
			len(result.Changes), filtered.FilterStats.TotalChanges)
	}

	if filtered.FilterStats.FilteredPercentage < 0 || filtered.FilterStats.FilteredPercentage > 100 {
		t.Errorf("Filtered percentage should be 0-100, got %.2f", filtered.FilterStats.FilteredPercentage)
	}
}

func TestFilterDiff_DisabledCategories(t *testing.T) {
	result := &DiffResult{
		Type: DiffTypeJSON,
		Changes: []Change{
			{Path: "$.timestamp", OldValue: "2025-01-15T10:00:00Z", NewValue: "2025-01-15T10:01:00Z", Type: ChangeTypeModified},
			{Path: "$.version", OldValue: "1.0.0", NewValue: "1.0.1", Type: ChangeTypeModified},
		},
		SimilarityScore: 80.0,
		LeftSize:        100,
		RightSize:       100,
	}

	config := DefaultFilterConfig()
	// Disable timestamp filtering
	config.EnabledCategories[NoiseCategoryTimestamp] = false

	filtered := FilterDiff(result, config)

	// Timestamp should now be in signal (not filtered)
	signalPaths := make(map[string]bool)
	for _, change := range filtered.SignalChanges {
		signalPaths[change.Path] = true
	}

	if !signalPaths["$.timestamp"] {
		t.Error("Expected timestamp to be in signal when category disabled")
	}
}

func TestFilteredDiffResult_GetSignalResult(t *testing.T) {
	original := &DiffResult{
		Type: DiffTypeJSON,
		Changes: []Change{
			{Path: "$.timestamp", OldValue: "old", NewValue: "new", Type: ChangeTypeModified},
			{Path: "$.user.role", OldValue: "user", NewValue: "admin", Type: ChangeTypeModified},
		},
		SimilarityScore: 80.0,
		LeftSize:        100,
		RightSize:       100,
	}

	filtered := FilterDiff(original, DefaultFilterConfig())
	signalResult := filtered.GetSignalResult()

	if signalResult == nil {
		t.Fatal("Expected signal result")
	}

	if len(signalResult.Changes) != len(filtered.SignalChanges) {
		t.Errorf("Expected %d changes in signal result, got %d",
			len(filtered.SignalChanges), len(signalResult.Changes))
	}

	if signalResult.Type != original.Type {
		t.Errorf("Expected type %v, got %v", original.Type, signalResult.Type)
	}
}

func TestFilteredDiffResult_GetNoiseResult(t *testing.T) {
	original := &DiffResult{
		Type: DiffTypeJSON,
		Changes: []Change{
			{Path: "$.timestamp", OldValue: "2025-01-15T10:00:00Z", NewValue: "2025-01-15T10:01:00Z", Type: ChangeTypeModified},
			{Path: "$.session_id", OldValue: "abc123", NewValue: "xyz789", Type: ChangeTypeModified},
		},
		SimilarityScore: 50.0,
		LeftSize:        100,
		RightSize:       100,
	}

	filtered := FilterDiff(original, DefaultFilterConfig())
	noiseResult := filtered.GetNoiseResult()

	if noiseResult == nil {
		t.Fatal("Expected noise result")
	}

	if len(noiseResult.Changes) != len(filtered.NoiseChanges) {
		t.Errorf("Expected %d changes in noise result, got %d",
			len(filtered.NoiseChanges), len(noiseResult.Changes))
	}
}

func TestFilteredDiffResult_Summary(t *testing.T) {
	result := &DiffResult{
		Type: DiffTypeJSON,
		Changes: []Change{
			{Path: "$.test", OldValue: "old", NewValue: "new", Type: ChangeTypeModified},
		},
		SimilarityScore: 90.0,
		LeftSize:        100,
		RightSize:       100,
	}

	filtered := FilterDiff(result, DefaultFilterConfig())
	summary := filtered.Summary()

	if summary == "" {
		t.Error("Expected non-empty summary")
	}

	filterSummary := filtered.FilterSummary()
	if filterSummary == "" {
		t.Error("Expected non-empty filter summary")
	}
}

func TestFilteredDiffResult_ApplyUserFeedback(t *testing.T) {
	result := &DiffResult{
		Type: DiffTypeJSON,
		Changes: []Change{
			{Path: "$.custom_field", OldValue: "value1", NewValue: "value2", Type: ChangeTypeModified},
		},
		SimilarityScore: 90.0,
		LeftSize:        100,
		RightSize:       100,
	}

	filtered := FilterDiff(result, DefaultFilterConfig())

	// Initially might be classified as signal
	initialClassification := filtered.Classifications[0]

	// Apply user feedback
	classifier := NewNoiseClassifier()
	err := filtered.ApplyUserFeedback(0, FeedbackNoise, "User marked as noise", classifier)
	if err != nil {
		t.Fatalf("ApplyUserFeedback failed: %v", err)
	}

	// Classification should be updated
	updatedClassification := filtered.Classifications[0]
	if updatedClassification.IsNoise == initialClassification.IsNoise {
		// Only fail if feedback didn't change anything and it should have
		if !updatedClassification.UserOverride {
			t.Error("Expected classification to be updated with user feedback")
		}
	}
}

func TestFilteredDiffResult_GetFilterEfficiency(t *testing.T) {
	result := &DiffResult{
		Type: DiffTypeJSON,
		Changes: []Change{
			{Path: "$.timestamp", OldValue: "2025-01-15T10:00:00Z", NewValue: "2025-01-15T10:01:00Z", Type: ChangeTypeModified},
			{Path: "$.session_id", OldValue: "abc123", NewValue: "xyz789", Type: ChangeTypeModified},
			{Path: "$.user.role", OldValue: "user", NewValue: "admin", Type: ChangeTypeModified},
		},
		SimilarityScore: 70.0,
		LeftSize:        100,
		RightSize:       100,
	}

	filtered := FilterDiff(result, DefaultFilterConfig())
	efficiency := filtered.GetFilterEfficiency()

	if efficiency < 0 || efficiency > 1.0 {
		t.Errorf("Efficiency should be 0-1.0, got %.2f", efficiency)
	}
}

func TestFilteredDiffResult_GetCategoryBreakdown(t *testing.T) {
	result := &DiffResult{
		Type: DiffTypeJSON,
		Changes: []Change{
			{Path: "$.timestamp", OldValue: "2025-01-15T10:00:00Z", NewValue: "2025-01-15T10:01:00Z", Type: ChangeTypeModified},
			{Path: "$.created_at", OldValue: "1705318245", NewValue: "1705318345", Type: ChangeTypeModified},
			{Path: "$.uuid", OldValue: "550e8400-e29b-41d4-a716-446655440000", NewValue: "7c9e6679-7425-40de-944b-e07fc1f90ae7", Type: ChangeTypeModified},
		},
		SimilarityScore: 60.0,
		LeftSize:        100,
		RightSize:       100,
	}

	filtered := FilterDiff(result, DefaultFilterConfig())
	breakdown := filtered.GetCategoryBreakdown()

	// Should have some categories
	if len(breakdown) == 0 {
		t.Error("Expected some category matches")
	}

	// Verify counts are positive
	for category, count := range breakdown {
		if count <= 0 {
			t.Errorf("Category %v should have positive count, got %d", category, count)
		}
	}
}

func TestFilterDiff_NilResult(t *testing.T) {
	config := DefaultFilterConfig()
	filtered := FilterDiff(nil, config)

	if filtered == nil {
		t.Fatal("Expected filtered result even with nil input")
	}

	if filtered.Original != nil {
		t.Error("Expected Original to be nil")
	}

	if len(filtered.SignalChanges) != 0 {
		t.Error("Expected no signal changes for nil result")
	}
}

func TestDefaultFilterConfig(t *testing.T) {
	config := DefaultFilterConfig()

	if !config.Enabled {
		t.Error("Expected filtering to be enabled by default")
	}

	if config.ConfidenceThreshold != 0.8 {
		t.Errorf("Expected confidence threshold 0.8, got %.2f", config.ConfidenceThreshold)
	}

	// Check that some categories are enabled
	enabledCount := 0
	for _, enabled := range config.EnabledCategories {
		if enabled {
			enabledCount++
		}
	}

	if enabledCount == 0 {
		t.Error("Expected some categories to be enabled by default")
	}

	// Timestamp should be enabled by default
	if !config.EnabledCategories[NoiseCategoryTimestamp] {
		t.Error("Expected timestamp category to be enabled")
	}

	// Build ID should be disabled by default (might be relevant)
	if config.EnabledCategories[NoiseCategoryBuildID] {
		t.Error("Expected build ID category to be disabled by default")
	}
}

func TestFilteredDiffResult_ToggleFilter(t *testing.T) {
	result := &DiffResult{
		Type:            DiffTypeJSON,
		Changes:         []Change{{Path: "$.test", OldValue: "old", NewValue: "new", Type: ChangeTypeModified}},
		SimilarityScore: 90.0,
		LeftSize:        100,
		RightSize:       100,
	}

	filtered := FilterDiff(result, DefaultFilterConfig())

	// Toggle off
	filtered.ToggleFilter(false)
	if filtered.FilterSettings.Enabled {
		t.Error("Expected filtering to be disabled after toggle")
	}

	// Toggle on
	filtered.ToggleFilter(true)
	if !filtered.FilterSettings.Enabled {
		t.Error("Expected filtering to be enabled after toggle")
	}
}

func TestFilteredDiffResult_IsFiltered(t *testing.T) {
	// Result with noise
	result1 := &DiffResult{
		Type: DiffTypeJSON,
		Changes: []Change{
			{Path: "$.timestamp", OldValue: "2025-01-15T10:00:00Z", NewValue: "2025-01-15T10:01:00Z", Type: ChangeTypeModified},
		},
		SimilarityScore: 90.0,
		LeftSize:        100,
		RightSize:       100,
	}

	filtered1 := FilterDiff(result1, DefaultFilterConfig())
	if !filtered1.IsFiltered() {
		t.Error("Expected IsFiltered to be true when noise changes exist")
	}

	// Result with no noise (all signal)
	result2 := &DiffResult{
		Type: DiffTypeJSON,
		Changes: []Change{
			{Path: "$.user.role", OldValue: "user", NewValue: "admin", Type: ChangeTypeModified},
		},
		SimilarityScore: 90.0,
		LeftSize:        100,
		RightSize:       100,
	}

	filtered2 := FilterDiff(result2, DefaultFilterConfig())
	if filtered2.IsFiltered() && len(filtered2.NoiseChanges) == 0 {
		t.Error("Expected IsFiltered to be false when no noise changes exist")
	}
}

// Benchmark filtering performance

func BenchmarkFilterDiff_Small(b *testing.B) {
	result := &DiffResult{
		Type: DiffTypeJSON,
		Changes: []Change{
			{Path: "$.timestamp", OldValue: "2025-01-15T10:00:00Z", NewValue: "2025-01-15T10:01:00Z", Type: ChangeTypeModified},
			{Path: "$.user.role", OldValue: "user", NewValue: "admin", Type: ChangeTypeModified},
			{Path: "$.session_id", OldValue: "abc123", NewValue: "xyz789", Type: ChangeTypeModified},
		},
		SimilarityScore: 80.0,
		LeftSize:        100,
		RightSize:       100,
	}

	config := DefaultFilterConfig()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = FilterDiff(result, config)
	}
}

func BenchmarkFilterDiff_Large(b *testing.B) {
	// Create a large diff result
	changes := make([]Change, 100)
	for i := 0; i < 100; i++ {
		if i%2 == 0 {
			changes[i] = Change{
				Path:     "$.timestamp",
				OldValue: "2025-01-15T10:00:00Z",
				NewValue: "2025-01-15T10:01:00Z",
				Type:     ChangeTypeModified,
			}
		} else {
			changes[i] = Change{
				Path:     "$.data.value",
				OldValue: "old",
				NewValue: "new",
				Type:     ChangeTypeModified,
			}
		}
	}

	result := &DiffResult{
		Type:            DiffTypeJSON,
		Changes:         changes,
		SimilarityScore: 70.0,
		LeftSize:        10000,
		RightSize:       10000,
	}

	config := DefaultFilterConfig()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = FilterDiff(result, config)
	}
}

func TestFilterPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping performance test in short mode")
	}

	// Create a realistic diff with 50 changes
	changes := make([]Change, 50)
	for i := 0; i < 50; i++ {
		if i%5 == 0 {
			// Noise
			changes[i] = Change{
				Path:     "$.timestamp",
				OldValue: "2025-01-15T10:00:00Z",
				NewValue: "2025-01-15T10:01:00Z",
				Type:     ChangeTypeModified,
			}
		} else {
			// Signal
			changes[i] = Change{
				Path:     "$.data.field",
				OldValue: "value1",
				NewValue: "value2",
				Type:     ChangeTypeModified,
			}
		}
	}

	result := &DiffResult{
		Type:            DiffTypeJSON,
		Changes:         changes,
		SimilarityScore: 75.0,
		LeftSize:        5000,
		RightSize:       5000,
	}

	config := DefaultFilterConfig()

	start := time.Now()
	filtered := FilterDiff(result, config)
	elapsed := time.Since(start)

	t.Logf("Filtered 50 changes in %v", elapsed)
	t.Logf("  Noise: %d, Signal: %d", len(filtered.NoiseChanges), len(filtered.SignalChanges))
	t.Logf("  Filtered: %.1f%%", filtered.FilterStats.FilteredPercentage)

	// Should complete in under 100ms
	if elapsed > 100*time.Millisecond {
		t.Errorf("Filtering took too long: %v (want <100ms)", elapsed)
	}
}
