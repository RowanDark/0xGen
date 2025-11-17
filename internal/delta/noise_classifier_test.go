package delta

import (
	"testing"
)

func TestNoiseClassifier_Classify(t *testing.T) {
	classifier := NewNoiseClassifier()

	tests := []struct {
		name          string
		change        Change
		expectNoise   bool
		minConfidence float64
	}{
		{
			name: "Timestamp change - noise",
			change: Change{
				Type:     ChangeTypeModified,
				Path:     "$.timestamp",
				OldValue: "2025-01-15T10:00:00Z",
				NewValue: "2025-01-15T10:01:00Z",
			},
			expectNoise:   true,
			minConfidence: 0.8,
		},
		{
			name: "Session ID change - noise",
			change: Change{
				Type:     ChangeTypeModified,
				Path:     "$.session_id",
				OldValue: "abc123xyz789def456ghi012jkl345mno678pqr901stu234vwx567yza890",
				NewValue: "zzz999yyy888xxx777www666vvv555uuu444ttt333sss222rrr111qqq000",
			},
			expectNoise:   true,
			minConfidence: 0.75,
		},
		{
			name: "User role change - signal",
			change: Change{
				Type:     ChangeTypeModified,
				Path:     "$.user.role",
				OldValue: "user",
				NewValue: "admin",
			},
			expectNoise: false,
		},
		{
			name: "Balance change - signal",
			change: Change{
				Type:     ChangeTypeModified,
				Path:     "$.account.balance",
				OldValue: "100.00",
				NewValue: "99.50",
			},
			expectNoise: false,
		},
		{
			name: "UUID change - noise",
			change: Change{
				Type:     ChangeTypeModified,
				Path:     "$.request_id",
				OldValue: "550e8400-e29b-41d4-a716-446655440000",
				NewValue: "7c9e6679-7425-40de-944b-e07fc1f90ae7",
			},
			expectNoise:   true,
			minConfidence: 0.85,
		},
		{
			name: "Unix timestamp change - noise",
			change: Change{
				Type:     ChangeTypeModified,
				Path:     "$.created_at",
				OldValue: "1705318245",
				NewValue: "1705318345",
			},
			expectNoise:   true,
			minConfidence: 0.8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			classification := classifier.Classify(tt.change)

			if classification.IsNoise != tt.expectNoise {
				t.Errorf("Expected IsNoise=%v, got %v (reason: %s)",
					tt.expectNoise, classification.IsNoise, classification.Reason)
			}

			if tt.expectNoise && classification.Confidence < tt.minConfidence {
				t.Errorf("Expected confidence >= %.2f for noise, got %.2f",
					tt.minConfidence, classification.Confidence)
			}
		})
	}
}

func TestNoiseClassifier_SetConfidenceThreshold(t *testing.T) {
	classifier := NewNoiseClassifier()

	// Default threshold
	change := Change{
		Type:     ChangeTypeModified,
		Path:     "$.test",
		OldValue: "value1",
		NewValue: "value2",
	}

	// Lower threshold to make more things noise
	classifier.SetConfidenceThreshold(0.5)
	_ = classifier.Classify(change) // Test that it works with new threshold

	// Verify threshold was set
	if classifier.confidenceThreshold != 0.5 {
		t.Errorf("Expected threshold 0.5, got %.2f", classifier.confidenceThreshold)
	}

	// Test invalid thresholds
	classifier.SetConfidenceThreshold(-0.1) // Should be ignored
	if classifier.confidenceThreshold != 0.5 {
		t.Error("Negative threshold should be ignored")
	}

	classifier.SetConfidenceThreshold(1.5) // Should be ignored
	if classifier.confidenceThreshold != 0.5 {
		t.Error("Threshold > 1.0 should be ignored")
	}
}

func TestNoiseClassifier_UserFeedback(t *testing.T) {
	feedback := NewFeedbackStore()
	classifier := NewNoiseClassifierWithFeedback(feedback)

	change := Change{
		Type:     ChangeTypeModified,
		Path:     "$.special_field",
		OldValue: "value1",
		NewValue: "value2",
	}

	// Without feedback, might not be classified as noise
	_ = classifier.Classify(change) // Just checking it works

	// Add user feedback saying it's noise
	feedback.AddFeedback(change.Path, change.OldValue, change.NewValue, FeedbackNoise, "User marked as noise")

	// Classify again - should now be noise due to feedback
	classification2 := classifier.Classify(change)

	if !classification2.IsNoise {
		t.Error("Expected classification to be noise after user feedback")
	}

	if !classification2.UserOverride {
		t.Error("Expected UserOverride to be true")
	}

	if classification2.Confidence != 1.0 {
		t.Errorf("Expected confidence 1.0 for user feedback, got %.2f", classification2.Confidence)
	}
}

func TestNoiseClassifier_FilterChanges(t *testing.T) {
	classifier := NewNoiseClassifier()

	changes := []Change{
		{
			Type:     ChangeTypeModified,
			Path:     "$.timestamp",
			OldValue: "2025-01-15T10:00:00Z",
			NewValue: "2025-01-15T10:01:00Z",
		},
		{
			Type:     ChangeTypeModified,
			Path:     "$.user.role",
			OldValue: "user",
			NewValue: "admin",
		},
		{
			Type:     ChangeTypeModified,
			Path:     "$.session_id",
			OldValue: "abc123xyz789def456ghi012jkl345mno678pqr901stu234",
			NewValue: "xyz789abc123ghi012jkl345mno678pqr901stu234vwx567",
		},
		{
			Type:     ChangeTypeModified,
			Path:     "$.balance",
			OldValue: "100",
			NewValue: "99",
		},
	}

	signal, noise := classifier.FilterChanges(changes)

	// We expect at least timestamp and session_id to be noise
	if len(noise) < 2 {
		t.Errorf("Expected at least 2 noise changes, got %d", len(noise))
	}

	// We expect at least role and balance to be signal
	if len(signal) < 2 {
		t.Errorf("Expected at least 2 signal changes, got %d", len(signal))
	}

	// Verify total
	if len(signal)+len(noise) != len(changes) {
		t.Errorf("Signal + noise should equal total changes: %d + %d != %d",
			len(signal), len(noise), len(changes))
	}
}

func TestNoiseClassifier_ClassifyBatch(t *testing.T) {
	classifier := NewNoiseClassifier()

	changes := []Change{
		{Path: "$.timestamp", OldValue: "2025-01-15T10:00:00Z", NewValue: "2025-01-15T10:01:00Z", Type: ChangeTypeModified},
		{Path: "$.user.name", OldValue: "Alice", NewValue: "Bob", Type: ChangeTypeModified},
		{Path: "$.uuid", OldValue: "550e8400-e29b-41d4-a716-446655440000", NewValue: "7c9e6679-7425-40de-944b-e07fc1f90ae7", Type: ChangeTypeModified},
	}

	classifications := classifier.ClassifyBatch(changes)

	if len(classifications) != len(changes) {
		t.Errorf("Expected %d classifications, got %d", len(changes), len(classifications))
	}

	// Check that at least some are classified as noise
	noiseCount := 0
	for _, class := range classifications {
		if class.IsNoise {
			noiseCount++
		}
	}

	if noiseCount < 2 {
		t.Errorf("Expected at least 2 noise classifications, got %d", noiseCount)
	}
}

func TestNoiseClassifier_GetStatistics(t *testing.T) {
	classifier := NewNoiseClassifier()

	classifications := []NoiseClassification{
		{IsNoise: true, Confidence: 0.9},
		{IsNoise: true, Confidence: 0.95},
		{IsNoise: false, Confidence: 0.85},
		{IsNoise: false, Confidence: 0.9},
		{IsNoise: true, Confidence: 0.88},
	}

	stats := classifier.GetStatistics(classifications)

	if stats.TotalChanges != 5 {
		t.Errorf("Expected 5 total changes, got %d", stats.TotalChanges)
	}

	if stats.NoiseCount != 3 {
		t.Errorf("Expected 3 noise changes, got %d", stats.NoiseCount)
	}

	if stats.SignalCount != 2 {
		t.Errorf("Expected 2 signal changes, got %d", stats.SignalCount)
	}

	if stats.NoisePercentage < 59 || stats.NoisePercentage > 61 {
		t.Errorf("Expected noise percentage around 60%%, got %.2f%%", stats.NoisePercentage)
	}

	// Check average confidences
	expectedAvgNoise := (0.9 + 0.95 + 0.88) / 3
	if stats.AvgNoiseConfidence < expectedAvgNoise-0.01 || stats.AvgNoiseConfidence > expectedAvgNoise+0.01 {
		t.Errorf("Expected avg noise confidence %.2f, got %.2f", expectedAvgNoise, stats.AvgNoiseConfidence)
	}
}

func TestHelperFunctions(t *testing.T) {
	tests := []struct {
		name     string
		testFunc func() bool
		expect   bool
	}{
		{"isNumeric - valid", func() bool { return isNumeric("123456") }, true},
		{"isNumeric - invalid", func() bool { return isNumeric("12a34") }, false},
		{"isNumeric - empty", func() bool { return isNumeric("") }, false},
		{"isHexString - valid", func() bool { return isHexString("abc123def456") }, true},
		{"isHexString - invalid", func() bool { return isHexString("xyz") }, false},
		{"isHexString - empty", func() bool { return isHexString("") }, false},
		{"isUUIDFormat - valid", func() bool { return isUUIDFormat("550e8400-e29b-41d4-a716-446655440000") }, true},
		{"isUUIDFormat - invalid", func() bool { return isUUIDFormat("not-a-uuid") }, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.testFunc()
			if result != tt.expect {
				t.Errorf("Expected %v, got %v", tt.expect, result)
			}
		})
	}
}

// Benchmarks

func BenchmarkClassify_Timestamp(b *testing.B) {
	classifier := NewNoiseClassifier()
	change := Change{
		Type:     ChangeTypeModified,
		Path:     "$.timestamp",
		OldValue: "2025-01-15T10:00:00Z",
		NewValue: "2025-01-15T10:01:00Z",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = classifier.Classify(change)
	}
}

func BenchmarkClassify_UserRole(b *testing.B) {
	classifier := NewNoiseClassifier()
	change := Change{
		Type:     ChangeTypeModified,
		Path:     "$.user.role",
		OldValue: "user",
		NewValue: "admin",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = classifier.Classify(change)
	}
}

func BenchmarkFilterChanges_Mixed(b *testing.B) {
	classifier := NewNoiseClassifier()
	changes := []Change{
		{Path: "$.timestamp", OldValue: "2025-01-15T10:00:00Z", NewValue: "2025-01-15T10:01:00Z", Type: ChangeTypeModified},
		{Path: "$.user.role", OldValue: "user", NewValue: "admin", Type: ChangeTypeModified},
		{Path: "$.session_id", OldValue: "abc123", NewValue: "xyz789", Type: ChangeTypeModified},
		{Path: "$.balance", OldValue: "100", NewValue: "99", Type: ChangeTypeModified},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = classifier.FilterChanges(changes)
	}
}
