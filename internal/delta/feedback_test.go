package delta

import (
	"testing"
)

func TestFeedbackStore_AddFeedback(t *testing.T) {
	store := NewFeedbackStore()

	entry := store.AddFeedback("$.timestamp", "value1", "value2", FeedbackNoise, "User marked as noise")

	if entry == nil {
		t.Fatal("Expected feedback entry")
	}

	if entry.Path != "$.timestamp" {
		t.Errorf("Expected path $.timestamp, got %s", entry.Path)
	}

	if entry.Feedback != FeedbackNoise {
		t.Errorf("Expected feedback type %v, got %v", FeedbackNoise, entry.Feedback)
	}

	if entry.Confidence != 1.0 {
		t.Errorf("Expected confidence 1.0, got %.2f", entry.Confidence)
	}

	// Check stats
	stats := store.GetStats()
	if stats.TotalFeedback != 1 {
		t.Errorf("Expected 1 total feedback, got %d", stats.TotalFeedback)
	}

	if stats.NoiseFeedback != 1 {
		t.Errorf("Expected 1 noise feedback, got %d", stats.NoiseFeedback)
	}
}

func TestFeedbackStore_GetClassification(t *testing.T) {
	store := NewFeedbackStore()

	// Add feedback
	store.AddFeedback("$.test", "old", "new", FeedbackNoise, "Test reason")

	// Get classification
	classification := store.GetClassification("$.test", "old", "new")

	if classification == nil {
		t.Fatal("Expected classification")
	}

	if !classification.IsNoise {
		t.Error("Expected IsNoise to be true")
	}

	if !classification.UserOverride {
		t.Error("Expected UserOverride to be true")
	}

	// Get classification for non-existent feedback
	classification2 := store.GetClassification("$.other", "a", "b")
	if classification2 != nil {
		t.Error("Expected nil classification for non-existent feedback")
	}
}

func TestFeedbackStore_UpdateFeedback(t *testing.T) {
	store := NewFeedbackStore()

	// Add initial feedback
	entry1 := store.AddFeedback("$.test", "old", "new", FeedbackNoise, "Initial")

	// Update feedback (add with same path/values)
	entry2 := store.AddFeedback("$.test", "old", "new", FeedbackSignal, "Updated")

	// Should be same ID (updated, not new)
	if entry1.ID != entry2.ID {
		t.Error("Expected same feedback entry to be updated")
	}

	if entry2.Feedback != FeedbackSignal {
		t.Errorf("Expected feedback to be updated to %v, got %v", FeedbackSignal, entry2.Feedback)
	}

	// Stats should still show 1 total
	stats := store.GetStats()
	if stats.TotalFeedback != 1 {
		t.Errorf("Expected 1 total feedback after update, got %d", stats.TotalFeedback)
	}
}

func TestFeedbackStore_GetFeedbackByPath(t *testing.T) {
	store := NewFeedbackStore()

	// Add multiple feedback entries
	store.AddFeedback("$.timestamp", "val1", "val2", FeedbackNoise, "Test 1")
	store.AddFeedback("$.timestamp", "val3", "val4", FeedbackNoise, "Test 2")
	store.AddFeedback("$.other", "val5", "val6", FeedbackSignal, "Test 3")

	// Get feedback for specific path
	feedback := store.GetFeedbackByPath("$.timestamp")

	if len(feedback) != 2 {
		t.Errorf("Expected 2 feedback entries for $.timestamp, got %d", len(feedback))
	}

	// Get feedback for path with no entries
	feedback2 := store.GetFeedbackByPath("$.nonexistent")
	if len(feedback2) != 0 {
		t.Errorf("Expected 0 feedback entries for nonexistent path, got %d", len(feedback2))
	}
}

func TestFeedbackStore_GetAllFeedback(t *testing.T) {
	store := NewFeedbackStore()

	// Add several entries
	store.AddFeedback("$.path1", "a", "b", FeedbackNoise, "Test 1")
	store.AddFeedback("$.path2", "c", "d", FeedbackSignal, "Test 2")
	store.AddFeedback("$.path3", "e", "f", FeedbackNoise, "Test 3")

	all := store.GetAllFeedback()

	if len(all) != 3 {
		t.Errorf("Expected 3 feedback entries, got %d", len(all))
	}
}

func TestFeedbackStore_DeleteFeedback(t *testing.T) {
	store := NewFeedbackStore()

	entry := store.AddFeedback("$.test", "old", "new", FeedbackNoise, "Test")

	// Delete the entry
	err := store.DeleteFeedback(entry.ID)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify it's gone
	all := store.GetAllFeedback()
	if len(all) != 0 {
		t.Errorf("Expected 0 entries after delete, got %d", len(all))
	}

	// Stats should be updated
	stats := store.GetStats()
	if stats.TotalFeedback != 0 {
		t.Errorf("Expected 0 total feedback after delete, got %d", stats.TotalFeedback)
	}

	// Try to delete non-existent entry
	err = store.DeleteFeedback("nonexistent")
	if err == nil {
		t.Error("Expected error when deleting non-existent entry")
	}
}

func TestFeedbackStore_ExportDataset(t *testing.T) {
	store := NewFeedbackStore()

	// Add feedback entries
	store.AddFeedback("$.timestamp", "2025-01-15T10:00:00Z", "2025-01-15T10:01:00Z", FeedbackNoise, "Timestamp")
	store.AddFeedback("$.user.role", "user", "admin", FeedbackSignal, "Role change")
	store.AddFeedback("$.session_id", "abc123", "xyz789", FeedbackNoise, "Session ID")

	dataset := store.ExportDataset()

	if len(dataset) != 3 {
		t.Errorf("Expected 3 datapoints, got %d", len(dataset))
	}

	// Verify structure
	for _, dp := range dataset {
		if dp.Path == "" {
			t.Error("Datapoint path should not be empty")
		}
		if dp.Label == "" {
			t.Error("Datapoint label should not be empty")
		}
		if dp.Label != "noise" && dp.Label != "signal" {
			t.Errorf("Invalid label: %s", dp.Label)
		}
	}
}

func TestFeedbackStore_FindSimilarFeedback(t *testing.T) {
	store := NewFeedbackStore()

	// Add feedback entries
	store.AddFeedback("$.timestamp", "2025-01-15T10:00:00Z", "2025-01-15T10:01:00Z", FeedbackNoise, "Test 1")
	store.AddFeedback("$.timestamp", "2025-01-15T11:00:00Z", "2025-01-15T11:01:00Z", FeedbackNoise, "Test 2")
	store.AddFeedback("$.user.name", "Alice", "Bob", FeedbackSignal, "Test 3")

	// Find similar feedback
	similar := store.FindSimilarFeedback("$.timestamp", "2025-01-15T12:00:00Z", "2025-01-15T12:01:00Z", 10)

	// Should find the timestamp entries as similar
	if len(similar) == 0 {
		t.Error("Expected to find similar feedback")
	}

	// First result should be most similar
	if similar[0].Similarity <= 0 {
		t.Errorf("Expected positive similarity score, got %.2f", similar[0].Similarity)
	}
}

func TestFeedbackStore_RecordAccuracyImprovement(t *testing.T) {
	store := NewFeedbackStore()

	stats := store.GetStats()
	if stats.AccuracyImprovements != 0 {
		t.Error("Expected 0 accuracy improvements initially")
	}

	store.RecordAccuracyImprovement()
	store.RecordAccuracyImprovement()

	stats = store.GetStats()
	if stats.AccuracyImprovements != 2 {
		t.Errorf("Expected 2 accuracy improvements, got %d", stats.AccuracyImprovements)
	}
}

func TestFeedbackStore_Clear(t *testing.T) {
	store := NewFeedbackStore()

	// Add some entries
	store.AddFeedback("$.test1", "a", "b", FeedbackNoise, "Test")
	store.AddFeedback("$.test2", "c", "d", FeedbackSignal, "Test")

	// Clear
	store.Clear()

	// Verify everything is cleared
	all := store.GetAllFeedback()
	if len(all) != 0 {
		t.Errorf("Expected 0 entries after clear, got %d", len(all))
	}

	stats := store.GetStats()
	if stats.TotalFeedback != 0 {
		t.Errorf("Expected stats to be reset, got %d total", stats.TotalFeedback)
	}
}

func TestFeedbackStore_Concurrent(t *testing.T) {
	store := NewFeedbackStore()

	// Test concurrent writes
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(n int) {
			store.AddFeedback("$.test", "old", "new", FeedbackNoise, "Concurrent test")
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Should have 1 entry (all same path/values, should update not create)
	all := store.GetAllFeedback()
	if len(all) != 1 {
		t.Errorf("Expected 1 entry after concurrent updates, got %d", len(all))
	}
}

func TestPathSimilarity(t *testing.T) {
	tests := []struct {
		name      string
		pathA     string
		pathB     string
		minScore  float64
		maxScore  float64
	}{
		{
			name:      "identical paths",
			pathA:     "$.user.name",
			pathB:     "$.user.name",
			minScore:  1.0,
			maxScore:  1.0,
		},
		{
			name:      "similar paths",
			pathA:     "$.user.email",
			pathB:     "$.user.name",
			minScore:  0.6,
			maxScore:  0.7,
		},
		{
			name:      "completely different",
			pathA:     "$.user.name",
			pathB:     "$.session.id",
			minScore:  0.0,
			maxScore:  0.5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := pathSimilarity(tt.pathA, tt.pathB)
			if score < tt.minScore || score > tt.maxScore {
				t.Errorf("Expected score between %.2f and %.2f, got %.2f",
					tt.minScore, tt.maxScore, score)
			}
		})
	}
}
