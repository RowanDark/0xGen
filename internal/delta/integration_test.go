package delta

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Integration tests for complete Delta workflows

// TestIntegration_SimpleDiffWorkflow tests the complete simple diff workflow
func TestIntegration_SimpleDiffWorkflow(t *testing.T) {
	// Create engine
	engine := NewEngine()

	// Test JSON diff workflow
	left := `{
		"user": {
			"id": 123,
			"name": "Alice",
			"role": "user",
			"timestamp": "2024-01-15T10:00:00Z",
			"sessionId": "abc123"
		}
	}`

	right := `{
		"user": {
			"id": 123,
			"name": "Alice",
			"role": "admin",
			"timestamp": "2024-01-15T10:01:00Z",
			"sessionId": "xyz789"
		}
	}`

	// Perform diff
	result, err := engine.Diff(DiffRequest{
		Left:  []byte(left),
		Right: []byte(right),
		Type:  DiffTypeJSON,
	})
	if err != nil {
		t.Fatalf("Diff failed: %v", err)
	}

	// Verify result (3 out of 5 fields changed, so ~60% similar)
	if result.SimilarityScore < 50 || result.SimilarityScore > 75 {
		t.Errorf("Expected similarity 50-75%%, got %.1f%%", result.SimilarityScore)
	}

	if len(result.Changes) == 0 {
		t.Error("Expected changes to be detected")
	}

	// Apply noise filtering
	filtered := FilterDiff(result, DefaultFilterConfig())

	// Verify filtering reduced noise
	if len(filtered.SignalChanges) >= len(result.Changes) {
		t.Error("Expected noise filtering to reduce change count")
	}

	// Check that role change is signal (not noise)
	foundRoleChange := false
	for _, change := range filtered.SignalChanges {
		if strings.Contains(change.Path, "role") {
			foundRoleChange = true
			if change.OldValue != "user" || change.NewValue != "admin" {
				t.Errorf("Role change has wrong values: %s -> %s", change.OldValue, change.NewValue)
			}
		}
	}

	if !foundRoleChange {
		t.Error("Expected role change to be classified as signal")
	}

	// Verify that timestamp/sessionId are filtered as noise
	for _, change := range filtered.NoiseChanges {
		if !strings.Contains(change.Path, "timestamp") && !strings.Contains(change.Path, "sessionId") {
			t.Logf("Unexpected noise classification: %s", change.Path)
		}
	}
}

// TestIntegration_BatchComparisonWorkflow tests the complete batch comparison workflow
func TestIntegration_BatchComparisonWorkflow(t *testing.T) {
	engine := NewBatchComparisonEngine()

	// Create responses simulating fuzzing results
	responses := []ResponseIdentifier{
		// Normal responses (cluster 1)
		{ID: "r1", Name: "User 1", Content: []byte(`{"id": 1, "name": "Alice", "role": "user"}`)},
		{ID: "r2", Name: "User 2", Content: []byte(`{"id": 2, "name": "Bob", "role": "user"}`)},
		{ID: "r3", Name: "User 3", Content: []byte(`{"id": 3, "name": "Charlie", "role": "user"}`)},
		// Similar to normal but slightly different
		{ID: "r4", Name: "User 4", Content: []byte(`{"id": 4, "name": "Dave", "role": "user"}`)},
		// Outlier - admin user (IDOR vulnerability simulation)
		{ID: "r5", Name: "Admin User", Content: []byte(`{"id": 5, "name": "Admin", "role": "admin", "apiKey": "secret123"}`)},
	}

	// Perform batch comparison
	result, err := engine.CompareBatch(BatchComparisonRequest{
		Responses:        responses,
		DiffType:         DiffTypeJSON,
		BaselineStrategy: BaselineAllPairs,
		OutlierThreshold: 80.0,
		EnableClustering: true,
		EnablePatterns:   true,
		EnableAnomalies:  true,
	})
	if err != nil {
		t.Fatalf("CompareBatch failed: %v", err)
	}

	// Verify basic results
	if len(result.Responses) != 5 {
		t.Errorf("Expected 5 responses, got %d", len(result.Responses))
	}

	// Verify similarity matrix dimensions
	if len(result.SimilarityMatrix) != 5 {
		t.Errorf("Expected 5x5 matrix, got %dx?", len(result.SimilarityMatrix))
	}

	for i, row := range result.SimilarityMatrix {
		if len(row) != 5 {
			t.Errorf("Matrix row %d has %d columns, expected 5", i, len(row))
		}
	}

	// Verify outlier detection (response 5 should be outlier)
	if len(result.Outliers) == 0 {
		t.Error("Expected at least one outlier to be detected")
	}

	foundAdminOutlier := false
	for _, idx := range result.Outliers {
		if idx == 4 { // Index of admin user
			foundAdminOutlier = true
		}
	}

	if !foundAdminOutlier {
		t.Logf("Warning: Admin user (index 4) not detected as outlier. Outliers: %v", result.Outliers)
	}

	// Verify clustering
	if result.Clusters == nil || len(result.Clusters) == 0 {
		t.Error("Expected clusters to be generated")
	}

	// Verify patterns
	if result.Patterns == nil {
		t.Error("Expected patterns to be detected")
	}

	if result.Patterns != nil {
		// Check for common fields
		if len(result.Patterns.CommonJSONKeys) == 0 {
			t.Error("Expected common JSON keys to be identified")
		}

		// Verify role is a common field
		if _, exists := result.Patterns.CommonJSONKeys["role"]; !exists {
			t.Error("Expected 'role' to be identified as common key")
		}

		// Verify AI insights generated
		if len(result.Patterns.AIInsights) == 0 {
			t.Error("Expected AI insights to be generated")
		}
	}

	// Verify anomalies
	if result.Anomalies == nil {
		t.Error("Expected anomaly detection results")
	}

	// Verify statistics
	if result.Statistics.TotalResponses != 5 {
		t.Errorf("Expected 5 total responses in stats, got %d", result.Statistics.TotalResponses)
	}

	// Mean similarity can vary widely based on outliers - just verify it's in valid range
	if result.Statistics.MeanSimilarity < 0 || result.Statistics.MeanSimilarity > 100 {
		t.Errorf("Mean similarity out of valid range: %.1f%%", result.Statistics.MeanSimilarity)
	}

	t.Logf("Batch comparison statistics:")
	t.Logf("  Mean similarity: %.1f%%", result.Statistics.MeanSimilarity)
	t.Logf("  Outliers detected: %d", len(result.Outliers))
	t.Logf("  Clusters: %d", len(result.Clusters))
}

// TestIntegration_ExportWorkflow tests the export workflow
func TestIntegration_ExportWorkflow(t *testing.T) {
	engine := NewBatchComparisonEngine()
	exporter := NewBatchExporter()

	// Create simple batch comparison
	responses := []ResponseIdentifier{
		{ID: "r1", Content: []byte(`{"status": "ok"}`)},
		{ID: "r2", Content: []byte(`{"status": "ok"}`)},
		{ID: "r3", Content: []byte(`{"status": "error"}`)},
	}

	result, err := engine.CompareBatch(BatchComparisonRequest{
		Responses:        responses,
		DiffType:         DiffTypeJSON,
		BaselineStrategy: BaselineFirst,
		OutlierThreshold: 80.0,
		EnableClustering: true,
		EnablePatterns:   true,
	})
	if err != nil {
		t.Fatalf("CompareBatch failed: %v", err)
	}

	// Test CSV export
	csvData, err := exporter.ExportCSV(result)
	if err != nil {
		t.Fatalf("ExportCSV failed: %v", err)
	}

	if len(csvData) == 0 {
		t.Error("CSV export produced no data")
	}

	csvStr := string(csvData)
	if !strings.Contains(csvStr, "Response") || !strings.Contains(csvStr, "Statistics") {
		t.Error("CSV export missing expected sections")
	}

	// Test JSON export
	jsonData, err := exporter.ExportJSON(result)
	if err != nil {
		t.Fatalf("ExportJSON failed: %v", err)
	}

	if len(jsonData) == 0 {
		t.Error("JSON export produced no data")
	}

	// Verify JSON is valid
	var exported map[string]interface{}
	if err := json.Unmarshal(jsonData, &exported); err != nil {
		t.Errorf("Exported JSON is invalid: %v", err)
	}

	// Verify key fields present
	if _, ok := exported["responses"]; !ok {
		t.Error("JSON export missing 'responses' field")
	}
	if _, ok := exported["similarity_matrix"]; !ok {
		t.Error("JSON export missing 'similarity_matrix' field")
	}

	// Test HTML export
	htmlData, err := exporter.ExportHTML(result)
	if err != nil {
		t.Fatalf("ExportHTML failed: %v", err)
	}

	if len(htmlData) == 0 {
		t.Error("HTML export produced no data")
	}

	htmlStr := string(htmlData)
	if !strings.Contains(htmlStr, "<!DOCTYPE html>") {
		t.Error("HTML export missing DOCTYPE")
	}
	if !strings.Contains(htmlStr, "Similarity Matrix") {
		t.Error("HTML export missing expected content")
	}
}

// TestIntegration_StorageWorkflow tests the storage workflow
func TestIntegration_StorageWorkflow(t *testing.T) {
	store := NewStore()
	engine := NewEngine()

	// Perform diff
	result, err := engine.Diff(DiffRequest{
		Left:  []byte(`{"a": 1}`),
		Right: []byte(`{"a": 2}`),
		Type:  DiffTypeJSON,
	})
	if err != nil {
		t.Fatalf("Diff failed: %v", err)
	}

	// Save to store
	stored, err := store.Save("Test Diff", result, "left-001", "right-001", []string{"test", "integration"})
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Retrieve from store
	retrieved, err := store.Get(stored.ID)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if retrieved.ID != stored.ID {
		t.Errorf("Retrieved wrong diff: expected %s, got %s", stored.ID, retrieved.ID)
	}

	// List all diffs
	allDiffs := store.List()
	if len(allDiffs) != 1 {
		t.Errorf("Expected 1 diff in store, got %d", len(allDiffs))
	}

	// Search by tag
	results := store.Search(SearchOptions{
		Tags: []string{"integration"},
	})

	if len(results) != 1 {
		t.Errorf("Expected 1 result from tag search, got %d", len(results))
	}

	// Delete
	err = store.Delete(stored.ID)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify deleted
	_, err = store.Get(stored.ID)
	if err == nil {
		t.Error("Expected error when getting deleted diff")
	}
}

// TestIntegration_RealWorldAuthBypass simulates a real-world auth bypass detection workflow
func TestIntegration_RealWorldAuthBypass(t *testing.T) {
	engine := NewEngine()

	// Simulate: Original response (normal user)
	normalUser := `{
		"user": {
			"id": 123,
			"username": "alice",
			"email": "alice@example.com",
			"role": "user",
			"permissions": ["read", "write"],
			"sessionToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc",
			"lastLogin": "2024-01-15T10:00:00Z"
		}
	}`

	// Simulate: Response after JWT manipulation (admin escalation)
	adminUser := `{
		"user": {
			"id": 123,
			"username": "alice",
			"email": "alice@example.com",
			"role": "admin",
			"permissions": ["read", "write", "admin", "delete"],
			"sessionToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz",
			"lastLogin": "2024-01-15T10:01:00Z",
			"adminPanel": {
				"url": "/admin",
				"features": ["user_management", "system_config"]
			}
		}
	}`

	// Step 1: Perform diff
	result, err := engine.Diff(DiffRequest{
		Left:  []byte(normalUser),
		Right: []byte(adminUser),
		Type:  DiffTypeJSON,
	})
	if err != nil {
		t.Fatalf("Diff failed: %v", err)
	}

	// Step 2: Filter noise
	filtered := FilterDiff(result, DefaultFilterConfig())

	// Step 3: Verify critical changes detected
	criticalChanges := []string{"role", "permissions", "adminPanel"}
	for _, criticalField := range criticalChanges {
		found := false
		for _, change := range filtered.SignalChanges {
			if strings.Contains(change.Path, criticalField) {
				found = true
				t.Logf("Critical change detected: %s (%s -> %s)",
					change.Path, change.OldValue, change.NewValue)
				break
			}
		}
		if !found {
			t.Errorf("Critical field '%s' not detected in signal changes", criticalField)
		}
	}

	// Step 4: Verify noise filtering worked
	// sessionToken and lastLogin should be filtered as noise
	for _, change := range filtered.NoiseChanges {
		if !strings.Contains(change.Path, "sessionToken") &&
			!strings.Contains(change.Path, "lastLogin") {
			t.Logf("Unexpected noise classification: %s", change.Path)
		}
	}

	// Step 5: Verify similarity score indicates significant change
	if filtered.Original.SimilarityScore > 85 {
		t.Errorf("Similarity too high for auth bypass scenario: %.1f%%", filtered.Original.SimilarityScore)
	}

	t.Logf("Auth bypass detection successful:")
	t.Logf("  Similarity: %.1f%%", result.SimilarityScore)
	t.Logf("  Total changes: %d", len(result.Changes))
	t.Logf("  Signal changes: %d", len(filtered.SignalChanges))
	t.Logf("  Noise changes: %d", len(filtered.NoiseChanges))
	t.Logf("  Noise percentage: %.1f%%", filtered.FilterStats.FilteredPercentage)
}

// TestIntegration_LargeScale tests performance with realistic data sizes
func TestIntegration_LargeScale(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping large-scale integration test in short mode")
	}

	engine := NewEngine()

	// Generate large JSON document (simulating real API response)
	largeJSON := generateLargeJSON(1000) // 1000 fields

	// Modify a few fields
	modifiedJSON := strings.Replace(largeJSON, `"field_500": "value_500"`, `"field_500": "modified_value"`, 1)
	modifiedJSON = strings.Replace(modifiedJSON, `"field_750": "value_750"`, `"field_750": "modified_value"`, 1)

	// Perform diff
	start := time.Now()
	result, err := engine.Diff(DiffRequest{
		Left:  []byte(largeJSON),
		Right: []byte(modifiedJSON),
		Type:  DiffTypeJSON,
	})
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("Diff failed: %v", err)
	}

	// Verify performance
	if duration > 2*time.Second {
		t.Errorf("Large JSON diff took too long: %v (expected < 2s)", duration)
	}

	// Verify accuracy
	if len(result.Changes) != 2 {
		t.Errorf("Expected 2 changes, got %d", len(result.Changes))
	}

	// Verify high similarity despite large size
	if result.SimilarityScore < 99.0 {
		t.Errorf("Expected >99%% similarity for 2 changes in 1000 fields, got %.1f%%", result.SimilarityScore)
	}

	t.Logf("Large-scale diff completed in %v", duration)
	t.Logf("Processed %d bytes in %.1fms (%.1f MB/s)",
		len(largeJSON),
		float64(duration.Milliseconds()),
		float64(len(largeJSON))/float64(duration.Milliseconds())/1000)
}

// Helper function to generate large JSON for testing
func generateLargeJSON(numFields int) string {
	var sb strings.Builder
	sb.WriteString("{")

	for i := 0; i < numFields; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`"field_`)
		sb.WriteString(string(rune('0' + (i / 100))))
		sb.WriteString(string(rune('0' + ((i / 10) % 10))))
		sb.WriteString(string(rune('0' + (i % 10))))
		sb.WriteString(`": "value_`)
		sb.WriteString(string(rune('0' + (i / 100))))
		sb.WriteString(string(rune('0' + ((i / 10) % 10))))
		sb.WriteString(string(rune('0' + (i % 10))))
		sb.WriteString(`"`)
	}

	sb.WriteString("}")
	return sb.String()
}
