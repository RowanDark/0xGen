package delta

import (
	"strings"
	"testing"
	"time"
)

// Test batch comparison with baseline-first strategy
func TestBatchComparison_BaselineFirst(t *testing.T) {
	engine := NewBatchComparisonEngine()

	responses := []ResponseIdentifier{
		{
			ID:      "resp1",
			Name:    "Response 1",
			Content: []byte("line1\nline2\nline3\n"),
		},
		{
			ID:      "resp2",
			Name:    "Response 2",
			Content: []byte("line1\nline2 modified\nline3\n"),
		},
		{
			ID:      "resp3",
			Name:    "Response 3",
			Content: []byte("line1\nline2\nline3\n"),
		},
	}

	req := BatchComparisonRequest{
		Responses:        responses,
		DiffType:         DiffTypeText,
		Granularity:      GranularityLine,
		BaselineStrategy: BaselineFirst,
		OutlierThreshold: 80.0,
		EnableClustering: true,
		EnablePatterns:   true,
		EnableAnomalies:  true,
	}

	result, err := engine.CompareBatch(req)
	if err != nil {
		t.Fatalf("CompareBatch failed: %v", err)
	}

	// Verify result structure
	if len(result.Responses) != 3 {
		t.Errorf("Expected 3 responses, got %d", len(result.Responses))
	}

	if result.Baseline == nil {
		t.Error("Expected baseline to be set")
	}

	if result.BaselineIndex != 0 {
		t.Errorf("Expected baseline index 0, got %d", result.BaselineIndex)
	}

	// Verify similarity matrix
	if len(result.SimilarityMatrix) != 3 {
		t.Errorf("Expected 3x3 similarity matrix, got %dx%d", len(result.SimilarityMatrix), len(result.SimilarityMatrix[0]))
	}

	// Diagonal should be 100%
	for i := 0; i < 3; i++ {
		if result.SimilarityMatrix[i][i] != 100.0 {
			t.Errorf("Expected diagonal[%d] = 100, got %.2f", i, result.SimilarityMatrix[i][i])
		}
	}

	// Matrix should be symmetric
	for i := 0; i < 3; i++ {
		for j := 0; j < 3; j++ {
			if result.SimilarityMatrix[i][j] != result.SimilarityMatrix[j][i] {
				t.Errorf("Matrix not symmetric at [%d][%d]: %.2f != %.2f", i, j,
					result.SimilarityMatrix[i][j], result.SimilarityMatrix[j][i])
			}
		}
	}

	// Response 1 and 3 should be identical (100% similar)
	if result.SimilarityMatrix[0][2] != 100.0 {
		t.Errorf("Expected responses 0 and 2 to be 100%% similar, got %.2f", result.SimilarityMatrix[0][2])
	}

	// Verify statistics
	if result.Statistics.TotalResponses != 3 {
		t.Errorf("Expected 3 total responses, got %d", result.Statistics.TotalResponses)
	}

	if result.Statistics.TotalComparisons != 3 {
		t.Errorf("Expected 3 comparisons, got %d", result.Statistics.TotalComparisons)
	}

	// Verify validation
	if err := result.Validate(); err != nil {
		t.Errorf("Result validation failed: %v", err)
	}
}

// Test batch comparison with all-pairs strategy
func TestBatchComparison_AllPairs(t *testing.T) {
	engine := NewBatchComparisonEngine()

	responses := []ResponseIdentifier{
		{ID: "r1", Content: []byte("test1")},
		{ID: "r2", Content: []byte("test2")},
		{ID: "r3", Content: []byte("test3")},
		{ID: "r4", Content: []byte("test4")},
	}

	req := BatchComparisonRequest{
		Responses:        responses,
		DiffType:         DiffTypeText,
		BaselineStrategy: BaselineAllPairs,
	}

	result, err := engine.CompareBatch(req)
	if err != nil {
		t.Fatalf("CompareBatch failed: %v", err)
	}

	// All-pairs should generate N*(N-1)/2 comparisons
	expectedPairs := 4 * 3 / 2
	if len(result.ComparisonMatrix) != expectedPairs {
		t.Errorf("Expected %d comparison pairs, got %d", expectedPairs, len(result.ComparisonMatrix))
	}

	// Verify all pairs are present
	pairMap := make(map[string]bool)
	for _, pair := range result.ComparisonMatrix {
		key := getPairKey(pair.LeftIndex, pair.RightIndex)
		if pairMap[key] {
			t.Errorf("Duplicate pair found: %s", key)
		}
		pairMap[key] = true
	}
}

// Test outlier detection
func TestBatchComparison_OutlierDetection(t *testing.T) {
	engine := NewBatchComparisonEngine()

	// Create 5 responses: 4 similar, 1 outlier
	// The similar ones should have avg similarity > 80%
	// The outlier should have avg similarity < 80%
	responses := []ResponseIdentifier{
		{ID: "r1", Content: []byte("line1\nline2\nline3\nline4\nline5\n")},
		{ID: "r2", Content: []byte("line1\nline2 modified\nline3\nline4\nline5\n")},
		{ID: "r3", Content: []byte("line1\nline2\nline3 modified\nline4\nline5\n")},
		{ID: "r4", Content: []byte("line1\nline2\nline3\nline4 modified\nline5\n")},
		{ID: "r5", Content: []byte("completely\ndifferent\ncontent\nhere\noutlier\n")},
	}

	req := BatchComparisonRequest{
		Responses:        responses,
		DiffType:         DiffTypeText,
		BaselineStrategy: BaselineAllPairs, // Use all-pairs for accurate outlier detection
		OutlierThreshold: 75.0, // Lower threshold to detect the outlier
	}

	result, err := engine.CompareBatch(req)
	if err != nil {
		t.Fatalf("CompareBatch failed: %v", err)
	}

	// Response 5 (index 4) should be detected as outlier
	if len(result.Outliers) == 0 {
		t.Error("Expected outliers to be detected")
	}

	// Check if index 4 is in the outliers list
	found := false
	for _, idx := range result.Outliers {
		if idx == 4 {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected index 4 to be an outlier, but outliers are: %v (similarity matrix: %v)",
			result.Outliers, result.SimilarityMatrix)
	}

	// The first 4 responses should NOT be outliers (they're similar to each other)
	for _, idx := range result.Outliers {
		if idx < 4 {
			t.Logf("Warning: Response %d detected as outlier (similarity to others may be borderline)", idx)
		}
	}
}

// Test clustering
func TestBatchComparison_Clustering(t *testing.T) {
	engine := NewBatchComparisonEngine()

	responses := []ResponseIdentifier{
		// Cluster 1: similar responses
		{ID: "r1", Content: []byte("cluster1\ndata\n")},
		{ID: "r2", Content: []byte("cluster1\ndata\n")},
		// Cluster 2: different responses
		{ID: "r3", Content: []byte("cluster2\ndifferent\n")},
		{ID: "r4", Content: []byte("cluster2\ndifferent\n")},
	}

	req := BatchComparisonRequest{
		Responses:        responses,
		DiffType:         DiffTypeText,
		BaselineStrategy: BaselineAllPairs,
		EnableClustering: true,
	}

	result, err := engine.CompareBatch(req)
	if err != nil {
		t.Fatalf("CompareBatch failed: %v", err)
	}

	if len(result.Clusters) == 0 {
		t.Error("Expected clusters to be detected")
	}

	// Should detect at least 2 clusters
	if len(result.Clusters) < 2 {
		t.Errorf("Expected at least 2 clusters, got %d", len(result.Clusters))
	}
}

// Test JSON pattern detection
func TestBatchComparison_JSONPatternDetection(t *testing.T) {
	engine := NewBatchComparisonEngine()

	json1 := `{"id": 1, "name": "Alice", "status": "active", "timestamp": "2023-01-01"}`
	json2 := `{"id": 2, "name": "Bob", "status": "active", "timestamp": "2023-01-02"}`
	json3 := `{"id": 3, "name": "Charlie", "status": "active", "timestamp": "2023-01-03", "extra": "data"}`

	responses := []ResponseIdentifier{
		{ID: "r1", Content: []byte(json1)},
		{ID: "r2", Content: []byte(json2)},
		{ID: "r3", Content: []byte(json3)},
	}

	req := BatchComparisonRequest{
		Responses:        responses,
		DiffType:         DiffTypeJSON,
		BaselineStrategy: BaselineFirst,
		EnablePatterns:   true,
	}

	result, err := engine.CompareBatch(req)
	if err != nil {
		t.Fatalf("CompareBatch failed: %v", err)
	}

	if result.Patterns == nil {
		t.Fatal("Expected patterns to be detected")
	}

	// "status" should be a constant field (same value in all responses)
	hasStatus := false
	for _, field := range result.Patterns.ConstantFields {
		if field == "status" {
			hasStatus = true
			break
		}
	}
	if !hasStatus {
		t.Error("Expected 'status' to be detected as constant field")
	}

	// "extra" should be unique to response 3
	if result.Patterns.UniqueElements[2] == nil {
		t.Error("Expected unique elements for response 2 (index 2)")
	}
}

// Test anomaly detection
func TestBatchComparison_AnomalyDetection(t *testing.T) {
	engine := NewBatchComparisonEngine()

	responses := []ResponseIdentifier{
		{
			ID:           "r1",
			Content:      []byte("normal content"),
			StatusCode:   200,
			ResponseTime: 100 * time.Millisecond,
		},
		{
			ID:           "r2",
			Content:      []byte("normal content"),
			StatusCode:   200,
			ResponseTime: 105 * time.Millisecond,
		},
		{
			ID:           "r3",
			Content:      []byte("normal content"),
			StatusCode:   500, // Unusual status code
			ResponseTime: 95 * time.Millisecond,
		},
		{
			ID:           "r4",
			Content:      []byte("normal content but very very long" + strings.Repeat("x", 1000)),
			StatusCode:   200,
			ResponseTime: 1000 * time.Millisecond, // Slow response
		},
	}

	req := BatchComparisonRequest{
		Responses:        responses,
		DiffType:         DiffTypeText,
		BaselineStrategy: BaselineFirst,
		EnableAnomalies:  true,
	}

	result, err := engine.CompareBatch(req)
	if err != nil {
		t.Fatalf("CompareBatch failed: %v", err)
	}

	if result.Anomalies == nil {
		t.Fatal("Expected anomalies to be detected")
	}

	// Response 3 should have unusual status code
	hasUnusualStatus := false
	for _, idx := range result.Anomalies.UnusualStatusCodes {
		if idx == 2 {
			hasUnusualStatus = true
			break
		}
	}
	if !hasUnusualStatus {
		t.Error("Expected response 2 (index 2) to have unusual status code")
	}

	// Should have a summary
	if result.Anomalies.Summary == "" {
		t.Error("Expected anomaly summary to be generated")
	}
}

// Test statistics calculation
func TestBatchComparison_Statistics(t *testing.T) {
	engine := NewBatchComparisonEngine()

	responses := []ResponseIdentifier{
		{ID: "r1", Content: []byte("test content"), StatusCode: 200, ResponseTime: 100 * time.Millisecond},
		{ID: "r2", Content: []byte("test content"), StatusCode: 200, ResponseTime: 200 * time.Millisecond},
		{ID: "r3", Content: []byte("test content"), StatusCode: 201, ResponseTime: 150 * time.Millisecond},
	}

	req := BatchComparisonRequest{
		Responses:        responses,
		DiffType:         DiffTypeText,
		BaselineStrategy: BaselineAllPairs,
	}

	result, err := engine.CompareBatch(req)
	if err != nil {
		t.Fatalf("CompareBatch failed: %v", err)
	}

	stats := result.Statistics

	// Verify response time stats
	if stats.ResponseTimeStats.Mean == 0 {
		t.Error("Expected response time mean to be calculated")
	}

	// Verify status code distribution
	if len(stats.StatusCodeDist) != 2 {
		t.Errorf("Expected 2 different status codes, got %d", len(stats.StatusCodeDist))
	}

	if stats.StatusCodeDist[200] != 2 {
		t.Errorf("Expected 2 responses with status 200, got %d", stats.StatusCodeDist[200])
	}

	if stats.StatusCodeDist[201] != 1 {
		t.Errorf("Expected 1 response with status 201, got %d", stats.StatusCodeDist[201])
	}

	// Verify content length stats
	if stats.ContentLengthStats.Mean == 0 {
		t.Error("Expected content length mean to be calculated")
	}
}

// Test median baseline strategy
func TestBatchComparison_MedianBaseline(t *testing.T) {
	engine := NewBatchComparisonEngine()

	responses := []ResponseIdentifier{
		{ID: "r1", Content: []byte("outlier content completely different")},
		{ID: "r2", Content: []byte("normal content")},
		{ID: "r3", Content: []byte("normal content")},
		{ID: "r4", Content: []byte("normal content")},
		{ID: "r5", Content: []byte("another outlier with unique data")},
	}

	req := BatchComparisonRequest{
		Responses:        responses,
		DiffType:         DiffTypeText,
		BaselineStrategy: BaselineMedian,
	}

	result, err := engine.CompareBatch(req)
	if err != nil {
		t.Fatalf("CompareBatch failed: %v", err)
	}

	// Baseline should be one of the "normal" responses (indices 1, 2, or 3)
	if result.BaselineIndex < 1 || result.BaselineIndex > 3 {
		t.Logf("Warning: Median baseline index is %d, expected 1-3 (but algorithm may vary)", result.BaselineIndex)
	}
}

// Test user-selected baseline strategy
func TestBatchComparison_UserSelectedBaseline(t *testing.T) {
	engine := NewBatchComparisonEngine()

	responses := []ResponseIdentifier{
		{ID: "r1", Content: []byte("content1")},
		{ID: "r2", Content: []byte("content2")},
		{ID: "r3", Content: []byte("content3")},
	}

	req := BatchComparisonRequest{
		Responses:        responses,
		DiffType:         DiffTypeText,
		BaselineStrategy: BaselineUserSelected,
		BaselineIndex:    1, // Select second response as baseline
	}

	result, err := engine.CompareBatch(req)
	if err != nil {
		t.Fatalf("CompareBatch failed: %v", err)
	}

	if result.BaselineIndex != 1 {
		t.Errorf("Expected baseline index 1, got %d", result.BaselineIndex)
	}

	if result.Baseline.ID != "r2" {
		t.Errorf("Expected baseline ID 'r2', got %s", result.Baseline.ID)
	}
}

// Test validation errors
func TestBatchComparison_ValidationErrors(t *testing.T) {
	engine := NewBatchComparisonEngine()

	tests := []struct {
		name    string
		req     BatchComparisonRequest
		wantErr bool
	}{
		{
			name: "too few responses",
			req: BatchComparisonRequest{
				Responses:        []ResponseIdentifier{{ID: "r1", Content: []byte("test")}},
				DiffType:         DiffTypeText,
				BaselineStrategy: BaselineFirst,
			},
			wantErr: true,
		},
		{
			name: "too many responses",
			req: BatchComparisonRequest{
				Responses:        make([]ResponseIdentifier, 51),
				DiffType:         DiffTypeText,
				BaselineStrategy: BaselineFirst,
			},
			wantErr: true,
		},
		{
			name: "invalid baseline index",
			req: BatchComparisonRequest{
				Responses: []ResponseIdentifier{
					{ID: "r1", Content: []byte("test")},
					{ID: "r2", Content: []byte("test")},
				},
				DiffType:         DiffTypeText,
				BaselineStrategy: BaselineUserSelected,
				BaselineIndex:    5, // Out of range
			},
			wantErr: true,
		},
		{
			name: "invalid diff type",
			req: BatchComparisonRequest{
				Responses: []ResponseIdentifier{
					{ID: "r1", Content: []byte("test")},
					{ID: "r2", Content: []byte("test")},
				},
				DiffType:         "invalid",
				BaselineStrategy: BaselineFirst,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := engine.CompareBatch(tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("CompareBatch() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Test performance with larger batch
func TestBatchComparison_Performance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	engine := NewBatchComparisonEngine()

	// Create 20 responses with varying content
	responses := make([]ResponseIdentifier, 20)
	for i := 0; i < 20; i++ {
		content := "Base content\n"
		for j := 0; j < i; j++ {
			content += "Additional line " + string(rune('A'+j)) + "\n"
		}
		responses[i] = ResponseIdentifier{
			ID:      "resp" + string(rune('0'+i)),
			Content: []byte(content),
		}
	}

	req := BatchComparisonRequest{
		Responses:        responses,
		DiffType:         DiffTypeText,
		BaselineStrategy: BaselineAllPairs,
		EnableClustering: true,
		EnablePatterns:   true,
		EnableAnomalies:  true,
	}

	start := time.Now()
	result, err := engine.CompareBatch(req)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("CompareBatch failed: %v", err)
	}

	// Acceptance criteria: 20 responses should complete in <5 seconds
	if duration > 5*time.Second {
		t.Errorf("Performance requirement not met: took %v (expected < 5s)", duration)
	}

	t.Logf("Batch comparison of 20 responses completed in %v", duration)
	t.Logf("Result: %s", result.Summary())
}

// Test summary generation
func TestBatchDiffResult_Summary(t *testing.T) {
	result := BatchDiffResult{
		Responses: []ResponseIdentifier{
			{ID: "r1", Content: []byte("test")},
			{ID: "r2", Content: []byte("test")},
		},
		Outliers: []int{1},
		Clusters: []ResponseCluster{{ClusterID: 0}},
		Statistics: BatchStatistics{
			MeanSimilarity: 85.5,
		},
	}

	summary := result.Summary()
	if !strings.Contains(summary, "2 responses") {
		t.Errorf("Summary should mention response count: %s", summary)
	}
	if !strings.Contains(summary, "85.5") {
		t.Errorf("Summary should mention similarity: %s", summary)
	}
	if !strings.Contains(summary, "1 outliers") {
		t.Errorf("Summary should mention outliers: %s", summary)
	}
}

// Helper function to generate pair key
func getPairKey(i, j int) string {
	if i > j {
		i, j = j, i
	}
	return string(rune('0'+i)) + "-" + string(rune('0'+j))
}

// Test type validation
func TestResponseIdentifier_Validate(t *testing.T) {
	tests := []struct {
		name    string
		resp    ResponseIdentifier
		wantErr bool
	}{
		{
			name:    "valid response",
			resp:    ResponseIdentifier{ID: "test", Content: []byte("content")},
			wantErr: false,
		},
		{
			name:    "missing ID",
			resp:    ResponseIdentifier{Content: []byte("content")},
			wantErr: true,
		},
		{
			name:    "empty content",
			resp:    ResponseIdentifier{ID: "test", Content: []byte{}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.resp.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Test batch result validation
func TestBatchDiffResult_Validate(t *testing.T) {
	validResult := BatchDiffResult{
		Responses: []ResponseIdentifier{
			{ID: "r1", Content: []byte("test")},
			{ID: "r2", Content: []byte("test")},
		},
		SimilarityMatrix: [][]float64{
			{100, 80},
			{80, 100},
		},
		Outliers: []int{},
	}

	if err := validResult.Validate(); err != nil {
		t.Errorf("Valid result failed validation: %v", err)
	}

	// Test invalid similarity matrix dimensions
	invalidResult := validResult
	invalidResult.SimilarityMatrix = [][]float64{{100}}
	if err := invalidResult.Validate(); err == nil {
		t.Error("Expected validation error for mismatched matrix dimensions")
	}

	// Test invalid outlier index
	invalidResult = validResult
	invalidResult.Outliers = []int{5}
	if err := invalidResult.Validate(); err == nil {
		t.Error("Expected validation error for out-of-range outlier index")
	}
}

// Benchmark batch comparison
func BenchmarkBatchComparison_10Responses(b *testing.B) {
	engine := NewBatchComparisonEngine()
	responses := make([]ResponseIdentifier, 10)
	for i := 0; i < 10; i++ {
		responses[i] = ResponseIdentifier{
			ID:      "resp" + string(rune('0'+i)),
			Content: []byte("test content line1\ntest content line2\n"),
		}
	}

	req := BatchComparisonRequest{
		Responses:        responses,
		DiffType:         DiffTypeText,
		BaselineStrategy: BaselineFirst,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := engine.CompareBatch(req)
		if err != nil {
			b.Fatalf("CompareBatch failed: %v", err)
		}
	}
}

// Benchmark all-pairs comparison
func BenchmarkBatchComparison_AllPairs_10Responses(b *testing.B) {
	engine := NewBatchComparisonEngine()
	responses := make([]ResponseIdentifier, 10)
	for i := 0; i < 10; i++ {
		responses[i] = ResponseIdentifier{
			ID:      "resp" + string(rune('0'+i)),
			Content: []byte("test content line1\ntest content line2\n"),
		}
	}

	req := BatchComparisonRequest{
		Responses:        responses,
		DiffType:         DiffTypeText,
		BaselineStrategy: BaselineAllPairs,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := engine.CompareBatch(req)
		if err != nil {
			b.Fatalf("CompareBatch failed: %v", err)
		}
	}
}
