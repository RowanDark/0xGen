package delta

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Test CSV export
func TestBatchExporter_ExportCSV(t *testing.T) {
	exporter := NewBatchExporter()

	result := createTestBatchResult()

	data, err := exporter.ExportCSV(result)
	if err != nil {
		t.Fatalf("ExportCSV failed: %v", err)
	}

	// Parse CSV to verify structure
	reader := csv.NewReader(bytes.NewReader(data))
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("Failed to parse CSV: %v", err)
	}

	if len(records) < 4 { // At least header + 3 data rows
		t.Errorf("Expected at least 4 CSV records, got %d", len(records))
	}

	// Verify header
	header := records[0]
	if header[0] != "Response" {
		t.Errorf("Expected first column header 'Response', got %s", header[0])
	}

	// Verify similarity matrix values are present
	if len(records[1]) < 4 { // Response name + 3 similarity values
		t.Errorf("Expected at least 4 columns in data row, got %d", len(records[1]))
	}

	// Check for statistics section
	foundStats := false
	for _, record := range records {
		if len(record) > 0 && record[0] == "Statistics" {
			foundStats = true
			break
		}
	}
	if !foundStats {
		t.Error("Expected Statistics section in CSV output")
	}
}

// Test JSON export
func TestBatchExporter_ExportJSON(t *testing.T) {
	exporter := NewBatchExporter()
	result := createTestBatchResult()

	data, err := exporter.ExportJSON(result)
	if err != nil {
		t.Fatalf("ExportJSON failed: %v", err)
	}

	// Verify it's valid JSON
	var exported map[string]interface{}
	if err := json.Unmarshal(data, &exported); err != nil {
		t.Fatalf("Failed to parse exported JSON: %v", err)
	}

	// Verify key fields are present
	if _, ok := exported["responses"]; !ok {
		t.Error("Expected 'responses' field in JSON")
	}

	if _, ok := exported["similarity_matrix"]; !ok {
		t.Error("Expected 'similarity_matrix' field in JSON")
	}

	if _, ok := exported["statistics"]; !ok {
		t.Error("Expected 'statistics' field in JSON")
	}

	if _, ok := exported["version"]; !ok {
		t.Error("Expected 'version' field in JSON")
	}

	if _, ok := exported["exported_at"]; !ok {
		t.Error("Expected 'exported_at' field in JSON")
	}
}

// Test HTML export
func TestBatchExporter_ExportHTML(t *testing.T) {
	exporter := NewBatchExporter()
	result := createTestBatchResult()

	data, err := exporter.ExportHTML(result)
	if err != nil {
		t.Fatalf("ExportHTML failed: %v", err)
	}

	html := string(data)

	// Verify HTML structure
	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Error("Expected HTML doctype")
	}

	if !strings.Contains(html, "<html") {
		t.Error("Expected HTML tag")
	}

	if !strings.Contains(html, "Batch Comparison Report") {
		t.Error("Expected report title")
	}

	// Verify key sections are present
	expectedSections := []string{
		"Summary",
		"Similarity Statistics",
		"Similarity Matrix",
	}

	for _, section := range expectedSections {
		if !strings.Contains(html, section) {
			t.Errorf("Expected section '%s' in HTML output", section)
		}
	}

	// Verify CSS is included
	if !strings.Contains(html, "<style>") {
		t.Error("Expected CSS styles in HTML")
	}

	// Verify table is present
	if !strings.Contains(html, "<table>") {
		t.Error("Expected table in HTML")
	}
}

// Test export with all formats
func TestBatchExporter_Export_AllFormats(t *testing.T) {
	exporter := NewBatchExporter()
	result := createTestBatchResult()

	formats := []ExportFormat{
		ExportFormatCSV,
		ExportFormatJSON,
		ExportFormatHTML,
	}

	for _, format := range formats {
		t.Run(string(format), func(t *testing.T) {
			data, err := exporter.Export(result, format)
			if err != nil {
				t.Errorf("Export(%s) failed: %v", format, err)
			}
			if len(data) == 0 {
				t.Errorf("Export(%s) returned empty data", format)
			}
		})
	}
}

// Test export with invalid format
func TestBatchExporter_Export_InvalidFormat(t *testing.T) {
	exporter := NewBatchExporter()
	result := createTestBatchResult()

	_, err := exporter.Export(result, "invalid")
	if err == nil {
		t.Error("Expected error for invalid export format")
	}
}

// Test CSV export with outliers
func TestBatchExporter_ExportCSV_WithOutliers(t *testing.T) {
	exporter := NewBatchExporter()
	result := createTestBatchResult()
	result.Outliers = []int{2}

	data, err := exporter.ExportCSV(result)
	if err != nil {
		t.Fatalf("ExportCSV failed: %v", err)
	}

	csvStr := string(data)
	if !strings.Contains(csvStr, "Outliers") {
		t.Error("Expected Outliers section in CSV with outliers")
	}
}

// Test CSV export with clusters
func TestBatchExporter_ExportCSV_WithClusters(t *testing.T) {
	exporter := NewBatchExporter()
	result := createTestBatchResult()
	result.Clusters = []ResponseCluster{
		{
			ClusterID:       0,
			ResponseIndices: []int{0, 1},
			Representative:  0,
			AvgSimilarity:   95.0,
			Size:            2,
		},
	}

	data, err := exporter.ExportCSV(result)
	if err != nil {
		t.Fatalf("ExportCSV failed: %v", err)
	}

	csvStr := string(data)
	if !strings.Contains(csvStr, "Clusters") {
		t.Error("Expected Clusters section in CSV with clusters")
	}
}

// Test HTML export with patterns and anomalies
func TestBatchExporter_ExportHTML_WithPatternsAndAnomalies(t *testing.T) {
	exporter := NewBatchExporter()
	result := createTestBatchResult()

	result.Patterns = &PatternAnalysis{
		CommonJSONKeys: map[string]int{"id": 3, "name": 3},
		ConstantFields: []string{"status"},
		VariableFields: []string{"timestamp"},
		AIInsights:     []string{"All responses have similar structure"},
	}

	result.Anomalies = &AnomalyDetection{
		UnusualStatusCodes: []int{1},
		UnusualLengths:     []int{2},
		Summary:            "Found anomalies: 1 with unusual status codes; 1 with unusual content lengths",
	}

	data, err := exporter.ExportHTML(result)
	if err != nil {
		t.Fatalf("ExportHTML failed: %v", err)
	}

	html := string(data)

	// Verify pattern section
	if !strings.Contains(html, "AI Insights") {
		t.Error("Expected AI Insights section")
	}

	if !strings.Contains(html, "All responses have similar structure") {
		t.Error("Expected AI insight to be rendered")
	}

	// Verify anomaly section
	if !strings.Contains(html, "Anomaly Detection") {
		t.Error("Expected Anomaly Detection section")
	}

	if !strings.Contains(html, "Found anomalies") {
		t.Error("Expected anomaly summary to be rendered")
	}
}

// Test summary export
func TestBatchExporter_ExportSummary(t *testing.T) {
	exporter := NewBatchExporter()
	result := createTestBatchResult()

	var buf bytes.Buffer
	err := exporter.ExportSummary(result, &buf)
	if err != nil {
		t.Fatalf("ExportSummary failed: %v", err)
	}

	summary := buf.String()

	// Verify key information is present
	expectedStrings := []string{
		"Batch Comparison Summary",
		"Responses:",
		"Comparisons:",
		"Similarity Statistics:",
		"Mean:",
		"Median:",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(summary, expected) {
			t.Errorf("Expected summary to contain '%s'", expected)
		}
	}
}

// Test summary export with all optional fields
func TestBatchExporter_ExportSummary_Complete(t *testing.T) {
	exporter := NewBatchExporter()
	result := createTestBatchResult()

	result.Outliers = []int{2}
	result.Clusters = []ResponseCluster{
		{ClusterID: 0, Size: 2, AvgSimilarity: 95.0},
	}
	result.Statistics.StatusCodeDist = map[int]int{200: 2, 500: 1}
	result.Patterns = &PatternAnalysis{
		AIInsights: []string{"Insight 1", "Insight 2"},
	}
	result.Anomalies = &AnomalyDetection{
		Summary: "Some anomalies detected",
	}

	var buf bytes.Buffer
	err := exporter.ExportSummary(result, &buf)
	if err != nil {
		t.Fatalf("ExportSummary failed: %v", err)
	}

	summary := buf.String()

	// Verify all sections are present
	sections := []string{
		"Outliers",
		"Clusters",
		"Status Code Distribution",
		"AI Insights",
		"Anomalies",
	}

	for _, section := range sections {
		if !strings.Contains(summary, section) {
			t.Errorf("Expected summary to contain section '%s'", section)
		}
	}
}

// Test HTML export with different similarity levels
func TestBatchExporter_HTML_SimilarityClasses(t *testing.T) {
	exporter := NewBatchExporter()
	result := &BatchDiffResult{
		Responses: []ResponseIdentifier{
			{ID: "r1", Name: "Response 1", Content: []byte("test")},
			{ID: "r2", Name: "Response 2", Content: []byte("test")},
			{ID: "r3", Name: "Response 3", Content: []byte("test")},
		},
		SimilarityMatrix: [][]float64{
			{100.0, 95.0, 70.0},
			{95.0, 100.0, 75.0},
			{70.0, 75.0, 100.0},
		},
		Statistics: BatchStatistics{
			TotalResponses:   3,
			TotalComparisons: 3,
			MeanSimilarity:   80.0,
		},
		ComputeTime: 100 * time.Millisecond,
	}

	data, err := exporter.ExportHTML(result)
	if err != nil {
		t.Fatalf("ExportHTML failed: %v", err)
	}

	html := string(data)

	// Verify CSS classes are applied based on similarity levels
	// High similarity (>= 95) should have similarity-high class
	// Medium similarity (>= 80) should have similarity-medium class
	// Low similarity (< 80) should have similarity-low class
	if !strings.Contains(html, "similarity-high") {
		t.Error("Expected similarity-high CSS class for high similarity values")
	}

	if !strings.Contains(html, "similarity-low") {
		t.Error("Expected similarity-low CSS class for low similarity values")
	}
}

// Test JSON export preserves all data
func TestBatchExporter_JSON_DataPreservation(t *testing.T) {
	exporter := NewBatchExporter()
	original := createTestBatchResult()

	// Add all optional fields
	original.Baseline = &original.Responses[0]
	original.BaselineIndex = 0
	original.Outliers = []int{2}
	original.Clusters = []ResponseCluster{{ClusterID: 0, Size: 2, AvgSimilarity: 95.0}}
	original.Patterns = &PatternAnalysis{AIInsights: []string{"Test insight"}}
	original.Anomalies = &AnomalyDetection{Summary: "Test anomaly"}

	data, err := exporter.ExportJSON(original)
	if err != nil {
		t.Fatalf("ExportJSON failed: %v", err)
	}

	// Parse back and verify all fields are preserved
	var exported struct {
		BatchDiffResult
		ExportedAt time.Time `json:"exported_at"`
		Version    string    `json:"version"`
	}

	if err := json.Unmarshal(data, &exported); err != nil {
		t.Fatalf("Failed to unmarshal exported JSON: %v", err)
	}

	// Verify key fields
	if len(exported.Responses) != len(original.Responses) {
		t.Errorf("Response count mismatch: got %d, want %d", len(exported.Responses), len(original.Responses))
	}

	if exported.BaselineIndex != original.BaselineIndex {
		t.Errorf("BaselineIndex mismatch: got %d, want %d", exported.BaselineIndex, original.BaselineIndex)
	}

	if len(exported.Outliers) != len(original.Outliers) {
		t.Errorf("Outliers count mismatch: got %d, want %d", len(exported.Outliers), len(original.Outliers))
	}

	if len(exported.Clusters) != len(original.Clusters) {
		t.Errorf("Clusters count mismatch: got %d, want %d", len(exported.Clusters), len(original.Clusters))
	}
}

// Helper function to create a test batch result
func createTestBatchResult() *BatchDiffResult {
	return &BatchDiffResult{
		Responses: []ResponseIdentifier{
			{ID: "resp1", Name: "Response 1", Content: []byte("test content 1")},
			{ID: "resp2", Name: "Response 2", Content: []byte("test content 2")},
			{ID: "resp3", Name: "Response 3", Content: []byte("test content 3")},
		},
		SimilarityMatrix: [][]float64{
			{100.0, 85.0, 90.0},
			{85.0, 100.0, 88.0},
			{90.0, 88.0, 100.0},
		},
		Outliers: []int{},
		Statistics: BatchStatistics{
			TotalResponses:   3,
			TotalComparisons: 3,
			MeanSimilarity:   87.67,
			MedianSimilarity: 88.0,
			StdDevSimilarity: 2.5,
			MinSimilarity:    85.0,
			MaxSimilarity:    90.0,
			StatusCodeDist:   map[int]int{200: 3},
			ContentLengthStats: DistributionStats{
				Mean:   14.0,
				Median: 14.0,
				StdDev: 0.0,
				Min:    14.0,
				Max:    14.0,
			},
		},
		ComputeTime: 150 * time.Millisecond,
	}
}

// Benchmark CSV export
func BenchmarkExportCSV(b *testing.B) {
	exporter := NewBatchExporter()
	result := createLargeBatchResult(20)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := exporter.ExportCSV(result)
		if err != nil {
			b.Fatalf("ExportCSV failed: %v", err)
		}
	}
}

// Benchmark JSON export
func BenchmarkExportJSON(b *testing.B) {
	exporter := NewBatchExporter()
	result := createLargeBatchResult(20)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := exporter.ExportJSON(result)
		if err != nil {
			b.Fatalf("ExportJSON failed: %v", err)
		}
	}
}

// Benchmark HTML export
func BenchmarkExportHTML(b *testing.B) {
	exporter := NewBatchExporter()
	result := createLargeBatchResult(20)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := exporter.ExportHTML(result)
		if err != nil {
			b.Fatalf("ExportHTML failed: %v", err)
		}
	}
}

// Helper function to create a large batch result for benchmarking
func createLargeBatchResult(size int) *BatchDiffResult {
	responses := make([]ResponseIdentifier, size)
	matrix := make([][]float64, size)

	for i := 0; i < size; i++ {
		responses[i] = ResponseIdentifier{
			ID:      "resp" + string(rune('0'+i)),
			Name:    "Response " + string(rune('0'+i)),
			Content: []byte("test content for response " + string(rune('0'+i))),
		}

		matrix[i] = make([]float64, size)
		for j := 0; j < size; j++ {
			if i == j {
				matrix[i][j] = 100.0
			} else {
				matrix[i][j] = 85.0 + float64((i+j)%10)
			}
		}
	}

	return &BatchDiffResult{
		Responses:        responses,
		SimilarityMatrix: matrix,
		Outliers:         []int{size - 1},
		Statistics: BatchStatistics{
			TotalResponses:   size,
			TotalComparisons: size * (size - 1) / 2,
			MeanSimilarity:   87.5,
			MedianSimilarity: 88.0,
			StdDevSimilarity: 3.2,
			MinSimilarity:    85.0,
			MaxSimilarity:    94.0,
		},
		ComputeTime: 500 * time.Millisecond,
	}
}
