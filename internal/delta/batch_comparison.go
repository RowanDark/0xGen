package delta

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"time"
)

// BatchComparisonEngine performs batch comparisons of multiple responses
type BatchComparisonEngine struct {
	engine *Engine
}

// NewBatchComparisonEngine creates a new batch comparison engine
func NewBatchComparisonEngine() *BatchComparisonEngine {
	return &BatchComparisonEngine{
		engine: NewEngine(),
	}
}

// CompareBatch performs a batch comparison of multiple responses
func (bce *BatchComparisonEngine) CompareBatch(req BatchComparisonRequest) (*BatchDiffResult, error) {
	startTime := time.Now()

	// Validate request
	if err := req.Validate(); err != nil {
		return nil, fmt.Errorf("invalid batch comparison request: %w", err)
	}

	// Set default outlier threshold
	outlierThreshold := req.OutlierThreshold
	if outlierThreshold == 0 {
		outlierThreshold = 80.0
	}

	n := len(req.Responses)
	result := &BatchDiffResult{
		Responses:        req.Responses,
		Outliers:         []int{},
		SimilarityMatrix: make([][]float64, n),
	}

	// Initialize similarity matrix
	for i := range result.SimilarityMatrix {
		result.SimilarityMatrix[i] = make([]float64, n)
		// Diagonal is always 100% (comparing to self)
		result.SimilarityMatrix[i][i] = 100.0
	}

	// Determine baseline strategy and perform comparisons
	switch req.BaselineStrategy {
	case BaselineFirst:
		if err := bce.baselineComparison(req, result, 0); err != nil {
			return nil, err
		}
	case BaselineUserSelected:
		if err := bce.baselineComparison(req, result, req.BaselineIndex); err != nil {
			return nil, err
		}
	case BaselineMedian:
		if err := bce.medianBaselineComparison(req, result); err != nil {
			return nil, err
		}
	case BaselineAllPairs:
		if err := bce.allPairsComparison(req, result); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported baseline strategy: %s", req.BaselineStrategy)
	}

	// Detect outliers
	result.Outliers = bce.detectOutliers(result.SimilarityMatrix, outlierThreshold)

	// Calculate statistics
	result.Statistics = bce.calculateStatistics(req, result)

	// Perform clustering if requested
	if req.EnableClustering {
		result.Clusters = bce.clusterResponses(result.SimilarityMatrix)
	}

	// Perform pattern detection if requested
	if req.EnablePatterns {
		patterns, err := bce.detectPatterns(req, result)
		if err != nil {
			// Log error but don't fail the entire operation
			patterns = &PatternAnalysis{
				AIInsights: []string{fmt.Sprintf("Pattern detection failed: %v", err)},
			}
		}
		result.Patterns = patterns
	}

	// Perform anomaly detection if requested
	if req.EnableAnomalies {
		result.Anomalies = bce.detectAnomalies(req, result)
	}

	result.ComputeTime = time.Since(startTime)
	return result, nil
}

// baselineComparison compares all responses to a baseline response
func (bce *BatchComparisonEngine) baselineComparison(req BatchComparisonRequest, result *BatchDiffResult, baselineIdx int) error {
	baseline := &req.Responses[baselineIdx]
	result.Baseline = baseline
	result.BaselineIndex = baselineIdx
	result.Comparisons = make([]DiffResult, 0, len(req.Responses)-1)

	for i, resp := range req.Responses {
		if i == baselineIdx {
			continue
		}

		// Perform diff
		diffReq := DiffRequest{
			Left:        baseline.Content,
			Right:       resp.Content,
			Type:        req.DiffType,
			Granularity: req.Granularity,
		}

		diffResult, err := bce.engine.Diff(diffReq)
		if err != nil {
			return fmt.Errorf("failed to diff response %d with baseline: %w", i, err)
		}

		result.Comparisons = append(result.Comparisons, *diffResult)

		// Update similarity matrix (symmetric)
		result.SimilarityMatrix[baselineIdx][i] = diffResult.SimilarityScore
		result.SimilarityMatrix[i][baselineIdx] = diffResult.SimilarityScore
	}

	return nil
}

// medianBaselineComparison finds the median response and uses it as baseline
func (bce *BatchComparisonEngine) medianBaselineComparison(req BatchComparisonRequest, result *BatchDiffResult) error {
	n := len(req.Responses)

	// First, do all-pairs comparison to find median
	tempMatrix := make([][]float64, n)
	for i := range tempMatrix {
		tempMatrix[i] = make([]float64, n)
		tempMatrix[i][i] = 100.0
	}

	// Calculate all pairwise similarities
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			diffReq := DiffRequest{
				Left:        req.Responses[i].Content,
				Right:       req.Responses[j].Content,
				Type:        req.DiffType,
				Granularity: req.Granularity,
			}

			diffResult, err := bce.engine.Diff(diffReq)
			if err != nil {
				return fmt.Errorf("failed to diff response %d with %d: %w", i, j, err)
			}

			tempMatrix[i][j] = diffResult.SimilarityScore
			tempMatrix[j][i] = diffResult.SimilarityScore
		}
	}

	// Find response with median average similarity
	medianIdx := bce.findMedianResponse(tempMatrix)

	// Now use the median response as baseline
	return bce.baselineComparison(req, result, medianIdx)
}

// allPairsComparison compares all pairs of responses (N×N matrix)
func (bce *BatchComparisonEngine) allPairsComparison(req BatchComparisonRequest, result *BatchDiffResult) error {
	n := len(req.Responses)
	result.ComparisonMatrix = make([]ComparisonPair, 0, n*(n-1)/2)

	// Calculate all pairwise similarities
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			diffReq := DiffRequest{
				Left:        req.Responses[i].Content,
				Right:       req.Responses[j].Content,
				Type:        req.DiffType,
				Granularity: req.Granularity,
			}

			diffResult, err := bce.engine.Diff(diffReq)
			if err != nil {
				return fmt.Errorf("failed to diff response %d with %d: %w", i, j, err)
			}

			result.ComparisonMatrix = append(result.ComparisonMatrix, ComparisonPair{
				LeftIndex:  i,
				RightIndex: j,
				DiffResult: *diffResult,
			})

			// Update similarity matrix (symmetric)
			result.SimilarityMatrix[i][j] = diffResult.SimilarityScore
			result.SimilarityMatrix[j][i] = diffResult.SimilarityScore
		}
	}

	return nil
}

// findMedianResponse finds the response with median average similarity
func (bce *BatchComparisonEngine) findMedianResponse(matrix [][]float64) int {
	n := len(matrix)
	avgSimilarities := make([]float64, n)

	// Calculate average similarity for each response
	for i := 0; i < n; i++ {
		sum := 0.0
		for j := 0; j < n; j++ {
			if i != j {
				sum += matrix[i][j]
			}
		}
		avgSimilarities[i] = sum / float64(n-1)
	}

	// Find the index with median average similarity
	sorted := make([]float64, n)
	copy(sorted, avgSimilarities)
	sort.Float64s(sorted)

	medianValue := sorted[n/2]
	if n%2 == 0 {
		medianValue = (sorted[n/2-1] + sorted[n/2]) / 2
	}

	// Find the response closest to the median
	minDiff := math.MaxFloat64
	medianIdx := 0
	for i, avg := range avgSimilarities {
		diff := math.Abs(avg - medianValue)
		if diff < minDiff {
			minDiff = diff
			medianIdx = i
		}
	}

	return medianIdx
}

// detectOutliers identifies responses that differ significantly from others
func (bce *BatchComparisonEngine) detectOutliers(matrix [][]float64, threshold float64) []int {
	n := len(matrix)
	outliers := make([]int, 0)

	for i := 0; i < n; i++ {
		// Calculate average similarity to all other responses
		sum := 0.0
		count := 0
		for j := 0; j < n; j++ {
			if i != j {
				sum += matrix[i][j]
				count++
			}
		}

		if count > 0 {
			avgSimilarity := sum / float64(count)
			if avgSimilarity < threshold {
				outliers = append(outliers, i)
			}
		}
	}

	return outliers
}

// calculateStatistics computes statistical metrics across the batch
func (bce *BatchComparisonEngine) calculateStatistics(req BatchComparisonRequest, result *BatchDiffResult) BatchStatistics {
	n := len(req.Responses)

	// Collect all similarity scores (excluding diagonal)
	similarities := make([]float64, 0, n*(n-1)/2)
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			similarities = append(similarities, result.SimilarityMatrix[i][j])
		}
	}

	stats := BatchStatistics{
		TotalResponses:   n,
		TotalComparisons: len(similarities),
		StatusCodeDist:   make(map[int]int),
	}

	if len(similarities) > 0 {
		// Calculate similarity statistics
		stats.MeanSimilarity = calculateMean(similarities)
		stats.MedianSimilarity = calculateMedian(similarities)
		stats.StdDevSimilarity = calculateStdDev(similarities, stats.MeanSimilarity)
		stats.MinSimilarity = calculateMin(similarities)
		stats.MaxSimilarity = calculateMax(similarities)
	}

	// Calculate response time statistics
	responseTimes := make([]float64, 0, n)
	for _, resp := range req.Responses {
		if resp.ResponseTime > 0 {
			responseTimes = append(responseTimes, float64(resp.ResponseTime.Milliseconds()))
		}
	}
	if len(responseTimes) > 0 {
		stats.ResponseTimeStats = DistributionStats{
			Mean:   calculateMean(responseTimes),
			Median: calculateMedian(responseTimes),
			StdDev: calculateStdDev(responseTimes, calculateMean(responseTimes)),
			Min:    calculateMin(responseTimes),
			Max:    calculateMax(responseTimes),
		}
	}

	// Calculate status code distribution
	for _, resp := range req.Responses {
		if resp.StatusCode > 0 {
			stats.StatusCodeDist[resp.StatusCode]++
		}
	}

	// Calculate content length statistics
	contentLengths := make([]float64, n)
	for i, resp := range req.Responses {
		contentLengths[i] = float64(len(resp.Content))
	}
	stats.ContentLengthStats = DistributionStats{
		Mean:   calculateMean(contentLengths),
		Median: calculateMedian(contentLengths),
		StdDev: calculateStdDev(contentLengths, calculateMean(contentLengths)),
		Min:    calculateMin(contentLengths),
		Max:    calculateMax(contentLengths),
	}

	return stats
}

// clusterResponses groups similar responses using simple threshold-based clustering
func (bce *BatchComparisonEngine) clusterResponses(matrix [][]float64) []ResponseCluster {
	n := len(matrix)
	visited := make([]bool, n)
	clusters := make([]ResponseCluster, 0)
	clusterID := 0

	// Use 90% similarity threshold for clustering
	const clusterThreshold = 90.0

	for i := 0; i < n; i++ {
		if visited[i] {
			continue
		}

		// Start a new cluster
		cluster := ResponseCluster{
			ClusterID:       clusterID,
			ResponseIndices: []int{i},
			Representative:  i,
		}
		visited[i] = true
		clusterID++

		// Find all responses similar to this one
		for j := i + 1; j < n; j++ {
			if !visited[j] && matrix[i][j] >= clusterThreshold {
				cluster.ResponseIndices = append(cluster.ResponseIndices, j)
				visited[j] = true
			}
		}

		cluster.Size = len(cluster.ResponseIndices)

		// Calculate average similarity within cluster
		if cluster.Size > 1 {
			totalSim := 0.0
			count := 0
			for _, idx1 := range cluster.ResponseIndices {
				for _, idx2 := range cluster.ResponseIndices {
					if idx1 < idx2 {
						totalSim += matrix[idx1][idx2]
						count++
					}
				}
			}
			if count > 0 {
				cluster.AvgSimilarity = totalSim / float64(count)
			}
		} else {
			cluster.AvgSimilarity = 100.0
		}

		clusters = append(clusters, cluster)
	}

	return clusters
}

// detectPatterns analyzes responses to find common and unique patterns
func (bce *BatchComparisonEngine) detectPatterns(req BatchComparisonRequest, result *BatchDiffResult) (*PatternAnalysis, error) {
	analysis := &PatternAnalysis{
		CommonHeaders:   make(map[string]int),
		CommonJSONKeys:  make(map[string]int),
		CommonErrorMsgs: make(map[string]int),
		UniqueElements:  make(map[int][]string),
		ConstantFields:  make([]string, 0),
		VariableFields:  make([]string, 0),
		AIInsights:      make([]string, 0),
	}

	// Analyze JSON responses for common keys
	if req.DiffType == DiffTypeJSON {
		allKeys := make(map[string][]int) // key -> response indices where it appears

		for i, resp := range req.Responses {
			var data map[string]interface{}
			if err := json.Unmarshal(resp.Content, &data); err != nil {
				continue
			}

			keys := extractJSONKeys(data, "")
			for _, key := range keys {
				if _, exists := allKeys[key]; !exists {
					allKeys[key] = make([]int, 0)
				}
				allKeys[key] = append(allKeys[key], i)
			}
		}

		// Determine common vs unique keys
		n := len(req.Responses)
		for key, indices := range allKeys {
			count := len(indices)
			analysis.CommonJSONKeys[key] = count

			if count == n {
				// Present in all responses - check if value is constant
				analysis.ConstantFields = append(analysis.ConstantFields, key)
			} else if count == 1 {
				// Unique to one response
				if analysis.UniqueElements[indices[0]] == nil {
					analysis.UniqueElements[indices[0]] = make([]string, 0)
				}
				analysis.UniqueElements[indices[0]] = append(analysis.UniqueElements[indices[0]], key)
			} else {
				// Present in some responses
				analysis.VariableFields = append(analysis.VariableFields, key)
			}
		}
	}

	// Generate AI insights based on patterns
	analysis.AIInsights = bce.generateInsights(req, result, analysis)

	return analysis, nil
}

// extractJSONKeys recursively extracts all JSON keys with their paths
func extractJSONKeys(data interface{}, prefix string) []string {
	keys := make([]string, 0)

	switch v := data.(type) {
	case map[string]interface{}:
		for key, value := range v {
			fullKey := key
			if prefix != "" {
				fullKey = prefix + "." + key
			}
			keys = append(keys, fullKey)
			keys = append(keys, extractJSONKeys(value, fullKey)...)
		}
	case []interface{}:
		for i, value := range v {
			arrayKey := fmt.Sprintf("%s[%d]", prefix, i)
			keys = append(keys, extractJSONKeys(value, arrayKey)...)
		}
	}

	return keys
}

// detectAnomalies identifies unusual responses in the batch
func (bce *BatchComparisonEngine) detectAnomalies(req BatchComparisonRequest, result *BatchDiffResult) *AnomalyDetection {
	anomalies := &AnomalyDetection{
		UnusualStatusCodes: make([]int, 0),
		UnusualLengths:     make([]int, 0),
		UniqueErrors:       make([]int, 0),
		SlowResponses:      make([]int, 0),
	}

	stats := result.Statistics

	// Detect unusual status codes (not the most common one)
	mostCommonStatus := 0
	maxCount := 0
	for status, count := range stats.StatusCodeDist {
		if count > maxCount {
			maxCount = count
			mostCommonStatus = status
		}
	}

	for i, resp := range req.Responses {
		// Check status code
		if resp.StatusCode > 0 && resp.StatusCode != mostCommonStatus {
			anomalies.UnusualStatusCodes = append(anomalies.UnusualStatusCodes, i)
		}

		// Check content length (> 2 std deviations from mean)
		contentLen := float64(len(resp.Content))
		if stats.ContentLengthStats.StdDev > 0 {
			zScore := math.Abs(contentLen-stats.ContentLengthStats.Mean) / stats.ContentLengthStats.StdDev
			if zScore > 2.0 {
				anomalies.UnusualLengths = append(anomalies.UnusualLengths, i)
			}
		}

		// Check response time (> 2 std deviations from mean)
		if resp.ResponseTime > 0 && stats.ResponseTimeStats.StdDev > 0 {
			respTime := float64(resp.ResponseTime.Milliseconds())
			zScore := math.Abs(respTime-stats.ResponseTimeStats.Mean) / stats.ResponseTimeStats.StdDev
			if zScore > 2.0 {
				anomalies.SlowResponses = append(anomalies.SlowResponses, i)
			}
		}
	}

	// Generate summary
	anomalies.Summary = bce.generateAnomalySummary(anomalies, req)

	return anomalies
}

// generateInsights creates AI-generated insights from patterns
func (bce *BatchComparisonEngine) generateInsights(req BatchComparisonRequest, result *BatchDiffResult, patterns *PatternAnalysis) []string {
	insights := make([]string, 0)

	// Analyze outliers
	if len(result.Outliers) > 0 {
		if len(result.Outliers) <= 3 {
			insights = append(insights, fmt.Sprintf("%d response(s) differ significantly from others (indices: %v)", len(result.Outliers), result.Outliers))
		} else {
			insights = append(insights, fmt.Sprintf("%d responses differ significantly from others", len(result.Outliers)))
		}
	}

	// Analyze clusters
	if len(result.Clusters) > 1 {
		insights = append(insights, fmt.Sprintf("Responses form %d distinct clusters of similar content", len(result.Clusters)))
	}

	// Analyze similarity distribution
	if result.Statistics.StdDevSimilarity > 15 {
		insights = append(insights, "High variability in response similarity - responses differ substantially")
	} else if result.Statistics.StdDevSimilarity < 5 {
		insights = append(insights, "Low variability in response similarity - responses are consistently similar")
	}

	// Analyze status codes
	if len(result.Statistics.StatusCodeDist) > 1 {
		insights = append(insights, fmt.Sprintf("Multiple status codes observed: %v", getStatusCodesList(result.Statistics.StatusCodeDist)))
	}

	// Analyze constant vs variable fields
	if len(patterns.ConstantFields) > 0 && len(patterns.VariableFields) > 0 {
		constRatio := float64(len(patterns.ConstantFields)) / float64(len(patterns.ConstantFields)+len(patterns.VariableFields)) * 100
		insights = append(insights, fmt.Sprintf("%.1f%% of fields are constant across all responses", constRatio))
	}

	// Analyze unique elements
	uniqueCount := 0
	for _, elements := range patterns.UniqueElements {
		uniqueCount += len(elements)
	}
	if uniqueCount > 0 {
		insights = append(insights, fmt.Sprintf("%d unique field(s) found across %d response(s)", uniqueCount, len(patterns.UniqueElements)))
	}

	return insights
}

// generateAnomalySummary creates a human-readable summary of anomalies
func (bce *BatchComparisonEngine) generateAnomalySummary(anomalies *AnomalyDetection, req BatchComparisonRequest) string {
	parts := make([]string, 0)

	if len(anomalies.UnusualStatusCodes) > 0 {
		parts = append(parts, fmt.Sprintf("%d with unusual status codes", len(anomalies.UnusualStatusCodes)))
	}
	if len(anomalies.UnusualLengths) > 0 {
		parts = append(parts, fmt.Sprintf("%d with unusual content lengths", len(anomalies.UnusualLengths)))
	}
	if len(anomalies.SlowResponses) > 0 {
		parts = append(parts, fmt.Sprintf("%d with slow response times", len(anomalies.SlowResponses)))
	}
	if len(anomalies.UniqueErrors) > 0 {
		parts = append(parts, fmt.Sprintf("%d with unique errors", len(anomalies.UniqueErrors)))
	}

	if len(parts) == 0 {
		return "No significant anomalies detected"
	}

	return fmt.Sprintf("Found anomalies: %s", joinStrings(parts, "; "))
}

// Helper functions for statistics

func calculateMean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

func calculateMedian(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := make([]float64, len(values))
	copy(sorted, values)
	sort.Float64s(sorted)

	n := len(sorted)
	if n%2 == 0 {
		return (sorted[n/2-1] + sorted[n/2]) / 2
	}
	return sorted[n/2]
}

func calculateStdDev(values []float64, mean float64) float64 {
	if len(values) <= 1 {
		return 0
	}
	sumSquares := 0.0
	for _, v := range values {
		diff := v - mean
		sumSquares += diff * diff
	}
	variance := sumSquares / float64(len(values)-1)
	return math.Sqrt(variance)
}

func calculateMin(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	min := values[0]
	for _, v := range values {
		if v < min {
			min = v
		}
	}
	return min
}

func calculateMax(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	max := values[0]
	for _, v := range values {
		if v > max {
			max = v
		}
	}
	return max
}

func getStatusCodesList(dist map[int]int) []int {
	codes := make([]int, 0, len(dist))
	for code := range dist {
		codes = append(codes, code)
	}
	sort.Ints(codes)
	return codes
}

func joinStrings(parts []string, sep string) string {
	if len(parts) == 0 {
		return ""
	}
	result := parts[0]
	for i := 1; i < len(parts); i++ {
		result += sep + parts[i]
	}
	return result
}
