// Package delta implements semantic diffing for text, JSON, and XML responses.
package delta

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// DiffType defines the type of diff being performed
type DiffType string

const (
	DiffTypeText DiffType = "text"
	DiffTypeJSON DiffType = "json"
	DiffTypeXML  DiffType = "xml"
)

// ChangeType defines the type of change detected
type ChangeType string

const (
	ChangeTypeAdded    ChangeType = "added"
	ChangeTypeRemoved  ChangeType = "removed"
	ChangeTypeModified ChangeType = "modified"
)

// DiffGranularity defines the level of detail for text diffs
type DiffGranularity string

const (
	GranularityLine      DiffGranularity = "line"
	GranularityWord      DiffGranularity = "word"
	GranularityCharacter DiffGranularity = "character"
)

var (
	diffTypeSet = map[DiffType]struct{}{
		DiffTypeText: {},
		DiffTypeJSON: {},
		DiffTypeXML:  {},
	}

	changeTypeSet = map[ChangeType]struct{}{
		ChangeTypeAdded:    {},
		ChangeTypeRemoved:  {},
		ChangeTypeModified: {},
	}

	granularitySet = map[DiffGranularity]struct{}{
		GranularityLine:      {},
		GranularityWord:      {},
		GranularityCharacter: {},
	}
)

// validate checks if the DiffType is valid
func (dt DiffType) validate() error {
	if _, ok := diffTypeSet[dt]; !ok {
		return fmt.Errorf("invalid diff type: %q", dt)
	}
	return nil
}

// validate checks if the ChangeType is valid
func (ct ChangeType) validate() error {
	if _, ok := changeTypeSet[ct]; !ok {
		return fmt.Errorf("invalid change type: %q", ct)
	}
	return nil
}

// validate checks if the DiffGranularity is valid
func (dg DiffGranularity) validate() error {
	if _, ok := granularitySet[dg]; !ok {
		return fmt.Errorf("invalid granularity: %q", dg)
	}
	return nil
}

// Change represents a single difference detected between two inputs
type Change struct {
	Type       ChangeType `json:"type"`
	Path       string     `json:"path,omitempty"`        // JSON path or XPath
	OldValue   string     `json:"old_value,omitempty"`   // Empty for added changes
	NewValue   string     `json:"new_value,omitempty"`   // Empty for removed changes
	LineNumber int        `json:"line_number,omitempty"` // For text diffs
	Context    string     `json:"context,omitempty"`     // Surrounding context
}

// Validate ensures the change is well-formed
func (c Change) Validate() error {
	if err := c.Type.validate(); err != nil {
		return err
	}

	switch c.Type {
	case ChangeTypeAdded:
		if strings.TrimSpace(c.NewValue) == "" {
			return errors.New("added change must have new_value")
		}
	case ChangeTypeRemoved:
		if strings.TrimSpace(c.OldValue) == "" {
			return errors.New("removed change must have old_value")
		}
	case ChangeTypeModified:
		if strings.TrimSpace(c.OldValue) == "" || strings.TrimSpace(c.NewValue) == "" {
			return errors.New("modified change must have both old_value and new_value")
		}
	}

	return nil
}

// DiffResult represents the complete result of a diff operation
type DiffResult struct {
	Type            DiffType      `json:"type"`
	Changes         []Change      `json:"changes"`
	SimilarityScore float64       `json:"similarity_score"` // 0.0 to 100.0
	LeftSize        int           `json:"left_size"`
	RightSize       int           `json:"right_size"`
	ComputeTime     time.Duration `json:"compute_time_ns"`
	Granularity     string        `json:"granularity,omitempty"` // For text diffs
}

// Validate ensures the diff result is well-formed
func (dr DiffResult) Validate() error {
	if err := dr.Type.validate(); err != nil {
		return err
	}

	if dr.SimilarityScore < 0 || dr.SimilarityScore > 100 {
		return fmt.Errorf("similarity score must be between 0 and 100, got %.2f", dr.SimilarityScore)
	}

	if dr.LeftSize < 0 {
		return fmt.Errorf("left_size cannot be negative: %d", dr.LeftSize)
	}

	if dr.RightSize < 0 {
		return fmt.Errorf("right_size cannot be negative: %d", dr.RightSize)
	}

	for i, change := range dr.Changes {
		if err := change.Validate(); err != nil {
			return fmt.Errorf("invalid change at index %d: %w", i, err)
		}
	}

	return nil
}

// GetAdded returns all added changes
func (dr DiffResult) GetAdded() []Change {
	var added []Change
	for _, change := range dr.Changes {
		if change.Type == ChangeTypeAdded {
			added = append(added, change)
		}
	}
	return added
}

// GetRemoved returns all removed changes
func (dr DiffResult) GetRemoved() []Change {
	var removed []Change
	for _, change := range dr.Changes {
		if change.Type == ChangeTypeRemoved {
			removed = append(removed, change)
		}
	}
	return removed
}

// GetModified returns all modified changes
func (dr DiffResult) GetModified() []Change {
	var modified []Change
	for _, change := range dr.Changes {
		if change.Type == ChangeTypeModified {
			modified = append(modified, change)
		}
	}
	return modified
}

// Summary returns a human-readable summary of the diff
func (dr DiffResult) Summary() string {
	added := len(dr.GetAdded())
	removed := len(dr.GetRemoved())
	modified := len(dr.GetModified())

	return fmt.Sprintf("%d changes (%.1f%% similar): %d added, %d removed, %d modified",
		len(dr.Changes), dr.SimilarityScore, added, removed, modified)
}

// DiffRequest represents a request to perform a diff
type DiffRequest struct {
	Left        []byte          `json:"left"`
	Right       []byte          `json:"right"`
	Type        DiffType        `json:"type"`
	Granularity DiffGranularity `json:"granularity,omitempty"` // For text diffs
}

// Validate ensures the diff request is well-formed
func (dr DiffRequest) Validate() error {
	if err := dr.Type.validate(); err != nil {
		return err
	}

	if len(dr.Left) == 0 {
		return errors.New("left input is empty")
	}

	if len(dr.Right) == 0 {
		return errors.New("right input is empty")
	}

	if dr.Type == DiffTypeText && dr.Granularity != "" {
		if err := dr.Granularity.validate(); err != nil {
			return err
		}
	}

	return nil
}

// StoredDiff represents a diff stored in persistent storage
type StoredDiff struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	LeftRequestID   string     `json:"left_request_id,omitempty"`
	RightRequestID  string     `json:"right_request_id,omitempty"`
	DiffType        DiffType   `json:"diff_type"`
	SimilarityScore float64    `json:"similarity_score"`
	Changes         []Change   `json:"changes"`
	Tags            []string   `json:"tags,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	ComputeTime     time.Duration `json:"compute_time_ns"`
}

// Validate ensures the stored diff is well-formed
func (sd StoredDiff) Validate() error {
	if strings.TrimSpace(sd.ID) == "" {
		return errors.New("id is required")
	}

	if strings.TrimSpace(sd.Name) == "" {
		return errors.New("name is required")
	}

	if err := sd.DiffType.validate(); err != nil {
		return err
	}

	if sd.SimilarityScore < 0 || sd.SimilarityScore > 100 {
		return fmt.Errorf("similarity score must be between 0 and 100, got %.2f", sd.SimilarityScore)
	}

	if sd.CreatedAt.IsZero() {
		return errors.New("created_at is required")
	}

	for i, change := range sd.Changes {
		if err := change.Validate(); err != nil {
			return fmt.Errorf("invalid change at index %d: %w", i, err)
		}
	}

	return nil
}

// MarshalJSON ensures proper JSON encoding
func (sd StoredDiff) MarshalJSON() ([]byte, error) {
	type Alias StoredDiff
	return json.Marshal(&struct {
		*Alias
		ComputeTime int64 `json:"compute_time_ns"`
	}{
		Alias:       (*Alias)(&sd),
		ComputeTime: int64(sd.ComputeTime),
	})
}

// UnmarshalJSON ensures proper JSON decoding
func (sd *StoredDiff) UnmarshalJSON(data []byte) error {
	type Alias StoredDiff
	aux := &struct {
		*Alias
		ComputeTime int64 `json:"compute_time_ns"`
	}{
		Alias: (*Alias)(sd),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	sd.ComputeTime = time.Duration(aux.ComputeTime)
	return nil
}

// BaselineStrategy defines how to select the baseline response in batch comparison
type BaselineStrategy string

const (
	BaselineFirst        BaselineStrategy = "first"         // Use first response as baseline
	BaselineMedian       BaselineStrategy = "median"        // Use median similarity as baseline
	BaselineUserSelected BaselineStrategy = "user_selected" // User specifies baseline index
	BaselineAllPairs     BaselineStrategy = "all_pairs"     // Compare all pairs (N×N matrix)
)

var (
	baselineStrategySet = map[BaselineStrategy]struct{}{
		BaselineFirst:        {},
		BaselineMedian:       {},
		BaselineUserSelected: {},
		BaselineAllPairs:     {},
	}
)

// validate checks if the BaselineStrategy is valid
func (bs BaselineStrategy) validate() error {
	if _, ok := baselineStrategySet[bs]; !ok {
		return fmt.Errorf("invalid baseline strategy: %q", bs)
	}
	return nil
}

// ResponseIdentifier uniquely identifies a response in a batch comparison
type ResponseIdentifier struct {
	ID          string    `json:"id"`                     // Unique identifier (e.g., request ID)
	Name        string    `json:"name,omitempty"`         // Human-readable name
	Content     []byte    `json:"content"`                // Response content
	StatusCode  int       `json:"status_code,omitempty"`  // HTTP status code
	ContentType string    `json:"content_type,omitempty"` // Content type
	ResponseTime time.Duration `json:"response_time_ns,omitempty"` // Response time
	Metadata    map[string]string `json:"metadata,omitempty"` // Additional metadata
}

// Validate ensures the response identifier is well-formed
func (ri ResponseIdentifier) Validate() error {
	if strings.TrimSpace(ri.ID) == "" {
		return errors.New("response id is required")
	}
	if len(ri.Content) == 0 {
		return errors.New("response content is empty")
	}
	return nil
}

// BatchComparisonRequest represents a request to compare multiple responses
type BatchComparisonRequest struct {
	Responses        []ResponseIdentifier `json:"responses"`
	DiffType         DiffType             `json:"diff_type"`
	Granularity      DiffGranularity      `json:"granularity,omitempty"`       // For text diffs
	BaselineStrategy BaselineStrategy     `json:"baseline_strategy"`
	BaselineIndex    int                  `json:"baseline_index,omitempty"`    // For user_selected strategy
	OutlierThreshold float64              `json:"outlier_threshold,omitempty"` // Similarity threshold for outliers (default: 80.0)
	EnableClustering bool                 `json:"enable_clustering"`
	EnablePatterns   bool                 `json:"enable_patterns"`
	EnableAnomalies  bool                 `json:"enable_anomalies"`
}

// Validate ensures the batch comparison request is well-formed
func (bcr BatchComparisonRequest) Validate() error {
	if len(bcr.Responses) < 2 {
		return errors.New("at least 2 responses required for batch comparison")
	}
	if len(bcr.Responses) > 50 {
		return errors.New("maximum 50 responses allowed for batch comparison")
	}

	if err := bcr.DiffType.validate(); err != nil {
		return err
	}

	if err := bcr.BaselineStrategy.validate(); err != nil {
		return err
	}

	if bcr.BaselineStrategy == BaselineUserSelected {
		if bcr.BaselineIndex < 0 || bcr.BaselineIndex >= len(bcr.Responses) {
			return fmt.Errorf("baseline_index %d out of range [0, %d)", bcr.BaselineIndex, len(bcr.Responses))
		}
	}

	for i, resp := range bcr.Responses {
		if err := resp.Validate(); err != nil {
			return fmt.Errorf("invalid response at index %d: %w", i, err)
		}
	}

	return nil
}

// ResponseCluster represents a group of similar responses
type ResponseCluster struct {
	ClusterID         int      `json:"cluster_id"`
	ResponseIndices   []int    `json:"response_indices"`          // Indices of responses in this cluster
	Representative    int      `json:"representative"`            // Index of representative response
	AvgSimilarity     float64  `json:"avg_similarity"`            // Average similarity within cluster
	Size              int      `json:"size"`                      // Number of responses in cluster
}

// BatchStatistics contains statistical analysis across batch responses
type BatchStatistics struct {
	TotalResponses      int                `json:"total_responses"`
	TotalComparisons    int                `json:"total_comparisons"`
	MeanSimilarity      float64            `json:"mean_similarity"`
	MedianSimilarity    float64            `json:"median_similarity"`
	StdDevSimilarity    float64            `json:"std_dev_similarity"`
	MinSimilarity       float64            `json:"min_similarity"`
	MaxSimilarity       float64            `json:"max_similarity"`
	ResponseTimeStats   DistributionStats  `json:"response_time_stats,omitempty"`
	StatusCodeDist      map[int]int        `json:"status_code_distribution,omitempty"`
	ContentLengthStats  DistributionStats  `json:"content_length_stats,omitempty"`
}

// DistributionStats contains statistical distribution metrics
type DistributionStats struct {
	Mean   float64 `json:"mean"`
	Median float64 `json:"median"`
	StdDev float64 `json:"std_dev"`
	Min    float64 `json:"min"`
	Max    float64 `json:"max"`
}

// PatternAnalysis contains detected patterns across responses
type PatternAnalysis struct {
	CommonHeaders      map[string]int            `json:"common_headers,omitempty"`       // Header -> occurrence count
	CommonJSONKeys     map[string]int            `json:"common_json_keys,omitempty"`     // JSON key -> occurrence count
	CommonErrorMsgs    map[string]int            `json:"common_error_msgs,omitempty"`    // Error message -> occurrence count
	UniqueElements     map[int][]string          `json:"unique_elements,omitempty"`      // Response index -> unique elements
	ConstantFields     []string                  `json:"constant_fields,omitempty"`      // Fields that never change
	VariableFields     []string                  `json:"variable_fields,omitempty"`      // Fields that change across responses
	AIInsights         []string                  `json:"ai_insights,omitempty"`          // AI-generated insights
}

// AnomalyDetection contains detected anomalies in the batch
type AnomalyDetection struct {
	UnusualStatusCodes  []int    `json:"unusual_status_codes,omitempty"`  // Response indices with unusual status codes
	UnusualLengths      []int    `json:"unusual_lengths,omitempty"`       // Response indices with unusual content lengths
	UniqueErrors        []int    `json:"unique_errors,omitempty"`         // Response indices with unique error messages
	SlowResponses       []int    `json:"slow_responses,omitempty"`        // Response indices with unusual response times
	Summary             string   `json:"summary,omitempty"`               // Human-readable summary
}

// BatchDiffResult represents the complete result of a batch comparison
type BatchDiffResult struct {
	Responses           []ResponseIdentifier `json:"responses"`
	Baseline            *ResponseIdentifier  `json:"baseline,omitempty"`
	BaselineIndex       int                  `json:"baseline_index,omitempty"`
	Comparisons         []DiffResult         `json:"comparisons"`              // Results of each comparison
	ComparisonMatrix    []ComparisonPair     `json:"comparison_matrix"`        // For all-pairs strategy
	Outliers            []int                `json:"outliers"`                 // Indices of outlier responses
	SimilarityMatrix    [][]float64          `json:"similarity_matrix"`        // N×N similarity matrix
	Clusters            []ResponseCluster    `json:"clusters,omitempty"`       // Response clusters
	Statistics          BatchStatistics      `json:"statistics"`
	Patterns            *PatternAnalysis     `json:"patterns,omitempty"`
	Anomalies           *AnomalyDetection    `json:"anomalies,omitempty"`
	ComputeTime         time.Duration        `json:"compute_time_ns"`
}

// ComparisonPair represents a single pairwise comparison in all-pairs mode
type ComparisonPair struct {
	LeftIndex       int        `json:"left_index"`
	RightIndex      int        `json:"right_index"`
	DiffResult      DiffResult `json:"diff_result"`
}

// Validate ensures the batch diff result is well-formed
func (bdr BatchDiffResult) Validate() error {
	if len(bdr.Responses) < 2 {
		return errors.New("at least 2 responses required")
	}

	for i, resp := range bdr.Responses {
		if err := resp.Validate(); err != nil {
			return fmt.Errorf("invalid response at index %d: %w", i, err)
		}
	}

	// Validate similarity matrix dimensions
	if len(bdr.SimilarityMatrix) != len(bdr.Responses) {
		return fmt.Errorf("similarity matrix row count %d does not match response count %d",
			len(bdr.SimilarityMatrix), len(bdr.Responses))
	}
	for i, row := range bdr.SimilarityMatrix {
		if len(row) != len(bdr.Responses) {
			return fmt.Errorf("similarity matrix row %d has %d columns, expected %d",
				i, len(row), len(bdr.Responses))
		}
	}

	// Validate outlier indices
	for _, idx := range bdr.Outliers {
		if idx < 0 || idx >= len(bdr.Responses) {
			return fmt.Errorf("outlier index %d out of range [0, %d)", idx, len(bdr.Responses))
		}
	}

	return nil
}

// Summary returns a human-readable summary of the batch comparison
func (bdr BatchDiffResult) Summary() string {
	return fmt.Sprintf("%d responses compared, %.1f%% avg similarity, %d outliers, %d clusters",
		len(bdr.Responses),
		bdr.Statistics.MeanSimilarity,
		len(bdr.Outliers),
		len(bdr.Clusters))
}
