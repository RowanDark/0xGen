# Delta API Documentation

## Overview

The Delta package provides semantic diff functionality for HTTP responses, JSON, and XML documents. This documentation is for plugin developers and advanced users who want to integrate Delta into their workflows programmatically.

## Package Import

```go
import "github.com/RowanDark/0xgen/internal/delta"
```

## Core Types

### DiffType

Defines the type of diff operation to perform.

```go
type DiffType string

const (
    DiffTypeText DiffType = "text"
    DiffTypeJSON DiffType = "json"
    DiffTypeXML  DiffType = "xml"
)
```

### DiffGranularity

Defines the level of detail for text diffs.

```go
type DiffGranularity string

const (
    GranularityLine      DiffGranularity = "line"
    GranularityWord      DiffGranularity = "word"
    GranularityCharacter DiffGranularity = "character"
)
```

### ChangeType

Represents the type of change detected.

```go
type ChangeType string

const (
    ChangeTypeAdded    ChangeType = "added"
    ChangeTypeRemoved  ChangeType = "removed"
    ChangeTypeModified ChangeType = "modified"
)
```

### Change

Represents a single difference detected between two inputs.

```go
type Change struct {
    Type       ChangeType `json:"type"`
    Path       string     `json:"path,omitempty"`        // JSON path or XPath
    OldValue   string     `json:"old_value,omitempty"`   // Empty for added changes
    NewValue   string     `json:"new_value,omitempty"`   // Empty for removed changes
    LineNumber int        `json:"line_number,omitempty"` // For text diffs
    Context    string     `json:"context,omitempty"`     // Surrounding context
}
```

### DiffResult

Complete result of a diff operation.

```go
type DiffResult struct {
    Type            DiffType      `json:"type"`
    Changes         []Change      `json:"changes"`
    SimilarityScore float64       `json:"similarity_score"` // 0.0 to 100.0
    LeftSize        int           `json:"left_size"`
    RightSize       int           `json:"right_size"`
    ComputeTime     time.Duration `json:"compute_time_ns"`
    Granularity     string        `json:"granularity,omitempty"` // For text diffs
}
```

**Methods:**

```go
// Validate ensures the diff result is well-formed
func (dr DiffResult) Validate() error

// GetAdded returns all added changes
func (dr DiffResult) GetAdded() []Change

// GetRemoved returns all removed changes
func (dr DiffResult) GetRemoved() []Change

// GetModified returns all modified changes
func (dr DiffResult) GetModified() []Change

// Summary returns a human-readable summary
func (dr DiffResult) Summary() string
```

## Simple Diff API

### Engine

Main diff engine for pairwise comparisons.

```go
type Engine struct {
    // Configuration options (future)
}
```

#### NewEngine

Creates a new diff engine.

```go
func NewEngine() *Engine
```

**Example:**

```go
engine := delta.NewEngine()
```

#### Diff

Performs a diff based on the request type.

```go
func (e *Engine) Diff(req DiffRequest) (*DiffResult, error)
```

**Parameters:**
- `req`: DiffRequest containing left/right content and options

**Returns:**
- `*DiffResult`: Diff result with changes and similarity score
- `error`: Error if validation fails or diff computation fails

**Example:**

```go
result, err := engine.Diff(delta.DiffRequest{
    Left:  []byte(`{"user": "alice", "role": "user"}`),
    Right: []byte(`{"user": "alice", "role": "admin"}`),
    Type:  delta.DiffTypeJSON,
})
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Similarity: %.1f%%\n", result.SimilarityScore)
fmt.Printf("Changes: %d\n", len(result.Changes))
```

### DiffRequest

Request to perform a diff operation.

```go
type DiffRequest struct {
    Left        []byte          `json:"left"`
    Right       []byte          `json:"right"`
    Type        DiffType        `json:"type"`
    Granularity DiffGranularity `json:"granularity,omitempty"` // For text diffs
}
```

**Validation:**

```go
func (dr DiffRequest) Validate() error
```

## Batch Comparison API

### BatchComparisonEngine

Engine for comparing multiple responses simultaneously.

```go
type BatchComparisonEngine struct {
    engine *Engine
}
```

#### NewBatchComparisonEngine

Creates a new batch comparison engine.

```go
func NewBatchComparisonEngine() *BatchComparisonEngine
```

**Example:**

```go
batchEngine := delta.NewBatchComparisonEngine()
```

#### CompareBatch

Performs a batch comparison of multiple responses.

```go
func (bce *BatchComparisonEngine) CompareBatch(req BatchComparisonRequest) (*BatchDiffResult, error)
```

**Parameters:**
- `req`: BatchComparisonRequest with responses and configuration

**Returns:**
- `*BatchDiffResult`: Complete batch analysis with matrix, outliers, statistics
- `error`: Error if validation fails or comparison fails

**Example:**

```go
result, err := batchEngine.CompareBatch(delta.BatchComparisonRequest{
    Responses: []delta.ResponseIdentifier{
        {ID: "r1", Content: []byte(`{"status": "ok"}`)},
        {ID: "r2", Content: []byte(`{"status": "ok"}`)},
        {ID: "r3", Content: []byte(`{"status": "error"}`)},
    },
    DiffType:         delta.DiffTypeJSON,
    BaselineStrategy: delta.BaselineAllPairs,
    OutlierThreshold: 80.0,
    EnableClustering: true,
    EnablePatterns:   true,
    EnableAnomalies:  true,
})
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Mean similarity: %.1f%%\n", result.Statistics.MeanSimilarity)
fmt.Printf("Outliers: %v\n", result.Outliers)
```

### BatchComparisonRequest

Request for batch comparison operation.

```go
type BatchComparisonRequest struct {
    Responses        []ResponseIdentifier `json:"responses"`
    DiffType         DiffType             `json:"diff_type"`
    Granularity      DiffGranularity      `json:"granularity,omitempty"`
    BaselineStrategy BaselineStrategy     `json:"baseline_strategy"`
    BaselineIndex    int                  `json:"baseline_index,omitempty"`
    OutlierThreshold float64              `json:"outlier_threshold,omitempty"` // Default: 80.0
    EnableClustering bool                 `json:"enable_clustering"`
    EnablePatterns   bool                 `json:"enable_patterns"`
    EnableAnomalies  bool                 `json:"enable_anomalies"`
}
```

### ResponseIdentifier

Identifies a response in batch comparison.

```go
type ResponseIdentifier struct {
    ID           string            `json:"id"`
    Name         string            `json:"name,omitempty"`
    Content      []byte            `json:"content"`
    StatusCode   int               `json:"status_code,omitempty"`
    ContentType  string            `json:"content_type,omitempty"`
    ResponseTime time.Duration     `json:"response_time_ns,omitempty"`
    Metadata     map[string]string `json:"metadata,omitempty"`
}
```

### BaselineStrategy

Defines how to select the baseline response.

```go
type BaselineStrategy string

const (
    BaselineFirst        BaselineStrategy = "first"         // Use first response
    BaselineMedian       BaselineStrategy = "median"        // Use median similarity
    BaselineUserSelected BaselineStrategy = "user_selected" // User specified
    BaselineAllPairs     BaselineStrategy = "all_pairs"     // Compare all pairs
)
```

### BatchDiffResult

Complete result of batch comparison.

```go
type BatchDiffResult struct {
    Responses        []ResponseIdentifier `json:"responses"`
    Baseline         *ResponseIdentifier  `json:"baseline,omitempty"`
    BaselineIndex    int                  `json:"baseline_index,omitempty"`
    Comparisons      []DiffResult         `json:"comparisons"`
    ComparisonMatrix []ComparisonPair     `json:"comparison_matrix"`
    Outliers         []int                `json:"outliers"`
    SimilarityMatrix [][]float64          `json:"similarity_matrix"`
    Clusters         []ResponseCluster    `json:"clusters,omitempty"`
    Statistics       BatchStatistics      `json:"statistics"`
    Patterns         *PatternAnalysis     `json:"patterns,omitempty"`
    Anomalies        *AnomalyDetection    `json:"anomalies,omitempty"`
    ComputeTime      time.Duration        `json:"compute_time_ns"`
}
```

**Methods:**

```go
// Validate ensures the result is well-formed
func (bdr BatchDiffResult) Validate() error

// Summary returns a human-readable summary
func (bdr BatchDiffResult) Summary() string
```

## Noise Filtering API

### NoiseClassifier

AI-powered noise classifier for filtering temporal changes.

```go
type NoiseClassifier struct {
    patterns     *PatternLibrary
    feedbackStore *FeedbackStore
}
```

#### NewNoiseClassifier

Creates a new noise classifier.

```go
func NewNoiseClassifier() *NoiseClassifier
```

#### ClassifyChange

Classifies a single change as noise or signal.

```go
func (nc *NoiseClassifier) ClassifyChange(change Change) NoiseClassification
```

**Example:**

```go
classifier := delta.NewNoiseClassifier()

change := delta.Change{
    Type:     delta.ChangeTypeModified,
    Path:     "timestamp",
    OldValue: "2024-01-15T10:00:00Z",
    NewValue: "2024-01-15T10:01:00Z",
}

classification := classifier.ClassifyChange(change)
fmt.Printf("Is noise: %v (confidence: %.1f%%)\n",
    classification.IsNoise, classification.Confidence*100)
// Output: Is noise: true (confidence: 95.0%)
```

#### FilterDiff

Applies noise filtering to entire diff result.

```go
func FilterDiff(result *DiffResult, classifier *NoiseClassifier) (*FilteredDiffResult, error)
```

**Example:**

```go
classifier := delta.NewNoiseClassifier()
filtered, err := delta.FilterDiff(diffResult, classifier)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Signal changes: %d\n", len(filtered.SignalChanges))
fmt.Printf("Noise changes: %d\n", len(filtered.NoiseChanges))
fmt.Printf("Noise percentage: %.1f%%\n", filtered.FilterStats.NoisePercentage)
```

### NoiseClassification

Result of noise classification for a single change.

```go
type NoiseClassification struct {
    IsNoise      bool
    Confidence   float64 // 0.0 to 1.0
    Reason       string
    Category     string
    PatternName  string
    UserOverride bool
}
```

### FilteredDiffResult

Diff result with noise filtering applied.

```go
type FilteredDiffResult struct {
    Original        *DiffResult
    SignalChanges   []Change
    NoiseChanges    []Change
    Classifications []NoiseClassification
    FilterStats     FilterStats
    ComputeTime     time.Duration
}
```

## Export API

### BatchExporter

Handles exporting batch comparison results to various formats.

```go
type BatchExporter struct{}
```

#### NewBatchExporter

Creates a new batch exporter.

```go
func NewBatchExporter() *BatchExporter
```

#### Export

Exports to specified format (csv, json, html).

```go
func (be *BatchExporter) Export(result *BatchDiffResult, format ExportFormat) ([]byte, error)
```

#### ExportCSV

Exports similarity matrix to CSV.

```go
func (be *BatchExporter) ExportCSV(result *BatchDiffResult) ([]byte, error)
```

**Example:**

```go
exporter := delta.NewBatchExporter()

csvData, err := exporter.ExportCSV(batchResult)
if err != nil {
    log.Fatal(err)
}

err = os.WriteFile("comparison.csv", csvData, 0644)
```

#### ExportJSON

Exports full results to JSON.

```go
func (be *BatchExporter) ExportJSON(result *BatchDiffResult) ([]byte, error)
```

#### ExportHTML

Exports visual report to HTML.

```go
func (be *BatchExporter) ExportHTML(result *BatchDiffResult) ([]byte, error)
```

#### ExportSummary

Exports plain text summary.

```go
func (be *BatchExporter) ExportSummary(result *BatchDiffResult, w io.Writer) error
```

## Storage API

### Store

In-memory storage for saved diff results.

```go
type Store struct {
    mu    sync.RWMutex
    diffs map[string]StoredDiff
    index map[string][]string // tag -> diff IDs
}
```

#### NewStore

Creates a new diff store.

```go
func NewStore() *Store
```

#### Save

Saves a diff result with tags.

```go
func (s *Store) Save(diff StoredDiff) error
```

**Example:**

```go
store := delta.NewStore()

stored := delta.StoredDiff{
    ID:              "diff-001",
    Name:            "Auth Bypass Test",
    LeftRequestID:   "req-normal",
    RightRequestID:  "req-bypass",
    DiffType:        delta.DiffTypeJSON,
    SimilarityScore: 78.5,
    Changes:         diffResult.Changes,
    Tags:            []string{"auth", "critical"},
    CreatedAt:       time.Now(),
}

err := store.Save(stored)
```

#### Get

Retrieves a diff by ID.

```go
func (s *Store) Get(id string) (*StoredDiff, error)
```

#### List

Lists all stored diffs.

```go
func (s *Store) List() []StoredDiff
```

#### Search

Searches diffs with filters.

```go
func (s *Store) Search(opts SearchOptions) []StoredDiff
```

**Example:**

```go
results := store.Search(delta.SearchOptions{
    MinSimilarity: 70.0,
    MaxSimilarity: 85.0,
    Tags:          []string{"auth"},
    Limit:         10,
})
```

## Complete Examples

### Example 1: Simple JSON Comparison

```go
package main

import (
    "fmt"
    "log"
    "github.com/RowanDark/0xgen/internal/delta"
)

func main() {
    engine := delta.NewEngine()

    left := `{"user": "alice", "role": "user", "session": "abc123"}`
    right := `{"user": "alice", "role": "admin", "session": "xyz789"}`

    result, err := engine.Diff(delta.DiffRequest{
        Left:  []byte(left),
        Right: []byte(right),
        Type:  delta.DiffTypeJSON,
    })
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Similarity: %.1f%%\n", result.SimilarityScore)
    fmt.Printf("Changes: %d\n", len(result.Changes))

    for _, change := range result.Changes {
        fmt.Printf("  %s at %s: %s -> %s\n",
            change.Type, change.Path, change.OldValue, change.NewValue)
    }
}
```

### Example 2: Batch Comparison with Filtering

```go
package main

import (
    "fmt"
    "log"
    "github.com/RowanDark/0xgen/internal/delta"
)

func main() {
    // Load responses (simplified)
    responses := []delta.ResponseIdentifier{
        {ID: "r1", Content: []byte(`{"status": "ok", "time": "10:00"}`)},
        {ID: "r2", Content: []byte(`{"status": "ok", "time": "10:01"}`)},
        {ID: "r3", Content: []byte(`{"status": "error", "time": "10:02"}`)},
    }

    // Batch comparison
    engine := delta.NewBatchComparisonEngine()
    result, err := engine.CompareBatch(delta.BatchComparisonRequest{
        Responses:        responses,
        DiffType:         delta.DiffTypeJSON,
        BaselineStrategy: delta.BaselineAllPairs,
        OutlierThreshold: 80.0,
        EnablePatterns:   true,
    })
    if err != nil {
        log.Fatal(err)
    }

    // Print results
    fmt.Printf("Mean similarity: %.1f%%\n", result.Statistics.MeanSimilarity)
    fmt.Printf("Outliers: %v\n", result.Outliers)

    if result.Patterns != nil {
        for _, insight := range result.Patterns.AIInsights {
            fmt.Printf("  - %s\n", insight)
        }
    }

    // Export
    exporter := delta.NewBatchExporter()
    htmlReport, _ := exporter.ExportHTML(result)
    // Save htmlReport to file
}
```

### Example 3: Custom Plugin Integration

```go
package myplugin

import (
    "github.com/RowanDark/0xgen/internal/delta"
    "github.com/RowanDark/0xgen/pkg/plugin"
)

type MyPlugin struct {
    deltaEngine      *delta.Engine
    classifier       *delta.NoiseClassifier
    store            *delta.Store
}

func (p *MyPlugin) Init() error {
    p.deltaEngine = delta.NewEngine()
    p.classifier = delta.NewNoiseClassifier()
    p.store = delta.NewStore()
    return nil
}

func (p *MyPlugin) AnalyzeResponses(responses [][]byte) (*delta.BatchDiffResult, error) {
    // Convert to ResponseIdentifier
    ids := make([]delta.ResponseIdentifier, len(responses))
    for i, resp := range responses {
        ids[i] = delta.ResponseIdentifier{
            ID:      fmt.Sprintf("resp-%d", i),
            Content: resp,
        }
    }

    // Batch compare
    engine := delta.NewBatchComparisonEngine()
    result, err := engine.CompareBatch(delta.BatchComparisonRequest{
        Responses:        ids,
        DiffType:         delta.DiffTypeJSON,
        BaselineStrategy: delta.BaselineMedian,
        EnableClustering: true,
        EnablePatterns:   true,
        EnableAnomalies:  true,
    })
    if err != nil {
        return nil, err
    }

    // Store result
    stored := delta.StoredDiff{
        ID:              fmt.Sprintf("batch-%d", time.Now().Unix()),
        Name:            "Plugin Analysis",
        DiffType:        delta.DiffTypeJSON,
        SimilarityScore: result.Statistics.MeanSimilarity,
        Tags:            []string{"plugin", "automated"},
        CreatedAt:       time.Now(),
    }
    p.store.Save(stored)

    return result, nil
}
```

## Error Handling

All API functions return errors for validation and computation failures:

```go
// Check validation errors
if err := request.Validate(); err != nil {
    return fmt.Errorf("invalid request: %w", err)
}

// Handle diff errors
result, err := engine.Diff(request)
if err != nil {
    return fmt.Errorf("diff failed: %w", err)
}

// Validate result
if err := result.Validate(); err != nil {
    return fmt.Errorf("invalid result: %w", err)
}
```

## Performance Considerations

### Memory Management

- Diff operations allocate memory proportional to input size
- Batch comparisons store full similarity matrix (N×N)
- Use streaming for very large inputs (>10MB)

### Concurrency

- `Engine` instances are not thread-safe
- Create one `Engine` per goroutine
- `Store` uses `sync.RWMutex` for thread-safety

### Optimization Tips

1. **Reuse engines** within a goroutine
2. **Choose appropriate granularity** (line is fastest)
3. **Enable caching** for repeated comparisons
4. **Limit batch size** to 20-30 for best performance

## Testing

### Running Tests

```bash
go test ./internal/delta/...
```

### Test Coverage

```bash
go test ./internal/delta/... -cover
```

### Benchmarks

```bash
go test ./internal/delta/... -bench=. -benchmem
```

## Versioning

Delta API follows semantic versioning. Current version: **1.0.0**

- Major: Breaking API changes
- Minor: New features, backward compatible
- Patch: Bug fixes

## Support

- **API Issues**: https://github.com/RowanDark/0xGen/issues
- **Examples**: `/examples/delta/`
- **Community**: 0xGen Discord server

---

**Last Updated**: January 2025
**Contributors**: 0xGen Team
