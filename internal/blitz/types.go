package blitz

import (
	"net/http"
	"regexp"
	"time"

	"github.com/RowanDark/0xgen/internal/findings"
)

// AttackType defines the fuzzing strategy for multiple payload positions.
type AttackType string

const (
	// Sniper replaces one position at a time with payloads while leaving others at default.
	AttackTypeSniper AttackType = "sniper"

	// BatteringRam uses the same payload value across all positions simultaneously.
	AttackTypeBatteringRam AttackType = "battering-ram"

	// Pitchfork pairs payloads from multiple lists, advancing through them in parallel.
	AttackTypePitchfork AttackType = "pitchfork"

	// ClusterBomb generates all possible combinations of payloads across positions.
	AttackTypeClusterBomb AttackType = "cluster-bomb"
)

// PayloadGenerator produces payloads for fuzzing operations.
type PayloadGenerator interface {
	// Generate returns all payloads for this generator.
	Generate() ([]string, error)

	// Name returns a human-readable name for this generator.
	Name() string
}

// Markers defines the delimiters used to mark payload insertion points.
// Compatible with raider.Markers but defined here for independence.
type Markers struct {
	Open  string
	Close string
}

// Position describes a payload insertion point in the request template.
type Position struct {
	Index   int    // Zero-based index in the template
	Name    string // Name/label for this position (from marker content)
	Default string // Default value when position is not targeted
}

// Request represents an HTTP request template with insertion points.
type Request struct {
	Raw       string     // Raw HTTP request template
	Positions []Position // Discovered insertion points
	Markers   Markers    // Marker delimiters used
}

// FuzzResult captures the outcome of a single fuzzing attempt.
type FuzzResult struct {
	ID           int64             `json:"id,omitempty"`
	RequestID    string            `json:"request_id"`
	Position     int               `json:"position"`
	PositionName string            `json:"position_name"`
	Payload      string            `json:"payload"`
	PayloadSet   map[int]string    `json:"payload_set,omitempty"` // For multi-position attacks
	StatusCode   int               `json:"status_code"`
	Duration     int64             `json:"duration_ms"`
	ContentLen   int64             `json:"content_length"`
	Request      MessageSnapshot   `json:"request"`
	Response     MessageSnapshot   `json:"response"`
	Matches      []PatternMatch    `json:"matches,omitempty"`
	Error        string            `json:"error,omitempty"`
	Timestamp    time.Time         `json:"timestamp"`
	Anomaly      *AnomalyIndicator `json:"anomaly,omitempty"`
}

// MessageSnapshot stores truncated HTTP message details.
type MessageSnapshot struct {
	Method  string            `json:"method,omitempty"`
	URL     string            `json:"url,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// PatternMatch records a regex match in the response.
type PatternMatch struct {
	Pattern string   `json:"pattern"`
	Matches []string `json:"matches"`
}

// AnomalyIndicator flags responses that differ from the baseline.
type AnomalyIndicator struct {
	StatusCodeAnomaly   bool    `json:"status_code_anomaly"`
	ContentLengthDelta  int64   `json:"content_length_delta"`
	ResponseTimeFactor  float64 `json:"response_time_factor"`
	PatternAnomalies    int     `json:"pattern_anomalies"`
	IsInteresting       bool    `json:"is_interesting"`
}

// AnalyzerConfig configures response analysis behavior.
type AnalyzerConfig struct {
	// Patterns to search for in responses (regex).
	Patterns []*regexp.Regexp

	// Track baseline metrics for anomaly detection.
	EnableAnomalyDetection bool

	// Thresholds for anomaly detection.
	StatusCodeDeviationThreshold int     // Status code difference to flag
	ContentLengthDeviationPct    float64 // Percentage deviation in content length
	ResponseTimeDeviationFactor  float64 // Factor deviation in response time
}

// EngineConfig configures the fuzzing engine.
type EngineConfig struct {
	// Request template with insertion points.
	Request *Request

	// Attack type determines how payloads are combined.
	AttackType AttackType

	// Payload generators (one per position for Pitchfork, shared otherwise).
	Generators []PayloadGenerator

	// HTTP client for making requests.
	Client *http.Client

	// Concurrency controls the number of parallel workers.
	Concurrency int

	// RateLimit specifies requests per second (0 = unlimited).
	RateLimit float64

	// MaxRetries for failed requests.
	MaxRetries int

	// CaptureLimit sets the maximum body bytes to capture.
	CaptureLimit int

	// Analyzer configuration.
	Analyzer *AnalyzerConfig

	// Storage backend (optional).
	Storage Storage

	// AI-powered features
	// EnableAIPayloads uses AI to generate contextually relevant payloads.
	EnableAIPayloads bool

	// EnableAIClassification uses AI to classify responses.
	EnableAIClassification bool

	// EnableFindingsCorrelation converts interesting results to 0xGen findings.
	EnableFindingsCorrelation bool

	// FindingsCallback is called when findings are detected (optional).
	FindingsCallback func(*findings.Finding) error
}

// Storage defines the interface for persisting fuzzing results.
type Storage interface {
	// Store saves a fuzzing result.
	Store(result *FuzzResult) error

	// Query retrieves results matching the given filters.
	Query(filters QueryFilters) ([]*FuzzResult, error)

	// GetStats returns summary statistics for the fuzzing session.
	GetStats() (*Stats, error)

	// Close releases resources.
	Close() error
}

// QueryFilters defines criteria for querying stored results.
type QueryFilters struct {
	StatusCodes    []int
	MinDuration    int64
	MaxDuration    int64
	HasError       *bool
	HasAnomalies   *bool
	PatternMatches []string
	Limit          int
	Offset         int
}

// Stats provides summary statistics for a fuzzing session.
type Stats struct {
	TotalRequests    int64
	SuccessfulReqs   int64
	FailedReqs       int64
	UniqueStatuses   map[int]int64
	AvgDuration      int64
	MinDuration      int64
	MaxDuration      int64
	AnomalyCount     int64
	PatternMatchCount int64
}

// Exporter exports results in various formats.
type Exporter interface {
	// Export writes results to the specified destination.
	Export(results []*FuzzResult, destination string) error

	// Format returns the export format name.
	Format() string
}
