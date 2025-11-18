package main

import (
	"time"

	pluginsdk "github.com/RowanDark/0xgen/sdk/plugin-sdk"
)

// RiskLevel represents the risk severity
type RiskLevel string

const (
	RiskLow      RiskLevel = "low"
	RiskMedium   RiskLevel = "medium"
	RiskHigh     RiskLevel = "high"
	RiskCritical RiskLevel = "critical"
)

// TokenExtractor defines how to extract tokens from HTTP responses
type TokenExtractor struct {
	Pattern  string `json:"pattern"`  // Regex or JSON path
	Location string `json:"location"` // Header, Cookie, Body
	Name     string `json:"name"`     // e.g., "sessionid", "csrf_token"
}

// TokenSample represents a single captured token
type TokenSample struct {
	ID               int64     `json:"id"`
	CaptureSessionID int64     `json:"capture_session_id"`
	TokenValue       string    `json:"token_value"`
	TokenLength      int       `json:"token_length"`
	CapturedAt       time.Time `json:"captured_at"`
	SourceRequestID  string    `json:"source_request_id,omitempty"`
}

// TestResult holds the outcome of a statistical test
type TestResult struct {
	PValue      float64 `json:"p_value"`
	Passed      bool    `json:"passed"` // p-value > 0.01
	Confidence  float64 `json:"confidence"`
	Description string  `json:"description"`
}

// Indicator represents a PRNG detection indicator
type Indicator struct {
	Test      string  `json:"test"`      // Which test reveals it
	Threshold float64 `json:"threshold"` // p-value or metric threshold
	Pattern   string  `json:"pattern"`   // Optional: regex or bit pattern
}

// PRNGSignature represents a known weak PRNG pattern
type PRNGSignature struct {
	Name        string      `json:"name"`         // "Java Random", "PHP mt_rand", etc.
	Indicators  []Indicator `json:"indicators"`   // Detection indicators
	Weakness    string      `json:"weakness"`     // Description of weakness
	ExploitHint string      `json:"exploit_hint"` // How to exploit
	Confidence  float64     `json:"confidence"`   // Detection confidence
}

// Pattern represents a detected pattern in token generation
type Pattern struct {
	Type        string  `json:"type"`        // Sequential, Timestamp-based, etc.
	Confidence  float64 `json:"confidence"`  // 0-1
	Description string  `json:"description"` // Human-readable explanation
	Evidence    string  `json:"evidence"`    // Supporting data
}

// EntropyAnalysis represents the complete analysis result
type EntropyAnalysis struct {
	CaptureSessionID int64   `json:"capture_session_id"`
	TokenCount       int     `json:"token_count"`
	TokenLength      int     `json:"token_length"`
	CharacterSet     []rune  `json:"character_set"`

	// Statistical test results
	ChiSquared        TestResult `json:"chi_squared"`
	Runs              TestResult `json:"runs"`
	SerialCorrelation TestResult `json:"serial_correlation"`
	Spectral          TestResult `json:"spectral"`
	ShannonEntropy    float64    `json:"shannon_entropy"`
	CollisionRate     float64    `json:"collision_rate"`
	BitDistribution   []float64  `json:"bit_distribution"`

	// AI analysis
	DetectedPRNG     *PRNGSignature `json:"detected_prng,omitempty"`
	DetectedPatterns []Pattern      `json:"detected_patterns"`
	Recommendations  []string       `json:"recommendations"`

	// Overall assessment
	RandomnessScore float64   `json:"randomness_score"` // 0-100
	Risk            RiskLevel `json:"risk"`

	// Confidence and reliability metrics
	ConfidenceLevel  float64 `json:"confidence_level"`   // 0-1, based on sample size
	ReliabilityScore float64 `json:"reliability_score"`  // 0-100, overall reliability
	TokensNeeded     int     `json:"tokens_needed"`      // Tokens needed for full confidence
	SampleQuality    string  `json:"sample_quality"`     // "insufficient", "marginal", "adequate", "excellent"
}

// CaptureStatus represents the state of a capture session
type CaptureStatus string

const (
	CaptureStatusActive  CaptureStatus = "active"
	CaptureStatusPaused  CaptureStatus = "paused"
	CaptureStatusStopped CaptureStatus = "stopped"
)

// StopReason indicates why a session stopped
type StopReason string

const (
	StopReasonManual          StopReason = "manual"           // User stopped manually
	StopReasonTargetReached   StopReason = "target_reached"   // Token count target reached
	StopReasonTimeout         StopReason = "timeout"          // Session timeout expired
	StopReasonPatternDetected StopReason = "pattern_detected" // Weak pattern detected, no need for more samples
	StopReasonError           StopReason = "error"            // Error occurred
)

// CaptureSession represents a token capture session with lifecycle management
type CaptureSession struct {
	ID          int64          `json:"id"`
	Name        string         `json:"name"`
	Extractor   TokenExtractor `json:"extractor"`
	StartedAt   time.Time      `json:"started_at"`
	CompletedAt *time.Time     `json:"completed_at,omitempty"`
	PausedAt    *time.Time     `json:"paused_at,omitempty"`
	TokenCount  int            `json:"token_count"`
	Status      CaptureStatus  `json:"status"`

	// Auto-stop conditions
	TargetCount int           `json:"target_count,omitempty"` // Stop after N tokens (0 = no limit)
	Timeout     time.Duration `json:"timeout,omitempty"`      // Stop after duration (0 = no timeout)
	StopReason  StopReason    `json:"stop_reason,omitempty"`

	// Incremental analysis tracking
	LastAnalyzedAt    *time.Time `json:"last_analyzed_at,omitempty"`
	LastAnalysisCount int        `json:"last_analysis_count"`     // Token count at last analysis
	AnalysisInterval  int        `json:"analysis_interval"`       // Analyze every N tokens (default: 50)
}

// IsActive returns true if the session is actively capturing
func (s *CaptureSession) IsActive() bool {
	return s.Status == CaptureStatusActive
}

// IsPaused returns true if the session is paused
func (s *CaptureSession) IsPaused() bool {
	return s.Status == CaptureStatusPaused
}

// IsStopped returns true if the session is stopped
func (s *CaptureSession) IsStopped() bool {
	return s.Status == CaptureStatusStopped
}

// ShouldAnalyze returns true if it's time to run analysis
func (s *CaptureSession) ShouldAnalyze() bool {
	if s.AnalysisInterval <= 0 {
		return false
	}
	tokensSinceLastAnalysis := s.TokenCount - s.LastAnalysisCount
	return tokensSinceLastAnalysis >= s.AnalysisInterval
}

// IsTimedOut returns true if the session has exceeded its timeout
func (s *CaptureSession) IsTimedOut(now time.Time) bool {
	if s.Timeout <= 0 {
		return false
	}
	elapsed := now.Sub(s.StartedAt)
	return elapsed >= s.Timeout
}

// HasReachedTarget returns true if the token count target has been reached
func (s *CaptureSession) HasReachedTarget() bool {
	if s.TargetCount <= 0 {
		return false
	}
	return s.TokenCount >= s.TargetCount
}

// SessionNotification represents an event notification for a session
type SessionNotification struct {
	SessionID   int64         `json:"session_id"`
	SessionName string        `json:"session_name"`
	Event       string        `json:"event"` // started, paused, stopped, analyzed, target_reached, etc.
	Message     string        `json:"message"`
	Timestamp   time.Time     `json:"timestamp"`
	Data        map[string]interface{} `json:"data,omitempty"`
}

// IncrementalStats holds streaming statistics that update as tokens arrive
type IncrementalStats struct {
	// Running totals
	TokenCount     int                `json:"token_count"`
	CharFrequency  map[rune]int       `json:"char_frequency"`
	TotalChars     int                `json:"total_chars"`
	UniqueTokens   map[string]bool    `json:"-"` // Not serialized (could be large)
	CollisionCount int                `json:"collision_count"`

	// Incremental entropy
	CurrentEntropy float64 `json:"current_entropy"`

	// Confidence metrics
	MinSampleSize    int     `json:"min_sample_size"`     // Minimum tokens needed for reliable results
	ConfidenceLevel  float64 `json:"confidence_level"`    // 0-1, based on sample size
	TokensNeeded     int     `json:"tokens_needed"`       // How many more tokens needed
	ReliabilityScore float64 `json:"reliability_score"`   // 0-100, overall reliability

	// Last update
	LastUpdated time.Time `json:"last_updated"`
}

// ToSeverity converts RiskLevel to pluginsdk.Severity
func (r RiskLevel) ToSeverity() pluginsdk.Severity {
	switch r {
	case RiskLow:
		return pluginsdk.SeverityLow
	case RiskMedium:
		return pluginsdk.SeverityMedium
	case RiskHigh:
		return pluginsdk.SeverityHigh
	case RiskCritical:
		return pluginsdk.SeverityCritical
	default:
		return pluginsdk.SeverityInfo
	}
}
