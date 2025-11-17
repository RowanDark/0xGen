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
}

// CaptureSession represents a token capture session
type CaptureSession struct {
	ID         int64     `json:"id"`
	Name       string    `json:"name"`
	Extractor  TokenExtractor `json:"extractor"`
	StartedAt  time.Time `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	TokenCount int       `json:"token_count"`
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
