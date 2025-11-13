package blitz

import (
	"math"
	"net/http"
	"regexp"
	"strings"
	"sync"
)

// Analyzer performs real-time response analysis and anomaly detection.
type Analyzer struct {
	config   *AnalyzerConfig
	baseline *baselineMetrics
	mu       sync.RWMutex
}

// baselineMetrics tracks typical response characteristics.
type baselineMetrics struct {
	statusCodes    map[int]int64 // Status code frequency
	totalResponses int64
	totalDuration  int64
	avgContentLen  int64
	contentLenSum  int64
	initialized    bool
}

// NewAnalyzer creates a new response analyzer with the given configuration.
func NewAnalyzer(config *AnalyzerConfig) *Analyzer {
	if config == nil {
		config = &AnalyzerConfig{
			EnableAnomalyDetection:       true,
			StatusCodeDeviationThreshold: 0, // Any different status code
			ContentLengthDeviationPct:    0.2,
			ResponseTimeDeviationFactor:  2.0,
		}
	}

	return &Analyzer{
		config: config,
		baseline: &baselineMetrics{
			statusCodes: make(map[int]int64),
		},
	}
}

// Analyze examines a response and generates analysis results.
func (a *Analyzer) Analyze(result *FuzzResult) {
	// Pattern matching
	if len(a.config.Patterns) > 0 && result.Response.Body != "" {
		result.Matches = a.findPatternMatches(result.Response.Body)
	}

	// Anomaly detection
	if a.config.EnableAnomalyDetection {
		result.Anomaly = a.detectAnomalies(result)
		a.updateBaseline(result)
	}
}

// findPatternMatches searches for configured patterns in the response body.
func (a *Analyzer) findPatternMatches(body string) []PatternMatch {
	var matches []PatternMatch

	for _, pattern := range a.config.Patterns {
		found := pattern.FindAllString(body, -1)
		if len(found) > 0 {
			matches = append(matches, PatternMatch{
				Pattern: pattern.String(),
				Matches: found,
			})
		}
	}

	return matches
}

// detectAnomalies compares the response against baseline metrics.
func (a *Analyzer) detectAnomalies(result *FuzzResult) *AnomalyIndicator {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if !a.baseline.initialized {
		// Not enough data yet
		return nil
	}

	indicator := &AnomalyIndicator{}

	// Status code anomaly
	indicator.StatusCodeAnomaly = a.isStatusCodeAnomaly(result.StatusCode)

	// Content length anomaly
	if a.baseline.avgContentLen > 0 {
		delta := result.ContentLen - a.baseline.avgContentLen
		indicator.ContentLengthDelta = delta

		deviation := float64(abs(delta)) / float64(a.baseline.avgContentLen)
		if deviation > a.config.ContentLengthDeviationPct {
			indicator.IsInteresting = true
		}
	}

	// Response time anomaly
	avgDuration := a.baseline.totalDuration / a.baseline.totalResponses
	if avgDuration > 0 {
		factor := float64(result.Duration) / float64(avgDuration)
		indicator.ResponseTimeFactor = factor

		if factor > a.config.ResponseTimeDeviationFactor || factor < 1.0/a.config.ResponseTimeDeviationFactor {
			indicator.IsInteresting = true
		}
	}

	// Pattern anomalies
	indicator.PatternAnomalies = len(result.Matches)
	if indicator.PatternAnomalies > 0 {
		indicator.IsInteresting = true
	}

	// Status code anomalies are always interesting
	if indicator.StatusCodeAnomaly {
		indicator.IsInteresting = true
	}

	return indicator
}

// isStatusCodeAnomaly checks if the status code differs from the baseline.
func (a *Analyzer) isStatusCodeAnomaly(statusCode int) bool {
	if len(a.baseline.statusCodes) == 0 {
		return false
	}

	// Find the most common status code
	var mostCommon int
	var maxCount int64

	for code, count := range a.baseline.statusCodes {
		if count > maxCount {
			maxCount = count
			mostCommon = code
		}
	}

	// Check if this status code deviates
	return statusCode != mostCommon
}

// updateBaseline incorporates the response into baseline metrics.
func (a *Analyzer) updateBaseline(result *FuzzResult) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Update status code frequency
	a.baseline.statusCodes[result.StatusCode]++

	// Update averages
	a.baseline.totalResponses++
	a.baseline.totalDuration += result.Duration
	a.baseline.contentLenSum += result.ContentLen
	a.baseline.avgContentLen = a.baseline.contentLenSum / a.baseline.totalResponses

	// Mark as initialized after a few samples
	if a.baseline.totalResponses >= 5 {
		a.baseline.initialized = true
	}
}

// GetBaseline returns a snapshot of the current baseline metrics.
func (a *Analyzer) GetBaseline() map[string]interface{} {
	a.mu.RLock()
	defer a.mu.RUnlock()

	statusCodes := make(map[int]int64)
	for k, v := range a.baseline.statusCodes {
		statusCodes[k] = v
	}

	avgDuration := int64(0)
	if a.baseline.totalResponses > 0 {
		avgDuration = a.baseline.totalDuration / a.baseline.totalResponses
	}

	return map[string]interface{}{
		"initialized":      a.baseline.initialized,
		"total_responses":  a.baseline.totalResponses,
		"status_codes":     statusCodes,
		"avg_duration_ms":  avgDuration,
		"avg_content_len":  a.baseline.avgContentLen,
	}
}

// abs returns the absolute value of an int64.
func abs(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}

// CompilePatterns compiles a list of regex pattern strings.
func CompilePatterns(patterns []string) ([]*regexp.Regexp, error) {
	var compiled []*regexp.Regexp

	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, err
		}
		compiled = append(compiled, re)
	}

	return compiled, nil
}

// DefaultPatterns returns common patterns to search for in responses.
func DefaultPatterns() []string {
	return []string{
		// Error indicators
		`(?i)error`,
		`(?i)exception`,
		`(?i)warning`,
		`(?i)fatal`,

		// SQL errors
		`(?i)SQL syntax`,
		`(?i)mysql_fetch`,
		`(?i)ORA-\d+`,
		`(?i)PostgreSQL.*ERROR`,

		// Debug info
		`(?i)stack trace`,
		`(?i)debug`,

		// Potential sensitive data
		`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`, // Email
		`\b\d{3}-\d{2}-\d{4}\b`,                                 // SSN
		`\b(?:\d{4}[-\s]?){3}\d{4}\b`,                           // Credit card
	}
}

// AnalyzeStatusCode provides a human-readable status interpretation.
func AnalyzeStatusCode(code int) string {
	switch {
	case code >= 200 && code < 300:
		return "Success"
	case code >= 300 && code < 400:
		return "Redirect"
	case code >= 400 && code < 500:
		return "Client Error"
	case code >= 500 && code < 600:
		return "Server Error"
	default:
		return "Unknown"
	}
}

// CaptureResponse creates a message snapshot from an HTTP response.
func CaptureResponse(resp *http.Response, body string, limit int) MessageSnapshot {
	snapshot := MessageSnapshot{
		Body: truncate(body, limit),
	}

	if resp != nil {
		snapshot.Headers = flattenHeaders(resp.Header)

		if resp.Request != nil {
			snapshot.Method = resp.Request.Method
			if resp.Request.URL != nil {
				snapshot.URL = resp.Request.URL.String()
			}
		}
	}

	return snapshot
}

// CaptureRequest creates a message snapshot from an HTTP request.
func CaptureRequest(req *http.Request, body []byte, limit int) MessageSnapshot {
	snapshot := MessageSnapshot{
		Body: truncate(string(body), limit),
	}

	if req != nil {
		snapshot.Method = req.Method
		if req.URL != nil {
			snapshot.URL = req.URL.String()
		}
		snapshot.Headers = flattenHeaders(req.Header)
	}

	return snapshot
}

// flattenHeaders converts http.Header to a simple map.
func flattenHeaders(h http.Header) map[string]string {
	if len(h) == 0 {
		return nil
	}

	out := make(map[string]string, len(h))
	for k, v := range h {
		out[k] = strings.Join(v, "; ")
	}

	return out
}

// truncate limits a string to the specified length.
func truncate(s string, limit int) string {
	if limit <= 0 || len(s) <= limit {
		return s
	}

	if limit < 3 {
		return s[:limit]
	}

	return s[:limit-3] + "..."
}

// round rounds a float64 to 2 decimal places.
func round(f float64) float64 {
	return math.Round(f*100) / 100
}
