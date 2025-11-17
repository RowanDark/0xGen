package delta

import (
	"regexp"
	"strings"
)

// NoiseCategory represents types of noise in HTTP responses
type NoiseCategory string

const (
	NoiseCategoryTimestamp  NoiseCategory = "timestamp"
	NoiseCategorySessionID  NoiseCategory = "session_id"
	NoiseCategoryUUID       NoiseCategory = "uuid"
	NoiseCategoryCSRFToken  NoiseCategory = "csrf_token"
	NoiseCategoryNonce      NoiseCategory = "nonce"
	NoiseCategoryRequestID  NoiseCategory = "request_id"
	NoiseCategoryCache      NoiseCategory = "cache_header"
	NoiseCategoryETag       NoiseCategory = "etag"
	NoiseCategoryDate       NoiseCategory = "date_header"
	NoiseCategoryRandom     NoiseCategory = "random_value"
	NoiseCategoryBuildID    NoiseCategory = "build_id"
	NoiseCategoryVersion    NoiseCategory = "version_string"
)

// NoisePattern represents a pattern that matches noise changes
type NoisePattern struct {
	Name        string
	Category    NoiseCategory
	Regex       *regexp.Regexp
	PathPattern *regexp.Regexp  // Optional: match specific JSON/XML paths
	Confidence  float64
	Description string
	Enabled     bool
}

// NoisePatternLibrary contains all noise detection patterns
type NoisePatternLibrary struct {
	patterns []NoisePattern
	enabled  map[string]bool
}

// NewNoisePatternLibrary creates a new pattern library with default patterns
func NewNoisePatternLibrary() *NoisePatternLibrary {
	lib := &NoisePatternLibrary{
		patterns: make([]NoisePattern, 0),
		enabled:  make(map[string]bool),
	}

	lib.initializeDefaultPatterns()
	return lib
}

// initializeDefaultPatterns sets up the default noise detection patterns
func (l *NoisePatternLibrary) initializeDefaultPatterns() {
	defaultPatterns := []NoisePattern{
		// Timestamp patterns
		{
			Name:        "ISO8601 Timestamp",
			Category:    NoiseCategoryTimestamp,
			Regex:       regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?`),
			Confidence:  0.95,
			Description: "ISO 8601 formatted timestamp",
			Enabled:     true,
		},
		{
			Name:        "Unix Timestamp (seconds)",
			Category:    NoiseCategoryTimestamp,
			Regex:       regexp.MustCompile(`\b1[0-9]{9}\b`), // 10 digits starting with 1 (year 2001-2286)
			PathPattern: regexp.MustCompile(`(?i)(time|timestamp|ts|created|updated|modified|date)`),
			Confidence:  0.85,
			Description: "Unix timestamp in seconds",
			Enabled:     true,
		},
		{
			Name:        "Unix Timestamp (milliseconds)",
			Category:    NoiseCategoryTimestamp,
			Regex:       regexp.MustCompile(`\b1[0-9]{12}\b`), // 13 digits
			PathPattern: regexp.MustCompile(`(?i)(time|timestamp|ts|created|updated|modified|date)`),
			Confidence:  0.90,
			Description: "Unix timestamp in milliseconds",
			Enabled:     true,
		},
		{
			Name:        "RFC2822 Date",
			Category:    NoiseCategoryDate,
			Regex:       regexp.MustCompile(`[A-Z][a-z]{2},\s+\d{1,2}\s+[A-Z][a-z]{2}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+GMT`),
			Confidence:  0.95,
			Description: "RFC 2822 date format (HTTP Date header)",
			Enabled:     true,
		},

		// UUID patterns
		{
			Name:        "UUID v4",
			Category:    NoiseCategoryUUID,
			Regex:       regexp.MustCompile(`\b[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b`),
			Confidence:  0.98,
			Description: "UUID version 4 (random)",
			Enabled:     true,
		},
		{
			Name:        "UUID (any version)",
			Category:    NoiseCategoryUUID,
			Regex:       regexp.MustCompile(`\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`),
			Confidence:  0.90,
			Description: "UUID any version",
			Enabled:     true,
		},

		// Session ID patterns
		{
			Name:        "Session ID (long alphanumeric)",
			Category:    NoiseCategorySessionID,
			Regex:       regexp.MustCompile(`\b[A-Za-z0-9+/]{32,}\b`),
			PathPattern: regexp.MustCompile(`(?i)(session|sid|jsessionid|phpsessid|asp\.net_sessionid)`),
			Confidence:  0.85,
			Description: "Session identifier (base64-like)",
			Enabled:     true,
		},
		{
			Name:        "Session ID (hex)",
			Category:    NoiseCategorySessionID,
			Regex:       regexp.MustCompile(`\b[a-f0-9]{32,64}\b`),
			PathPattern: regexp.MustCompile(`(?i)(session|sid)`),
			Confidence:  0.80,
			Description: "Session identifier (hex)",
			Enabled:     true,
		},

		// CSRF Token patterns
		{
			Name:        "CSRF Token",
			Category:    NoiseCategoryCSRFToken,
			Regex:       regexp.MustCompile(`\b[A-Za-z0-9_-]{32,}\b`),
			PathPattern: regexp.MustCompile(`(?i)(csrf|xsrf|_token|authenticity_token)`),
			Confidence:  0.90,
			Description: "CSRF protection token",
			Enabled:     true,
		},

		// Nonce patterns
		{
			Name:        "Cryptographic Nonce",
			Category:    NoiseCategoryNonce,
			Regex:       regexp.MustCompile(`\b[A-Za-z0-9+/]{16,}\b`),
			PathPattern: regexp.MustCompile(`(?i)(nonce|random|salt)`),
			Confidence:  0.85,
			Description: "Cryptographic nonce value",
			Enabled:     true,
		},

		// Request ID patterns
		{
			Name:        "Request ID",
			Category:    NoiseCategoryRequestID,
			Regex:       regexp.MustCompile(`\b[A-Za-z0-9-]{20,}\b`),
			PathPattern: regexp.MustCompile(`(?i)(request_id|req_id|request-id|x-request-id|trace_id|correlation_id)`),
			Confidence:  0.90,
			Description: "Request/trace identifier",
			Enabled:     true,
		},

		// Cache and ETag patterns
		{
			Name:        "ETag (quoted)",
			Category:    NoiseCategoryETag,
			Regex:       regexp.MustCompile(`"[A-Za-z0-9-]{8,}"`),
			PathPattern: regexp.MustCompile(`(?i)(etag|e-tag)`),
			Confidence:  0.92,
			Description: "HTTP ETag header value",
			Enabled:     true,
		},
		{
			Name:        "Cache Key",
			Category:    NoiseCategoryCache,
			Regex:       regexp.MustCompile(`\b[a-f0-9]{32}\b`),
			PathPattern: regexp.MustCompile(`(?i)(cache|key)`),
			Confidence:  0.75,
			Description: "Cache key (MD5-like)",
			Enabled:     true,
		},

		// Build ID and version patterns
		{
			Name:        "Build ID",
			Category:    NoiseCategoryBuildID,
			Regex:       regexp.MustCompile(`\b[a-f0-9]{7,40}\b`),
			PathPattern: regexp.MustCompile(`(?i)(build|commit|revision|sha|git)`),
			Confidence:  0.80,
			Description: "Build/commit identifier",
			Enabled:     true,
		},
		{
			Name:        "Semantic Version",
			Category:    NoiseCategoryVersion,
			Regex:       regexp.MustCompile(`\b\d+\.\d+\.\d+(?:-[a-z0-9.]+)?(?:\+[a-z0-9.]+)?\b`),
			PathPattern: regexp.MustCompile(`(?i)(version|ver|v|release)`),
			Confidence:  0.70,
			Description: "Semantic version number",
			Enabled:     true,
		},

		// Random values
		{
			Name:        "Random Hex String",
			Category:    NoiseCategoryRandom,
			Regex:       regexp.MustCompile(`\b[a-f0-9]{16,}\b`),
			PathPattern: regexp.MustCompile(`(?i)(random|rand|secret|key|token)`),
			Confidence:  0.75,
			Description: "Random hexadecimal string",
			Enabled:     true,
		},
	}

	for _, pattern := range defaultPatterns {
		l.patterns = append(l.patterns, pattern)
		l.enabled[pattern.Name] = pattern.Enabled
	}
}

// AddPattern adds a custom noise pattern
func (l *NoisePatternLibrary) AddPattern(pattern NoisePattern) {
	l.patterns = append(l.patterns, pattern)
	l.enabled[pattern.Name] = pattern.Enabled
}

// EnablePattern enables a pattern by name
func (l *NoisePatternLibrary) EnablePattern(name string) {
	l.enabled[name] = true
}

// DisablePattern disables a pattern by name
func (l *NoisePatternLibrary) DisablePattern(name string) {
	l.enabled[name] = false
}

// IsEnabled checks if a pattern is enabled
func (l *NoisePatternLibrary) IsEnabled(name string) bool {
	enabled, exists := l.enabled[name]
	if !exists {
		return false
	}
	return enabled
}

// GetPatterns returns all patterns
func (l *NoisePatternLibrary) GetPatterns() []NoisePattern {
	return l.patterns
}

// GetEnabledPatterns returns only enabled patterns
func (l *NoisePatternLibrary) GetEnabledPatterns() []NoisePattern {
	var enabled []NoisePattern
	for _, pattern := range l.patterns {
		if l.IsEnabled(pattern.Name) {
			enabled = append(enabled, pattern)
		}
	}
	return enabled
}

// MatchValue checks if a value matches any noise pattern
func (l *NoisePatternLibrary) MatchValue(value, path string) []NoiseMatch {
	var matches []NoiseMatch

	value = strings.TrimSpace(value)
	if value == "" {
		return matches
	}

	for _, pattern := range l.GetEnabledPatterns() {
		// Check if value matches the pattern regex
		if !pattern.Regex.MatchString(value) {
			continue
		}

		// If pattern has a path restriction, check it
		if pattern.PathPattern != nil && path != "" {
			if !pattern.PathPattern.MatchString(path) {
				continue
			}
		}

		matches = append(matches, NoiseMatch{
			Pattern:     pattern,
			Value:       value,
			Path:        path,
			Confidence:  pattern.Confidence,
			Category:    pattern.Category,
			Description: pattern.Description,
		})
	}

	return matches
}

// NoiseMatch represents a detected noise pattern match
type NoiseMatch struct {
	Pattern     NoisePattern
	Value       string
	Path        string
	Confidence  float64
	Category    NoiseCategory
	Description string
}

// GetTopMatch returns the highest confidence match
func GetTopMatch(matches []NoiseMatch) *NoiseMatch {
	if len(matches) == 0 {
		return nil
	}

	top := matches[0]
	for _, match := range matches[1:] {
		if match.Confidence > top.Confidence {
			top = match
		}
	}

	return &top
}
