package delta

import (
	"regexp"
	"testing"
)

func TestNoisePatternLibrary_MatchValue(t *testing.T) {
	lib := NewNoisePatternLibrary()

	tests := []struct {
		name           string
		value          string
		path           string
		expectMatch    bool
		expectCategory NoiseCategory
		minConfidence  float64
	}{
		{
			name:           "ISO8601 timestamp",
			value:          "2025-01-15T10:30:45Z",
			path:           "$.timestamp",
			expectMatch:    true,
			expectCategory: NoiseCategoryTimestamp,
			minConfidence:  0.9,
		},
		{
			name:           "Unix timestamp seconds",
			value:          "1705318245",
			path:           "$.created_at",
			expectMatch:    true,
			expectCategory: NoiseCategoryTimestamp,
			minConfidence:  0.8,
		},
		{
			name:           "Unix timestamp milliseconds",
			value:          "1705318245123",
			path:           "$.updated_at",
			expectMatch:    true,
			expectCategory: NoiseCategoryTimestamp,
			minConfidence:  0.8,
		},
		{
			name:           "UUID v4",
			value:          "550e8400-e29b-41d4-a716-446655440000",
			path:           "$.request_id",
			expectMatch:    true,
			expectCategory: NoiseCategoryUUID,
			minConfidence:  0.9,
		},
		{
			name:           "Session ID",
			value:          "abc123xyz789def456ghi012jkl345mno678pqr901stu234",
			path:           "$.session_id",
			expectMatch:    true,
			expectCategory: NoiseCategorySessionID,
			minConfidence:  0.7,
		},
		{
			name:           "CSRF token",
			value:          "csrf_token_abcdef123456789ghi012jkl345mno678pqr901",
			path:           "$.csrf_token",
			expectMatch:    true,
			expectCategory: NoiseCategoryCSRFToken,
			minConfidence:  0.8,
		},
		{
			name:           "ETag",
			value:          `"686897696a7c876b7e"`,
			path:           "$.etag",
			expectMatch:    true,
			expectCategory: NoiseCategoryETag,
			minConfidence:  0.9,
		},
		{
			name:           "Not noise - user email",
			value:          "user@example.com",
			path:           "$.email",
			expectMatch:    false,
		},
		{
			name:           "Not noise - user role",
			value:          "admin",
			path:           "$.role",
			expectMatch:    false,
		},
		{
			name:           "Semantic version",
			value:          "1.2.3",
			path:           "$.version",
			expectMatch:    true,
			expectCategory: NoiseCategoryVersion,
			minConfidence:  0.6,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := lib.MatchValue(tt.value, tt.path)

			if tt.expectMatch {
				if len(matches) == 0 {
					t.Errorf("Expected match for value %q with path %q, got no matches", tt.value, tt.path)
					return
				}

				topMatch := GetTopMatch(matches)
				if topMatch.Category != tt.expectCategory {
					t.Errorf("Expected category %v, got %v", tt.expectCategory, topMatch.Category)
				}

				if topMatch.Confidence < tt.minConfidence {
					t.Errorf("Expected confidence >= %.2f, got %.2f", tt.minConfidence, topMatch.Confidence)
				}
			} else {
				if len(matches) > 0 {
					topMatch := GetTopMatch(matches)
					t.Errorf("Expected no match for value %q, got match with category %v (confidence: %.2f)",
						tt.value, topMatch.Category, topMatch.Confidence)
				}
			}
		})
	}
}

func TestNoisePatternLibrary_EnableDisable(t *testing.T) {
	lib := NewNoisePatternLibrary()

	// Test that patterns are enabled by default
	if !lib.IsEnabled("ISO8601 Timestamp") {
		t.Error("Expected pattern to be enabled by default")
	}

	// Disable a pattern
	lib.DisablePattern("ISO8601 Timestamp")
	if lib.IsEnabled("ISO8601 Timestamp") {
		t.Error("Expected pattern to be disabled")
	}

	// Verify it doesn't match when disabled
	matches := lib.MatchValue("2025-01-15T10:30:45Z", "$.timestamp")
	for _, match := range matches {
		if match.Pattern.Name == "ISO8601 Timestamp" {
			t.Error("Disabled pattern should not match")
		}
	}

	// Re-enable
	lib.EnablePattern("ISO8601 Timestamp")
	if !lib.IsEnabled("ISO8601 Timestamp") {
		t.Error("Expected pattern to be re-enabled")
	}
}

func TestNoisePatternLibrary_CustomPattern(t *testing.T) {
	lib := NewNoisePatternLibrary()

	// Add custom pattern (use a unique pattern that won't conflict)
	customPattern := NoisePattern{
		Name:        "Custom API Key",
		Category:    NoiseCategoryRandom,
		Regex:       compileRegex(`CUSTOMKEY[A-Z0-9]{16}`),
		PathPattern: compileRegex(`api_key`),
		Confidence:  0.95,
		Description: "Custom API key pattern",
		Enabled:     true,
	}

	lib.AddPattern(customPattern)

	// Test it matches with unique pattern
	matches := lib.MatchValue("CUSTOMKEYABCD1234EFGH5678", "$.api_key")
	if len(matches) == 0 {
		t.Error("Custom pattern should match")
		return
	}

	// Find our custom pattern in the matches
	found := false
	for _, match := range matches {
		if match.Pattern.Name == "Custom API Key" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected custom pattern to be in matches")
	}
}

func TestGetTopMatch(t *testing.T) {
	matches := []NoiseMatch{
		{Confidence: 0.7},
		{Confidence: 0.95},
		{Confidence: 0.8},
	}

	top := GetTopMatch(matches)
	if top == nil {
		t.Fatal("Expected top match")
	}

	if top.Confidence != 0.95 {
		t.Errorf("Expected highest confidence 0.95, got %.2f", top.Confidence)
	}
}

func TestGetTopMatch_Empty(t *testing.T) {
	matches := []NoiseMatch{}
	top := GetTopMatch(matches)

	if top != nil {
		t.Error("Expected nil for empty matches")
	}
}

func TestNoisePatternLibrary_GetEnabledPatterns(t *testing.T) {
	lib := NewNoisePatternLibrary()

	initialCount := len(lib.GetEnabledPatterns())
	if initialCount == 0 {
		t.Error("Expected some enabled patterns by default")
	}

	// Disable all patterns
	for _, pattern := range lib.GetPatterns() {
		lib.DisablePattern(pattern.Name)
	}

	enabledCount := len(lib.GetEnabledPatterns())
	if enabledCount != 0 {
		t.Errorf("Expected 0 enabled patterns, got %d", enabledCount)
	}

	// Re-enable one
	allPatterns := lib.GetPatterns()
	if len(allPatterns) > 0 {
		lib.EnablePattern(allPatterns[0].Name)
		enabledCount = len(lib.GetEnabledPatterns())
		if enabledCount != 1 {
			t.Errorf("Expected 1 enabled pattern, got %d", enabledCount)
		}
	}
}

func compileRegex(pattern string) *regexp.Regexp {
	return regexp.MustCompile(pattern)
}

// Benchmarks

func BenchmarkMatchValue_Timestamp(b *testing.B) {
	lib := NewNoisePatternLibrary()
	value := "2025-01-15T10:30:45Z"
	path := "$.timestamp"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = lib.MatchValue(value, path)
	}
}

func BenchmarkMatchValue_UUID(b *testing.B) {
	lib := NewNoisePatternLibrary()
	value := "550e8400-e29b-41d4-a716-446655440000"
	path := "$.id"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = lib.MatchValue(value, path)
	}
}

func BenchmarkMatchValue_NoMatch(b *testing.B) {
	lib := NewNoisePatternLibrary()
	value := "regular text value"
	path := "$.description"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = lib.MatchValue(value, path)
	}
}
