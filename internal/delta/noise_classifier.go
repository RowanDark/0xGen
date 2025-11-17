package delta

import (
	"strings"
)

// NoiseClassifier determines if a change is noise or signal
type NoiseClassifier struct {
	patterns         *NoisePatternLibrary
	confidenceThreshold float64
	feedback         *FeedbackStore
}

// NoiseClassification represents the classification of a change
type NoiseClassification struct {
	IsNoise     bool
	Confidence  float64
	Reason      string
	Category    NoiseCategory
	PatternName string
	UserOverride bool // True if user manually classified this
}

// NewNoiseClassifier creates a new noise classifier
func NewNoiseClassifier() *NoiseClassifier {
	return &NoiseClassifier{
		patterns:            NewNoisePatternLibrary(),
		confidenceThreshold: 0.8,
		feedback:            NewFeedbackStore(),
	}
}

// NewNoiseClassifierWithFeedback creates a classifier with custom feedback store
func NewNoiseClassifierWithFeedback(feedback *FeedbackStore) *NoiseClassifier {
	return &NoiseClassifier{
		patterns:            NewNoisePatternLibrary(),
		confidenceThreshold: 0.8,
		feedback:            feedback,
	}
}

// SetConfidenceThreshold sets the minimum confidence for noise classification
func (nc *NoiseClassifier) SetConfidenceThreshold(threshold float64) {
	if threshold >= 0 && threshold <= 1.0 {
		nc.confidenceThreshold = threshold
	}
}

// GetPatternLibrary returns the pattern library for configuration
func (nc *NoiseClassifier) GetPatternLibrary() *NoisePatternLibrary {
	return nc.patterns
}

// GetFeedbackStore returns the feedback store
func (nc *NoiseClassifier) GetFeedbackStore() *FeedbackStore {
	return nc.feedback
}

// Classify determines if a change is noise or signal
func (nc *NoiseClassifier) Classify(change Change) NoiseClassification {
	// Check for user feedback override first
	if override := nc.feedback.GetClassification(change.Path, change.OldValue, change.NewValue); override != nil {
		return *override
	}

	// Classify based on patterns and heuristics
	return nc.classifyWithPatterns(change)
}

// classifyWithPatterns uses pattern matching and heuristics
func (nc *NoiseClassifier) classifyWithPatterns(change Change) NoiseClassification {
	path := change.Path

	// Special handling for different change types
	switch change.Type {
	case ChangeTypeAdded:
		return nc.classifyValue(change.NewValue, path, "added")
	case ChangeTypeRemoved:
		return nc.classifyValue(change.OldValue, path, "removed")
	case ChangeTypeModified:
		return nc.classifyModification(change.OldValue, change.NewValue, path)
	}

	return NoiseClassification{
		IsNoise:    false,
		Confidence: 1.0,
		Reason:     "Unknown change type",
	}
}

// classifyValue classifies a single value
func (nc *NoiseClassifier) classifyValue(value, path, changeType string) NoiseClassification {
	matches := nc.patterns.MatchValue(value, path)

	if len(matches) == 0 {
		return NoiseClassification{
			IsNoise:    false,
			Confidence: 0.9,
			Reason:     "No noise patterns matched",
		}
	}

	// Get top match
	topMatch := GetTopMatch(matches)
	if topMatch == nil {
		return NoiseClassification{
			IsNoise:    false,
			Confidence: 0.9,
			Reason:     "No noise patterns matched",
		}
	}

	// Determine if it's noise based on confidence threshold
	isNoise := topMatch.Confidence >= nc.confidenceThreshold

	reason := topMatch.Description
	if isNoise {
		reason = "Likely noise: " + topMatch.Description
	} else {
		reason = "Low confidence match: " + topMatch.Description
	}

	return NoiseClassification{
		IsNoise:     isNoise,
		Confidence:  topMatch.Confidence,
		Reason:      reason,
		Category:    topMatch.Category,
		PatternName: topMatch.Pattern.Name,
	}
}

// classifyModification classifies a modification (old value -> new value)
func (nc *NoiseClassifier) classifyModification(oldValue, newValue, path string) NoiseClassification {
	// Check if both values match the same noise pattern
	oldMatches := nc.patterns.MatchValue(oldValue, path)
	newMatches := nc.patterns.MatchValue(newValue, path)

	// If both match noise patterns, it's likely noise
	if len(oldMatches) > 0 && len(newMatches) > 0 {
		oldTop := GetTopMatch(oldMatches)
		newTop := GetTopMatch(newMatches)

		// If both match the same category with high confidence, it's noise
		if oldTop.Category == newTop.Category {
			avgConfidence := (oldTop.Confidence + newTop.Confidence) / 2
			isNoise := avgConfidence >= nc.confidenceThreshold

			return NoiseClassification{
				IsNoise:     isNoise,
				Confidence:  avgConfidence,
				Reason:      "Both values match noise pattern: " + string(oldTop.Category),
				Category:    oldTop.Category,
				PatternName: oldTop.Pattern.Name,
			}
		}
	}

	// Check for semantic similarities that indicate noise
	if nc.areValuesSemanticallyNoise(oldValue, newValue, path) {
		return NoiseClassification{
			IsNoise:    true,
			Confidence: 0.85,
			Reason:     "Values are semantically similar noise (same format, different value)",
		}
	}

	// Default: not noise
	return NoiseClassification{
		IsNoise:    false,
		Confidence: 0.8,
		Reason:     "Values don't match known noise patterns",
	}
}

// areValuesSemanticallyNoise checks if values are semantically similar noise
func (nc *NoiseClassifier) areValuesSemanticallyNoise(oldValue, newValue, path string) bool {
	// Same length and type usually indicates same kind of data
	if len(oldValue) == len(newValue) {
		// Check if both are numeric (timestamps)
		if isNumeric(oldValue) && isNumeric(newValue) {
			// Likely timestamps if in path with time-related keywords
			if strings.Contains(strings.ToLower(path), "time") ||
				strings.Contains(strings.ToLower(path), "date") ||
				strings.Contains(strings.ToLower(path), "ts") {
				return true
			}
		}

		// Check if both are hex strings of same length
		if isHexString(oldValue) && isHexString(newValue) {
			// Likely session IDs or tokens
			if strings.Contains(strings.ToLower(path), "session") ||
				strings.Contains(strings.ToLower(path), "token") ||
				strings.Contains(strings.ToLower(path), "id") {
				return true
			}
		}

		// Check if both are UUIDs (same format)
		if isUUIDFormat(oldValue) && isUUIDFormat(newValue) {
			return true
		}
	}

	return false
}

// Helper functions

func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}

func isHexString(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range strings.ToLower(s) {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func isUUIDFormat(s string) bool {
	// Simple UUID format check: 8-4-4-4-12
	parts := strings.Split(s, "-")
	if len(parts) != 5 {
		return false
	}
	return len(parts[0]) == 8 && len(parts[1]) == 4 && len(parts[2]) == 4 &&
		len(parts[3]) == 4 && len(parts[4]) == 12
}

// ClassifyBatch classifies multiple changes
func (nc *NoiseClassifier) ClassifyBatch(changes []Change) []NoiseClassification {
	classifications := make([]NoiseClassification, len(changes))
	for i, change := range changes {
		classifications[i] = nc.Classify(change)
	}
	return classifications
}

// FilterChanges returns only signal changes (non-noise)
func (nc *NoiseClassifier) FilterChanges(changes []Change) (signal, noise []Change) {
	signal = make([]Change, 0)
	noise = make([]Change, 0)

	for _, change := range changes {
		classification := nc.Classify(change)
		if classification.IsNoise {
			noise = append(noise, change)
		} else {
			signal = append(signal, change)
		}
	}

	return signal, noise
}

// GetStatistics returns classification statistics
func (nc *NoiseClassifier) GetStatistics(classifications []NoiseClassification) ClassificationStats {
	stats := ClassificationStats{}

	for _, class := range classifications {
		if class.IsNoise {
			stats.NoiseCount++
			stats.NoiseConfidenceSum += class.Confidence
		} else {
			stats.SignalCount++
			stats.SignalConfidenceSum += class.Confidence
		}

		if class.UserOverride {
			stats.UserOverrideCount++
		}
	}

	if stats.NoiseCount > 0 {
		stats.AvgNoiseConfidence = stats.NoiseConfidenceSum / float64(stats.NoiseCount)
	}

	if stats.SignalCount > 0 {
		stats.AvgSignalConfidence = stats.SignalConfidenceSum / float64(stats.SignalCount)
	}

	stats.TotalChanges = len(classifications)

	if stats.TotalChanges > 0 {
		stats.NoisePercentage = (float64(stats.NoiseCount) / float64(stats.TotalChanges)) * 100
	}

	return stats
}

// ClassificationStats contains statistics about classifications
type ClassificationStats struct {
	TotalChanges         int
	NoiseCount           int
	SignalCount          int
	NoisePercentage      float64
	AvgNoiseConfidence   float64
	AvgSignalConfidence  float64
	NoiseConfidenceSum   float64
	SignalConfidenceSum  float64
	UserOverrideCount    int
}
