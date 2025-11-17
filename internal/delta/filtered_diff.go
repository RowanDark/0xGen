package delta

import (
	"fmt"
	"time"
)

// FilterConfig configures noise filtering
type FilterConfig struct {
	Enabled             bool
	ConfidenceThreshold float64
	EnabledCategories   map[NoiseCategory]bool
	CustomPatterns      []NoisePattern
}

// DefaultFilterConfig returns a default filter configuration
func DefaultFilterConfig() FilterConfig {
	return FilterConfig{
		Enabled:             true,
		ConfidenceThreshold: 0.8,
		EnabledCategories: map[NoiseCategory]bool{
			NoiseCategoryTimestamp: true,
			NoiseCategorySessionID: true,
			NoiseCategoryUUID:      true,
			NoiseCategoryCSRFToken: true,
			NoiseCategoryNonce:     true,
			NoiseCategoryRequestID: true,
			NoiseCategoryCache:     true,
			NoiseCategoryETag:      true,
			NoiseCategoryDate:      true,
			NoiseCategoryRandom:    true,
			NoiseCategoryBuildID:   false, // Disabled by default - might be relevant
			NoiseCategoryVersion:   false, // Disabled by default - might be relevant
		},
		CustomPatterns: []NoisePattern{},
	}
}

// FilteredDiffResult contains both filtered and unfiltered diff results
type FilteredDiffResult struct {
	Original         *DiffResult
	SignalChanges    []Change
	NoiseChanges     []Change
	Classifications  []NoiseClassification
	FilterSettings   FilterConfig
	FilterStats      FilterStats
	ComputeTime      time.Duration
}

// FilterStats contains statistics about filtering
type FilterStats struct {
	TotalChanges         int
	SignalChanges        int
	NoiseChanges         int
	FilteredPercentage   float64
	AvgNoiseConfidence   float64
	AvgSignalConfidence  float64
	FilterComputeTime    time.Duration
	PatternMatches       map[NoiseCategory]int
}

// FilterDiff applies noise filtering to a diff result
func FilterDiff(result *DiffResult, config FilterConfig) *FilteredDiffResult {
	startTime := time.Now()

	if result == nil {
		return &FilteredDiffResult{
			Original:       result,
			FilterSettings: config,
		}
	}

	// Create classifier with custom threshold
	classifier := NewNoiseClassifier()
	classifier.SetConfidenceThreshold(config.ConfidenceThreshold)

	// Configure pattern library
	patterns := classifier.GetPatternLibrary()

	// Disable patterns for disabled categories
	for _, pattern := range patterns.GetPatterns() {
		if enabled, ok := config.EnabledCategories[pattern.Category]; ok && !enabled {
			patterns.DisablePattern(pattern.Name)
		}
	}

	// Add custom patterns
	for _, customPattern := range config.CustomPatterns {
		patterns.AddPattern(customPattern)
	}

	// Classify all changes
	classifications := make([]NoiseClassification, len(result.Changes))
	signalChanges := make([]Change, 0)
	noiseChanges := make([]Change, 0)
	patternMatches := make(map[NoiseCategory]int)

	for i, change := range result.Changes {
		classification := classifier.Classify(change)
		classifications[i] = classification

		if classification.IsNoise {
			noiseChanges = append(noiseChanges, change)
			if classification.Category != "" {
				patternMatches[classification.Category]++
			}
		} else {
			signalChanges = append(signalChanges, change)
		}
	}

	// Calculate statistics
	stats := classifier.GetStatistics(classifications)
	filterStats := FilterStats{
		TotalChanges:        len(result.Changes),
		SignalChanges:       stats.SignalCount,
		NoiseChanges:        stats.NoiseCount,
		FilteredPercentage:  stats.NoisePercentage,
		AvgNoiseConfidence:  stats.AvgNoiseConfidence,
		AvgSignalConfidence: stats.AvgSignalConfidence,
		FilterComputeTime:   time.Since(startTime),
		PatternMatches:      patternMatches,
	}

	return &FilteredDiffResult{
		Original:        result,
		SignalChanges:   signalChanges,
		NoiseChanges:    noiseChanges,
		Classifications: classifications,
		FilterSettings:  config,
		FilterStats:     filterStats,
		ComputeTime:     time.Since(startTime),
	}
}

// GetSignalResult returns a DiffResult containing only signal changes
func (fdr *FilteredDiffResult) GetSignalResult() *DiffResult {
	if fdr.Original == nil {
		return nil
	}

	// Recalculate similarity based on signal changes only
	signalLen := len(fdr.SignalChanges)
	totalLen := fdr.Original.LeftSize
	if fdr.Original.RightSize > totalLen {
		totalLen = fdr.Original.RightSize
	}

	similarity := 100.0
	if totalLen > 0 {
		unchanged := totalLen - signalLen
		if unchanged < 0 {
			unchanged = 0
		}
		similarity = (float64(unchanged) / float64(totalLen)) * 100.0
	}

	return &DiffResult{
		Type:            fdr.Original.Type,
		Changes:         fdr.SignalChanges,
		SimilarityScore: similarity,
		LeftSize:        fdr.Original.LeftSize,
		RightSize:       fdr.Original.RightSize,
		ComputeTime:     fdr.Original.ComputeTime,
		Granularity:     fdr.Original.Granularity,
	}
}

// GetNoiseResult returns a DiffResult containing only noise changes
func (fdr *FilteredDiffResult) GetNoiseResult() *DiffResult {
	if fdr.Original == nil {
		return nil
	}

	return &DiffResult{
		Type:            fdr.Original.Type,
		Changes:         fdr.NoiseChanges,
		SimilarityScore: 0, // Not applicable for noise
		LeftSize:        fdr.Original.LeftSize,
		RightSize:       fdr.Original.RightSize,
		ComputeTime:     fdr.Original.ComputeTime,
		Granularity:     fdr.Original.Granularity,
	}
}

// Summary returns a human-readable summary of the filtered diff
func (fdr *FilteredDiffResult) Summary() string {
	if fdr.Original == nil {
		return "No diff result"
	}

	return fdr.Original.Summary() + "\n" +
		fdr.FilterSummary()
}

// FilterSummary returns a summary of the filtering results
func (fdr *FilteredDiffResult) FilterSummary() string {
	if !fdr.FilterSettings.Enabled {
		return "Filtering disabled"
	}

	return fmt.Sprintf("Filtered: %d noise (%.1f%%), %d signal",
		fdr.FilterStats.NoiseChanges,
		fdr.FilterStats.FilteredPercentage,
		fdr.FilterStats.SignalChanges)
}

// IsFiltered returns true if any changes were filtered out
func (fdr *FilteredDiffResult) IsFiltered() bool {
	return len(fdr.NoiseChanges) > 0
}

// GetClassification returns the classification for a specific change index
func (fdr *FilteredDiffResult) GetClassification(index int) *NoiseClassification {
	if index < 0 || index >= len(fdr.Classifications) {
		return nil
	}
	return &fdr.Classifications[index]
}

// ToggleFilter switches between filtered and unfiltered view
func (fdr *FilteredDiffResult) ToggleFilter(enabled bool) {
	fdr.FilterSettings.Enabled = enabled
}

// ApplyUserFeedback applies user feedback to a change
func (fdr *FilteredDiffResult) ApplyUserFeedback(changeIndex int, feedback FeedbackType, reason string, classifier *NoiseClassifier) error {
	if changeIndex < 0 || changeIndex >= len(fdr.Original.Changes) {
		return fmt.Errorf("invalid change index: %d", changeIndex)
	}

	change := fdr.Original.Changes[changeIndex]

	// Add feedback
	feedbackStore := classifier.GetFeedbackStore()
	feedbackStore.AddFeedback(change.Path, change.OldValue, change.NewValue, feedback, reason)

	// Reclassify
	newClassification := classifier.Classify(change)
	fdr.Classifications[changeIndex] = newClassification

	// Update signal/noise lists
	fdr.rebuildChangeLists()

	return nil
}

// rebuildChangeLists rebuilds signal and noise change lists based on current classifications
func (fdr *FilteredDiffResult) rebuildChangeLists() {
	fdr.SignalChanges = make([]Change, 0)
	fdr.NoiseChanges = make([]Change, 0)

	for i, change := range fdr.Original.Changes {
		if i < len(fdr.Classifications) {
			if fdr.Classifications[i].IsNoise {
				fdr.NoiseChanges = append(fdr.NoiseChanges, change)
			} else {
				fdr.SignalChanges = append(fdr.SignalChanges, change)
			}
		}
	}

	// Recalculate stats
	fdr.FilterStats.SignalChanges = len(fdr.SignalChanges)
	fdr.FilterStats.NoiseChanges = len(fdr.NoiseChanges)
	if fdr.FilterStats.TotalChanges > 0 {
		fdr.FilterStats.FilteredPercentage = (float64(fdr.FilterStats.NoiseChanges) / float64(fdr.FilterStats.TotalChanges)) * 100
	}
}

// GetFilterEfficiency returns a score indicating how effective filtering was
func (fdr *FilteredDiffResult) GetFilterEfficiency() float64 {
	if fdr.FilterStats.TotalChanges == 0 {
		return 0
	}

	// Efficiency is based on:
	// - Percentage of changes filtered (higher is better)
	// - Confidence of noise classifications (higher is better)
	// Weight: 70% filtered percentage, 30% confidence

	filteredScore := fdr.FilterStats.FilteredPercentage / 100.0
	confidenceScore := fdr.FilterStats.AvgNoiseConfidence

	return (filteredScore * 0.7) + (confidenceScore * 0.3)
}

// GetCategoryBreakdown returns a breakdown of noise by category
func (fdr *FilteredDiffResult) GetCategoryBreakdown() map[NoiseCategory]int {
	return fdr.FilterStats.PatternMatches
}
