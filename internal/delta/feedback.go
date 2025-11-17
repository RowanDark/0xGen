package delta

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

// FeedbackType represents user feedback on classification
type FeedbackType string

const (
	FeedbackNoise  FeedbackType = "noise"
	FeedbackSignal FeedbackType = "signal"
)

// FeedbackEntry represents a user's classification feedback
type FeedbackEntry struct {
	ID           string
	Path         string
	OldValue     string
	NewValue     string
	Feedback     FeedbackType
	Confidence   float64
	Reason       string
	CreatedAt    time.Time
	PatternHash  string // Hash of path+oldValue+newValue for quick lookup
}

// FeedbackStore manages user feedback for improving classification
type FeedbackStore struct {
	mu       sync.RWMutex
	entries  map[string]*FeedbackEntry // keyed by pattern hash
	byPath   map[string][]string       // path -> list of entry IDs
	stats    FeedbackStats
}

// FeedbackStats tracks feedback statistics
type FeedbackStats struct {
	TotalFeedback     int
	NoiseFeedback     int
	SignalFeedback    int
	AccuracyImprovements int // Count of times feedback improved accuracy
}

// NewFeedbackStore creates a new feedback store
func NewFeedbackStore() *FeedbackStore {
	return &FeedbackStore{
		entries: make(map[string]*FeedbackEntry),
		byPath:  make(map[string][]string),
		stats:   FeedbackStats{},
	}
}

// AddFeedback adds user feedback for a change
func (fs *FeedbackStore) AddFeedback(path, oldValue, newValue string, feedback FeedbackType, reason string) *FeedbackEntry {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	hash := generatePatternHash(path, oldValue, newValue)

	// Check if feedback already exists
	if existing, ok := fs.entries[hash]; ok {
		// Update existing feedback
		existing.Feedback = feedback
		existing.Reason = reason
		existing.CreatedAt = time.Now().UTC()
		return existing
	}

	// Create new feedback entry
	entry := &FeedbackEntry{
		ID:          generateID(),
		Path:        path,
		OldValue:    oldValue,
		NewValue:    newValue,
		Feedback:    feedback,
		Confidence:  1.0, // User feedback has max confidence
		Reason:      reason,
		CreatedAt:   time.Now().UTC(),
		PatternHash: hash,
	}

	fs.entries[hash] = entry

	// Index by path
	fs.byPath[path] = append(fs.byPath[path], entry.ID)

	// Update stats
	fs.stats.TotalFeedback++
	if feedback == FeedbackNoise {
		fs.stats.NoiseFeedback++
	} else {
		fs.stats.SignalFeedback++
	}

	return entry
}

// GetClassification returns a classification based on user feedback
func (fs *FeedbackStore) GetClassification(path, oldValue, newValue string) *NoiseClassification {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	hash := generatePatternHash(path, oldValue, newValue)
	entry, ok := fs.entries[hash]
	if !ok {
		return nil
	}

	return &NoiseClassification{
		IsNoise:      entry.Feedback == FeedbackNoise,
		Confidence:   entry.Confidence,
		Reason:       "User feedback: " + entry.Reason,
		UserOverride: true,
	}
}

// GetFeedbackByPath returns all feedback for a specific path
func (fs *FeedbackStore) GetFeedbackByPath(path string) []*FeedbackEntry {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	ids := fs.byPath[path]
	entries := make([]*FeedbackEntry, 0, len(ids))

	for _, id := range ids {
		for _, entry := range fs.entries {
			if entry.ID == id {
				entries = append(entries, entry)
				break
			}
		}
	}

	return entries
}

// GetAllFeedback returns all feedback entries
func (fs *FeedbackStore) GetAllFeedback() []*FeedbackEntry {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	entries := make([]*FeedbackEntry, 0, len(fs.entries))
	for _, entry := range fs.entries {
		entries = append(entries, entry)
	}

	return entries
}

// DeleteFeedback removes feedback by ID
func (fs *FeedbackStore) DeleteFeedback(id string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	// Find and delete entry
	for hash, entry := range fs.entries {
		if entry.ID == id {
			delete(fs.entries, hash)

			// Remove from path index
			if ids, ok := fs.byPath[entry.Path]; ok {
				for i, entryID := range ids {
					if entryID == id {
						fs.byPath[entry.Path] = append(ids[:i], ids[i+1:]...)
						break
					}
				}
			}

			// Update stats
			fs.stats.TotalFeedback--
			if entry.Feedback == FeedbackNoise {
				fs.stats.NoiseFeedback--
			} else {
				fs.stats.SignalFeedback--
			}

			return nil
		}
	}

	return fmt.Errorf("feedback entry not found: %s", id)
}

// GetStats returns feedback statistics
func (fs *FeedbackStore) GetStats() FeedbackStats {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	return fs.stats
}

// ExportDataset exports feedback as training data
func (fs *FeedbackStore) ExportDataset() []FeedbackDataPoint {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	datapoints := make([]FeedbackDataPoint, 0, len(fs.entries))

	for _, entry := range fs.entries {
		datapoints = append(datapoints, FeedbackDataPoint{
			Path:     entry.Path,
			OldValue: entry.OldValue,
			NewValue: entry.NewValue,
			Label:    string(entry.Feedback),
			Reason:   entry.Reason,
		})
	}

	return datapoints
}

// FeedbackDataPoint represents a single training data point
type FeedbackDataPoint struct {
	Path     string `json:"path"`
	OldValue string `json:"old_value"`
	NewValue string `json:"new_value"`
	Label    string `json:"label"` // "noise" or "signal"
	Reason   string `json:"reason"`
}

// RecordAccuracyImprovement records when feedback improved accuracy
func (fs *FeedbackStore) RecordAccuracyImprovement() {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	fs.stats.AccuracyImprovements++
}

// Clear removes all feedback
func (fs *FeedbackStore) Clear() {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	fs.entries = make(map[string]*FeedbackEntry)
	fs.byPath = make(map[string][]string)
	fs.stats = FeedbackStats{}
}

// Helper functions

// generatePatternHash creates a hash for quick lookup
func generatePatternHash(path, oldValue, newValue string) string {
	data := fmt.Sprintf("%s|%s|%s", path, oldValue, newValue)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// generateID creates a unique ID
func generateID() string {
	return fmt.Sprintf("fb_%d", time.Now().UnixNano())
}

// SimilarFeedback finds similar feedback entries (for learning patterns)
type SimilarFeedback struct {
	Entry      *FeedbackEntry
	Similarity float64
}

// FindSimilarFeedback finds feedback similar to the given change
func (fs *FeedbackStore) FindSimilarFeedback(path, oldValue, newValue string, limit int) []SimilarFeedback {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	similar := make([]SimilarFeedback, 0)

	for _, entry := range fs.entries {
		similarity := calculateSimilarityScore(path, oldValue, newValue, entry)
		if similarity > 0.5 { // Only include if somewhat similar
			similar = append(similar, SimilarFeedback{
				Entry:      entry,
				Similarity: similarity,
			})
		}
	}

	// Sort by similarity (simple bubble sort for small datasets)
	for i := 0; i < len(similar); i++ {
		for j := i + 1; j < len(similar); j++ {
			if similar[j].Similarity > similar[i].Similarity {
				similar[i], similar[j] = similar[j], similar[i]
			}
		}
	}

	// Limit results
	if len(similar) > limit {
		similar = similar[:limit]
	}

	return similar
}

// calculateSimilarityScore calculates how similar a change is to a feedback entry
func calculateSimilarityScore(path, oldValue, newValue string, entry *FeedbackEntry) float64 {
	score := 0.0

	// Path similarity (weight: 0.5)
	if path == entry.Path {
		score += 0.5
	} else if pathSimilarity(path, entry.Path) > 0.7 {
		score += 0.25
	}

	// Value similarity (weight: 0.5)
	if oldValue == entry.OldValue && newValue == entry.NewValue {
		score += 0.5
	} else {
		// Check for pattern similarity (same length, same type)
		if len(oldValue) == len(entry.OldValue) && len(newValue) == len(entry.NewValue) {
			score += 0.2
		}
	}

	return score
}

// pathSimilarity calculates similarity between two paths
func pathSimilarity(a, b string) float64 {
	partsA := strings.Split(a, ".")
	partsB := strings.Split(b, ".")

	commonParts := 0
	maxParts := len(partsA)
	if len(partsB) > maxParts {
		maxParts = len(partsB)
	}

	for i := 0; i < len(partsA) && i < len(partsB); i++ {
		if partsA[i] == partsB[i] {
			commonParts++
		}
	}

	if maxParts == 0 {
		return 0
	}

	return float64(commonParts) / float64(maxParts)
}
