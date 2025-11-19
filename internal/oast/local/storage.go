package local

import (
	"context"
	"sort"
	"sync"
	"time"
)

// DefaultTTL is the default time-to-live for interactions.
const DefaultTTL = 24 * time.Hour

// Storage provides thread-safe in-memory storage for OAST interactions
// with TTL-based cleanup and efficient indexing.
type Storage struct {
	mu sync.RWMutex

	// Main storage: ID -> []Interaction
	byID map[string][]*Interaction

	// Ordered list for TTL cleanup (oldest first)
	timeline []*Interaction

	// Index by test ID for fast lookup: testID -> []interactionID
	testIndex map[string][]string

	// Configuration
	ttl time.Duration

	// Cleanup goroutine control
	cancel context.CancelFunc
}

// NewStorage creates a new in-memory interaction storage with default TTL.
func NewStorage() *Storage {
	return NewStorageWithTTL(DefaultTTL)
}

// NewStorageWithTTL creates a new storage with a custom TTL.
func NewStorageWithTTL(ttl time.Duration) *Storage {
	ctx, cancel := context.WithCancel(context.Background())

	s := &Storage{
		byID:      make(map[string][]*Interaction),
		timeline:  make([]*Interaction, 0),
		testIndex: make(map[string][]string),
		ttl:       ttl,
		cancel:    cancel,
	}

	// Start cleanup goroutine
	go s.cleanupLoop(ctx)

	return s
}

// Store saves an interaction to storage.
func (s *Storage) Store(interaction *Interaction) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Store in main map
	s.byID[interaction.ID] = append(s.byID[interaction.ID], interaction)

	// Add to timeline
	s.timeline = append(s.timeline, interaction)

	// Update test index if TestID is set
	if interaction.TestID != "" {
		s.testIndex[interaction.TestID] = append(s.testIndex[interaction.TestID], interaction.ID)
	}

	return nil
}

// GetByID returns all interactions for a given callback ID.
func (s *Storage) GetByID(id string) []*Interaction {
	s.mu.RLock()
	defer s.mu.RUnlock()

	interactions := s.byID[id]
	if interactions == nil {
		return []*Interaction{}
	}

	// Return a copy to prevent external modification
	result := make([]*Interaction, len(interactions))
	copy(result, interactions)
	return result
}

// GetByTestID returns all interactions for a given test ID.
func (s *Storage) GetByTestID(testID string) []*Interaction {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Get all interaction IDs for this test
	ids := s.testIndex[testID]
	if len(ids) == 0 {
		return []*Interaction{}
	}

	// Collect all interactions, avoiding duplicates
	seen := make(map[string]bool)
	var result []*Interaction

	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		result = append(result, s.byID[id]...)
	}

	return result
}

// List returns interactions matching the given filter.
func (s *Storage) List(filter InteractionFilter) []*Interaction {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// If specific ID requested, return those
	if filter.ID != "" {
		interactions := s.byID[filter.ID]
		if interactions == nil {
			return []*Interaction{}
		}
		result := make([]*Interaction, len(interactions))
		copy(result, interactions)
		return result
	}

	// If test ID filter, use index
	if filter.TestID != "" {
		ids := s.testIndex[filter.TestID]
		if len(ids) == 0 {
			return []*Interaction{}
		}

		seen := make(map[string]bool)
		var result []*Interaction
		for _, id := range ids {
			if seen[id] {
				continue
			}
			seen[id] = true
			result = append(result, s.byID[id]...)
		}
		return result
	}

	// Otherwise, scan all interactions with filtering
	var result []*Interaction
	for _, interactions := range s.byID {
		for _, i := range interactions {
			// Apply type filter
			if filter.Type != "" && i.Type != filter.Type {
				continue
			}
			// Apply since filter
			if !filter.Since.IsZero() && i.Timestamp.Before(filter.Since) {
				continue
			}
			// Apply request ID filter
			if filter.RequestID != "" && i.RequestID != filter.RequestID {
				continue
			}

			result = append(result, i)
		}
	}

	// Sort by timestamp (newest first)
	sort.Slice(result, func(i, j int) bool {
		return result[i].Timestamp.After(result[j].Timestamp)
	})

	// Apply limit
	if filter.Limit > 0 && len(result) > filter.Limit {
		result = result[:filter.Limit]
	}

	return result
}

// GetAll returns all stored interactions.
func (s *Storage) GetAll() []*Interaction {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*Interaction, len(s.timeline))
	copy(result, s.timeline)
	return result
}

// GetCount returns the total number of stored interactions.
func (s *Storage) GetCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.timeline)
}

// GetCountByID returns the number of interactions for a specific ID.
func (s *Storage) GetCountByID(id string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byID[id])
}

// HasInteraction checks if any interaction exists for the given ID.
func (s *Storage) HasInteraction(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byID[id]) > 0
}

// Clear removes all stored interactions.
func (s *Storage) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.byID = make(map[string][]*Interaction)
	s.timeline = make([]*Interaction, 0)
	s.testIndex = make(map[string][]string)
}

// DeleteByID removes all interactions for a given ID.
func (s *Storage) DeleteByID(id string) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := len(s.byID[id])
	if count == 0 {
		return 0
	}

	// Get interactions to remove for updating test index
	toRemove := s.byID[id]

	// Remove from byID map
	delete(s.byID, id)

	// Remove from timeline
	filtered := make([]*Interaction, 0, len(s.timeline)-count)
	for _, interaction := range s.timeline {
		if interaction.ID != id {
			filtered = append(filtered, interaction)
		}
	}
	s.timeline = filtered

	// Update test index
	for _, interaction := range toRemove {
		if interaction.TestID != "" {
			s.removeFromTestIndex(interaction.TestID, id)
		}
	}

	return count
}

// GetSince returns all interactions since the given timestamp.
func (s *Storage) GetSince(since time.Time) []*Interaction {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*Interaction, 0)
	for _, interaction := range s.timeline {
		if interaction.Timestamp.After(since) || interaction.Timestamp.Equal(since) {
			result = append(result, interaction)
		}
	}
	return result
}

// GetIDs returns all unique callback IDs that have interactions.
func (s *Storage) GetIDs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := make([]string, 0, len(s.byID))
	for id := range s.byID {
		ids = append(ids, id)
	}
	return ids
}

// GetStats returns statistics about stored interactions.
func (s *Storage) GetStats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := Stats{
		ByType:    make(map[string]int),
		UniqueIDs: len(s.byID),
	}

	for _, interaction := range s.timeline {
		stats.TotalInteractions++
		stats.ByType[interaction.Type]++

		if stats.OldestTimestamp.IsZero() || interaction.Timestamp.Before(stats.OldestTimestamp) {
			stats.OldestTimestamp = interaction.Timestamp
		}
		if interaction.Timestamp.After(stats.NewestTimestamp) {
			stats.NewestTimestamp = interaction.Timestamp
		}
	}

	return stats
}

// SetTTL configures the time-to-live for interactions.
func (s *Storage) SetTTL(ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ttl = ttl
}

// GetTTL returns the current TTL setting.
func (s *Storage) GetTTL() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ttl
}

// Close stops the cleanup goroutine and releases resources.
func (s *Storage) Close() {
	if s.cancel != nil {
		s.cancel()
	}
}

// cleanupLoop periodically removes old interactions.
func (s *Storage) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.Cleanup()
		}
	}
}

// Cleanup removes interactions older than the configured TTL.
func (s *Storage) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.timeline) == 0 {
		return
	}

	cutoff := time.Now().Add(-s.ttl)

	// Find index where old interactions end
	cutoffIndex := 0
	for i, interaction := range s.timeline {
		if interaction.Timestamp.After(cutoff) {
			cutoffIndex = i
			break
		}
		// If we reach the end, all interactions are old
		if i == len(s.timeline)-1 {
			cutoffIndex = len(s.timeline)
		}
	}

	// Nothing to remove
	if cutoffIndex == 0 {
		return
	}

	// Remove old interactions
	toRemove := s.timeline[:cutoffIndex]

	for _, interaction := range toRemove {
		// Remove from byID map
		interactions := s.byID[interaction.ID]
		for i, existing := range interactions {
			if existing == interaction {
				// Remove this element
				s.byID[interaction.ID] = append(
					interactions[:i],
					interactions[i+1:]...,
				)
				break
			}
		}

		// If no more interactions for this ID, delete the key
		if len(s.byID[interaction.ID]) == 0 {
			delete(s.byID, interaction.ID)
		}

		// Remove from test index
		if interaction.TestID != "" {
			s.removeFromTestIndex(interaction.TestID, interaction.ID)
		}
	}

	// Update timeline
	s.timeline = s.timeline[cutoffIndex:]
}

// removeFromTestIndex removes an interaction ID from the test index.
// Must be called with lock held.
func (s *Storage) removeFromTestIndex(testID, interactionID string) {
	ids := s.testIndex[testID]
	for i, id := range ids {
		if id == interactionID {
			s.testIndex[testID] = append(ids[:i], ids[i+1:]...)
			break
		}
	}
	if len(s.testIndex[testID]) == 0 {
		delete(s.testIndex, testID)
	}
}
