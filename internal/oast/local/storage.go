package local

import (
	"sync"
	"time"
)

// Storage provides thread-safe in-memory storage for OAST interactions.
type Storage struct {
	mu           sync.RWMutex
	interactions []*Interaction
	byID         map[string][]*Interaction
}

// NewStorage creates a new in-memory interaction storage.
func NewStorage() *Storage {
	return &Storage{
		interactions: make([]*Interaction, 0),
		byID:         make(map[string][]*Interaction),
	}
}

// Store saves an interaction to storage.
func (s *Storage) Store(interaction *Interaction) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.interactions = append(s.interactions, interaction)
	s.byID[interaction.ID] = append(s.byID[interaction.ID], interaction)

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

// GetAll returns all stored interactions.
func (s *Storage) GetAll() []*Interaction {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*Interaction, len(s.interactions))
	copy(result, s.interactions)
	return result
}

// GetCount returns the total number of stored interactions.
func (s *Storage) GetCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.interactions)
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

	s.interactions = make([]*Interaction, 0)
	s.byID = make(map[string][]*Interaction)
}

// DeleteByID removes all interactions for a given ID.
func (s *Storage) DeleteByID(id string) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := len(s.byID[id])
	if count == 0 {
		return 0
	}

	// Remove from byID map
	delete(s.byID, id)

	// Remove from interactions slice
	filtered := make([]*Interaction, 0, len(s.interactions)-count)
	for _, interaction := range s.interactions {
		if interaction.ID != id {
			filtered = append(filtered, interaction)
		}
	}
	s.interactions = filtered

	return count
}

// GetSince returns all interactions since the given timestamp.
func (s *Storage) GetSince(since time.Time) []*Interaction {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*Interaction, 0)
	for _, interaction := range s.interactions {
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
