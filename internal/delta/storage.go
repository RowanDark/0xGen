package delta

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/RowanDark/0xgen/internal/findings"
)

// Store manages diff storage and retrieval
type Store struct {
	mu    sync.RWMutex
	diffs map[string]*StoredDiff
	tags  map[string][]string // tag -> diff IDs
}

// NewStore creates a new diff storage
func NewStore() *Store {
	return &Store{
		diffs: make(map[string]*StoredDiff),
		tags:  make(map[string][]string),
	}
}

// Save stores a diff result
func (s *Store) Save(name string, result *DiffResult, leftReqID, rightReqID string, tags []string) (*StoredDiff, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("name is required")
	}

	if result == nil {
		return nil, errors.New("result is required")
	}

	if err := result.Validate(); err != nil {
		return nil, fmt.Errorf("invalid result: %w", err)
	}

	stored := &StoredDiff{
		ID:              findings.NewID(),
		Name:            name,
		LeftRequestID:   strings.TrimSpace(leftReqID),
		RightRequestID:  strings.TrimSpace(rightReqID),
		DiffType:        result.Type,
		SimilarityScore: result.SimilarityScore,
		Changes:         result.Changes,
		Tags:            tags,
		CreatedAt:       time.Now().UTC(),
		ComputeTime:     result.ComputeTime,
	}

	if err := stored.Validate(); err != nil {
		return nil, fmt.Errorf("invalid stored diff: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.diffs[stored.ID] = stored

	// Index by tags
	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		if tag != "" {
			s.tags[tag] = append(s.tags[tag], stored.ID)
		}
	}

	return cloneStoredDiff(stored), nil
}

// Get retrieves a diff by ID
func (s *Store) Get(id string) (*StoredDiff, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, errors.New("id is required")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	diff, ok := s.diffs[id]
	if !ok {
		return nil, errors.New("diff not found")
	}

	return cloneStoredDiff(diff), nil
}

// Delete removes a diff by ID
func (s *Store) Delete(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return errors.New("id is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	diff, ok := s.diffs[id]
	if !ok {
		return errors.New("diff not found")
	}

	// Remove from tag index
	for _, tag := range diff.Tags {
		ids := s.tags[tag]
		for i, diffID := range ids {
			if diffID == id {
				s.tags[tag] = append(ids[:i], ids[i+1:]...)
				break
			}
		}
		if len(s.tags[tag]) == 0 {
			delete(s.tags, tag)
		}
	}

	delete(s.diffs, id)
	return nil
}

// List returns all diffs
func (s *Store) List() []*StoredDiff {
	s.mu.RLock()
	defer s.mu.RUnlock()

	diffs := make([]*StoredDiff, 0, len(s.diffs))
	for _, diff := range s.diffs {
		diffs = append(diffs, cloneStoredDiff(diff))
	}

	return diffs
}

// ListByTag returns all diffs with a specific tag
func (s *Store) ListByTag(tag string) []*StoredDiff {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return []*StoredDiff{}
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := s.tags[tag]
	diffs := make([]*StoredDiff, 0, len(ids))

	for _, id := range ids {
		if diff, ok := s.diffs[id]; ok {
			diffs = append(diffs, cloneStoredDiff(diff))
		}
	}

	return diffs
}

// SearchOptions configures diff search
type SearchOptions struct {
	MinSimilarity float64
	MaxSimilarity float64
	DiffType      DiffType
	Tags          []string
	Limit         int
}

// Search finds diffs matching the criteria
func (s *Store) Search(opts SearchOptions) []*StoredDiff {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []*StoredDiff

	for _, diff := range s.diffs {
		// Check similarity range
		if opts.MinSimilarity > 0 && diff.SimilarityScore < opts.MinSimilarity {
			continue
		}
		if opts.MaxSimilarity > 0 && diff.SimilarityScore > opts.MaxSimilarity {
			continue
		}

		// Check diff type
		if opts.DiffType != "" && diff.DiffType != opts.DiffType {
			continue
		}

		// Check tags (must have all specified tags)
		if len(opts.Tags) > 0 {
			hasAllTags := true
			for _, requiredTag := range opts.Tags {
				found := false
				for _, diffTag := range diff.Tags {
					if diffTag == requiredTag {
						found = true
						break
					}
				}
				if !found {
					hasAllTags = false
					break
				}
			}
			if !hasAllTags {
				continue
			}
		}

		results = append(results, cloneStoredDiff(diff))

		// Apply limit
		if opts.Limit > 0 && len(results) >= opts.Limit {
			break
		}
	}

	return results
}

// Update modifies an existing diff
func (s *Store) Update(id string, updates func(*StoredDiff) error) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return errors.New("id is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	diff, ok := s.diffs[id]
	if !ok {
		return errors.New("diff not found")
	}

	// Create a copy to work with
	updated := cloneStoredDiff(diff)

	// Apply updates
	if err := updates(updated); err != nil {
		return err
	}

	// Validate
	if err := updated.Validate(); err != nil {
		return fmt.Errorf("invalid updated diff: %w", err)
	}

	// Update tag index if tags changed
	if !equalTags(diff.Tags, updated.Tags) {
		// Remove old tag references
		for _, tag := range diff.Tags {
			ids := s.tags[tag]
			for i, diffID := range ids {
				if diffID == id {
					s.tags[tag] = append(ids[:i], ids[i+1:]...)
					break
				}
			}
			if len(s.tags[tag]) == 0 {
				delete(s.tags, tag)
			}
		}

		// Add new tag references
		for _, tag := range updated.Tags {
			tag = strings.TrimSpace(tag)
			if tag != "" {
				s.tags[tag] = append(s.tags[tag], id)
			}
		}
	}

	s.diffs[id] = updated
	return nil
}

// Stats returns storage statistics
func (s *Store) Stats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var totalChanges int
	diffTypes := make(map[string]int)

	for _, diff := range s.diffs {
		totalChanges += len(diff.Changes)
		diffTypes[string(diff.DiffType)]++
	}

	return map[string]interface{}{
		"total_diffs":    len(s.diffs),
		"total_changes":  totalChanges,
		"total_tags":     len(s.tags),
		"diffs_by_type":  diffTypes,
	}
}

// Helper functions

func cloneStoredDiff(sd *StoredDiff) *StoredDiff {
	if sd == nil {
		return nil
	}

	clone := &StoredDiff{
		ID:              sd.ID,
		Name:            sd.Name,
		LeftRequestID:   sd.LeftRequestID,
		RightRequestID:  sd.RightRequestID,
		DiffType:        sd.DiffType,
		SimilarityScore: sd.SimilarityScore,
		Changes:         make([]Change, len(sd.Changes)),
		Tags:            make([]string, len(sd.Tags)),
		CreatedAt:       sd.CreatedAt,
		ComputeTime:     sd.ComputeTime,
	}

	copy(clone.Changes, sd.Changes)
	copy(clone.Tags, sd.Tags)

	return clone
}

func equalTags(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	aMap := make(map[string]struct{}, len(a))
	for _, tag := range a {
		aMap[tag] = struct{}{}
	}

	for _, tag := range b {
		if _, ok := aMap[tag]; !ok {
			return false
		}
	}

	return true
}
