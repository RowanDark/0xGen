// Package delta implements semantic diffing for text, JSON, and XML responses.
package delta

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// DiffType defines the type of diff being performed
type DiffType string

const (
	DiffTypeText DiffType = "text"
	DiffTypeJSON DiffType = "json"
	DiffTypeXML  DiffType = "xml"
)

// ChangeType defines the type of change detected
type ChangeType string

const (
	ChangeTypeAdded    ChangeType = "added"
	ChangeTypeRemoved  ChangeType = "removed"
	ChangeTypeModified ChangeType = "modified"
)

// DiffGranularity defines the level of detail for text diffs
type DiffGranularity string

const (
	GranularityLine      DiffGranularity = "line"
	GranularityWord      DiffGranularity = "word"
	GranularityCharacter DiffGranularity = "character"
)

var (
	diffTypeSet = map[DiffType]struct{}{
		DiffTypeText: {},
		DiffTypeJSON: {},
		DiffTypeXML:  {},
	}

	changeTypeSet = map[ChangeType]struct{}{
		ChangeTypeAdded:    {},
		ChangeTypeRemoved:  {},
		ChangeTypeModified: {},
	}

	granularitySet = map[DiffGranularity]struct{}{
		GranularityLine:      {},
		GranularityWord:      {},
		GranularityCharacter: {},
	}
)

// validate checks if the DiffType is valid
func (dt DiffType) validate() error {
	if _, ok := diffTypeSet[dt]; !ok {
		return fmt.Errorf("invalid diff type: %q", dt)
	}
	return nil
}

// validate checks if the ChangeType is valid
func (ct ChangeType) validate() error {
	if _, ok := changeTypeSet[ct]; !ok {
		return fmt.Errorf("invalid change type: %q", ct)
	}
	return nil
}

// validate checks if the DiffGranularity is valid
func (dg DiffGranularity) validate() error {
	if _, ok := granularitySet[dg]; !ok {
		return fmt.Errorf("invalid granularity: %q", dg)
	}
	return nil
}

// Change represents a single difference detected between two inputs
type Change struct {
	Type       ChangeType `json:"type"`
	Path       string     `json:"path,omitempty"`        // JSON path or XPath
	OldValue   string     `json:"old_value,omitempty"`   // Empty for added changes
	NewValue   string     `json:"new_value,omitempty"`   // Empty for removed changes
	LineNumber int        `json:"line_number,omitempty"` // For text diffs
	Context    string     `json:"context,omitempty"`     // Surrounding context
}

// Validate ensures the change is well-formed
func (c Change) Validate() error {
	if err := c.Type.validate(); err != nil {
		return err
	}

	switch c.Type {
	case ChangeTypeAdded:
		if strings.TrimSpace(c.NewValue) == "" {
			return errors.New("added change must have new_value")
		}
	case ChangeTypeRemoved:
		if strings.TrimSpace(c.OldValue) == "" {
			return errors.New("removed change must have old_value")
		}
	case ChangeTypeModified:
		if strings.TrimSpace(c.OldValue) == "" || strings.TrimSpace(c.NewValue) == "" {
			return errors.New("modified change must have both old_value and new_value")
		}
	}

	return nil
}

// DiffResult represents the complete result of a diff operation
type DiffResult struct {
	Type            DiffType      `json:"type"`
	Changes         []Change      `json:"changes"`
	SimilarityScore float64       `json:"similarity_score"` // 0.0 to 100.0
	LeftSize        int           `json:"left_size"`
	RightSize       int           `json:"right_size"`
	ComputeTime     time.Duration `json:"compute_time_ns"`
	Granularity     string        `json:"granularity,omitempty"` // For text diffs
}

// Validate ensures the diff result is well-formed
func (dr DiffResult) Validate() error {
	if err := dr.Type.validate(); err != nil {
		return err
	}

	if dr.SimilarityScore < 0 || dr.SimilarityScore > 100 {
		return fmt.Errorf("similarity score must be between 0 and 100, got %.2f", dr.SimilarityScore)
	}

	if dr.LeftSize < 0 {
		return fmt.Errorf("left_size cannot be negative: %d", dr.LeftSize)
	}

	if dr.RightSize < 0 {
		return fmt.Errorf("right_size cannot be negative: %d", dr.RightSize)
	}

	for i, change := range dr.Changes {
		if err := change.Validate(); err != nil {
			return fmt.Errorf("invalid change at index %d: %w", i, err)
		}
	}

	return nil
}

// GetAdded returns all added changes
func (dr DiffResult) GetAdded() []Change {
	var added []Change
	for _, change := range dr.Changes {
		if change.Type == ChangeTypeAdded {
			added = append(added, change)
		}
	}
	return added
}

// GetRemoved returns all removed changes
func (dr DiffResult) GetRemoved() []Change {
	var removed []Change
	for _, change := range dr.Changes {
		if change.Type == ChangeTypeRemoved {
			removed = append(removed, change)
		}
	}
	return removed
}

// GetModified returns all modified changes
func (dr DiffResult) GetModified() []Change {
	var modified []Change
	for _, change := range dr.Changes {
		if change.Type == ChangeTypeModified {
			modified = append(modified, change)
		}
	}
	return modified
}

// Summary returns a human-readable summary of the diff
func (dr DiffResult) Summary() string {
	added := len(dr.GetAdded())
	removed := len(dr.GetRemoved())
	modified := len(dr.GetModified())

	return fmt.Sprintf("%d changes (%.1f%% similar): %d added, %d removed, %d modified",
		len(dr.Changes), dr.SimilarityScore, added, removed, modified)
}

// DiffRequest represents a request to perform a diff
type DiffRequest struct {
	Left        []byte          `json:"left"`
	Right       []byte          `json:"right"`
	Type        DiffType        `json:"type"`
	Granularity DiffGranularity `json:"granularity,omitempty"` // For text diffs
}

// Validate ensures the diff request is well-formed
func (dr DiffRequest) Validate() error {
	if err := dr.Type.validate(); err != nil {
		return err
	}

	if len(dr.Left) == 0 {
		return errors.New("left input is empty")
	}

	if len(dr.Right) == 0 {
		return errors.New("right input is empty")
	}

	if dr.Type == DiffTypeText && dr.Granularity != "" {
		if err := dr.Granularity.validate(); err != nil {
			return err
		}
	}

	return nil
}

// StoredDiff represents a diff stored in persistent storage
type StoredDiff struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	LeftRequestID   string     `json:"left_request_id,omitempty"`
	RightRequestID  string     `json:"right_request_id,omitempty"`
	DiffType        DiffType   `json:"diff_type"`
	SimilarityScore float64    `json:"similarity_score"`
	Changes         []Change   `json:"changes"`
	Tags            []string   `json:"tags,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	ComputeTime     time.Duration `json:"compute_time_ns"`
}

// Validate ensures the stored diff is well-formed
func (sd StoredDiff) Validate() error {
	if strings.TrimSpace(sd.ID) == "" {
		return errors.New("id is required")
	}

	if strings.TrimSpace(sd.Name) == "" {
		return errors.New("name is required")
	}

	if err := sd.DiffType.validate(); err != nil {
		return err
	}

	if sd.SimilarityScore < 0 || sd.SimilarityScore > 100 {
		return fmt.Errorf("similarity score must be between 0 and 100, got %.2f", sd.SimilarityScore)
	}

	if sd.CreatedAt.IsZero() {
		return errors.New("created_at is required")
	}

	for i, change := range sd.Changes {
		if err := change.Validate(); err != nil {
			return fmt.Errorf("invalid change at index %d: %w", i, err)
		}
	}

	return nil
}

// MarshalJSON ensures proper JSON encoding
func (sd StoredDiff) MarshalJSON() ([]byte, error) {
	type Alias StoredDiff
	return json.Marshal(&struct {
		*Alias
		ComputeTime int64 `json:"compute_time_ns"`
	}{
		Alias:       (*Alias)(&sd),
		ComputeTime: int64(sd.ComputeTime),
	})
}

// UnmarshalJSON ensures proper JSON decoding
func (sd *StoredDiff) UnmarshalJSON(data []byte) error {
	type Alias StoredDiff
	aux := &struct {
		*Alias
		ComputeTime int64 `json:"compute_time_ns"`
	}{
		Alias: (*Alias)(sd),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	sd.ComputeTime = time.Duration(aux.ComputeTime)
	return nil
}
