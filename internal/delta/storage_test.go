package delta

import (
	"testing"
	"time"
)

func TestStore_Save(t *testing.T) {
	store := NewStore()

	result := &DiffResult{
		Type:            DiffTypeText,
		Changes:         []Change{{Type: ChangeTypeAdded, NewValue: "test"}},
		SimilarityScore: 85.5,
		LeftSize:        100,
		RightSize:       110,
		ComputeTime:     100 * time.Millisecond,
	}

	stored, err := store.Save("test diff", result, "req1", "req2", []string{"tag1", "tag2"})
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	if stored.ID == "" {
		t.Error("expected non-empty ID")
	}

	if stored.Name != "test diff" {
		t.Errorf("Name = %q, want %q", stored.Name, "test diff")
	}

	if stored.LeftRequestID != "req1" {
		t.Errorf("LeftRequestID = %q, want %q", stored.LeftRequestID, "req1")
	}

	if stored.RightRequestID != "req2" {
		t.Errorf("RightRequestID = %q, want %q", stored.RightRequestID, "req2")
	}

	if len(stored.Tags) != 2 {
		t.Errorf("got %d tags, want 2", len(stored.Tags))
	}

	if stored.SimilarityScore != 85.5 {
		t.Errorf("SimilarityScore = %.2f, want 85.5", stored.SimilarityScore)
	}
}

func TestStore_Save_Invalid(t *testing.T) {
	store := NewStore()

	tests := []struct {
		name   string
		dfName string
		result *DiffResult
	}{
		{
			name:   "empty name",
			dfName: "",
			result: &DiffResult{
				Type:            DiffTypeText,
				SimilarityScore: 85.5,
			},
		},
		{
			name:   "nil result",
			dfName: "test",
			result: nil,
		},
		{
			name:   "invalid result",
			dfName: "test",
			result: &DiffResult{
				Type:            DiffType("invalid"),
				SimilarityScore: 85.5,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := store.Save(tt.dfName, tt.result, "", "", nil)
			if err == nil {
				t.Error("expected error for invalid input")
			}
		})
	}
}

func TestStore_Get(t *testing.T) {
	store := NewStore()

	result := &DiffResult{
		Type:            DiffTypeText,
		Changes:         []Change{},
		SimilarityScore: 85.5,
		LeftSize:        100,
		RightSize:       100,
	}

	stored, err := store.Save("test", result, "", "", nil)
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	retrieved, err := store.Get(stored.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	if retrieved.ID != stored.ID {
		t.Errorf("ID = %q, want %q", retrieved.ID, stored.ID)
	}

	if retrieved.Name != stored.Name {
		t.Errorf("Name = %q, want %q", retrieved.Name, stored.Name)
	}
}

func TestStore_Get_NotFound(t *testing.T) {
	store := NewStore()

	_, err := store.Get("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent diff")
	}
}

func TestStore_Delete(t *testing.T) {
	store := NewStore()

	result := &DiffResult{
		Type:            DiffTypeText,
		Changes:         []Change{},
		SimilarityScore: 85.5,
		LeftSize:        100,
		RightSize:       100,
	}

	stored, err := store.Save("test", result, "", "", []string{"tag1"})
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Verify it exists
	if _, err := store.Get(stored.ID); err != nil {
		t.Fatalf("Get() before delete error = %v", err)
	}

	// Delete it
	if err := store.Delete(stored.ID); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Verify it's gone
	if _, err := store.Get(stored.ID); err == nil {
		t.Error("expected error after delete")
	}

	// Verify tag index is cleaned up
	byTag := store.ListByTag("tag1")
	if len(byTag) != 0 {
		t.Errorf("expected 0 diffs with tag after delete, got %d", len(byTag))
	}
}

func TestStore_List(t *testing.T) {
	store := NewStore()

	result := &DiffResult{
		Type:            DiffTypeText,
		Changes:         []Change{},
		SimilarityScore: 85.5,
		LeftSize:        100,
		RightSize:       100,
	}

	// Add multiple diffs
	for i := 0; i < 3; i++ {
		if _, err := store.Save("test", result, "", "", nil); err != nil {
			t.Fatalf("Save() error = %v", err)
		}
	}

	list := store.List()
	if len(list) != 3 {
		t.Errorf("got %d diffs, want 3", len(list))
	}
}

func TestStore_ListByTag(t *testing.T) {
	store := NewStore()

	result := &DiffResult{
		Type:            DiffTypeText,
		Changes:         []Change{},
		SimilarityScore: 85.5,
		LeftSize:        100,
		RightSize:       100,
	}

	// Add diffs with different tags
	store.Save("diff1", result, "", "", []string{"tag1", "tag2"})
	store.Save("diff2", result, "", "", []string{"tag1"})
	store.Save("diff3", result, "", "", []string{"tag2"})
	store.Save("diff4", result, "", "", []string{"tag3"})

	tag1List := store.ListByTag("tag1")
	if len(tag1List) != 2 {
		t.Errorf("got %d diffs with tag1, want 2", len(tag1List))
	}

	tag2List := store.ListByTag("tag2")
	if len(tag2List) != 2 {
		t.Errorf("got %d diffs with tag2, want 2", len(tag2List))
	}

	tag3List := store.ListByTag("tag3")
	if len(tag3List) != 1 {
		t.Errorf("got %d diffs with tag3, want 1", len(tag3List))
	}

	nonexistentList := store.ListByTag("nonexistent")
	if len(nonexistentList) != 0 {
		t.Errorf("got %d diffs with nonexistent tag, want 0", len(nonexistentList))
	}
}

func TestStore_Search(t *testing.T) {
	store := NewStore()

	// Add diffs with different attributes
	result1 := &DiffResult{
		Type:            DiffTypeText,
		Changes:         []Change{},
		SimilarityScore: 90.0,
		LeftSize:        100,
		RightSize:       100,
	}
	store.Save("diff1", result1, "", "", []string{"tag1"})

	result2 := &DiffResult{
		Type:            DiffTypeJSON,
		Changes:         []Change{},
		SimilarityScore: 50.0,
		LeftSize:        100,
		RightSize:       100,
	}
	store.Save("diff2", result2, "", "", []string{"tag2"})

	result3 := &DiffResult{
		Type:            DiffTypeXML,
		Changes:         []Change{},
		SimilarityScore: 75.0,
		LeftSize:        100,
		RightSize:       100,
	}
	store.Save("diff3", result3, "", "", []string{"tag1", "tag2"})

	tests := []struct {
		name string
		opts SearchOptions
		want int
	}{
		{
			name: "by min similarity",
			opts: SearchOptions{MinSimilarity: 80.0},
			want: 1,
		},
		{
			name: "by max similarity",
			opts: SearchOptions{MaxSimilarity: 60.0},
			want: 1,
		},
		{
			name: "by similarity range",
			opts: SearchOptions{MinSimilarity: 70.0, MaxSimilarity: 80.0},
			want: 1,
		},
		{
			name: "by diff type",
			opts: SearchOptions{DiffType: DiffTypeJSON},
			want: 1,
		},
		{
			name: "by single tag",
			opts: SearchOptions{Tags: []string{"tag1"}},
			want: 2,
		},
		{
			name: "by multiple tags",
			opts: SearchOptions{Tags: []string{"tag1", "tag2"}},
			want: 1,
		},
		{
			name: "with limit",
			opts: SearchOptions{Limit: 1},
			want: 1,
		},
		{
			name: "combined criteria",
			opts: SearchOptions{
				MinSimilarity: 70.0,
				DiffType:      DiffTypeXML,
				Tags:          []string{"tag1"},
			},
			want: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := store.Search(tt.opts)
			if len(results) != tt.want {
				t.Errorf("got %d results, want %d", len(results), tt.want)
			}
		})
	}
}

func TestStore_Update(t *testing.T) {
	store := NewStore()

	result := &DiffResult{
		Type:            DiffTypeText,
		Changes:         []Change{},
		SimilarityScore: 85.5,
		LeftSize:        100,
		RightSize:       100,
	}

	stored, err := store.Save("original name", result, "", "", []string{"tag1"})
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Update the name and tags
	err = store.Update(stored.ID, func(sd *StoredDiff) error {
		sd.Name = "updated name"
		sd.Tags = []string{"tag2", "tag3"}
		return nil
	})
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	// Verify the update
	updated, err := store.Get(stored.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	if updated.Name != "updated name" {
		t.Errorf("Name = %q, want %q", updated.Name, "updated name")
	}

	if len(updated.Tags) != 2 {
		t.Errorf("got %d tags, want 2", len(updated.Tags))
	}

	// Verify old tag is removed from index
	oldTagList := store.ListByTag("tag1")
	if len(oldTagList) != 0 {
		t.Errorf("old tag should be removed, got %d diffs", len(oldTagList))
	}

	// Verify new tags are in index
	newTagList := store.ListByTag("tag2")
	if len(newTagList) != 1 {
		t.Errorf("new tag should be added, got %d diffs", len(newTagList))
	}
}

func TestStore_Update_Invalid(t *testing.T) {
	store := NewStore()

	result := &DiffResult{
		Type:            DiffTypeText,
		Changes:         []Change{},
		SimilarityScore: 85.5,
		LeftSize:        100,
		RightSize:       100,
	}

	stored, err := store.Save("test", result, "", "", nil)
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Try to update with invalid data
	err = store.Update(stored.ID, func(sd *StoredDiff) error {
		sd.Name = "" // Invalid
		return nil
	})
	if err == nil {
		t.Error("expected error for invalid update")
	}

	// Verify the original is unchanged
	retrieved, err := store.Get(stored.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	if retrieved.Name != "test" {
		t.Errorf("Name should be unchanged, got %q", retrieved.Name)
	}
}

func TestStore_Stats(t *testing.T) {
	store := NewStore()

	// Add some diffs
	store.Save("diff1", &DiffResult{
		Type:            DiffTypeText,
		Changes:         []Change{{Type: ChangeTypeAdded, NewValue: "test"}},
		SimilarityScore: 85.5,
		LeftSize:        100,
		RightSize:       100,
	}, "", "", []string{"tag1"})

	store.Save("diff2", &DiffResult{
		Type:            DiffTypeJSON,
		Changes:         []Change{{Type: ChangeTypeModified, OldValue: "old", NewValue: "new"}},
		SimilarityScore: 75.0,
		LeftSize:        100,
		RightSize:       100,
	}, "", "", []string{"tag2"})

	stats := store.Stats()

	totalDiffs, ok := stats["total_diffs"].(int)
	if !ok || totalDiffs != 2 {
		t.Errorf("total_diffs = %v, want 2", totalDiffs)
	}

	totalChanges, ok := stats["total_changes"].(int)
	if !ok || totalChanges != 2 {
		t.Errorf("total_changes = %v, want 2", totalChanges)
	}

	totalTags, ok := stats["total_tags"].(int)
	if !ok || totalTags != 2 {
		t.Errorf("total_tags = %v, want 2", totalTags)
	}

	diffsByType, ok := stats["diffs_by_type"].(map[string]int)
	if !ok {
		t.Fatal("diffs_by_type should be a map")
	}

	if diffsByType["text"] != 1 {
		t.Errorf("text diffs = %d, want 1", diffsByType["text"])
	}

	if diffsByType["json"] != 1 {
		t.Errorf("json diffs = %d, want 1", diffsByType["json"])
	}
}

func TestStore_Concurrent(t *testing.T) {
	store := NewStore()

	result := &DiffResult{
		Type:            DiffTypeText,
		Changes:         []Change{},
		SimilarityScore: 85.5,
		LeftSize:        100,
		RightSize:       100,
	}

	// Test concurrent writes
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(n int) {
			_, err := store.Save("test", result, "", "", nil)
			if err != nil {
				t.Errorf("concurrent Save() error = %v", err)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	list := store.List()
	if len(list) != 10 {
		t.Errorf("got %d diffs after concurrent writes, want 10", len(list))
	}
}
