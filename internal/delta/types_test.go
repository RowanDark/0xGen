package delta

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDiffType_Validate(t *testing.T) {
	tests := []struct {
		name    string
		dt      DiffType
		wantErr bool
	}{
		{"valid text", DiffTypeText, false},
		{"valid json", DiffTypeJSON, false},
		{"valid xml", DiffTypeXML, false},
		{"invalid", DiffType("invalid"), true},
		{"empty", DiffType(""), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.dt.validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestChangeType_Validate(t *testing.T) {
	tests := []struct {
		name    string
		ct      ChangeType
		wantErr bool
	}{
		{"valid added", ChangeTypeAdded, false},
		{"valid removed", ChangeTypeRemoved, false},
		{"valid modified", ChangeTypeModified, false},
		{"invalid", ChangeType("invalid"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.ct.validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestChange_Validate(t *testing.T) {
	tests := []struct {
		name    string
		change  Change
		wantErr bool
	}{
		{
			name: "valid added",
			change: Change{
				Type:     ChangeTypeAdded,
				NewValue: "test",
			},
			wantErr: false,
		},
		{
			name: "invalid added - missing new value",
			change: Change{
				Type: ChangeTypeAdded,
			},
			wantErr: true,
		},
		{
			name: "valid removed",
			change: Change{
				Type:     ChangeTypeRemoved,
				OldValue: "test",
			},
			wantErr: false,
		},
		{
			name: "invalid removed - missing old value",
			change: Change{
				Type: ChangeTypeRemoved,
			},
			wantErr: true,
		},
		{
			name: "valid modified",
			change: Change{
				Type:     ChangeTypeModified,
				OldValue: "old",
				NewValue: "new",
			},
			wantErr: false,
		},
		{
			name: "invalid modified - missing old value",
			change: Change{
				Type:     ChangeTypeModified,
				NewValue: "new",
			},
			wantErr: true,
		},
		{
			name: "invalid modified - missing new value",
			change: Change{
				Type:     ChangeTypeModified,
				OldValue: "old",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.change.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDiffResult_Validate(t *testing.T) {
	tests := []struct {
		name    string
		result  DiffResult
		wantErr bool
	}{
		{
			name: "valid result",
			result: DiffResult{
				Type:            DiffTypeText,
				Changes:         []Change{},
				SimilarityScore: 85.5,
				LeftSize:        100,
				RightSize:       120,
			},
			wantErr: false,
		},
		{
			name: "invalid type",
			result: DiffResult{
				Type:            DiffType("invalid"),
				SimilarityScore: 85.5,
			},
			wantErr: true,
		},
		{
			name: "invalid similarity - too low",
			result: DiffResult{
				Type:            DiffTypeText,
				SimilarityScore: -10,
			},
			wantErr: true,
		},
		{
			name: "invalid similarity - too high",
			result: DiffResult{
				Type:            DiffTypeText,
				SimilarityScore: 150,
			},
			wantErr: true,
		},
		{
			name: "invalid left size",
			result: DiffResult{
				Type:            DiffTypeText,
				SimilarityScore: 85.5,
				LeftSize:        -1,
			},
			wantErr: true,
		},
		{
			name: "invalid right size",
			result: DiffResult{
				Type:            DiffTypeText,
				SimilarityScore: 85.5,
				RightSize:       -1,
			},
			wantErr: true,
		},
		{
			name: "invalid change",
			result: DiffResult{
				Type:            DiffTypeText,
				SimilarityScore: 85.5,
				Changes: []Change{
					{Type: ChangeTypeAdded}, // Missing new value
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.result.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDiffResult_GetMethods(t *testing.T) {
	result := DiffResult{
		Type: DiffTypeText,
		Changes: []Change{
			{Type: ChangeTypeAdded, NewValue: "added1"},
			{Type: ChangeTypeRemoved, OldValue: "removed1"},
			{Type: ChangeTypeModified, OldValue: "old", NewValue: "new"},
			{Type: ChangeTypeAdded, NewValue: "added2"},
			{Type: ChangeTypeRemoved, OldValue: "removed2"},
		},
		SimilarityScore: 60,
	}

	added := result.GetAdded()
	if len(added) != 2 {
		t.Errorf("GetAdded() returned %d changes, want 2", len(added))
	}

	removed := result.GetRemoved()
	if len(removed) != 2 {
		t.Errorf("GetRemoved() returned %d changes, want 2", len(removed))
	}

	modified := result.GetModified()
	if len(modified) != 1 {
		t.Errorf("GetModified() returned %d changes, want 1", len(modified))
	}
}

func TestDiffResult_Summary(t *testing.T) {
	result := DiffResult{
		Type: DiffTypeText,
		Changes: []Change{
			{Type: ChangeTypeAdded, NewValue: "added"},
			{Type: ChangeTypeRemoved, OldValue: "removed"},
			{Type: ChangeTypeModified, OldValue: "old", NewValue: "new"},
		},
		SimilarityScore: 75.5,
	}

	summary := result.Summary()
	expected := "3 changes (75.5% similar): 1 added, 1 removed, 1 modified"
	if summary != expected {
		t.Errorf("Summary() = %q, want %q", summary, expected)
	}
}

func TestDiffRequest_Validate(t *testing.T) {
	tests := []struct {
		name    string
		req     DiffRequest
		wantErr bool
	}{
		{
			name: "valid text request",
			req: DiffRequest{
				Left:        []byte("hello"),
				Right:       []byte("world"),
				Type:        DiffTypeText,
				Granularity: GranularityLine,
			},
			wantErr: false,
		},
		{
			name: "valid json request",
			req: DiffRequest{
				Left:  []byte(`{"key":"value"}`),
				Right: []byte(`{"key":"changed"}`),
				Type:  DiffTypeJSON,
			},
			wantErr: false,
		},
		{
			name: "invalid type",
			req: DiffRequest{
				Left:  []byte("test"),
				Right: []byte("test"),
				Type:  DiffType("invalid"),
			},
			wantErr: true,
		},
		{
			name: "empty left",
			req: DiffRequest{
				Right: []byte("test"),
				Type:  DiffTypeText,
			},
			wantErr: true,
		},
		{
			name: "empty right",
			req: DiffRequest{
				Left: []byte("test"),
				Type: DiffTypeText,
			},
			wantErr: true,
		},
		{
			name: "invalid granularity",
			req: DiffRequest{
				Left:        []byte("test"),
				Right:       []byte("test"),
				Type:        DiffTypeText,
				Granularity: DiffGranularity("invalid"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestStoredDiff_Validate(t *testing.T) {
	tests := []struct {
		name    string
		sd      StoredDiff
		wantErr bool
	}{
		{
			name: "valid",
			sd: StoredDiff{
				ID:              "TEST123",
				Name:            "test diff",
				DiffType:        DiffTypeText,
				SimilarityScore: 85.5,
				CreatedAt:       time.Now(),
				Changes:         []Change{},
			},
			wantErr: false,
		},
		{
			name: "missing id",
			sd: StoredDiff{
				Name:            "test",
				DiffType:        DiffTypeText,
				SimilarityScore: 85.5,
				CreatedAt:       time.Now(),
			},
			wantErr: true,
		},
		{
			name: "missing name",
			sd: StoredDiff{
				ID:              "TEST123",
				DiffType:        DiffTypeText,
				SimilarityScore: 85.5,
				CreatedAt:       time.Now(),
			},
			wantErr: true,
		},
		{
			name: "invalid diff type",
			sd: StoredDiff{
				ID:              "TEST123",
				Name:            "test",
				DiffType:        DiffType("invalid"),
				SimilarityScore: 85.5,
				CreatedAt:       time.Now(),
			},
			wantErr: true,
		},
		{
			name: "invalid similarity",
			sd: StoredDiff{
				ID:              "TEST123",
				Name:            "test",
				DiffType:        DiffTypeText,
				SimilarityScore: 150,
				CreatedAt:       time.Now(),
			},
			wantErr: true,
		},
		{
			name: "missing created_at",
			sd: StoredDiff{
				ID:              "TEST123",
				Name:            "test",
				DiffType:        DiffTypeText,
				SimilarityScore: 85.5,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.sd.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestStoredDiff_JSON(t *testing.T) {
	sd := StoredDiff{
		ID:              "TEST123",
		Name:            "test diff",
		DiffType:        DiffTypeText,
		SimilarityScore: 85.5,
		Changes: []Change{
			{Type: ChangeTypeAdded, NewValue: "test"},
		},
		Tags:        []string{"tag1", "tag2"},
		CreatedAt:   time.Now().UTC().Truncate(time.Second),
		ComputeTime: 500 * time.Millisecond,
	}

	// Test marshaling
	data, err := json.Marshal(sd)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	// Test unmarshaling
	var decoded StoredDiff
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	// Verify fields
	if decoded.ID != sd.ID {
		t.Errorf("ID = %q, want %q", decoded.ID, sd.ID)
	}
	if decoded.Name != sd.Name {
		t.Errorf("Name = %q, want %q", decoded.Name, sd.Name)
	}
	if decoded.DiffType != sd.DiffType {
		t.Errorf("DiffType = %q, want %q", decoded.DiffType, sd.DiffType)
	}
	if decoded.SimilarityScore != sd.SimilarityScore {
		t.Errorf("SimilarityScore = %f, want %f", decoded.SimilarityScore, sd.SimilarityScore)
	}
	if decoded.ComputeTime != sd.ComputeTime {
		t.Errorf("ComputeTime = %v, want %v", decoded.ComputeTime, sd.ComputeTime)
	}
}
