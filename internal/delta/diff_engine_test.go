package delta

import (
	"strings"
	"testing"
)

func TestEngine_DiffText_Line(t *testing.T) {
	engine := NewEngine()

	tests := []struct {
		name         string
		left         string
		right        string
		wantChanges  int
		minSimilar   float64
		maxSimilar   float64
	}{
		{
			name:        "identical",
			left:        "line1\nline2\nline3",
			right:       "line1\nline2\nline3",
			wantChanges: 0,
			minSimilar:  100,
			maxSimilar:  100,
		},
		{
			name:        "one line added",
			left:        "line1\nline2",
			right:       "line1\nline2\nline3",
			wantChanges: 1,
			minSimilar:  60,
			maxSimilar:  80,
		},
		{
			name:        "one line removed",
			left:        "line1\nline2\nline3",
			right:       "line1\nline2",
			wantChanges: 1,
			minSimilar:  60,
			maxSimilar:  80,
		},
		{
			name:        "completely different",
			left:        "aaa\nbbb\nccc",
			right:       "xxx\nyyy\nzzz",
			wantChanges: 6, // 3 removed + 3 added
			minSimilar:  0,
			maxSimilar:  10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := DiffRequest{
				Left:        []byte(tt.left),
				Right:       []byte(tt.right),
				Type:        DiffTypeText,
				Granularity: GranularityLine,
			}

			result, err := engine.Diff(req)
			if err != nil {
				t.Fatalf("Diff() error = %v", err)
			}

			if err := result.Validate(); err != nil {
				t.Errorf("result validation failed: %v", err)
			}

			if len(result.Changes) != tt.wantChanges {
				t.Errorf("got %d changes, want %d", len(result.Changes), tt.wantChanges)
			}

			if result.SimilarityScore < tt.minSimilar || result.SimilarityScore > tt.maxSimilar {
				t.Errorf("similarity %.2f not in range [%.2f, %.2f]",
					result.SimilarityScore, tt.minSimilar, tt.maxSimilar)
			}

			if result.Type != DiffTypeText {
				t.Errorf("Type = %v, want %v", result.Type, DiffTypeText)
			}

			if result.Granularity != string(GranularityLine) {
				t.Errorf("Granularity = %v, want %v", result.Granularity, GranularityLine)
			}
		})
	}
}

func TestEngine_DiffText_Word(t *testing.T) {
	engine := NewEngine()

	req := DiffRequest{
		Left:        []byte("hello world"),
		Right:       []byte("hello universe"),
		Type:        DiffTypeText,
		Granularity: GranularityWord,
	}

	result, err := engine.Diff(req)
	if err != nil {
		t.Fatalf("Diff() error = %v", err)
	}

	if result.Type != DiffTypeText {
		t.Errorf("Type = %v, want %v", result.Type, DiffTypeText)
	}

	if result.Granularity != string(GranularityWord) {
		t.Errorf("Granularity = %v, want %v", result.Granularity, GranularityWord)
	}

	// Should detect that "world" was removed and "universe" was added
	// (plus the space characters)
	if len(result.Changes) == 0 {
		t.Error("expected some changes for word diff")
	}
}

func TestEngine_DiffText_Character(t *testing.T) {
	engine := NewEngine()

	req := DiffRequest{
		Left:        []byte("abc"),
		Right:       []byte("adc"),
		Type:        DiffTypeText,
		Granularity: GranularityCharacter,
	}

	result, err := engine.Diff(req)
	if err != nil {
		t.Fatalf("Diff() error = %v", err)
	}

	if result.Type != DiffTypeText {
		t.Errorf("Type = %v, want %v", result.Type, DiffTypeText)
	}

	if result.Granularity != string(GranularityCharacter) {
		t.Errorf("Granularity = %v, want %v", result.Granularity, GranularityCharacter)
	}

	// Should detect that 'b' was removed and 'd' was added
	if len(result.Changes) != 2 {
		t.Errorf("got %d changes, want 2", len(result.Changes))
	}
}

func TestEngine_DiffJSON(t *testing.T) {
	engine := NewEngine()

	tests := []struct {
		name        string
		left        string
		right       string
		wantChanges int
	}{
		{
			name:        "identical",
			left:        `{"key":"value"}`,
			right:       `{"key":"value"}`,
			wantChanges: 0,
		},
		{
			name:        "value changed",
			left:        `{"key":"value1"}`,
			right:       `{"key":"value2"}`,
			wantChanges: 1,
		},
		{
			name:        "key added",
			left:        `{"key1":"value1"}`,
			right:       `{"key1":"value1","key2":"value2"}`,
			wantChanges: 1,
		},
		{
			name:        "key removed",
			left:        `{"key1":"value1","key2":"value2"}`,
			right:       `{"key1":"value1"}`,
			wantChanges: 1,
		},
		{
			name:        "nested object change",
			left:        `{"outer":{"inner":"value1"}}`,
			right:       `{"outer":{"inner":"value2"}}`,
			wantChanges: 1,
		},
		{
			name:        "array element added",
			left:        `{"arr":[1,2]}`,
			right:       `{"arr":[1,2,3]}`,
			wantChanges: 1,
		},
		{
			name:        "array element removed",
			left:        `{"arr":[1,2,3]}`,
			right:       `{"arr":[1,2]}`,
			wantChanges: 1,
		},
		{
			name:        "type change",
			left:        `{"key":"string"}`,
			right:       `{"key":123}`,
			wantChanges: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := DiffRequest{
				Left:  []byte(tt.left),
				Right: []byte(tt.right),
				Type:  DiffTypeJSON,
			}

			result, err := engine.Diff(req)
			if err != nil {
				t.Fatalf("Diff() error = %v", err)
			}

			if err := result.Validate(); err != nil {
				t.Errorf("result validation failed: %v", err)
			}

			if len(result.Changes) != tt.wantChanges {
				t.Errorf("got %d changes, want %d", len(result.Changes), tt.wantChanges)
			}

			if result.Type != DiffTypeJSON {
				t.Errorf("Type = %v, want %v", result.Type, DiffTypeJSON)
			}

			// Verify paths are set
			for _, change := range result.Changes {
				if change.Path == "" {
					t.Errorf("change has empty path: %+v", change)
				}
				if !strings.HasPrefix(change.Path, "$") {
					t.Errorf("JSON path should start with $, got %q", change.Path)
				}
			}
		})
	}
}

func TestEngine_DiffJSON_Fallback(t *testing.T) {
	engine := NewEngine()

	// Invalid JSON should fall back to text diff
	req := DiffRequest{
		Left:  []byte(`not valid json`),
		Right: []byte(`also not valid`),
		Type:  DiffTypeJSON,
	}

	result, err := engine.Diff(req)
	if err != nil {
		t.Fatalf("Diff() error = %v", err)
	}

	// Should still return a result (text diff fallback)
	if result == nil {
		t.Error("expected fallback to text diff")
	}
}

func TestEngine_DiffXML(t *testing.T) {
	engine := NewEngine()

	tests := []struct {
		name        string
		left        string
		right       string
		wantChanges int
	}{
		{
			name:        "identical",
			left:        `<root><item>value</item></root>`,
			right:       `<root><item>value</item></root>`,
			wantChanges: 0,
		},
		{
			name:        "text content changed",
			left:        `<root><item>value1</item></root>`,
			right:       `<root><item>value2</item></root>`,
			wantChanges: 1,
		},
		{
			name:        "attribute added",
			left:        `<root><item>value</item></root>`,
			right:       `<root><item id="1">value</item></root>`,
			wantChanges: 1,
		},
		{
			name:        "attribute changed",
			left:        `<root><item id="1">value</item></root>`,
			right:       `<root><item id="2">value</item></root>`,
			wantChanges: 1,
		},
		{
			name:        "element added",
			left:        `<root><item1>a</item1></root>`,
			right:       `<root><item1>a</item1><item2>b</item2></root>`,
			wantChanges: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := DiffRequest{
				Left:  []byte(tt.left),
				Right: []byte(tt.right),
				Type:  DiffTypeXML,
			}

			result, err := engine.Diff(req)
			if err != nil {
				t.Fatalf("Diff() error = %v", err)
			}

			if err := result.Validate(); err != nil {
				t.Errorf("result validation failed: %v", err)
			}

			if len(result.Changes) != tt.wantChanges {
				t.Errorf("got %d changes, want %d", len(result.Changes), tt.wantChanges)
				for i, c := range result.Changes {
					t.Logf("  change %d: type=%s path=%s", i, c.Type, c.Path)
				}
			}

			if result.Type != DiffTypeXML {
				t.Errorf("Type = %v, want %v", result.Type, DiffTypeXML)
			}

			// Verify paths are set
			for _, change := range result.Changes {
				if change.Path == "" {
					t.Errorf("change has empty path: %+v", change)
				}
				if !strings.HasPrefix(change.Path, "/") {
					t.Errorf("XPath should start with /, got %q", change.Path)
				}
			}
		})
	}
}

func TestEngine_DiffXML_Fallback(t *testing.T) {
	engine := NewEngine()

	// Invalid XML should fall back to text diff
	req := DiffRequest{
		Left:  []byte(`not valid xml`),
		Right: []byte(`also not valid`),
		Type:  DiffTypeXML,
	}

	result, err := engine.Diff(req)
	if err != nil {
		t.Fatalf("Diff() error = %v", err)
	}

	// Should still return a result (text diff fallback)
	if result == nil {
		t.Error("expected fallback to text diff")
	}
}

func TestGenerateUnifiedDiff(t *testing.T) {
	result := &DiffResult{
		Type: DiffTypeText,
		Changes: []Change{
			{Type: ChangeTypeRemoved, OldValue: "old line"},
			{Type: ChangeTypeAdded, NewValue: "new line"},
		},
	}

	unified := GenerateUnifiedDiff(result, "left.txt", "right.txt")

	if !strings.Contains(unified, "--- left.txt") {
		t.Error("unified diff should contain left file name")
	}

	if !strings.Contains(unified, "+++ right.txt") {
		t.Error("unified diff should contain right file name")
	}

	if !strings.Contains(unified, "-old line") {
		t.Error("unified diff should contain removed line")
	}

	if !strings.Contains(unified, "+new line") {
		t.Error("unified diff should contain added line")
	}
}

func TestGenerateUnifiedDiff_NonText(t *testing.T) {
	result := &DiffResult{
		Type: DiffTypeJSON,
		Changes: []Change{
			{Type: ChangeTypeModified, Path: "$.key", OldValue: "old", NewValue: "new"},
		},
	}

	unified := GenerateUnifiedDiff(result, "left.json", "right.json")

	// Should return empty string for non-text diffs
	if unified != "" {
		t.Errorf("expected empty string for non-text diff, got %q", unified)
	}
}

func TestDiff_InvalidRequest(t *testing.T) {
	engine := NewEngine()

	// Empty left
	req := DiffRequest{
		Right: []byte("test"),
		Type:  DiffTypeText,
	}

	_, err := engine.Diff(req)
	if err == nil {
		t.Error("expected error for invalid request")
	}
}

func TestDiff_UnsupportedType(t *testing.T) {
	engine := NewEngine()

	req := DiffRequest{
		Left:  []byte("test"),
		Right: []byte("test"),
		Type:  DiffType("unsupported"),
	}

	_, err := engine.Diff(req)
	if err == nil {
		t.Error("expected error for unsupported type")
	}
}

func TestSplitLines(t *testing.T) {
	tests := []struct {
		name  string
		text  string
		want  int
	}{
		{"empty", "", 0},
		{"single line", "hello", 1},
		{"two lines", "hello\nworld", 2},
		{"three lines", "a\nb\nc", 3},
		{"trailing newline", "a\nb\n", 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines := splitLines(tt.text)
			if len(lines) != tt.want {
				t.Errorf("splitLines() = %d lines, want %d", len(lines), tt.want)
			}
		})
	}
}

func TestSplitWords(t *testing.T) {
	tests := []struct {
		name string
		text string
		want int
	}{
		{"empty", "", 0},
		{"single word", "hello", 1},
		{"two words", "hello world", 3}, // "hello", " ", "world"
		{"with punctuation", "hello, world!", 5}, // "hello", ",", " ", "world", "!"
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			words := splitWords(tt.text)
			if len(words) != tt.want {
				t.Errorf("splitWords() = %d tokens, want %d", len(words), tt.want)
			}
		})
	}
}

func TestFormatValue(t *testing.T) {
	tests := []struct {
		name  string
		value interface{}
		want  string
	}{
		{"nil", nil, "null"},
		{"string", "hello", "hello"},
		{"number", 42.0, "42"},
		{"bool", true, "true"},
		{"object", map[string]interface{}{"key": "value"}, `{"key":"value"}`},
		{"array", []interface{}{1.0, 2.0, 3.0}, "[1,2,3]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatValue(tt.value)
			if got != tt.want {
				t.Errorf("formatValue() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCalculateSimilarity(t *testing.T) {
	tests := []struct {
		name        string
		leftLen     int
		rightLen    int
		changeCount int
		want        float64
	}{
		{"identical", 10, 10, 0, 100.0},
		{"completely different", 10, 10, 20, 0.0},
		{"half different", 10, 10, 5, 50.0},
		{"empty", 0, 0, 0, 100.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateSimilarity(tt.leftLen, tt.rightLen, tt.changeCount)
			if got != tt.want {
				t.Errorf("calculateSimilarity() = %.2f, want %.2f", got, tt.want)
			}
		})
	}
}

func TestEngine_DiffText_LineNumbers(t *testing.T) {
	engine := NewEngine()

	tests := []struct {
		name           string
		left           string
		right          string
		wantChanges    []Change
	}{
		{
			name:  "insertion after unchanged line",
			left:  "line1\nline2",
			right: "line1\nX\nline2",
			wantChanges: []Change{
				{Type: ChangeTypeAdded, NewValue: "X", LineNumber: 2},
			},
		},
		{
			name:  "deletion after unchanged line",
			left:  "line1\nX\nline2",
			right: "line1\nline2",
			wantChanges: []Change{
				{Type: ChangeTypeRemoved, OldValue: "X", LineNumber: 2},
			},
		},
		{
			name:  "multiple changes with unchanged lines",
			left:  "line1\nline2\nline3\nline4",
			right: "line1\nX\nline3\nY",
			wantChanges: []Change{
				// Myers diff returns removals before additions at the same position
				{Type: ChangeTypeRemoved, OldValue: "line2", LineNumber: 2},
				{Type: ChangeTypeAdded, NewValue: "X", LineNumber: 2},
				{Type: ChangeTypeRemoved, OldValue: "line4", LineNumber: 4},
				{Type: ChangeTypeAdded, NewValue: "Y", LineNumber: 4},
			},
		},
		{
			name:  "change at beginning",
			left:  "X\nline2\nline3",
			right: "line1\nline2\nline3",
			wantChanges: []Change{
				// Myers diff returns removals before additions
				{Type: ChangeTypeRemoved, OldValue: "X", LineNumber: 1},
				{Type: ChangeTypeAdded, NewValue: "line1", LineNumber: 1},
			},
		},
		{
			name:  "duplicate lines - addition at end",
			left:  "foo\nbar\nbar",
			right: "foo\nbar\nbar\nbar",
			wantChanges: []Change{
				{Type: ChangeTypeAdded, NewValue: "bar", LineNumber: 4},
			},
		},
		{
			name:  "duplicate lines - removal from middle",
			left:  "foo\nbar\nbar\nbar",
			right: "foo\nbar\nbar",
			wantChanges: []Change{
				{Type: ChangeTypeRemoved, OldValue: "bar", LineNumber: 4},
			},
		},
		{
			name:  "duplicate lines - multiple changes",
			left:  "a\nb\nb\nc",
			right: "a\nb\nb\nb\nc",
			wantChanges: []Change{
				{Type: ChangeTypeAdded, NewValue: "b", LineNumber: 4},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := DiffRequest{
				Left:        []byte(tt.left),
				Right:       []byte(tt.right),
				Type:        DiffTypeText,
				Granularity: GranularityLine,
			}

			result, err := engine.Diff(req)
			if err != nil {
				t.Fatalf("Diff() error = %v", err)
			}

			if len(result.Changes) != len(tt.wantChanges) {
				t.Errorf("got %d changes, want %d", len(result.Changes), len(tt.wantChanges))
				for i, c := range result.Changes {
					t.Logf("  got change %d: type=%s line=%d old=%q new=%q",
						i, c.Type, c.LineNumber, c.OldValue, c.NewValue)
				}
				return
			}

			// Check each change
			for i, wantChange := range tt.wantChanges {
				gotChange := result.Changes[i]

				if gotChange.Type != wantChange.Type {
					t.Errorf("change %d: type = %s, want %s", i, gotChange.Type, wantChange.Type)
				}

				if gotChange.LineNumber != wantChange.LineNumber {
					t.Errorf("change %d (%s): line number = %d, want %d",
						i, gotChange.Type, gotChange.LineNumber, wantChange.LineNumber)
				}

				if gotChange.OldValue != wantChange.OldValue {
					t.Errorf("change %d: old value = %q, want %q", i, gotChange.OldValue, wantChange.OldValue)
				}

				if gotChange.NewValue != wantChange.NewValue {
					t.Errorf("change %d: new value = %q, want %q", i, gotChange.NewValue, wantChange.NewValue)
				}
			}
		})
	}
}
