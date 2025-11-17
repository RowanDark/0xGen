package delta

import (
	"testing"
)

func TestMyersDiff_Identical(t *testing.T) {
	left := []string{"a", "b", "c"}
	right := []string{"a", "b", "c"}

	changes := myersDiff(left, right)

	if len(changes) != 0 {
		t.Errorf("identical sequences should have 0 changes, got %d", len(changes))
	}
}

func TestMyersDiff_SingleAddition(t *testing.T) {
	left := []string{"a", "b"}
	right := []string{"a", "b", "c"}

	changes := myersDiff(left, right)

	if len(changes) != 1 {
		t.Errorf("got %d changes, want 1", len(changes))
	}

	if changes[0].Type != ChangeTypeAdded {
		t.Errorf("change type = %v, want %v", changes[0].Type, ChangeTypeAdded)
	}

	if changes[0].NewValue != "c" {
		t.Errorf("new value = %q, want %q", changes[0].NewValue, "c")
	}
}

func TestMyersDiff_SingleDeletion(t *testing.T) {
	left := []string{"a", "b", "c"}
	right := []string{"a", "b"}

	changes := myersDiff(left, right)

	if len(changes) != 1 {
		t.Errorf("got %d changes, want 1", len(changes))
	}

	if changes[0].Type != ChangeTypeRemoved {
		t.Errorf("change type = %v, want %v", changes[0].Type, ChangeTypeRemoved)
	}

	if changes[0].OldValue != "c" {
		t.Errorf("old value = %q, want %q", changes[0].OldValue, "c")
	}
}

func TestMyersDiff_Replacement(t *testing.T) {
	left := []string{"a", "b", "c"}
	right := []string{"a", "x", "c"}

	changes := myersDiff(left, right)

	// Should be 1 removal and 1 addition
	if len(changes) != 2 {
		t.Errorf("got %d changes, want 2", len(changes))
	}

	// First should be removal of "b"
	if changes[0].Type != ChangeTypeRemoved {
		t.Errorf("first change type = %v, want %v", changes[0].Type, ChangeTypeRemoved)
	}

	// Second should be addition of "x"
	if changes[1].Type != ChangeTypeAdded {
		t.Errorf("second change type = %v, want %v", changes[1].Type, ChangeTypeAdded)
	}
}

func TestMyersDiff_CompletelyDifferent(t *testing.T) {
	left := []string{"a", "b", "c"}
	right := []string{"x", "y", "z"}

	changes := myersDiff(left, right)

	// Should be 3 removals + 3 additions = 6 changes
	if len(changes) != 6 {
		t.Errorf("got %d changes, want 6", len(changes))
	}

	// First 3 should be removals
	for i := 0; i < 3; i++ {
		if changes[i].Type != ChangeTypeRemoved {
			t.Errorf("change %d type = %v, want %v", i, changes[i].Type, ChangeTypeRemoved)
		}
	}

	// Last 3 should be additions
	for i := 3; i < 6; i++ {
		if changes[i].Type != ChangeTypeAdded {
			t.Errorf("change %d type = %v, want %v", i, changes[i].Type, ChangeTypeAdded)
		}
	}
}

func TestMyersDiff_EmptyLeft(t *testing.T) {
	left := []string{}
	right := []string{"a", "b", "c"}

	changes := myersDiff(left, right)

	if len(changes) != 3 {
		t.Errorf("got %d changes, want 3", len(changes))
	}

	for i, change := range changes {
		if change.Type != ChangeTypeAdded {
			t.Errorf("change %d type = %v, want %v", i, change.Type, ChangeTypeAdded)
		}
	}
}

func TestMyersDiff_EmptyRight(t *testing.T) {
	left := []string{"a", "b", "c"}
	right := []string{}

	changes := myersDiff(left, right)

	if len(changes) != 3 {
		t.Errorf("got %d changes, want 3", len(changes))
	}

	for i, change := range changes {
		if change.Type != ChangeTypeRemoved {
			t.Errorf("change %d type = %v, want %v", i, change.Type, ChangeTypeRemoved)
		}
	}
}

func TestMyersDiff_BothEmpty(t *testing.T) {
	left := []string{}
	right := []string{}

	changes := myersDiff(left, right)

	if len(changes) != 0 {
		t.Errorf("got %d changes, want 0", len(changes))
	}
}

func TestMyersDiff_MultipleChanges(t *testing.T) {
	left := []string{"a", "b", "c", "d", "e"}
	right := []string{"a", "x", "c", "y", "e"}

	changes := myersDiff(left, right)

	// Should detect:
	// - "b" removed, "x" added (position 1)
	// - "d" removed, "y" added (position 3)
	// Total: 4 changes

	if len(changes) != 4 {
		t.Errorf("got %d changes, want 4", len(changes))
	}
}

func TestMyersDiff_InsertAtBeginning(t *testing.T) {
	left := []string{"b", "c", "d"}
	right := []string{"a", "b", "c", "d"}

	changes := myersDiff(left, right)

	if len(changes) != 1 {
		t.Errorf("got %d changes, want 1", len(changes))
	}

	if changes[0].Type != ChangeTypeAdded {
		t.Errorf("change type = %v, want %v", changes[0].Type, ChangeTypeAdded)
	}

	if changes[0].NewValue != "a" {
		t.Errorf("new value = %q, want %q", changes[0].NewValue, "a")
	}
}

func TestMyersDiff_DeleteAtBeginning(t *testing.T) {
	left := []string{"a", "b", "c", "d"}
	right := []string{"b", "c", "d"}

	changes := myersDiff(left, right)

	if len(changes) != 1 {
		t.Errorf("got %d changes, want 1", len(changes))
	}

	if changes[0].Type != ChangeTypeRemoved {
		t.Errorf("change type = %v, want %v", changes[0].Type, ChangeTypeRemoved)
	}

	if changes[0].OldValue != "a" {
		t.Errorf("old value = %q, want %q", changes[0].OldValue, "a")
	}
}

func TestMyersDiff_RealWorldExample(t *testing.T) {
	left := []string{
		"function hello() {",
		"  console.log('world');",
		"}",
	}
	right := []string{
		"function hello(name) {",
		"  console.log('Hello, ' + name);",
		"}",
	}

	changes := myersDiff(left, right)

	// Should detect that 2 lines were modified (remove old + add new)
	if len(changes) != 4 {
		t.Errorf("got %d changes, want 4", len(changes))
	}
}

func TestLongestCommonSubsequence(t *testing.T) {
	tests := []struct {
		name  string
		left  []string
		right []string
		want  int
	}{
		{"identical", []string{"a", "b", "c"}, []string{"a", "b", "c"}, 3},
		{"completely different", []string{"a", "b", "c"}, []string{"x", "y", "z"}, 0},
		{"partial match", []string{"a", "b", "c"}, []string{"a", "x", "c"}, 2},
		{"empty left", []string{}, []string{"a", "b"}, 0},
		{"empty right", []string{"a", "b"}, []string{}, 0},
		{"both empty", []string{}, []string{}, 0},
		{"subset", []string{"a", "b", "c", "d"}, []string{"b", "d"}, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := longestCommonSubsequence(tt.left, tt.right)
			if got != tt.want {
				t.Errorf("longestCommonSubsequence() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestMaxMin(t *testing.T) {
	if max(5, 3) != 5 {
		t.Error("max(5, 3) should be 5")
	}
	if max(3, 5) != 5 {
		t.Error("max(3, 5) should be 5")
	}
	if min(5, 3) != 3 {
		t.Error("min(5, 3) should be 3")
	}
	if min(3, 5) != 3 {
		t.Error("min(3, 5) should be 3")
	}
}

func BenchmarkMyersDiff_Small(b *testing.B) {
	left := []string{"a", "b", "c", "d", "e"}
	right := []string{"a", "x", "c", "y", "e"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		myersDiff(left, right)
	}
}

func BenchmarkMyersDiff_Medium(b *testing.B) {
	left := make([]string, 100)
	right := make([]string, 100)

	for i := 0; i < 100; i++ {
		left[i] = string(rune('a' + (i % 26)))
		right[i] = string(rune('a' + ((i + 5) % 26)))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		myersDiff(left, right)
	}
}

func BenchmarkMyersDiff_Large(b *testing.B) {
	left := make([]string, 1000)
	right := make([]string, 1000)

	for i := 0; i < 1000; i++ {
		left[i] = string(rune('a' + (i % 26)))
		right[i] = string(rune('a' + ((i + 10) % 26)))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		myersDiff(left, right)
	}
}
