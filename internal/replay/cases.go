package replay

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/RowanDark/Glyph/internal/cases"
)

// LoadCases reads cases from a JSON file.
func LoadCases(path string) ([]cases.Case, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read cases: %w", err)
	}
	var list []cases.Case
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("decode cases: %w", err)
	}
	return list, nil
}

// WriteCases writes the provided cases to disk using deterministic encoding.
func WriteCases(path string, list []cases.Case) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create cases directory: %w", err)
	}
	normalised := cloneAndSortCases(list)
	data, err := json.MarshalIndent(normalised, "", "  ")
	if err != nil {
		return fmt.Errorf("encode cases: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write cases: %w", err)
	}
	return nil
}

// CasesEqual compares two case slices after normalising ordering.
func CasesEqual(a, b []cases.Case) bool {
	normA := cloneAndSortCases(a)
	normB := cloneAndSortCases(b)
	if len(normA) != len(normB) {
		return false
	}
	for i := range normA {
		if !casesEqual(normA[i], normB[i]) {
			return false
		}
	}
	return true
}

func cloneAndSortCases(list []cases.Case) []cases.Case {
	cloned := make([]cases.Case, len(list))
	for i, c := range list {
		cloned[i] = c.Clone()
	}
	sort.SliceStable(cloned, func(i, j int) bool {
		return cloned[i].ID < cloned[j].ID
	})
	return cloned
}

func casesEqual(a, b cases.Case) bool {
	dataA, err := json.Marshal(a)
	if err != nil {
		return false
	}
	dataB, err := json.Marshal(b)
	if err != nil {
		return false
	}
	return string(dataA) == string(dataB)
}
