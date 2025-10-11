package replay

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/RowanDark/Glyph/internal/cases"
	"github.com/RowanDark/Glyph/internal/observability/tracing"
)

// LoadCases reads cases from a JSON file.
func LoadCases(path string) ([]cases.Case, error) {
	return LoadCasesWithContext(context.Background(), path)
}

// LoadCasesWithContext reads cases from a JSON file using the provided context for tracing.
func LoadCasesWithContext(ctx context.Context, path string) ([]cases.Case, error) {
	_, span := tracing.StartSpan(ctx, "replay.load_cases", tracing.WithSpanKind(tracing.SpanKindInternal), tracing.WithAttributes(map[string]any{"glyph.replay.cases_path": strings.TrimSpace(path)}))
	status := tracing.StatusOK
	statusMsg := ""
	defer func() {
		if span != nil {
			span.EndWithStatus(status, statusMsg)
		}
	}()

	data, err := os.ReadFile(path)
	if err != nil {
		if span != nil {
			span.RecordError(err)
		}
		status = tracing.StatusError
		statusMsg = "read cases"
		return nil, fmt.Errorf("read cases: %w", err)
	}
	var list []cases.Case
	if err := json.Unmarshal(data, &list); err != nil {
		if span != nil {
			span.RecordError(err)
		}
		status = tracing.StatusError
		statusMsg = "decode cases"
		return nil, fmt.Errorf("decode cases: %w", err)
	}
	if span != nil {
		span.SetAttribute("glyph.replay.case_count", len(list))
	}
	return list, nil
}

// WriteCases writes the provided cases to disk using deterministic encoding.
func WriteCases(path string, list []cases.Case) error {
	return WriteCasesWithContext(context.Background(), path, list)
}

// WriteCasesWithContext writes cases using the provided context for tracing.
func WriteCasesWithContext(ctx context.Context, path string, list []cases.Case) error {
	attrs := map[string]any{
		"glyph.replay.cases_path": strings.TrimSpace(path),
		"glyph.replay.case_count": len(list),
	}
	_, span := tracing.StartSpan(ctx, "replay.write_cases", tracing.WithSpanKind(tracing.SpanKindInternal), tracing.WithAttributes(attrs))
	status := tracing.StatusOK
	statusMsg := ""
	defer func() {
		if span != nil {
			span.EndWithStatus(status, statusMsg)
		}
	}()

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		if span != nil {
			span.RecordError(err)
		}
		status = tracing.StatusError
		statusMsg = "create cases directory"
		return fmt.Errorf("create cases directory: %w", err)
	}
	normalised := cloneAndSortCases(list)
	data, err := json.MarshalIndent(normalised, "", "  ")
	if err != nil {
		if span != nil {
			span.RecordError(err)
		}
		status = tracing.StatusError
		statusMsg = "encode cases"
		return fmt.Errorf("encode cases: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		if span != nil {
			span.RecordError(err)
		}
		status = tracing.StatusError
		statusMsg = "write cases"
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
