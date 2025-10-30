package replay

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/RowanDark/0xgen/internal/cases"
	"github.com/RowanDark/0xgen/internal/observability/tracing"
)

// LoadCases reads cases from a JSON file.
func LoadCases(path string) ([]cases.Case, error) {
	return LoadCasesWithContext(context.Background(), path)
}

// LoadCasesWithContext reads cases from a JSON file using the provided context for tracing.
func LoadCasesWithContext(ctx context.Context, path string) ([]cases.Case, error) {
	_, span := tracing.StartSpan(ctx, "replay.load_cases", tracing.WithSpanKind(tracing.SpanKindInternal), tracing.WithAttributes(map[string]any{"oxg.replay.cases_path": strings.TrimSpace(path)}))
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
		span.SetAttribute("oxg.replay.case_count", len(list))
	}
	return list, nil
}

// WriteCases writes the provided cases to disk using deterministic encoding.
type writeCasesConfig struct {
	order []string
}

// WriteCasesOption configures optional behaviour when writing cases.
type WriteCasesOption func(*writeCasesConfig)

// WithCaseOrder preserves the provided ordering when serialising cases.
func WithCaseOrder(order []string) WriteCasesOption {
	clone := append([]string(nil), order...)
	return func(cfg *writeCasesConfig) {
		if len(clone) > 0 {
			cfg.order = clone
		}
	}
}

// WriteCases writes the provided cases to disk using deterministic encoding.
func WriteCases(path string, list []cases.Case, opts ...WriteCasesOption) error {
	return WriteCasesWithContext(context.Background(), path, list, opts...)
}

// WriteCasesWithContext writes cases using the provided context for tracing.
func WriteCasesWithContext(ctx context.Context, path string, list []cases.Case, opts ...WriteCasesOption) error {
	attrs := map[string]any{
		"oxg.replay.cases_path": strings.TrimSpace(path),
		"oxg.replay.case_count": len(list),
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
	cfg := writeCasesConfig{}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	normalised := cloneAndOrderCases(list, cfg.order)
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
	return CasesEqualWithOrder(a, b, nil)
}

// CasesEqualWithOrder compares two case slices using the provided ordering when supplied.
func CasesEqualWithOrder(a, b []cases.Case, order []string) bool {
	normA := cloneAndOrderCases(a, order)
	normB := cloneAndOrderCases(b, order)
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

// OrderCases clones and reorders the provided cases using the supplied ordering.
func OrderCases(list []cases.Case, order []string) []cases.Case {
	return cloneAndOrderCases(list, order)
}

func cloneAndOrderCases(list []cases.Case, order []string) []cases.Case {
	cloned := make([]cases.Case, len(list))
	for i, c := range list {
		cloned[i] = c.Clone()
	}
	if len(order) == 0 {
		sort.SliceStable(cloned, func(i, j int) bool {
			return cloned[i].ID < cloned[j].ID
		})
		return cloned
	}
	index := make(map[string]int, len(order))
	for pos, id := range order {
		trimmed := strings.TrimSpace(id)
		if trimmed == "" {
			continue
		}
		if _, exists := index[trimmed]; !exists {
			index[trimmed] = pos
		}
	}
	sort.SliceStable(cloned, func(i, j int) bool {
		left, okLeft := index[cloned[i].ID]
		right, okRight := index[cloned[j].ID]
		switch {
		case okLeft && okRight:
			if left == right {
				return cloned[i].ID < cloned[j].ID
			}
			return left < right
		case okLeft:
			return true
		case okRight:
			return false
		default:
			return cloned[i].ID < cloned[j].ID
		}
	})
	return cloned
}

// ComputeCaseDigest renders the provided cases and returns a deterministic digest.
func ComputeCaseDigest(list []cases.Case, order []string, algorithm string) (string, error) {
	ordered := cloneAndOrderCases(list, order)
	data, err := json.Marshal(ordered)
	if err != nil {
		return "", fmt.Errorf("encode cases: %w", err)
	}
	digest, err := computeDigest(data, algorithm)
	if err != nil {
		return "", err
	}
	return digest, nil
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
