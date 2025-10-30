package replay

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/RowanDark/0xgen/internal/findings"
	"github.com/RowanDark/0xgen/internal/observability/tracing"
)

// OrderFindings clones and reorders the findings according to the provided sequence.
func OrderFindings(list []findings.Finding, order []string) []findings.Finding {
	return cloneAndOrderFindings(list, order)
}

func cloneAndOrderFindings(list []findings.Finding, order []string) []findings.Finding {
	cloned := make([]findings.Finding, len(list))
	for i, f := range list {
		cloned[i] = f.Clone()
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

// ComputeFindingsDigest renders the findings and returns a deterministic digest.
func ComputeFindingsDigest(list []findings.Finding, order []string, algorithm string) (string, error) {
	ordered := cloneAndOrderFindings(list, order)
	data, err := json.Marshal(ordered)
	if err != nil {
		return "", fmt.Errorf("encode findings: %w", err)
	}
	digest, err := computeDigest(data, algorithm)
	if err != nil {
		return "", err
	}
	return digest, nil
}

// WriteFindings persists the findings to a JSONL file using deterministic ordering.
func WriteFindings(path string, list []findings.Finding) error {
	return WriteFindingsWithContext(context.Background(), path, list)
}

// WriteFindingsWithContext writes findings using the provided context for tracing.
func WriteFindingsWithContext(ctx context.Context, path string, list []findings.Finding) error {
	attrs := map[string]any{
		"oxg.replay.findings_path": strings.TrimSpace(path),
		"oxg.replay.finding_count": len(list),
	}
	_, span := tracing.StartSpan(ctx, "replay.write_findings", tracing.WithSpanKind(tracing.SpanKindInternal), tracing.WithAttributes(attrs))
	status := tracing.StatusOK
	statusMsg := ""
	defer func() {
		if span != nil {
			span.EndWithStatus(status, statusMsg)
		}
	}()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		if span != nil {
			span.RecordError(err)
		}
		status = tracing.StatusError
		statusMsg = "create findings directory"
		return fmt.Errorf("create findings directory: %w", err)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		if span != nil {
			span.RecordError(err)
		}
		status = tracing.StatusError
		statusMsg = "remove existing findings"
		return fmt.Errorf("remove existing findings: %w", err)
	}

	writer := findings.NewWriter(path, findings.WithMaxBytes(0))
	if writer == nil {
		status = tracing.StatusError
		statusMsg = "create findings writer"
		return fmt.Errorf("create findings writer: nil writer")
	}
	defer func() {
		if err := writer.Close(); err != nil && status == tracing.StatusOK {
			status = tracing.StatusError
			statusMsg = "close findings writer"
			if span != nil {
				span.RecordError(err)
			}
		}
	}()

	for _, f := range list {
		if err := writer.Write(f.Clone()); err != nil {
			if span != nil {
				span.RecordError(err)
			}
			status = tracing.StatusError
			statusMsg = "write finding"
			return fmt.Errorf("write finding: %w", err)
		}
	}
	return nil
}
