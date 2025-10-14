package replay

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/RowanDark/0xgen/internal/observability/tracing"
)

// FlowRecord captures a sanitized proxy flow suitable for replay.
// TimestampUnix is recorded in seconds since the Unix epoch to keep the log compact.
type FlowRecord struct {
	ID                string `json:"id"`
	Sequence          uint64 `json:"sequence"`
	Type              string `json:"type"`
	TimestampUnix     int64  `json:"timestamp_unix"`
	SanitizedBase64   string `json:"sanitized_base64,omitempty"`
	RawBodyBytes      int    `json:"raw_body_bytes,omitempty"`
	RawBodyCaptured   int    `json:"raw_body_captured,omitempty"`
	SanitizedRedacted bool   `json:"sanitized_redacted,omitempty"`
}

// LoadFlows reads flow records from a JSONL file.
func LoadFlows(path string) ([]FlowRecord, error) {
	return LoadFlowsWithContext(context.Background(), path)
}

// LoadFlowsWithContext reads flow records from a JSONL file using the provided context for tracing.
func LoadFlowsWithContext(ctx context.Context, path string) ([]FlowRecord, error) {
	attrs := map[string]any{"glyph.replay.flows_path": strings.TrimSpace(path)}
	_, span := tracing.StartSpan(ctx, "replay.load_flows", tracing.WithSpanKind(tracing.SpanKindInternal), tracing.WithAttributes(attrs))
	status := tracing.StatusOK
	statusMsg := ""
	defer func() {
		if span != nil {
			span.EndWithStatus(status, statusMsg)
		}
	}()

	file, err := os.Open(path)
	if err != nil {
		if span != nil {
			span.RecordError(err)
		}
		status = tracing.StatusError
		statusMsg = "open flows"
		return nil, fmt.Errorf("open flows: %w", err)
	}
	defer file.Close()

	var records []FlowRecord
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var record FlowRecord
		if err := json.Unmarshal(line, &record); err != nil {
			if span != nil {
				span.RecordError(err)
			}
			status = tracing.StatusError
			statusMsg = "decode flow record"
			return nil, fmt.Errorf("decode flow record: %w", err)
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		if span != nil {
			span.RecordError(err)
		}
		status = tracing.StatusError
		statusMsg = "scan flows"
		return nil, fmt.Errorf("scan flows: %w", err)
	}
	sort.SliceStable(records, func(i, j int) bool {
		if records[i].Sequence == records[j].Sequence {
			return records[i].ID < records[j].ID
		}
		return records[i].Sequence < records[j].Sequence
	})
	if span != nil {
		span.SetAttribute("glyph.replay.flow_records", len(records))
	}
	return records, nil
}

// WriteFlows persists the provided flow records as JSONL.
func WriteFlows(path string, flows []FlowRecord) error {
	return WriteFlowsWithContext(context.Background(), path, flows)
}

// WriteFlowsWithContext persists flow records using the provided context for tracing.
func WriteFlowsWithContext(ctx context.Context, path string, flows []FlowRecord) error {
	attrs := map[string]any{
		"glyph.replay.flows_path":   strings.TrimSpace(path),
		"glyph.replay.flow_records": len(flows),
	}
	_, span := tracing.StartSpan(ctx, "replay.write_flows", tracing.WithSpanKind(tracing.SpanKindInternal), tracing.WithAttributes(attrs))
	status := tracing.StatusOK
	statusMsg := ""
	defer func() {
		if span != nil {
			span.EndWithStatus(status, statusMsg)
		}
	}()

	if strings.TrimSpace(path) == "" {
		err := errors.New("flow output path required")
		if span != nil {
			span.RecordError(err)
		}
		status = tracing.StatusError
		statusMsg = "missing path"
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		if span != nil {
			span.RecordError(err)
		}
		status = tracing.StatusError
		statusMsg = "create flow directory"
		return fmt.Errorf("create flow directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		if span != nil {
			span.RecordError(err)
		}
		status = tracing.StatusError
		statusMsg = "open flow output"
		return fmt.Errorf("open flow output: %w", err)
	}
	defer file.Close()

	sorted := make([]FlowRecord, len(flows))
	copy(sorted, flows)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Sequence == sorted[j].Sequence {
			return sorted[i].ID < sorted[j].ID
		}
		return sorted[i].Sequence < sorted[j].Sequence
	})

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	for _, record := range sorted {
		data, err := json.Marshal(record)
		if err != nil {
			if span != nil {
				span.RecordError(err)
			}
			status = tracing.StatusError
			statusMsg = "encode flow record"
			return fmt.Errorf("encode flow record: %w", err)
		}
		if _, err := writer.Write(data); err != nil {
			if span != nil {
				span.RecordError(err)
			}
			status = tracing.StatusError
			statusMsg = "write flow record"
			return fmt.Errorf("write flow record: %w", err)
		}
		if err := writer.WriteByte('\n'); err != nil {
			if span != nil {
				span.RecordError(err)
			}
			status = tracing.StatusError
			statusMsg = "write newline"
			return fmt.Errorf("write newline: %w", err)
		}
	}
	if err := writer.Flush(); err != nil {
		if span != nil {
			span.RecordError(err)
		}
		status = tracing.StatusError
		statusMsg = "flush flow writer"
		return err
	}
	return nil
}
