package replay

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
	file, err := os.Open(path)
	if err != nil {
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
			return nil, fmt.Errorf("decode flow record: %w", err)
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan flows: %w", err)
	}
	sort.SliceStable(records, func(i, j int) bool {
		if records[i].Sequence == records[j].Sequence {
			return records[i].ID < records[j].ID
		}
		return records[i].Sequence < records[j].Sequence
	})
	return records, nil
}

// WriteFlows persists the provided flow records as JSONL.
func WriteFlows(path string, flows []FlowRecord) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("flow output path required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create flow directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
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
			return fmt.Errorf("encode flow record: %w", err)
		}
		if _, err := writer.Write(data); err != nil {
			return fmt.Errorf("write flow record: %w", err)
		}
		if err := writer.WriteByte('\n'); err != nil {
			return fmt.Errorf("write newline: %w", err)
		}
	}
	return writer.Flush()
}
