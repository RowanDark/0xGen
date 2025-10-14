package exporter

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/RowanDark/0xgen/internal/cases"
)

type jsonlEntry struct {
	Type      string       `json:"type"`
	Telemetry *Telemetry   `json:"telemetry,omitempty"`
	Case      *cases.Case  `json:"case,omitempty"`
	Metrics   *CaseMetrics `json:"metrics,omitempty"`
}

// EncodeJSONL renders the telemetry snapshot followed by individual case entries as JSONL.
func EncodeJSONL(casesList []cases.Case, telemetry Telemetry) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)

	if err := encoder.Encode(jsonlEntry{Type: "telemetry", Telemetry: &telemetry}); err != nil {
		return nil, fmt.Errorf("encode telemetry entry: %w", err)
	}

	for _, c := range casesList {
		clone := c.Clone()
		metrics := CaseMetrics{SourceCount: len(clone.Sources), EvidenceCount: len(clone.Evidence)}
		entry := jsonlEntry{Type: "case", Case: &clone, Metrics: &metrics}
		if err := encoder.Encode(entry); err != nil {
			return nil, fmt.Errorf("encode case entry %s: %w", clone.ID, err)
		}
	}

	return buf.Bytes(), nil
}
