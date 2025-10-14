package exporter

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/RowanDark/0xgen/internal/cases"
)

var csvHeader = []string{
	"case_id",
	"case_version",
	"generated_at",
	"asset_kind",
	"asset_identifier",
	"asset_details",
	"vector_kind",
	"vector_value",
	"severity",
	"risk_score",
	"risk_rationale",
	"confidence",
	"summary",
	"proof_summary",
	"labels",
	"source_ids",
	"source_plugins",
	"source_types",
	"source_count",
	"evidence_count",
}

// EncodeCSV renders cases as comma-separated values suitable for spreadsheets.
func EncodeCSV(casesList []cases.Case) ([]byte, error) {
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	if err := writer.Write(csvHeader); err != nil {
		return nil, fmt.Errorf("write csv header: %w", err)
	}

	for _, c := range casesList {
		if err := writer.Write(serialiseCase(c)); err != nil {
			return nil, fmt.Errorf("write case %s: %w", c.ID, err)
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, fmt.Errorf("flush csv writer: %w", err)
	}
	return buf.Bytes(), nil
}

func serialiseCase(c cases.Case) []string {
	generatedAt := ""
	if ts := c.GeneratedAt.Time(); !ts.IsZero() {
		generatedAt = ts.UTC().Format(time.RFC3339)
	}

	labels := flattenMap(c.Labels)
	sourceIDs := make([]string, 0, len(c.Sources))
	sourcePlugins := make([]string, 0, len(c.Sources))
	sourceTypes := make([]string, 0, len(c.Sources))
	for _, src := range c.Sources {
		if src.ID != "" {
			sourceIDs = append(sourceIDs, src.ID)
		}
		if src.Plugin != "" {
			sourcePlugins = append(sourcePlugins, src.Plugin)
		}
		if src.Type != "" {
			sourceTypes = append(sourceTypes, src.Type)
		}
	}

	summary := strings.TrimSpace(c.Summary)
	proofSummary := strings.TrimSpace(c.Proof.Summary)

	return []string{
		c.ID,
		c.Version,
		generatedAt,
		strings.TrimSpace(c.Asset.Kind),
		strings.TrimSpace(c.Asset.Identifier),
		strings.TrimSpace(c.Asset.Details),
		strings.TrimSpace(c.Vector.Kind),
		strings.TrimSpace(c.Vector.Value),
		string(c.Risk.Severity),
		formatFloat(c.Risk.Score),
		strings.TrimSpace(c.Risk.Rationale),
		formatFloat(c.Confidence),
		summary,
		proofSummary,
		labels,
		strings.Join(sourceIDs, ";"),
		strings.Join(sourcePlugins, ";"),
		strings.Join(sourceTypes, ";"),
		strconv.Itoa(len(c.Sources)),
		strconv.Itoa(len(c.Evidence)),
	}
}

func flattenMap(values map[string]string) string {
	if len(values) == 0 {
		return ""
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	pairs := make([]string, 0, len(values))
	for _, key := range keys {
		pairs = append(pairs, fmt.Sprintf("%s=%s", key, values[key]))
	}
	return strings.Join(pairs, ";")
}

func formatFloat(value float64) string {
	if value == 0 {
		return "0"
	}
	return strconv.FormatFloat(value, 'f', -1, 64)
}
