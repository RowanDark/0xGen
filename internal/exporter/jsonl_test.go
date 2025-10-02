package exporter

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/RowanDark/Glyph/internal/cases"
	"github.com/RowanDark/Glyph/internal/findings"
)

func TestEncodeJSONLIncludesTelemetryAndCases(t *testing.T) {
	findingsList := loadSampleFindings(t)

	builder := cases.NewBuilder(
		cases.WithDeterministicMode(5150),
		cases.WithClock(func() time.Time { return time.Unix(1700009000, 0).UTC() }),
	)

	casesList, err := builder.Build(context.Background(), findingsList)
	if err != nil {
		t.Fatalf("build cases: %v", err)
	}
	if len(casesList) == 0 {
		t.Fatalf("expected sample fixture to produce cases")
	}

	telemetry := BuildTelemetry(casesList, len(findingsList))
	data, err := EncodeJSONL(casesList, telemetry)
	if err != nil {
		t.Fatalf("encode jsonl: %v", err)
	}

	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if got, want := len(lines), len(casesList)+1; got != want {
		t.Fatalf("expected %d JSONL entries, got %d", want, got)
	}

	var telemetryEntry map[string]any
	if err := json.Unmarshal(lines[0], &telemetryEntry); err != nil {
		t.Fatalf("unmarshal telemetry entry: %v", err)
	}
	if telemetryEntry["type"] != "telemetry" {
		t.Fatalf("expected telemetry entry, got %v", telemetryEntry["type"])
	}
	rawTelemetry, ok := telemetryEntry["telemetry"].(map[string]any)
	if !ok {
		t.Fatalf("telemetry payload missing: %#v", telemetryEntry)
	}
	if rawTelemetry["case_count"].(float64) != float64(len(casesList)) {
		t.Fatalf("unexpected case_count: %#v", rawTelemetry["case_count"])
	}
	if rawTelemetry["finding_count"].(float64) != float64(len(findingsList)) {
		t.Fatalf("unexpected finding_count: %#v", rawTelemetry["finding_count"])
	}
	severityCounts, ok := rawTelemetry["severity_counts"].(map[string]any)
	if !ok {
		t.Fatalf("severity_counts missing: %#v", rawTelemetry)
	}
	for _, key := range []string{"crit", "high", "med", "low", "info"} {
		if _, exists := severityCounts[key]; !exists {
			t.Fatalf("severity key %q missing", key)
		}
	}
	pluginCounts, ok := rawTelemetry["plugin_counts"].(map[string]any)
	if !ok || len(pluginCounts) == 0 {
		t.Fatalf("plugin_counts missing: %#v", rawTelemetry)
	}

	for idx, line := range lines[1:] {
		var entry map[string]any
		if err := json.Unmarshal(line, &entry); err != nil {
			t.Fatalf("unmarshal case entry %d: %v", idx, err)
		}
		if entry["type"] != "case" {
			t.Fatalf("expected case entry, got %v", entry["type"])
		}
		metrics, ok := entry["metrics"].(map[string]any)
		if !ok {
			t.Fatalf("case metrics missing: %#v", entry)
		}
		casePayload, ok := entry["case"]
		if !ok {
			t.Fatalf("case payload missing: %#v", entry)
		}
		buf, err := json.Marshal(casePayload)
		if err != nil {
			t.Fatalf("marshal case payload: %v", err)
		}
		var decoded cases.Case
		if err := json.Unmarshal(buf, &decoded); err != nil {
			t.Fatalf("unmarshal case payload: %v", err)
		}
		if decoded.ID == "" {
			t.Fatalf("case id missing")
		}
		if decoded.Risk.Severity == "" {
			t.Fatalf("risk severity missing")
		}
		if got := int(metrics["source_count"].(float64)); got != len(decoded.Sources) {
			t.Fatalf("source_count mismatch: got %d want %d", got, len(decoded.Sources))
		}
		if got := int(metrics["evidence_count"].(float64)); got != len(decoded.Evidence) {
			t.Fatalf("evidence_count mismatch: got %d want %d", got, len(decoded.Evidence))
		}
	}
}

func loadSampleFindings(t *testing.T) []findings.Finding {
	t.Helper()
	path := filepath.Join("..", "cases", "testdata", "sample_web_service_findings.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fs []findings.Finding
	if err := json.Unmarshal(data, &fs); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	return fs
}
