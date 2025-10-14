package exporter

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/RowanDark/0xgen/internal/cases"
)

func TestEncodeSARIFProducesStructuredLog(t *testing.T) {
	findingsList := loadSampleFindings(t)
	builder := cases.NewBuilder(
		cases.WithDeterministicMode(5150),
		cases.WithClock(func() time.Time { return time.Unix(1700009000, 0).UTC() }),
	)

	casesList, err := builder.Build(context.Background(), findingsList)
	if err != nil {
		t.Fatalf("build cases: %v", err)
	}

	data, err := EncodeSARIF(casesList)
	if err != nil {
		t.Fatalf("encode sarif: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal sarif: %v", err)
	}
	if doc["version"] != "2.1.0" {
		t.Fatalf("unexpected SARIF version: %v", doc["version"])
	}

	runs, ok := doc["runs"].([]any)
	if !ok || len(runs) == 0 {
		t.Fatalf("runs missing in SARIF output")
	}
	run, ok := runs[0].(map[string]any)
	if !ok {
		t.Fatalf("first run malformed: %#v", runs[0])
	}
	tool, ok := run["tool"].(map[string]any)
	if !ok {
		t.Fatalf("tool missing: %#v", run)
	}
	driver, ok := tool["driver"].(map[string]any)
	if !ok {
		t.Fatalf("driver missing: %#v", tool)
	}
	if driver["name"] != "Glyph" {
		t.Fatalf("unexpected driver name: %v", driver["name"])
	}

	rules, ok := driver["rules"].([]any)
	if !ok || len(rules) != len(casesList) {
		t.Fatalf("rules mismatch: got %d want %d", len(rules), len(casesList))
	}

	results, ok := run["results"].([]any)
	if !ok || len(results) != len(casesList) {
		t.Fatalf("results mismatch: got %d want %d", len(results), len(casesList))
	}

	firstResult, ok := results[0].(map[string]any)
	if !ok {
		t.Fatalf("first result malformed: %#v", results[0])
	}
	if firstResult["level"] == "" {
		t.Fatalf("result level missing")
	}
	message, ok := firstResult["message"].(map[string]any)
	if !ok || strings.TrimSpace(message["text"].(string)) == "" {
		t.Fatalf("result message missing: %#v", firstResult)
	}
	if _, ok := firstResult["partialFingerprints"].(map[string]any); !ok {
		t.Fatalf("partialFingerprints missing")
	}
	if fixes, ok := firstResult["fixes"].([]any); !ok || len(fixes) == 0 {
		t.Fatalf("expected remediation fixes in SARIF result")
	}
}

func TestEncodeSARIFEmptyCases(t *testing.T) {
	data, err := EncodeSARIF(nil)
	if err != nil {
		t.Fatalf("encode sarif: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal sarif: %v", err)
	}
	runs, ok := doc["runs"].([]any)
	if !ok || len(runs) == 0 {
		t.Fatalf("expected at least one run in SARIF output")
	}
}
