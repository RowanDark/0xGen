package exporter

import (
	"context"
	"encoding/csv"
	"strings"
	"testing"
	"time"

	"github.com/RowanDark/0xgen/internal/cases"
)

func TestEncodeCSVIncludesHeaderAndRows(t *testing.T) {
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
		t.Fatalf("expected fixture to produce cases")
	}

	data, err := EncodeCSV(casesList)
	if err != nil {
		t.Fatalf("encode csv: %v", err)
	}

	reader := csv.NewReader(strings.NewReader(string(data)))
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}

	if got, want := len(records), len(casesList)+1; got != want {
		t.Fatalf("expected %d records, got %d", want, got)
	}

	header := records[0]
	if len(header) != len(csvHeader) {
		t.Fatalf("unexpected header length: got %d want %d", len(header), len(csvHeader))
	}
	for i, field := range header {
		if field != csvHeader[i] {
			t.Fatalf("unexpected header field %d: got %q want %q", i, field, csvHeader[i])
		}
	}

	first := records[1]
	if got := first[0]; strings.TrimSpace(got) == "" {
		t.Fatalf("case id missing: %#v", first)
	}
	if got := first[8]; strings.TrimSpace(got) == "" {
		t.Fatalf("severity missing: %#v", first)
	}
	if got := first[16]; strings.TrimSpace(got) == "" {
		t.Fatalf("source plugins missing: %#v", first)
	}
}
