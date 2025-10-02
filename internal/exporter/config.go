package exporter

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	defaultOutputDir = "/out"
	sarifFilename    = "cases.sarif"
	jsonlFilename    = "cases.jsonl"
)

// Format identifies the supported export encodings.
type Format string

const (
	// FormatSARIF renders cases in SARIF 2.1.0.
	FormatSARIF Format = "sarif"
	// FormatJSONL renders telemetry and cases as newline-delimited JSON objects.
	FormatJSONL Format = "jsonl"
)

var (
	// DefaultSARIFPath is where the SARIF export is written when no --out flag is provided.
	DefaultSARIFPath = filepath.Join(defaultOutputDir, sarifFilename)
	// DefaultJSONLPath is where the JSONL export is written when no --out flag is provided.
	DefaultJSONLPath = filepath.Join(defaultOutputDir, jsonlFilename)
)

func init() {
	if custom := strings.TrimSpace(os.Getenv("GLYPH_OUT")); custom != "" {
		DefaultSARIFPath = filepath.Join(custom, sarifFilename)
		DefaultJSONLPath = filepath.Join(custom, jsonlFilename)
	}
}

// ParseFormat validates the provided format string.
func ParseFormat(raw string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case string(FormatSARIF):
		return FormatSARIF, nil
	case string(FormatJSONL):
		return FormatJSONL, nil
	default:
		return "", fmt.Errorf("unsupported format %q (expected sarif or jsonl)", raw)
	}
}
