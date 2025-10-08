package exporter

import (
	"os"
	"path/filepath"
	"strings"
)

const (
	defaultOutputDir = "/out"
	sarifFilename    = "cases.sarif"
	jsonlFilename    = "cases.jsonl"
	csvFilename      = "cases.csv"
)

// Format identifies the supported export encodings.
type Format string

const (
	// FormatSARIF renders cases in SARIF 2.1.0.
	FormatSARIF Format = "sarif"
	// FormatJSONL renders telemetry and cases as newline-delimited JSON objects.
	FormatJSONL Format = "jsonl"
	// FormatCSV renders a tabular summary of cases.
	FormatCSV Format = "csv"
)

var (
	// DefaultSARIFPath is where the SARIF export is written when no --out flag is provided.
	DefaultSARIFPath = filepath.Join(defaultOutputDir, sarifFilename)
	// DefaultJSONLPath is where the JSONL export is written when no --out flag is provided.
	DefaultJSONLPath = filepath.Join(defaultOutputDir, jsonlFilename)
	// DefaultCSVPath is where the CSV export is written when no --out flag is provided.
	DefaultCSVPath = filepath.Join(defaultOutputDir, csvFilename)
)

func init() {
	base := strings.TrimSpace(os.Getenv("GLYPH_OUT"))
	if base == "" {
		base = defaultOutputDir
	}

	DefaultSARIFPath = filepath.Join(base, sarifFilename)
	DefaultJSONLPath = filepath.Join(base, jsonlFilename)
	DefaultCSVPath = filepath.Join(base, csvFilename)
	setBaseOutput(base)

	MustRegisterFormat(FormatSpec{
		Format:          FormatSARIF,
		DefaultFilename: sarifFilename,
		Description:     "SARIF 2.1.0 security findings log",
		Encode: func(req Request) ([]byte, error) {
			return EncodeSARIF(req.Cases)
		},
	})

	MustRegisterFormat(FormatSpec{
		Format:          FormatJSONL,
		DefaultFilename: jsonlFilename,
		Description:     "JSON Lines export containing telemetry and cases",
		Encode: func(req Request) ([]byte, error) {
			return EncodeJSONL(req.Cases, req.Telemetry)
		},
	})

	MustRegisterFormat(FormatSpec{
		Format:          FormatCSV,
		DefaultFilename: csvFilename,
		Description:     "CSV summary of cases for spreadsheet workflows",
		Encode: func(req Request) ([]byte, error) {
			return EncodeCSV(req.Cases)
		},
	})
}
