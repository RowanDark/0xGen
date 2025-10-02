package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/RowanDark/Glyph/internal/cases"
	"github.com/RowanDark/Glyph/internal/exporter"
	"github.com/RowanDark/Glyph/internal/reporter"
)

func runExport(args []string) int {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	input := fs.String("input", reporter.DefaultFindingsPath, "path to findings JSONL input")
	out := fs.String("out", "", "path to write the exported output")
	formatRaw := fs.String("format", "", "export format (sarif or jsonl)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if strings.TrimSpace(*formatRaw) == "" {
		fmt.Fprintln(os.Stderr, "--format is required")
		return 2
	}
	format, err := exporter.ParseFormat(*formatRaw)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	inputPath := strings.TrimSpace(*input)
	if inputPath == "" {
		fmt.Fprintln(os.Stderr, "--input must be provided")
		return 2
	}

	findingsList, err := reporter.ReadJSONL(inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load findings: %v\n", err)
		return 1
	}

	builder := cases.NewBuilder()
	casesList, err := builder.Build(context.Background(), findingsList)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build cases: %v\n", err)
		return 1
	}

	outputPath := strings.TrimSpace(*out)
	if outputPath == "" {
		switch format {
		case exporter.FormatSARIF:
			outputPath = exporter.DefaultSARIFPath
		case exporter.FormatJSONL:
			outputPath = exporter.DefaultJSONLPath
		default:
			outputPath = exporter.DefaultJSONLPath
		}
	}

	var data []byte
	switch format {
	case exporter.FormatSARIF:
		data, err = exporter.EncodeSARIF(casesList)
	case exporter.FormatJSONL:
		telemetry := exporter.BuildTelemetry(casesList, len(findingsList))
		data, err = exporter.EncodeJSONL(casesList, telemetry)
	default:
		err = fmt.Errorf("unsupported format: %s", format)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "encode export: %v\n", err)
		return 1
	}

	if err := ensureParentDir(outputPath); err != nil {
		fmt.Fprintf(os.Stderr, "create output directory: %v\n", err)
		return 1
	}
	if err := os.WriteFile(outputPath, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write export: %v\n", err)
		return 1
	}

	fmt.Fprintf(os.Stdout, "exported %d case(s) to %s\n", len(casesList), outputPath)
	return 0
}

func ensureParentDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		return nil
	}
	return os.MkdirAll(dir, 0o755)
}
