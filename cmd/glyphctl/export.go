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
	formats := exporter.Formats()
	names := make([]string, 0, len(formats))
	for _, spec := range formats {
		names = append(names, string(spec.Format))
	}
	formatHelp := "export format"
	if len(names) > 0 {
		formatHelp = fmt.Sprintf("export format (%s)", strings.Join(names, ", "))
	}
	formatRaw := fs.String("format", "", formatHelp)
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

	telemetry := exporter.BuildTelemetry(casesList, len(findingsList))
	req := exporter.Request{Cases: casesList, Findings: findingsList, Telemetry: telemetry}

	outputPath := strings.TrimSpace(*out)
	if outputPath == "" {
		if path, err := exporter.DefaultPath(format); err == nil {
			outputPath = path
		} else {
			fmt.Fprintf(os.Stderr, "--out is required for format %s (%v)\n", format, err)
			return 2
		}
	}

	data, err := exporter.Encode(format, req)
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
