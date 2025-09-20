package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/RowanDark/Glyph/internal/reporter"
)

func runReport(args []string) int {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	input := fs.String("input", reporter.DefaultFindingsPath, "path to findings JSONL input")
	output := fs.String("out", reporter.DefaultReportPath, "path to write the markdown report")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *input == "" || *output == "" {
		fmt.Fprintln(os.Stderr, "--input and --out must be provided")
		return 2
	}

	if err := reporter.RenderReport(*input, *output); err != nil {
		fmt.Fprintf(os.Stderr, "generate report: %v\n", err)
		return 1
	}

	return 0
}
