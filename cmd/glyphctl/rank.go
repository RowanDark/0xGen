package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/RowanDark/Glyph/internal/ranker"
	"github.com/RowanDark/Glyph/internal/reporter"
)

func runRank(args []string) int {
	fs := flag.NewFlagSet("rank", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	input := fs.String("input", reporter.DefaultFindingsPath, "path to findings JSONL input")
	output := fs.String("out", ranker.DefaultOutputPath, "path to write the ranked JSONL output")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	in := strings.TrimSpace(*input)
	out := strings.TrimSpace(*output)
	if in == "" || out == "" {
		fmt.Fprintln(os.Stderr, "--input and --out must be provided")
		return 2
	}

	findings, err := reporter.ReadJSONL(in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load findings: %v\n", err)
		return 1
	}

	ranked := ranker.Rank(findings)
	if err := ranker.WriteJSONL(out, ranked); err != nil {
		fmt.Fprintf(os.Stderr, "write ranked findings: %v\n", err)
		return 1
	}

	return 0
}
