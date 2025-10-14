package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/RowanDark/0xgen/internal/history"
)

func runHistorySearch(args []string) int {
	fs := flag.NewFlagSet("history search", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	historyPath := fs.String("history", history.DefaultPath(), "path to the proxy history JSONL log")
	query := fs.String("q", "", "search query (e.g. host:example.com method:POST)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	idx, err := history.Load(*historyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load history: %v\n", err)
		return 1
	}

	results, err := idx.Search(*query)
	if err != nil {
		fmt.Fprintf(os.Stderr, "search history: %v\n", err)
		return 1
	}

	for _, result := range results {
		fmt.Fprintln(os.Stdout, strings.TrimSpace(result.ID))
	}

	return 0
}
