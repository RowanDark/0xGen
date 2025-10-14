package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/RowanDark/0xgen/internal/findings"
	"github.com/RowanDark/0xgen/internal/reporter"
	"github.com/RowanDark/0xgen/internal/seer"
)

func main() {
	htmlPath := flag.String("html", "", "path to HTML content to scan")
	outPath := flag.String("out", reporter.DefaultFindingsPath, "output findings JSONL path")
	target := flag.String("target", "http://example.com", "target label for findings")
	flag.Parse()

	path := strings.TrimSpace(*htmlPath)
	if path == "" {
		fmt.Fprintln(os.Stderr, "--html is required")
		os.Exit(2)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read html: %v\n", err)
		os.Exit(1)
	}

	targetLabel := strings.TrimSpace(*target)
	if targetLabel == "" {
		targetLabel = "http://example.com"
	}

	cfg := seer.Config{Now: func() time.Time { return time.Now().UTC() }}
	findingsList := seer.Scan(targetLabel, string(data), cfg)
	if len(findingsList) == 0 {
		fmt.Fprintln(os.Stdout, "no findings detected; nothing to seed")
		return
	}

	outputPath := strings.TrimSpace(*outPath)
	if outputPath == "" {
		outputPath = reporter.DefaultFindingsPath
	}

	writer := findings.NewWriter(outputPath)
	for _, entry := range findingsList {
		if err := writer.Write(entry); err != nil {
			fmt.Fprintf(os.Stderr, "write finding: %v\n", err)
			os.Exit(1)
		}
	}
	if err := writer.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "flush findings: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stdout, "seeded %d findings\n", len(findingsList))
}
