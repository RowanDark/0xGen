package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/RowanDark/Glyph/internal/osintwell"
)

func runOSINTWell(args []string) int {
	fs := flag.NewFlagSet("osint-well", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	domain := fs.String("domain", "", "domain to enumerate using Amass")
	output := fs.String("out", osintwell.DefaultOutputPath, "path to the assets JSONL output")
	binary := fs.String("binary", "amass", "path to the amass binary")
	extra := fs.String("args", "", "additional flags to pass to amass (space separated)")
	label := fs.String("label", osintwell.DefaultToolLabel, "tool label recorded in the output")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*domain) == "" {
		fmt.Fprintln(os.Stderr, "--domain must be provided")
		return 2
	}

	extraArgs := splitArgs(*extra)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cfg := osintwell.Config{
		Domain:     *domain,
		OutputPath: *output,
		Binary:     *binary,
		ExtraArgs:  extraArgs,
		ToolLabel:  strings.TrimSpace(*label),
	}

	if err := osintwell.Run(ctx, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "osint-well: %v\n", err)
		return 1
	}
	return 0
}

func splitArgs(input string) []string {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return nil
	}
	return strings.Fields(trimmed)
}
