package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/RowanDark/Glyph/internal/plugins"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("glyphctl", flag.ContinueOnError)
	fs.SetOutput(stderr)

	manifestPath := fs.String("manifest", "", "Path to a plugin manifest to validate")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *manifestPath == "" {
		fmt.Fprintln(stderr, "--manifest flag is required")
		return 2
	}

	if err := plugins.ValidateManifest(*manifestPath); err != nil {
		fmt.Fprintf(stderr, "invalid manifest: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "manifest %s is valid\n", *manifestPath)
	return 0
}
