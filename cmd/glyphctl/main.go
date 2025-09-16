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
		if _, err := fmt.Fprintln(stderr, "--manifest flag is required"); err != nil {
			return 2
		}
		return 2
	}

	if err := plugins.ValidateManifest(*manifestPath); err != nil {
		if _, writeErr := fmt.Fprintf(stderr, "invalid manifest: %v\n", err); writeErr != nil {
			return 1
		}
		return 1
	}

	if _, err := fmt.Fprintf(stdout, "manifest %s is valid\n", *manifestPath); err != nil {
		return 1
	}
	return 0
}
