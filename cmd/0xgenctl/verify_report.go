package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/RowanDark/0xgen/internal/reporter"
)

func runVerifyReport(args []string) int {
	fs := flag.NewFlagSet("verify-report", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	signature := fs.String("signature", "", "path to detached signature (defaults to <report>.sig)")
	key := fs.String("key", "", "path to cosign public key")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	remaining := fs.Args()
	if len(remaining) == 0 {
		fmt.Fprintln(os.Stderr, "report path is required")
		return 2
	}

	artifactPath := strings.TrimSpace(remaining[0])
	if artifactPath == "" {
		fmt.Fprintln(os.Stderr, "report path is required")
		return 2
	}

	signaturePath := strings.TrimSpace(*signature)
	if signaturePath == "" {
		signaturePath = artifactPath + ".sig"
	}
	if !filepath.IsAbs(signaturePath) {
		signaturePath = filepath.Clean(signaturePath)
	}

	keyPath := strings.TrimSpace(*key)
	if keyPath == "" {
		fmt.Fprintln(os.Stderr, "--key is required")
		return 2
	}

	if err := reporter.VerifyArtifact(artifactPath, signaturePath, keyPath); err != nil {
		fmt.Fprintf(os.Stderr, "verify report: %v\n", err)
		return 1
	}

	fmt.Fprintln(os.Stdout, "Signature verified.")
	return 0
}
