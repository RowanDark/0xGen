package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/RowanDark/0xgen/internal/plugins/integrity"
)

func runPluginVerify(args []string) int {
	fs := flag.NewFlagSet("plugin verify", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	expected := fs.String("hash", "", "expected SHA-256 hash of the artifact")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: 0xgenctl plugin verify <path> --hash <sha256>")
		return 2
	}
	path := fs.Arg(0)
	if *expected == "" {
		fmt.Fprintln(os.Stderr, "--hash is required")
		return 2
	}

	hash, err := integrity.HashFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hash artifact: %v\n", err)
		return 1
	}
	if !strings.EqualFold(hash, *expected) {
		fmt.Fprintf(os.Stderr, "hash mismatch: expected %s got %s\n", *expected, hash)
		return 1
	}
	if _, err := fmt.Fprintf(os.Stdout, "hash verified for %s\n", path); err != nil {
		fmt.Fprintf(os.Stderr, "write stdout: %v\n", err)
		return 1
	}
	return 0
}
