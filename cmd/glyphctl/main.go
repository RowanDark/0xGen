package main

import (
	"flag"
	"os"
)

func main() {
	// Parse global flags (including --manifest-validate) once.
	flag.Parse()
	// Fast path: if the validator flag is present, run it and exit with its code.
	if *manifestValidate != "" {
		os.Exit(runManifestValidate())
	}
	// No subcommand/flags provided: show usage and exit non-zero.
	flag.Usage()
	os.Exit(2)
}
