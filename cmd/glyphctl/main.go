package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	// Parse global flags (including --manifest-validate) once.
	flag.Parse()
	// Fast path: if the validator flag is present, run it and exit with its code.
	if *manifestValidate != "" {
		os.Exit(runManifestValidate())
	}

	args := flag.Args()
	if len(args) == 0 {
		// No subcommand/flags provided: show usage and exit non-zero.
		flag.Usage()
		os.Exit(2)
	}

	switch args[0] {
	case "report":
		os.Exit(runReport(args[1:]))
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", args[0])
		flag.Usage()
		os.Exit(2)
	}
}
