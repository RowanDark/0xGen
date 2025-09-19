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
	case "osint-well":
		os.Exit(runOSINTWell(args[1:]))
	case "plugin":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "plugin subcommand required")
			os.Exit(2)
		}
		switch args[1] {
		case "run":
			os.Exit(runPluginRun(args[2:]))
		case "verify":
			os.Exit(runPluginVerify(args[2:]))
		default:
			fmt.Fprintf(os.Stderr, "unknown plugin subcommand: %s\n", args[1])
			os.Exit(2)
		}
	case "version":
		os.Exit(runVersion(args[1:]))
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", args[0])
		flag.Usage()
		os.Exit(2)
	}
}
