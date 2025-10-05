package main

import (
	"flag"
	"fmt"
)

var showVersion = flag.Bool("version", false, "Print glyphctl version and exit")

// maybePrintVersion writes the embedded version string to stdout when the global
// --version flag is provided. It returns true when the flag was handled so that
// callers can exit early without executing subcommands.
func maybePrintVersion() bool {
	if !*showVersion {
		return false
	}
	fmt.Println(version)
	return true
}
