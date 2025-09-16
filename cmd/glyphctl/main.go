package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	flag.Parse()

	if code := runManifestValidate(); code != 0 || *manifestValidate != "" {
		if *manifestValidate != "" {
			os.Exit(code)
		}
	}

	fmt.Fprintln(os.Stderr, "no command specified")
	flag.Usage()
	os.Exit(2)
}
