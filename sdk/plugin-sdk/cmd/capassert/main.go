package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/RowanDark/0xgen/sdk/plugin-sdk/lint/capabilityassert"
)

func main() {
	flag.Parse()
	patterns := flag.Args()
	diags, err := capabilityassert.Run(patterns)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if len(diags) == 0 {
		return
	}
	for _, d := range diags {
		fmt.Fprintf(os.Stderr, "%s:%d:%d: %s\n", d.File, d.Line, d.Column, d.Message)
	}
	os.Exit(1)
}
