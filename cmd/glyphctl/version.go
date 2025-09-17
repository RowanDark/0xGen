package main

import (
	"flag"
	"fmt"
	"os"
)

var version = "dev"

func runVersion(args []string) int {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintln(os.Stderr, "version takes no arguments")
		return 2
	}
	fmt.Println(version)
	return 0
}
