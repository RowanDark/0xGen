package main

import (
	"flag"
	"fmt"
	"os"
)

var version = "dev"

func versionString() string {
	return fmt.Sprintf("%s %s", productName, version)
}

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
	fmt.Println(versionString())
	return 0
}
