package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/RowanDark/Glyph/internal/system/wslpath"
)

func runWSLPath(args []string) int {
	fs := flag.NewFlagSet("wsl path", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	toWindows := fs.Bool("to-windows", false, "convert a WSL path to a Windows path")
	toWSL := fs.Bool("to-wsl", false, "convert a Windows path to a WSL path")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *toWindows == *toWSL {
		fmt.Fprintln(os.Stderr, "specify exactly one of --to-windows or --to-wsl")
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "path argument required")
		return 2
	}

	var (
		result string
		err    error
	)
	input := fs.Arg(0)
	if *toWindows {
		result, err = wslpath.ToWindows(input)
	} else {
		result, err = wslpath.ToWSL(input)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "translate path: %v\n", err)
		return 1
	}
	fmt.Println(result)
	return 0
}
