package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usage()
	}

	switch args[0] {
	case "init":
		return runInit(args[1:])
	case "help", "-h", "--help":
		return usage()
	default:
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func usage() error {
	fmt.Fprintf(os.Stderr, "glyph-plugin commands:\n")
	fmt.Fprintf(os.Stderr, "  init   scaffold a new plugin project\n")
	return errors.New("usage")
}

func runInit(args []string) error {
	fs := flag.NewFlagSet("glyph-plugin init", flag.ContinueOnError)
	lang := fs.String("lang", "go", "language for the plugin (go|node)")
	name := fs.String("name", "", "directory name for the new plugin")
	module := fs.String("module", "", "Go module path (required for --lang=go)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *name == "" {
		return errors.New("--name is required")
	}

	switch *lang {
	case "go":
		if *module == "" {
			return errors.New("--module is required for Go plugins")
		}
		return scaffoldGo(*name, *module)
	case "node":
		return scaffoldNode(*name)
	default:
		return fmt.Errorf("unsupported language %q", *lang)
	}
}
