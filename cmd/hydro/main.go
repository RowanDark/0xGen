package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

var (
	aggressive   = flag.Bool("aggressive", false, "scan aggressively, potentially impacting targets")
	recursive    = flag.Bool("recursive", false, "scan recursively, potentially impacting targets")
	confirmLegal = flag.Bool("confirm-legal", false, "confirm you have legal authorization for destructive scans")
)

const safetyBanner = `⚠️  LEGAL NOTICE ⚠️
You are enabling scan options that may be destructive.
Ensure you have explicit authorization to test these systems and
understand all applicable laws, contracts, and policies before proceeding.`

func main() {
	flag.Parse()

	destructiveFlags := activeDestructiveFlags(*aggressive, *recursive)
	if err := maybeWarnDestructive(os.Stderr, *confirmLegal, destructiveFlags); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(2)
	}

	fmt.Printf("hydro scan starting (aggressive=%t, recursive=%t)\n", *aggressive, *recursive)
}

func activeDestructiveFlags(aggressiveEnabled, recursiveEnabled bool) []string {
	var result []string
	if aggressiveEnabled {
		result = append(result, "--aggressive")
	}
	if recursiveEnabled {
		result = append(result, "--recursive")
	}
	return result
}

func maybeWarnDestructive(w io.Writer, confirmed bool, destructiveFlags []string) error {
	if len(destructiveFlags) == 0 {
		return nil
	}

	fmt.Fprintln(w, safetyBanner)
	fmt.Fprintf(w, "Destructive options enabled: %s\n", strings.Join(destructiveFlags, ", "))
	fmt.Fprintln(w)

	if confirmed {
		return nil
	}

	return fmt.Errorf("refusing to continue without --confirm-legal when %s is set", joinDestructiveFlags(destructiveFlags))
}

func joinDestructiveFlags(flags []string) string {
	switch len(flags) {
	case 0:
		return ""
	case 1:
		return flags[0]
	default:
		return strings.Join(flags[:len(flags)-1], ", ") + " and " + flags[len(flags)-1]
	}
}
