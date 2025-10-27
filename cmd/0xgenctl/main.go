package main

import (
	"flag"
	"fmt"
	"os"
)

const productName = "0xgen"
const cliBanner = productName + " CLI (0xgenctl)"

func init() {
	defaultUsage := flag.Usage
	flag.Usage = func() {
		fmt.Fprintln(flag.CommandLine.Output(), cliBanner)
		fmt.Fprintln(flag.CommandLine.Output())
		if defaultUsage != nil {
			defaultUsage()
		}
	}
}

func main() {
	// Parse global flags (including --manifest-validate) once.
	flag.Parse()
	if maybePrintVersion() {
		return
	}
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
	case "verify-report":
		os.Exit(runVerifyReport(args[1:]))
	case "demo":
		os.Exit(runDemo(args[1:]))
	case "findings":
		os.Exit(runFindings(args[1:]))
	case "export":
		os.Exit(runExport(args[1:]))
	case "osint-well":
		os.Exit(runOSINTWell(args[1:]))
	case "rank":
		os.Exit(runRank(args[1:]))
	case "config":
		os.Exit(runConfig(args[1:]))
	case "api-token":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "api-token subcommand required")
			os.Exit(2)
		}
		switch args[1] {
		case "new":
			os.Exit(runAPITokenNew(args[2:]))
		default:
			fmt.Fprintf(os.Stderr, "unknown api-token subcommand: %s\n", args[1])
			os.Exit(2)
		}
	case "scope":
		os.Exit(runScope(args[1:]))
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
		case "registry":
			os.Exit(runPluginRegistry(args[2:]))
		case "install":
			os.Exit(runPluginInstall(args[2:]))
		case "remove":
			os.Exit(runPluginRemove(args[2:]))
		default:
			fmt.Fprintf(os.Stderr, "unknown plugin subcommand: %s\n", args[1])
			os.Exit(2)
		}
	case "raider":
		os.Exit(runRaider(args[1:]))
	case "history":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "history subcommand required")
			os.Exit(2)
		}
		switch args[1] {
		case "search":
			os.Exit(runHistorySearch(args[2:]))
		default:
			fmt.Fprintf(os.Stderr, "unknown history subcommand: %s\n", args[1])
			os.Exit(2)
		}
	case "repeater":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "repeater subcommand required")
			os.Exit(2)
		}
		switch args[1] {
		case "send":
			os.Exit(runRepeaterSend(args[2:]))
		default:
			fmt.Fprintf(os.Stderr, "unknown repeater subcommand: %s\n", args[1])
			os.Exit(2)
		}
	case "serve":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "serve subcommand required")
			os.Exit(2)
		}
		switch args[1] {
		case "ui":
			os.Exit(runServeUI(args[2:]))
		default:
			fmt.Fprintf(os.Stderr, "unknown serve subcommand: %s\n", args[1])
			os.Exit(2)
		}
	case "replay":
		os.Exit(runReplay(args[1:]))
	case "version":
		os.Exit(runVersion(args[1:]))
	case "self-update":
		os.Exit(runSelfUpdate(args[1:]))
	case "proxy":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "proxy subcommand required")
			os.Exit(2)
		}
		switch args[1] {
		case "trust":
			os.Exit(runProxyTrust(args[2:]))
		default:
			fmt.Fprintf(os.Stderr, "unknown proxy subcommand: %s\n", args[1])
			os.Exit(2)
		}
	case "wsl":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "wsl subcommand required")
			os.Exit(2)
		}
		switch args[1] {
		case "path":
			os.Exit(runWSLPath(args[2:]))
		default:
			fmt.Fprintf(os.Stderr, "unknown wsl subcommand: %s\n", args[1])
			os.Exit(2)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", args[0])
		flag.Usage()
		os.Exit(2)
	}
}
