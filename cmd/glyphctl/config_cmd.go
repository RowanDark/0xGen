package main

import (
	"fmt"
	"io"
	"os"

	"github.com/RowanDark/Glyph/internal/config"
)

func runConfig(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "config subcommand required")
		return 2
	}

	switch args[0] {
	case "print":
		return runConfigPrint()
	default:
		fmt.Fprintf(os.Stderr, "unknown config subcommand: %s\n", args[0])
		return 2
	}
}

func runConfigPrint() int {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		return 1
	}

	printResolvedConfig(os.Stdout, cfg)
	return 0
}

func printResolvedConfig(out io.Writer, cfg config.Config) {
	fmt.Fprintf(out, "server_addr: %s\n", cfg.ServerAddr)
	fmt.Fprintf(out, "auth_token: %s\n", cfg.AuthToken)
	fmt.Fprintf(out, "output_dir: %s\n", cfg.OutputDir)
	fmt.Fprintln(out, "proxy:")
	fmt.Fprintf(out, "  enable: %t\n", cfg.Proxy.Enable)
	fmt.Fprintf(out, "  addr: %s\n", cfg.Proxy.Addr)
	fmt.Fprintf(out, "  rules_path: %s\n", cfg.Proxy.RulesPath)
	fmt.Fprintf(out, "  history_path: %s\n", cfg.Proxy.HistoryPath)
	fmt.Fprintf(out, "  ca_cert_path: %s\n", cfg.Proxy.CACertPath)
	fmt.Fprintf(out, "  ca_key_path: %s\n", cfg.Proxy.CAKeyPath)
}
