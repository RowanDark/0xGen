package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/RowanDark/0xgen/internal/config"
)

func runConfig(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "config subcommand required")
		return 2
	}

	switch args[0] {
	case "print":
		return runConfigPrint()
	case "migrate":
		return runConfigMigrate()
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

func runConfigMigrate() int {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "determine home directory: %v\n", err)
		return 1
	}

	legacyPath := filepath.Join(home, ".0xgen", "config.toml")
	data, err := os.ReadFile(legacyPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "no legacy config found at %s\n", legacyPath)
			return 2
		}
		fmt.Fprintf(os.Stderr, "read legacy config: %v\n", err)
		return 1
	}

	newDir := filepath.Join(home, ".0xgen")
	if err := os.MkdirAll(newDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "create config directory: %v\n", err)
		return 1
	}

	newPath := filepath.Join(newDir, "config.toml")
	if _, err := os.Stat(newPath); err == nil {
		fmt.Fprintf(os.Stderr, "config already exists at %s; refusing to overwrite\n", newPath)
		return 2
	} else if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "stat config: %v\n", err)
		return 1
	}

	if err := os.WriteFile(newPath, data, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "write config: %v\n", err)
		return 1
	}

	fmt.Fprintf(os.Stdout, "Migrated config to %s\n", newPath)
	return 0
}
