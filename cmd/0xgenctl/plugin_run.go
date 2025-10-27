package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/RowanDark/0xgen/internal/env"
	"github.com/RowanDark/0xgen/internal/plugins/launcher"
)

func runPluginRun(args []string) int {
	fs := flag.NewFlagSet("plugin run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	sample := fs.String("sample", "", "sample plugin to execute")
	server := fs.String("server", "127.0.0.1:50051", "0xgend gRPC address")
	token := fs.String("token", "supersecrettoken", "0xgend authentication token")
	duration := fs.Duration("duration", 5*time.Second, "maximum runtime before termination")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *sample == "" {
		fmt.Fprintln(os.Stderr, "--sample is required")
		return 2
	}

	root, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "determine working directory: %v\n", err)
		return 1
	}

	manifestPath := filepath.Join(root, "plugins", "samples", *sample, "manifest.json")
	envVars := map[string]string{}
	if val, ok := env.Lookup("0XGEN_OUT"); ok {
		if trimmed := strings.TrimSpace(val); trimmed != "" {
			envVars["0XGEN_OUT"] = trimmed
		}
	}
	if val, ok := env.Lookup("0XGEN_E2E_SMOKE"); ok {
		if trimmed := strings.TrimSpace(val); trimmed != "" {
			envVars["0XGEN_E2E_SMOKE"] = trimmed
		}
	}
	cfg := launcher.Config{
		ManifestPath:              manifestPath,
		AllowlistPath:             filepath.Join(root, "plugins", "ALLOWLIST"),
		RepoRoot:                  root,
		SkipSignatureVerification: true,
		ServerAddr:                *server,
		AuthToken:                 *token,
		Duration:                  *duration,
		Stdout:                    os.Stdout,
		Stderr:                    os.Stderr,
		ExtraEnv:                  envVars,
	}

	ctx := context.Background()
	if _, err := launcher.Run(ctx, cfg); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			fmt.Fprintln(os.Stderr, "plugin reached the configured runtime limit")
			return 0
		}
		fmt.Fprintf(os.Stderr, "run plugin: %v\n", err)
		return 1
	}
	return 0
}
