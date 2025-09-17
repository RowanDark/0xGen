package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/RowanDark/Glyph/internal/plugins"
	"github.com/RowanDark/Glyph/internal/plugins/integrity"
	"github.com/RowanDark/Glyph/internal/plugins/runner"
)

func runPluginRun(args []string) int {
	fs := flag.NewFlagSet("plugin run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	sample := fs.String("sample", "", "sample plugin to execute")
	server := fs.String("server", "127.0.0.1:50051", "glyphd gRPC address")
	token := fs.String("token", "supersecrettoken", "glyphd authentication token")
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
	manifest, err := plugins.LoadManifest(manifestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load manifest: %v\n", err)
		return 1
	}

	allowlist, err := integrity.LoadAllowlist(filepath.Join(root, "plugins", "ALLOWLIST"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "load allowlist: %v\n", err)
		return 1
	}

	artifactPath := manifest.Artifact
	if !filepath.IsAbs(artifactPath) {
		artifactPath = filepath.Join(root, artifactPath)
	}
	if err := allowlist.Verify(artifactPath); err != nil {
		fmt.Fprintf(os.Stderr, "artifact verification failed: %v\n", err)
		return 1
	}

	pluginDir := filepath.Dir(manifestPath)
	binaryDir, err := os.MkdirTemp("", "glyph-plugin-build-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create build dir: %v\n", err)
		return 1
	}
	defer os.RemoveAll(binaryDir)
	binaryPath := filepath.Join(binaryDir, manifest.Entry)

	build := exec.Command("go", "build", "-o", binaryPath, ".")
	build.Dir = pluginDir
	var buildOutput bytes.Buffer
	build.Stdout = &buildOutput
	build.Stderr = &buildOutput
	if err := build.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "build plugin: %v\n%s\n", err, buildOutput.String())
		return 1
	}

	ctx := context.Background()
	limits := runner.Limits{
		CPUSeconds: 60,
		WallTime:   *duration,
	}
	if limits.WallTime <= 0 {
		limits.WallTime = 5 * time.Second
	}
	env := map[string]string{}
	if val := os.Getenv("GLYPH_OUT"); strings.TrimSpace(val) != "" {
		env["GLYPH_OUT"] = val
	}
	if val := os.Getenv("GLYPH_E2E_SMOKE"); strings.TrimSpace(val) != "" {
		env["GLYPH_E2E_SMOKE"] = val
	}
	config := runner.Config{
		Binary: binaryPath,
		Args:   []string{"--server", *server, "--token", *token},
		Env:    env,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		Limits: limits,
	}

	if err := runner.Run(ctx, config); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			fmt.Fprintln(os.Stderr, "plugin reached the configured runtime limit")
			return 0
		}
		fmt.Fprintf(os.Stderr, "run plugin: %v\n", err)
		return 1
	}
	return 0
}
