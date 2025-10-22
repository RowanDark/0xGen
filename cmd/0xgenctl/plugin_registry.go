package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

var runRegistryCommand = runExternalCommand

func runPluginRegistry(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "plugin registry subcommand required")
		return 2
	}
	switch args[0] {
	case "publish":
		return runPluginRegistryPublish(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown plugin registry subcommand: %s\n", args[0])
		return 2
	}
}

func runPluginRegistryPublish(args []string) int {
	fs := flag.NewFlagSet("0xgenctl plugin registry publish", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	ref := fs.String("ref", "", "git ref used for generated links")
	repoURL := fs.String("repo-url", "", "repository URL used for documentation links")
	pythonBin := fs.String("python", "python", "python interpreter to execute the generator")
	script := fs.String("script", filepath.Join("scripts", "update_plugin_catalog.py"), "path to the registry generator script")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	cmdArgs := make([]string, 0, 6)
	if *ref != "" {
		cmdArgs = append(cmdArgs, "--ref", *ref)
	}
	if *repoURL != "" {
		cmdArgs = append(cmdArgs, "--repo-url", *repoURL)
	}
	cmdArgs = append(cmdArgs, fs.Args()...)

	command := append([]string{*script}, cmdArgs...)
	if err := runRegistryCommand(context.Background(), *pythonBin, command); err != nil {
		fmt.Fprintf(os.Stderr, "regenerate plugin registry: %v\n", err)
		return 1
	}
	return 0
}

func runExternalCommand(ctx context.Context, program string, args []string) error {
	cmd := exec.CommandContext(ctx, program, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	return cmd.Run()
}
