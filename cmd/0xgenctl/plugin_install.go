package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/RowanDark/0xgen/internal/plugins/marketplace"
)

func runPluginInstall(args []string) int {
	fs := flag.NewFlagSet("0xgenctl plugin install", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	registry := fs.String("registry", "", "registry index URL or file path")
	pluginsDir := fs.String("plugins-dir", "plugins", "destination directory for plugins")
	force := fs.Bool("force", false, "overwrite existing installation")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: 0xgenctl plugin install <id> [--registry URL]")
		return 2
	}
	pluginID := fs.Arg(0)

	registrySource := strings.TrimSpace(*registry)
	if registrySource == "" {
		if env, ok := os.LookupEnv("0XGEN_PLUGIN_REGISTRY_URL"); ok {
			registrySource = strings.TrimSpace(env)
		}
	}
	if registrySource == "" {
		registrySource = "http://127.0.0.1:9090/plugins/registry"
	}

	manager, err := marketplace.NewManager(strings.TrimSpace(*pluginsDir), registrySource)
	if err != nil {
		fmt.Fprintf(os.Stderr, "configure plugin manager: %v\n", err)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	installed, err := manager.Install(ctx, pluginID, marketplace.InstallOptions{Force: *force})
	if err != nil {
		fmt.Fprintf(os.Stderr, "install plugin: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stdout, "Installed %s %s\n", installed.Name, installed.Version)
	return 0
}

func runPluginRemove(args []string) int {
	fs := flag.NewFlagSet("0xgenctl plugin remove", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	pluginsDir := fs.String("plugins-dir", "plugins", "plugin directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: 0xgenctl plugin remove <id>")
		return 2
	}
	pluginID := fs.Arg(0)

	registrySource := ""
	if env, ok := os.LookupEnv("0XGEN_PLUGIN_REGISTRY_URL"); ok {
		registrySource = strings.TrimSpace(env)
	}
	if registrySource == "" {
		registrySource = "http://127.0.0.1:9090/plugins/registry"
	}
	manager, err := marketplace.NewManager(strings.TrimSpace(*pluginsDir), registrySource)
	if err != nil {
		fmt.Fprintf(os.Stderr, "configure plugin manager: %v\n", err)
		return 1
	}
	if err := manager.Remove(pluginID); err != nil {
		fmt.Fprintf(os.Stderr, "remove plugin: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stdout, "Removed %s\n", pluginID)
	return 0
}
