package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/RowanDark/0xgen/internal/env"
	"github.com/RowanDark/0xgen/internal/updater"
)

func runSelfUpdate(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "channel":
			return runSelfUpdateChannel(args[1:])
		}
	}

	fs := flag.NewFlagSet("self-update", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	channelFlag := fs.String("channel", "", "update channel to use for this invocation (stable or beta)")
	rollback := fs.Bool("rollback", false, "restore the previous glyphctl binary")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "self-update takes no positional arguments")
		return 2
	}

	store, err := updater.NewStore("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "prepare updater config: %v\n", err)
		return 1
	}
	cfg, err := store.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load updater config: %v\n", err)
		return 1
	}

	channel := cfg.Channel
	if channel == "" {
		channel = updater.ChannelStable
	}
	persist := true
	if *channelFlag != "" {
		normalized, err := updater.NormalizeChannel(*channelFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid channel %q: %v\n", *channelFlag, err)
			return 2
		}
		channel = normalized
		persist = false
	}

	baseURL := ""
	if val, ok := env.Lookup("0XGEN_UPDATER_BASE_URL"); ok {
		baseURL = strings.TrimSpace(val)
	}
	client := &updater.Client{
		Store:          store,
		BaseURL:        baseURL,
		CurrentVersion: version,
		Out:            os.Stdout,
	}

	ctx := context.Background()
	if *rollback {
		if err := client.Rollback(ctx, updater.RollbackOptions{ForceStable: true}); err != nil {
			fmt.Fprintf(os.Stderr, "rollback failed: %v\n", err)
			return 1
		}
		return 0
	}

	if err := client.Update(ctx, updater.UpdateOptions{Channel: channel, PersistChannel: persist}); err != nil {
		fmt.Fprintf(os.Stderr, "update failed: %v\n", err)
		return 1
	}
	return 0
}

func runSelfUpdateChannel(args []string) int {
	fs := flag.NewFlagSet("self-update channel", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	store, err := updater.NewStore("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "prepare updater config: %v\n", err)
		return 1
	}
	cfg, err := store.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load updater config: %v\n", err)
		return 1
	}

	switch fs.NArg() {
	case 0:
		ch := cfg.Channel
		if ch == "" {
			ch, _ = updater.NormalizeChannel("")
		}
		fmt.Fprintln(os.Stdout, ch)
		return 0
	case 1:
		channel, err := updater.NormalizeChannel(fs.Arg(0))
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid channel %q: %v\n", fs.Arg(0), err)
			return 2
		}
		cfg.Channel = channel
		if err := store.Save(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "persist updater config: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stdout, "default channel set to %s\n", channel)
		return 0
	default:
		fmt.Fprintln(os.Stderr, "self-update channel accepts at most one argument")
		return 2
	}
}
