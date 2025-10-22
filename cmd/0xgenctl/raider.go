package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/RowanDark/0xgen/internal/raider"
)

func runRaider(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "raider subcommand required")
		return 2
	}
	switch args[0] {
	case "run":
		return runRaiderRun(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown raider subcommand: %s\n", args[0])
		return 2
	}
}

func runRaiderRun(args []string) int {
	fs := flag.NewFlagSet("raider run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	reqPath := fs.String("req", "", "path to the HTTP request template")
	markerSpec := fs.String("positions", "{{}}", "marker delimiters for insertion points")
	payloadSpec := fs.String("payload", "", "payload source (file, range, or comma separated list)")
	concurrency := fs.Int("concurrency", 1, "number of concurrent workers")
	rateSpec := fs.String("rate", "", "per-host rate limit (e.g. 5/s, 120/m)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if strings.TrimSpace(*reqPath) == "" {
		fmt.Fprintln(os.Stderr, "--req is required")
		return 2
	}
	if strings.TrimSpace(*payloadSpec) == "" {
		fmt.Fprintln(os.Stderr, "--payload is required")
		return 2
	}

	data, err := os.ReadFile(*reqPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read request template: %v\n", err)
		return 1
	}

	markers, err := raider.ParseMarkers(*markerSpec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse positions: %v\n", err)
		return 2
	}

	tpl, err := raider.ParseTemplate(string(data), markers)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse template: %v\n", err)
		return 1
	}

	payloads, err := raider.LoadPayloads(*payloadSpec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load payloads: %v\n", err)
		return 1
	}

	limit, err := parseRateLimit(*rateSpec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse rate: %v\n", err)
		return 2
	}

	opts := []raider.EngineOption{
		raider.WithConcurrency(*concurrency),
		raider.WithRateLimit(limit),
	}
	engine := raider.NewEngine(tpl, payloads, opts...)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	go func() {
		select {
		case <-sigCh:
			cancel()
		case <-ctx.Done():
		}
	}()

	encoder := jsonEncoder()
	var mu sync.Mutex
	err = engine.Run(ctx, func(res raider.Result) error {
		mu.Lock()
		defer mu.Unlock()
		if err := encoder(res); err != nil {
			cancel()
			return err
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return 1
		}
		fmt.Fprintf(os.Stderr, "raider run failed: %v\n", err)
		return 1
	}

	return 0
}

func parseRateLimit(spec string) (float64, error) {
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" {
		return 0, nil
	}
	parts := strings.Split(trimmed, "/")
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid rate format: expected <count>/<unit>")
	}
	count, err := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
	if err != nil || count <= 0 {
		return 0, fmt.Errorf("invalid rate count")
	}
	unit := strings.ToLower(strings.TrimSpace(parts[1]))
	switch unit {
	case "s", "sec", "second", "seconds":
		return count, nil
	case "m", "min", "minute", "minutes":
		return count / 60.0, nil
	case "h", "hour", "hours":
		return count / 3600.0, nil
	default:
		return 0, fmt.Errorf("unknown rate unit %q", unit)
	}
}

func jsonEncoder() func(raider.Result) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	return func(res raider.Result) error {
		return enc.Encode(res)
	}
}
