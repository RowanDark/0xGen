package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

func main() {
	fs := flag.NewFlagSet("grapher", flag.ExitOnError)
	var (
		outPath    = fs.String("out", "", "path to write schema results")
		timeout    = fs.Duration("timeout", 5*time.Second, "request timeout")
		targetsArg multiValue
		filePath   = fs.String("targets-file", "", "path to newline-delimited base URLs")
	)
	fs.Var(&targetsArg, "target", "base URL to probe (repeatable)")
	fs.Parse(os.Args[1:])

	targets, err := gatherTargets(targetsArg.values, *filePath, fs.Args())
	if err != nil {
		fatal(err)
	}
	if len(targets) == 0 {
		fatal(errors.New("at least one target must be provided"))
	}

	output := strings.TrimSpace(*outPath)
	if output == "" {
		output = defaultOutputPath()
	}

	client := &http.Client{Timeout: *timeout}
	ctx := context.Background()

	results, err := runDiscovery(ctx, client, targets)
	if err != nil {
		fatal(err)
	}
	if err := writeResults(output, results); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	logger.Error("grapher execution failed", "error", err)
	os.Exit(1)
}

type multiValue struct {
	values []string
}

func (m *multiValue) String() string {
	return strings.Join(m.values, ",")
}

func (m *multiValue) Set(value string) error {
	m.values = append(m.values, value)
	return nil
}

func gatherTargets(flagTargets []string, filePath string, args []string) ([]string, error) {
	targets := make([]string, 0, len(flagTargets)+len(args))
	targets = append(targets, flagTargets...)

	if filePath = strings.TrimSpace(filePath); filePath != "" {
		content, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("read targets file: %w", err)
		}
		for _, line := range strings.Split(string(content), "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" {
				targets = append(targets, trimmed)
			}
		}
	}

	for _, arg := range args {
		trimmed := strings.TrimSpace(arg)
		if trimmed != "" {
			targets = append(targets, trimmed)
		}
	}

	deduped := make([]string, 0, len(targets))
	seen := make(map[string]struct{}, len(targets))
	for _, t := range targets {
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		deduped = append(deduped, t)
	}
	return deduped, nil
}

func runDiscovery(ctx context.Context, client *http.Client, targets []string) ([]schemaResult, error) {
	now := time.Now
	var all []schemaResult
	seen := make(map[string]struct{})
	for _, target := range targets {
		results, err := discoverSchemas(ctx, client, target, now)
		if err != nil {
			return nil, fmt.Errorf("discover %s: %w", target, err)
		}
		for _, res := range results {
			key := string(res.Type) + "|" + res.URL
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			all = append(all, res)
		}
	}
	sortSchemaResults(all)
	return all, nil
}

func sortSchemaResults(results []schemaResult) {
	sort.Slice(results, func(i, j int) bool {
		if results[i].Type == results[j].Type {
			if results[i].URL == results[j].URL {
				return results[i].Timestamp.Before(results[j].Timestamp)
			}
			return results[i].URL < results[j].URL
		}
		return results[i].Type < results[j].Type
	})
}
