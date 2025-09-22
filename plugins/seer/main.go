package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/RowanDark/Glyph/internal/findings"
	"github.com/RowanDark/Glyph/internal/seer"
	pluginsdk "github.com/RowanDark/Glyph/sdk/plugin-sdk"
)

func main() {
	defaultServer := envOrDefault("GLYPH_SERVER", "127.0.0.1:50051")
	defaultToken := envOrDefault("GLYPH_AUTH_TOKEN", "supersecrettoken")
	defaultAllowlist := strings.TrimSpace(os.Getenv("SEER_ALLOWLIST_FILE"))

	serverAddr := flag.String("server", defaultServer, "glyphd gRPC address")
	authToken := flag.String("token", defaultToken, "authentication token")
	allowlistPath := flag.String("allowlist", defaultAllowlist, "path to newline-separated allowlist entries")
	flag.Parse()

	allowlist, err := collectAllowlist(*allowlistPath)
	if err != nil {
		slog.Error("failed to load allowlist", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg := pluginsdk.Config{
		PluginName: "seer",
		Host:       *serverAddr,
		AuthToken:  *authToken,
		Capabilities: []pluginsdk.Capability{
			pluginsdk.CapabilityHTTPPassive,
			pluginsdk.CapabilityEmitFindings,
		},
		Logger: logger,
	}

	detectorCfg := seer.Config{Allowlist: allowlist}

	hooks := pluginsdk.Hooks{
		OnStart: func(ctx *pluginsdk.Context) error {
			ctx.Logger().Info("seer plugin initialised", "allowlist_entries", len(allowlist))
			return nil
		},
		OnHTTPPassive: func(ctx *pluginsdk.Context, event pluginsdk.HTTPPassiveEvent) error {
			if event.Response == nil {
				return nil
			}
			body := event.Response.Body
			if len(body) == 0 {
				return nil
			}
			if !utf8.Valid(body) {
				ctx.Logger().Debug("skipping non-utf8 response body")
				return nil
			}
			content := string(body)
			if strings.TrimSpace(content) == "" {
				return nil
			}

			target := responseTarget(event.Response)
			results := seer.Scan(target, content, detectorCfg)
			for _, finding := range results {
				if err := ctx.EmitFinding(convertFinding(finding)); err != nil {
					return err
				}
			}
			return nil
		},
	}

	if err := pluginsdk.Serve(ctx, cfg, hooks); err != nil {
		logger.Error("plugin terminated", "error", err)
		os.Exit(1)
	}

	time.Sleep(100 * time.Millisecond)
}

func envOrDefault(key, fallback string) string {
	if val := strings.TrimSpace(os.Getenv(key)); val != "" {
		return val
	}
	return fallback
}

func collectAllowlist(path string) ([]string, error) {
	var entries []string

	if env := strings.TrimSpace(os.Getenv("SEER_ALLOWLIST")); env != "" {
		for _, part := range strings.Split(env, ",") {
			trimmed := strings.TrimSpace(part)
			if trimmed != "" {
				entries = append(entries, trimmed)
			}
		}
	}

	if path == "" {
		return entries, nil
	}

	fileEntries, err := readAllowlistFile(path)
	if err != nil {
		return nil, err
	}
	entries = append(entries, fileEntries...)
	return entries, nil
}

func readAllowlistFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open allowlist: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()

	var entries []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entries = append(entries, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read allowlist: %w", err)
	}
	return entries, nil
}

func responseTarget(resp *pluginsdk.HTTPResponse) string {
	if resp == nil {
		return ""
	}
	host := strings.TrimSpace(resp.Headers.Get("Host"))
	if host == "" {
		host = strings.TrimSpace(resp.Headers.Get(":authority"))
	}
	if host == "" {
		return ""
	}
	scheme := strings.TrimSpace(resp.Headers.Get(":scheme"))
	if scheme == "" {
		scheme = "https"
	}
	path := strings.TrimSpace(resp.Headers.Get(":path"))
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return fmt.Sprintf("%s://%s%s", scheme, host, path)
}

func convertFinding(f findings.Finding) pluginsdk.Finding {
	meta := map[string]string{}
	for k, v := range f.Metadata {
		meta[k] = v
	}
	if len(meta) == 0 {
		meta = nil
	}
	return pluginsdk.Finding{
		ID:         f.ID,
		Type:       f.Type,
		Message:    f.Message,
		Target:     f.Target,
		Evidence:   f.Evidence,
		Severity:   mapSeverity(f.Severity),
		Metadata:   meta,
		DetectedAt: f.DetectedAt.Time(),
	}
}

func mapSeverity(sev findings.Severity) pluginsdk.Severity {
	switch sev {
	case findings.SeverityCritical:
		return pluginsdk.SeverityCritical
	case findings.SeverityHigh:
		return pluginsdk.SeverityHigh
	case findings.SeverityMedium:
		return pluginsdk.SeverityMedium
	case findings.SeverityLow:
		return pluginsdk.SeverityLow
	default:
		return pluginsdk.SeverityInfo
	}
}
