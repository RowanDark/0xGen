package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/RowanDark/0xgen/internal/findings"
	"github.com/RowanDark/0xgen/internal/seer"
	pluginsdk "github.com/RowanDark/0xgen/sdk/plugin-sdk"
)

const (
	defaultEvidencePrefix = 4
	defaultEvidenceSuffix = 4
	defaultMaxScanBytes   = 512 * 1024
)

func main() {
	defaultServer := envOrDefault("0XGEN_SERVER", "127.0.0.1:50051")
	defaultToken := envOrDefault("0XGEN_AUTH_TOKEN", "supersecrettoken")
	defaultAllowlist := strings.TrimSpace(os.Getenv("SEER_ALLOWLIST_FILE"))
	configuredEvidencePrefix := envOrDefaultInt("SEER_EVIDENCE_PREFIX", defaultEvidencePrefix)
	configuredEvidenceSuffix := envOrDefaultInt("SEER_EVIDENCE_SUFFIX", defaultEvidenceSuffix)
	configuredMaxScanBytes := envOrDefaultInt("SEER_MAX_SCAN_BYTES", defaultMaxScanBytes)

	serverAddr := flag.String("server", defaultServer, "0xgend gRPC address")
	authToken := flag.String("token", defaultToken, "authentication token")
	allowlistPath := flag.String("allowlist", defaultAllowlist, "path to newline-separated allowlist entries")
	evidencePrefix := flag.Int("evidence-prefix", configuredEvidencePrefix, "characters to retain at the start of emitted evidence")
	evidenceSuffix := flag.Int("evidence-suffix", configuredEvidenceSuffix, "characters to retain at the end of emitted evidence")
	maxScanBytes := flag.Int("max-scan-bytes", configuredMaxScanBytes, "maximum number of bytes to scan from each artifact")
	flag.Parse()

	allowlist, err := collectAllowlist(*allowlistPath)
	if err != nil {
		slog.Error("failed to load allowlist", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	capToken := strings.TrimSpace(os.Getenv("0XGEN_CAPABILITY_TOKEN"))
	if capToken == "" {
		logger.Error("missing 0XGEN_CAPABILITY_TOKEN environment variable")
		os.Exit(1)
	}

	secretsToken := strings.TrimSpace(os.Getenv("0XGEN_SECRETS_TOKEN"))
	secretsScope := strings.TrimSpace(os.Getenv("0XGEN_SECRETS_SCOPE"))

	cfg := pluginsdk.Config{
		PluginName:      "seer",
		Host:            *serverAddr,
		AuthToken:       *authToken,
		CapabilityToken: capToken,
		SecretsToken:    secretsToken,
		SecretsScope:    secretsScope,
		Capabilities: []pluginsdk.Capability{
			pluginsdk.CapabilityHTTPPassive,
			pluginsdk.CapabilityEmitFindings,
		},
		Logger: logger,
	}

	prefix := clampNonNegative(*evidencePrefix)
	suffix := clampNonNegative(*evidenceSuffix)
	maxBytes := *maxScanBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxScanBytes
	}

	detectorCfg := seer.Config{
		Allowlist:      allowlist,
		EvidencePrefix: prefix,
		EvidenceSuffix: suffix,
		MaxScanBytes:   maxBytes,
	}

	hooks := pluginsdk.Hooks{
		OnStart: func(ctx *pluginsdk.Context) error {
			ctx.Logger().Info("seer plugin initialised",
				"allowlist_entries", len(allowlist),
				"evidence_prefix", detectorCfg.EvidencePrefix,
				"evidence_suffix", detectorCfg.EvidenceSuffix,
				"max_scan_bytes", detectorCfg.MaxScanBytes,
			)
			return nil
		},
		OnHTTPPassive: func(ctx *pluginsdk.Context, event pluginsdk.HTTPPassiveEvent) error {
			if event.Response == nil {
				return nil
			}
			if ct := strings.TrimSpace(event.Response.Headers.Get("Content-Type")); isBinaryContentType(ct) {
				ctx.Logger().Debug("skipping binary content-type response", "content_type", ct)
				return nil
			}
			body := event.Response.Body
			if len(body) == 0 {
				return nil
			}
			if isLikelyBinary(body) {
				ctx.Logger().Debug("skipping binary-like response body")
				return nil
			}
			if !utf8.Valid(body) {
				ctx.Logger().Debug("skipping non-utf8 response body")
				return nil
			}

			maxBytes := detectorCfg.MaxScanBytes
			if maxBytes <= 0 {
				maxBytes = defaultMaxScanBytes
			}
			if maxBytes > 0 && len(body) > maxBytes {
				body = clampBody(body, maxBytes)
				if len(body) == 0 {
					return nil
				}
			}
			if !utf8.Valid(body) {
				ctx.Logger().Debug("skipping non-utf8 response body after clamp")
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

func envOrDefaultInt(key string, fallback int) int {
	val := strings.TrimSpace(os.Getenv(key))
	if val == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(val)
	if err != nil {
		return fallback
	}
	if parsed < 0 {
		return fallback
	}
	return parsed
}

func clampNonNegative(val int) int {
	if val < 0 {
		return 0
	}
	return val
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

func isLikelyBinary(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	sample := data
	if len(sample) > 2048 {
		sample = sample[:2048]
	}
	var nonText int
	for _, b := range sample {
		if b == 0 {
			return true
		}
		if b < 0x20 {
			switch b {
			case '\n', '\r', '\t':
				continue
			default:
				nonText++
			}
			continue
		}
		if b > 0x7E {
			nonText++
		}
	}
	ratio := float64(nonText) / float64(len(sample))
	return ratio > 0.3
}

func clampBody(data []byte, max int) []byte {
	if max <= 0 || len(data) <= max {
		return data
	}
	trimmed := data[:max]
	for len(trimmed) > 0 && !utf8.Valid(trimmed) {
		trimmed = trimmed[:len(trimmed)-1]
	}
	return trimmed
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

func isBinaryContentType(value string) bool {
	if value == "" {
		return false
	}
	ct := strings.ToLower(strings.TrimSpace(value))
	if idx := strings.Index(ct, ";"); idx != -1 {
		ct = strings.TrimSpace(ct[:idx])
	}
	if ct == "" {
		return false
	}
	if strings.HasPrefix(ct, "text/") {
		return false
	}
	textualHints := []string{"json", "xml", "yaml", "yml", "javascript", "ecmascript", "csv", "form-urlencoded"}
	for _, hint := range textualHints {
		if strings.Contains(ct, hint) {
			return false
		}
	}
	binaryMatches := []string{
		"application/octet-stream",
		"application/pdf",
		"application/zip",
		"application/x-7z-compressed",
		"application/x-bzip2",
		"application/x-gzip",
		"application/x-tar",
		"application/vnd.ms-excel",
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
	}
	for _, match := range binaryMatches {
		if ct == match {
			return true
		}
	}
	binaryPrefixes := []string{"image/", "audio/", "video/", "font/"}
	for _, prefix := range binaryPrefixes {
		if strings.HasPrefix(ct, prefix) {
			return true
		}
	}
	if strings.HasSuffix(ct, "+protobuf") || strings.HasSuffix(ct, "+avro") {
		return true
	}
	return false
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
