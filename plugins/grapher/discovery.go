package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type schemaType string

const (
	schemaOpenAPI schemaType = "openapi"
	schemaGraphQL schemaType = "graphql"
)

var openAPICandidates = []string{
	"/.well-known/openapi.json",
	"/.well-known/openapi.yaml",
	"/.well-known/apis.json",
	"/openapi.json",
	"/swagger.json",
	"/swagger/v1/swagger.json",
}

var graphQLCandidates = []string{
	"/.well-known/graphql",
	"/graphql",
	"/api/graphql",
}

const (
	maxResponseBytes = 1 << 20 // 1 MiB
)

// schemaResult captures information about a discovered schema endpoint.
type schemaResult struct {
	Type      schemaType
	URL       string
	Status    int
	Timestamp time.Time
}

// discoverSchemas probes well-known OpenAPI and GraphQL endpoints using the provided HTTP client.
func discoverSchemas(ctx context.Context, client *http.Client, baseURL string, now func() time.Time) ([]schemaResult, error) {
	if client == nil {
		return nil, errors.New("http client must not be nil")
	}
	parsed, err := normalizeBaseURL(baseURL)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	results := make([]schemaResult, 0, len(openAPICandidates)+len(graphQLCandidates))

	for _, path := range openAPICandidates {
		target := resolveURL(parsed, path)
		if _, ok := seen[target]; ok {
			continue
		}
		status, ok := fetchEndpoint(ctx, client, target, http.MethodGet)
		if !ok {
			continue
		}
		seen[target] = struct{}{}
		results = append(results, schemaResult{
			Type:      schemaOpenAPI,
			URL:       target,
			Status:    status,
			Timestamp: now().UTC(),
		})
	}

	for _, path := range graphQLCandidates {
		target := resolveURL(parsed, path)
		if _, ok := seen[target]; ok {
			continue
		}
		status, ok := probeGraphQLEndpoint(ctx, client, target)
		if !ok {
			continue
		}
		seen[target] = struct{}{}
		results = append(results, schemaResult{
			Type:      schemaGraphQL,
			URL:       target,
			Status:    status,
			Timestamp: now().UTC(),
		})
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].Type == results[j].Type {
			return results[i].URL < results[j].URL
		}
		return results[i].Type < results[j].Type
	})
	return results, nil
}

func normalizeBaseURL(raw string) (*url.URL, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, errors.New("base url must not be empty")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("parse base url: %w", err)
	}
	if parsed.Scheme == "" {
		parsed, err = url.Parse("https://" + trimmed)
		if err != nil {
			return nil, fmt.Errorf("parse base url with https: %w", err)
		}
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("base url missing host: %s", raw)
	}
	return parsed, nil
}

func resolveURL(base *url.URL, candidate string) string {
	ref := &url.URL{Path: candidate}
	return base.ResolveReference(ref).String()
}

func fetchEndpoint(ctx context.Context, client *http.Client, target, method string) (int, bool) {
	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return 0, false
	}
	req.Header.Set("Accept", "application/json, application/yaml;q=0.9, */*;q=0.5")

	resp, err := client.Do(req)
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return resp.StatusCode, true
	}
	return resp.StatusCode, false
}

func probeGraphQLEndpoint(ctx context.Context, client *http.Client, target string) (int, bool) {
	status, ok := fetchEndpoint(ctx, client, target, http.MethodHead)
	if ok {
		return status, true
	}
	// Retry with GET for servers that do not implement HEAD.
	status, ok = fetchEndpoint(ctx, client, target, http.MethodGet)
	if !ok {
		// Treat 400 responses as evidence of a GraphQL handler complaining about a missing query.
		if status == http.StatusBadRequest {
			return status, true
		}
		return status, false
	}
	return status, true
}

// writeResults persists schema results to JSON Lines.
func writeResults(path string, results []schemaResult) error {
	if path == "" {
		return errors.New("output path must not be empty")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	for _, res := range results {
		payload := map[string]any{
			"type":   string(res.Type),
			"url":    res.URL,
			"status": res.Status,
			"ts":     res.Timestamp.UTC().Format(time.RFC3339),
		}
		if err := encoder.Encode(payload); err != nil {
			return fmt.Errorf("encode result: %w", err)
		}
	}
	return nil
}

func defaultOutputPath() string {
	base := strings.TrimSpace(os.Getenv("GLYPH_OUT"))
	if base == "" {
		base = "/out"
	}
	return filepath.Join(base, "schemas.jsonl")
}
