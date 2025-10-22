package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	maxResponseBytes       = 1 << 20 // 1 MiB
	maxRedirects           = 3
	maxRetries             = 2
	maxSchemaFetchBytes    = 256 * 1024
	maxSchemaFetchDuration = time.Second
)

var retryStatuses = map[int]struct{}{
	http.StatusTooManyRequests:    {},
	http.StatusServiceUnavailable: {},
}

var redirectStatuses = map[int]struct{}{
	http.StatusMovedPermanently: {},
	http.StatusFound:            {},
}

// schemaResult captures information about a discovered schema endpoint.
type schemaResult struct {
	Type      schemaType
	URL       string
	Status    int
	Bytes     int
	Hash      string
	Timestamp time.Time
}

// discoverSchemas probes well-known OpenAPI and GraphQL endpoints using the provided HTTP client.
func discoverSchemas(ctx context.Context, client *http.Client, baseURL string, now func() time.Time, fetchDocs bool) ([]schemaResult, error) {
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
		status, finalURL, _, header, ok := fetchEndpoint(ctx, client, target, http.MethodGet, false)
		if !ok || !shouldRecordStatus(status) {
			seen[target] = struct{}{}
			continue
		}
		seen[target] = struct{}{}
		seen[finalURL] = struct{}{}

		digestHeader := header
		var body []byte
		if fetchDocs && status >= http.StatusOK && status < http.StatusMultipleChoices {
			if fetchedBody, fetchedHeader, ok := fetchOpenAPIDocument(ctx, client, finalURL); ok {
				body = fetchedBody
				digestHeader = fetchedHeader
			}
		}

		bytesRead, hash := schemaDigest(digestHeader, body, fetchDocs)
		results = append(results, schemaResult{
			Type:      schemaOpenAPI,
			URL:       finalURL,
			Status:    status,
			Bytes:     bytesRead,
			Hash:      hash,
			Timestamp: now().UTC(),
		})
	}

	for _, path := range graphQLCandidates {
		target := resolveURL(parsed, path)
		if _, ok := seen[target]; ok {
			continue
		}
		status, finalURL, ok := probeGraphQLEndpoint(ctx, client, target)
		if !ok {
			seen[target] = struct{}{}
			continue
		}
		seen[target] = struct{}{}
		seen[finalURL] = struct{}{}
		results = append(results, schemaResult{
			Type:      schemaGraphQL,
			URL:       finalURL,
			Status:    status,
			Bytes:     0,
			Hash:      "",
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

func schemaDigest(header http.Header, body []byte, enabled bool) (int, string) {
	if !enabled {
		return 0, ""
	}
	if len(body) == 0 {
		return 0, ""
	}
	if len(body) > maxSchemaFetchBytes {
		return 0, ""
	}
	ct := strings.ToLower(strings.TrimSpace(header.Get("Content-Type")))
	if ct == "" || !strings.Contains(ct, "json") {
		return 0, ""
	}
	sum := sha256.Sum256(body)
	return len(body), hex.EncodeToString(sum[:])
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

func fetchEndpoint(ctx context.Context, client *http.Client, target, method string, capture bool) (int, string, []byte, http.Header, bool) {
	current := target
	redirects := 0
	attempts := 0

	for {
		status, next, shouldRedirect, header, body, ok := singleRequest(ctx, client, current, method, capture && method == http.MethodGet)
		if !ok {
			return 0, "", nil, nil, false
		}

		if shouldRedirect {
			if redirects >= maxRedirects || next == "" {
				return status, current, nil, header, true
			}
			redirects++
			current = next
			continue
		}

		if _, retry := retryStatuses[status]; retry {
			if attempts >= maxRetries {
				return status, current, nil, header, true
			}
			attempts++
			backoff := time.Duration(attempts) * 200 * time.Millisecond
			if !sleepWithContext(ctx, backoff) {
				return 0, "", nil, nil, false
			}
			continue
		}

		return status, current, body, header, true
	}
}

func fetchOpenAPIDocument(ctx context.Context, client *http.Client, target string) ([]byte, http.Header, bool) {
	ctx, cancel := context.WithTimeout(ctx, maxSchemaFetchDuration)
	defer cancel()

	status, _, body, header, ok := fetchEndpoint(ctx, client, target, http.MethodGet, true)
	if !ok {
		return nil, nil, false
	}
	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		return nil, header, false
	}
	return body, header, true
}

func singleRequest(ctx context.Context, client *http.Client, target, method string, capture bool) (status int, next string, redirect bool, header http.Header, body []byte, ok bool) {
	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return 0, "", false, nil, nil, false
	}
	req.Header.Set("Accept", "application/json, application/yaml;q=0.9, */*;q=0.5")

	clientCopy := *client
	clientCopy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp, err := clientCopy.Do(req)
	if err != nil {
		if !errors.Is(err, http.ErrUseLastResponse) || resp == nil {
			return 0, "", false, nil, nil, false
		}
	}
	defer resp.Body.Close()
	if capture {
		limit := int64(maxSchemaFetchBytes + 1)
		if limit > maxResponseBytes {
			limit = maxResponseBytes
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, limit))
		if err != nil {
			return 0, "", false, nil, nil, false
		}
		body = data
	} else {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
	}

	status = resp.StatusCode
	header = resp.Header.Clone()
	if _, ok := redirectStatuses[status]; ok {
		loc := strings.TrimSpace(resp.Header.Get("Location"))
		if loc == "" {
			return status, "", true, header, nil, true
		}
		nextURL, err := safeRedirect(target, loc)
		if err != nil {
			return status, "", true, header, nil, true
		}
		return status, nextURL, true, header, nil, true
	}

	return status, "", false, header, body, true
}

func safeRedirect(current, location string) (string, error) {
	base, err := url.Parse(current)
	if err != nil {
		return "", err
	}
	ref, err := url.Parse(location)
	if err != nil {
		return "", err
	}
	next := base.ResolveReference(ref)
	if next.Host != base.Host {
		return "", fmt.Errorf("redirect host mismatch: %s -> %s", base.Host, next.Host)
	}
	return next.String(), nil
}

func sleepWithContext(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return true
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func probeGraphQLEndpoint(ctx context.Context, client *http.Client, target string) (int, string, bool) {
	statusHead, urlHead, _, _, okHead := fetchEndpoint(ctx, client, target, http.MethodHead, false)
	headRecordable := okHead && shouldRecordStatus(statusHead)
	needGet := !headRecordable || statusHead == http.StatusMethodNotAllowed || statusHead == http.StatusNotImplemented

	if needGet {
		statusGet, urlGet, _, _, okGet := fetchEndpoint(ctx, client, target, http.MethodGet, false)
		if okGet && shouldRecordStatus(statusGet) {
			return statusGet, urlGet, true
		}
		if headRecordable {
			return statusHead, urlHead, true
		}
		return 0, "", false
	}

	if !okHead {
		return 0, "", false
	}
	return statusHead, urlHead, true
}

func shouldRecordStatus(status int) bool {
	return status != 0 && status != http.StatusNotFound
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
	seen := make(map[string]struct{}, len(results))
	for _, res := range results {
		key := string(res.Type) + "|" + res.URL + "|" + res.Hash
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		payload := map[string]any{
			"type":   string(res.Type),
			"url":    res.URL,
			"status": res.Status,
			"bytes":  res.Bytes,
			"hash":   res.Hash,
			"ts":     res.Timestamp.UTC().Format(time.RFC3339),
		}
		if err := encoder.Encode(payload); err != nil {
			return fmt.Errorf("encode result: %w", err)
		}
	}
	return nil
}

func defaultOutputPath() string {
	base := strings.TrimSpace(os.Getenv("0XGEN_OUT"))
	if base == "" {
		base = "/out"
	}
	return filepath.Join(base, "schemas.jsonl")
}
