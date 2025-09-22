package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDiscoverSchemasOpenAPI(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"openapi":"3.1.0"}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	client := srv.Client()
	ctx := context.Background()
	now := func() time.Time { return time.Unix(100, 0).UTC() }

	results, err := discoverSchemas(ctx, client, srv.URL, now)
	if err != nil {
		t.Fatalf("discoverSchemas returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	res := results[0]
	if res.Type != schemaOpenAPI {
		t.Fatalf("expected type openapi, got %s", res.Type)
	}
	if res.Status != http.StatusOK {
		t.Fatalf("expected status 200, got %d", res.Status)
	}
	if res.URL != srv.URL+"/.well-known/openapi.json" {
		t.Fatalf("unexpected url %s", res.URL)
	}
	if !res.Timestamp.Equal(now()) {
		t.Fatalf("unexpected timestamp: %s", res.Timestamp)
	}
}

func TestDiscoverSchemasGraphQLHead(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/graphql", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		t.Fatalf("unexpected method: %s", r.Method)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	client := srv.Client()
	ctx := context.Background()
	now := func() time.Time { return time.Unix(200, 0).UTC() }

	results, err := discoverSchemas(ctx, client, srv.URL, now)
	if err != nil {
		t.Fatalf("discoverSchemas returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	res := results[0]
	if res.Type != schemaGraphQL {
		t.Fatalf("expected graphql, got %s", res.Type)
	}
	if res.Status != http.StatusOK {
		t.Fatalf("expected status 200, got %d", res.Status)
	}
}

func TestDiscoverSchemasGraphQLBadRequest(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/graphql", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodHead:
			w.WriteHeader(http.StatusMethodNotAllowed)
		case http.MethodGet:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"errors":[{"message":"must provide query string"}]}`))
		default:
			t.Fatalf("unexpected method: %s", r.Method)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	client := srv.Client()
	ctx := context.Background()
	now := func() time.Time { return time.Unix(300, 0).UTC() }

	results, err := discoverSchemas(ctx, client, srv.URL, now)
	if err != nil {
		t.Fatalf("discoverSchemas returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	res := results[0]
	if res.Type != schemaGraphQL {
		t.Fatalf("expected graphql, got %s", res.Type)
	}
	if res.Status != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", res.Status)
	}
}

func TestGatherTargetsFromFileAndArgs(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	file := filepath.Join(tempDir, "targets.txt")
	content := "https://example.com\n\nhttps://api.example.com\n"
	if err := os.WriteFile(file, []byte(content), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	targets, err := gatherTargets([]string{"https://foo.test"}, file, []string{"https://api.example.com", "https://bar.test"})
	if err != nil {
		t.Fatalf("gatherTargets returned error: %v", err)
	}
	expected := []string{"https://foo.test", "https://example.com", "https://api.example.com", "https://bar.test"}
	if len(targets) != len(expected) {
		t.Fatalf("expected %d targets, got %d", len(expected), len(targets))
	}
	for i, target := range targets {
		if target != expected[i] {
			t.Fatalf("target %d mismatch: expected %s, got %s", i, expected[i], target)
		}
	}
}

func TestWriteResults(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	out := filepath.Join(tempDir, "schemas.jsonl")

	results := []schemaResult{
		{Type: schemaOpenAPI, URL: "https://example.com/openapi.json", Status: 200, Timestamp: time.Unix(0, 0).UTC()},
		{Type: schemaGraphQL, URL: "https://example.com/graphql", Status: 400, Timestamp: time.Unix(1, 0).UTC()},
	}
	if err := writeResults(out, results); err != nil {
		t.Fatalf("writeResults returned error: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != len(results) {
		t.Fatalf("expected %d lines, got %d", len(results), len(lines))
	}
	for i, line := range lines {
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Fatalf("line %d not valid json: %v", i, err)
		}
		if obj["type"] == nil || obj["url"] == nil || obj["status"] == nil || obj["ts"] == nil {
			t.Fatalf("line %d missing fields: %s", i, line)
		}
	}
}

func TestDefaultOutputPath(t *testing.T) {
	t.Setenv("GLYPH_OUT", "/custom")
	expected := filepath.Join("/custom", "schemas.jsonl")
	if got := defaultOutputPath(); got != expected {
		t.Fatalf("expected %s, got %s", expected, got)
	}
}

func TestNormalizeBaseURL(t *testing.T) {
	t.Parallel()

	u, err := normalizeBaseURL("example.com")
	if err != nil {
		t.Fatalf("normalizeBaseURL returned error: %v", err)
	}
	if u.Scheme != "https" {
		t.Fatalf("expected https scheme, got %s", u.Scheme)
	}
	if u.Host != "example.com" {
		t.Fatalf("expected host example.com, got %s", u.Host)
	}
}
