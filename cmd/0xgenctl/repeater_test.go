package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/RowanDark/0xgen/internal/history"
	"github.com/RowanDark/0xgen/internal/proxy"
)

type capturedRequest struct {
	header http.Header
	host   string
	body   []byte
}

func TestRepeaterSendOverridesHeadersAndAppendsHistory(t *testing.T) {
	t.Helper()

	captureCh := make(chan capturedRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		captureCh <- capturedRequest{header: r.Header.Clone(), host: r.Host, body: data}
		w.Header().Set("X-From-Server", "replayed")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	parsedURL, err := url.Parse(server.URL + "/demo")
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}

	tempDir := t.TempDir()
	historyPath := filepath.Join(tempDir, "history.jsonl")

	initial := proxy.HistoryEntry{
		Timestamp: time.Now().UTC(),
		Protocol:  "http",
		Method:    "POST",
		URL:       parsedURL.String(),
		RequestHeaders: map[string][]string{
			"Host":         []string{parsedURL.Host},
			"Content-Type": []string{"application/json"},
		},
	}
	if err := history.Append(historyPath, initial); err != nil {
		t.Fatalf("write initial history: %v", err)
	}

	payload := []byte(`{"override":true}`)
	bodyPath := filepath.Join(tempDir, "body.json")
	if err := os.WriteFile(bodyPath, payload, 0o600); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	exitCode := runRepeaterSend([]string{
		"--history", historyPath,
		"--id", "1",
		"--set", "Header:X-Token=override",
		"--set-body", "@" + bodyPath,
	})
	if exitCode != 0 {
		t.Fatalf("runRepeaterSend exit code = %d", exitCode)
	}

	var captured capturedRequest
	select {
	case captured = <-captureCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for replayed request")
	}

	if got := captured.header.Get("X-Token"); got != "override" {
		t.Fatalf("expected X-Token header = override, got %q", got)
	}
	if captured.host != parsedURL.Host {
		t.Fatalf("expected host %q, got %q", parsedURL.Host, captured.host)
	}
	if string(captured.body) != string(payload) {
		t.Fatalf("unexpected request body: %q", string(captured.body))
	}
	if got := captured.header.Get("Content-Length"); got != strconv.Itoa(len(payload)) {
		t.Fatalf("expected Content-Length %d, got %q", len(payload), got)
	}

	idx, err := history.Load(historyPath)
	if err != nil {
		t.Fatalf("reload history: %v", err)
	}
	entries := idx.Entries()
	if len(entries) != 2 {
		t.Fatalf("expected two history entries, got %d", len(entries))
	}

	latest := entries[1]
	if latest.ID != "2" {
		t.Fatalf("expected replay ID 2, got %s", latest.ID)
	}
	record := latest.Record
	if record.StatusCode != http.StatusCreated {
		t.Fatalf("expected status %d, got %d", http.StatusCreated, record.StatusCode)
	}
	if record.RequestHeaders["X-Token"][0] != "override" {
		t.Fatalf("history did not capture header override: %#v", record.RequestHeaders)
	}
	if record.RequestSize != len(payload) {
		t.Fatalf("expected request size %d, got %d", len(payload), record.RequestSize)
	}
	if record.ResponseSize != 2 {
		t.Fatalf("expected response size 2, got %d", record.ResponseSize)
	}
	if record.ResponseHeaders["X-From-Server"][0] != "replayed" {
		t.Fatalf("expected response header recorded, got %#v", record.ResponseHeaders)
	}
	if !strings.EqualFold(record.Method, "POST") {
		t.Fatalf("expected method POST, got %q", record.Method)
	}
	if record.URL != parsedURL.String() {
		t.Fatalf("expected url %q, got %q", parsedURL.String(), record.URL)
	}
}
