package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"log/slog"
)

type recordedRequest struct {
	Header http.Header
	Body   []byte
}

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func waitErr(t *testing.T, ch <-chan error) {
	t.Helper()
	select {
	case err := <-ch:
		if err != nil {
			t.Fatalf("proxy exited with error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timeout waiting for proxy shutdown")
	}
}

func TestProxyEndToEndHeaderRewrite(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "upstream-demo")
		_, _ = w.Write([]byte("demo"))
	}))
	t.Cleanup(upstream.Close)

	tempDir := t.TempDir()
	rules := `[{"name":"demo-rewrite","match":{"url_contains":"/"},"response":{"add_headers":{"X-Glyph":"on","Content-Security-Policy":"default-src 'self'"},"remove_headers":["Server"]}}]`
	rulesPath := filepath.Join(tempDir, "rules.json")
	if err := os.WriteFile(rulesPath, []byte(rules), 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}

	historyPath := filepath.Join(tempDir, "history.jsonl")
	cfg := Config{
		Addr:        "127.0.0.1:0",
		RulesPath:   rulesPath,
		HistoryPath: historyPath,
		CACertPath:  filepath.Join(tempDir, "ca.pem"),
		CAKeyPath:   filepath.Join(tempDir, "ca.key"),
		Logger:      newTestLogger(),
	}

	proxy, err := New(cfg)
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.Run(ctx)
	}()

	readyCtx, readyCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer readyCancel()
	if err := proxy.WaitUntilReady(readyCtx); err != nil {
		t.Fatalf("proxy not ready: %v", err)
	}

	proxyURL, _ := url.Parse("http://" + proxy.Addr())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatalf("http request via proxy: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if got := resp.Header.Get("X-Glyph"); got != "on" {
		t.Fatalf("expected injected header, got %q", got)
	}
	if got := resp.Header.Get("Content-Security-Policy"); got != "default-src 'self'" {
		t.Fatalf("csp header = %q", got)
	}
	if got := resp.Header.Get("Server"); got != "" {
		t.Fatalf("expected server header stripped, got %q", got)
	}

	cancel()
	waitErr(t, errCh)

	data, err := os.ReadFile(historyPath)
	if err != nil {
		t.Fatalf("read history: %v", err)
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		t.Fatal("history file empty")
	}
	lines := strings.Split(trimmed, "\n")
	if len(lines) != 1 {
		t.Fatalf("expected single history entry, got %d", len(lines))
	}

	var entry HistoryEntry
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("decode history: %v", err)
	}
	if entry.StatusCode != http.StatusOK {
		t.Fatalf("history status = %d", entry.StatusCode)
	}
	if !contains(entry.MatchedRules, "demo-rewrite") {
		t.Fatalf("history missing rule reference: %#v", entry.MatchedRules)
	}
	if headerValues := entry.ResponseHeaders["X-Glyph"]; len(headerValues) == 0 || headerValues[0] != "on" {
		t.Fatalf("history missing rewritten header")
	}
	if _, exists := entry.ResponseHeaders["Server"]; exists {
		t.Fatal("history should not include stripped server header")
	}
}

func TestProxyHTTPModificationAndHistory(t *testing.T) {
	t.Parallel()

	received := make(chan recordedRequest, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		received <- recordedRequest{Header: r.Header.Clone(), Body: body}
		w.Header().Set("X-Origin", "upstream")
		_, _ = w.Write([]byte("origin"))
	}))
	t.Cleanup(upstream.Close)

	tempDir := t.TempDir()
	target := upstream.URL + "/test"

	rules := `[{
        "name": "modify-http",
        "match": {"url_contains": "/test"},
        "request": {"add_headers": {"X-Galdr-Request": "yes"}},
        "response": {"add_headers": {"X-Galdr-Response": "added"}, "body": {"set": "rewritten"}}
    }]`
	rulesPath := filepath.Join(tempDir, "rules.json")
	if err := os.WriteFile(rulesPath, []byte(rules), 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}

	historyPath := filepath.Join(tempDir, "history.jsonl")
	cfg := Config{
		Addr:        "127.0.0.1:0",
		RulesPath:   rulesPath,
		HistoryPath: historyPath,
		CACertPath:  filepath.Join(tempDir, "ca.pem"),
		CAKeyPath:   filepath.Join(tempDir, "ca.key"),
		Logger:      newTestLogger(),
	}

	proxy, err := New(cfg)
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.Run(ctx)
	}()

	readyCtx, readyCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer readyCancel()
	if err := proxy.WaitUntilReady(readyCtx); err != nil {
		t.Fatalf("proxy not ready: %v", err)
	}

	proxyURL, _ := url.Parse("http://" + proxy.Addr())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get(target)
	if err != nil {
		t.Fatalf("http get via proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if got, want := resp.Header.Get("X-Galdr-Response"), "added"; got != want {
		t.Fatalf("response header = %q, want %q", got, want)
	}
	if got, want := string(body), "rewritten"; got != want {
		t.Fatalf("response body = %q, want %q", got, want)
	}

	select {
	case req := <-received:
		if got := req.Header.Get("X-Galdr-Request"); got != "yes" {
			t.Fatalf("upstream header missing, got %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for upstream request")
	}

	cancel()
	waitErr(t, errCh)

	data, err := os.ReadFile(historyPath)
	if err != nil {
		t.Fatalf("read history: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 0 {
		t.Fatalf("no history entries")
	}

	var entry HistoryEntry
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &entry); err != nil {
		t.Fatalf("decode history: %v", err)
	}
	if entry.Method != "GET" {
		t.Fatalf("history method = %q", entry.Method)
	}
	if !contains(entry.MatchedRules, "modify-http") {
		t.Fatalf("history missing rule reference: %#v", entry.MatchedRules)
	}
	if headers := entry.RequestHeaders["X-Galdr-Request"]; len(headers) == 0 || headers[0] != "yes" {
		t.Fatalf("history missing request header")
	}
	if headers := entry.ResponseHeaders["X-Galdr-Response"]; len(headers) == 0 || headers[0] != "added" {
		t.Fatalf("history missing response header")
	}
}

func TestProxyHTTPSInterception(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Origin", "https")
		_, _ = w.Write([]byte("secure"))
	}))
	t.Cleanup(upstream.Close)

	pool := x509.NewCertPool()
	cert := upstream.Certificate()
	if cert == nil {
		t.Fatal("upstream certificate missing")
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if !pool.AppendCertsFromPEM(pemBytes) {
		t.Fatal("failed to append upstream certificate")
	}

	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}

	tempDir := t.TempDir()
	rules := `[{
        "name": "https-rule",
        "match": {"url_contains": "https"},
        "response": {"add_headers": {"X-Proxy-Injected": "true"}}
    }]`
	rulesPath := filepath.Join(tempDir, "rules.json")
	if err := os.WriteFile(rulesPath, []byte(rules), 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}

	cfg := Config{
		Addr:        "127.0.0.1:0",
		RulesPath:   rulesPath,
		HistoryPath: filepath.Join(tempDir, "history.jsonl"),
		CACertPath:  filepath.Join(tempDir, "ca.pem"),
		CAKeyPath:   filepath.Join(tempDir, "ca.key"),
		Logger:      newTestLogger(),
		Transport:   transport,
	}

	proxy, err := New(cfg)
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.Run(ctx)
	}()

	readyCtx, readyCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer readyCancel()
	if err := proxy.WaitUntilReady(readyCtx); err != nil {
		t.Fatalf("proxy not ready: %v", err)
	}

	proxyURL, _ := url.Parse("http://" + proxy.Addr())
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(proxy.CACertificatePEM()) {
		t.Fatal("failed to append proxy CA")
	}

	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: caPool},
	}}

	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatalf("https request via proxy: %v", err)
	}
	_ = resp.Body.Close()

	if got := resp.Header.Get("X-Proxy-Injected"); got != "true" {
		t.Fatalf("expected injected header, got %q", got)
	}

	cancel()
	waitErr(t, errCh)

	data, err := os.ReadFile(cfg.HistoryPath)
	if err != nil {
		t.Fatalf("read history: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 0 {
		t.Fatalf("missing history entries")
	}
	var entry HistoryEntry
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &entry); err != nil {
		t.Fatalf("decode history: %v", err)
	}
	if entry.Protocol != "HTTPS" {
		t.Fatalf("history protocol = %q", entry.Protocol)
	}
	if !contains(entry.MatchedRules, "https-rule") {
		t.Fatalf("https rule missing from history")
	}
	if headers := entry.ResponseHeaders["X-Proxy-Injected"]; len(headers) == 0 || headers[0] != "true" {
		t.Fatalf("history missing injected header")
	}
}

func contains(list []string, needle string) bool {
	for _, item := range list {
		if item == needle {
			return true
		}
	}
	return false
}
