package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RowanDark/Glyph/internal/proxy"
)

func TestGaldrProxyHeaderRewriteAndHistory(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping galdr proxy e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "tiny-upstream")
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(upstream.Close)

	root := repoRoot(t)
	glyphdBin := buildGlyphd(ctx, t, root)

	tempDir := t.TempDir()
	rulesPath := filepath.Join(tempDir, "rules.json")
	historyPath := filepath.Join(tempDir, "history.jsonl")
	caCertPath := filepath.Join(tempDir, "proxy_ca.pem")
	caKeyPath := filepath.Join(tempDir, "proxy_ca.key")

	rules := `[{"name":"rewrite","match":{"url_contains":"/"},"response":{"add_headers":{"X-Glyph":"on"},"remove_headers":["Server"]}}]`
	if err := os.WriteFile(rulesPath, []byte(rules), 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}

	glyphdListen, glyphdDial := resolveAddresses(t)
	proxyListen, proxyDial := resolveAddresses(t)

	cmdCtx, cmdCancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(cmdCtx, glyphdBin,
		"--addr", glyphdListen,
		"--token", "test",
		"--enable-proxy",
		"--proxy-addr", proxyListen,
		"--proxy-rules", rulesPath,
		"--proxy-history", historyPath,
		"--proxy-ca-cert", caCertPath,
		"--proxy-ca-key", caKeyPath,
	)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GLYPH_OUT="+tempDir)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start glyphd: %v", err)
	}

	done := make(chan struct{})
	var cmdErr error
	go func() {
		cmdErr = cmd.Wait()
		close(done)
	}()

	t.Cleanup(func() {
		cmdCancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("glyphd did not exit after cancellation")
		}
	})

	if err := waitForListener(cmdCtx, glyphdDial, done, func() error { return cmdErr }); err != nil {
		t.Fatalf("glyphd gRPC listener not ready: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}
	if err := waitForListener(cmdCtx, proxyDial, done, func() error { return cmdErr }); err != nil {
		t.Fatalf("galdr proxy listener not ready: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}

	proxyURL, err := url.Parse("http://" + proxyDial)
	if err != nil {
		t.Fatalf("parse proxy url: %v", err)
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}

	targetURL := upstream.URL + "/demo"
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("http request via galdr: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status code: %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Glyph"); got != "on" {
		t.Fatalf("expected X-Glyph header, got %q\nbody: %s", got, string(body))
	}
	if got := resp.Header.Get("Server"); got != "" {
		t.Fatalf("expected Server header stripped, got %q", got)
	}

	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		cmdCancel()
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		cmdCancel()
		t.Fatalf("glyphd did not exit after interrupt")
	}

	data, err := os.ReadFile(historyPath)
	if err != nil {
		t.Fatalf("read history: %v", err)
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		t.Fatalf("history file empty")
	}

	lines := strings.Split(trimmed, "\n")
	if len(lines) != 1 {
		t.Fatalf("expected one history entry, got %d", len(lines))
	}

	var entry proxy.HistoryEntry
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("decode history entry: %v\nline: %s", err, lines[0])
	}
	if entry.URL != targetURL {
		t.Fatalf("history url = %q, want %q", entry.URL, targetURL)
	}
	if entry.Timestamp.IsZero() {
		t.Fatalf("history timestamp missing: %+v", entry)
	}
	if headers := entry.ResponseHeaders["X-Glyph"]; len(headers) == 0 || headers[0] != "on" {
		t.Fatalf("history missing rewritten header: %+v", entry.ResponseHeaders)
	}
	if _, exists := entry.ResponseHeaders["Server"]; exists {
		t.Fatalf("history should not record stripped server header: %+v", entry.ResponseHeaders)
	}
}
